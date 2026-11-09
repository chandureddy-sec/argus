package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// ---- journal parse: failed SSH logins ----

func journalLine(t *testing.T, ident, msg string, realtimeMicros int64) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]string{
		"SYSLOG_IDENTIFIER":    ident,
		"MESSAGE":              msg,
		"__REALTIME_TIMESTAMP": strconv.FormatInt(realtimeMicros, 10),
		"_HOSTNAME":            "lab-vm-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseSSHFailure_FailedPasswordInvalidUser(t *testing.T) {
	line := journalLine(t, "sshd", "Failed password for invalid user admin from 203.0.113.9 port 54321 ssh2", 1_762_000_000_000_000)
	ev, ok := ParseSSHFailure("agent-1", line)
	if !ok {
		t.Fatal("expected an event")
	}
	if ev.ClassUID != ClassAuthentication {
		t.Errorf("class_uid = %d, want %d", ev.ClassUID, ClassAuthentication)
	}
	if ev.Fields["src_ip"] != "203.0.113.9" {
		t.Errorf("src_ip = %v", ev.Fields["src_ip"])
	}
	if ev.Fields["user"] != "admin" {
		t.Errorf("user = %v", ev.Fields["user"])
	}
	if ev.Fields["status"] != "failure" {
		t.Errorf("status = %v", ev.Fields["status"])
	}
	if ev.AgentID != "agent-1" || ev.OCSFVersion == "" {
		t.Errorf("envelope missing: %+v", ev)
	}
	if len(ev.Raw) == 0 {
		t.Error("raw record not preserved")
	}
}

func TestParseSSHFailure_FailedPasswordRoot(t *testing.T) {
	line := journalLine(t, "sshd", "Failed password for root from 198.51.100.4 port 2222 ssh2", 1_762_000_000_111_000)
	ev, ok := ParseSSHFailure("agent-1", line)
	if !ok {
		t.Fatal("expected an event")
	}
	if ev.Fields["src_ip"] != "198.51.100.4" || ev.Fields["user"] != "root" {
		t.Errorf("parsed wrong: %+v", ev.Fields)
	}
}

func TestParseSSHFailure_SkipsNonSshdAndNonFailures(t *testing.T) {
	if _, ok := ParseSSHFailure("a", journalLine(t, "cron", "some cron message", 1)); ok {
		t.Error("non-sshd line must be skipped")
	}
	if _, ok := ParseSSHFailure("a", journalLine(t, "sshd", "Accepted password for alice from 10.0.0.5 port 22 ssh2", 1)); ok {
		t.Error("successful login must not be a failure event")
	}
	if _, ok := ParseSSHFailure("a", []byte("{ not json")); ok {
		t.Error("malformed line must be skipped, not panic")
	}
}

// ---- journal parse: failed sudo ----

func TestParseSudo_PamAuthFailure(t *testing.T) {
	msg := "pam_unix(sudo:auth): authentication failure; logname=bob uid=1000 euid=0 tty=/dev/pts/0 ruser=bob rhost=10.0.0.9 user=bob"
	ev, ok := ParseSudo("agent-1", journalLine(t, "sudo", msg, 1_762_000_000_000_000))
	if !ok {
		t.Fatal("expected a sudo event")
	}
	if ev.Fields["user"] != "bob" || ev.Fields["src_ip"] != "10.0.0.9" {
		t.Errorf("parsed wrong: %+v", ev.Fields)
	}
	if ev.Fields["status"] != "failure" || ev.Fields["activity"] != "sudo" {
		t.Errorf("fields wrong: %+v", ev.Fields)
	}
	if ev.ClassUID != ClassAuthentication || len(ev.Raw) == 0 {
		t.Errorf("envelope wrong: %+v", ev)
	}
}

func TestParseSudo_NotInSudoers(t *testing.T) {
	msg := "carol : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/carol ; USER=root ; COMMAND=/bin/bash"
	ev, ok := ParseSudo("a", journalLine(t, "sudo", msg, 2))
	if !ok || ev.Fields["user"] != "carol" || ev.Fields["status"] != "failure" {
		t.Errorf("not-in-sudoers parse wrong: ok=%v %+v", ok, ev)
	}
}

func TestParseSudo_SkipsSuccessAndNonSudo(t *testing.T) {
	_, ok := ParseSudo("a", journalLine(t, "sudo", "bob : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls", 1))
	if ok {
		t.Error("successful sudo must be skipped")
	}
	if _, ok := ParseSudo("a", journalLine(t, "sshd", "Failed password for root from 1.2.3.4 port 22 ssh2", 1)); ok {
		t.Error("non-sudo line must be skipped by ParseSudo")
	}
}

func TestParseAuthFailure_Dispatch(t *testing.T) {
	ssh := journalLine(t, "sshd", "Failed password for root from 198.51.100.4 port 2222 ssh2", 1)
	if ev, ok := ParseAuthFailure("a", ssh); !ok || ev.Fields["activity"] != "logon" {
		t.Errorf("ssh dispatch wrong: ok=%v %+v", ok, ev)
	}
	sudo := journalLine(t, "sudo", "dan : 1 incorrect password attempt ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/sh", 1)
	if ev, ok := ParseAuthFailure("a", sudo); !ok || ev.Fields["activity"] != "sudo" || ev.Fields["user"] != "dan" {
		t.Errorf("sudo dispatch wrong: ok=%v %+v", ok, ev)
	}
	if _, ok := ParseAuthFailure("a", journalLine(t, "cron", "tick", 1)); ok {
		t.Error("other units must be skipped")
	}
}

// ---- bounded offline queue ----

func TestBoundedQueue(t *testing.T) {
	q := NewQueue(3)
	for i := 0; i < 5; i++ {
		q.Push(&Event{Fields: map[string]any{"n": i}})
	}
	if q.Dropped() != 2 {
		t.Errorf("dropped = %d, want 2", q.Dropped())
	}
	batch := q.PopBatch(10)
	if len(batch) != 3 {
		t.Fatalf("batch size = %d, want 3 (capacity)", len(batch))
	}
	// Oldest two (0,1) were dropped; remaining should be 2,3,4 in FIFO order.
	if batch[0].Fields["n"] != 2 || batch[2].Fields["n"] != 4 {
		t.Errorf("FIFO order wrong: %v .. %v", batch[0].Fields["n"], batch[2].Fields["n"])
	}
	if len(q.PopBatch(10)) != 0 {
		t.Error("queue should be empty after draining")
	}
}

func TestQueuePopBatchHonorsMax(t *testing.T) {
	q := NewQueue(100)
	for i := 0; i < 10; i++ {
		q.Push(&Event{})
	}
	if n := len(q.PopBatch(4)); n != 4 {
		t.Errorf("PopBatch(4) = %d, want 4", n)
	}
}

// ---- host inventory ----

func TestBuildInventory(t *testing.T) {
	ev := BuildInventory("agent-1", "0.1.0")
	if ev.ClassUID != ClassDeviceInventory {
		t.Errorf("class_uid = %d, want %d", ev.ClassUID, ClassDeviceInventory)
	}
	if ev.Fields["hostname"] == "" || ev.Fields["os"] == "" {
		t.Errorf("inventory missing hostname/os: %+v", ev.Fields)
	}
	if ev.Fields["agent_version"] != "0.1.0" {
		t.Errorf("agent_version = %v", ev.Fields["agent_version"])
	}
}

// ---- batch shipping ----

func TestSendBatch(t *testing.T) {
	var gotSeq, gotNonce int
	var count int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/aed/ingest" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Header.Get("X-AED-Seq") != "" {
			gotSeq++
		}
		if r.Header.Get("X-AED-Nonce") != "" {
			gotNonce++
		}
		b, _ := io.ReadAll(r.Body)
		var payload struct {
			Events []json.RawMessage `json:"events"`
		}
		_ = json.Unmarshal(b, &payload)
		count = len(payload.Events)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	c := New(Config{GatewayURL: srv.URL, AgentID: "agent-1", Version: "0.1"}, srv.Client())
	events := []*Event{BuildInventory("agent-1", "0.1"), {ClassUID: ClassAuthentication}}
	if err := c.SendBatch(context.Background(), events); err != nil {
		t.Fatalf("SendBatch: %v", err)
	}
	if gotSeq != 1 || gotNonce != 1 {
		t.Errorf("seq/nonce headers missing: seq=%d nonce=%d", gotSeq, gotNonce)
	}
	if count != 2 {
		t.Errorf("gateway received %d events, want 2", count)
	}
}

func TestSendBatchEmptyIsNoop(t *testing.T) {
	c := New(Config{GatewayURL: "http://unused", Version: "0.1"}, nil)
	if err := c.SendBatch(context.Background(), nil); err != nil {
		t.Errorf("empty batch should be a no-op, got %v", err)
	}
}
