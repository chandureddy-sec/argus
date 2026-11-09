//go:build linux

package agent

import (
	"bufio"
	"context"
	"os/exec"
)

// FollowAuthFailures streams sshd and sudo auth failures from the systemd
// journal into the queue until ctx is cancelled. Linux-only (uses journalctl).
// It runs no elevated action; it only reads the journal.
func (c *Client) FollowAuthFailures(ctx context.Context, q *Queue) error {
	// -f follow, -n 0 start at the tail, JSON output, sshd + sudo only
	// (repeated SYSLOG_IDENTIFIER matches are OR-ed by journalctl).
	cmd := exec.CommandContext(ctx, "journalctl", "-f", "-n", "0", "-o", "json",
		"SYSLOG_IDENTIFIER=sshd", "SYSLOG_IDENTIFIER=sudo")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if ev, ok := ParseAuthFailure(c.cfg.AgentID, sc.Bytes()); ok {
			q.Push(ev)
		}
	}
	return cmd.Wait()
}
