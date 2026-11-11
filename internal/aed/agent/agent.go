// Package agent is the AED lab endpoint agent (Slice 3): a collection-only
// client that registers with the gateway and sends heartbeats over mTLS. It
// takes no actions on the host. Lab use only.
package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
)

// Config holds the agent's identity and where to reach the gateway.
type Config struct {
	GatewayURL        string
	AgentID           string
	Version           string
	HeartbeatInterval time.Duration
	CertPEM           []byte
}

// Client sends heartbeats to the AED gateway.
type Client struct {
	cfg     Config
	http    *http.Client
	mu      sync.Mutex
	lastSeq int64
	certB64 string
}

// New builds a Client. A nil httpClient uses a plain timeout client (tests);
// the real agent passes an mTLS client from MTLSClient.
func New(cfg Config, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.HeartbeatInterval <= 0 {
		cfg.HeartbeatInterval = 30 * time.Second
	}
	var b64 string
	if len(cfg.CertPEM) > 0 {
		b64 = base64.StdEncoding.EncodeToString(cfg.CertPEM)
	}
	return &Client{cfg: cfg, http: httpClient, certB64: b64}
}

// nextSeq returns a strictly increasing sequence number. It is seeded from the
// wall clock in nanoseconds so it keeps increasing across agent restarts, which
// the gateway's replay guard requires.
func (c *Client) nextSeq() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now().UnixNano()
	if now <= c.lastSeq {
		now = c.lastSeq + 1
	}
	c.lastSeq = now
	return now
}

func newNonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

type heartbeatBody struct {
	Version   string `json:"version"`
	AgentTime string `json:"agent_time"`
}

// SendHeartbeat posts one heartbeat (with a fresh sequence + nonce for replay
// protection) and returns an error unless the gateway answers 200.
func (c *Client) SendHeartbeat(ctx context.Context) error {
	body, err := json.Marshal(heartbeatBody{
		Version:   c.cfg.Version,
		AgentTime: time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.GatewayURL+"/aed/heartbeat", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-AED-Seq", fmt.Sprintf("%d", c.nextSeq()))
	req.Header.Set("X-AED-Nonce", newNonce())
	if c.certB64 != "" {
		req.Header.Set("X-AED-Client-Cert", c.certB64)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("heartbeat: gateway returned %d", resp.StatusCode)
	}
	return nil
}

// SendBatch ships a batch of telemetry events to the gateway's ingest endpoint
// (with a fresh sequence + nonce). An empty batch is a no-op. Returns an error
// unless the gateway answers 202.
func (c *Client) SendBatch(ctx context.Context, events []*Event) error {
	if len(events) == 0 {
		return nil
	}
	body, err := json.Marshal(map[string]any{"events": events})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.GatewayURL+"/aed/ingest", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-AED-Seq", fmt.Sprintf("%d", c.nextSeq()))
	req.Header.Set("X-AED-Nonce", newNonce())
	if c.certB64 != "" {
		req.Header.Set("X-AED-Client-Cert", c.certB64)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("ingest: gateway returned %d", resp.StatusCode)
	}
	return nil
}

// ShipLoop drains the queue in batches of up to batchMax every interval until
// ctx is done. On a send failure the batch is re-queued at the head and retried
// next tick, so telemetry survives a temporary gateway outage (bounded by the
// queue capacity).
func (c *Client) ShipLoop(ctx context.Context, q *Queue, batchMax int, interval time.Duration) {
	if interval <= 0 {
		interval = 15 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			batch := q.PopBatch(batchMax)
			if len(batch) == 0 {
				continue
			}
			if err := c.SendBatch(ctx, batch); err != nil {
				q.PushFront(batch) // retry next tick
			}
		}
	}
}

// Run sends an immediate heartbeat and then one per interval until ctx is done.
func (c *Client) Run(ctx context.Context) {
	t := time.NewTicker(c.cfg.HeartbeatInterval)
	defer t.Stop()
	_ = c.SendHeartbeat(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = c.SendHeartbeat(ctx)
		}
	}
}

// MTLSClient builds an http.Client that presents the agent certificate (mTLS)
// and trusts the gateway CA. TLS 1.3 only.
func MTLSClient(certFile, keyFile, caFile string, timeout time.Duration) (*http.Client, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load agent cert/key: %w", err)
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("CA file %q contains no certificates", caFile)
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				RootCAs:      pool,
				MinVersion:   tls.VersionTLS13,
			},
		},
	}, nil
}
