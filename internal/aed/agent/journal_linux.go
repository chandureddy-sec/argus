//go:build linux

package agent

import (
	"bufio"
	"context"
	"os/exec"
)

// FollowSSHFailures streams sshd failures from the systemd journal into the
// queue until ctx is cancelled. Linux-only (uses journalctl). It runs no
// elevated action; it only reads the journal.
func (c *Client) FollowSSHFailures(ctx context.Context, q *Queue) error {
	// -f follow, -n 0 start at the tail, JSON output, sshd only.
	cmd := exec.CommandContext(ctx, "journalctl", "-f", "-n", "0", "-o", "json", "SYSLOG_IDENTIFIER=sshd")
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
		if ev, ok := ParseSSHFailure(c.cfg.AgentID, sc.Bytes()); ok {
			q.Push(ev)
		}
	}
	return cmd.Wait()
}
