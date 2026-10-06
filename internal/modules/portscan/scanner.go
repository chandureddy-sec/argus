package portscan

import (
	"context"
	"net"
	"strconv"
	"sync"
	"time"

	"reconx/pkg/models"
)

// CommonPorts defines a list of frequently used TCP ports.
var CommonPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
	993, 995, 1433, 1521, 3306, 3389, 5432, 5900,
	6379, 8080, 8443, 8888, 27017,
}

// KnownService returns the typical service name for a common port.
func KnownService(port int) string {
	switch port {
	case 21: return "ftp"
	case 22: return "ssh"
	case 23: return "telnet"
	case 25: return "smtp"
	case 53: return "dns"
	case 80: return "http"
	case 110: return "pop3"
	case 143: return "imap"
	case 443: return "https"
	case 445: return "smb"
	case 993: return "imaps"
	case 995: return "pop3s"
	case 1433: return "mssql"
	case 1521: return "oracle"
	case 3306: return "mysql"
	case 3389: return "rdp"
	case 5432: return "postgresql"
	case 5900: return "vnc"
	case 6379: return "redis"
	case 8080: return "http-proxy"
	case 8443: return "https-alt"
	case 8888: return "http-alt"
	case 27017: return "mongodb"
	default: return "unknown"
	}
}

// ScanPorts performs a concurrent TCP port scan against the provided list of ports.
func ScanPorts(ctx context.Context, host string, ports []int, timeout time.Duration) ([]models.PortResult, error) {
	if timeout == 0 {
		timeout = 2 * time.Second
	}

	results := make([]models.PortResult, 0, len(ports))
	var mu sync.Mutex

	portChan := make(chan int, len(ports))
	for _, p := range ports {
		portChan <- p
	}
	close(portChan)

	var wg sync.WaitGroup
	// Use more workers if there are a lot of ports (up to 200).
	workers := 200
	if workers > len(ports) {
		workers = len(ports)
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portChan {
				select {
				case <-ctx.Done():
					return
				default:
				}

				target := net.JoinHostPort(host, strconv.Itoa(port))
				conn, err := net.DialTimeout("tcp", target, timeout)

				var state string
				var banner string
				if err != nil {
					state = "closed"
				} else {
					state = "open"
					_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
					buf := make([]byte, 256)
					n, _ := conn.Read(buf)
					if n > 0 {
						banner = string(buf[:n])
					}
					conn.Close()
				}

				mu.Lock()
				results = append(results, models.PortResult{
					Port:     port,
					Protocol: "tcp",
					State:    state,
					Service:  KnownService(port),
					Banner:   banner,
				})
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
	return results, nil
}
