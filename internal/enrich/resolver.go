package enrich

import (
	"context"
	"net"
	"sync"
	"time"
)

// HostResolution maps a hostname to its resolved IP addresses.
type HostResolution struct {
	Hostname string   `json:"hostname"`
	IPs      []string `json:"ips"`
	Alive    bool     `json:"alive"`
}

// BulkResolver resolves a collection of hostnames to IP addresses concurrently.
type BulkResolver struct {
	concurrency int
	timeout     time.Duration
}

// NewBulkResolver initializes a BulkResolver with specified concurrency.
func NewBulkResolver(concurrency int, timeout time.Duration) *BulkResolver {
	if concurrency <= 0 {
		concurrency = 20
	}
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	return &BulkResolver{
		concurrency: concurrency,
		timeout:     timeout,
	}
}

// ResolveAll resolves hostnames in parallel and returns a map of hostname -> resolved IPs,
// plus a list of all unique IP addresses discovered.
func (b *BulkResolver) ResolveAll(ctx context.Context, hostnames []string) (map[string][]string, []string) {
	if len(hostnames) == 0 {
		return make(map[string][]string), nil
	}

	jobs := make(chan string, len(hostnames))
	results := make(chan HostResolution, len(hostnames))

	var wg sync.WaitGroup
	workers := b.concurrency
	if workers > len(hostnames) {
		workers = len(hostnames)
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resolver := &net.Resolver{
				PreferGo: true,
			}

			for host := range jobs {
				resCtx, cancel := context.WithTimeout(ctx, b.timeout)
				ips, err := resolver.LookupHost(resCtx, host)
				cancel()

				if err == nil && len(ips) > 0 {
					results <- HostResolution{
						Hostname: host,
						IPs:      ips,
						Alive:    true,
					}
				} else {
					results <- HostResolution{
						Hostname: host,
						IPs:      nil,
						Alive:    false,
					}
				}
			}
		}()
	}

	for _, h := range hostnames {
		jobs <- h
	}
	close(jobs)

	wg.Wait()
	close(results)

	hostMap := make(map[string][]string)
	uniqueIPMap := make(map[string]bool)

	for res := range results {
		if res.Alive && len(res.IPs) > 0 {
			hostMap[res.Hostname] = res.IPs
			for _, ip := range res.IPs {
				uniqueIPMap[ip] = true
			}
		}
	}

	uniqueIPs := make([]string, 0, len(uniqueIPMap))
	for ip := range uniqueIPMap {
		uniqueIPs = append(uniqueIPs, ip)
	}

	return hostMap, uniqueIPs
}
