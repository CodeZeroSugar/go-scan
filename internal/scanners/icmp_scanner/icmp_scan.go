package icmpscanner

import (
	"fmt"
	"net"
	"sync"
)

const DiscoveryWorkers = 100

func DiscoveryScan(input string) ([]net.IP, error) {
	targets, err := ParseTargets(input)
	if err != nil {
		return nil, fmt.Errorf("failed to parse input for discovery scan: %w", err)
	}

	jobs := make(chan net.IP)
	results := make(chan net.IP)

	var wg sync.WaitGroup

	for i := 0; i < DiscoveryWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobs {
				ok, err := Ping(target)
				if err != nil {
					continue
				}
				if ok {
					results <- target
				}
			}
		}()
	}

	go func() {
		for _, t := range targets {
			jobs <- t
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	var hostsUp []net.IP
	for ip := range results {
		hostsUp = append(hostsUp, ip)
	}

	return hostsUp, nil
}
