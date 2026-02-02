package main

import (
	"fmt"
	"log"
	"net"
	"sort"
	"time"

	"github.com/CodeZeroSugar/go-scan/internal/paths"
	"github.com/CodeZeroSugar/go-scan/internal/stats"
)

const (
	Version = "1.0.0-alpha"
	URL     = "https://github.com/CodeZeroSugar/go-scan"
	Workers = 100
)

func main() {
	now := time.Now()
	formattedTime := now.Format("2006-01-02 15:04:05")
	fmt.Printf("Starting GoScan %s ( %s ) at %s\n", Version, URL, formattedTime)

	params := handleFlags()

	ip := net.ParseIP(params.target)
	if ip == nil {
		log.Fatalf("failed to parse IP from: %s", params.target)
	}

	p, portLen, err := parsePortOpts(params)
	if err != nil {
		log.Fatalf("%s", err)
	}

	taskQueue := make(chan PortScanTask)
	taskResults := make(chan PortScanResults, portLen)

	for range Workers {
		go scan(taskQueue, taskResults)
	}

	fmt.Printf("Scanning %d ports...\n", portLen)

	if params.portMode == series {
		for i := p[0]; i < p[1]; i++ {
			task := PortScanTask{
				TargetIP: ip.To4(),
				Port:     i,
			}
			taskQueue <- task
		}
	} else {
		for _, i := range p {
			task := PortScanTask{
				TargetIP: ip.To4(),
				Port:     i,
			}
			taskQueue <- task
		}
	}

	close(taskQueue)

	var aggregatedResults []PortScanResults
	var openPorts []int

	for range portLen {
		result := <-taskResults
		if result.State == Open {
			aggregatedResults = append(aggregatedResults, result)
			openPorts = append(openPorts, result.Port)
		}
	}

	statPath, err := paths.StatsPath()
	if err != nil {
		log.Printf("failed to validate path to stats file: %s", err)
	}
	if err = stats.UpdateStats(openPorts, statPath); err != nil {
		log.Printf("failed to update stats file: %s", err)
	}

	sort.Slice(aggregatedResults, func(i, j int) bool {
		return aggregatedResults[i].Port < aggregatedResults[j].Port
	})

	fmt.Printf("Scan Results for: %v\n", ip)
	for _, res := range aggregatedResults {
		fmt.Printf("Port: %-5d | State: %v\n", res.Port, res.State.String())
	}
	d := time.Since(now)
	fmt.Printf("GoScan done: %d ports scanned in %.2f seconds\n", portLen, d.Seconds())
}
