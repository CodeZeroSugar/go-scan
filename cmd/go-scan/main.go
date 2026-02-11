package main

import (
	"flag"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/CodeZeroSugar/go-scan/internal/paths"
	icmpscanner "github.com/CodeZeroSugar/go-scan/internal/scanners/icmp_scanner"
	tcpscanner "github.com/CodeZeroSugar/go-scan/internal/scanners/tcp_scanner"
	"github.com/CodeZeroSugar/go-scan/internal/stats"
)

const (
	Version = "1.0.0"
	URL     = "https://github.com/CodeZeroSugar/go-scan"
	Workers = 100
)

func main() {
	now := time.Now()
	formattedTime := now.Format("2006-01-02 15:04:05")
	fmt.Printf("Starting GoScan %s ( %s ) at %s\n\n", Version, URL, formattedTime)

	statPath, err := paths.StatsPath()
	if err != nil {
		log.Printf("failed to validate path to stats file: %s", err)
	}

	params := handleFlags()

	if params.Stats {
		args := flag.Args()
		err = handleStats(args, statPath)
		if err != nil {
			log.Printf("something went wrong reporting stats: %s", err)
		}
		return
	}

	ip := params.Target

	if params.Discovery {
		fmt.Println("Performing host discovery scan...")
		hostsUp, err := icmpscanner.DiscoveryScan(ip)
		if err != nil {
			log.Fatalf("%s", err)
		}

		fmt.Println("Hosts up:")

		for _, h := range hostsUp {
			fmt.Printf("%s\n", h.String())
		}
		return
	}

	p, portLen, err := tcpscanner.ParsePortOpts(params)
	if err != nil {
		log.Fatalf("%s", err)
	}

	taskQueue := make(chan tcpscanner.PortScanTask)
	taskResults := make(chan tcpscanner.PortScanResults, portLen)

	for i := 0; i < Workers; i++ {
		go tcpscanner.Scan(taskQueue, taskResults)
	}

	hostsUp, err := icmpscanner.DiscoveryScan(ip)
	if err != nil {
		log.Fatalf("%s", err)
	}

	var hosts []string
	for _, h := range hostsUp {
		hosts = append(hosts, h.String())
	}

	totalTasks := 0
	for range hostsUp {
		totalTasks += portLen
	}

	go func() {
		for _, ip := range hostsUp {
			if params.PortMode == tcpscanner.Series {
				for port := p[0]; port < p[1]; port++ {
					taskQueue <- tcpscanner.PortScanTask{
						TargetIP: ip.To4(),
						Port:     port,
					}
				}
			} else {
				for _, port := range p {
					taskQueue <- tcpscanner.PortScanTask{
						TargetIP: ip.To4(),
						Port:     port,
					}
				}
			}
		}
		close(taskQueue)
	}()

	resultsByHost := make(map[string][]tcpscanner.PortScanResults)
	openPortsByHost := make(map[string][]int)

	for i := 0; i < totalTasks; i++ {
		res := <-taskResults
		host := res.TargetIP.String()

		if res.State == tcpscanner.Open || (res.State == tcpscanner.Filtered && params.Filtered) {
			resultsByHost[host] = append(resultsByHost[host], res)
			openPortsByHost[host] = append(openPortsByHost[host], res.Port)
		}
	}

	sortHosts(hosts)
	for _, h := range hosts {
		results := resultsByHost[h]
		sort.Slice(results, func(i, j int) bool {
			return results[i].Port < results[j].Port
		})

		fmt.Printf("Scan Results for: %s\n", h)
		if len(results) == 0 {
			fmt.Printf("- No accessible ports detected\n\n")
			continue
		}

		for i, res := range results {
			fmt.Printf("Port: %5d | State: %v\n", res.Port, res.State.String())

			if i == len(results)-1 {
				fmt.Println("")
			}
		}

		if err := stats.UpdateStats(openPortsByHost[h], statPath); err != nil {
			log.Printf("failed to update stats file: %s", err)
		}
	}

	d := time.Since(now)
	fmt.Printf("GoScan done: %d host(s) scanned in %.2f seconds\n", len(resultsByHost), d.Seconds())
}
