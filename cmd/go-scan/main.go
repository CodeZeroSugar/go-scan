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
	Version = "1.0.0-alpha"
	URL     = "https://github.com/CodeZeroSugar/go-scan"
	Workers = 100
)

func main() {
	now := time.Now()
	formattedTime := now.Format("2006-01-02 15:04:05")
	fmt.Printf("Starting GoScan %s ( %s ) at %s\n", Version, URL, formattedTime)

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

	for range Workers {
		go tcpscanner.Scan(taskQueue, taskResults)
	}

	hostsUp, err := icmpscanner.DiscoveryScan(ip)
	if err != nil {
		log.Fatalf("%s", err)
	}

	fmt.Printf("Scanning %d ports...\n", portLen)

	for _, ip := range hostsUp {

		if params.PortMode == tcpscanner.Series {
			for i := p[0]; i < p[1]; i++ {
				task := tcpscanner.PortScanTask{
					TargetIP: ip.To4(),
					Port:     i,
				}
				taskQueue <- task
			}
		} else {
			for _, i := range p {
				task := tcpscanner.PortScanTask{
					TargetIP: ip.To4(),
					Port:     i,
				}
				taskQueue <- task
			}
		}

		close(taskQueue)

		var aggregatedResults []tcpscanner.PortScanResults
		var openPorts []int

		for range portLen {
			result := <-taskResults
			if result.State == tcpscanner.Open {
				aggregatedResults = append(aggregatedResults, result)
				openPorts = append(openPorts, result.Port)
			}
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

	}
	d := time.Since(now)
	fmt.Printf("GoScan done: %d ports scanned in %.2f seconds\n", portLen, d.Seconds())
}
