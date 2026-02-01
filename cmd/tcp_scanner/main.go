package main

import (
	"fmt"
	"log"
	"net"
	"sort"
)

const (
	Workers = 100
)

func main() {
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
	for range portLen {
		result := <-taskResults
		if result.State == Open {
			aggregatedResults = append(aggregatedResults, result)
		}
	}

	sort.Slice(aggregatedResults, func(i, j int) bool {
		return aggregatedResults[i].Port < aggregatedResults[j].Port
	})

	fmt.Printf("Scan Results for: %v\n", ip)
	for _, res := range aggregatedResults {
		fmt.Printf("Port: %-5d | State: %v\n", res.Port, res.State.String())
	}

	fmt.Println("Scan complete")
}
