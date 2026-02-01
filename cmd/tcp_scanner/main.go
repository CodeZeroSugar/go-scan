package main

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
)

const (
	LoopBack = "127.0.0.1"
	Ports    = 1023
	Workers  = 100
)

func main() {
	params := handleFlags()

	ip := net.ParseIP(params.target)
	if ip == nil {
		log.Fatalf("failed to parse IP from: %s", params.target)
	}

	var portLen int
	var p []int

	switch params.portMode {
	case single:
		portLen = 1
		numStr := params.ports[0]
		num, err := strconv.Atoi(numStr)
		if err != nil {
			log.Fatalf("invalid integer assigned to port: %s", err)
		}
		p = append(p, num)
	case selection:
		portLen = len(params.ports)
		for _, n := range params.ports {
			num, err := strconv.Atoi(n)
			if err != nil {
				log.Fatalf("invalid integer assigned to port: %s", err)
			}
			p = append(p, num)
		}
	case series:
		splitPorts := strings.Split(params.ports[0], "-")
		numLow, err := strconv.Atoi(splitPorts[0])
		if err != nil {
			log.Fatalf("invalid integer assigned to port: %s", err)
		}
		numHigh, err := strconv.Atoi(splitPorts[1])
		if err != nil {
			log.Fatalf("invalid integer assigned to port: %s", err)
		}
		portLen = numHigh - 1
		p = append(p, numLow, numHigh)

	default:
		log.Fatalf("Invalid format for ports")
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
	fmt.Printf("Scan Results for: %v\n", ip)
	for range portLen {
		result := <-taskResults
		if result.State == PortStateOpen {
			fmt.Printf("Port: %-5d | State: %v | Error: %v\n", result.Port, result.State.String(), result.ErrorInfo)
		}
	}

	fmt.Println("Scan complete")
}
