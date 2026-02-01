package main

import (
	"fmt"
	"log"
	"net"
	"os"
)

const (
	LoopBack = "127.0.0.1"
	Ports    = 1023
	Workers  = 100
)

func main() {
	args := os.Args[1:]
	target := args[0]

	fmt.Printf("Scanning '%s' ports 1-%d\n", target, Ports)

	ip := net.ParseIP(target)
	if ip == nil {
		log.Fatalf("failed to parse IP from: %s", target)
	}

	taskQueue := make(chan PortScanTask)
	taskResults := make(chan PortScanResults, Ports)

	for range Workers {
		go scan(taskQueue, taskResults)
	}
	for i := range Ports {
		if i == 0 {
			continue
		}
		task := PortScanTask{
			TargetIP: ip.To4(),
			Port:     i,
		}
		taskQueue <- task
	}
	close(taskQueue)
	fmt.Printf("Scan Results for: %v\n", ip)
	for range Ports - 1 {
		result := <-taskResults
		if result.State == PortStateOpen {
			fmt.Printf("Port: %-5d | State: %v | Error: %v\n", result.Port, result.State.String(), result.ErrorInfo)
		}
	}

	fmt.Println("Scan complete")
}
