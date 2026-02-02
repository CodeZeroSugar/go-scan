package main

import (
	"errors"
	"flag"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/CodeZeroSugar/go-scan/internal/stats"
)

type portMode int

const (
	single portMode = iota
	selection
	series
)

type params struct {
	target   string
	ports    []string
	portMode portMode
	stats    bool
}

func handleFlags() params {
	var params params
	var targetVar string
	var portsVar string
	var statsVar bool
	flag.StringVar(&targetVar, "t", "127.0.0.1", "The IP Address you want to scan. Defaults to loopback.")
	flag.StringVar(&portsVar, "p", "1-1023", "Input a single port to scan only that port.\nSeparate ports with commas (no spaces) to scan those specific ports (22,54,80).\nProvide a range like '1-500' to scan all ports in that range.\nDefault is common ports.")
	flag.BoolVar(&statsVar, "stats", false, "Display port stats. Cannot be used with other flags.\nOptions: top <n>, all\n")

	flag.Parse()
	params.target = targetVar
	params.stats = statsVar

	if strings.Contains(portsVar, ",") {
		params.portMode = selection
		splitPorts := strings.Split(portsVar, ",")

		trimmedPorts := make([]string, 0)
		for _, port := range splitPorts {
			trimmedPorts = append(trimmedPorts, strings.TrimSpace(port))
		}
		params.ports = trimmedPorts
	} else if strings.Contains(portsVar, "-") {
		params.portMode = series
		params.ports = append(params.ports, strings.TrimSpace(portsVar))
	} else {
		params.portMode = single
		params.ports = append(params.ports, portsVar)
	}

	return params
}

func handleStats(args []string, statPath string) error {
	if len(args) == 0 {
		return fmt.Errorf("need to provide options for stats flag (top <n>, all)")
	}
	stats, err := stats.RetrieveStats(statPath)
	if err != nil {
		return fmt.Errorf("failed to retreive stats: %w", err)
	}
	type PortCount struct {
		Port  int
		Count int
	}
	var portCounts []PortCount
	for port, ps := range stats.Ports {
		portCounts = append(portCounts, PortCount{
			Port:  port,
			Count: ps.Count,
		})
	}

	sort.Slice(portCounts, func(i, j int) bool {
		return portCounts[i].Count > portCounts[j].Count
	})

	if args[0] == "all" {
		fmt.Printf("Displaying all open ports:\n")
		for _, pc := range portCounts {
			fmt.Printf("Port %5d : count %d\n", pc.Port, pc.Count)
		}
		return nil
	}
	if args[0] == "top" {
		var n int
		if len(args) < 2 {
			n = 10
		} else {
			num, err := strconv.Atoi(args[1])
			if err != nil {
				return errors.New("-stats top <n> requires 'n' to be an integer")
			}
			n = num
		}
		if len(portCounts) < n {
			n = len(portCounts)
		}
		fmt.Printf("Display Top %d open ports:\n", n)
		for i := 0; i < n; i++ {
			pc := portCounts[i]
			fmt.Printf("Port %5d : count %d\n", pc.Port, pc.Count)
		}
		return nil
	}

	return fmt.Errorf("'%s' is not a valid option for stats", args[0])
}
