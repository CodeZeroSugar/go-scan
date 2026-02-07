package main

import (
	"errors"
	"flag"
	"fmt"
	"sort"
	"strconv"
	"strings"

	tcpscanner "github.com/CodeZeroSugar/go-scan/internal/scanners/tcp_scanner"
	"github.com/CodeZeroSugar/go-scan/internal/stats"
)

func handleFlags() tcpscanner.Params {
	var params tcpscanner.Params
	var targetVar string
	var portsVar string
	var snVar bool
	var statsVar bool
	flag.StringVar(&targetVar, "t", "127.0.0.1", "The IP Address you want to scan. Defaults to loopback.")
	flag.StringVar(&portsVar, "p", "1-1023", "Input a single port to scan only that port.\nSeparate ports with commas (no spaces) to scan those specific ports (22,54,80).\nProvide a range like '1-500' to scan all ports in that range.\nDefault is common ports.")
	flag.BoolVar(&snVar, "sn", false, "Toggle for discovery scan only.\nStandard scan uses discovery by default.\nUsing this flag will disable port scanning and only ping hosts specified by -t flag.")
	flag.BoolVar(&statsVar, "stats", false, "Display port stats. Cannot be used with other flags.\nOptions: top <n>, all\n")

	flag.Parse()
	params.Target = targetVar
	params.Stats = statsVar

	if strings.Contains(portsVar, ",") {
		params.PortMode = tcpscanner.Selection
		splitPorts := strings.Split(portsVar, ",")

		trimmedPorts := make([]string, 0)
		for _, port := range splitPorts {
			trimmedPorts = append(trimmedPorts, strings.TrimSpace(port))
		}
		params.Ports = trimmedPorts
	} else if strings.Contains(portsVar, "-") {
		params.PortMode = tcpscanner.Series
		params.Ports = append(params.Ports, strings.TrimSpace(portsVar))
	} else {
		params.PortMode = tcpscanner.Single
		params.Ports = append(params.Ports, portsVar)
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
