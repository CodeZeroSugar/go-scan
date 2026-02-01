package main

import (
	"flag"
	"strings"
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
}

func handleFlags() params {
	var params params
	var targetVar string
	var portsVar string
	flag.StringVar(&targetVar, "t", "127.0.0.1", "The IP Address you want to scan. Defaults to loopback.")
	flag.StringVar(&portsVar, "p", "1-1023", "Input a single port to scan only that port.\nSeparate ports with commas (no spaces) to scan those specific ports (22,54,80).\nProvide a range like '1-500' to scan all ports in that range.\nDefault is common ports.")

	flag.Parse()
	params.target = targetVar

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
