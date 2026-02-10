package main

import (
	"bytes"
	"net"
	"slices"
)

func sortHosts(hosts []string) {
	slices.SortFunc(hosts, func(a, b string) int {
		ipA := net.ParseIP(a)
		ipB := net.ParseIP(b)

		if ipA == nil && ipB == nil {
			return 0
		}
		if ipA == nil {
			return 1
		}
		if ipB == nil {
			return -1
		}

		ipA = ipA.To16()
		ipB = ipB.To16()

		return bytes.Compare(ipA, ipB)
	})
}
