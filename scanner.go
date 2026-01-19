package main

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket/layers"
)

type Scanner struct {
	TargetIP    net.IP
	TargetPorts []layers.TCPPort
	SourceIP    net.IP
	SourcePort  layers.TCPPort
	Timeout     time.Duration
}

func NewScanner(targetIP, sourceIP string, targetPorts []int, sourcePort int, timeout time.Duration) (*Scanner, error) {
	destIP := net.ParseIP(targetIP)
	if destIP == nil {
		return nil, fmt.Errorf("failed to parse destination IP '%s' for scanner", targetIP)
	}
	srcIP := net.ParseIP(sourceIP)

	var ports []layers.TCPPort
	for _, p := range targetPorts {
		ports = append(ports, layers.TCPPort(p))
	}

	srcPort := layers.TCPPort(sourcePort)

	return &Scanner{
		TargetIP:    destIP,
		TargetPorts: ports,
		SourceIP:    srcIP,
		SourcePort:  srcPort,
		Timeout:     timeout,
	}, nil
}
