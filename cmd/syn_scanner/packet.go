package main

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"syscall"
)

type LayerIP struct {
	SrcIP   string
	DstIP   string
	Protcol string
}

type LayerTCP struct {
	SrcPort  int
	DstPort  int
	Seq      int32
	Flags    int
	Window   int
	Checksum int
}

type Packet struct {
	IP  LayerIP
	TCP LayerTCP
}

type RawSocket struct {
	Fd int
}

func (p *Packet) CalculateChecksum() ([]byte, error) {
	buf := new(bytes.Buffer)
}

func (p *Packet) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	err := enc.Encode(p.IP)
	if err != nil {
		return nil, fmt.Errorf("failed to encode IP header: %w", err)
	}
	err = enc.Encode(p.TCP)
	if err != nil {
		return nil, fmt.Errorf("failed to encode TCP header: %w", err)
	}
	return buf.Bytes(), nil
}

func (r *RawSocket) Send(p []byte, to syscall.Sockaddr, packet *Packet) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return fmt.Errorf("failed to create socket: %w", err)
	}
	err = syscall.SetsockoptString(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, "1")
	if err != nil {
		return fmt.Errorf("failed to set socket opt: %w", err)
	}

	err = syscall.Sendto(fd, p, packet.TCP.Flags, to)
	if err != nil {
		return fmt.Errorf("failed to send packet over raw socket: %w", err)
	}

	return nil
}
