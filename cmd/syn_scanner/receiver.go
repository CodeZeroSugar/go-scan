package main

import (
	"encoding/binary"
	"fmt"
	"syscall"
)

type TCPEvent struct {
	SrcIP   uint32
	DstIP   uint32
	SrcPort uint16
	DstPort uint16
	Flags   uint16
}

type Receiver struct {
	fd  int
	buf []byte
}

func NewReceiver() (*Receiver, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return nil, fmt.Errorf("failed to create receiver socket: %w", err)
	}

	buf := make([]byte, 65535)

	r := &Receiver{
		fd:  fd,
		buf: buf,
	}
	return r, nil
}

func (r *Receiver) Receive(out chan<- TCPEvent) {
	n, _, err := syscall.Recvfrom(r.fd, r.buf, 0)
	if err != nil {
		return
	}

	fmt.Println("Bytes received: ", n)
	fmt.Printf("% x\n", r.buf[:n])

	event := ParseTCP(r.buf[:n])
	out <- event
}

func ParseTCP(buf []byte) TCPEvent {
	if len(buf) < 20 {
		return TCPEvent{}
	}

	version := buf[0] >> 4
	if version != 4 {
		return TCPEvent{}
	}

	protocol := buf[9]
	if protocol != syscall.IPPROTO_TCP {
		return TCPEvent{}
	}

	ihl := (buf[0] & 0x0F) * 4
	if len(buf) < int(ihl+20) {
		return TCPEvent{}
	}

	tcp := buf[ihl:]

	srcIP := binary.BigEndian.Uint32(buf[12:16])
	dstIP := binary.BigEndian.Uint32(buf[16:20])

	srcPort := binary.BigEndian.Uint16(tcp[0:2])
	dstPort := binary.BigEndian.Uint16(tcp[2:4])

	flags := binary.BigEndian.Uint16(tcp[12:14]) & 0x01FF

	event := TCPEvent{
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: srcPort,
		DstPort: dstPort,
		Flags:   flags,
	}

	return event
}

func (t *TCPEvent) Filter() {
	syn := t.Flags&0x002 != 0
	ack := t.Flags&0x010 != 0
	rst := t.Flags&0x004 != 0

	switch {
	case syn && ack:
		fmt.Println("Port Open (SYN+ACK)")
	case rst:
		fmt.Println("Port Closed (RST)")
	default:
		fmt.Println("Other TCP packet")
	}
}
