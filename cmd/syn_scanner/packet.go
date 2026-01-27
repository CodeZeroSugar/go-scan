package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
)

type TCPFlags uint16

const (
	tcpFIN TCPFlags = 1 << 0
	tcpSYN TCPFlags = 1 << 1
	tcpRST TCPFlags = 1 << 2
	tcpPSH TCPFlags = 1 << 3
	tcpACK TCPFlags = 1 << 4
	tcpURG TCPFlags = 1 << 5
	tcpECE TCPFlags = 1 << 6
	tcpCWR TCPFlags = 1 << 7
	tcpNS  TCPFlags = 1 << 8
)

func packOffsetFlags(offset uint8, flags uint16) uint16 {
	return uint16(offset)<<12 | (flags & 0x0FFF)
}

type Packet struct {
	IPSeg       IPSegment
	TCPSeg      TCPSegment
	Destination net.IP
	Bytes       []byte
}

type IPSegment struct {
	Version        uint8
	IHL            uint8
	TypeOfService  uint8
	TotalLength    uint16
	Identification uint16
	Flags          uint8
	FragmentOffset uint16
	TTL            uint8
	Protocol       uint8
	SrcAddr        uint32
	DstAddr        uint32
}

type TCPSegment struct {
	SrcPort    uint16
	DstPort    uint16
	SeqNumber  uint32
	AckNumber  uint32
	DataOffset uint8
	Flags      TCPFlags
	WindowSize uint16
	UrgPointer uint16
}

func CalcChecksum(msg []byte) uint16 {
	var s uint32
	for i := 0; i < len(msg); i += 2 {
		s += uint32(msg[i])<<8 | uint32(msg[i+1])
	}
	if len(msg)%2 == 1 {
		s += uint32(msg[len(msg)-1]) << 8
	}
	for s>>16 > 0 {
		s = (s >> 16) + (s & 0xffff)
	}
	return ^uint16(s)
}

func buildPsuedoHeader(srcIP, dstIP uint32, tcpSegment []byte) []byte {
	psh := make([]byte, 12+len(tcpSegment))

	binary.BigEndian.PutUint32(psh[0:4], srcIP)
	binary.BigEndian.PutUint32(psh[4:8], dstIP)

	psh[8] = 0
	psh[9] = syscall.IPPROTO_TCP

	binary.BigEndian.PutUint16(psh[10:12], uint16(len(tcpSegment)))

	copy(psh[12:], tcpSegment)

	return psh
}

func (i *IPSegment) Marshal() []byte {
	buf := make([]byte, 20)

	buf[0] = (i.Version << 4) | i.IHL
	buf[1] = i.TypeOfService

	flags := uint16(i.Flags&0x7) << 13
	frag := i.FragmentOffset & 0x1FFF

	binary.BigEndian.PutUint16(buf[2:4], i.TotalLength)
	binary.BigEndian.PutUint16(buf[4:6], i.Identification)
	binary.BigEndian.PutUint16(buf[6:8], flags|frag)
	buf[8] = i.TTL
	buf[9] = i.Protocol
	binary.BigEndian.PutUint16(buf[10:12], 0) // checksum
	binary.BigEndian.PutUint32(buf[12:16], i.SrcAddr)
	binary.BigEndian.PutUint32(buf[16:20], i.DstAddr)

	csum := CalcChecksum(buf)
	binary.BigEndian.PutUint16(buf[10:12], csum)

	return buf
}

func (t *TCPSegment) Marshal(srcIP, dstIP uint32) []byte {
	buf := make([]byte, 20)

	binary.BigEndian.PutUint16(buf[0:2], t.SrcPort)
	binary.BigEndian.PutUint16(buf[2:4], t.DstPort)
	binary.BigEndian.PutUint32(buf[4:8], t.SeqNumber)
	binary.BigEndian.PutUint32(buf[8:12], t.AckNumber)

	flags := packOffsetFlags(t.DataOffset, uint16(t.Flags))
	binary.BigEndian.PutUint16(buf[12:14], flags)

	binary.BigEndian.PutUint16(buf[14:16], t.WindowSize)
	binary.BigEndian.PutUint16(buf[16:18], 0)
	binary.BigEndian.PutUint16(buf[18:20], t.UrgPointer)

	psh := buildPsuedoHeader(srcIP, dstIP, buf)
	csum := CalcChecksum(psh)
	binary.BigEndian.PutUint16(buf[16:18], csum)

	return buf
}

func (p *Packet) GeneratePacket() {
	ipBytes := p.IPSeg.Marshal()
	tcpBytes := p.TCPSeg.Marshal(p.IPSeg.SrcAddr, p.IPSeg.DstAddr)
	p.Bytes = append(ipBytes, tcpBytes...)
}

func (p *Packet) SendPacket() error {
	s, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return fmt.Errorf("failed to create socket: %w", err)
	}
	defer syscall.Close(s)
	err = syscall.SetsockoptString(s, syscall.IPPROTO_IP, syscall.IP_HDRINCL, "1")
	if err != nil {
		return fmt.Errorf("failed to set socket opt: %w", err)
	}
	var dstAddr [4]byte
	copy(dstAddr[:], p.Destination.To4())

	to := &syscall.SockaddrInet4{
		Addr: dstAddr,
	}

	err = syscall.Sendto(s, p.Bytes, 0, to)
	if err != nil {
		return fmt.Errorf("failed to send packet over raw socket: %w", err)
	}

	return nil
}

func NewPacket(srcIP, dstIP string, dstPort uint16) (*Packet, error) {
	srcAddr := net.ParseIP(srcIP).To4()
	if srcAddr == nil {
		return nil, fmt.Errorf("failed to parse '%s' to address", srcIP)
	}
	dstAddr := net.ParseIP(dstIP).To4()
	if dstAddr == nil {
		return nil, fmt.Errorf("failed to parse '%s' to address", srcIP)
	}

	ip := IPSegment{
		Version:        0x4,
		IHL:            0x5,
		TypeOfService:  0x0,
		TotalLength:    0x0,
		Identification: 0xabcd,
		Flags:          0x0,
		FragmentOffset: 0x0,
		TTL:            64,
		Protocol:       syscall.IPPROTO_TCP,
		SrcAddr:        binary.BigEndian.Uint32(srcAddr),
		DstAddr:        binary.BigEndian.Uint32(dstAddr),
	}

	tcp := TCPSegment{
		SrcPort:    12345,
		DstPort:    dstPort,
		SeqNumber:  0x0,
		AckNumber:  0x0,
		DataOffset: 0x5,
		WindowSize: 65535,
		UrgPointer: 0x0,
	}

	packet := &Packet{
		IPSeg:       ip,
		TCPSeg:      tcp,
		Destination: dstAddr,
	}

	return packet, nil
}
