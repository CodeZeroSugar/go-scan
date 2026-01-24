package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
)

type Packet struct {
	IPSeg        IPSegment
	TCPSeg       TCPSegment
	TmpIPHeader  []byte
	TmpTCPHeader []byte
	Packet       []byte
}

type IPSegment struct {
	Version        uint8
	IHL            uint8
	TypeOfService  uint8
	TotalLength    uint16
	Identification uint16
	Flags          int
	FragmentOffset int
	TTL            uint8
	Protocol       uint8
	HeaderChecksum uint16
	SrcAddr        uint32
	DstAddr        uint32
	VIHL           uint8
	FFO            int
}

type TCPSegment struct {
	SrcPort                                    uint16
	DstPort                                    uint16
	SeqNumber                                  uint32
	AckNumber                                  uint32
	DataOffset                                 uint8
	Reserved                                   uint8
	NS, CWR, ECE, URG, ACK, PSH, RST, SYN, FIN uint8
	WindowSize                                 uint16
	Checksum                                   uint16
	UrgPointer                                 uint16
	DataOffsetResFlags                         uint8
}

func ipToInt(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func (i *IPSegment) setCalculatedFields() {
	i.VIHL = (i.Version << 4) + i.IHL
	i.FFO = (i.Flags << 13) + i.FragmentOffset
}

func (t *TCPSegment) setDataOffsetResFlags() {
	t.DataOffsetResFlags = (t.DataOffset << 12) + (t.Reserved << 9) + (t.NS << 8) + (t.CWR << 7) + (t.ECE << 6) + (t.URG << 5) + (t.ACK << 4) + (t.PSH << 3) + (t.RST << 2) + (t.SYN << 1) + t.FIN
}

func (p *Packet) CalcChecksum(msg []byte) uint16 {
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

func (p *Packet) GenerateTempIPHeader() error {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, "!BBHHHBBH4s4s")
	err := binary.Write(buf, binary.BigEndian, p.IPSeg)
	if err != nil {
		return fmt.Errorf("failed to write temp IP header to buffer: %w", err)
	}
	p.TmpIPHeader = buf.Bytes()
	return nil
}

func (p *Packet) GenerateTempTCPHeader() error {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, "!HHLLHHH")
	err := binary.Write(buf, binary.BigEndian, p.TCPSeg)
	if err != nil {
		return fmt.Errorf("failed to write temp TCP header to buffer: %w", err)
	}
	p.TmpTCPHeader = buf.Bytes()
	return nil
}

func NewPacket(srcIP, dstIP string, dstPort int) (*Packet, error) {
	srcAddr := net.ParseIP(srcIP)
	if srcAddr == nil {
		return nil, fmt.Errorf("failed to parse '%s' to address", srcIP)
	}
	intSrcAddr := ipToInt(srcAddr.To4())
	dstAddr := net.ParseIP(dstIP)
	if dstAddr == nil {
		return nil, fmt.Errorf("failed to parse '%s' to address", srcIP)
	}
	intDstAddr := ipToInt(dstAddr.To4())

	ip := IPSegment{
		Version:        0x4,
		IHL:            0x5,
		TypeOfService:  0x0,
		TotalLength:    0x28,
		Identification: 0xabcd,
		Flags:          0x0,
		FragmentOffset: 0x0,
		TTL:            0x40,
		Protocol:       0x6,
		HeaderChecksum: 0x0,
		SrcAddr:        intSrcAddr,
		DstAddr:        intDstAddr,
	}
	ip.setCalculatedFields()

	tcp := TCPSegment{
		SrcPort:    0x3039,
		DstPort:    dstPort,
		SeqNumber:  0x0,
		AckNumber:  0x0,
		DataOffset: 0x5,
		Reserved:   0x0,
		NS:         0x0,
		CWR:        0x0,
		ECE:        0x0,
		URG:        0x0,
		ACK:        0x0,
		PSH:        0x0,
		RST:        0x0,
		SYN:        0x1,
		FIN:        0x0,
		Checksum:   0x0,
		UrgPointer: 0x0,
	}
	tcp.setDataOffsetResFlags()

	packet := Packet{
		IPSeg:  ip,
		TCPSeg: tcp,
		Buffer: make([]byte, 0),
	}

	return &packet, nil
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
