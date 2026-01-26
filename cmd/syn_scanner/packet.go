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
	Destination  net.IP
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

func (p *Packet) GenerateTempIPHeader() error {
	buf := new(bytes.Buffer)
	tmpIPHeader := struct {
		vIhl      uint8
		tos       uint8
		tLength   uint16
		id        uint16
		fFO       int
		ttl       uint8
		protocol  uint8
		hChecksum uint16
		srcAddr   uint32
		dstAddr   uint32
	}{
		vIhl:      p.IPSeg.VIHL,
		tos:       p.IPSeg.TypeOfService,
		tLength:   p.IPSeg.TotalLength,
		id:        p.IPSeg.Identification,
		fFO:       p.IPSeg.FFO,
		ttl:       p.IPSeg.TTL,
		protocol:  p.IPSeg.Protocol,
		hChecksum: p.IPSeg.HeaderChecksum,
		srcAddr:   p.IPSeg.SrcAddr,
		dstAddr:   p.IPSeg.DstAddr,
	}
	err := binary.Write(buf, binary.BigEndian, tmpIPHeader)
	if err != nil {
		return fmt.Errorf("failed to write temp IP header to buffer: %w", err)
	}
	p.TmpIPHeader = buf.Bytes()
	return nil
}

func (p *Packet) GenerateTempTCPHeader() error {
	buf := new(bytes.Buffer)
	tmpTCPHeader := struct {
		srcPort            uint16
		dstPort            uint16
		seqNo              uint32
		ackNo              uint32
		dataOffsetResFlags uint8
		windowSize         uint16
		checksum           uint16
		urgPointer         uint16
	}{
		srcPort:            p.TCPSeg.SrcPort,
		dstPort:            p.TCPSeg.DstPort,
		seqNo:              p.TCPSeg.SeqNumber,
		ackNo:              p.TCPSeg.AckNumber,
		dataOffsetResFlags: p.TCPSeg.DataOffsetResFlags,
		windowSize:         p.TCPSeg.WindowSize,
		checksum:           p.TCPSeg.Checksum,
		urgPointer:         p.TCPSeg.UrgPointer,
	}
	err := binary.Write(buf, binary.BigEndian, tmpTCPHeader)
	if err != nil {
		return fmt.Errorf("failed to write temp TCP header to buffer: %w", err)
	}
	p.TmpTCPHeader = buf.Bytes()
	return nil
}

func (p *Packet) GeneratePacket() error {
	finalIP := new(bytes.Buffer)
	p.IPSeg.HeaderChecksum = CalcChecksum(p.TmpTCPHeader)
	ipHeader := struct {
		vIhl      uint8
		tos       uint8
		tLength   uint16
		id        uint16
		fFO       int
		ttl       uint8
		protocol  uint8
		hChecksum uint16
		srcAddr   uint32
		dstAddr   uint32
	}{
		vIhl:      p.IPSeg.VIHL,
		tos:       p.IPSeg.TypeOfService,
		tLength:   p.IPSeg.TotalLength,
		id:        p.IPSeg.Identification,
		fFO:       p.IPSeg.FFO,
		ttl:       p.IPSeg.TTL,
		protocol:  p.IPSeg.Protocol,
		hChecksum: p.IPSeg.HeaderChecksum,
		srcAddr:   p.IPSeg.SrcAddr,
		dstAddr:   p.IPSeg.DstAddr,
	}
	err := binary.Write(finalIP, binary.BigEndian, ipHeader)
	if err != nil {
		return fmt.Errorf("failed to write final IP header to buffer: %w", err)
	}

	pseudoHeader := new(bytes.Buffer)
	err = p.GenerateTempTCPHeader()
	psuedo := struct {
		srcAddr      uint32
		dstAddr      uint32
		checksum     uint16
		protocol     uint8
		lenTCPHeader int
	}{
		srcAddr:      p.IPSeg.SrcAddr,
		dstAddr:      p.IPSeg.DstAddr,
		checksum:     p.TCPSeg.Checksum,
		protocol:     p.IPSeg.Protocol,
		lenTCPHeader: len(p.TmpTCPHeader),
	}
	if err != nil {
		return fmt.Errorf("failed to generate temp TCP header: %w", err)
	}
	err = binary.Write(pseudoHeader, binary.BigEndian, psuedo)
	if err != nil {
		return fmt.Errorf("failed to write psuedoheader: %w", err)
	}

	psh := append(pseudoHeader.Bytes(), p.TmpTCPHeader...)
	finalTCP := new(bytes.Buffer)
	fTCP := struct {
		srcPort            uint16
		dstPort            uint16
		seqNo              uint32
		ackNo              uint32
		dataOffsetResFlags uint8
		windowSize         uint16
		checksum           uint16
		urgPointer         uint16
	}{
		srcPort:            p.TCPSeg.SrcPort,
		dstPort:            p.TCPSeg.DstPort,
		seqNo:              p.TCPSeg.SeqNumber,
		ackNo:              p.TCPSeg.AckNumber,
		dataOffsetResFlags: p.TCPSeg.DataOffsetResFlags,
		windowSize:         p.TCPSeg.WindowSize,
		checksum:           CalcChecksum(psh),
		urgPointer:         p.TCPSeg.UrgPointer,
	}
	err = binary.Write(finalTCP, binary.BigEndian, fTCP)
	if err != nil {
		return fmt.Errorf("failed to write final tcp header %w", err)
	}
	pack := append(finalIP.Bytes(), finalTCP.Bytes()...)
	p.Packet = pack

	return nil
}

func (p *Packet) SendPacket() error {
	s, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return fmt.Errorf("failed to create socket: %w", err)
	}
	err = syscall.SetsockoptString(s, syscall.IPPROTO_IP, syscall.IP_HDRINCL, "1")
	if err != nil {
		return fmt.Errorf("failed to set socket opt: %w", err)
	}
	var dstAddr [4]byte
	copy(dstAddr[:], p.Destination.To4())
	to := syscall.SockaddrInet4{
		Port: int(p.TCPSeg.DstPort),
		Addr: dstAddr,
	}

	err = syscall.Sendto(s, p.Packet, p.IPSeg.Flags, &to)
	if err != nil {
		return fmt.Errorf("failed to send packet over raw socket: %w", err)
	}

	return nil
}

func NewPacket(srcIP, dstIP string, dstPort uint16) (*Packet, error) {
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
		IPSeg:       ip,
		TCPSeg:      tcp,
		Destination: dstAddr,
	}

	return &packet, nil
}
