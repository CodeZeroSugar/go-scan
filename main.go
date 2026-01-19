package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	SrcAddress  = "127.0.0.1"
	DestAddress = "127.0.0.1"
	DestPort    = 80
)

func main() {
	if os.Getuid() != 0 {
		log.Fatalln("Must run as root")
	}

	dstIP := net.ParseIP(DestAddress)
	if dstIP == nil {
		log.Fatalln("Invalid IP")
	}

	srcIP := net.ParseIP(SrcAddress)
	srcPort := layers.TCPPort(44444)
	dstPort := layers.TCPPort(DestPort)

	ip := &layers.IPv4{
		Version:    4,
		IHL:        5,
		TOS:        0,
		Length:     0,
		Id:         0x1337,
		Flags:      layers.IPv4DontFragment,
		FragOffset: 0,
		TTL:        64,
		Protocol:   layers.IPProtocolTCP,
		SrcIP:      srcIP,
		DstIP:      dstIP,
	}

	tcp := &layers.TCP{
		SrcPort:    srcPort,
		DstPort:    dstPort,
		Seq:        0x12345678 + uint32(time.Now().UnixNano()),
		Ack:        0,
		DataOffset: 5,
		Window:     64240,
		Checksum:   0,
		URG:        false,
		ACK:        false,
		PSH:        false,
		RST:        false,
		SYN:        true,
		FIN:        false,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err := tcp.SetNetworkLayerForChecksum(ip)
	if err != nil {
		log.Fatalf("failed to set network layer for checksum: %v", err)
	}

	err = gopacket.SerializeLayers(
		buf,
		opts,
		ip,
		tcp,
	)
	if err != nil {
		log.Fatalf("Serialize failed: %v", err)
	}

	packetData := buf.Bytes()

	conn, err := net.ListenPacket("ip4:tcp", DestAddress)
	if err != nil {
		log.Fatalf("ListenPacket failed: %v", err)
	}
	defer conn.Close()

	dstAddr := &net.IPAddr{IP: dstIP}
	n, err := conn.WriteTo(packetData, dstAddr)
	if err != nil {
		log.Fatalf("WriteTo failed: %v", err)
	}

	fmt.Printf("Sent %d byte to TCP SYN -> %s:%d\n", n, dstIP, dstPort)
	listen(DestAddress, DestPort)
}
