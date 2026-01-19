package main

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func listen(remoteIP string, remotePort int) error {
	localIP := net.ParseIP(SrcAddress)
	localPort := layers.TCPPort(44444)
	targetIP := net.ParseIP(remoteIP)
	targetPort := layers.TCPPort(DestPort)

	handle, err := pcap.OpenLive("any", 1600, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to start live capture: %w", err)
	}
	defer handle.Close()

	filter := fmt.Sprintf("tcp and src host %s and dst host %s and src port %d and dst port %d and tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)",
		remoteIP, localIP, remotePort, localPort)

	if err := handle.SetBPFFilter(filter); err != nil {
		return fmt.Errorf("failed to set BPFF filter: %w", err)
	}

	fmt.Printf("Listening for SYN-ACK from %s:%d -> %s:%d ...\n", targetIP, targetPort, SrcAddress, 44444)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			// tcp, _ := tcpLayer.(*layers.TCP)

			fmt.Printf("SYN-ACK Received\n")
		}
	}

	return nil
}
