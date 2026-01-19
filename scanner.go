package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/routing"
)

type scanner struct {
	netInterface *net.Interface
	sourceIP     net.IP
	targetIP     net.IP
	targetPorts  []layers.TCPPort
	sourcePort   layers.TCPPort
	gateway      net.IP
	handle       *pcap.Handle
	opts         gopacket.SerializeOptions
	buf          gopacket.SerializeBuffer
	timeout      time.Duration
}

func newScanner(targetIP string, targetPorts []int, sourcePort int32, router routing.Router, timeout time.Duration) (*scanner, error) {
	destIP := net.ParseIP(targetIP)
	if destIP == nil {
		return nil, fmt.Errorf("failed to parse destination IP '%s' for scanner", targetIP)
	}
	iface, gw, src, err := router.Route(destIP)
	if err != nil {
		return nil, fmt.Errorf("failed to get route to target, couldn not establish parameters for scanner: %w", err)
	}

	var ports []layers.TCPPort
	for _, p := range targetPorts {
		ports = append(ports, layers.TCPPort(p))
	}

	srcPort := layers.TCPPort(sourcePort)

	handle, err := pcap.OpenLive(iface.Name, sourcePort, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("failed to create handle for scanner: %w", err)
	}

	return &scanner{
		netInterface: iface,
		sourceIP:     src,
		targetIP:     destIP,
		sourcePort:   srcPort,
		targetPorts:  ports,
		gateway:      gw,
		handle:       handle,
		timeout:      timeout,
	}, nil
}

func (s *scanner) close() {
	s.handle.Close()
}

func (s *scanner) send(l ...gopacket.SerializableLayer) error {
	if err := gopacket.SerializeLayers(s.buf, s.opts, l...); err != nil {
		return fmt.Errorf("failed to serialize layer while sending packet: %w", err)
	}
	return s.handle.WritePacketData(s.buf.Bytes())
}

func (s *scanner) scan() {
	ip4 := layers.IPv4{
		SrcIP:    s.sourceIP,
		DstIP:    s.targetIP,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := layers.TCP{
		SrcPort: s.sourcePort,
		DstPort: 0,
		SYN:     true,
	}
	tcp.SetNetworkLayerForChecksum(&ip4)

	ipFlow := gopacket.NewFlow(layers.EndpointIPv4, s.targetIP, s.sourceIP)

	for _, port := range s.targetPorts {
		start := time.Now()
		tcp.DstPort = port
		if err := s.send(&ip4, &tcp); err != nil {
			log.Printf("error sending to port %v: %v", tcp.DstPort, err)
		}

		if time.Since(start) > s.timeout {
			log.Printf("timed out for %v", s.targetIP)
		}

		data, _, err := s.handle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		} else if err != nil {
			log.Printf("error reading packet: %v", err)
			continue
		}

		packet := gopacket.NewPacket(data, layers.LayerTypeTCP, gopacket.NoCopy)

		filterPacket(packet, ipFlow)

	}
}

func filterPacket(packet gopacket.Packet, ipFlow gopacket.Flow) {
	if net := packet.NetworkLayer(); net == nil {
	} else if net.NetworkFlow() != ipFlow {
	} else if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer == nil {
	} else if tcp, ok := tcpLayer.(*layers.TCP); !ok {
		panic("tcp layer is not tcp layer")
	} else if tcp.DstPort != 54321 {
	} else if tcp.RST {
		log.Printf("port %v closed", tcp.SrcPort)
	} else if tcp.SYN && tcp.ACK {
		log.Printf("port %v open", tcp.SrcPort)
	} else {
		log.Printf("ignoring useless packet")
	}
}
