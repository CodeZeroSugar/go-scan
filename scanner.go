package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
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

func getInterfaceAndSrcIP(dst net.IP) (*net.Interface, net.IP, error) {
	conn, err := net.Dial("udp", dst.String()+":53")
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	srcIP := localAddr.IP

	iface, err := interfaceByIP(srcIP)
	if err != nil {
		return nil, nil, err
	}

	return iface, srcIP, nil
}

func interfaceByIP(ip net.IP) (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if ipNet.IP.Equal(ip) {
				return &iface, nil
			}
		}
	}
	return nil, fmt.Errorf("no interface owns IP %s", ip)
}

func newScanner(targetIP net.IP, targetPorts []int, sourcePort int32, timeout time.Duration) (*scanner, error) {
	iface, src, err := getInterfaceAndSrcIP(targetIP)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface and source IP: %w", err)
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
		targetIP:     targetIP,
		sourcePort:   srcPort,
		targetPorts:  ports,
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

func (s *scanner) scan() error {
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
			return nil
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
	return nil
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
