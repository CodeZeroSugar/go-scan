package main

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"os"
	"strings"
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

func getDefaultGateway(ifaceName string) (net.IP, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, fmt.Errorf("failed to open route file: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Scan()

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		if fields[0] != ifaceName {
			continue
		}
		if fields[1] != "00000000" {
			continue
		}

		gwHex := fields[2]
		b, err := hex.DecodeString(gwHex)
		if err != nil || len(b) != 4 {
			continue
		}

		return net.IPv4(b[3], b[2], b[1], b[0]), nil

	}
	return nil, fmt.Errorf("default gateway not found for %s", ifaceName)
}

func newScanner(targetIP net.IP, targetPorts []int, sourcePort int32, timeout time.Duration) (*scanner, error) {
	iface, src, err := getInterfaceAndSrcIP(targetIP)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface and source IP: %w", err)
	}
	gw, err := getDefaultGateway(iface.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to get gateway from interface: %w", err)
	}

	var ports []layers.TCPPort
	for _, p := range targetPorts {
		ports = append(ports, layers.TCPPort(p))
	}

	srcPort := layers.TCPPort(sourcePort)

	handle, err := pcap.OpenLive(iface.Name, 262144, true, time.Second*15)
	if err != nil {
		return nil, fmt.Errorf("failed to create handle for scanner: %w", err)
	}

	return &scanner{
		netInterface: iface,
		sourceIP:     src,
		targetIP:     targetIP,
		sourcePort:   srcPort,
		targetPorts:  ports,
		gateway:      gw,
		handle:       handle,
		buf:          gopacket.NewSerializeBuffer(),
		opts: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		timeout: timeout,
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

func isOnLink(srcIP, dstIP net.IP, iface *net.Interface) bool {
	addrs, err := iface.Addrs()
	if err != nil {
		return false
	}

	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if ipNet.Contains(dstIP) {
			return true
		}
	}
	return false
}

func (s *scanner) getHardwareAddress() (net.HardwareAddr, error) {
	start := time.Now()
	arpDst := s.targetIP
	if !isOnLink(s.sourceIP, s.targetIP, s.netInterface) {
		arpDst = s.gateway
	}

	srcProt := s.sourceIP.To4()
	if srcProt == nil {
		return nil, fmt.Errorf("non-IPv4 used for source address in ARP")
	}

	dstProt := arpDst.To4()
	if dstProt == nil {
		return nil, fmt.Errorf("non-IPv4 used for destination address in ARP")
	}

	eth := layers.Ethernet{
		SrcMAC:       s.netInterface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(s.netInterface.HardwareAddr),
		SourceProtAddress: []byte(srcProt),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(dstProt),
	}
	if err := s.send(&eth, &arp); err != nil {
		return nil, fmt.Errorf("failed to send arp request for hw address: %w", err)
	}
	for {
		if time.Since(start) > time.Second*3 {
			return nil, errors.New("ARP reply timed out")
		}
		data, _, err := s.handle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		} else if err != nil {
			return nil, fmt.Errorf("failed to read packet data for arp request: %w", err)
		}
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
		if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
			arp := arpLayer.(*layers.ARP)
			if net.IP(arp.SourceProtAddress).Equal(net.IP(arpDst)) {
				return net.HardwareAddr(arp.SourceHwAddress), nil
			}
		}
	}
}

func (s *scanner) scan() error {
	hwaddr, err := s.getHardwareAddress()
	if err != nil {
		return fmt.Errorf("failed to get destination hardware address: %w", err)
	}
	filter := "tcp"

	if err := s.handle.SetBPFFilter(filter); err != nil {
		return fmt.Errorf("failed to set filter")
	}

	eth := layers.Ethernet{
		SrcMAC:       s.netInterface.HardwareAddr,
		DstMAC:       hwaddr,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := layers.IPv4{
		SrcIP:    s.sourceIP,
		DstIP:    s.targetIP,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}

	for _, port := range s.targetPorts {
		tcp := layers.TCP{
			SrcPort: s.sourcePort,
			DstPort: port,
			SYN:     true,
			Seq:     rand.Uint32(),
			Window:  14600,
		}
		tcp.SetNetworkLayerForChecksum(&ip4)
		fmt.Printf("Scanning port @ %v:%v\n", s.targetIP, port)
		tcp.DstPort = port
		if err := s.send(&eth, &ip4, &tcp); err != nil {
			log.Printf("error sending to port %v: %v", tcp.DstPort, err)
		}

		deadline := time.Now().Add(s.timeout)

		for time.Now().Before(deadline) {
			data, _, err := s.handle.ReadPacketData()
			if err == pcap.NextErrorTimeoutExpired {
				continue
			} else if err != nil {
				log.Printf("error reading packet: %v", err)
				continue
			}

			packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)

			handlePacket(packet, port)

		}

	}
	fmt.Println("Scan complete.")
	return nil
}

func handlePacket(packet gopacket.Packet, sourcePort layers.TCPPort) {
	fmt.Println("handling packet...")
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}

	tcp := tcpLayer.(*layers.TCP)

	if tcp.DstPort != sourcePort {
		return
	}

	switch {
	case tcp.SYN && tcp.ACK:
		log.Printf("port %d OPEN", tcp.SrcPort)

	case tcp.RST:
		log.Printf("port %d CLOSED", tcp.SrcPort)
	default:
		log.Printf("tcp packet: src=%v dst=%v flags=S:%v A:%v R:%v", tcp.SrcPort, tcp.DstPort, tcp.SYN, tcp.ACK, tcp.RST)

	}
}
