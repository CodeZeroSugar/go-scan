// Package icmpscanner provides GoScan's host discovery functions
package icmpscanner

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const testIP = "192.168.0.168"

func ping(ipAddr string) error {
	c, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		return fmt.Errorf("failed to establish icmp packet connection: %w", err)
	}
	defer c.Close()

	wm := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: os.Getpid() & 0xffff, Seq: 1,
			Data: []byte("HELLO-R-U-THERE"),
		},
	}

	wb, err := wm.Marshal(nil)
	if err != nil {
		return fmt.Errorf("failed to marshal message bytes: %w", err)
	}
	if _, err := c.WriteTo(wb, &net.UDPAddr{IP: net.ParseIP(ipAddr), Zone: "eth0"}); err != nil {
		return fmt.Errorf("failed to write bytes for icmp: %w", err)
	}

	rb := make([]byte, 1500)
	n, peer, err := c.ReadFrom(rb)
	if err != nil {
		return fmt.Errorf("failed to read bytes returned from icmp: %w", err)
	}
	rm, err := icmp.ParseMessage(ipv4.ICMPTypeEcho.Protocol(), rb[:n])
	if err != nil {
		return fmt.Errorf("failed to parse icmp return message: %w", err)
	}
	switch rm.Type {
	case ipv4.ICMPTypeEchoReply:
		fmt.Printf("got reflection from %v", peer)
	default:
		return fmt.Errorf("got %+v; want echo reply", rm)
	}
	return nil
}
