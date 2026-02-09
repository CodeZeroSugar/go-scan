// Package icmpscanner provides GoScan's host discovery functions
package icmpscanner

import (
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func Ping(ipAddr net.IP) (bool, error) {
	const timeout = 1 * time.Second
	c, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		return false, fmt.Errorf("failed to establish icmp packet connection: %w", err)
	}

	err = c.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return false, fmt.Errorf("failed to set timeout: %w", err)
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
		return false, fmt.Errorf("failed to marshal message bytes: %w", err)
	}
	if _, err := c.WriteTo(wb, &net.UDPAddr{IP: ipAddr, Zone: "eth0"}); err != nil {
		return false, fmt.Errorf("failed to write bytes for icmp: %w", err)
	}

	rb := make([]byte, 1500)
	n, _, err := c.ReadFrom(rb)
	if err != nil {
		return false, fmt.Errorf("failed to read bytes returned from icmp: %w", err)
	}
	rm, err := icmp.ParseMessage(ipv4.ICMPTypeEcho.Protocol(), rb[:n])
	if err != nil {
		return false, fmt.Errorf("failed to parse icmp return message: %w", err)
	}
	switch rm.Type {
	case ipv4.ICMPTypeEchoReply:
		return true, nil
	default:
		return false, fmt.Errorf("got %+v; want echo reply", rm)
	}
}
