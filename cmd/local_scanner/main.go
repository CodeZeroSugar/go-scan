package main

import (
	"fmt"
	"log"
	"net"
)

const (
	LoopBack = "127.0.0.1"
	Ports    = 20000
)

func main() {
	fmt.Printf("Scanning '%s' ports 1-%d\n", LoopBack, Ports)

	ip := net.ParseIP(LoopBack)
	if ip == nil {
		log.Fatalf("failed to parse IP from: %s", LoopBack)
	}

	port := 0

	for {

		if port >= Ports {
			break
		} else {
			port++
		}

		tcpAddrDst := net.TCPAddr{
			IP:   ip,
			Port: port,
		}

		conn, err := net.DialTCP("tcp", nil, &tcpAddrDst)
		if err != nil {
			if _, ok := err.(net.Error); ok {
				// log.Printf("connection attempt for port %v failed: %v", tcpAddrDst.Port, e)
			}
			continue
		}

		conn.Close()

		fmt.Printf("Connection to port %v was opened and closed successfully\n", tcpAddrDst.Port)

	}

	fmt.Println("Scan complete")
}
