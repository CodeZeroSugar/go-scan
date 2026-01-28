package main

import (
	"fmt"
	"log"
)

const (
	TargetIP   = "172.28.19.171"
	TargetPort = 80
)

func main() {
	fmt.Printf("Sending TCP SYN to %s:%d\n", TargetIP, TargetPort)

	recv, err := NewReceiver()
	if err != nil {
		log.Fatalf("failed to establish receiver: %s", err)
	}

	tcpChan := make(chan TCPEvent)

	go recv.Receive(tcpChan)

	p, err := NewPacket("127.0.0.1", TargetIP, TargetPort)
	if err != nil {
		log.Fatalf("failed to create new packet: %s", err)
	}

	p.GeneratePacket()

	err = p.SendPacket()
	if err != nil {
		log.Printf("failed to send packet: %s", err)
	}

	event := <-tcpChan
	event.Filter()
}
