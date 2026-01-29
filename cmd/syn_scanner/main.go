package main

import (
	"fmt"
	"log"
)

const (
	TargetIP   = "192.168.0.168"
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
	switch event.Classify() {
	case TCPOpen:
		fmt.Println("Port Open")

		rst := TCPSegment{
			SrcPort:    p.TCPSeg.SrcPort,
			DstPort:    p.TCPSeg.DstPort,
			SeqNumber:  event.Ack,
			AckNumber:  event.Seq + 1,
			DataOffset: 5,
			Flags: TCPFlags{
				RST: 1,
				ACK: 1,
			},
		}

		p.TCPSeg = rst
		p.GeneratePacket()
		err = p.SendPacket()
		if err != nil {
			log.Printf("failed to send RST")
		}
	case TCPClosed:
		fmt.Println("Port Closed")
	}
}
