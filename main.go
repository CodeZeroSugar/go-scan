package main

import (
	"flag"
	"log"
	"net"
	"os"
	"time"

	"github.com/google/gopacket/examples/util"
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

	defer util.Run()()

	for _, arg := range flag.Args() {
		var ip net.IP
		if ip = net.ParseIP(arg); ip == nil {
			log.Printf("non-ip target: %q", arg)
			continue
		} else if ip = ip.To4(); ip == nil {
			log.Printf("non-ipv4 target: %q", arg)
			continue
		}

		s, err := newScanner(ip, []int{80}, 54321, time.Second*5)
		if err != nil {
			log.Printf("unable to create scanner for %v: %v", ip, err)
			continue
		}

		if err := s.scan(); err != nil {
			log.Printf("unable to scan %v: %v", ip, err)
		}
		s.close()
	}
}
