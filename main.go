package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
)

const Address = "golang.org:80"

func main() {
	conn, err := net.Dial("tcp", Address)
	if err != nil {
		log.Printf("failed to connect to '%s':%s", Address, err)
	}

	fmt.Fprintf(conn, "GET / HTTP/1.0\r\n\r\n")

	status, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		log.Printf("failed to read from connection: %s", err)
	}

	fmt.Println(status)
}
