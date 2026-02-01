package main

import "flag"

type params struct {
	target string
	ports  int
	root   bool
}

func handleFlags() (params, error) {
	var params params

	targetPtr := flag.String("t", "127.0.0.1", "The IP Address you want to scan. Defaults to loopback.")

	func init {
		const (
			defaultPorts =	 
		)
	portsPtr := flag.Int("p", 1023, "")

	}
}
