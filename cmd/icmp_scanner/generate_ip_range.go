package icmpscanner

import (
	"bytes"
	"net"
)

func GenerateIPRange(start, end net.IP) <-chan net.IP {
	ch := make(chan net.IP, 128)
	go func() {
		defer close(ch)
		start4 := start.To4()
		end4 := end.To4()

		if start4 == nil || end4 == nil {
			return
		}

		current := make([]byte, 4)
		copy(current, start4)
		for bytes.Compare(current, end4) <= 0 {
			ch <- net.IP(current[:])
			if !incrementIP(current) {
				break
			}
		}
	}()
	return ch
}
