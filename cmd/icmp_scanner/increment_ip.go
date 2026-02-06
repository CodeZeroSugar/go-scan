package icmpscanner

import (
	"fmt"
	"net"
)

func incrementIP(current net.IP) (net.IP, error) {
	currentBytes := current.To4()
	if len(currentBytes) != 4 {
		return nil, fmt.Errorf("invalid IP address, cannot increment")
	}

	bytesCopy := make([]byte, 4)
	copy(bytesCopy, currentBytes)

	for i := 3; i >= 0; i-- {
		if bytesCopy[i] < 255 {
			bytesCopy[i]++
			return net.IP(bytesCopy), nil
		}
		bytesCopy[i] = 0
	}
	return nil, fmt.Errorf("IP overflow")
}
