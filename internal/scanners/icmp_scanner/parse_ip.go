package icmpscanner

import (
	"bytes"
	"fmt"
	"net"
	"strings"
)

func ParseIPRange(input string) (start, end net.IP, err error) {
	var left string
	var right string

	if !strings.Contains(input, "-") {
		ip := net.ParseIP(strings.TrimSpace(input))
		if ip == nil {
			return nil, nil, fmt.Errorf("'%s' is an invalid IP", input)
		}
		return nil, ip, nil
	}
	splitIP := strings.SplitN(input, "-", 2)

	if len(splitIP) != 2 {
		return nil, nil, fmt.Errorf("invalid format for IP range")
	}

	left, right = strings.TrimSpace(splitIP[0]), strings.TrimSpace(splitIP[1])

	if len(right) == 0 {
		end := net.ParseIP(left)
		if end == nil {
			return nil, nil, fmt.Errorf("'%s' is an invalid IP", splitIP[0])
		}
		return nil, end, nil
	}

	if !strings.Contains(splitIP[1], ".") {
		s := strings.SplitAfter(splitIP[0], ".")
		right = s[0] + s[1] + s[2] + right
	}

	start = net.ParseIP(left)
	if start == nil {
		return nil, nil, fmt.Errorf("'%s' is an invalid IP", start)
	}
	end = net.ParseIP(right)
	if end == nil {
		return nil, nil, fmt.Errorf("'%s' is an invalid IP", end)
	}
	if bytes.Compare(start, end) > 0 {
		return nil, nil, fmt.Errorf("start IP is after end IP")
	}
	return start, end, nil
}
