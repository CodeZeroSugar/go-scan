package main

import (
	"fmt"
	"strconv"
	"strings"
)

func parsePortOpts(params params) ([]int, int, error) {
	var portLen int
	var p []int
	switch params.portMode {
	case single:
		portLen = 1
		numStr := params.ports[0]
		num, err := strconv.Atoi(numStr)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid integer assigned to port: %w", err)
		}
		p = append(p, num)
	case selection:
		portLen = len(params.ports)
		for _, n := range params.ports {
			num, err := strconv.Atoi(n)
			if err != nil {
				return nil, 0, fmt.Errorf("invalid integer assigned to port: %w", err)
			}
			p = append(p, num)
		}
	case series:
		splitPorts := strings.Split(params.ports[0], "-")
		numLow, err := strconv.Atoi(splitPorts[0])
		if err != nil {
			return nil, 0, fmt.Errorf("invalid integer assigned to port: %w", err)
		}
		numHigh, err := strconv.Atoi(splitPorts[1])
		if err != nil {
			return nil, 0, fmt.Errorf("invalid integer assigned to port: %w", err)
		}
		portLen = numHigh - numLow
		p = append(p, numLow, numHigh)

	default:
		return nil, 0, fmt.Errorf("invalid integer assigned to port")
	}

	return p, portLen, nil
}
