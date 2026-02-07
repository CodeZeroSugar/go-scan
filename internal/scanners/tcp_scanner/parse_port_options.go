package tcpscanner

import (
	"fmt"
	"strconv"
	"strings"
)

type Params struct {
	Target    string
	Ports     []string
	PortMode  PortMode
	Discovery bool
	Stats     bool
}

type PortMode int

const (
	Single PortMode = iota
	Selection
	Series
)

func ParsePortOpts(params Params) ([]int, int, error) {
	var portLen int
	var p []int
	switch params.PortMode {
	case Single:
		portLen = 1
		numStr := params.Ports[0]
		num, err := strconv.Atoi(numStr)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid integer assigned to port: %w", err)
		}
		p = append(p, num)
	case Selection:
		portLen = len(params.Ports)
		for _, n := range params.Ports {
			num, err := strconv.Atoi(n)
			if err != nil {
				return nil, 0, fmt.Errorf("invalid integer assigned to port: %w", err)
			}
			p = append(p, num)
		}
	case Series:
		splitPorts := strings.Split(params.Ports[0], "-")
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
