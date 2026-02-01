package main

import (
	"errors"
	"net"
	"strings"
)

//go:generate stringer -type=PortState
type PortState int

const (
	Open PortState = iota
	Closed
	Filtered
	Unreachable
)

type PortScanTask struct {
	TargetIP net.IP
	Port     int
	// Timeout  time.Duration
}

type PortScanResults struct {
	Port      int
	State     PortState
	ErrorInfo error
}

func scan(taskQueue chan PortScanTask, resultQueue chan PortScanResults) {
	for {
		task, ok := <-taskQueue
		if !ok {
			return
		}

		tcpAddrDst := net.TCPAddr{
			IP:   task.TargetIP,
			Port: task.Port,
		}

		var state PortState
		var netErr net.Error
		var resultErr error

		conn, err := net.DialTCP("tcp", nil, &tcpAddrDst)
		if err == nil {
			state = Open
			resultErr = nil
			conn.Close()
		} else {
			if errors.As(err, &netErr) && netErr.Timeout() {
				state = Filtered
				resultErr = netErr
			} else if strings.Contains(err.Error(), "unreachable") {
				state = Unreachable
				resultErr = err
			} else {
				state = Closed
				resultErr = err
			}
		}

		results := PortScanResults{
			Port:      tcpAddrDst.Port,
			State:     state,
			ErrorInfo: resultErr,
		}

		resultQueue <- results
	}
}
