package main

import (
	"errors"
	"net"
	"strings"
)

type PortState int

const (
	PortStateOpen        = 0
	PortStateClosed      = 1
	PortStateFiltered    = 2
	PortStateUnreachable = 3
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
			state = PortStateOpen
			resultErr = nil
			conn.Close()
		} else {
			if errors.As(err, &netErr) && netErr.Timeout() {
				state = PortStateFiltered
				resultErr = netErr
			} else if strings.Contains(err.Error(), "unreachable") {
				state = PortStateUnreachable
				resultErr = err
			} else {
				state = PortStateClosed
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
