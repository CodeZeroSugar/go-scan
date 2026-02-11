// Package tcpscanner provides the code for the TCP port scanning functions of go-scan
package tcpscanner

import (
	"net"
	"time"
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
	TargetIP  net.IP
	Port      int
	State     PortState
	ErrorInfo error
}

func Scan(taskQueue chan PortScanTask, resultQueue chan PortScanResults) {
	for {
		task, ok := <-taskQueue
		if !ok {
			return
		}

		tcpAddrDst := net.TCPAddr{
			IP:   task.TargetIP,
			Port: task.Port,
		}

		d := net.Dialer{
			Timeout: 2 * time.Second,
		}

		conn, err := d.Dial("tcp", tcpAddrDst.String())

		state, resultErr := filterConnState(err)
		if conn != nil {
			conn.Close()
		}

		results := PortScanResults{
			TargetIP:  task.TargetIP,
			Port:      tcpAddrDst.Port,
			State:     state,
			ErrorInfo: resultErr,
		}

		resultQueue <- results
	}
}
