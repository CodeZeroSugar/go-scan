// Package tcpscanner provides the code for the TCP port scanning functions of go-scan
package tcpscanner

import (
	"errors"
	"net"
	"strings"
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

		var state PortState
		var netErr net.Error
		var resultErr error

		d := net.Dialer{
			Timeout: 1 * time.Second,
		}

		conn, err := d.Dial("tcp", tcpAddrDst.String())
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
			TargetIP:  task.TargetIP,
			Port:      tcpAddrDst.Port,
			State:     state,
			ErrorInfo: resultErr,
		}

		resultQueue <- results
	}
}
