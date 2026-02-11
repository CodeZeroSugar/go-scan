package tcpscanner

import (
	"context"
	"errors"
	"net"
	"strings"
)

func filterConnState(err error) (PortState, error) {
	if err == nil {
		return Open, nil
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return Filtered, err
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return Filtered, err
	}

	if isUnreachable(err) {
		return Unreachable, err
	}

	return Closed, err
}

func isUnreachable(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no route") || strings.Contains(msg, "unreachable")
}
