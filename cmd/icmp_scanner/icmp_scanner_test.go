package icmpscanner

import (
	"testing"
)

func TestPing(t *testing.T) {
	err := ping(testIP)
	if err != nil {
		t.Errorf("ping failed: %s", err)
	}
}
