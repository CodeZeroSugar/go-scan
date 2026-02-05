package icmpscanner

import (
	"net"
	"testing"
)

/*
func TestPing(t *testing.T) {
	err := ping(testIP)
	if err != nil {
		t.Errorf("ping failed: %s", err)
	}
}
*/

func TestGenerateIPRange(t *testing.T) {
	tests := []struct {
		name      string
		startStr  string
		endStr    string
		wantCount int
		wantFirst string
		wantLast  string
	}{
		{
			name:      "normal /24 range",
			startStr:  "192.168.0.0",
			endStr:    "192.168.0.255",
			wantCount: 256, // inclusive: 0 through 255
			wantFirst: "192.168.0.0",
			wantLast:  "192.168.0.255",
		},
		{
			name:      "small range",
			startStr:  "10.0.0.5",
			endStr:    "10.0.0.8",
			wantCount: 4,
			wantFirst: "10.0.0.5",
			wantLast:  "10.0.0.8",
		},
		{
			name:      "single IP",
			startStr:  "172.16.1.100",
			endStr:    "172.16.1.100",
			wantCount: 1,
			wantFirst: "172.16.1.100",
			wantLast:  "172.16.1.100",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start := net.ParseIP(tt.startStr)
			end := net.ParseIP(tt.endStr)
			if start == nil || end == nil {
				t.Fatalf("failed to parse IPs: %s or %s", tt.startStr, tt.endStr)
			}

			ch := GenerateIPRange(start, end) // your function

			var got []net.IP
			for ip := range ch {
				got = append(got, ip)
			}

			if len(got) != tt.wantCount {
				t.Errorf("wrong count: got %d, want %d", len(got), tt.wantCount)
			}

			if len(got) > 0 {
				if got[0].String() != tt.wantFirst {
					t.Errorf("first IP wrong: got %s, want %s", got[0], tt.wantFirst)
				}
				if got[len(got)-1].String() != tt.wantLast {
					t.Errorf("last IP wrong: got %s, want %s", got[len(got)-1], tt.wantLast)
				}
			}

			// Optional: check no duplicates or monotonic increase
			// (add if you're paranoid)
		})
	}
}
