package icmpscanner

import (
	"fmt"
	"net"
	"testing"
)

func TestParseRange(t *testing.T) {
	type testOptions struct {
		input string
		start net.IP
		end   net.IP
	}

	var tests []testOptions
	test1 := testOptions{
		input: "192.168.0.25",
		start: nil,
		end:   net.ParseIP("192.168.0.25"),
	}
	test2 := testOptions{
		input: "192.168.0.1-192.168.0.255",
		start: net.ParseIP("192.168.0.1"),
		end:   net.ParseIP("192.168.0.255"),
	}
	test3 := testOptions{
		input: "192.168.0.2-",
		start: nil,
		end:   net.ParseIP("192.168.0.2"),
	}
	test4 := testOptions{
		input: "192.168.0.100-192.168.0.50",
		start: nil,
		end:   nil,
	}
	test5 := testOptions{
		input: "notandipaddress",
		start: nil,
		end:   nil,
	}
	test6 := testOptions{
		input: "192.168.1.1-abc",
		start: nil,
		end:   nil,
	}
	tests = append(tests, test1, test2, test3, test4, test5, test6)

	for _, tt := range tests {
		s, e, err := ParseIPRange(tt.input)
		if err != nil {
			fmt.Println(err)
		}

		if s.String() != tt.start.String() || e.String() != tt.end.String() {
			t.Errorf("Start expected: %v Start Got: %v\nEnd expected: %v End Got: %v", s, tt.start, e, tt.end)
		}
	}
}
