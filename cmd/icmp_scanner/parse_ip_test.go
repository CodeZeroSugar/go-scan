package icmpscanner

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseRange(t *testing.T) {
	// Test: Valid single IP Address
	ip := "192.168.0.25"
	start, end, err := ParseIPRange(ip)
	require.NoError(t, err)
	require.NotNil(t, ip)
	assert.Equal(t, net.IP(nil), start)
	assert.Equal(t, net.ParseIP(ip), end)

	// Test: Valid IP range, two full addresses
	ip = "192.168.0.10-192.168.0.20"
	start, end, err = ParseIPRange(ip)
	require.NoError(t, err)
	require.NotNil(t, ip)
	assert.Equal(t, net.ParseIP("192.168.0.10"), start)
	assert.Equal(t, net.ParseIP("192.168.0.20"), end)

	// Test: Valid IP and hyphen
	ip = "192.168.0.25-"
	start, end, err = ParseIPRange(ip)
	require.NoError(t, err)
	require.NotNil(t, ip)
	assert.Equal(t, net.IP(nil), start)
	assert.Equal(t, net.ParseIP("192.168.0.25"), end)

	// Test: Valid IP range, one full other last octet
	ip = "192.168.0.25-192.168.0.60"
	start, end, err = ParseIPRange(ip)
	require.NoError(t, err)
	require.NotNil(t, ip)
	assert.Equal(t, net.ParseIP("192.168.0.25"), start)
	assert.Equal(t, net.ParseIP("192.168.0.60"), end)

	// Test: Invalid IP
	ip = "192.168.1223.23"
	start, end, err = ParseIPRange(ip)
	require.Error(t, err)
	assert.Equal(t, net.IP(nil), start)
	assert.Equal(t, net.IP(nil), end)

	// Test: Invalid order
	ip = "192.168.0.204-192.168.0.123"
	start, end, err = ParseIPRange(ip)
	require.Error(t, err)
	assert.Equal(t, net.IP(nil), start)
	assert.Equal(t, net.IP(nil), end)

	// Test: Invalid order, one full and last octet
	ip = "192.168.0.204-123"
	start, end, err = ParseIPRange(ip)
	require.Error(t, err)
	assert.Equal(t, net.IP(nil), start)
	assert.Equal(t, net.IP(nil), end)

	// Test: 4 byte IP representation
	netIP := net.ParseIP("192.168.0.5")
	b := netIP.To4()
	incrementIP(b)
}
