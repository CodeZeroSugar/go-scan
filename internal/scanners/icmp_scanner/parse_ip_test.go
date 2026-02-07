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

	// Test: Full test - range
	ip = "192.168.0.25-192.168.0.60"
	scanRange, err := ParseTargets(ip)
	require.NoError(t, err)
	assert.Equal(t, net.ParseIP("192.168.0.25").String(), scanRange[0].String())
	assert.Equal(t, net.ParseIP("192.168.0.60").String(), scanRange[len(scanRange)-1].String())
	assert.Equal(t, 36, len(scanRange))

	// Test: Full test - 2 ranges separated by commas
	ip = "192.168.0.5-192.168.0.10, 192.168.0.20-192.168.0.30"
	scanRange, err = ParseTargets(ip)
	require.NoError(t, err)
	assert.Equal(t, net.ParseIP("192.168.0.5").String(), scanRange[0].String())
	assert.Equal(t, net.ParseIP("192.168.0.30").String(), scanRange[len(scanRange)-1].String())
	assert.Equal(t, 17, len(scanRange))

	// Test: Full test - 2 ranges, separated by commas, hyphen format with only last octet
	ip = "192.168.0.15-25, 192.168.0.100-200"
	scanRange, err = ParseTargets(ip)
	require.NoError(t, err)
	assert.Equal(t, "192.168.0.15", scanRange[0].String())
	assert.Equal(t, "192.168.0.200", scanRange[len(scanRange)-1].String())
	assert.Equal(t, 112, len(scanRange))

	// Test: Full test - CIDR, single range
	ip = "192.168.0.0/24"
	scanRange, err = ParseTargets(ip)
	require.NoError(t, err)
	assert.Equal(t, "192.168.0.0", scanRange[0].String())
	assert.Equal(t, "192.168.0.255", scanRange[len(scanRange)-1].String())
	assert.Equal(t, 256, len(scanRange))

	// Test: Full test - CIDR, multiple ranges separated by commas
	ip = "192.168.0.0/24, 192.168.1.0/24"
	scanRange, err = ParseTargets(ip)
	require.NoError(t, err)
	assert.Equal(t, "192.168.0.0", scanRange[0].String())
	assert.Equal(t, "192.168.1.255", scanRange[len(scanRange)-1].String())
	assert.Equal(t, 512, len(scanRange))

	// Test: Full test - single ip
	ip = "192.168.0.25"
	scanRange, err = ParseTargets(ip)
	require.NoError(t, err)
	assert.Equal(t, net.ParseIP("192.168.0.25").String(), scanRange[0].String())
	assert.Equal(t, net.ParseIP("192.168.0.25").String(), scanRange[len(scanRange)-1].String())
	assert.Equal(t, 1, len(scanRange))

	// Test: Full test - single ips separated by commas
	ip = "192.168.0.25, 192.168.0.38, 192.168.0.55, 192.168.1.211"
	scanRange, err = ParseTargets(ip)
	require.NoError(t, err)
	assert.Equal(t, net.ParseIP("192.168.0.25").String(), scanRange[0].String())
	assert.Equal(t, net.ParseIP("192.168.1.211").String(), scanRange[len(scanRange)-1].String())
	assert.Equal(t, 4, len(scanRange))

	// Test: Full test - combination
	ip = "192.168.0.10-192.168.0.20, 192.168.1.0/24, 192.168.2.20-30, 192.168.2.52"
	scanRange, err = ParseTargets(ip)
	require.NoError(t, err)
	assert.Equal(t, "192.168.0.10", scanRange[0].String())
	assert.Equal(t, "192.168.2.52", scanRange[len(scanRange)-1].String())
	assert.Equal(t, 279, len(scanRange))
}
