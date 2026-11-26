package as

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestIP4ToAsRange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ip2asn-v4-u32.tsv")
	// 253.255.255.255 through 255.0.0.1, inclusive.
	row := "4261412863\t4278190081\t64512\tCH\tEXAMPLE Example Network\n"
	if err := os.WriteFile(path, []byte(row), 0600); err != nil {
		t.Fatal(err)
	}
	ParseASNumbersIPv4(path)

	for _, ip := range []string{"253.255.255.255", "254.0.0.1", "255.0.0.1"} {
		if got := GetASInfoIPv4(net.ParseIP(ip)); got.AsNumber != 64512 || got.Name != "EXAMPLE" {
			t.Errorf("GetASInfoIPv4(%s) = %+v; want AS64512 EXAMPLE", ip, got)
		}
	}
	for _, ip := range []string{"253.255.255.254", "255.0.0.2"} {
		if got := GetASInfoIPv4(net.ParseIP(ip)); got != (ASInfo{}) {
			t.Errorf("GetASInfoIPv4(%s) = %+v; want no match", ip, got)
		}
	}
}
