package as

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestIP6ToAsRange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ip2asn-v6.tsv")
	row := "2620:2d:4000::\t2620:2d:4003:ffff:ffff:ffff:ffff:ffff\t41231\tGB\tCANONICAL-AS Canonical Group Limited\n"
	if err := os.WriteFile(path, []byte(row), 0600); err != nil {
		t.Fatal(err)
	}
	ParseASNumbersIPv6(path)
	ip := "2620:2d:4000:1::1"
	got := GetASInfoIPv6(net.ParseIP(ip))
	wantName := "CANONICAL-AS"
	if got.Name != wantName {
		t.Errorf("GetASInfo(%s) = %s; want %s", ip, got.Name, wantName)
	}
	wantAsNumber := uint32(41231)
	if got.AsNumber != wantAsNumber {
		t.Errorf("GetASInfo(%s) = %d; want %d", ip, got.AsNumber, wantAsNumber)
	}
}
