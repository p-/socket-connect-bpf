package as

import (
	"net"
	"testing"
)

func TestIP6ToAsRange(t *testing.T) {
	ParseASNumbersIPv6("./ip2asn-v6.tsv")
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
