package as

import (
	"net"
	"testing"
)

func TestIPToAsRange(t *testing.T) {
	ParseASNumbers("./ip2asn-v4-u32.tsv")
	ip := "82.197.176.1"
	got := GetASInfo(net.ParseIP(ip))
	wantName := "INIT7"
	if got.Name != wantName {
		t.Errorf("GetASInfo(%s) = %s; want %s", ip, got.Name, wantName)
	}
	wantAsNumber := uint32(13030)
	if got.AsNumber != wantAsNumber {
		t.Errorf("GetASInfo(%s) = %d; want %d", ip, got.AsNumber, wantAsNumber)
	}
}
