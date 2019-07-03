package as

import (
	"net"
	"testing"
)

func TestIPToAsRange(t *testing.T) {
	ParseASNumbers("./ip2asn-v4-u32.tsv")
	ip := "38.63.2.254"
	got := GetASInfo(net.ParseIP(ip))
	wantDesc := "COGENT-174 - Cogent Communications"
	if got.Desc != wantDesc {
		t.Errorf("GetASInfo(%s) = %s; want %s", ip, got.Desc, wantDesc)
	}
	wantAsNumber := uint32(174)
	if got.AsNumber != wantAsNumber {
		t.Errorf("GetASInfo(%s) = %d; want %d", ip, got.AsNumber, wantAsNumber)
	}
}
