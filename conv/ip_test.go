package conv

import (
	"net"
	"testing"
)

func TestIp4Conversion(t *testing.T) {
	got := ToIP4(251789322)
	want := "10.0.2.15"
	if !got.Equal(net.ParseIP(want)) {
		t.Errorf("ToIP4(251789322) = %s; want %s", got, want)
	}
}

func TestIp4ConversionWithLocalhost(t *testing.T) {
	got := ToIP4(16777343)
	want := "127.0.0.1"
	if !got.Equal(net.ParseIP(want)) {
		t.Errorf("ToIP4(16777343) = %s; want %s", got, want)
	}
}

func TestIp6ConversionWithLocalhost(t *testing.T) {
	got := ToIP6(0, 72057594037927936)
	want := "::1"
	if !got.Equal(net.ParseIP(want)) {
		t.Errorf("ToIP6(0, 72057594037927936) = %s; want %s", got, want)
	}
}

func TestIp6ConversionWith6to4Address(t *testing.T) {
	got := ToIP6(18305688338976, 0)
	want := "2002:d20:a610::"
	if !got.Equal(net.ParseIP(want)) {
		t.Errorf("ToIP6(18305688338976, 0) = %s; want %s", got, want)
	}
}
