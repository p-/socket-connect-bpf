package dns

import (
	"testing"
)

func TestReturnCachedHostname(t *testing.T) {
	AddIP4Entry(123456789, 21, "github.com")

	got := GetHostname(123456789, 21)
	want := "github.com"
	if got != want {
		t.Errorf("GetHostname(123456789, 21) = %s; want %s", got, want)
	}
}

func TestDoesNotReturnHostForWrongPid(t *testing.T) {
	AddIP4Entry(123456789, 21, "github.com")

	got := GetHostname(123456789, 33)
	want := ""
	if got != want {
		t.Errorf("GetHostname(123456789, 33) = %s; want %s", got, want)
	}
}

func TestDoesNotReturnHostForWrongIP(t *testing.T) {
	AddIP4Entry(123456789, 21, "github.com")

	got := GetHostname(111111111, 21)
	want := ""
	if got != want {
		t.Errorf("GetHostname(111111111, 21) = %s; want %s", got, want)
	}
}
