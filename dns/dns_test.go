package dns

import (
	"testing"
)

func TestReturnCachedHostname(t *testing.T) {
	AddIP4Entry(111111111, 21, "github.com")

	got := GetHostname(111111111, 21)
	want := "github.com"
	if got != want {
		t.Errorf("GetHostname(111111111, 21) = %s; want %s", got, want)
	}
}

func TestDoesNotReturnHostForWrongIP(t *testing.T) {
	AddIP4Entry(111111111, 21, "github.com")

	got := GetHostname(111111111, 33)
	want := ""
	if got != want {
		t.Errorf("GetHostname(111111111, 33) = %s; want %s", got, want)
	}
}
