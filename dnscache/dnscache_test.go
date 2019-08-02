package dnscache

import (
	"testing"
)

// IPv4
func TestGetHostname4ReturnsCachedHostname(t *testing.T) {
	AddIP4Entry(123456789, 21, "github.com")

	got := GetHostname4(123456789, 21)
	want := "github.com"
	if got != want {
		t.Errorf("GetHostname4(123456789, 21) = %s; want %s", got, want)
	}
}

func TestGetHostname4DoesNotReturnHostForWrongPid(t *testing.T) {
	AddIP4Entry(123456789, 21, "github.com")

	got := GetHostname4(123456789, 33)
	want := ""
	if got != want {
		t.Errorf("GetHostname4(123456789, 33) = %s; want %s", got, want)
	}
}

func TestGetHostname4DoesNotReturnHostForWrongIP(t *testing.T) {
	AddIP4Entry(123456789, 21, "github.com")

	got := GetHostname4(111111111, 21)
	want := ""
	if got != want {
		t.Errorf("GetHostname4(111111111, 21) = %s; want %s", got, want)
	}
}

// IPv6
func TestGetHostname6ReturnsCachedHostname(t *testing.T) {
	AddIP6Entry(123456789, 987654321, 21, "github.com")

	got := GetHostname6(123456789, 987654321, 21)
	want := "github.com"
	if got != want {
		t.Errorf("GetHostname6(123456789, 987654321, 21) = %s; want %s", got, want)
	}
}

func TestGetHostname6DoesNotReturnHostForWrongPid(t *testing.T) {
	AddIP6Entry(123456789, 987654321, 21, "github.com")

	got := GetHostname6(123456789, 987654321, 33)
	want := ""
	if got != want {
		t.Errorf("GetHostname6(123456789, 987654321, 33) = %s; want %s", got, want)
	}
}

func TestGetHostname6DoesNotReturnHostForWrongIP(t *testing.T) {
	AddIP6Entry(123456789, 987654321, 21, "github.com")

	got := GetHostname6(111111111, 111111111, 21)
	want := ""
	if got != want {
		t.Errorf("GetHostname6(111111111, 111111111, 21) = %s; want %s", got, want)
	}
}
