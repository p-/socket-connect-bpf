package conv

import (
	"testing"
)

func TestExistingAfConversion(t *testing.T) {
	got := ToAddressFamily(10)
	want := "AF_INET6"
	if got != want {
		t.Errorf("ToAddressFamily(10) = %s; want %s", got, want)
	}
}
func TestNotExistingAfConversion(t *testing.T) {
	got := ToAddressFamily(55)
	want := "55"
	if got != want {
		t.Errorf("ToAddressFamily(55) = %s; want %s", got, want)
	}
}
