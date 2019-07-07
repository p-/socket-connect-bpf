package linux

import "testing"

func TestNotExistingPid(t *testing.T) {
	got := ProcessPathForPid(32769) // There should be no such PID, default MAX PID is 32768
	want := ""
	if got != want {
		t.Errorf("ProcessPathForPid(32769) = %s; want %s", got, want)
	}
}
