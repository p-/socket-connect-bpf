package linux

import "testing"

func TestProcessPathForPidForNotExistingPid(t *testing.T) {
	got := ProcessPathForPid(32769) // There should be no such PID, default MAX PID is 32768
	want := ""
	if got != want {
		t.Errorf("ProcessPathForPid(32769) = %s; want %s", got, want)
	}
}

func TestProcessArgsForPidForNotExistingPid(t *testing.T) {
	got := ProcessArgsForPid(32769) // There should be no such PID, default MAX PID is 32768
	want := ""
	if got != want {
		t.Errorf("ProcessArgsForPid(32769) = %s; want %s", got, want)
	}
}
