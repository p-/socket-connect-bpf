package linux

import (
	"log"
	"os"
	"path/filepath"
	"strconv"
)

// PathForPid should retrieve the Process Path for a given PID.
// TODO return error
func ProcessPathForPid(pid int) string {
	readPath := "/proc/" + strconv.Itoa(pid) + "/exe"

	resolved, err := filepath.EvalSymlinks(readPath)
	if err != nil {
		log.Printf("Pid %d: Could not resolve path for %s", pid, readPath)
		return ""
	}

	if _, err := os.Stat(resolved); err != nil {
		log.Printf("Pid %d: File %s does not exist", pid, resolved)
		return ""
	}

	return resolved
}
