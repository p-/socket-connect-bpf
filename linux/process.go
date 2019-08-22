package linux

import (
	"bytes"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

// ProcessArgsForPid should retrieve the Process Arguments for a given PID.
// TODO maybe combine with method above and only make one call
func ProcessArgsForPid(pid int) string {
	readPath := "/proc/" + strconv.Itoa(pid) + "/cmdline"
	file, err := os.Open(readPath)
	if err != nil {
		log.Printf("Pid %d: could not open File %s", pid, readPath)
		return ""
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		log.Printf("Pid %d: could not read File %s", pid, readPath)
		return ""
	}

	if len(data) < 1 {
		return ""
	}

	parts := strings.Split(string(bytes.TrimRight(data, string("\x00"))), string(byte(0)))

	return strings.Join(parts[1:], " ")
}
