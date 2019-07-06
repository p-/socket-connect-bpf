package main

import (
	"fmt"
	"strconv"
	"time"

	"github.com/p-/socket-connect-bpf/as"
)

type output interface {
	PrintHeader()
	PrintLine(eventPayload)
}

type timing struct {
	start time.Time
}

func newTiming() timing {
	return timing{time.Now()}
}

func (t timing) Now() float64 {
	return time.Now().Sub(t.start).Seconds()
}

func newOutput() output {
	return newTableOutput()
}

type tableOutput struct {
	timing timing
}

func (t tableOutput) PrintHeader() {
	header := "%-12s %-14s %-6s %-16s %-16s %-20s %s\n"
	args := []interface{}{"TIME", "AF", "PID", "USER", "PCOMM", "DESTINATION", "AS-INFO"}
	fmt.Printf(header, args...)
}

func (t tableOutput) PrintLine(e eventPayload) {
	dest := e.DestIP.String() + ":" + strconv.Itoa(int(e.DestPort))
	var asText = ""
	if (as.ASInfo{}) != e.ASInfo {
		asText = "AS" + strconv.Itoa(int(e.ASInfo.AsNumber)) + " (" + e.ASInfo.Name + ")"
	}
	header := "%-12s %-14s %-6d %-16s %-16s %-20s %s\n"
	args := []interface{}{e.Time, e.AddressFamily, e.Pid, e.User, e.Comm, dest, asText}
	fmt.Printf(header, args...)
}

func newTableOutput() output {
	return &tableOutput{newTiming()}
}
