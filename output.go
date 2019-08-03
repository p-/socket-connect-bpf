package main

import (
	"fmt"
	"strconv"

	"github.com/p-/socket-connect-bpf/as"
)

type output interface {
	PrintHeader()
	PrintLine(eventPayload)
}

func newOutput(includeAsNumbers bool) output {
	return newTableOutput(includeAsNumbers)
}

type tableOutput struct {
	includeAsNumbers bool
}

func (t tableOutput) PrintHeader() {
	var header string
	var args []interface{}
	if t.includeAsNumbers {
		header = "%-9s %-9s %-6s %-34s %-16s %-20s %-32s %s\n"
		args = []interface{}{"TIME", "AF", "PID", "PROCESS", "USER", "DESTINATION", "HOST", "AS-INFO"}
	} else {
		header = "%-9s %-9s %-6s %-34s %-16s %-20s %s\n"
		args = []interface{}{"TIME", "AF", "PID", "PROCESS", "USER", "DESTINATION", "HOST"}
	}

	fmt.Printf(header, args...)
}

func (t tableOutput) PrintLine(e eventPayload) {
	time := e.GoTime.Format("15:04:05")
	dest := e.DestIP.String() + ":" + strconv.Itoa(int(e.DestPort))

	var header string
	var args []interface{}

	if t.includeAsNumbers {
		var asText = ""
		if (as.ASInfo{}) != e.ASInfo {
			asText = "AS" + strconv.Itoa(int(e.ASInfo.AsNumber)) + " (" + e.ASInfo.Name + ")"
		}
		header = "%-9s %-9s %-6d %-34s %-16s %-20s %-32s %s\n"
		args = []interface{}{time, e.AddressFamily, e.Pid, e.ProcessPath, e.User, dest, e.Host, asText}
	} else {
		header = "%-9s %-9s %-6d %-34s %-16s %-20s %s\n"
		args = []interface{}{time, e.AddressFamily, e.Pid, e.ProcessPath, e.User, dest, e.Host}
	}

	fmt.Printf(header, args...)
}

func newTableOutput(includeAsNumbers bool) output {
	return &tableOutput{includeAsNumbers}
}
