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

func newOutput(printAll bool) output {
	return newTableOutput(printAll)
}

type tableOutput struct {
	printAll bool
}

func (t tableOutput) PrintHeader() {
	var header string
	var args []interface{}
	if t.printAll {
		header = "%-9s %-9s %-6s %-42s %-16s %-20s %s\n"
		args = []interface{}{"TIME", "AF", "PID", "PROCESS", "USER", "DESTINATION", "AS-INFO"}
	} else {
		header = "%-9s %-9s %-6s %-34s %-16s %-20s\n"
		args = []interface{}{"TIME", "AF", "PID", "PROCESS", "USER", "DESTINATION"}
	}

	fmt.Printf(header, args...)
}

func (t tableOutput) PrintLine(e eventPayload) {
	time := e.GoTime.Format("15:04:05")
	dest := e.DestIP.String() + " " + strconv.Itoa(int(e.DestPort))

	var header string
	var args []interface{}

	if t.printAll {
		var asText = ""
		if (as.ASInfo{}) != e.ASInfo {
			asText = "AS" + strconv.Itoa(int(e.ASInfo.AsNumber)) + " (" + e.ASInfo.Name + ")"
		}
		header = "%-9s %-9s %-6d %-42s %-16s %-20s %s\n"
		args = []interface{}{time, e.AddressFamily, e.Pid, e.ProcessPath + " " + e.ProcessArgs, e.User, dest, asText}
	} else {
		header = "%-9s %-9s %-6d %-34s %-16s %-20s\n"
		args = []interface{}{time, e.AddressFamily, e.Pid, e.ProcessPath, e.User, dest}
	}

	fmt.Printf(header, args...)
}

func newTableOutput(includeAsNumbers bool) output {
	return &tableOutput{includeAsNumbers}
}
