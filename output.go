package main

import (
	"fmt"
	"time"
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
	header := "%-12s %-14s %-6s %-16s %-16s %s\n"
	args := []interface{}{"TIME", "AF", "PID", "USER", "PCOMM", "DESTINATION"}
	fmt.Printf(header, args...)
}

func (t tableOutput) PrintLine(e eventPayload) {
	header := "%-12s %-14s %-6d %-16s %-16s %s:%d\n"
	args := []interface{}{e.Time, e.AddressFamily, e.Pid, e.User, e.Comm, e.DestIP, e.DestPort}
	fmt.Printf(header, args...)
}

func newTableOutput() output {
	return &tableOutput{newTiming()}
}
