// Copyright 2019 Peter Stöckli
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux
// +build linux

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/p-/socket-connect-bpf/as"
	"github.com/p-/socket-connect-bpf/conv"
	"github.com/p-/socket-connect-bpf/linux"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-12 -cflags "-O2 -g -Wall -Werror" -target amd64 bpf securitySocketConnectSrc.c -- -Iheaders/

var out output

func main() {
	setupOutput()
	setupWorkers()
}

func setupOutput() {
	printAll := flag.Bool("a", false, "print all (AS numbers and process arguments in output")
	flag.Parse()
	if *printAll {
		as.ParseASNumbers("./as/ip2asn-v4-u32.tsv")
	}
	out = newOutput(*printAll)
}

func setupWorkers() {
	fn := "security_socket_connect"

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	kp, err := link.Kprobe(fn, objs.KprobeSecuritySocketConnect)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	rd4, err := perf.NewReader(objs.Ipv4Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
	}
	defer rd4.Close()

	rd6, err := perf.NewReader(objs.Ipv6Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
	}
	defer rd6.Close()

	rdOther, err := perf.NewReader(objs.OtherSocketEvents, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
	}
	defer rdOther.Close()

	go func() {
		<-stopper
		log.Println("Received signal, exiting program..")

		if err := rd4.Close(); err != nil {
			log.Fatalf("closing perf event reader: %s", err)
		}

		if err := rd6.Close(); err != nil {
			log.Fatalf("closing perf event reader: %s", err)
		}

		if err := rdOther.Close(); err != nil {
			log.Fatalf("closing perf event reader: %s", err)
		}
	}()

	out.PrintHeader()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	go (func() {
		for {
			if !readIP4Events(rd4) {
				return
			}
		}
	})()

	go (func() {
		for {
			if !readIP6Events(rd6) {
				return
			}
		}
	})()

	go (func() {
		if !readOtherEvents(rdOther) {
			return
		}
	})()

	<-sig
}

func readIP4Events(rd *perf.Reader) bool {
	var event IP4Event
	record, err := rd.Read()
	if err != nil {
		if errors.Is(err, perf.ErrClosed) {
			return false
		}
		log.Printf("reading from perf event reader: %s", err)
		return true
	}

	if record.LostSamples != 0 {
		log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
		return true
	}

	if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
		log.Printf("parsing perf event: %s", err)
		return true
	}

	eventPayload := newGenericEventPayload(&event.Event)
	eventPayload.DestIP = conv.ToIP4(event.Daddr)
	eventPayload.DestPort = event.Dport
	eventPayload.ASInfo = as.GetASInfo(eventPayload.DestIP)
	out.PrintLine(eventPayload)
	return true
}

func readIP6Events(rd *perf.Reader) bool {
	var event IP6Event
	record, err := rd.Read()
	if err != nil {
		if errors.Is(err, perf.ErrClosed) {
			return false
		}
		log.Printf("reading from perf event reader: %s", err)
		return true
	}

	if record.LostSamples != 0 {
		log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
		return true
	}

	if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
		log.Printf("parsing perf event: %s", err)
		return true
	}

	eventPayload := newGenericEventPayload(&event.Event)
	eventPayload.DestIP = conv.ToIP6(event.Daddr1, event.Daddr2)
	eventPayload.DestPort = event.Dport
	out.PrintLine(eventPayload)
	return true
}

func readOtherEvents(rd *perf.Reader) bool {
	var event OtherSocketEvent
	record, err := rd.Read()
	if err != nil {
		if errors.Is(err, perf.ErrClosed) {
			return false
		}
		log.Printf("reading from perf event reader: %s", err)
		return true
	}

	if record.LostSamples != 0 {
		log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
		return true
	}

	if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
		log.Printf("parsing perf event: %s", err)
		return true
	}

	eventPayload := newGenericEventPayload(&event.Event)
	out.PrintLine(eventPayload)
	return true
}

func newGenericEventPayload(event *Event) eventPayload {
	username := strconv.Itoa(int(event.UID))
	user, err := user.LookupId(username)
	if err != nil {
		log.Printf("Could not lookup user with id: %d", event.UID)
	} else {
		username = user.Username
	}

	pid := int(event.Pid)
	payload := eventPayload{
		KernelTime:    strconv.Itoa(int(event.TsUs)),
		GoTime:        time.Now(),
		AddressFamily: conv.ToAddressFamily(int(event.Af)),
		Pid:           event.Pid,
		ProcessPath:   linux.ProcessPathForPid(pid),
		ProcessArgs:   linux.ProcessArgsForPid(pid),
		User:          username,
		Comm:          unix.ByteSliceToString(event.Task[:]),
	}
	return payload
}

// Event is a common event interface
type Event struct {
	TsUs uint64
	Pid  uint32
	UID  uint32
	Af   uint16 // Address Family
	Task [16]byte
}

// IP4Event represents a socket connect event from AF_INET(4)
type IP4Event struct {
	Event
	Daddr uint32
	Dport uint16
}

// IP6Event represents a socket connect event from AF_INET6
type IP6Event struct {
	Event
	Daddr1 uint64
	Daddr2 uint64
	Dport  uint16
}

// OtherSocketEvent represents the socket connects that are not AF_INET, AF_INET6 or AF_UNIX
type OtherSocketEvent struct {
	Event
}

type eventPayload struct {
	KernelTime    string
	GoTime        time.Time
	AddressFamily string
	Pid           uint32
	ProcessPath   string
	ProcessArgs   string
	User          string
	Comm          string
	Host          string
	DestIP        net.IP
	DestPort      uint16
	ASInfo        as.ASInfo
}
