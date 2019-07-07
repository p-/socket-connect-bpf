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

package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"net"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"unsafe"

	bpf "github.com/iovisor/gobpf/bcc"
	"github.com/p-/socket-connect-bpf/as"
	"github.com/p-/socket-connect-bpf/conv"
	"github.com/p-/socket-connect-bpf/linux"
)

import "C"

//go:generate go run bpf/includebpf.go

func main() {
	log.Print("starting socket-connect-bpf")
	as.ParseASNumbers("./as/ip2asn-v4-u32.tsv")
	setupWorkers()
	select {} // block forever
}

func runSecuritySocketConnectKprobes() {
	m := bpf.NewModule(securitySocketConnectSrc, []string{})
	defer m.Close()
	securitySocketConnectEntry, err := m.LoadKprobe("security_socket_connect_entry")
	if err != nil {
		log.Fatal("LoadKprobe failed!", err)
	}

	err = m.AttachKprobe("security_socket_connect", securitySocketConnectEntry, -1)

	table4 := bpf.NewTable(m.TableId("ipv4_events"), m)
	channel4 := make(chan []byte)
	map4, err := bpf.InitPerfMap(table4, channel4)
	if err != nil {
		map4 = nil
	}

	table6 := bpf.NewTable(m.TableId("ipv6_events"), m)
	channel6 := make(chan []byte)
	map6, err := bpf.InitPerfMap(table6, channel6)
	if err != nil {
		map6 = nil
	}

	otherTable := bpf.NewTable(m.TableId("other_socket_events"), m)
	otherChannel := make(chan []byte)
	otherMap, err := bpf.InitPerfMap(otherTable, otherChannel)
	if err != nil {
		otherMap = nil
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	out := newOutput()
	out.PrintHeader()

	go (func() {
		for {
			var event IP4Event
			data := <-channel4
			binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event)
			eventPayload := newGenericEventPayload(&event.Event)
			eventPayload.DestIP = conv.ToIP4(event.Daddr)
			eventPayload.DestPort = event.Dport
			eventPayload.ASInfo = as.GetASInfo(eventPayload.DestIP)
			out.PrintLine(eventPayload)
		}
	})()

	go (func() {
		for {
			var event IP6Event
			data := <-channel6
			binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event)
			eventPayload := newGenericEventPayload(&event.Event)
			eventPayload.DestIP = conv.ToIP6(event.Daddr1, event.Daddr2)
			eventPayload.DestPort = event.Dport
			out.PrintLine(eventPayload)
		}
	})()

	go (func() {
		for {
			var event OtherSocketEvent
			data := <-otherChannel
			binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event)
			eventPayload := newGenericEventPayload(&event.Event)
			out.PrintLine(eventPayload)
		}
	})()

	if map4 != nil {
		map4.Start()
	}
	if map6 != nil {
		map6.Start()
	}
	if otherMap != nil {
		otherMap.Start()
	}
	<-sig
	if map4 != nil {
		map4.Stop()
	}
	if map6 != nil {
		map6.Stop()
	}
	if otherMap != nil {
		otherMap.Stop()
	}
}

func runDNSLookupKprobes() {
	m := bpf.NewModule(dnsLookupSrc, []string{})
	defer m.Close()
	dnsLookupEntry, err := m.LoadKprobe("dns_lookup_entry")
	if err != nil {
		log.Fatal("LoadKprobe failed!", err)
	}

	dnsLookupReturn, err := m.LoadUprobe("dns_lookup_return")
	if err != nil {
		log.Fatal("LoadKprobe failed!", err)
	}

	attachUprobe(m, "getaddrinfo", dnsLookupEntry)
	attachUprobe(m, "gethostbyname", dnsLookupEntry)
	attachUprobe(m, "gethostbyname2", dnsLookupEntry)

	attachUretprobe(m, "getaddrinfo", dnsLookupReturn)
	attachUretprobe(m, "gethostbyname", dnsLookupReturn)
	attachUretprobe(m, "gethostbyname2", dnsLookupReturn)

	tableTimings := bpf.NewTable(m.TableId("events"), m)
	channelTimings := make(chan []byte)
	mapTimings, err := bpf.InitPerfMap(tableTimings, channelTimings)
	if err != nil {
		mapTimings = nil
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	go (func() {
		for {
			var event DNSEvent
			data := <-channelTimings
			binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event)
			printDNSEvent(&event)
		}
	})()

	if mapTimings != nil {
		mapTimings.Start()
	}
	<-sig
	if mapTimings != nil {
		mapTimings.Stop()
	}
}

func setupWorkers() {
	go runSecuritySocketConnectKprobes()
	go runDNSLookupKprobes()
}

func attachUprobe(module *bpf.Module, functionName string, bpfProgram int) {
	err := module.AttachUprobe("c", functionName, bpfProgram, -1)
	if err != nil {
		log.Fatal("AttachUprobe failed!", err)
	}

}

func attachUretprobe(module *bpf.Module, functionName string, bpfProgram int) {
	err := module.AttachUretprobe("c", functionName, bpfProgram, -1)
	if err != nil {
		log.Fatal("AttachUretprobe failed!", err)
	}
}

func newGenericEventPayload(event *Event) eventPayload {
	task := (*C.char)(unsafe.Pointer(&event.Task))

	username := strconv.Itoa(int(event.UID))
	user, err := user.LookupId(username)
	if err != nil {
		log.Printf("Could not lookup user with id: %d", event.UID)
	} else {
		username = user.Username
	}

	payload := eventPayload{
		Time:          strconv.Itoa(int(event.TsUs)),
		AddressFamily: conv.ToAddressFamily(int(event.Af)),
		Pid:           event.Pid,
		ProcessPath:   linux.ProcessPathForPid(int(event.Pid)),
		User:          username,
		Comm:          C.GoString(task),
	}
	return payload
}

func printDNSEvent(event *DNSEvent) {
	host := (*C.char)(unsafe.Pointer(&event.Host))
	task := (*C.char)(unsafe.Pointer(&event.Task))
	log.Printf("PID: %d, Host: %s, Task %s", event.Pid, C.GoString(host), C.GoString(task))
}

// DNSEvent is used for DNS Lookup events
type DNSEvent struct {
	Pid   uint32
	Delta uint64
	Task  [16]byte
	Host  [80]byte
}

// Event is a common event interface
type Event struct {
	TsUs uint64
	Pid  uint32
	UID  uint32
	Af   uint32 // Address Family
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
	Time          string
	AddressFamily string
	Pid           uint32
	ProcessPath   string
	User          string
	Comm          string
	DestIP        net.IP
	DestPort      uint16
	ASInfo        as.ASInfo
}
