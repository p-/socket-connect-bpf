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
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"unsafe"

	bpf "github.com/iovisor/gobpf/bcc"
	"github.com/p-/socket-connect-bpf/conv"
)

import "C"

// partly based on https://github.com/iovisor/bcc/blob/master/tools/tcpconnect.py
const src string = `
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <bcc/proto.h>

struct ipv4_data_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
	u32 af;
    char task[TASK_COMM_LEN];
    u32 daddr;
	u16 dport;
} __attribute__((packed));
BPF_PERF_OUTPUT(ipv4_events);

struct ipv6_data_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
	u32 af;
    char task[TASK_COMM_LEN];
    unsigned __int128 daddr;
	u16 dport;
} __attribute__((packed));
BPF_PERF_OUTPUT(ipv6_events);

int security_socket_connect_entry(struct pt_regs *ctx, struct socket *sock, struct sockaddr *address, int addrlen)
{
	int ret = PT_REGS_RC(ctx);
	
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    u32 uid = bpf_get_current_uid_gid();

    struct sock *skp = sock->sk;

    // The AF options are listed in https://github.com/torvalds/linux/blob/master/include/linux/socket.h

	u32 address_family = address->sa_family;
    if (address_family == AF_INET) {
        struct ipv4_data_t data4 = {.pid = pid, .uid = uid};
        data4.ts_us = bpf_ktime_get_ns() / 1000;

		struct sockaddr_in *daddr = (struct sockaddr_in *)address;
		
		bpf_probe_read(&data4.daddr, sizeof(data4.daddr), &daddr->sin_addr.s_addr);
			
		u16 dport = 0;
		bpf_probe_read(&dport, sizeof(dport), &daddr->sin_port);
		data4.dport = ntohs(dport);

		data4.af = address_family;

		bpf_get_current_comm(&data4.task, sizeof(data4.task));
		ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
		
    } else if (address_family == AF_INET6) {
        struct ipv6_data_t data6 = {.pid = pid, .uid = uid};
		data6.ts_us = bpf_ktime_get_ns() / 1000;
		
		struct sockaddr_in6 *daddr6 = (struct sockaddr_in6 *)address;
		
		bpf_probe_read(&data6.daddr, sizeof(data6.daddr), &daddr6->sin6_addr.in6_u.u6_addr32);

		u16 dport6 = 0;
		bpf_probe_read(&dport6, sizeof(dport6), &daddr6->sin6_port);
		data6.dport = ntohs(dport6);

		data6.af = address_family;

        bpf_get_current_comm(&data6.task, sizeof(data6.task));
        ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
    }

    return 0;
}
`

func main() {
	log.Print("starting socket-connect-bpf")
	setupWorkers()
	select {} // block forever
}

func runKprobes() {
	m := bpf.NewModule(src, []string{})
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

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	go (func() {
		for {
			var event IP4Event
			data := <-channel4
			binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event)
			printIP4Event(&event)
		}
	})()

	go (func() {
		for {
			var event IP6Event
			data := <-channel6
			binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event)
			printIP6Event(&event)
		}
	})()

	if map4 != nil {
		map4.Start()
	}
	if map6 != nil {
		map6.Start()
	}
	<-sig
	if map4 != nil {
		map4.Stop()
	}
	if map6 != nil {
		map6.Stop()
	}
}

func setupWorkers() {
	go runKprobes()
}

func printIP4Event(event *IP4Event) {
	log.Print("IP4Event")
	log.Print(event)
	task := (*C.char)(unsafe.Pointer(&event.Task))
	log.Printf("Pid: %d, Task: %s", event.Pid, C.GoString(task))

	user, err := user.LookupId(strconv.Itoa(int(event.UID)))
	if err != nil {
		log.Printf("Could not lookup user with id: %d", event.UID)
	} else {
		log.Printf("User: %d (%s)", event.UID, user.Username)
	}

	destIP := conv.ToIP4(event.Daddr)
	log.Printf("Destination Address: %s:%d", destIP, event.Dport)
	log.Print("----")
}

func printIP6Event(event *IP6Event) {
	// TODO combine event printing
	log.Print("IP6Event")
	log.Print(event)
	task := (*C.char)(unsafe.Pointer(&event.Task))
	log.Printf("Pid: %d, Task: %s", event.Pid, C.GoString(task))

	user, err := user.LookupId(strconv.Itoa(int(event.UID)))
	if err != nil {
		log.Printf("Could not lookup user with id: %d", event.UID)
	} else {
		log.Printf("User: %d (%s)", event.UID, user.Username)
	}

	destIP := conv.ToIP6(event.Daddr1, event.Daddr2)
	log.Printf("Destination Address: [%s]:%d", destIP, event.Dport)
	log.Print("----")
}

// Event is a common event interface
type Event struct {
	TsUs uint64
	Pid  uint32
	UID  uint32
	Af   uint32
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
