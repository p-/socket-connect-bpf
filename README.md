# socket-connect-bpf

socket-connect-bpf is a Linux command line utility that writes a new line with human-readable information about a connection to the standard output if a new connection to a remote or local target is made.

## Details
socket-connect-bpf is a BPF/eBPF prototype with a kernel probe attached to `security_socket_connect` from [linux/security.h](https://github.com/torvalds/linux/blob/master/include/linux/security.h).

To resolve IP addresses to hostnames a user probe to `getaddrinfo` is used.

## License
The socket-connect-bpf Go code is licensed under the Apache License. The BPF code is licensed under GPL as some [BPF-helpers are GPL-only](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md#helpers).

## Requirements
* x64 CPU(s)
* Recent Linux Kernel: 4.15 or later
* [Go](https://golang.org/)
* upstream [bpfcc-tools](https://github.com/iovisor/bcc/blob/master/INSTALL.md#ubuntu---binary)


## Using
Tested on Ubuntu 18.04.2 with Linux Kernel 4.18.

Build:

    go install
    go generate
    go build

Run:

    sudo ./socket-connect-bpf

## Autonomous System (AS) Information

Information about an autonomous system (AS) that an IP address belongs to is not displayed by default.
It can be turned on with the flag `-a`.

AS Data of [IPtoASN](https://iptoasn.com/) is used.
The local AS-Number lookup will require some more RAM.

## Development

### Tests
Run tests:

    go test ./...

### IDE
[VS Code](https://code.visualstudio.com/) can be used for development. The committed `settings.json` file highlights `*.bpf` files as C files.