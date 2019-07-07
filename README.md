# socket-connect-bpf

BPF/eBPF prototype with a probe attached to `security_socket_connect` from [linux/security.h](https://github.com/torvalds/linux/blob/master/include/linux/security.h).

## License
The socket-connect-bpf Go code is licensed under the Apache License. The BPF code is licensed under GPL as some [BPF-helpers are GPL-only](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md#helpers).

## Requirements
* Recent Kernel: 4.18 and later
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

Stop:

    sudo killall socket-connect-bpf

## AS Numbers

AS Data of [IPtoASN](https://iptoasn.com/) is used.
The local AS-Number lookup will require some more RAM.

## Development
Run tests:

    go test ./...
