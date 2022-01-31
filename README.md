# socket-connect-bpf

socket-connect-bpf is a Linux command line utility that writes human-readable information about each application that makes new (network) connections to the standard output.

![socket-connect-bpf while making a request with curl](samples/socket-connect-bpf.gif)

More [sample output](samples/socket-connect-bpf-example.txt).

## Details
socket-connect-bpf is a BPF/eBPF prototype with a kernel probe attached to [`security_socket_connect`](https://github.com/torvalds/linux/blob/master/include/linux/security.h). Connections to AF_UNSPEC and AF_UNIX are explicitly excluded. 

Following information about each request is displayed if possible:

| Name          | Description                                              | Sample             |
| --------------|----------------------------------------------------------|--------------------|
| Time          | Time at which the connection event was received.         | `17:15:58`         |
| AF            | Address family                                           | `AF_INET`          |
| PID           | Process ID of the process making the request.            | `8549`             |
| Process       | Process path/args of the process making the request.     | `/usr/bin/curl`    |
| User          | Username under which the process is executed.            | `root`             |
| Destination   | IP address and port of the destination.                  | `127.0.0.1 53`     |
| AS-Info       | Info about the autonomous system (AS) of the IP address. | `AS36459 (GITHUB)` |

## Use cases

You might want to try `socket-connect-bpf` for the following use cases:

* Check if an application contains analytics.
* Check if your trusted dependencies communicate with the outside world.
* As a less invasive alternative to Kernel modules that provide the same functionality.

## License
The socket-connect-bpf Go code is licensed under the Apache License. The BPF code is licensed under GPL as some [BPF-helpers are GPL-only](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md#helpers).

## Requirements
* x64/amd64 or AArch64/arm64 CPU
* Recent Linux Kernel: 4.18 or later
* [Go](https://golang.org/) 1.17 or later

## Installation

### Install binaries (Version 0.4.0 or later)
Tested on following architecures:

* amd64 (Intel x64 CPU)
* arm64 (AWS Graviton2/Arm Neoverse-N1)

Instructions tested on Ubuntu 20.04 with Linux Kernel 5.13:

* Extract the corresponding `socket-connect-bpf-*.tar.gz` [release](https://github.com/p-/socket-connect-bpf/releases).

### Verify binaries (Version 0.4.0 or later)
Tarballs can be verified with [minisign](https://github.com/jedisct1/minisign) and following public key:

`RWRUqB/iFRENms4B2LbOrNGizwXbStkIPE8sUq01r63cXJP8kzHp+ITv`

## Running:

    sudo ./socket-connect-bpf

### Print all
Print all `-a` also prints the process arguments and the AS information.

    sudo ./socket-connect-bpf -a

### Autonomous System (AS) Information

Information about an autonomous system (AS) that an IP address belongs to is not displayed by default.
It can be turned on with the print all flag `-a`.

    sudo ./socket-connect-bpf -a

#### AS data
AS data of [IPtoASN](https://iptoasn.com/) is used.
The local AS-Number lookup will require some more RAM.

To update the AS data used while developing run:

    ./updateASData.sh

## Development


### Build code from repository
Step-by-Step instructions for Ubuntu 20.04 with Linux Kernel 5.13.

    # Install Go 1.17 or later (if not already installed)
    sudo snap install --classic go

    # Install Clang 12 (for compiling the BPF sources)
    sudo apt install clang-12

    # Change into a folder of your choice and clone socket-connect-bpf
    git clone https://github.com/p-/socket-connect-bpf.git

    cd socket-connect-bpf
    
    go generate
    go build

### Tests
Run tests:

    go test ./...

### IDE
[VS Code](https://code.visualstudio.com/) or any other Go Lang IDE can be used for development.
