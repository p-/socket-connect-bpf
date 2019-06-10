# socket-connect-bpf

BPF/eBPF prototype with a probe attached to `security_socket_connect` from [linux/security.h](https://github.com/torvalds/linux/blob/master/include/linux/security.h).

Please note: does not work yet.

## Using
Tested on Ubuntu 18.04.2 with Linux Kernel 4.18.

Build:

    go build

Run:

    sudo ./socket-connect-bpf

Stop:

    sudo killall socket-connect-bpf
