// +build ignore

#include "vmlinux_compact_common.h"

#if defined(__TARGET_ARCH_arm64)
#include "vmlinux_compact_arm64.h"
#elif defined(__TARGET_ARCH_x86)
#include "vmlinux_compact_amd64.h"
#endif

#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_endian.h"

#define TASK_COMM_LEN 16
#define AF_UNIX 1
#define AF_UNSPEC 0
#define AF_INET 2
#define AF_INET6 10

struct ipv4_event_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
    u16 af;
    char task[TASK_COMM_LEN];
    u32 daddr;
    u16 dport;
} __attribute__((packed));

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} ipv4_events SEC(".maps");


struct ipv6_event_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
    u16 af;
    char task[TASK_COMM_LEN];
    unsigned __int128 daddr;
    u16 dport;
} __attribute__((packed));

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} ipv6_events SEC(".maps");

struct other_socket_event_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
    u16 af;
    char task[TASK_COMM_LEN];
} __attribute__((packed));

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} other_socket_events SEC(".maps");

SEC("kprobe/security_socket_connect")
int kprobe_security_socket_connect(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    u32 uid = bpf_get_current_uid_gid();

    struct sockaddr *address = (struct sockaddr *)PT_REGS_PARM2(ctx);

    u16 address_family = 0;
    bpf_probe_read(&address_family, sizeof(address_family), &address->sa_family);

    if (address_family == AF_INET) {
        struct ipv4_event_t data4 = {.pid = pid, .uid = uid, .af = address_family};
        data4.ts_us = bpf_ktime_get_ns() / 1000;

        struct sockaddr_in *daddr = (struct sockaddr_in *)address;

        bpf_probe_read(&data4.daddr, sizeof(data4.daddr), &daddr->sin_addr.s_addr);

        u16 dport = 0;
        bpf_probe_read(&dport, sizeof(dport), &daddr->sin_port);
        data4.dport = bpf_ntohs(dport);

        bpf_get_current_comm(&data4.task, sizeof(data4.task));

        if (data4.dport != 0) {
            bpf_perf_event_output(ctx, &ipv4_events, BPF_F_CURRENT_CPU, &data4, sizeof(data4));
        }
    }
    else if (address_family == AF_INET6) {
        struct ipv6_event_t data6 = {.pid = pid, .uid = uid, .af = address_family};
        data6.ts_us = bpf_ktime_get_ns() / 1000;

        struct sockaddr_in6 *daddr6 = (struct sockaddr_in6 *)address;

        bpf_probe_read(&data6.daddr, sizeof(data6.daddr), &daddr6->sin6_addr.in6_u.u6_addr32);

        u16 dport6 = 0;
        bpf_probe_read(&dport6, sizeof(dport6), &daddr6->sin6_port);
        data6.dport = bpf_ntohs(dport6);

        bpf_get_current_comm(&data6.task, sizeof(data6.task));

        if (data6.dport != 0) {
            bpf_perf_event_output(ctx, &ipv6_events, BPF_F_CURRENT_CPU, &data6, sizeof(data6));
        }
    }
    else if (address_family != AF_UNIX && address_family != AF_UNSPEC) { // other address families, except UNIX and UNSPEC sockets
        struct other_socket_event_t socket_event = {.pid = pid, .uid = uid, .af = address_family};
        socket_event.ts_us = bpf_ktime_get_ns() / 1000;
        bpf_get_current_comm(&socket_event.task, sizeof(socket_event.task));
        bpf_perf_event_output(ctx, &other_socket_events, BPF_F_CURRENT_CPU, &socket_event, sizeof(socket_event));
    }

    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
