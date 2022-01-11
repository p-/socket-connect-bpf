// +build ignore

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>

// Based on https://github.com/iovisor/bcc/blob/51d62d36bd072530a238ac147a61b631fdc44659/tools/gethostlatency.py
// map to getaddrinfo

// struct addrinfo copied from: include/netdb.h
struct addrinfo
{
  int ai_flags;         /* Input flags.  */
  int ai_family;        /* Protocol family for socket.  */
  int ai_socktype;      /* Socket type.  */
  int ai_protocol;      /* Protocol for socket.  */
  u32 ai_addrlen;       /* Length of socket address.  */ // CHANGED from socklen_t
  struct sockaddr *ai_addr; /* Socket address for socket.  */
  char *ai_canonname;       /* Canonical name for service location.  */
  struct addrinfo *ai_next; /* Pointer to next in list.  */
};

struct val_t {
    u32 pid;
    char host[80];
} __attribute__((packed));

struct data_t {
    u32 pid;
    u32 af;
    u32 ip4addr;
    __int128 ip6addr;
    char host[80];
} __attribute__((packed));

BPF_HASH(start, u32, struct val_t);
BPF_HASH(currres, u32, struct addrinfo **);
BPF_PERF_OUTPUT(events);

int getaddrinfo_entry(struct pt_regs *ctx, const char *node, const char *service,
                       const struct addrinfo *hints,
                       struct addrinfo **res) {
    if (!PT_REGS_PARM1(ctx))
        return 0;
    struct val_t val = {};

    bpf_probe_read(&val.host, sizeof(val.host),
                    (void *)PT_REGS_PARM1(ctx));
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    val.pid = pid;
    start.update(&pid, &val);
    currres.update(&pid, &res);
    
    return 0;
}
int getaddrinfo_return(struct pt_regs *ctx) {
    struct val_t *valp;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    valp = start.lookup(&pid);
    if (valp == 0) {
        return 0; // missed start
    }

    struct addrinfo ***res;
    res = currres.lookup(&pid);
    if (!res || !(*res)) {
        return 0;   // missed entry
    }

    struct addrinfo **resx = *res;
    struct addrinfo *resxx = *resx;

    #pragma unroll
    for (int i = 0; i < 9; i++) //  Limit max entries that are considered
    {
        struct data_t data = {};
        bpf_probe_read(&data.host, sizeof(data.host), (void *)valp->host);
        data.af = resxx->ai_family;

        if (data.af == AF_INET) {
            struct sockaddr_in *daddr = (struct sockaddr_in *)resxx->ai_addr;
            bpf_probe_read(&data.ip4addr, sizeof(data.ip4addr), &daddr->sin_addr.s_addr);
        } else if (data.af == AF_INET6) {
            struct sockaddr_in6 *daddr6 = (struct sockaddr_in6 *)resxx->ai_addr;
            bpf_probe_read(&data.ip6addr, sizeof(data.ip6addr), &daddr6->sin6_addr.in6_u.u6_addr32);
        }

        data.pid = valp->pid;
        events.perf_submit(ctx, &data, sizeof(data));

        if (resxx->ai_next == NULL) {
            break;
        }
        resxx = resxx->ai_next;
    }

    start.delete(&pid);
    currres.delete(&pid);
    return 0;
}
