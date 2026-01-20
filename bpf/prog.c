// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stdbool.h>

char LICENSE[] SEC("license") = "GPL";

struct sia_ip_stats {
    __u64 up_9981;
    __u64 down_9981;
    __u64 up_9984_tcp;
    __u64 down_9984_tcp;
    __u64 up_9984_udp;
    __u64 down_9984_udp;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535);
    __type(key, __u32);
    __type(value, struct sia_ip_stats);
} ip4_bytes_up SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535);
    __type(key, __u32);
    __type(value, struct sia_ip_stats);
} ip4_bytes_down SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535);
    __type(key, struct in6_addr);
    __type(value, struct sia_ip_stats);
} ip6_bytes_up SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535);
    __type(key, struct in6_addr);
    __type(value, struct sia_ip_stats);
} ip6_bytes_down SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} host_ipv4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8[16]);
} host_ipv6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 32);
    __type(key, __u32);
    __type(value, __u64);
} tc_debug SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u32);
} tc_last_ip SEC(".maps");

static __always_inline void tcdbg_inc(__u32 idx, __u64 v)
{
    __u64 *p = bpf_map_lookup_elem(&tc_debug, &idx);
    if (p)
        __sync_fetch_and_add(p, v);
}

static __always_inline int handle_ipv4(__u32 client_ip_net, __u8 proto,
                                       __u16 sport, __u16 dport,
                                       __u64 bytes, bool egress)
{
    struct sia_ip_stats zero = {};
    struct sia_ip_stats *st;
    void *map = egress ? (void *)&ip4_bytes_up : (void *)&ip4_bytes_down;

    // store key in host byte order for Go
    __u32 client_ip = bpf_ntohl(client_ip_net);

    st = bpf_map_lookup_elem(map, &client_ip);
    if (!st) {
        bpf_map_update_elem(map, &client_ip, &zero, BPF_ANY);
        st = bpf_map_lookup_elem(map, &client_ip);
        if (!st)
            return 0;
    }

    // server: ingress matches on dport, egress on sport
    __u16 port = bpf_ntohs(egress ? sport : dport);

    if (proto == IPPROTO_TCP) {
        if (port == 9981) {
            if (egress) st->up_9981 += bytes;
            else        st->down_9981 += bytes;
        } else if (port == 9984) {
            if (egress) st->up_9984_tcp += bytes;
            else        st->down_9984_tcp += bytes;
        }
    } else if (proto == IPPROTO_UDP) {
        if (port == 9984) {
            if (egress) st->up_9984_udp += bytes;
            else        st->down_9984_udp += bytes;
        }
    }

    return 0;
}

static __always_inline int handle_ipv6(struct in6_addr *client_ip, __u8 proto,
                                       __u16 sport, __u16 dport,
                                       __u64 bytes, bool egress)
{
    struct sia_ip_stats zero = {};
    struct sia_ip_stats *st;
    void *map = egress ? (void *)&ip6_bytes_up : (void *)&ip6_bytes_down;

    st = bpf_map_lookup_elem(map, client_ip);
    if (!st) {
        bpf_map_update_elem(map, client_ip, &zero, BPF_ANY);
        st = bpf_map_lookup_elem(map, client_ip);
        if (!st)
            return 0;
    }

    __u16 port = bpf_ntohs(egress ? sport : dport);

    if (proto == IPPROTO_TCP) {
        if (port == 9981) {
            if (egress) st->up_9981 += bytes;
            else        st->down_9981 += bytes;
        } else if (port == 9984) {
            if (egress) st->up_9984_tcp += bytes;
            else        st->down_9984_tcp += bytes;
        }
    } else if (proto == IPPROTO_UDP) {
        if (port == 9984) {
            if (egress) st->up_9984_udp += bytes;
            else        st->down_9984_udp += bytes;
        }
    }

    return 0;
}

static __always_inline int parse_ipv4(void *data, void *data_end, bool egress)
{
    struct ethhdr *eth = data;
    struct iphdr *iph;
    __u64 off = sizeof(*eth);

    if (data + off > data_end)
        return 0;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return 0;

    iph = data + off;
    if ((void *)(iph + 1) > data_end)
        return 0;

    __u8 proto = iph->protocol;
    __u32 client_ip_net = egress ? iph->daddr : iph->saddr;
    __u64 bytes = (__u64)((char *)data_end - (char *)data);

    void *l4 = (void *)iph + iph->ihl * 4;
    if (l4 > data_end)
        return 0;

    __u16 sport = 0, dport = 0;

    if (proto == IPPROTO_TCP) {
        struct tcphdr *th = l4;
        if ((void *)(th + 1) > data_end)
            return 0;
        sport = th->source;
        dport = th->dest;
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *uh = l4;
        if ((void *)(uh + 1) > data_end)
            return 0;
        sport = uh->source;
        dport = uh->dest;
    } else {
        return 0;
    }

    return handle_ipv4(client_ip_net, proto, sport, dport, bytes, egress);
}

static __always_inline int parse_ipv6(void *data, void *data_end, bool egress)
{
    struct ethhdr *eth = data;
    struct ipv6hdr *ip6h;
    __u64 off = sizeof(*eth);

    if (data + off > data_end)
        return 0;

    if (eth->h_proto != bpf_htons(ETH_P_IPV6))
        return 0;

    ip6h = data + off;
    if ((void *)(ip6h + 1) > data_end)
        return 0;

    __u8 proto = ip6h->nexthdr;
    struct in6_addr client_ip = egress ? ip6h->daddr : ip6h->saddr;
    __u64 bytes = (__u64)((char *)data_end - (char *)data);

    void *l4 = (void *)(ip6h + 1);
    if (l4 > data_end)
        return 0;

    __u16 sport = 0, dport = 0;

    if (proto == IPPROTO_TCP) {
        struct tcphdr *th = l4;
        if ((void *)(th + 1) > data_end)
            return 0;
        sport = th->source;
        dport = th->dest;
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *uh = l4;
        if ((void *)(uh + 1) > data_end)
            return 0;
        sport = uh->source;
        dport = uh->dest;
    } else {
        return 0;
    }

    return handle_ipv6(&client_ip, proto, sport, dport, bytes, egress);
}

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    parse_ipv4(data, data_end, false);
    parse_ipv6(data, data_end, false);

    return XDP_PASS;
}

SEC("tc")
int tc_egress(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    parse_ipv4(data, data_end, true);
    parse_ipv6(data, data_end, true);

    // debug: last two IPs, stored in host order
    __u32 key0 = 0, key1 = 1;
    struct iphdr *iph;
    struct ethhdr *eth = data;
    __u64 off = sizeof(*eth);

    if (data + off <= data_end && eth->h_proto == bpf_htons(ETH_P_IP)) {
        iph = data + off;
        if ((void *)(iph + 1) <= data_end) {
            __u32 src = bpf_ntohl(iph->saddr);
            __u32 dst = bpf_ntohl(iph->daddr);
            bpf_map_update_elem(&tc_last_ip, &key0, &src, BPF_ANY);
            bpf_map_update_elem(&tc_last_ip, &key1, &dst, BPF_ANY);
        }
    }

    return BPF_OK;
}
