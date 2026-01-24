// prog.c - Sia host traffic collector (consensus/siamux/quic)
// Counts full on-wire bytes (Ethernet frame) per client IP and per configured ports.

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

#define PORT_CONSENSUS 1
#define PORT_SIAMUX    2
#define PORT_QUIC      3

struct sia_ip_stats {
    __u64 consensus_up;
    __u64 consensus_down;
    __u64 siamux_up;
    __u64 siamux_down;
    __u64 quic_up;
    __u64 quic_down;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u16);
} port_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535);
    __type(key, __u32);              // IPv4 address (network order)
    __type(value, struct sia_ip_stats);
} ip4_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535);
    __type(key, struct in6_addr);    // IPv6 address
    __type(value, struct sia_ip_stats);
} ip6_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u32);
} tc_last_ip4 SEC(".maps");

static __always_inline __u16 get_port(__u32 name)
{
    __u16 *p = bpf_map_lookup_elem(&port_config, &name);
    return p ? *p : 0;
}

static __always_inline void account_ipv4(__u32 ip, __u8 proto,
                                         __u16 sport, __u16 dport,
                                         __u64 bytes, bool egress)
{
    struct sia_ip_stats *st;
    struct sia_ip_stats zero = {};

    st = bpf_map_lookup_elem(&ip4_stats, &ip);
    if (!st) {
        bpf_map_update_elem(&ip4_stats, &ip, &zero, BPF_ANY);
        st = bpf_map_lookup_elem(&ip4_stats, &ip);
        if (!st)
            return;
    }

    __u16 p_consensus = get_port(PORT_CONSENSUS);
    __u16 p_siamux    = get_port(PORT_SIAMUX);
    __u16 p_quic      = get_port(PORT_QUIC);

    __u16 port = egress ? sport : dport;

    if (proto == IPPROTO_TCP) {
        if (port == p_consensus) {
            if (egress) st->consensus_up   += bytes;
            else        st->consensus_down += bytes;
        } else if (port == p_siamux) {
            if (egress) st->siamux_up   += bytes;
            else        st->siamux_down += bytes;
        }
    } else if (proto == IPPROTO_UDP) {
        if (port == p_quic) {
            if (egress) st->quic_up   += bytes;
            else        st->quic_down += bytes;
        }
    }
}

static __always_inline void account_ipv6(struct in6_addr *ip6, __u8 proto,
                                         __u16 sport, __u16 dport,
                                         __u64 bytes, bool egress)
{
    struct sia_ip_stats *st;
    struct sia_ip_stats zero = {};

    st = bpf_map_lookup_elem(&ip6_stats, ip6);
    if (!st) {
        bpf_map_update_elem(&ip6_stats, ip6, &zero, BPF_ANY);
        st = bpf_map_lookup_elem(&ip6_stats, ip6);
        if (!st)
            return;
    }

    __u16 p_consensus = get_port(PORT_CONSENSUS);
    __u16 p_siamux    = get_port(PORT_SIAMUX);
    __u16 p_quic      = get_port(PORT_QUIC);

    __u16 port = egress ? sport : dport;

    if (proto == IPPROTO_TCP) {
        if (port == p_consensus) {
            if (egress) st->consensus_up   += bytes;
            else        st->consensus_down += bytes;
        } else if (port == p_siamux) {
            if (egress) st->siamux_up   += bytes;
            else        st->siamux_down += bytes;
        }
    } else if (proto == IPPROTO_UDP) {
        if (port == p_quic) {
            if (egress) st->quic_up   += bytes;
            else        st->quic_down += bytes;
        }
    }
}

/*
 * handle_ipv4/6 now accept bytes_l2 which represents the full on-wire
 * bytes for the packet (Ethernet frame length at XDP, skb->len at TC).
 * We keep computing sport/dport and proto as before, but we pass
 * bytes_l2 into account_* so the existing counters reflect full-frame bytes.
 */

static __always_inline int handle_ipv4(void *data, void *data_end,
                                       __u64 bytes_l2,
                                       bool egress)
{
    struct iphdr *iph = data;
    if ((void *)(iph + 1) > data_end)
        return 0;

    __u8 proto = iph->protocol;
    __u32 ihl = iph->ihl * 4;
    if ((void *)iph + ihl > data_end)
        return 0;

    __u16 sport = 0, dport = 0;

    void *l4 = (void *)iph + ihl;
    if (l4 > data_end)
        return 0;

    if (proto == IPPROTO_TCP) {
        struct tcphdr *th = l4;
        if ((void *)(th + 1) > data_end)
            return 0;
        sport = bpf_ntohs(th->source);
        dport = bpf_ntohs(th->dest);
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *uh = l4;
        if ((void *)(uh + 1) > data_end)
            return 0;
        sport = bpf_ntohs(uh->source);
        dport = bpf_ntohs(uh->dest);
    } else {
        return 0;
    }

    __u32 src = iph->saddr;
    __u32 dst = iph->daddr;

    // For ingress: client is src, for egress: client is dst
    __u32 client = egress ? dst : src;

    // Use bytes_l2 (full on-wire bytes) as the metric stored in the existing counters.
    account_ipv4(client, proto, sport, dport, bytes_l2, egress);

    if (egress) {
        __u32 key0 = 0, key1 = 1;
        bpf_map_update_elem(&tc_last_ip4, &key0, &src, BPF_ANY);
        bpf_map_update_elem(&tc_last_ip4, &key1, &dst, BPF_ANY);
    }

    return 0;
}

static __always_inline int handle_ipv6(void *data, void *data_end,
                                       __u64 bytes_l2,
                                       bool egress)
{
    struct ipv6hdr *ip6h = data;
    if ((void *)(ip6h + 1) > data_end)
        return 0;

    __u8 proto = ip6h->nexthdr;
    void *l4 = ip6h + 1;
    if (l4 > data_end)
        return 0;

    __u16 sport = 0, dport = 0;

    if (proto == IPPROTO_TCP) {
        struct tcphdr *th = l4;
        if ((void *)(th + 1) > data_end)
            return 0;
        sport = bpf_ntohs(th->source);
        dport = bpf_ntohs(th->dest);
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *uh = l4;
        if ((void *)(uh + 1) > data_end)
            return 0;
        sport = bpf_ntohs(uh->source);
        dport = bpf_ntohs(uh->dest);
    } else {
        return 0;
    }

    struct in6_addr src = ip6h->saddr;
    struct in6_addr dst = ip6h->daddr;

    struct in6_addr client = egress ? dst : src;

    // Use bytes_l2 (full on-wire bytes) as the metric stored in the existing counters.
    account_ipv6(&client, proto, sport, dport, bytes_l2, egress);

    return 0;
}

SEC("xdp")
int xdp_ingress(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Full on-wire bytes from Ethernet header to end of packet
    __u64 bytes_l2 = (__u64)((char *)data_end - (char *)data);

    __u16 h_proto = bpf_ntohs(eth->h_proto);
    void *nh = eth + 1;

    if (h_proto == ETH_P_IP) {
        handle_ipv4(nh, data_end, bytes_l2, false);
    } else if (h_proto == ETH_P_IPV6) {
        handle_ipv6(nh, data_end, bytes_l2, false);
    }

    return XDP_PASS;
}

SEC("tc")
int tc_egress(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return BPF_OK;

    // Use skb->len as the best approximation of full on-wire bytes at TC
    __u64 bytes_l2 = skb->len;

    __u16 h_proto = bpf_ntohs(eth->h_proto);
    void *nh = eth + 1;

    if (h_proto == ETH_P_IP) {
        handle_ipv4(nh, data_end, bytes_l2, true);
    } else if (h_proto == ETH_P_IPV6) {
        handle_ipv6(nh, data_end, bytes_l2, true);
    }

    return BPF_OK;
}
