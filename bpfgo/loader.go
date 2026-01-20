package bpfgo

import (
    "encoding/binary"
    "fmt"
    "log"
    "net"
    "os"
    "syscall"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
)

const (
    bpfObjPath = "bpf/sia_bpfel.o"
    bpfFsMount = "/sys/fs/bpf"

    PinHostIPv4 = "/sys/fs/bpf/host_ipv4"
    PinHostIPv6 = "/sys/fs/bpf/host_ipv6"
    PinTCDebug  = "/sys/fs/bpf/tc_debug"
    PinTCLastIP = "/sys/fs/bpf/tc_last_ip"

    PinIP4Down = "/sys/fs/bpf/ip4_bytes_down"
    PinIP4Up   = "/sys/fs/bpf/ip4_bytes_up"
    PinIP6Down = "/sys/fs/bpf/ip6_bytes_down"
    PinIP6Up   = "/sys/fs/bpf/ip6_bytes_up"

    progXDP      = "xdp_prog"
    progTCEgress = "tc_egress"
)

type Handles struct {
    Coll    *ebpf.Collection
    XDPLink link.Link
    TCLink  link.Link
}

func (h *Handles) Close() {
    if h.XDPLink != nil {
        _ = h.XDPLink.Close()
    }
    if h.TCLink != nil {
        _ = h.TCLink.Close()
    }
    if h.Coll != nil {
        h.Coll.Close()
    }
    UnloadPinned()
}

func ensureBPFFS() {
    if fi, err := os.Stat(bpfFsMount); err != nil || !fi.IsDir() {
        _ = os.MkdirAll(bpfFsMount, 0755)
    }
    _ = syscall.Mount("bpf", bpfFsMount, "bpf", 0, "")
}

func ifaceIndex(name string) int {
    ifi, err := net.InterfaceByName(name)
    if err != nil {
        log.Fatalf("get interface %s: %v", name, err)
    }
    return ifi.Index
}

func hostAddrs(iface string) (net.IP, net.IP) {
    ifi, err := net.InterfaceByName(iface)
    if err != nil {
        log.Fatalf("get interface %s: %v", iface, err)
    }
    addrs, err := ifi.Addrs()
    if err != nil {
        log.Fatalf("get addrs for %s: %v", iface, err)
    }

    var v4, v6 net.IP
    for _, a := range addrs {
        if ipnet, ok := a.(*net.IPNet); ok {
            ip := ipnet.IP
            if ip4 := ip.To4(); ip4 != nil {
                v4 = ip4
            } else if ip6 := ip.To16(); ip6 != nil {
                v6 = ip6
            }
        }
    }
    return v4, v6
}

func ip4ToU32(ip net.IP) uint32 {
    return binary.BigEndian.Uint32(ip.To4())
}

func Load(iface string) (*Handles, error) {
    ensureBPFFS()

    spec, err := ebpf.LoadCollectionSpec(bpfObjPath)
    if err != nil {
        return nil, fmt.Errorf("load BPF spec: %w", err)
    }

    coll, err := ebpf.NewCollection(spec)
    if err != nil {
        return nil, fmt.Errorf("new collection: %w", err)
    }

    xdpProg := coll.Programs[progXDP]
    tcProg := coll.Programs[progTCEgress]
    if xdpProg == nil || tcProg == nil {
        coll.Close()
        return nil, fmt.Errorf("missing XDP or TC program")
    }

    ifIndex := ifaceIndex(iface)

    xdpLink, err := link.AttachXDP(link.XDPOptions{
        Program:   xdpProg,
        Interface: ifIndex,
        Flags:     link.XDPGenericMode,
    })
    if err != nil {
        coll.Close()
        return nil, fmt.Errorf("attach XDP: %w", err)
    }

    tcLink, err := link.AttachTCX(link.TCXOptions{
        Program:   tcProg,
        Interface: ifIndex,
        Attach:    ebpf.AttachTCXEgress,
    })
    if err != nil {
        xdpLink.Close()
        coll.Close()
        return nil, fmt.Errorf("attach TC: %w", err)
    }

    maps := map[string]string{
        "ip4_bytes_down": PinIP4Down,
        "ip4_bytes_up":   PinIP4Up,
        "ip6_bytes_down": PinIP6Down,
        "ip6_bytes_up":   PinIP6Up,
        "host_ipv4":      PinHostIPv4,
        "host_ipv6":      PinHostIPv6,
        "tc_debug":       PinTCDebug,
        "tc_last_ip":     PinTCLastIP,
    }
    for name, path := range maps {
        m := coll.Maps[name]
        if m == nil {
            xdpLink.Close()
            tcLink.Close()
            coll.Close()
            return nil, fmt.Errorf("missing map %s", name)
        }
        if err := m.Pin(path); err != nil {
            xdpLink.Close()
            tcLink.Close()
            coll.Close()
            return nil, fmt.Errorf("pin %s: %w", name, err)
        }
    }

    host4, host6 := hostAddrs(iface)
    if host4 != nil {
        val := ip4ToU32(host4)
        key := uint32(0)
        if err := coll.Maps["host_ipv4"].Put(&key, &val); err != nil {
            log.Fatalf("write host_ipv4: %v", err)
        }
        log.Printf("host IPv4: %s", host4.String())
    }
    if host6 != nil {
        key := uint32(0)
        var v [16]byte
        copy(v[:], host6.To16())
        if err := coll.Maps["host_ipv6"].Put(&key, &v); err != nil {
            log.Fatalf("write host_ipv6: %v", err)
        }
        log.Printf("host IPv6: %s", host6.String())
    }

    log.Printf("BPF loaded on %s", iface)

    return &Handles{
        Coll:    coll,
        XDPLink: xdpLink,
        TCLink:  tcLink,
    }, nil
}

func UnloadPinned() {
    for _, p := range []string{
        PinHostIPv4, PinHostIPv6, PinTCDebug, PinTCLastIP,
        PinIP4Down, PinIP4Up, PinIP6Down, PinIP6Up,
    } {
        _ = os.Remove(p)
    }
}
