package bpfgo

import (
    "encoding/binary"
    "net"

    "github.com/cilium/ebpf"
)

// New semantic stats struct (matches BPF struct)
type SiaIPStats struct {
    ConsensusUp   uint64
    ConsensusDown uint64
    SiamuxUp      uint64
    SiamuxDown    uint64
    QuicUp        uint64
    QuicDown      uint64
}

// New pinned map paths (matches your Makefile install paths)
const (
    PinIP4Stats  = "/sys/fs/bpf/collector/ip4_stats"
    PinIP6Stats  = "/sys/fs/bpf/collector/ip6_stats"
    PinPortCfg   = "/sys/fs/bpf/collector/port_config"
    PinTCLastIP4 = "/sys/fs/bpf/collector/tc_last_ip4"
)

func openPinned(path string) (*ebpf.Map, error) {
    return ebpf.LoadPinnedMap(path, nil)
}

func IntToIP4(nn uint32) net.IP {
    b := make([]byte, 4)
    binary.BigEndian.PutUint32(b, nn)
    return net.IPv4(b[0], b[1], b[2], b[3])
}

func IPv6FromKey(key [16]byte) net.IP {
    return net.IP(key[:])
}

// ResetCounters wipes all IPv4 + IPv6 stats
func ResetCounters() {
    paths := []string{PinIP4Stats, PinIP6Stats}

    for _, p := range paths {
        m, err := openPinned(p)
        if err != nil {
            continue
        }

        it := m.Iterate()
        var k []byte
        var v []byte

        for it.Next(&k, &v) {
            _ = m.Delete(k)
        }

        m.Close()
    }
}

// CleanupZeroEntries removes entries where all counters are zero
func CleanupZeroEntries() {
    paths := []string{PinIP4Stats, PinIP6Stats}

    for _, p := range paths {
        m, err := openPinned(p)
        if err != nil {
            continue
        }

        it := m.Iterate()
        var key []byte
        var val SiaIPStats

        for it.Next(&key, &val) {
            if val.ConsensusUp == 0 &&
                val.ConsensusDown == 0 &&
                val.SiamuxUp == 0 &&
                val.SiamuxDown == 0 &&
                val.QuicUp == 0 &&
                val.QuicDown == 0 {
                _ = m.Delete(key)
            }
        }

        m.Close()
    }
}
