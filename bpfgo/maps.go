package bpfgo

import (
    "encoding/binary"
    "net"

    "github.com/cilium/ebpf"
)

type SiaIPStats struct {
    Up9981      uint64
    Down9981    uint64
    Up9984TCP   uint64
    Down9984TCP uint64
    Up9984UDP   uint64
    Down9984UDP uint64
}

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

func ResetCounters() {
    for _, p := range []string{PinIP4Down, PinIP4Up, PinIP6Down, PinIP6Up} {
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

func CleanupZeroEntries() {
    paths := []string{PinIP4Down, PinIP4Up, PinIP6Down, PinIP6Up}

    for _, p := range paths {
        m, err := openPinned(p)
        if err != nil {
            continue
        }

        it := m.Iterate()
        var key []byte
        var val SiaIPStats

        for it.Next(&key, &val) {
            if val.Up9981 == 0 &&
                val.Down9981 == 0 &&
                val.Up9984TCP == 0 &&
                val.Down9984TCP == 0 &&
                val.Up9984UDP == 0 &&
                val.Down9984UDP == 0 {
                _ = m.Delete(key)
            }
        }

        m.Close()
    }
}
