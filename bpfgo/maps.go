package bpfgo

import (
	"bytes"
	"encoding/binary"
	"fmt"

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
// const (
// 	PinIP4Stats  = "/sys/fs/bpf/collector/ip4_stats"
// 	PinIP6Stats  = "/sys/fs/bpf/collector/ip6_stats"
// 	PinPortCfg   = "/sys/fs/bpf/collector/port_config"
// 	PinTCLastIP4 = "/sys/fs/bpf/collector/tc_last_ip4"
// )

// func openPinned(path string) (*ebpf.Map, error) {
// 	return ebpf.LoadPinnedMap(path, nil)
// }

// func IntToIP4(nn uint32) net.IP {
// 	b := make([]byte, 4)
// 	binary.BigEndian.PutUint32(b, nn)
// 	return net.IPv4(b[0], b[1], b[2], b[3])
// }

// func IPv6FromKey(key [16]byte) net.IP {
// 	return net.IP(key[:])
// }

// ResetCountersUsingHandles sets every map value to zero while preserving keys.
func ResetCountersUsingHandles(ip4Map, ip6Map *ebpf.Map) error {
	if ip4Map != nil {
		if err := resetMapValuesToZero(ip4Map); err != nil {
			return fmt.Errorf("reset ip4: %w", err)
		}
	}
	if ip6Map != nil {
		if err := resetMapValuesToZero(ip6Map); err != nil {
			return fmt.Errorf("reset ip6: %w", err)
		}
	}
	return nil
}

// CleanupZeroEntriesUsingHandles deletes keys whose values are all zero.
func CleanupZeroEntriesUsingHandles(ip4Map, ip6Map *ebpf.Map) error {
	if ip4Map != nil {
		if err := deleteZeroValueKeys(ip4Map); err != nil {
			return fmt.Errorf("cleanup ip4: %w", err)
		}
	}
	if ip6Map != nil {
		if err := deleteZeroValueKeys(ip6Map); err != nil {
			return fmt.Errorf("cleanup ip6: %w", err)
		}
	}
	return nil
}

// resetMapValuesToZero iterates keys and writes a zeroed value for each key.
func resetMapValuesToZero(m *ebpf.Map) error {
	if m == nil {
		return fmt.Errorf("map is nil")
	}

	ks := int(m.KeySize())
	vs := int(m.ValueSize())
	if ks <= 0 {
		ks = 1
	}
	if vs <= 0 {
		vs = 1
	}

	// allocate raw buffers
	keyBuf := make([]byte, ks)
	valBuf := make([]byte, vs)

	// prepare zero value encoded in native endian for the map value size
	zeroVal := make([]byte, vs)
	// If the value size matches SiaIPStats, encode zero struct for clarity
	if vs == binary.Size(SiaIPStats{}) {
		var z SiaIPStats
		buf := bytes.NewBuffer(zeroVal[:0])
		if err := binary.Write(buf, binary.LittleEndian, &z); err == nil {
			copy(zeroVal, buf.Bytes())
		}
	}

	it := m.Iterate()
	for it.Next(&keyBuf, &valBuf) {
		// copy key because iterator may reuse backing buffer
		kcopy := make([]byte, len(keyBuf))
		copy(kcopy, keyBuf)

		// update the map with zeroVal
		if err := m.Put(kcopy, zeroVal); err != nil {
			// continue but return error to caller
			_ = it.Err()
			return fmt.Errorf("put zero value: %w", err)
		}
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("iterate map: %w", err)
	}
	return nil
}

// deleteZeroValueKeys deletes keys whose decoded SiaIPStats are all zero.
// If the map value size doesn't match SiaIPStats, it will compare raw bytes to zero.
func deleteZeroValueKeys(m *ebpf.Map) error {
	if m == nil {
		return fmt.Errorf("map is nil")
	}

	ks := int(m.KeySize())
	vs := int(m.ValueSize())
	if ks <= 0 {
		ks = 1
	}
	if vs < 0 {
		vs = 0
	}

	keyBuf := make([]byte, ks)
	valBuf := make([]byte, vs)

	it := m.Iterate()
	for it.Next(&keyBuf, &valBuf) {
		// copy key for deletion
		kcopy := make([]byte, len(keyBuf))
		copy(kcopy, keyBuf)

		// check if value is zero
		isZero := true
		if vs == binary.Size(SiaIPStats{}) {
			var s SiaIPStats
			buf := bytes.NewReader(valBuf)
			if err := binary.Read(buf, binary.LittleEndian, &s); err != nil {
				// if unmarshal fails, treat as non-zero to avoid accidental deletion
				isZero = false
			} else {
				if s.ConsensusUp != 0 || s.ConsensusDown != 0 ||
					s.SiamuxUp != 0 || s.SiamuxDown != 0 ||
					s.QuicUp != 0 || s.QuicDown != 0 {
					isZero = false
				}
			}
		} else {
			// fallback: raw bytes all zero?
			for _, b := range valBuf {
				if b != 0 {
					isZero = false
					break
				}
			}
		}

		if isZero {
			if err := m.Delete(kcopy); err != nil {
				// continue deleting others but return the error
				_ = it.Err()
				return fmt.Errorf("delete key: %w", err)
			}
		}
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("iterate map: %w", err)
	}
	return nil
}
