package live

import (
	"fmt"
	"log"
	"time"

	"github.com/back2basic/collector/bpfgo"

	"github.com/cilium/ebpf"
)

func openPinned(path string) *ebpf.Map {
	m, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return nil
	}
	return m
}

func dumpDown4() {
	m := openPinned(bpfgo.PinIP4Down)
	if m == nil {
		return
	}
	defer m.Close()

	it := m.Iterate()
	var key uint32
	var val bpfgo.SiaIPStats

	for it.Next(&key, &val) {
		ip := bpfgo.IntToIP4(key)
        // skip if value are 0
        if val.Down9981 == 0 && val.Down9984TCP == 0 && val.Down9984UDP == 0 {
            continue
        }
		fmt.Printf("DOWN4: ip=%s  down_9981=%d  down_9984_tcp=%d  down_9984_udp=%d\n",
			ip, val.Down9981, val.Down9984TCP, val.Down9984UDP)
	}
}

func dumpUp4() {
	m := openPinned(bpfgo.PinIP4Up)
	if m == nil {
		return
	}
	defer m.Close()

	it := m.Iterate()
	var key uint32
	var val bpfgo.SiaIPStats

	for it.Next(&key, &val) {
		ip := bpfgo.IntToIP4(key)
        // skip if value are 0
        if val.Up9981 == 0 && val.Up9984TCP == 0 && val.Up9984UDP == 0 {
            continue
        }
		fmt.Printf("UP4:   ip=%s  up_9981=%d  up_9984_tcp=%d  up_9984_udp=%d\n",
			ip, val.Up9981, val.Up9984TCP, val.Up9984UDP)
	}
}

func dumpDown6() {
	m := openPinned(bpfgo.PinIP6Down)
	if m == nil {
		return
	}
	defer m.Close()

	it := m.Iterate()
	var key [16]byte
	var val bpfgo.SiaIPStats

	for it.Next(&key, &val) {
		ip := bpfgo.IPv6FromKey(key)
        // skip if value are 0
        if val.Down9981 == 0 && val.Down9984TCP == 0 && val.Down9984UDP == 0 {
            continue
        }
		fmt.Printf("DOWN6: ip=%s  down_9981=%d  down_9984_tcp=%d  down_9984_udp=%d\n",
			ip, val.Down9981, val.Down9984TCP, val.Down9984UDP)
	}
}

func dumpUp6() {
	m := openPinned(bpfgo.PinIP6Up)
	if m == nil {
		return
	}
	defer m.Close()

	it := m.Iterate()
	var key [16]byte
	var val bpfgo.SiaIPStats

	for it.Next(&key, &val) {
		ip := bpfgo.IPv6FromKey(key)
        // skip if value are 0
        if val.Up9981 == 0 && val.Up9984TCP == 0 && val.Up9984UDP == 0 {
            continue
        }
		fmt.Printf("UP6:   ip=%s  up_9981=%d  up_9984_tcp=%d  up_9984_udp=%d\n",
			ip, val.Up9981, val.Up9984TCP, val.Up9984UDP)
	}
}

func dumpTCDebug() {
	m := openPinned(bpfgo.PinTCDebug)
	if m == nil {
		return
	}
	defer m.Close()

	for i := 0; i < 32; i++ {
		key := uint32(i)
		var val uint64
		if err := m.Lookup(&key, &val); err == nil && val > 0 {
			log.Printf("TCDBG[%d] = %d", i, val)
		}
	}
}

func dumpTCLastIP() {
	m := openPinned(bpfgo.PinTCLastIP)
	if m == nil {
		return
	}
	defer m.Close()

	for i := 0; i < 2; i++ {
		key := uint32(i)
		var val uint32
		if err := m.Lookup(&key, &val); err == nil {
			ip := bpfgo.IntToIP4(val)
			log.Printf("TC_LAST_IP[%d] = %s", i, ip)
		}
	}
}

func Run(h *bpfgo.Handles, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		fmt.Println("---- DOWN (XDP ingress) ----")
		dumpDown4()
		dumpDown6()

		fmt.Println("---- UP (TC egress) --------")
		dumpUp4()
		dumpUp6()

		fmt.Println("---------- DEBUG -----------")
		dumpTCDebug()
		dumpTCLastIP()

		fmt.Println("-----------------------------")

		// if doReset {
		//     bpfgo.ResetCounters()
		//     bpfgo.CleanupZeroEntries()
		// }
	}
}
