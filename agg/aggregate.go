package agg

import (
	"log"
	"os"
	"time"

	"github.com/back2basic/euregiohosting/collector/bpfgo"
	"github.com/back2basic/euregiohosting/collector/dns"
	"github.com/back2basic/euregiohosting/collector/model"
	"github.com/back2basic/euregiohosting/collector/storage"

	"github.com/cilium/ebpf"
)

func openPinned(path string) *ebpf.Map {
	m, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return nil
	}
	return m
}

func Run(h *bpfgo.Handles, flushInterval time.Duration, appwriteInterval time.Duration) {
	hostname := os.Getenv("SIA_HOSTNAME")
	if hostname == "" {
		log.Fatalln("SIA_HOSTNAME is not set")
	}

	flushTicker := time.NewTicker(flushInterval)
	// appwriteTimer := alignedTicker(appwriteInterval)

	// var appwriteTicker *time.Ticker

	for {
		select {
		case <-flushTicker.C:
			flushToSQLite(hostname)

		// case <-appwriteTimer.C:
		// 	pushDailyToAppwrite(hostname)
		// 	appwriteTicker = time.NewTicker(appwriteInterval)

		// case <-func() <-chan time.Time { 
		// 	if appwriteTicker != nil { 
		// 		return appwriteTicker.C 
		// 		} 
		// 		return nil 
		// 		}():
		// 		 pushDailyToAppwrite(hostname)
		}
	}
}

func flushToSQLite(hostname string) {
	now := time.Now().Unix()

	var rec4 []model.TrafficRecord4
	var rec6 []model.TrafficRecord6

	// -------- IPv4 UP --------
	if m := openPinned(bpfgo.PinIP4Up); m != nil {
		iter := m.Iterate()
		var key uint32
		var val bpfgo.SiaIPStats

		for iter.Next(&key, &val) {
			ip := bpfgo.IntToIP4(key)
			name := dns.Resolve(ip)

			// skip if value are 0
			if val.Up9981 == 0 && val.Up9984TCP == 0 && val.Up9984UDP == 0 {
				continue
			}

			rec4 = append(rec4, model.TrafficRecord4{
				Key:         key,
				IP:          ip.String(),
				DNS:         name,
				Up9981:      val.Up9981,
				Down9981:    0,
				Up9984TCP:   val.Up9984TCP,
				Down9984TCP: 0,
				Up9984UDP:   val.Up9984UDP,
				Down9984UDP: 0,
				Timestamp:   now,
			})
		}
		m.Close()
	}

	// -------- IPv4 DOWN --------
	if m := openPinned(bpfgo.PinIP4Down); m != nil {
		iter := m.Iterate()
		var key uint32
		var val bpfgo.SiaIPStats

		for iter.Next(&key, &val) {
			ip := bpfgo.IntToIP4(key)
			name := dns.Resolve(ip)

			// skip if value are 0
			if val.Down9981 == 0 && val.Down9984TCP == 0 && val.Down9984UDP == 0 {
				continue
			}

			rec4 = append(rec4, model.TrafficRecord4{
				Key:         key,
				IP:          ip.String(),
				DNS:         name,
				Up9981:      0,
				Down9981:    val.Down9981,
				Up9984TCP:   0,
				Down9984TCP: val.Down9984TCP,
				Up9984UDP:   0,
				Down9984UDP: val.Down9984UDP,
				Timestamp:   now,
			})
		}
		m.Close()
	}

	// -------- IPv6 UP --------
	if m := openPinned(bpfgo.PinIP6Up); m != nil {
		iter := m.Iterate()
		var key [16]byte
		var val bpfgo.SiaIPStats

		for iter.Next(&key, &val) {
			ip := bpfgo.IPv6FromKey(key)
			name := dns.Resolve(ip)

			// skip if value are 0
			if val.Up9981 == 0 && val.Up9984TCP == 0 && val.Up9984UDP == 0 {
				continue
			}

			rec6 = append(rec6, model.TrafficRecord6{
				Key:         key,
				IP:          ip.String(),
				DNS:         name,
				Up9981:      val.Up9981,
				Down9981:    0,
				Up9984TCP:   val.Up9984TCP,
				Down9984TCP: 0,
				Up9984UDP:   val.Up9984UDP,
				Down9984UDP: 0,
				Timestamp:   now,
			})
		}
		m.Close()
	}

	// -------- IPv6 DOWN --------
	if m := openPinned(bpfgo.PinIP6Down); m != nil {
		iter := m.Iterate()
		var key [16]byte
		var val bpfgo.SiaIPStats

		for iter.Next(&key, &val) {
			ip := bpfgo.IPv6FromKey(key)
			name := dns.Resolve(ip)

			// skip if value are 0
			if val.Down9981 == 0 && val.Down9984TCP == 0 && val.Down9984UDP == 0 {
				continue
			}

			rec6 = append(rec6, model.TrafficRecord6{
				Key:         key,
				IP:          ip.String(),
				DNS:         name,
				Up9981:      0,
				Down9981:    val.Down9981,
				Up9984TCP:   0,
				Down9984TCP: val.Down9984TCP,
				Up9984UDP:   0,
				Down9984UDP: val.Down9984UDP,
				Timestamp:   now,
			})
		}
		m.Close()
	}

	// Nothing to flush
	if len(rec4)+len(rec6) == 0 {
		return
	}

	log.Printf("AGG: flushing %d IPv4 + %d IPv6 rows to SQLite", len(rec4), len(rec6))

	// Write to SQLite
	if err := storage.FlushSQLite(hostname, rec4, rec6); err != nil {
		log.Printf("AGG: SQLite flush error: %v", err)
		return
	}

	// Reset all maps after successful flush
	resetAllMaps(rec4, rec6)
}

func resetAllMaps(rec4 []model.TrafficRecord4, rec6 []model.TrafficRecord6) {
	zero := bpfgo.SiaIPStats{}

	// IPv4 UP
	if m := openPinned(bpfgo.PinIP4Up); m != nil {
		for _, r := range rec4 {
			_ = m.Update(&r.Key, &zero, ebpf.UpdateAny)
		}
		m.Close()
	}

	// IPv4 DOWN
	if m := openPinned(bpfgo.PinIP4Down); m != nil {
		for _, r := range rec4 {
			_ = m.Update(&r.Key, &zero, ebpf.UpdateAny)
		}
		m.Close()
	}

	// IPv6 UP
	if m := openPinned(bpfgo.PinIP6Up); m != nil {
		for _, r := range rec6 {
			_ = m.Update(&r.Key, &zero, ebpf.UpdateAny)
		}
		m.Close()
	}

	// IPv6 DOWN
	if m := openPinned(bpfgo.PinIP6Down); m != nil {
		for _, r := range rec6 {
			_ = m.Update(&r.Key, &zero, ebpf.UpdateAny)
		}
		m.Close()
	}
}

func resetBPFMaps(rec4 []model.TrafficRecord4, rec6 []model.TrafficRecord6) {
	// IPv4
	if m4 := openPinned(bpfgo.PinIP4Up); m4 != nil {
		for _, r := range rec4 {
			zero := bpfgo.SiaIPStats{}
			_ = m4.Update(&r.Key, &zero, ebpf.UpdateAny)

			if isZeroStats(r) {
				_ = m4.Delete(&r.Key)
			}
		}
		m4.Close()
	}

	// IPv6
	if m6 := openPinned(bpfgo.PinIP6Up); m6 != nil {
		for _, r := range rec6 {
			zero := bpfgo.SiaIPStats{}
			_ = m6.Update(&r.Key, &zero, ebpf.UpdateAny)

			if isZeroStats6(r) {
				_ = m6.Delete(&r.Key)
			}
		}
		m6.Close()
	}
}

func isZeroStats(r model.TrafficRecord4) bool {
	return r.Up9981 == 0 &&
		r.Down9981 == 0 &&
		r.Up9984TCP == 0 &&
		r.Down9984TCP == 0 &&
		r.Up9984UDP == 0 &&
		r.Down9984UDP == 0
}

func isZeroStats6(r model.TrafficRecord6) bool {
	return r.Up9981 == 0 &&
		r.Down9981 == 0 &&
		r.Up9984TCP == 0 &&
		r.Down9984TCP == 0 &&
		r.Up9984UDP == 0 &&
		r.Down9984UDP == 0
}

func pushDailyToAppwrite(hostname string) {
	rows, err := storage.QueryDailyTotals()
	if err != nil {
		log.Printf("AGG: daily SQLite query error: %v", err)
		return
	}

	if len(rows) == 0 {
		return
	}

	if err := storage.PushDailyToAppwrite(hostname, rows); err != nil {
		log.Printf("AGG: Appwrite daily push error: %v", err)
	}
}

func alignedTicker(d time.Duration) *time.Timer {
    now := time.Now()
    next := now.Truncate(d).Add(d)
    return time.NewTimer(next.Sub(now))
}
