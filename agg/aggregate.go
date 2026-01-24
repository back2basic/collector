package agg

import (
	"database/sql"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/back2basic/collector/bpfgo"
	"github.com/back2basic/collector/dns"
	"github.com/back2basic/collector/storage"
)

// Aggregator persists live counters into SQLite and then resets them.
type Aggregator struct {
	h  *bpfgo.Handles
	db *sql.DB
}

func New(h *bpfgo.Handles, db *sql.DB) *Aggregator {
	return &Aggregator{h: h, db: db}
}

// FlushOnce performs a single synchronous flush of current counters to the DB.
func (a *Aggregator) FlushOnce() {
	// call the same internal flush implementation used by the ticker
	a.flush()
}

func (a *Aggregator) Run(flushInterval time.Duration, exteralFlushInterval time.Duration) {
	flushTicker := time.NewTicker(flushInterval)
	defer flushTicker.Stop()
	hostname, err := os.Hostname()
	if err != nil {
		log.Printf("aggregator: get hostname: %v", err)
	}
	extTimer := alignedTicker(exteralFlushInterval)

	var extTicker *time.Ticker
	for {
		select {
		case <-flushTicker.C:
			a.flush()

		case <-extTimer.C:
            bpfgo.CleanupZeroEntriesUsingHandles(a.h.IP4Stats, a.h.IP6Stats)
			pushDailyToAppwrite(hostname)
			extTicker = time.NewTicker(exteralFlushInterval)

		case <-func() <-chan time.Time {
			if extTicker != nil {
				return extTicker.C
			}
			return nil
		}():
            bpfgo.CleanupZeroEntriesUsingHandles(a.h.IP4Stats, a.h.IP6Stats)
			pushDailyToAppwrite(hostname)
		}
	}
}

func (a *Aggregator) flush() {
	now := time.Now().UTC().Truncate(time.Minute)

	tx, err := a.db.Begin()
	if err != nil {
		fmt.Println("agg: begin tx:", err)
		return
	}

	stmt, err := tx.Prepare(`
        INSERT INTO traffic (
            timestamp,
            ip,
            dns,
            consensus_up,
            consensus_down,
            siamux_up,
            siamux_down,
            quic_up,
            quic_down
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)
	if err != nil {
		fmt.Println("agg: prepare:", err)
		_ = tx.Rollback()
		return
	}
	defer stmt.Close()

	// IPv4
	iter := a.h.IP4Stats.Iterate()
	var ip uint32
	var st bpfgo.SiaIPStats

	for iter.Next(&ip, &st) {
		if st.ConsensusDown == 0 &&
			st.ConsensusUp == 0 &&
			st.SiamuxDown == 0 &&
			st.SiamuxUp == 0 &&
			st.QuicDown == 0 &&
			st.QuicUp == 0 {
			continue
		}
		ipStr := fmt.Sprintf("%d.%d.%d.%d",
			byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))

		// Use existing dns.Resolve which has its own cache and TTL
		dnsName := dns.Resolve(net.ParseIP(ipStr))

		_, err := stmt.Exec(
			now.Unix(),
			ipStr,
			dnsName,
			st.ConsensusUp,
			st.ConsensusDown,
			st.SiamuxUp,
			st.SiamuxDown,
			st.QuicUp,
			st.QuicDown,
		)
		if err != nil {
			fmt.Println("agg: insert ipv4:", err)
		}
	}

	// IPv6
	iter6 := a.h.IP6Stats.Iterate()
	var ip6 [16]byte
	var st6 bpfgo.SiaIPStats

	for iter6.Next(&ip6, &st6) {
		if st6.ConsensusDown == 0 &&
			st6.ConsensusUp == 0 &&
			st6.SiamuxDown == 0 &&
			st6.SiamuxUp == 0 &&
			st6.QuicDown == 0 &&
			st6.QuicUp == 0 {
			continue
		}
		ipStr := net.IP(ip6[:]).String()

		dnsName := dns.Resolve(net.ParseIP(ipStr))

		_, err := stmt.Exec(
			now.Unix(),
			ipStr,
			dnsName,
			st6.ConsensusUp,
			st6.ConsensusDown,
			st6.SiamuxUp,
			st6.SiamuxDown,
			st6.QuicUp,
			st6.QuicDown,
		)
		if err != nil {
			fmt.Println("agg: insert ipv6:", err)
		}
	}

	if err := tx.Commit(); err != nil {
		fmt.Println("agg: commit:", err)
	}

	// Persisted, now reset live counters
	if err := bpfgo.ResetCountersUsingHandles(a.h.IP4Stats, a.h.IP6Stats); err != nil {
		log.Printf("reset counters: %v", err)
	}
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
