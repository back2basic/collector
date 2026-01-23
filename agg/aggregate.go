package agg

import (
	"database/sql"
	"fmt"
	"net"
	"time"

	"github.com/back2basic/collector/bpfgo"
)

type Aggregator struct {
	h  *bpfgo.Handles
	db *sql.DB
}

func New(h *bpfgo.Handles, db *sql.DB) *Aggregator {
	return &Aggregator{h: h, db: db}
}

func (a *Aggregator) Run() {
	flushTicker := time.NewTicker(1 * time.Minute)
	defer flushTicker.Stop()

	for {
		<-flushTicker.C
		a.flush()
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
            consensus_up,
            consensus_down,
            siamux_up,
            siamux_down,
            quic_up,
            quic_down
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
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

		_, err := stmt.Exec(
			now,
			ipStr,
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

		_, err := stmt.Exec(
			now,
			ipStr,
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
}
