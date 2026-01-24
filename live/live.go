package live

import (
    "fmt"
    "net"
    "time"

    "github.com/back2basic/collector/bpfgo"
    "github.com/back2basic/collector/model"
    "github.com/back2basic/collector/storage"
)

type Live struct {
    h *bpfgo.Handles
}

func New(h *bpfgo.Handles) *Live {
    return &Live{h: h}
}

func (l *Live) Run() {
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()

    for {
        <-ticker.C
        l.printStats()
    }
}

func (l *Live) printStats() {
    // Live section: current BPF map contents
    fmt.Println("---- LIVE TRAFFIC (semantic counters) ----")

    // IPv4 live
    iter := l.h.IP4Stats.Iterate()
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
        addr := net.IPv4(byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
        fmt.Printf("IPv4 %s  consensus(down/up)=%s/%s  siamux(down/up)=%s/%s  quic(down/up)=%s/%s\n",
            addr.String(),
            bytesHuman(st.ConsensusDown), bytesHuman(st.ConsensusUp),
            bytesHuman(st.SiamuxDown), bytesHuman(st.SiamuxUp),
            bytesHuman(st.QuicDown),bytesHuman(st.QuicUp),
        )
    }

    // IPv6 live
    iter6 := l.h.IP6Stats.Iterate()
    var ip6 net.IP
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
        fmt.Printf("IPv6 %s  consensus(down/up)=%s/%s  siamux(down/up)=%s/%s  quic(down/up)=%s/%s\n",
            ip6.String(),
            bytesHuman(st6.ConsensusDown), bytesHuman(st6.ConsensusUp),
            bytesHuman(st6.SiamuxDown), bytesHuman(st6.SiamuxUp),
            bytesHuman(st6.QuicDown), bytesHuman(st6.QuicUp),
        )
    }

    fmt.Println("-------------------------------------------")

    // Stored / aggregated section: use existing storage.QueryDailyTotals()
    fmt.Println("---- STORED TRAFFIC (aggregated today) ----")

    aggMap := make(map[string]model.AggregatedRecord)
    if recs, err := storage.QueryDailyTotals(); err == nil {
        for _, r := range recs {
            aggMap[r.IP] = r
        }
    } else {
        fmt.Printf("WARNING: failed to load aggregated totals: %v\n", err)
    }

    // Print stored entries
    for ipStr, agg := range aggMap {
        parsed := net.ParseIP(ipStr)
        if parsed == nil {
            fmt.Printf("%s  consensus(down/up)=%s/%s  siamux(down/up)=%s/%s  quic(down/up)=%s/%s\n",
                ipStr,
                bytesHuman(agg.ConsensusDown), bytesHuman(agg.ConsensusUp),
                bytesHuman(agg.SiamuxDown), bytesHuman(agg.SiamuxUp),
                bytesHuman(agg.QuicDown), bytesHuman(agg.QuicUp),
            )
            continue
        }
        if parsed.To4() != nil {
            fmt.Printf("IPv4 %s  consensus(down/up)=%s/%s  siamux(down/up)=%s/%s  quic(down/up)=%s/%s\n",
                ipStr,
                bytesHuman(agg.ConsensusDown), bytesHuman(agg.ConsensusUp),
                bytesHuman(agg.SiamuxDown), bytesHuman(agg.SiamuxUp),
                bytesHuman(agg.QuicDown), bytesHuman(agg.QuicUp),
            )
        } else {
            fmt.Printf("IPv6 %s  consensus(down/up)=%s/%s  siamux(down/up)=%s/%s  quic(down/up)=%s/%s\n",
                ipStr,
                bytesHuman(agg.ConsensusDown), bytesHuman(agg.ConsensusUp),
                bytesHuman(agg.SiamuxDown), bytesHuman(agg.SiamuxUp),
                bytesHuman(agg.QuicDown), bytesHuman(agg.QuicUp),
            )
        }
    }

    fmt.Println("-------------------------------------------")
}

// bytesHuman converts bytes to a human readable string with units (KB/MB/GB/TB).
// Uses 1024 base and prints with two decimals.
func bytesHuman(b uint64) string {
    const (
        KB = 1024
        MB = KB * 1024
        GB = MB * 1024
        TB = GB * 1024
    )

    switch {
    case b >= TB:
        return fmt.Sprintf("%.2f TB", float64(b)/float64(TB))
    case b >= GB:
        return fmt.Sprintf("%.2f GB", float64(b)/float64(GB))
    case b >= MB:
        return fmt.Sprintf("%.2f MB", float64(b)/float64(MB))
    case b >= KB:
        return fmt.Sprintf("%.2f KB", float64(b)/float64(KB))
    default:
        return fmt.Sprintf("%d B", b)
    }
}
