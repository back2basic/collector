package live

import (
    "fmt"
    "net"
    "time"

    "github.com/back2basic/collector/bpfgo"
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
    fmt.Println("---- LIVE TRAFFIC (semantic counters) ----")

    // IPv4
    iter := l.h.IP4Stats.Iterate()
    var ip uint32
    var st bpfgo.SiaIPStats

    for iter.Next(&ip, &st) {
        addr := net.IPv4(byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
        fmt.Printf("IPv4 %s  consensus(down/up)=%d/%d  siamux(down/up)=%d/%d  quic(down/up)=%d/%d\n",
            addr.String(),
            st.ConsensusDown, st.ConsensusUp,
            st.SiamuxDown, st.SiamuxUp,
            st.QuicDown, st.QuicUp,
        )
    }

    // IPv6
    iter6 := l.h.IP6Stats.Iterate()
    var ip6 net.IP
    var st6 bpfgo.SiaIPStats

    for iter6.Next(&ip6, &st6) {
        fmt.Printf("IPv6 %s  consensus(down/up)=%d/%d  siamux(down/up)=%d/%d  quic(down/up)=%d/%d\n",
            ip6.String(),
            st6.ConsensusDown, st6.ConsensusUp,
            st6.SiamuxDown, st6.SiamuxUp,
            st6.QuicDown, st6.QuicUp,
        )
    }

    fmt.Println("-------------------------------------------")
}
