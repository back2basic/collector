package prom

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"

	"github.com/back2basic/collector/bpfgo"
	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Collector struct {
	h *bpfgo.Handles

	up   *prometheus.Desc
	down *prometheus.Desc
}

func New(h *bpfgo.Handles) *Collector {
	return &Collector{
		h: h,
		up: prometheus.NewDesc(
			"collector_bytes_up",
			"Bytes uploaded per client and port",
			[]string{"ip", "port"},
			nil,
		),
		down: prometheus.NewDesc(
			"collector_bytes_down",
			"Bytes downloaded per client and port",
			[]string{"ip", "port"},
			nil,
		),
	}
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.up
	ch <- c.down
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	collectMap := func(m *ebpf.Map, isIPv6 bool) {
		iter := m.Iterate()

		key := make([]byte, m.KeySize())
		val := make([]byte, m.ValueSize())

		for iter.Next(&key, &val) {
			ip := decodeIP(key, isIPv6)
			stats := decodeStats(val)

			if stats.ConsensusUp == 0 && stats.ConsensusDown == 0 &&
				stats.SiamuxUp == 0 && stats.SiamuxDown == 0 &&
				stats.QuicUp == 0 && stats.QuicDown == 0 {
				continue
			}

			emit := func(port string, up, down uint64) {
				ch <- prometheus.MustNewConstMetric(c.up, prometheus.CounterValue, float64(up), ip, port)
				ch <- prometheus.MustNewConstMetric(c.down, prometheus.CounterValue, float64(down), ip, port)
			}
			if stats.ConsensusUp != 0 && stats.ConsensusDown != 0 {
				emit("9981", stats.ConsensusUp, stats.ConsensusDown)
			}
			if stats.SiamuxUp != 0 && stats.SiamuxDown != 0 {
				emit("9984_tcp", stats.SiamuxUp, stats.SiamuxDown)
			}
			if stats.QuicUp != 0 && stats.QuicDown != 0 {
				emit("9984_udp", stats.QuicUp, stats.QuicDown)
			}
		}
	}

	collectMap(c.h.IP4Stats, false)
	collectMap(c.h.IP6Stats, true)
}

func decodeIP(b []byte, ipv6 bool) string {
	if ipv6 {
		return net.IP(b).String()
	}
	ip := binary.LittleEndian.Uint32(b)
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ip),
		byte(ip>>8),
		byte(ip>>16),
		byte(ip>>24),
	)
}

type SiaIPStats struct {
	ConsensusUp   uint64
	ConsensusDown uint64
	SiamuxUp      uint64
	SiamuxDown    uint64
	QuicUp        uint64
	QuicDown      uint64
}

func decodeStats(b []byte) SiaIPStats {
	var s SiaIPStats
	_ = binary.Read(bytes.NewReader(b), binary.LittleEndian, &s)
	return s
}

func Run(h *bpfgo.Handles, addr string) {
	c := New(h)
	prometheus.MustRegister(c)

	http.Handle("/metrics", promhttp.Handler())
	go http.ListenAndServe(addr, nil)
}
