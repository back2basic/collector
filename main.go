package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/back2basic/collector/agg"
	"github.com/back2basic/collector/bpfgo"
	"github.com/back2basic/collector/live"
	"github.com/back2basic/collector/prom"
	"github.com/back2basic/collector/storage"
)

func main() {
	iface := os.Getenv("INTERFACE")
	if iface == "" {
		log.Fatal("missing INTERFACE in env file.")
	}

	// Load BPF + attach XDP + TC
	h, err := bpfgo.Load(iface)
	if err != nil {
		log.Fatalf("load BPF: %v", err)
	}
	// ensure handles and links are closed on exit
	defer func() {
		// small delay to allow final operations to complete
		time.Sleep(100 * time.Millisecond)
		h.Close()
	}()

	// Start aggregator
	ag := agg.New(h, storage.DB)
	go ag.Run(1*time.Minute, 5*time.Minute)

	// Start live dashboard
	lv := live.New(h)
	go lv.Run()

	// Start Prometheus exporter
	promAddr := os.Getenv("PROMETHEUS_ADDR")
	if promAddr == "" {
		promAddr = ":9100"
	}
	go prom.Run(h, promAddr)

	// Wait for shutdown signal
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	<-ctx.Done()
	log.Println("Received shutdown signal, flushing and cleaning up...")

	// 1) Persist current counters synchronously
	// Aggregator exposes FlushOnce() (see suggested addition below).
	ag.FlushOnce()

	// 2) Reset counters (zero values) using handles
	if err := bpfgo.ResetCountersUsingHandles(h.IP4Stats, h.IP6Stats); err != nil {
		log.Printf("shutdown: reset counters: %v", err)
	}

	// 3) Cleanup zero entries only if maps are pinned (controlled by env)
	// Set PINNED_MAPS=1 in env if you pin maps and want cleanup on shutdown.
	if os.Getenv("PINNED_MAPS") == "1" {
		if err := bpfgo.CleanupZeroEntriesUsingHandles(h.IP4Stats, h.IP6Stats); err != nil {
			log.Printf("shutdown: cleanup zero entries: %v", err)
		}
	}

	// 4) Close handles (deferred above) and exit
	log.Println("shutdown: complete")
}
