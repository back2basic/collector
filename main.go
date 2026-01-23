package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/back2basic/collector/agg"
	"github.com/back2basic/collector/bpfgo"
	"github.com/back2basic/collector/live"
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
	defer h.Close()

	// Start aggregator
	ag := agg.New(h, storage.DB)
	go ag.Run()

	// Start live dashboard
	lv := live.New(h)
	go lv.Run()

	// Wait for shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	s := <-sigCh
	log.Printf("Received %s, shutting down", s)
}
