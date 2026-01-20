package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/back2basic/collector/agg"
	"github.com/back2basic/collector/bpfgo"
	"github.com/back2basic/collector/live"
)

func main() {
	// Load BPF
	iface := os.Getenv("INTERFACE")
	if iface == "" {
		log.Fatal("missing INTERFACE in env file.")
	}

	h, err := bpfgo.Load(iface)
	if err != nil {
		log.Fatalf("load BPF: %v", err)
	}
	defer h.Close()

	// Fast loop: human-facing, no DNS
	go live.Run(h, 30*time.Second)

	// Slow loop: 5-min SQLite flush + 1-min Appwrite daily aggregation
	go agg.Run(h, 1*time.Minute, 5*time.Minute)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	s := <-sigCh
	log.Printf("Received %s, shutting down", s)
}
