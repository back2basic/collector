# `collector` — Sia Hostd Traffic Collector (XDP + TC + Go)

`collector` is a high‑performance traffic accounting daemon for Sia hostd.  
It uses **XDP (ingress)** and **TC (egress)** eBPF programs to measure per‑client bandwidth on Sia’s ports:

- **9981** — Consensus  
- **9984 TCP** — RHP4 (Siamux)  
- **9984 UDP** — RHP4 (QUIC)

Traffic is tracked per client IP (IPv4 + IPv6) and flushed to SQLite every minute.

The collector is designed for **production**, with:

- Zero‑copy packet parsing in eBPF  
- Dual‑stack IPv4/IPv6 support  
- Per‑client counters  
- Graceful shutdown  
- Systemd integration  

---

## ✨ Features

- XDP ingress accounting (DOWN traffic)  
- TC egress accounting (UP traffic)  
- Per‑client IPv4/IPv6 stats  
- Port‑aware classification (9981, 9984 TCP, 9984 UDP)  
- SQLite storage (1‑minute flush)  
- Automatic BPF map pinning  
- Graceful shutdown on SIGTERM  
- Systemd service included  

---

## 📦 Repository Structure

```
.
├── bpf/
│   └── prog.c              # XDP + TC eBPF program
├── bpfgo/
│   └── loader.go           # BPF loader, map pinning, XDP/TC attach
├── agg/
│   └── aggregate.go        # SQLite aggregation + flush logic
├── live/
│   └── live.go             # Live in-memory dashboard
├── collector.service       # Systemd unit
├── Makefile
└── main.go                 # Entry point
```

---

# 🔧 Installation

## 1. Download the Release

Download from:

**`https://github.com/back2basic/collector/releases`**

You need:

- `collector`  
- `sia_bpfel.o`  
- `install.sh` 
- `collector.service`  
- `uninstall.sh` (optional)

Place them in the same directory.

---

## 2. Run the Installer

```bash
chmod +x install.sh
sudo ./install.sh
```

The installer will:

- Copy the binary to `/usr/local/bin/collector`
- Copy the BPF object to `/var/lib/collector/bpf/sia_bpfel.o`
- Create `/etc/collector.env` if missing
- Install + enable + start the systemd service

---

## 3. Configure Your Network Interface

Edit:

```
/etc/collector.env
```

Set:

```
INTERFACE="eth0"
```

Find your interface:

```bash
ip -br link show
```

Restart:

```bash
sudo systemctl restart collector
```

---

## 4. Check Logs

```bash
journalctl -u collector -f
```

You should see:

- Ports loaded into BPF map  
- XDP + TC programs attached  
- Live traffic once peers connect  

---

# ⚙️ Runtime Behavior

### XDP (Ingress)
- Attached to `$INTERFACE`
- Counts **DOWN** traffic
- Classifies by destination port
- Keys by client IP

### TC (Egress)
- Attached to `$INTERFACE` egress
- Counts **UP** traffic
- Classifies by source port
- Keys by client IP

### Aggregation
- Runs every **1 minute**
- Persists counters to SQLite
- Resets counters to zero
- Optionally cleans zero keys (if `PINNED_MAPS=1`)

### Live Dashboard
- Prints every **30 seconds**
- Shows active clients only (non‑zero counters)

---

# 🗂️ SQLite Schema

Each row contains:

| Column | Description |
|--------|-------------|
| timestamp | Unix minute timestamp |
| ip | IPv4/IPv6 address |
| dns | Reverse lookup result |
| consensus_up / consensus_down | Port 9981 |
| siamux_up / siamux_down | Port 9984 TCP |
| quic_up / quic_down | Port 9984 UDP |

---

# 🧪 Development

### Build only

```bash
sudo make build
```

### Uninstall

```bash
chmod +x uninstall.sh
sudo ./uninstall.sh
```

Removes:

- Binary  
- Systemd unit  
- `/var/lib/collector`  

`/etc/collector.env` is preserved.

---

# 📊 Example Output

```
---- LIVE TRAFFIC (semantic counters) ----
IPv4 10.20.31.114  consensus(down/up)=0 B/0 B  siamux(down/up)=748 B/26.07 KB  quic(down/up)=0 B/0 B
-------------------------------------------

---- STORED TRAFFIC (aggregated today) ----
IPv4 10.20.31.114  consensus(down/up)=0 B/0 B  siamux(down/up)=1.46 KB/52.13 KB  quic(down/up)=0 B/0 B
-------------------------------------------
```

---

# 🧭 Roadmap

- Web dashboard (HTML/JS)  
- Historical charts (SQLite → graphs)  
- Prometheus exporter  
- Alerting for abnormal 9981 spikes  
- Optional remote API sync  
- Configurable port sets (already implemented)  
- JSON/CSV export  

---
