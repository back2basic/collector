# `collector` — Sia Hostd Traffic Collector (XDP + TC + Go)

`collector` is a high‑performance traffic accounting daemon for Sia hosts.  
It uses **XDP (ingress)** and **TC (egress)** to measure per‑client bandwidth on Sia’s ports:

- **9981** — Consensus  
- **9984 TCP** — RPH4  
- **9984 UDP** — Quick  

Traffic is tracked per client IP (IPv4 + IPv6), flushed to SQLite.  
An optional future extension will allow pushing aggregated data to a remote API endpoint.

The collector is designed for **production**, with:

- Zero‑copy packet parsing in eBPF  
- Dual‑stack IPv4/IPv6 support  
- Per‑client counters  
- Graceful shutdown  
- Systemd integration  

---

## ✨ Features

- **XDP ingress accounting** (DOWN traffic)
- **TC egress accounting** (UP traffic)
- **Per‑client IPv4/IPv6 stats**
- **Port‑aware classification** (9981, 9984 TCP, 9984 UDP)
- **SQLite storage** (1‑minute flush)
- **Automatic BPF map pinning**
- **Graceful shutdown on SIGTERM**
- **Systemd service included**

---

## 📦 Repository Structure

```
.
├── bpf/
│   └── prog.c              # XDP + TC eBPF program
├── bpfgo/
│   └── loader.go           # BPF loader, map pinning, XDP/TC attach
├── agg/
│   └── agg.go              # SQLite aggregation + clock alignment
├── live/
│   └── live.go             # Live in-memory dashboard
├── collector.service       # Systemd unit
├── Makefile                # Build + install automation
└── main.go                 # Entry point
```

---

## ⚙️ Installation

### Build + Install

```bash
sudo make install
```

This will:

- Build the Go binary  
- Install it to `/usr/local/bin/collector`  
- Install the systemd service  
- Create `/var/lib/collector/bpf/`  
- Copy `bpf/sia_bpfel.o` into it  
- Create `/etc/collector.env` if missing  
- Enable + start the service  

---

## 🧭 Check

### Service logs

```bash
journalctl -u collector -f
```

---

## 🧩 Environment Variables

Stored in `/etc/collector.env`:

```
SIA_HOSTNAME=""
INTERFACE="eth0"
SQLITE_PATH="/var/lib/collector/traffic.db"
API_ENDPOINT=""        # optional, future use
API_TOKEN=""           # optional, future use
```

Check if `INTERFACE` is correct for your system.
API sync is disabled unless both `API_ENDPOINT` and `API_TOKEN` are set.

---

## 🚀 Runtime Behavior

### XDP (Ingress)
- Attached to `eth0`
- Counts **DOWN** traffic
- Classifies by port + protocol
- Keys by client IP

### TC (Egress)
- Attached to `eth0` egress
- Counts **UP** traffic
- Matches on `sport` for egress direction
- Keys by client IP

### Aggregation
- SQLite flush every **1 minute**
- Aggregation aligned to real 5‑minute boundaries:
  ```
  :00, :05, :10, :15, ...
  ```
- Optional API sync (disabled by default)

### Live Dashboard
- Prints top clients every **30 seconds**
- No DNS lookups (fast mode)

---

## 🗂️ SQLite Schema

Each row contains:

- client_ip (TEXT)
- up_9981
- down_9981
- up_9984_tcp
- down_9984_tcp
- up_9984_udp
- down_9984_udp
- timestamp

---

## 🧪 Development

### Build only

```bash
sudo make build
```

### Uninstall

```bash
sudo make uninstall
```

This removes:

- Binary  
- Systemd unit  
- `/var/lib/collector`  
- `/etc/collector.env`  

---

## 🛡️ Safety & Stability

- BPF maps are pinned under `/sys/fs/bpf/`
- Graceful shutdown detaches XDP + TC
- Memory footprint stabilizes around **25–40 MB**

---

## 📊 Example Output

```bash
journalctl -u collector -f
```

```
---- DOWN (XDP ingress) ----
DOWN4: ip=51.81.107.134  down_9984_tcp=85311154
DOWN4: ip=66.23.193.244  down_9984_tcp=293904

---- UP (TC egress) ----
UP4:   ip=51.81.107.134  up_9984_tcp=706632
UP4:   ip=66.23.193.244  up_9984_tcp=12474

TC_LAST_IP[0] = 95.111.251.94
TC_LAST_IP[1] = 51.81.107.134
```

---

## 🧭 Roadmap

- Web dashboard (HTML/JS frontend)
- Historical charts (SQLite → graphs)
- Alerting for abnormal 9981 spikes
- Prometheus exporter
- Optional remote API sync
- Configurable port sets (custom services)
- Export to JSON/CSV for external tools

---
