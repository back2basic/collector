# Sia Collector

This is a high‑performance traffic
accounting daemon for Sia hostd using XDP + TC eBPF.

## 🚀 Features
- XDP ingress + TC egress traffic accounting
- Per‑client IPv4/IPv6 counters
- Port classification for 9981 + 9984 (TCP/UDP)
- SQLite aggregation (1‑minute flush)
- DNS reverse lookup caching
- Live dashboard (30‑second refresh)
- Graceful shutdown with final flush + counter reset
- Automatic bpffs mounting + map pinning
- Systemd service
- Installer + uninstaller scripts

## 📦 Included in this release
- `collector` (compiled Go binary)
- `sia_bpfel.o` (compiled eBPF program)
- `install.sh`
- `uninstall.sh`
- `collector.service`
- `CHANGELOG.md`

# 📦 Installation

## 1. Download the Release

Go to:

**`https://github.com/back2basic/collector/releases` [(github.com in Bing)](https://www.bing.com/search?q="https%3A%2F%2Fgithub.com%2Fback2basic%2Fcollector%2Freleases")**

Download the following files from the latest release:

- `collector` (compiled Go binary)  
- `sia_bpfel.o` (compiled eBPF program)  
- `install.sh`  
- `uninstall.sh` (optional)

Place them in the same directory before running the installer.

---

## 2. Run the Installer

```bash
chmod +x install.sh
sudo ./install.sh
```

The installer will:

- Create `/var/lib/collector/` and `/var/lib/collector/bpf/`
- Copy:
  - `collector` → `/usr/local/bin/collector`
  - `sia_bpfel.o` → `/var/lib/collector/bpf/sia_bpfel.o`
- Create `/etc/collector.env` if missing
- Install and enable the systemd service
- Start the collector

You will see progress messages for each step.

---

## 3. Configure Your Network Interface

Edit:

```
/etc/collector.env
```

Set the correct outgoing interface:

```
INTERFACE="eth0"
```

To list your interfaces:

```bash
ip -br link show
```

After editing, restart the service:

```bash
sudo systemctl restart collector
```

---

## 4. Verify the Service

Check logs:

```bash
journalctl -u collector -f
```

You should see:

- Ports loaded into the BPF map  
- XDP + TC programs attached  
- Live traffic counters (once peers connect)

---

## 5. Uninstall (Optional)

```bash
chmod +x uninstall.sh
sudo ./uninstall.sh
```

This removes:

- Systemd service  
- Binary  
- `/var/lib/collector` directory  

`/etc/collector.env` is left in place for safety.

---

## 6. Requirements

- Linux kernel **5.x or newer**  
- Root privileges (required for XDP/TC)  
- No kernel headers needed (you ship the compiled BPF object)  
- bpffs is mounted automatically by the loader  

---
