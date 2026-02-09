# Changelog

## v0.1 — Initial Release

### Added
- XDP ingress + TC egress eBPF programs for per‑client traffic accounting.
- IPv4 + IPv6 support.
- Port classification for:
  - 9981 (Consensus)
  - 9984 TCP (Siamux)
  - 9984 UDP (QUIC)
- Go loader with automatic bpffs mounting and map pinning.
- SQLite aggregation (1‑minute flush).
- DNS reverse lookup with caching.
- Live cli dashboard (30‑second refresh).
- Graceful shutdown with:
  - final flush
  - counter reset
  - optional zero‑key cleanup
- Systemd service.
- Installer + uninstaller scripts.
