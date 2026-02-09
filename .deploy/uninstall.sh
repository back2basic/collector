#!/usr/bin/env bash
set -e

echo "=== Uninstalling Sia Collector ==="

echo "[1/5] Stopping service..."
sudo systemctl stop collector || true
sudo systemctl disable collector || true

echo "[2/5] Removing systemd unit..."
sudo rm -f /etc/systemd/system/collector.service
sudo systemctl daemon-reload

echo "[3/5] Removing binary..."
sudo rm -f /usr/local/bin/collector

echo "[4/5] Removing data directory..."
sudo rm -rf /var/lib/collector

echo "[5/5] Leaving /etc/collector.env in place (manual cleanup optional)."

echo "Uninstall complete."
