#!/usr/bin/env bash
set -e

echo "=== Sia Collector v0.1 Installer ==="

# Paths
BIN_DST="/usr/local/bin/collector"
BPF_DIR="/var/lib/collector/bpf"
ENV_FILE="/etc/collector.env"
SERVICE_FILE="/etc/systemd/system/collector.service"

echo "[1/7] Creating directories..."
sudo mkdir -p /var/lib/collector
sudo mkdir -p "$BPF_DIR"

echo "[2/7] Installing collector binary..."
sudo cp collector "$BIN_DST"
sudo chmod 755 "$BIN_DST"

echo "[3/7] Installing BPF object..."
sudo cp sia_bpfel.o "$BPF_DIR/sia_bpfel.o"
sudo chmod 644 "$BPF_DIR/sia_bpfel.o"

echo "[4/7] Creating /etc/collector.env (if missing)..."
if [ ! -f "$ENV_FILE" ]; then
    sudo tee "$ENV_FILE" >/dev/null <<EOF
# Collector configuration
INTERFACE="eth0"
PORT_SIA_CONSENSUS="9981"
PORT_RHP4_SIAMUX="9984"
PORT_RHP4_QUIC="9984"
SQLITE_PATH="/var/lib/collector/traffic.db"
API_ENDPOINT=""
API_TOKEN=""
EOF
    sudo chmod 644 "$ENV_FILE"
    echo "Created $ENV_FILE"
else
    echo "$ENV_FILE already exists, leaving it untouched."
fi

echo "[5/7] Installing systemd service..."
sudo cp collector.service "$SERVICE_FILE"
sudo chmod 644 "$SERVICE_FILE"

echo "[6/7] Enabling and starting service..."
sudo systemctl daemon-reload
sudo systemctl enable collector
sudo systemctl restart collector

echo "[7/7] Installation complete!"

echo
echo "IMPORTANT:"
echo "  - Edit /etc/collector.env and set INTERFACE to your correct network interface."
echo "    Example: ip -br link show"
echo
echo "Then restart the service:"
echo "    sudo systemctl restart collector"
echo
echo "Collector v0.1 installed successfully."
