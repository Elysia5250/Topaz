#!/usr/bin/env bash
# Topaz Coord (topaz-coord) one-command Linux VPS installer / upgrader.
#
# Usage (on your Linux VPS as root / sudo):
#   sudo ./deploy-coord.sh --binary ./topaz-coord --public-url https://1.2.3.4:7722
#
# Re-running this script upgrades the binary in place without overwriting
# /etc/topaz-coord/coord.env or /var/lib/topaz-coord/coord.db.

set -euo pipefail

BIN_SRC=""
PUBLIC_URL=""
LISTEN_PORT="7722"
RELAY_PORT="7723"
STUN_PORT="3478"
ENABLE_WS_443="false"
RELAY_MBPS="50"
RELAY_SESSIONS="8"

usage() {
    cat <<'EOF'
Usage: sudo ./deploy-coord.sh [OPTIONS]

Options:
  --binary <PATH>        Path to compiled `topaz-coord` binary (default: ./topaz-coord)
  --public-url <URL>     Public coord URL printed with invite codes (e.g. https://1.2.3.4:7722)
  --port <PORT>          HTTPS/WSS control-plane port (default: 7722)
  --relay-port <PORT>    TCP relay port (default: 7723)
  --stun-port <PORT>     UDP STUN port (default: 3478)
  --ws-443               Also listen for WSS relay on 0.0.0.0:443 (adds CAP_NET_BIND_SERVICE)
  --relay-mbps <N>       Per-account relay bandwidth cap in Mbit/s (default: 50)
  --relay-sessions <N>   Max concurrent relay sessions per account (default: 8)
  -h, --help             Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary) BIN_SRC="$2"; shift 2 ;;
        --public-url) PUBLIC_URL="$2"; shift 2 ;;
        --port) LISTEN_PORT="$2"; shift 2 ;;
        --relay-port) RELAY_PORT="$2"; shift 2 ;;
        --stun-port) STUN_PORT="$2"; shift 2 ;;
        --ws-443) ENABLE_WS_443="true"; shift ;;
        --relay-mbps) RELAY_MBPS="$2"; shift 2 ;;
        --relay-sessions) RELAY_SESSIONS="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo "Please run as root (e.g. sudo $0 ...)" >&2
    exit 1
fi

if [[ -z "$BIN_SRC" ]]; then
    if [[ -x "./topaz-coord" ]]; then
        BIN_SRC="./topaz-coord"
    elif [[ -x "./target/release/topaz-coord" ]]; then
        BIN_SRC="./target/release/topaz-coord"
    else
        echo "Could not find topaz-coord binary. Pass --binary /path/to/topaz-coord" >&2
        exit 1
    fi
fi

if [[ ! -f "$BIN_SRC" ]]; then
    echo "Binary not found: $BIN_SRC" >&2
    exit 1
fi

# 1. Create dedicated system user & state directory.
if ! id -u topaz >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin topaz
fi

install -d -m 0700 -o topaz -g topaz /var/lib/topaz-coord
install -d -m 0755 /etc/topaz-coord

# 2. Install binary atomically.
install -m 0755 "$BIN_SRC" /usr/local/bin/topaz-coord.new
mv -f /usr/local/bin/topaz-coord.new /usr/local/bin/topaz-coord

# 3. Write /etc/topaz-coord/coord.env only if missing (preserve edits on upgrade).
ENV_FILE="/etc/topaz-coord/coord.env"
if [[ ! -f "$ENV_FILE" ]]; then
    if [[ -z "$PUBLIC_URL" ]]; then
        DETECTED_IP="$(curl -4 -fsS --max-time 3 https://ifconfig.me 2>/dev/null || true)"
        if [[ -n "$DETECTED_IP" ]]; then
            PUBLIC_URL="https://${DETECTED_IP}:${LISTEN_PORT}"
        fi
    fi

    cat > "$ENV_FILE" <<EOF
# Topaz coordination & relay server configuration
COORD_LISTEN=0.0.0.0:${LISTEN_PORT}
COORD_RELAY_LISTEN=0.0.0.0:${RELAY_PORT}
COORD_STUN_LISTEN=0.0.0.0:${STUN_PORT}
COORD_DB=/var/lib/topaz-coord/coord.db
COORD_RELAY_MBPS_PER_ACCOUNT=${RELAY_MBPS}
COORD_RELAY_SESSIONS_PER_ACCOUNT=${RELAY_SESSIONS}
EOF
    if [[ -n "$PUBLIC_URL" ]]; then
        echo "COORD_PUBLIC_URL=${PUBLIC_URL}" >> "$ENV_FILE"
    else
        echo "# COORD_PUBLIC_URL=https://<YOUR_VPS_IP>:${LISTEN_PORT}" >> "$ENV_FILE"
    fi
    if [[ "$ENABLE_WS_443" == "true" ]]; then
        echo "COORD_RELAY_WS_LISTEN=0.0.0.0:443" >> "$ENV_FILE"
    else
        echo "# COORD_RELAY_WS_LISTEN=0.0.0.0:443" >> "$ENV_FILE"
    fi
    chmod 0640 "$ENV_FILE"
    chown root:topaz "$ENV_FILE"
    echo "Created $ENV_FILE"
else
    echo "Keeping existing $ENV_FILE"
fi

# 4. Install systemd unit.
CAP_LINE=""
if [[ "$ENABLE_WS_443" == "true" ]] || grep -qE '^COORD_RELAY_WS_LISTEN=.*:443$' "$ENV_FILE"; then
    CAP_LINE="AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE"
fi

cat > /etc/systemd/system/topaz-coord.service <<EOF
[Unit]
Description=Topaz coordination, STUN and relay server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=topaz
Group=topaz
EnvironmentFile=/etc/topaz-coord/coord.env
ExecStart=/usr/local/bin/topaz-coord
WorkingDirectory=/var/lib/topaz-coord
Restart=always
RestartSec=3
LimitNOFILE=65536
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/var/lib/topaz-coord
${CAP_LINE}

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now topaz-coord.service
systemctl restart topaz-coord.service

# Wait briefly for DB & TLS key initialization.
sleep 1

echo ""
echo "=== topaz-coord is running ==="
systemctl --no-pager --lines=5 status topaz-coord.service || true
echo ""
PIN="$(sudo -u topaz env $(grep -v '^#' "$ENV_FILE" | xargs) /usr/local/bin/topaz-coord fingerprint 2>/dev/null || true)"
echo "TLS Pin: ${PIN:-<run: sudo -u topaz topaz-coord --db /var/lib/topaz-coord/coord.db fingerprint>}"
echo ""
echo "Open these firewall ports on your VPS:"
echo "  - ${LISTEN_PORT}/tcp   (HTTPS control plane + WSS signaling/relay)"
echo "  - ${RELAY_PORT}/tcp   (TCP relay)"
echo "  - ${STUN_PORT}/udp   (UDP STUN for NAT hole punching)"
if [[ -n "$CAP_LINE" ]]; then
    echo "  - 443/tcp    (Extra WSS relay)"
fi
echo ""
echo "Create your first invite code:"
echo "  sudo -u topaz bash -c 'set -a; source /etc/topaz-coord/coord.env; topaz-coord invite create'"
