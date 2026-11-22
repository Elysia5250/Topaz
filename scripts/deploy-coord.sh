#!/usr/bin/env bash
# Topaz Coord (topaz-coord) one-command Linux VPS installer / upgrader.
#
# Zero-build usage (downloads prebuilt static musl binary from GitHub Releases):
#   curl -fsSL https://raw.githubusercontent.com/Elysia5250/Topaz/master/scripts/deploy-coord.sh \
#     | sudo bash -s -- --public-url https://<VPS_IP>:7722
#
# Local binary usage:
#   sudo ./deploy-coord.sh --binary ./topaz-coord --public-url https://<VPS_IP>:7722
#
# Re-running this script upgrades /usr/local/bin/topaz-coord in place without
# overwriting /etc/topaz-coord/coord.env or /var/lib/topaz-coord/coord.db.

set -euo pipefail

REPO="Elysia5250/Topaz"
VERSION="latest"
BIN_SRC=""
PUBLIC_URL=""
LISTEN_PORT="7722"
RELAY_PORT="7723"
RELAY_QUIC_PORT="7724"
STUN_PORT="3478"
ENABLE_WS_443="false"
RELAY_MBPS="50"
RELAY_SESSIONS="8"
TMP_DIR=""

cleanup() {
    if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT

usage() {
    cat <<'EOF'
Usage: sudo ./deploy-coord.sh [OPTIONS]

Options:
  --binary <PATH>        Use a local `topaz-coord` binary instead of downloading from GitHub Releases
  --version <TAG>        Release tag to download (default: latest, e.g. v0.1.0)
  --repo <OWNER/REPO>    GitHub repository for releases (default: Elysia5250/Topaz)
  --public-url <URL>     Public coord URL printed with invite codes (e.g. https://1.2.3.4:7722)
  --port <PORT>          HTTPS/WSS control-plane port (default: 7722)
  --relay-port <PORT>    TCP relay port (default: 7723)
  --relay-quic-port <P>  UDP/QUIC datagram relay port (default: 7724)
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
        --version) VERSION="$2"; shift 2 ;;
        --repo) REPO="$2"; shift 2 ;;
        --public-url) PUBLIC_URL="$2"; shift 2 ;;
        --port) LISTEN_PORT="$2"; shift 2 ;;
        --relay-port) RELAY_PORT="$2"; shift 2 ;;
        --relay-quic-port) RELAY_QUIC_PORT="$2"; shift 2 ;;
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

download_release_binary() {
    local arch asset base_url
    case "$(uname -m)" in
        x86_64|amd64) arch="x86_64" ;;
        aarch64|arm64) arch="aarch64" ;;
        other)
            echo "Unsupported CPU architecture: $(uname -m). Build from source and pass --binary." >&2
            exit 1
            ;;
        *)
            echo "Unsupported CPU architecture: $(uname -m). Build from source and pass --binary." >&2
            exit 1
            ;;
    esac

    asset="topaz-coord-linux-${arch}"
    if [[ "$VERSION" == "latest" ]]; then
        base_url="https://github.com/${REPO}/releases/latest/download"
    else
        base_url="https://github.com/${REPO}/releases/download/${VERSION}"
    fi

    TMP_DIR="$(mktemp -d)"
    echo "Downloading ${asset} (${VERSION}) from ${REPO}..."
    curl -fsSL "${base_url}/${asset}" -o "${TMP_DIR}/${asset}"
    curl -fsSL "${base_url}/SHA256SUMS.txt" -o "${TMP_DIR}/SHA256SUMS.txt"

    if command -v sha256sum >/dev/null 2>&1; then
        echo "Verifying SHA256 checksum..."
        (
            cd "$TMP_DIR"
            grep "  ${asset}\$" SHA256SUMS.txt | sha256sum -c -
        )
    elif command -v shasum >/dev/null 2>&1; then
        echo "Verifying SHA256 checksum (shasum)..."
        (
            cd "$TMP_DIR"
            grep "  ${asset}\$" SHA256SUMS.txt | shasum -a 256 -c -
        )
    else
        echo "Error: neither sha256sum nor shasum found; refusing to install unverified binary." >&2
        exit 1
    fi

    chmod 0755 "${TMP_DIR}/${asset}"
    BIN_SRC="${TMP_DIR}/${asset}"
}

if [[ -z "$BIN_SRC" ]]; then
    if [[ -x "./topaz-coord" ]]; then
        BIN_SRC="./topaz-coord"
    elif [[ -x "./target/release/topaz-coord" ]]; then
        BIN_SRC="./target/release/topaz-coord"
    else
        download_release_binary
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
COORD_RELAY_QUIC_LISTEN=0.0.0.0:${RELAY_QUIC_PORT}
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
echo "Version: $(/usr/local/bin/topaz-coord version 2>/dev/null || /usr/local/bin/topaz-coord --version 2>/dev/null || echo unknown)"
systemctl --no-pager --lines=5 status topaz-coord.service || true
echo ""
PIN="$(sudo -u topaz bash -c 'set -a; source /etc/topaz-coord/coord.env; /usr/local/bin/topaz-coord fingerprint' 2>/dev/null || true)"
echo "TLS Pin: ${PIN:-<run: sudo -u topaz topaz-coord --db /var/lib/topaz-coord/coord.db fingerprint>}"
echo ""
echo "Open these firewall ports on your VPS:"
echo "  - ${LISTEN_PORT}/tcp   (HTTPS control plane + WSS signaling/relay)"
echo "  - ${RELAY_PORT}/tcp   (TCP relay)"
echo "  - ${RELAY_QUIC_PORT}/udp   (UDP/QUIC datagram relay for VPN)"
echo "  - ${STUN_PORT}/udp   (UDP STUN for NAT hole punching)"
if [[ -n "$CAP_LINE" ]]; then
    echo "  - 443/tcp    (Extra WSS relay)"
fi
echo ""
echo "Create your first invite code:"
echo "  sudo -u topaz bash -c 'set -a; source /etc/topaz-coord/coord.env; topaz-coord invite create'"
