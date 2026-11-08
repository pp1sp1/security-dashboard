#!/usr/bin/env bash
# Proxmox & Docker Security Dashboard – instalator.
#
# Użycie:
#   ./install.sh                 – tworzy venv i instaluje zależności
#   ./install.sh --install-trivy – dodatkowo instaluje Trivy na tym hoście
#   ./install.sh --systemd       – dodatkowo rejestruje usługę systemd (wymaga root)
set -euo pipefail

cd "$(dirname "$0")"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info() { echo -e "${GREEN}[i]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
fail() { echo -e "${RED}[✗]${NC} $*"; exit 1; }

# ---------------------------------------------------------------- wymagania
command -v python3 >/dev/null 2>&1 || fail "Brak python3 (zainstaluj: apt install python3 python3-venv)"
PYVER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
python3 - "$PYVER" <<'EOF' || fail "Wymagany Python >= 3.9"
import sys
major, minor = sys.argv[1].split(".")
sys.exit(0 if (int(major), int(minor)) >= (3, 9) else 1)
EOF
info "Python $PYVER OK"

# ---------------------------------------------------------------- venv + zależności
if [ ! -d .venv ]; then
    info "Tworzę środowisko wirtualne .venv…"
    python3 -m venv .venv
fi
info "Instaluję zależności pip…"
.venv/bin/pip install --quiet --upgrade pip
.venv/bin/pip install --quiet -r requirements.txt
info "Zależności zainstalowane."

# ---------------------------------------------------------------- wykrywanie środowiska
if [ -d /etc/pve ]; then
    info "Wykryto Proxmox VE – panel będzie widział LXC (pct) i VM (qm) tego węzła."
else
    warn "Nie wykryto Proxmox VE – zasoby PVE dodaj przez SSH (GUI) lub Proxmox API (Ustawienia)."
fi
if [ -S /var/run/docker.sock ]; then
    info "Wykryto socket Dockera – kontenery zostaną automatycznie zeskanowane."
else
    warn "Brak /var/run/docker.sock – tryb Docker nieaktywny."
fi

# ---------------------------------------------------------------- opcje
INSTALL_TRIVY=0; SYSTEMD=0
for arg in "$@"; do
    case "$arg" in
        --install-trivy) INSTALL_TRIVY=1 ;;
        --systemd) SYSTEMD=1 ;;
        *) warn "Nieznany argument: $arg" ;;
    esac
done

if [ "$INSTALL_TRIVY" = "1" ]; then
    info "Instaluję Trivy na tym hoście…"
    .venv/bin/python - <<'EOF'
import scanner, store
store.load()
target = {"id": "local", "type": "local", "name": "local",
          "endpoint": {"kind": "local"}}
version = scanner.install_scanner(target, "trivy")
print(f"Trivy {version} zainstalowany w /usr/local/bin/trivy")
EOF
fi

if [ "$SYSTEMD" = "1" ]; then
    [ "$(id -u)" = "0" ] || fail "Opcja --systemd wymaga roota"
    PORT="${DASH_PORT:-8080}"
    HOST="${DASH_HOST:-127.0.0.1}"
    cat > /etc/systemd/system/security-dashboard.service <<EOF
[Unit]
Description=Proxmox & Docker Security Dashboard
After=network-online.target pve-cluster.service docker.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$(pwd)
ExecStart=$(pwd)/.venv/bin/uvicorn main:app --host ${HOST} --port ${PORT}
Restart=always
RestartSec=5
# Opcjonalnie: ochrona tokenem odkomentuj poniższą linię i ustaw własny sekret
# Environment=DASH_TOKEN=zmien-mnie-na-sekret
Environment=DASH_DATA_DIR=$(pwd)/data

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now security-dashboard.service
    info "Usługa systemd uruchomiona: systemctl status security-dashboard"
fi

echo
info "Instalacja zakończona."
echo
echo "Uruchomienie ręczne:"
echo "  .venv/bin/uvicorn main:app --host 127.0.0.1 --port 8080"
echo
echo "Panel dostępny pod: http://<adres-tego-hosta>:8080"
echo "Konfiguracja: plik data/state.json powstaje przy pierwszym starcie (chmod 600)."
