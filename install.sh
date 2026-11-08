#!/usr/bin/env bash
# Proxmox & Docker Security Dashboard – instalator.
#
# Użycie:
#   ./install.sh                  – venv + zależności + AUTOSTART (systemd), jeśli możliwe
#   ./install.sh --install-trivy  – dodatkowo instaluje Trivy na tym hoście
#   ./install.sh --no-systemd     – NIE rejestruje autostartu (tylko venv i zależności)
#   ./install.sh --uninstall      – usuwa usługę autostartu (panel przestaje startować)
#
# Autostart:
#   Panel rejestrowany jest jako usługa systemd `security-dashboard.service`
#   (systemctl enable --now), więc startuje automatycznie po restarcie hosta.
#   Jeśli dodatkowo na hoście jest Docker, usługa docker.service też trafia
#   do autostartu.
#
# Zmienne środowiskowe (opcjonalnie):
#   DASH_HOST=0.0.0.0     adres nasłuchu usługi   (domyślnie 0.0.0.0)
#   DASH_PORT=8080        port usługi             (domyślnie 8080)
#   DASH_TOKEN=sekret     ochrona hasłem GUI/API  (zalecane przy 0.0.0.0)
set -euo pipefail

cd "$(dirname "$0")"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info() { echo -e "${GREEN}[i]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
fail() { echo -e "${RED}[✗]${NC} $*"; exit 1; }

SERVICE=security-dashboard
UNIT=/etc/systemd/system/${SERVICE}.service

# ---------------------------------------------------------------- wymagania
command -v python3 >/dev/null 2>&1 || fail "Brak python3 (zainstaluj: apt install python3 python3-venv)"
PYVER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
python3 - "$PYVER" <<'EOF' || fail "Wymagany Python >= 3.9"
import sys
major, minor = sys.argv[1].split(".")
sys.exit(0 if (int(major), int(minor)) >= (3, 9) else 1)
EOF
info "Python $PYVER OK"

# ---------------------------------------------------------------- opcje
INSTALL_TRIVY=0; SYSTEMD=1; UNINSTALL=0
for arg in "$@"; do
    case "$arg" in
        --install-trivy) INSTALL_TRIVY=1 ;;
        --systemd)       SYSTEMD=1 ;;
        --no-systemd)    SYSTEMD=0 ;;
        --uninstall)     UNINSTALL=1 ;;
        *) warn "Nieznany argument: $arg" ;;
    esac
done

# ---------------------------------------------------------------- deinstalacja
if [ "$UNINSTALL" = "1" ]; then
    if command -v systemctl >/dev/null 2>&1; then
        SUDO=""
        [ "$(id -u)" = "0" ] || { command -v sudo >/dev/null 2>&1 && SUDO="sudo -n"; }
        $SUDO systemctl disable --now ${SERVICE}.service 2>/dev/null || true
        $SUDO rm -f "$UNIT"
        $SUDO systemctl daemon-reload
        info "Usługa ${SERVICE} usunięta z autostartu."
    else
        warn "systemd niedostępny – nic do usunięcia."
    fi
    exit 0
fi

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

# ---------------------------------------------------------------- trivy (opcja)
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

# ---------------------------------------------------------------- autostart (systemd)
setup_systemd() {
    if ! command -v systemctl >/dev/null 2>&1; then
        warn "systemd niedostępny (kontener?) – autostart pominięty."
        return 1
    fi
    SUDO=""
    if [ "$(id -u)" != "0" ]; then
        if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
            SUDO="sudo -n"
        else
            warn "Brak uprawnień root/sudo – autostart nie został zarejestrowany."
            echo "  Wykonaj ręcznie (jako root):"
            echo "    sudo $0 --systemd"
            return 1
        fi
    fi

    HOST="${DASH_HOST:-0.0.0.0}"
    PORT="${DASH_PORT:-8080}"
    APP_DIR="$(pwd)"
    TOKEN_LINE=""
    if [ -n "${DASH_TOKEN:-}" ]; then
        TOKEN_LINE="Environment=DASH_TOKEN=${DASH_TOKEN}"
    fi

    info "Rejestruję autostart: usługa systemd '${SERVICE}' (${HOST}:${PORT})…"
    $SUDO tee "$UNIT" >/dev/null <<EOF
[Unit]
Description=Proxmox & Docker Security Dashboard
After=network-online.target pve-cluster.service docker.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${APP_DIR}
ExecStart=${APP_DIR}/.venv/bin/uvicorn main:app --host ${HOST} --port ${PORT}
Restart=always
RestartSec=5
Environment=DASH_DATA_DIR=${APP_DIR}/data
${TOKEN_LINE}
# Uwaga: usługa działa jako root – to konieczne dla pct/qm, pct push i /usr/local/bin.
# Przy DASH_HOST=0.0.0.0 zalecana ochrona tokenem: DASH_TOKEN=sekret ./install.sh
[Install]
WantedBy=multi-user.target
EOF
    $SUDO systemctl daemon-reload
    if $SUDO systemctl is-active --quiet ${SERVICE}.service 2>/dev/null; then
        $SUDO systemctl restart ${SERVICE}.service
        info "Usługa zaktualizowana i zrestartowana."
    fi
    $SUDO systemctl enable ${SERVICE}.service >/dev/null 2>&1 \
        && info "Autostart włączony: panel uruchomi się po restarcie hosta." \
        || warn "Nie udało się włączyć autostartu: systemctl enable ${SERVICE}"

    # Docker także do autostartu (jeśli obecny)
    if command -v docker >/dev/null 2>&1 \
       && $SUDO systemctl list-unit-files docker.service >/dev/null 2>&1; then
        $SUDO systemctl enable docker.service >/dev/null 2>&1 \
            && info "Usługa docker.service również dodana do autostartu." || true
    fi

    echo
    info "Sterowanie usługą:"
    echo "    systemctl status  ${SERVICE}"
    echo "    systemctl restart ${SERVICE}"
    echo "    journalctl -u ${SERVICE} -f      (logi na żywo)"
}

if [ "$SYSTEMD" = "1" ]; then
    setup_systemd || true
else
    info "Pominięto autostart (--no-systemd)."
fi

# ---------------------------------------------------------------- podsumowanie
echo
info "Instalacja zakończona."
echo
if [ "$SYSTEMD" = "1" ] && command -v systemctl >/dev/null 2>&1 \
   && systemctl is-active --quiet ${SERVICE}.service 2>/dev/null; then
    PORT_SHOW="${DASH_PORT:-8080}"
    echo "Panel działa jako usługa:  http://$(hostname -I 2>/dev/null | awk '{print $1}'):${PORT_SHOW}"
    echo "Po restarcie hosta panel wystartuje sam (systemctl enable ${SERVICE})."
else
    echo "Uruchomienie ręczne:"
    echo "  .venv/bin/uvicorn main:app --host 0.0.0.0 --port 8080"
    echo "  (lub ./install.sh --systemd, aby dodać autostart)"
fi
echo
echo "Konfiguracja: plik data/state.json powstaje przy pierwszym starcie (chmod 600)."
