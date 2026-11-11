#!/usr/bin/env bash
# Proxmox & Docker Security Dashboard – instalator.
#
# Użycie:
#   ./install.sh                  – venv + zależności + AUTOSTART (systemd), jeśli możliwe
#   ./install.sh --install-trivy  – dodatkowo instaluje Trivy na tym hoście
#   ./install.sh --no-systemd     – NIE rejestruje autostartu (tylko venv i zależności)
#   ./install.sh --uninstall      – usuwa usługę autostartu (panel przestaje startować)
#   ./install.sh --update         – pobiera najnowszy kod z GitHuba i aktualizuje panel,
#                                   NIE dotykając data/state.json (ustawienia, hosty SSH,
#                                   historia skanów) ani .venv
#
# Instalacja jednym poleceniem (bez klonowania repo):
#   curl -fsSL https://raw.githubusercontent.com/pp1sp1/security-dashboard/main/install.sh | bash
#   (instalator sam pobierze kod z GitHuba do /opt/security-dashboard i dokończy instalację)
#
# Autostart:
#   Panel rejestrowany jest jako usługa systemd `security-dashboard.service`
#   (systemctl enable --now), więc startuje automatycznie po restarcie hosta.
#   Jeśli dodatkowo na hoście jest Docker, usługa docker.service też trafia
#   do autostartu.
#
# Zmienne środowiskowe (opcjonalnie):
#   DASH_HOST=0.0.0.0     adres nasłuchu usługi   (domyślnie 127.0.0.1; przy ponownym
#                         uruchomieniu instalatora ZACHOWUJE dotychczasowy adres z unitu)
#   DASH_PORT=8080        port usługi             (domyślnie 8080)
#   DASH_TOKEN=sekret     ochrona hasłem GUI/API  (zalecane przy 0.0.0.0)
#   DASH_INSTALL_DIR=/opt/security-dashboard   katalog instalacji (tryb curl|bash)
#   DASH_REPO_TARBALL=URL nadpisanie źródła kodu (domyślnie GitHub main.tar.gz)
set -euo pipefail

REPO_TARBALL="${DASH_REPO_TARBALL:-https://github.com/pp1sp1/security-dashboard/archive/refs/heads/main.tar.gz}"
DEFAULT_DIR="/opt/security-dashboard"
SERVICE=security-dashboard
UNIT=/etc/systemd/system/${SERVICE}.service

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info() { echo -e "${GREEN}[i]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
fail() { echo -e "${RED}[✗]${NC} $*"; exit 1; }

# Wejdź do katalogu panelu, jeśli skrypt leży obok main.py (git clone / ZIP):
# `./install.sh` oraz `bash /sciezka/install.sh --update` działają wtedy na właściwym katalogu.
# W trybie curl|bash (piping) plików lokalnych nie ma – dalej zadziała bootstrap.
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"
if [ -n "$SELF_DIR" ] && [ -f "$SELF_DIR/main.py" ]; then
    cd "$SELF_DIR"
fi

# ---------------------------------------------------------------- opcje
INSTALL_TRIVY=0; SYSTEMD=1; UNINSTALL=0; UPDATE=0
for arg in "$@"; do
    case "$arg" in
        --install-trivy) INSTALL_TRIVY=1 ;;
        --systemd)       SYSTEMD=1 ;;
        --no-systemd)    SYSTEMD=0 ;;
        --uninstall)     UNINSTALL=1 ;;
        --update)        UPDATE=1 ;;
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
        info "Usługa ${SERVICE} usunięta z autostartu. Pliki panelu i data/ pozostały."
    else
        warn "systemd niedostępny – nic do usunięcia."
    fi
    exit 0
fi

# ---------------------------------------------------------------- pobranie kodu z GitHuba
fetch_repo() {
    local dl="" tmp src
    if command -v curl >/dev/null 2>&1; then
        dl="curl"
    elif command -v wget >/dev/null 2>&1; then
        dl="wget"
    else
        fail "Brak curl i wget – nie mogę pobrać kodu panelu (zainstaluj: apt install curl)."
    fi
    tmp=$(mktemp -d /tmp/.dash-code.XXXXXX)
    info "Pobieram kod panelu: $REPO_TARBALL" >&2
    if [ "$dl" = "curl" ]; then
        curl -fsSL --connect-timeout 20 -o "$tmp/code.tgz" "$REPO_TARBALL" \
            || { rm -rf "$tmp"; fail "Pobieranie (curl) nie powiodło się – sprawdź adres/internet."; }
    else
        wget -qO "$tmp/code.tgz" "$REPO_TARBALL" \
            || { rm -rf "$tmp"; fail "Pobieranie (wget) nie powiodło się – sprawdź adres/internet."; }
    fi
    [ -s "$tmp/code.tgz" ] || { rm -rf "$tmp"; fail "Pobrane archiwum jest puste."; }
    tar -xzf "$tmp/code.tgz" -C "$tmp"
    src=$(find "$tmp" -maxdepth 1 -type d -name 'security-dashboard*' | head -n 1)
    if [ -z "$src" ] || [ ! -f "$src/main.py" ]; then
        rm -rf "$tmp"
        fail "Archiwum nie zawiera kodu panelu (main.py) – sprawdź DASH_REPO_TARBALL."
    fi
    echo "$src"
}

# Nadpisanie plików kodu z zachowaniem data/ (ustawienia, hosty, wyniki) i .venv.
apply_code() {
    local SRC="$1" DEST="$2" f d
    for f in main.py scanner.py executor.py proxmox.py ssh_manager.py docker_mgr.py \
             remediation.py notifier.py store.py requirements.txt README.md install.sh; do
        [ -f "$SRC/$f" ] && cp -f "$SRC/$f" "$DEST/$f"
    done
    for d in templates static; do
        if [ -d "$SRC/$d" ]; then
            rm -rf "$DEST/$d"
            cp -a "$SRC/$d" "$DEST/$d"
        fi
    done
    chmod +x "$DEST/install.sh" 2>/dev/null || true
}

# ---------------------------------------------------------------- tryb curl|bash (bootstrap)
# Uruchomiony bez plików projektu (np. `curl … | bash`) – pobierz kod sam.
if [ ! -f main.py ]; then
    DEST="${DASH_INSTALL_DIR:-$DEFAULT_DIR}"
    info "Brak plików panelu w bieżącym katalogu ($(pwd))."
    if [ -f "$DEST/main.py" ]; then
        SRC=$(fetch_repo)
        info "Znaleziono istniejącą instalację w $DEST – aktualizuję kod (data/ i .venv zachowane)…"
        apply_code "$SRC" "$DEST"
        rm -rf "$(dirname "$SRC")"
    else
        if ! mkdir -p "$DEST" 2>/dev/null; then
            fail "Nie mogę utworzyć katalogu $DEST – uruchom jako root lub ustaw: DASH_INSTALL_DIR=/twoja/sciezka"
        fi
        SRC=$(fetch_repo)
        cp -a "$SRC/." "$DEST/"
        rm -rf "$(dirname "$SRC")"
        info "Kod panelu zapisany w: $DEST"
    fi
    cd "$DEST"
    UPDATE=0   # kod świeży po pobraniu – nie pobieramy drugi raz
fi

# ---------------------------------------------------------------- tryb --update
if [ "$UPDATE" = "1" ]; then
    SRC=$(fetch_repo)
    APP_DIR="$(pwd)"
    apply_code "$SRC" "$APP_DIR"
    rm -rf "$(dirname "$SRC")"
    info "Kod zaktualizowany (katalog data/ i .venv nietknięte – ustawienia, hosty SSH "
    info "i wyniki skanów zostały zachowane)."
    if [ -d .venv ]; then
        info "Aktualizuję zależności Python…"
        .venv/bin/pip install --quiet --upgrade pip || true
        .venv/bin/pip install --quiet -r requirements.txt \
            || warn "pip install zgłosił błędy – sprawdź komunikaty powyżej."
    fi
    if command -v systemctl >/dev/null 2>&1; then
        SUDO=""
        [ "$(id -u)" = "0" ] || { command -v sudo >/dev/null 2>&1 && SUDO="sudo -n"; }
        if $SUDO systemctl is-active --quiet ${SERVICE}.service 2>/dev/null; then
            $SUDO systemctl restart ${SERVICE}.service
            info "Usługa ${SERVICE} zrestartowana – panel działa na nowym kodzie."
        else
            info "Usługa ${SERVICE} nie jest aktywna – uruchom panel ręcznie albo wykonaj "
            echo "    $0   (doda także autostart systemd)."
        fi
    fi
    echo
    info "Aktualizacja zakończona."
    exit 0
fi

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

    # Przy ponownym uruchomieniu instalatora zachowaj dotychczasowy adres/port z unitu
    # (zmiana nie może "przemycić" utraty dostępu po aktualizacji); DASH_HOST/DASH_PORT mają priorytet.
    CUR_HOST=$(sed -n 's/^ExecStart=.*--host \([^ ]*\).*$/\1/p' "$UNIT" 2>/dev/null | tail -n 1)
    CUR_PORT=$(sed -n 's/^ExecStart=.*--port \([^ ]*\).*$/\1/p' "$UNIT" 2>/dev/null | tail -n 1)
    HOST="${DASH_HOST:-${CUR_HOST:-127.0.0.1}}"
    PORT="${DASH_PORT:-${CUR_PORT:-8080}}"
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
# Domyślnie nasłuch na 127.0.0.1 (bezpiecznie; dostęp przez tunel SSH / reverse proxy).
# Dostęp sieciowy: DASH_HOST=0.0.0.0 DASH_TOKEN=twoj-sekret ./install.sh
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
    PORT_SHOW="${DASH_PORT:-$(sed -n 's/^ExecStart=.*--port \([^ ]*\).*$/\1/p' "$UNIT" 2>/dev/null | tail -n 1)}"
    PORT_SHOW="${PORT_SHOW:-8080}"
    HOST_SHOW=$(sed -n 's/^ExecStart=.*--host \([^ ]*\).*$/\1/p' "$UNIT" 2>/dev/null | tail -n 1)
    echo "Panel działa jako usługa:  http://${HOST_SHOW:-127.0.0.1}:${PORT_SHOW}"
    if [ "${HOST_SHOW:-127.0.0.1}" = "127.0.0.1" ]; then
        echo
        echo "Nasłuch tylko lokalnie (bezpieczny domyślny). Dostęp z sieci LAN (opcjonalnie):"
        echo "    DASH_HOST=0.0.0.0 DASH_TOKEN=twoj-sekret ./install.sh"
        echo "albo tunel SSH:  ssh -L 8080:127.0.0.1:8080 user@host"
    fi
    echo "Po restarcie hosta panel wystartuje sam (systemctl enable ${SERVICE})."
else
    echo "Uruchomienie ręczne:"
    echo "  .venv/bin/uvicorn main:app --host 127.0.0.1 --port 8080   (lokalnie)"
    echo "  DASH_TOKEN=sekret .venv/bin/uvicorn main:app --host 0.0.0.0 --port 8080   (LAN)"
    echo "  (lub ./install.sh, aby dodać autostart systemd)"
fi
echo
echo "Aktualizacja panelu w przyszłości (bez utraty ustawień i wyników):"
echo "    $0 --update"
echo
echo "Konfiguracja: plik data/state.json powstaje przy pierwszym starcie (chmod 600)."
