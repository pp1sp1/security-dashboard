# Proxmox & Docker Security Dashboard

Lekki, bezobsługowy panel webowy (FastAPI + Tailwind CSS) do **skanowania podatności
i automatycznej naprawy pakietów** na:

- węźle **Proxmox VE** i jego maszynach: kontenery **LXC** (skanowanie z zewnątrz
  przez rootfs / `pct exec`) oraz **VM** (przez QEMU Guest Agent lub Proxmox API),
- hoście z **Dockerem** (socket `/var/run/docker.sock`): kontenery i obrazy,
- dowolnych zdalnych serwerach przez **SSH** (IP, port, użytkownik, hasło lub klucz).

Silniki skanujące: **Trivy** (Aqua Security) i **Grype** (Anchore) – z automatyczną
instalacją jednym kliknięciem i automatyczną aktualizacją baz CVE przed każdym skanem.

---

## Funkcje

| Moduł | Opis |
|---|---|
| Automatyczne wykrywanie | `/etc/pve` → węzeł PVE; `/var/run/docker.sock` → Docker; hosty SSH dodajesz w GUI; opcjonalnie Proxmox API |
| Skanery | status Trivy/Grype na każdym zasobie; „brak skanera” → przycisk „zainstaluj” (pobiera statyczne binarki z GitHub Releases) |
| Skanowanie | w tle (BackgroundTasks); aktualizacja Trivy DB / Grype DB przed skanem; pliki, pakiety systemowe i zależności aplikacji |
| Naprawa (remediacja) | „Zaktualizuj ten pakiet” przy każdej podatności oraz „Zaktualizuj wszystkie podatne pakiety naraz”; automatyczne wykrywanie menedżera: `apt-get install --only-upgrade` (Debian/Ubuntu), `apk add --upgrade` (Alpine), `dnf/yum update` (RHEL) |
| Powiadomienia | ntfy, Gotify, Home Assistant (sensor + notify), Discord webhook, Telegram bot – dla CRITICAL/HIGH, z dedupe 24 h |
| GUI | ciemny motyw Tailwind: tabela zasobów, liczniki CRITICAL/HIGH/MEDIUM/LOW, szczegóły CVE z linkami, harmonogram skanów, dziennik aktywności |
| Bezobsługowość | brak bazy danych – stan w `data/state.json` (chmod 600); harmonogram w tle; auto-reconnect SSH; cache wyników |

## Wymagania

- Linux (Debian/Ubuntu/Alpine/RHEL lub inny z Pythonem ≥ 3.9),
- zalecane uruchamianie jako **root** (pełny dostęp do `pct`/`qm`, `/usr/local/bin`, socketa Dockera) –
  w przeciwnym razie instalacja skanerów użyje `sudo` bez hasła,
- dostęp do internetu (pobranie skanerów i baz CVE),
- opcjonalnie: Proxmox VE, Docker, oraz Trivy/Grype.

## Szybki start

```bash
unzip proxmox-security-dashboard.zip -d security-dashboard
cd security-dashboard
chmod +x install.sh
./install.sh                       # venv + zależności + AUTOSTART (systemd)
./install.sh --install-trivy       # (opcjonalnie) Trivy na tym hoście od razu

# warianty:
./install.sh --no-systemd          # bez autostartu (tylko venv i zależności)
./install.sh --uninstall           # usuwa usługę autostartu
DASH_TOKEN=mój-sekret ./install.sh # autostart + ochrona hasłem

# albo ręcznie (bez autostartu):
.venv/bin/uvicorn main:app --host 0.0.0.0 --port 8080
```

`./install.sh` domyślnie rejestruje usługę systemd **`security-dashboard.service`**
(`systemctl enable --now`), więc panel **startuje automatycznie po restarcie hosta**.
Jeśli na hoście jest Docker, do autostartu trafia też `docker.service`. Sterowanie:

```bash
systemctl status security-dashboard     # stan usługi
systemctl restart security-dashboard    # restart po aktualizacji
journalctl -u security-dashboard -f     # logi na żywo
```

Otwórz `http://<adres-hosta>:8080` w przeglądarce.

> **Bezpieczeństwo:** panel potrafi wykonywać polecenia na hostach – nie wystawiaj go
> bezpośrednio do internetu. Usługa systemd domyślnie nasłuchuje na `0.0.0.0:8080`;
> ogranicz dostęp firewallem i ustaw ochronę tokenem:
> `DASH_TOKEN=twoj-sekret ./install.sh`
> (GUI poprosi o token, API wymaga nagłówka `X-Dash-Token`). Inny adres/port:
> `DASH_HOST=127.0.0.1 DASH_PORT=8080 ./install.sh`.

## Workflow w panelu

1. **Zasoby** pojawiają się automatycznie: lokalny host, LXC/VM z PVE, kontenery Dockera,
   hosty SSH. Przycisk „Odśwież” ponawia wykrywanie.
2. Przy zasobie widzisz status skanerów. **„trivy brak – zainstaluj”** → panel pobiera
   najnowszą binarkę i instaluje na celu (lokalnie / SFTP / `pct push` / skrypt w VM / `docker cp`).
3. **„Skanuj”** – zadanie w tle: najpierw aktualizacja bazy CVE, potem skan.
   Postęp widoczny w panelu zadań (prawy dolny róg).
4. **„Szczegóły”** – tabela podatności z filtrami wag; przy każdej: pakiet, wersja
   zainstalowana → poprawka, przycisk **„Zaktualizuj ten pakiet”**.
5. **„Napraw pakiety”** – masowa aktualizacja wszystkich podatnych pakietów z dostępną
   poprawką (wszystkie naraz, jednym poleceniem na cel).
6. Po naprawie uruchom ponowny skan, aby zweryfikować efekt.

## Proxmox VE – jak to działa

- **Węzeł lokalny** (panel działa na PVE): wykrycie przez `/etc/pve`; LXC listowane przez
  `pct list`, VM przez `qm list`.
- **LXC skanowane z zewnątrz** (domyślnie, brak agenta w kontenerze): Trivy na węźle skanuje
  `/var/lib/lxc/<vmid>/rootfs`. Nic nie jest instalowane w kontenerze. Naprawa i tak idzie
  przez `pct exec`. Jeżeli rootfs nie jest dostępny (np. nietypowe storage), panel
  automatycznie przełącza się na `pct exec` i instaluje skaner wewnątrz kontenera.
- **VM**: polecenia przez **QEMU Guest Agent** (`qm guest exec`, wymaga zainstalowanego
  i uruchomionego agenta oraz curl/wget w VM dla instalacji skanera). Ze względu na limity
  wyjścia agenta duże raporty JSON są zapisywane do pliku w VM i odczytywane stamtąd;
  w razie ucięcia panel pokaże ostrzeżenie z sugestią trybu SSH.
- **Zdalny węzeł PVE**: dodaj go jako **host SSH** (zaznacz „To jest węzeł Proxmox VE”),
  a panel wykryje jego LXC/VM (`pct`/`qm` przez SSH). Alternatywnie włącz **Proxmox API**
  w Ustawieniach (token lub login/hasło) – zdalne VM skanowane przez `agent/exec` API,
  LXC przez API tylko listowane (skanowanie wymaga SSH do węzła).

## Docker

- Wykrycie socketa (`/var/run/docker.sock` lub `DOCKER_HOST`); listowane są uruchomione
  kontenery; skanowanie przez `trivy image <obraz>` / `grype <obraz>` na hoście panelu.
- Naprawa w kontenerze działa przez `docker exec` (`apk`/`apt` wewnątrz kontenera), ale
  pamiętaj: zmiany w kontenerze znikają przy odtworzeniu z obrazu – trwałe naprawy robisz
  przez aktualizację obrazu i redeploy.

## Powiadomienia – konfiguracja (Ustawienia)

- **ntfy**: URL tematu, np. `https://ntfy.sh/moj-sekret-temat`; subskrybuj temat w aplikacji.
- **Gotify**: URL serwera + token aplikacji.
- **Home Assistant**: URL + token długoterminowy (Profil → Bezpieczeństwo). Panel ustawia
  sensor (np. `sensor.security_dashboard`, stan = liczba CRITICAL+HIGH, atrybuty per cel)
  i opcjonalnie wywołuje usługę `notify.*` (np. `notify.mobile_app_telefon`).
- **Discord**: webhook kanału (Ustawienia kanału → Integracje → Webhooki).
- **Telegram**: token od @BotFather + chat_id (np. przez @userinfobot). Bot musi mieć
  rozmowę z odbiorcą.
- Próg wag: HIGH i CRITICAL (domyślnie) lub tylko CRITICAL. Dedupe: to samo CVE nie jest
  wysyłane ponownie przez 24 h. Przycisk „Testuj powiadomienia” sprawdza wszystkie
  włączone kanały.

## Harmonogram skanów

Ustawienia → „Harmonogram skanów (godziny)”: co N godzin panel skanuje wszystkie
dostępne zasoby (baza CVE aktualizowana raz na cykl). `0` wyłącza harmonogram.

## Struktura projektu

```
main.py          FastAPI: REST API, wykrywanie środowiska, zadania w tle, harmonogram
scanner.py       Trivy/Grype: wykrywanie, auto-instalacja, bazy CVE, skanowanie, parsowanie
proxmox.py       pct/qm lokalnie i przez SSH, klient Proxmox API (token/hasło), guest exec
ssh_manager.py   paramiko: pula połączeń, exec, SFTP, test hosta
docker_mgr.py    wykrywanie socketa, lista kontenerów/obrazów
remediation.py   wykrywanie menedżera pakietów i budowa komend naprawy
notifier.py      ntfy, Gotify, Home Assistant, Discord, Telegram
store.py         persystencja: data/state.json (atomowo, chmod 600)
templates/       GUI (index.html)
static/          app.js, style.css
install.sh       instalator: venv, zależności, AUTOSTART systemd (--no-systemd, --uninstall)
```

## API (skrót)

| Metoda | Endpoint | Opis |
|---|---|---|
| GET | `/api/status` | wersja, wykryte środowisko |
| GET | `/api/hosts` | zasoby + podsumowania skanów |
| POST | `/api/discover` | wymuś ponowne wykrywanie |
| POST | `/api/hosts/ssh` | dodaj host SSH (test połączenia opcjonalny) |
| DELETE | `/api/hosts/ssh/{id}` | usuń host SSH |
| POST | `/api/hosts/{id}/test` | test połączenia |
| GET | `/api/hosts/{id}/scanners` | wersje Trivy/Grype na celu |
| POST | `/api/hosts/{id}/install-scanner` | `{"name":"trivy"|"grype"}` – instalacja |
| POST | `/api/hosts/{id}/scan` | skan w tle (baza CVE aktualizowana wg ustawień) |
| POST | `/api/hosts/{id}/update-dbs` | tylko aktualizacja baz CVE |
| GET | `/api/hosts/{id}/vulns` | pełny wynik ostatniego skanu |
| POST | `/api/hosts/{id}/remediate` | `{"packages":["pkg1",…]}` – aktualizacja wybranych |
| POST | `/api/hosts/{id}/remediate-all` | napraw wszystkie podatne pakiety |
| POST | `/api/scan-all` | skan wszystkich zasobów |
| GET | `/api/tasks` | statusy zadań w tle |
| GET/POST | `/api/settings` | ustawienia (sekrety maskowane) |
| POST | `/api/settings/test-notify` | test powiadomień |
| GET | `/api/logs` | dziennik aktywności |

## Rozwiązywanie problemów

- **„Brak skanera” na zasobie** – kliknij chip `trivy/grype brak – zainstaluj` lub włącz
  „Automatycznie doinstaluj skaner przy skanie”. Instalacja wymaga root/sudo na celu.
- **VM: „QEMU Guest Agent”** – zainstaluj agenta w VM (`apt install qemu-guest-agent`) i
  włącz w opcjach VM; upewnij się, że działa (`systemctl status qemu-guest-agent`).
- **Skan VM kończy się ostrzeżeniem o ucięciu** – limit wyjścia agenta; dodaj VM jako host
  SSH, aby skanować niezawodnie.
- **LXC z nietypowym storage (ZFS/BTRFS/LVM-thin)** – rootfs wykrywany jest z
  `lxc.rootfs.path` w `/var/lib/lxc/<vmid>/config` (obsługuje datasety ZFS, np.
  `/rpool/data/subvol-<vmid>-disk-0`). Dla storage katalogowego używany jest
  `/var/lib/lxc/<vmid>/rootfs`. Gdy rootfs nadal niedostępny (np. LVM-thin), panel
  sam użyje `pct exec` i zainstaluje Trivy wewnątrz kontenera (kontener potrzebuje
  wtedy tylko `sh`).
- **`trivy: not found` wewnątrz kontenera LXC** – panel skanuje LXC z zewnątrz
  (rootfs na węźle), więc wystarczy Trivy na węźle PVE. Jeśli celowo skanujesz
  wewnątrz, sprawdź architekturę/libc (Alpine/musl wymaga `apk add trivy`).
- **grype: „invalid exclusion pattern(s)”** – naprawione w v1.1.0 (wzorce wyłączeń
  muszą być globami `/proc/**`, a nie `/proc`). Zaktualizuj panel do tej wersji.
- **Remediacja apt: 0 OK, same błędy** – najczęściej `apt-get update` kończy się
  błędem (np. repozytorium enterprise PVE bez subskrypcji). Od v1.1.0 nieudany
  update nie przerywa naprawy; pakiety nieobecne w dpkg są pomijane z powodem.
  Przyczyna każdego błędu widać w dzienniku i szczegółach zadania.
- **„Nie rozpoznano systemu”** – naprawa wspiera apt/apk/dnf; inne dystrybucje wymagają
  ręcznej aktualizacji.
- **Pakiety się nie aktualizują** – repozytoria celu muszą zawierać wersje poprawek
  (`apt-get update` wykonuje panel automatycznie; sprawdź mirror/subskrypcję PVE).
- **Brak powiadomień** – „Testuj powiadomienia” pokazuje błąd per kanał; sprawdź URL/tokeny.
- **Reset danych** – zatrzymaj panel i usuń `data/state.json` (zostanie utworzony na nowo).

## Bezpieczeństwo i dane

- Stan (w tym sekrety: hasła SSH, tokeny) trzymany jest w `data/state.json` z uprawnieniami
  `0600` – zadbaj o ochronę katalogu `data/`.
- Klucze prywatne wpisywane w GUI przechowywane są w tym pliku; zalecany dedykowany klucz
  tylko dla panelu.
- Panel nie wymaga bazy danych ani kompilacji; cały kod to Python + statyczne pliki GUI.
