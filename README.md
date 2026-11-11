# Proxmox & Docker Security Dashboard

Lekki, bezobsługowy panel webowy (**FastAPI + Tailwind CSS**) do skanowania podatności i automatycznej naprawy pakietów na:
- **Węźle Proxmox VE i jego maszynach:** kontenery LXC (skanowanie z zewnątrz przez `rootfs` / `pct exec`) oraz VM (przez QEMU Guest Agent lub Proxmox API),
- **Hoście z Dockerem** (`/var/run/docker.sock`): kontenery i obrazy,
- **Dowolnych zdalnych serwerach przez SSH** (IP, port, użytkownik, hasło lub klucz).

**Silniki skanujące:** Trivy (Aqua Security) i Grype (Anchore) – z automatyczną instalacją jednym kliknięciem i automatyczną aktualizacją baz CVE przed każdym skanem.

---

## ⚡ Szybki start (Instalacja jednym poleceniem)

Wklej poniższe polecenie w terminalu na maszynie docelowej. Pobierze ono kod z GitHuba, przygotuje środowisko wirtualne Pythona (`venv`), doinstaluje zależności i uruchomi instalator:

```bash
git clone https://github.com/pp1sp1/security-dashboard.git && cd security-dashboard && chmod +x install.sh && ./install.sh
```

**Wariant bez gita (curl/wget)** – instalator sam pobiera kod i aktualizuje się tą samą komendą:

```bash
curl -fsSL https://raw.githubusercontent.com/pp1sp1/security-dashboard/main/install.sh | bash -
```

### Opcjonalne warianty instalacji jednym poleceniem:

* **Zainstaluj od razu z Trivy na hoście:**
  ```bash
  git clone https://github.com/pp1sp1/security-dashboard.git && cd security-dashboard && chmod +x install.sh && ./install.sh --install-trivy
  ```

* **Bez autostartu** (instalator domyślnie dodaje usługę systemd; `--no-systemd` rezygnuje):
  ```bash
  ./install.sh --no-systemd
  ```

* **Ręczne uruchomienie (po zainstalowaniu):**
  ```bash
  .venv/bin/uvicorn main:app --host 127.0.0.1 --port 8080
  ```

Otwórz w przeglądarce: **`http://<adres-hosta>:8080`**

> ⚠️ **Bezpieczeństwo:** Panel potrafi wykonywać polecenia na hostach – **nie wystawiaj go bezpośrednio do otwartego internetu**. Domyślnie systemd wiąże na `127.0.0.1` (dostęp przez tunel SSH lub reverse proxy).  
> Dla dostępu sieciowego ustaw ochronę tokenem:  
> `DASH_TOKEN=twoj-sekret DASH_HOST=0.0.0.0 ./install.sh`  
> *(GUI poprosi o token, API wymaga nagłówka `X-Dash-Token`)*.

---

## 🔄 Aktualizacja panelu (bez utraty danych)

```bash
cd security-dashboard && ./install.sh --update
```

Instalator pobiera najnowszy kod z GitHuba i podmienia **wyłącznie pliki aplikacji** (`*.py`, `templates/`, `static/`, `install.sh`, `README.md`). **Nie dotyka**:

- `data/state.json` – ustawienia, hosty SSH, tokeny powiadomień, historia skanów,
- `.venv` – środowisko Python (zależności doinstalowywane wg `requirements.txt`),
- `data/` – wszystkie wyniki skanów.

Po aktualizacji usługa jest automatycznie restartowana (jeśli działa pod systemd). Ta sama komenda `curl … | bash` wpisana ponownie również działa jako aktualizacja – instalator wykryje istniejącą instalację w `/opt/security-dashboard` (lub w `DASH_INSTALL_DIR`) i odświeży kod z zachowaniem danych.

---

## ✨ Funkcje

| Moduł | Opis |
| :--- | :--- |
| **Automatyczne wykrywanie** | `/etc/pve` → węzeł PVE; `/var/run/docker.sock` → Docker; hosty SSH dodajesz w GUI; opcjonalnie Proxmox API |
| **Skanery** | Status Trivy/Grype na każdym zasobie; „brak skanera” → przycisk „zainstaluj” – **cel pobiera binarkę sam przez curl/wget** (fallback: panel pobiera na hoście i wgrywa przez SFTP / `pct push` / `docker cp`) |
| **Skanowanie** | W tle (`BackgroundTasks`); aktualizacja Trivy DB / Grype DB przed skanem; pliki, pakiety systemowe i zależności aplikacji |
| **Naprawa (remediacja)** | „Zaktualizuj ten pakiet” przy każdej podatności oraz „Zaktualizuj wszystkie podatne pakiety naraz”; automatyczne wykrywanie menedżera: `apt-get install --only-upgrade` (Debian/Ubuntu), `apk add --upgrade` (Alpine), `dnf/yum update` (RHEL) |
| **Powiadomienia** | ntfy, Gotify, Home Assistant (sensor + notify), Discord webhook, Telegram bot – dla CRITICAL/HIGH, z dedupe 24 h |
| **GUI** | Ciemny motyw Tailwind: tabela zasobów, liczniki CRITICAL/HIGH/MEDIUM/LOW, szczegóły CVE z linkami, harmonogram skanów, dziennik aktywności |
| **Bezobsługowość** | Brak bazy danych – stan w `data/state.json` (`chmod 600`); harmonogram w tle; auto-reconnect SSH; cache wyników |

---

## 📋 Wymagania

- **Linux** (Debian/Ubuntu/Alpine/RHEL lub inny z Pythonem ≥ 3.9),
- **Uprawnienia:** zalecane uruchamianie jako `root` (pełny dostęp do `pct`/`qm`, `/usr/local/bin`, socketa Dockera) – w przeciwnym razie instalacja skanerów użyje `sudo` bez hasła,
- Dostęp do internetu (pobranie skanerów i baz CVE),
- **Opcjonalnie:** Proxmox VE, Docker oraz Trivy/Grype.

---

## 🔄 Workflow w panelu

1. **Wykrywanie:** Zasoby pojawiają się automatycznie: lokalny host, LXC/VM z PVE, kontenery Dockera, hosty SSH. Przycisk „Odśwież” ponawia wykrywanie.
2. **Status skanerów:** Przy zasobie widzisz status. Jeśli brakuje silnika (`trivy brak – zainstaluj`), kliknięcie wysyła celowi polecenie, które **samo pobiera najnowszą binarkę przez curl/wget** i instaluje do `/usr/local/bin`. Gdy cel nie ma internetu ani curl/wget, panel pobiera binarkę na hoście i wysyła (SFTP / `pct push` / `docker cp`). Panel aktualizuje też starsze wersje skanerów do najnowszych.
3. **Skanowanie:** Przycisk „Skanuj” uruchamia zadanie w tle: najpierw następuje aktualizacja bazy CVE, potem skan. Postęp jest widoczny w panelu zadań (prawy dolny róg).
4. **Szczegóły:** Tabela podatności z filtrami wag. Przy każdej pozycji: pakiet, wersja zainstalowana → wersja poprawiona, przycisk „Zaktualizuj ten pakiet”.
5. **Naprawa:** „Napraw pakiety” wykonuje masową aktualizację wszystkich podatnych pakietów z dostępną poprawką (naraz, jednym poleceniem na dany cel).
6. **Weryfikacja:** Po naprawie uruchom ponowny skan, aby potwierdzić usunięcie podatności.

---

## 🖥️ Proxmox VE – jak to działa

* **Węzeł lokalny (panel działa na PVE):** Wykrycie przez `/etc/pve`; LXC listowane przez `pct list`, VM przez `qm list`.
* **LXC skanowane z zewnątrz (domyślnie, brak agenta w kontenerze):** Trivy na węźle skanuje `/var/lib/lxc/<vmid>/rootfs`. Nic nie jest instalowane w kontenerze. Naprawa odbywa się przez `pct exec`. Jeżeli `rootfs` nie jest dostępny (np. nietypowe storage), panel automatycznie przełącza się na `pct exec` i instaluje skaner wewnątrz kontenera.
* **VM:** Polecenia idą przez QEMU Guest Agent (`qm guest exec`, wymaga zainstalowanego i uruchomionego agenta oraz `curl`/`wget` w VM do instalacji skanera). Ze względu na limity wyjścia agenta, duże raporty JSON są zapisywane do pliku wewnątrz VM i stamtąd odczytywane; w razie ucięcia panel pokaże ostrzeżenie z sugestią trybu SSH.
* **Zdalny węzeł PVE:** Dodaj go jako host SSH (zaznacz „To jest węzeł Proxmox VE”), a panel wykryje jego LXC/VM (`pct`/`qm` przez SSH). Alternatywnie włącz Proxmox API w Ustawieniach (token lub login/hasło) – zdalne VM skanowane są przez `agent/exec` API, a LXC przez API są tylko listowane (skanowanie wymaga SSH do węzła).

---

## 🐳 Docker

- Wykrycie socketa (`/var/run/docker.sock` lub zmienna `DOCKER_HOST`). Listowane są uruchomione kontenery. Skanowanie odbywa się przez `trivy image <obraz>` / `grype <obraz>` na hoście panelu.
- Naprawa w kontenerze działa przez `docker exec` (`apk`/`apt` wewnątrz kontenera).  
  *Pamiętaj: zmiany w kontenerze znikają przy odtworzeniu z obrazu – trwałe naprawy wykonuje się przez aktualizację obrazu i redeploy.*

---

## 🔔 Powiadomienia – konfiguracja (Ustawienia)

- **ntfy:** URL tematu, np. `https://ntfy.sh/moj-sekret-temat`; subskrybuj temat w aplikacji.
- **Gotify:** URL serwera + token aplikacji.
- **Home Assistant:** URL + token długoterminowy (*Profil → Bezpieczeństwo*). Panel konfiguruje sensor (np. `sensor.security_dashboard`, stan = liczba CRITICAL+HIGH, atrybuty per cel) i opcjonalnie wywołuje usługę `notify.*` (np. `notify.mobile_app_telefon`).
- **Discord:** Webhook kanału (*Ustawienia kanału → Integracje → Webhooki*).
- **Telegram:** Token od `@BotFather` + `chat_id` (np. z `@userinfobot`). Bot musi mieć aktywny czat z odbiorcą.
- **Próg wag:** HIGH i CRITICAL (domyślnie) lub tylko CRITICAL. 
- **Deduplikacja:** To samo CVE nie jest wysyłane ponownie przez 24 h. Przycisk „Testuj powiadomienia” weryfikuje wszystkie włączone kanały.

---

## ⏰ Harmonogram skanów

W *Ustawienia → „Harmonogram skanów (godziny)”*: co N godzin panel skanuje wszystkie dostępne zasoby (baza CVE jest aktualizowana raz na cykl). Wartość `0` całkowicie wyłącza harmonogram.

---

## 📁 Struktura projektu

```text
main.py          # FastAPI: REST API, wykrywanie środowiska, zadania w tle, harmonogram
scanner.py       # Trivy/Grype: wykrywanie, auto-instalacja (curl/wget na celu), bazy CVE, skanowanie
proxmox.py       # pct/qm lokalnie i przez SSH, klient Proxmox API (token/hasło), guest exec
executor.py      # Abstrakcja wykonywania poleceń: local / ssh / pct exec / qm guest exec / docker exec
ssh_manager.py   # Paramiko: pula połączeń, exec, SFTP, test hosta
docker_mgr.py    # Wykrywanie socketa, lista kontenerów/obrazów
remediation.py   # Wykrywanie menedżera pakietów i budowa komend naprawy
notifier.py      # ntfy, Gotify, Home Assistant, Discord, Telegram
store.py         # Persystencja: data/state.json (atomowo, chmod 600)
templates/       # GUI (index.html)
static/          # app.js, style.css
install.sh       # Instalator (venv, autostart systemd, --update, tryb curl|bash)
```

---

## 🔌 API (Skrót)

| Metoda | Endpoint | Opis |
| :--- | :--- | :--- |
| `GET` | `/api/status` | Wersja, wykryte środowisko |
| `GET` | `/api/hosts` | Zasoby + podsumowania skanów |
| `POST` | `/api/discover` | Wymuś ponowne wykrywanie |
| `POST` | `/api/hosts/ssh` | Dodaj host SSH (test połączenia opcjonalny) |
| `DELETE` | `/api/hosts/ssh/{id}` | Usuń host SSH |
| `POST` | `/api/hosts/{id}/test` | Test połączenia |
| `GET` | `/api/hosts/{id}/scanners` | Wersje Trivy/Grype na celu |
| `POST` | `/api/hosts/{id}/install-scanner` | Instalacja silnika skanującego (`{"name":"trivy"}`) |
| `POST` | `/api/hosts/{id}/scan` | Skan w tle (baza CVE aktualizowana wg ustawień) |
| `POST` | `/api/hosts/{id}/update-dbs` | Tylko aktualizacja baz CVE |
| `GET` | `/api/hosts/{id}/vulns` | Pełny wynik ostatniego skanu |
| `POST` | `/api/hosts/{id}/remediate` | Aktualizacja wybranych pakietów (`{"packages":["pkg1", ...]}`) |
| `POST` | `/api/hosts/{id}/remediate-all` | Napraw wszystkie podatne pakiety |
| `POST` | `/api/scan-all` | Skan wszystkich zasobów |
| `GET` | `/api/tasks` | Statusy zadań w tle |
| `GET/POST` | `/api/settings` | Ustawienia (sekrety maskowane) |
| `POST` | `/api/settings/test-notify` | Test powiadomień |
| `GET` | `/api/logs` | Dziennik aktywności |

---

## ❓ Rozwiązywanie problemów

* **„Brak skanera” na zasobie:** Kliknij chip `trivy/grype brak – zainstaluj` lub włącz opcję „Automatycznie doinstaluj skaner przy skanie”. Od v1.2.0 cel pobiera binarkę **sam przez curl/wget** – wymagany internet i `curl`/`wget` na celu; gdy ich brak, panel pobiera na hoście i wysyła przez SFTP/`pct push`/`docker cp`.
* **Instalacja w VM kończy się błędem „VM wymaga curl lub wget”:** W maszynie musi być `curl` albo `wget` oraz dostęp do internetu (`apt install curl` w VM). Alternatywnie dodaj VM jako host SSH – panel wgra skaner przez SFTP.
* **VM: „QEMU Guest Agent”:** Zainstaluj agenta w maszynie VM (`apt install qemu-guest-agent`) i włącz go w opcjach VM w Proxmoxie; upewnij się, że działa (`systemctl status qemu-guest-agent`).
* **Skan VM kończy się ostrzeżeniem o ucięciu:** Wynika to z limitu bufora agenta; dodaj tę VM jako bezpośredni host SSH, aby skanować bez ograniczeń.
* **LXC z nietypowym storage:** Brak ścieżki `/var/lib/lxc/<vmid>/rootfs` → panel sam przełączy się na `pct exec` i doinstaluje Trivy w kontenerze (kontener wymaga wtedy powłoki `sh`).
* **„Nie rozpoznano systemu”:** Moduł naprawy wspiera dystrybucje z `apt`, `apk` oraz `dnf/yum`; inne systemy wymagają ręcznej aktualizacji.
* **Pakiety się nie aktualizują:** Repozytoria celu muszą zawierać wersje z poprawkami (panel wykonuje `apt-get update` automatycznie; sprawdź konfigurację mirrorów/subskrypcji na PVE).
* **Brak powiadomień:** Użyj przycisku „Testuj powiadomienia” – pokaże błąd per kanał; zweryfikuj URL-e i tokeny.
* **Reset danych:** Zatrzymaj panel i usuń plik `data/state.json` (przy kolejnym uruchomieniu zostanie wygenerowany na nowo).

---

## 🔒 Bezpieczeństwo i dane

- Stan aplikacji (w tym sekrety: hasła SSH, tokeny) przechowywany jest w `data/state.json` z restrykcyjnymi uprawnieniami `0600` – chroń zawartość katalogu `data/`.
- Klucze prywatne wpisywane w GUI zapisywane są w tym samym pliku; zaleca się wygenerowanie dedykowanej pary kluczy wyłącznie pod operacje tego panelu.
- Panel nie wymaga zewnętrznej bazy danych ani kompilacji – cały kod to czysty Python oraz statyczne pliki GUI.
