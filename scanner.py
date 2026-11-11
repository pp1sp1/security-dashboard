"""Silnik skanowania: Trivy i Grype.

Funkcje:
  - wykrywanie zainstalowanych skanerów na celu,
  - automatyczna instalacja: cel POBIERA binarkę SAM przez curl/wget
    (GitHub Releases) – przez pct exec / qm guest exec / ssh / docker exec;
    gdy cel nie ma internetu ani curl/wget – fallback: pobranie na hoście
    panelu i wgranie (lokalnie / SFTP / pct push / docker cp),
  - aktualizacja baz CVE (trivy image --download-db-only, grype db update),
  - skanowanie: filesystem/rootfs, obrazy Docker; dla LXC domyślnie ZEWNĄTRZ
    (rootfs węzła PVE), z fallbackiem na pct exec; dla VM przez QEMU Guest
    Agent (z detekcją ucięcia wyjścia).
"""
from __future__ import annotations

import io
import json
import os
import re
import shlex
import shutil
import tarfile
import tempfile
import time
import uuid

import httpx

import executor
import remediation
import store
from executor import CommandError

GITHUB_API = "https://api.github.com"
SCAN_TIMEOUT = 1200
# Pobieranie ~170 MB na celu (często wolne łącze VM/kontenera) – 15 min zapasu.
INSTALL_TIMEOUT = 900

TRIVY_SKIP_DIRS = ("--skip-dirs /proc --skip-dirs /sys --skip-dirs /dev --skip-dirs /run "
                   "--skip-dirs /var/lib/docker --skip-dirs /var/lib/containerd")
# Uwaga: syft/grype wymaga wzorców GLOB kończących się na '**' – same '/proc'
# są odrzucane błędem "invalid exclusion pattern(s)". Cudzysłowy chronią '**'
# przed rozwinięciem przez powłokę.
GRYPE_EXCLUDES = ("--exclude '/proc/**' --exclude '/sys/**' --exclude '/dev/**' "
                  "--exclude '/run/**' --exclude '/var/lib/docker/**' "
                  "--exclude '/var/lib/containerd/**'")
SCANNER_DIRS = ("/usr/local/bin", "/usr/bin")

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}


# ---------------------------------------------------------------- endpoint skanera

def _scanner_exec_endpoint(target: dict) -> tuple[dict, str | None]:
    """Zwraca (endpoint_do_poleceń_skanera, rootfs_path|None).

    Dla LXC preferowane jest skanowanie z zewnątrz (rootfs na węźle PVE) –
    wtedy skaner działa na węźle i nic nie instalujemy w kontenerze."""
    t = target.get("type", "")
    ep = dict(target.get("endpoint") or {})
    if t in ("lxc", "ssh-lxc"):
        rootfs = executor.lxc_rootfs_path(ep)
        if rootfs:
            return executor.parent_endpoint(ep), rootfs
        return ep, None
    if t in ("docker-container", "docker-image"):
        return {"kind": "local"}, None
    return ep, None


def _sev_sort(v: dict):
    return (_SEV_ORDER.get(v.get("severity"), 9), v.get("id", ""))


# ---------------------------------------------------------------- wykrywanie

def _version_from_output(out: str) -> str | None:
    m = re.search(r"(\d+\.\d+\.\d+)", out or "")
    return m.group(1) if m else None


def scanner_bin(endpoint: dict, name: str) -> str | None:
    """Bezwzględna ścieżka skanera na celu albo None.

    Działa też tam, gdzie PATH w sesji poleceń jest okrojony (QEMU Guest Agent,
    systemd) – sprawdza standardowe lokalizacje oprócz `command -v`.
    """
    probe = (f"command -v {name} 2>/dev/null"
             f" || {{ test -x /usr/local/bin/{name} && echo /usr/local/bin/{name}; }}"
             f" || {{ test -x /usr/bin/{name} && echo /usr/bin/{name}; }}")
    try:
        rc, out, _ = executor.execute(endpoint, probe, timeout=20)
    except CommandError:
        return None
    if rc != 0:
        return None
    lines = [ln.strip() for ln in (out or "").splitlines() if ln.strip()]
    if not lines:
        return None
    bin_path = lines[-1]
    return bin_path if "/" in bin_path else None


def check_scanner(endpoint: dict, name: str) -> str | None:
    bin_path = scanner_bin(endpoint, name)
    if not bin_path:
        return None
    try:
        rc, out, _ = executor.execute(endpoint, f"{shlex.quote(bin_path)} --version",
                                      timeout=30)
    except CommandError:
        return None
    if rc != 0:
        return None
    return _version_from_output(out)


def check_scanners(endpoint: dict) -> dict:
    return {"trivy": check_scanner(endpoint, "trivy"),
            "grype": check_scanner(endpoint, "grype")}


# ---------------------------------------------------------------- instalacja

def _release_latest(name: str, arch: str) -> tuple[str, str]:
    """Najnowsze wydanie z GitHub Releases. Zwraca (wersja, URL_tar.gz).

    To tylko małe zapytanie do API – sam plik ~170 MB pobiera DOPiero cel
    (curl/wget na hoście docelowym), więc panel nie przesyła go przez
    pct push / QEMU Guest Agent / SFTP."""
    repo = {"trivy": "aquasecurity/trivy", "grype": "anchore/grype"}[name]
    r = httpx.get(f"{GITHUB_API}/repos/{repo}/releases/latest", timeout=40,
                  headers={"Accept": "application/vnd.github+json"})
    r.raise_for_status()
    data = r.json()
    version = (data.get("tag_name") or "").lstrip("v")
    if name == "trivy":
        want = "Linux-64bit.tar.gz" if arch in ("amd64", "arm") else "Linux-ARM64.tar.gz"

        def _match(n: str) -> bool:
            return n.startswith("trivy_") and n.endswith(want)
    else:
        want = f"linux_{arch}.tar.gz"

        def _match(n: str) -> bool:
            return n.startswith("grype_") and f"_{want}" in n
    for a in data.get("assets", []):
        if _match(a.get("name", "")):
            return version, a["browser_download_url"]
    names = ", ".join(a.get("name", "") for a in (data.get("assets") or [])[:25])
    raise RuntimeError(f"Nie znaleziono paczki {name} dla architektury '{arch}'. "
                       f"Dostępne: {names}")


def _download_blob(url: str) -> bytes:
    """Fallback: pobiera archiwum do pamięci na HOŚCIE panelu."""
    r = httpx.get(url, timeout=300, follow_redirects=True)
    r.raise_for_status()
    return r.content


def _extract_bin(name: str, blob: bytes) -> bytes:
    """Wyciąga binarkę <name> z archiwum tar.gz (fallback, w pamięci)."""
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
        for member in tf.getmembers():
            if member.isfile() and member.name.split("/")[-1] == name:
                fobj = tf.extractfile(member)
                if fobj:
                    return fobj.read()
    raise RuntimeError(f"Archiwum nie zawiera binarki '{name}'")


def _target_install_cmd(name: str, url: str) -> str:
    """Polecenie `sh -c` instalujące skaner BEZPOŚREDNIO NA CELU.

    Cel sam pobiera statyczną binarkę z GitHub Releases (curl, a gdy brak –
    wget), rozpakowuje i instaluje do /usr/local/bin. Dzięki temu przez
    pct exec / qm guest exec / ssh / docker exec nie przesyłamy setek MB
    i nie ma problemu z plikami 0-bajtowymi po przerwanym pushu.
    Wszystkie błędy (brak curl/wget, brak internetu, uszkodzone archiwum)
    trafiają do stderr, który wraca w komunikacie zadania w GUI."""
    u = shlex.quote(url)
    return (
        "set -e; "
        f"d=$(mktemp -d /tmp/.dash-{name}.XXXXXX) || exit 95; "
        "trap 'rm -rf \"$d\"' EXIT INT TERM; "
        "if command -v curl >/dev/null 2>&1; then "
        "curl -fsSL --connect-timeout 20 -o \"$d/a.tgz\" " + u + "; "
        "elif command -v wget >/dev/null 2>&1; then "
        "wget -qO \"$d/a.tgz\" " + u + "; "
        "else echo 'NO_FETCHER: cel nie ma curl ani wget' >&2; exit 91; fi; "
        "test -s \"$d/a.tgz\" || { echo 'DOWNLOAD_EMPTY: pobrano 0 bajtów' >&2; exit 92; }; "
        "tar -xzf \"$d/a.tgz\" -C \"$d\"; "
        f"b=$(find \"$d\" -type f -name {shlex.quote(name)} | head -n 1); "
        "test -n \"$b\" || { echo 'NO_BIN: w archiwum nie ma binarki' >&2; exit 93; }; "
        "mkdir -p /usr/local/bin; "
        f"cp \"$b\" /usr/local/bin/{name}; "
        f"chmod 0755 /usr/local/bin/{name}; "
        f"test -s /usr/local/bin/{name} || {{ echo 'DST_EMPTY: plik po instalacji pusty' >&2; exit 94; }}; "
        f"/usr/local/bin/{name} --version"
    )


def _deploy_local(tmp_path: str, name: str) -> None:
    dst = f"/usr/local/bin/{name}"
    rc, out, err = executor.run_local(["sh", "-c",
                                       f"install -m 0755 {shlex.quote(tmp_path)} {dst}"], 30)
    if rc == 0:
        return
    rc2, out2, err2 = executor.run_local(["sh", "-c",
                                          f"sudo -n install -m 0755 {shlex.quote(tmp_path)} {dst}"], 30)
    if rc2 != 0:
        raise CommandError(rc2, out2, err2 or err,
                           "Brak uprawnień do zapisu /usr/local/bin – uruchom panel "
                           "jako root lub skonfiguruj sudo bez hasła.")


def _deploy_pct(ep: dict, local_path: str, name: str) -> None:
    """Wgrywa binarkę do kontenera LXC przez `pct push` (węzeł lokalny lub przez SSH).

    Uwaga na współbieżność: ścieżka tymczasowa jest UNIKALNA dla każdego
    zadania (dawniej PID procesu – równoległe instalacje nadpisywały sobie
    plik, co dawało binarki 0-bajtowe w kontenerze)."""
    import ssh_manager
    vmid = ep["vmid"]
    if not os.path.isfile(local_path) or os.path.getsize(local_path) == 0:
        raise CommandError(1, "", "", f"Plik źródłowy {local_path} jest pusty – nie wysyłam")
    node_tmp = f"/tmp/.dash-{name}-{uuid.uuid4().hex[:8]}"
    if ep.get("via") == "ssh":
        host = store.get_ssh_host(ep["ssh_host_id"])
        ssh_manager.upload_file(host, local_path, node_tmp)
    else:
        shutil.copyfile(local_path, node_tmp)
    executor.execute_checked(ep, "mkdir -p /usr/local/bin", 30)
    if ep.get("via") == "ssh":
        rc, out, err = ssh_manager.run(
            store.get_ssh_host(ep["ssh_host_id"]),
            f"pct push {vmid} {shlex.quote(node_tmp)} /usr/local/bin/{name} --perms 0755", 180)
        ssh_manager.run(store.get_ssh_host(ep["ssh_host_id"]),
                        f"rm -f {shlex.quote(node_tmp)}", 15)
    else:
        rc, out, err = executor.run_local(
            ["pct", "push", str(vmid), node_tmp, f"/usr/local/bin/{name}", "--perms", "0755"], 180)
        executor.run_local(["sh", "-c", f"rm -f {shlex.quote(node_tmp)}"], 15)
    if rc != 0:
        raise CommandError(rc, out, err, "pct push nie powiódł się")
    # Niektóre wersje PVE ignorują --perms – wymuś prawa wykonywania i sprawdź,
    # że plik istnieje ORAZ nie jest pusty (push mógł po cichu przegrać 0 bajtów).
    executor.execute_checked(ep, f"chmod 0755 /usr/local/bin/{name} && "
                                 f"test -x /usr/local/bin/{name} && "
                                 f"test -s /usr/local/bin/{name}", 30)


def install_scanner(target: dict, name: str, progress=None) -> str:
    """Instaluje (lub aktualizuje) trivy/grype dla celu. Zwraca wersję.

    Strategia (od v1.2.0):
      1. PREFEROWANA – cel pobiera binarkę SAM przez curl/wget (polecenie idzie
         przez executor: pct exec / qm guest exec / ssh / docker exec).
         Zero przesyłania setek MB przez panel; aktualizuje też starsze wersje.
      2. FALLBACK – gdy cel nie ma curl/wget ani internetu (a da się wgrywać
         pliki: local / ssh / pct / docker), panel pobiera binarkę na hoście
         i wysyła (SFTP / pct push / docker cp).
    """
    if name not in ("trivy", "grype"):
        raise ValueError(f"Nieznany skaner: {name}")

    def say(msg: str):
        store.log(f"[{target.get('id')}] {msg}")
        if progress:
            progress(msg)

    ep, _rootfs = _scanner_exec_endpoint(target)
    kind = ep.get("kind")
    if kind == "api-lxc":
        raise CommandError(1, "", "Instalacja w LXC przez samo API PVE nie jest możliwa – "
                                  "dodaj węzeł przez SSH (zakładka: Dodaj hosta SSH).")
    if kind == "docker-image":
        raise CommandError(1, "", "Obraz Dockera nie ma powłoki – skanowanie obrazu odbywa "
                                  "się na hoście panelu (zainstaluj skaner na hoście).")

    arch = executor.run_arch(ep)
    existing = check_scanner(ep, name)
    say(f"Sprawdzam najnowszą wersję {name} ({arch}) na GitHubie…")
    try:
        version, url = _release_latest(name, arch)
    except Exception as exc:
        if existing:
            say(f"Nie udało się sprawdzić nowszej wersji ({str(exc)[:140]}). "
                f"Na celu zostaje {name} v{existing}")
            return existing
        raise

    if existing == version:
        say(f"{name} v{existing} już zainstalowany (to najnowsza wersja)")
        return existing
    if existing:
        say(f"Na celu jest {name} v{existing} – aktualizuję do v{version}…")

    # ---------- 1) instalacja NA CELU (preferowana) ----------
    say(f"Instaluję {name} {version} na celu (pobieranie curl/wget bezpośrednio "
        f"na hoście docelowym)…")
    try:
        executor.execute_checked(ep, _target_install_cmd(name, url), timeout=INSTALL_TIMEOUT)
        ver = check_scanner(ep, name)
        if ver:
            say(f"Zainstalowano {name} v{ver}")
            return ver
        # binarka wgrana, ale nie działa – lecimy do diagnostyki / fallbacku
        raise CommandError(1, "", "", "binarka wgrana na celu, ale `--version` nie odpowiada")
    except CommandError as exc:
        reason = ((exc.err or "") + " " + (exc.out or "")).strip()[-260:] or str(exc)
        if kind not in ("local", "ssh", "pct", "docker-exec"):
            # VM przez QEMU Guest Agent: nie da się wgrać pliku z zewnątrz.
            raise CommandError(
                exc.rc, exc.out, exc.err,
                f"Instalacja {name} w VM nie powiodła się: {reason} "
                f"| VM wymaga curl lub wget oraz dostępu do internetu; "
                f"alternatywnie dodaj tę maszynę jako host SSH (instalacja przez SFTP).") from None
        say(f"Pobieranie na celu nie powiodło się ({reason[:160]}) – "
            f"pobieram na hoście panelu i wysyłam na cel…")

    # ---------- 2) fallback: pobierz na hoście panelu i wgraj na cel ----------
    blob = _download_blob(url)
    bin_bytes = _extract_bin(name, blob)
    say(f"Pobrano {name} {version} ({max(1, len(bin_bytes) // 1048576)} MB). Wysyłam na cel…")
    fd, tmp = tempfile.mkstemp(prefix=f".dash-{name}-", suffix=".bin")
    with os.fdopen(fd, "wb") as fh:
        fh.write(bin_bytes)
    os.chmod(tmp, 0o755)
    try:
        if kind == "local":
            _deploy_local(tmp, name)
        elif kind == "ssh":
            import ssh_manager
            remote_tmp = f"/tmp/.dash-{name}-{uuid.uuid4().hex[:8]}"
            ssh_manager.upload_file(store.get_ssh_host(ep["ssh_host_id"]), tmp, remote_tmp)
            executor.execute_checked(
                ep, f"install -m 0755 {shlex.quote(remote_tmp)} /usr/local/bin/{name} "
                    f"|| sudo -n install -m 0755 {shlex.quote(remote_tmp)} /usr/local/bin/{name}", 90)
            executor.execute_checked(ep, f"rm -f {shlex.quote(remote_tmp)}", 15)
        elif kind == "pct":
            _deploy_pct(ep, tmp, name)
        elif kind == "docker-exec":
            cid = ep["cid"]
            executor.execute_checked(ep, "mkdir -p /usr/local/bin", 20)
            rc, out, err = executor.run_local(["docker", "cp", tmp,
                                               f"{cid}:/usr/local/bin/{name}"], 90)
            if rc != 0:
                raise CommandError(rc, out, err, "docker cp nie powiódł się "
                                                 "(kontener z READ-ONLY FS?)")
            executor.execute_checked(ep, f"chmod 0755 /usr/local/bin/{name} && "
                                         f"test -s /usr/local/bin/{name}", 20)
        else:
            raise CommandError(1, "", f"Instalacja skanera nieobsługiwana dla endpointu {kind}")
        ver = check_scanner(ep, name)
        if not ver:
            raise RuntimeError(_install_verify_diag(ep, name))
        say(f"Zainstalowano {name} v{ver}")
        return ver
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def _install_verify_diag(endpoint: dict, name: str) -> str:
    """Diagnostyka, gdy binarka została wgrana, ale nie da się jej uruchomić.

    Pokazuje ls -l oraz prawdziwy błąd wykonania (brak pliku / uprawnień /
    brak ładowarki ELF np. musl / zła architektura), zamiast tajemniczego
    „--version nie odpowiada”.
    """
    parts: list[str] = []
    for d in SCANNER_DIRS:
        try:
            rc, out, err = executor.execute(
                endpoint,
                f"ls -l {d}/{name} 2>&1; {d}/{name} --version 2>&1 | head -n 3", 30)
        except CommandError as exc:
            out, err = str(exc), ""
            rc = 1
        txt = ((out or "") + (err or "")).strip()
        if txt:
            parts.append(f"[{d}] {txt[:220]}")
    diag = " | ".join(parts)[:600]
    if re.search(r"\s0 [A-Z][a-z]{2} \d", diag) or "DOWNLOAD_EMPTY" in diag:
        hint = " (plik na celu ma 0 bajtów – przerwane przesyłanie; spróbuj ponownie)"
    elif "not found" in diag:
        hint = (" (kontener Alpine/musl? użyj skanowania rootfs z węzła albo "
                "`apk add trivy`)")
    else:
        hint = ""
    return (f"{name} wgrany, ale `--version` nie odpowiada{hint}. "
            f"Diagnostyka: {diag or 'brak wyjścia'}")


# ---------------------------------------------------------------- bazy CVE

def update_databases(target: dict, engines: list[str]) -> dict:
    """Aktualizuje bazy podatności (trivy DB / grype DB) tam, gdzie działa skaner."""
    ep, _rootfs = _scanner_exec_endpoint(target)
    out: dict = {}
    for name in engines:
        if name not in ("trivy", "grype"):
            continue
        bin_path = scanner_bin(ep, name)
        if not bin_path:
            out[name] = {"ok": False, "msg": "skaner nie jest zainstalowany na celu"}
            continue
        cmd = (f"{shlex.quote(bin_path)} image --download-db-only" if name == "trivy"
               else f"{shlex.quote(bin_path)} db update")
        rc, stdout, err = executor.execute(ep, cmd, 900)
        msg = (stdout or err or "").strip()[-200:] or ("OK" if rc == 0 else f"Kod wyjścia {rc}")
        out[name] = {"ok": rc == 0, "msg": msg}
    return out


# ---------------------------------------------------------------- parsowanie wyników

def _extract_json(text: str) -> dict:
    text = (text or "").strip()
    if not text:
        raise RuntimeError("Skaner nie zwrócił danych "
                           "(możliwe ucięcie wyjścia przez QEMU Guest Agent – "
                           "dodaj tę maszynę przez SSH, aby skanować niezawodnie)")
    idx = text.find("{")
    if idx > 0:
        text = text[idx:]
    return json.loads(text)


def _parse_trivy(text: str) -> list[dict]:
    data = _extract_json(text)
    vulns: list[dict] = []
    for result in data.get("Results") or []:
        for v in result.get("Vulnerabilities") or []:
            vulns.append({
                "id": (v.get("VulnerabilityID") or "").strip(),
                "pkg": (v.get("PkgName") or "").strip(),
                "installed": (v.get("InstalledVersion") or "").strip(),
                "fixed": (v.get("FixedVersion") or "").strip(),
                "severity": (v.get("Severity") or "UNKNOWN").upper(),
                "title": (v.get("Title") or "")[:200],
                "url": (v.get("PrimaryURL") or "").strip(),
                "desc": (v.get("Description") or "")[:280],
            })
    return vulns


_GRYPE_SEV = {"Critical": "CRITICAL", "High": "HIGH", "Medium": "MEDIUM",
              "Low": "LOW", "Negligible": "LOW"}


def _parse_grype(text: str) -> list[dict]:
    data = _extract_json(text)
    vulns: list[dict] = []
    for m in data.get("matches") or []:
        vul = m.get("vulnerability") or {}
        art = m.get("artifact") or {}
        fixes = ((vul.get("fix") or {}).get("versions")) or []
        vid = (vul.get("id") or "").strip()
        sev_raw = vul.get("severity") or "UNKNOWN"
        vulns.append({
            "id": vid,
            "pkg": (art.get("name") or "").strip(),
            "installed": (art.get("version") or "").strip(),
            "fixed": (fixes[0] if fixes else "").strip(),
            "severity": _GRYPE_SEV.get(sev_raw, str(sev_raw).upper()),
            "title": "",
            "url": f"https://nvd.nist.gov/vuln/detail/{vid}" if vid.startswith("CVE") else "",
            "desc": (vul.get("description") or "")[:280],
        })
    return vulns


# ---------------------------------------------------------------- skanowanie

def _run_capture(endpoint: dict, cmd: str, timeout: int) -> tuple[int, str, str]:
    return executor.execute(endpoint, cmd, timeout)


def _scan_trivy(target: dict, ep: dict, rootfs: str | None, skip_db: bool,
                say) -> tuple[list[dict], bool]:
    bin_path = scanner_bin(ep, "trivy")
    if not bin_path:
        raise CommandError(
            127, "", "", "Brak trivy na celu skanowania (jeśli LXC – skanowanie z zewnątrz "
                         "wymaga trivy na węźle PVE; w VM – kliknij „Zainstaluj skaner”)")
    B = shlex.quote(bin_path)
    skip = "--skip-db-update" if skip_db else ""
    t = target.get("type")
    timeout = SCAN_TIMEOUT + 120

    if t in ("docker-container", "docker-image"):
        ref = (target.get("endpoint") or {}).get("image") or ""
        if not ref:
            raise RuntimeError("Brak referencji obrazu Dockera")
        say(f"trivy image {ref}")
        cmd = (f"{B} image {skip} --format json --scanners vuln --quiet "
               f"--timeout {SCAN_TIMEOUT}s {shlex.quote(ref)}")
        rc, out, err = _run_capture(ep, cmd, timeout)
        if rc != 0:
            raise CommandError(rc, out, err, f"trivy image nie powiódł się: {(err or out)[:300]}")
        return _parse_trivy(out), False

    if rootfs:
        say(f"trivy rootfs (z zewnątrz, rootfs węzła): {rootfs}")
        cmd = (f"{B} rootfs {skip} --format json --scanners vuln --quiet "
               f"{TRIVY_SKIP_DIRS} --timeout {SCAN_TIMEOUT}s {shlex.quote(rootfs)}")
        rc, out, err = _run_capture(ep, cmd, timeout)
        if rc != 0:
            raise CommandError(rc, out, err, f"trivy rootfs nie powiódł się: {(err or out)[:300]}")
        return _parse_trivy(out), False

    if t in ("qemu", "ssh-qemu", "api-qemu"):
        # Skan wewnątrz VM: JSON do pliku, odczyt przez agenta + detekcja ucięcia.
        say("trivy rootfs / (wewnątrz VM, przez QEMU Guest Agent)…")
        remote = (f"{B} rootfs {skip} --format json --scanners vuln --quiet "
                  f"{TRIVY_SKIP_DIRS} --timeout {SCAN_TIMEOUT}s / "
                  f"> /tmp/.dash-scan.json 2>/tmp/.dash-scan.err; echo RC=$?; "
                  f"wc -c < /tmp/.dash-scan.json")
        rc, out, err = _run_capture(ep, remote, timeout)
        if rc != 0:
            raise CommandError(rc, out, err,
                               f"Skan w VM nie powiódł się: {(err or out)[:300]} "
                               f"(czy QEMU Guest Agent działa?)")
        m_rc = re.search(r"RC=(\d+)", out or "")
        m_size = re.search(r"(\d+)\s*$", (out or "").strip())
        scan_rc = int(m_rc.group(1)) if m_rc else 1
        size = int(m_size.group(1)) if m_size else 0
        if scan_rc != 0:
            _, errtxt, _ = _run_capture(ep, "cat /tmp/.dash-scan.err 2>/dev/null; "
                                            "rm -f /tmp/.dash-scan.err /tmp/.dash-scan.json", 30)
            raise CommandError(
                scan_rc, out, errtxt,
                f"trivy w VM zwrócił błąd (rc={scan_rc}): {(errtxt or '').strip()[:250] or 'brak stderr'}"
                f" | agent: {(err or '').strip()[:200] or '—'}")
        rc2, payload, _ = _run_capture(ep, "cat /tmp/.dash-scan.json; "
                                           "rm -f /tmp/.dash-scan.json /tmp/.dash-scan.err", 180)
        truncated = size > 0 and len(payload or "") < size * 0.97
        return _parse_trivy(payload), truncated

    # local / ssh / pct-inside
    say("trivy rootfs / …")
    cmd = (f"{B} rootfs {skip} --format json --scanners vuln --quiet "
           f"{TRIVY_SKIP_DIRS} --timeout {SCAN_TIMEOUT}s /")
    rc, out, err = _run_capture(ep, cmd, timeout)
    if rc != 0:
        raise CommandError(rc, out, err, f"trivy rootfs nie powiódł się: {(err or out)[:300]}")
    return _parse_trivy(out), False


def _scan_grype(target: dict, ep: dict, rootfs: str | None, skip_db: bool,
                say) -> tuple[list[dict], bool]:
    bin_path = scanner_bin(ep, "grype")
    if not bin_path:
        raise CommandError(
            127, "", "", "Brak grype na celu skanowania (jeśli LXC – skanowanie z zewnątrz "
                         "wymaga grype na węźle PVE; w VM – kliknij „Zainstaluj skaner”)")
    G = shlex.quote(bin_path)
    env_prefix = "GRYPE_DB_AUTO_UPDATE=false " if skip_db else ""
    t = target.get("type")
    timeout = SCAN_TIMEOUT + 120

    if t in ("docker-container", "docker-image"):
        ref = (target.get("endpoint") or {}).get("image") or ""
        say(f"grype {ref}")
        rc, out, err = _run_capture(ep, f"{env_prefix}{G} -o json {shlex.quote(ref)}", timeout)
        if rc != 0:
            raise CommandError(rc, out, err, f"grype nie powiódł się: {(err or out)[:300]}")
        return _parse_grype(out), False

    if rootfs:
        say(f"grype dir:{rootfs} (z zewnątrz)")
        rc, out, err = _run_capture(ep, f"{env_prefix}{G} -o json {GRYPE_EXCLUDES} "
                                        f"{shlex.quote('dir:' + rootfs)}", timeout)
        if rc != 0:
            raise CommandError(rc, out, err, f"grype nie powiódł się: {(err or out)[:300]}")
        return _parse_grype(out), False

    if t in ("qemu", "ssh-qemu", "api-qemu"):
        say("grype dir:/ (wewnątrz VM, przez QEMU Guest Agent)…")
        remote = (f"{env_prefix}{G} -o json {GRYPE_EXCLUDES} dir:/ "
                  f"> /tmp/.dash-scan.json 2>/tmp/.dash-scan.err; echo RC=$?; "
                  f"wc -c < /tmp/.dash-scan.json")
        rc, out, err = _run_capture(ep, remote, timeout)
        if rc != 0:
            raise CommandError(rc, out, err, f"Skan w VM nie powiódł się: {(err or out)[:300]} "
                                             f"(czy QEMU Guest Agent działa?)")
        m_rc = re.search(r"RC=(\d+)", out or "")
        m_size = re.search(r"(\d+)\s*$", (out or "").strip())
        scan_rc = int(m_rc.group(1)) if m_rc else 1
        size = int(m_size.group(1)) if m_size else 0
        if scan_rc != 0:
            _, errtxt, _ = _run_capture(ep, "cat /tmp/.dash-scan.err 2>/dev/null; "
                                            "rm -f /tmp/.dash-scan.err /tmp/.dash-scan.json", 30)
            raise CommandError(
                scan_rc, out, errtxt,
                f"grype w VM zwrócił błąd (rc={scan_rc}): {(errtxt or '').strip()[:250] or 'brak stderr'}"
                f" | agent: {(err or '').strip()[:200] or '—'}")
        rc2, payload, _ = _run_capture(ep, "cat /tmp/.dash-scan.json; "
                                           "rm -f /tmp/.dash-scan.json /tmp/.dash-scan.err", 180)
        truncated = size > 0 and len(payload or "") < size * 0.97
        return _parse_grype(payload), truncated

    say("grype dir:/ …")
    rc, out, err = _run_capture(ep, f"{env_prefix}{G} -o json {GRYPE_EXCLUDES} dir:/", timeout)
    if rc != 0:
        raise CommandError(rc, out, err, f"grype nie powiódł się: {(err or out)[:300]}")
    return _parse_grype(out), False


def scan_target(target: dict, engines: list[str], skip_db_update: bool,
                progress=None) -> dict:
    """Wykonuje skan celu zadanymi silnikami i zwraca znormalizowany wynik."""

    def say(msg: str):
        store.log(f"[{target.get('id')}] {msg}")
        if progress:
            progress(msg)

    ep, rootfs = _scanner_exec_endpoint(target)
    merged: dict = {}
    engines_used: list[str] = []
    truncated = False

    for engine in engines:
        say(f"Skanuję silnikiem {engine}…")
        if engine == "trivy":
            vulns, tr_trunc = _scan_trivy(target, ep, rootfs, skip_db_update, say)
        elif engine == "grype":
            vulns, tr_trunc = _scan_grype(target, ep, rootfs, skip_db_update, say)
        else:
            raise ValueError(f"Nieznany silnik: {engine}")
        engines_used.append(engine)
        truncated = truncated or tr_trunc
        for v in vulns:
            key = (v["id"], v["pkg"], v["installed"])
            cur = merged.get(key)
            if cur is None:
                merged[key] = v
            else:
                if not cur.get("fixed") and v.get("fixed"):
                    cur["fixed"] = v["fixed"]
                if not cur.get("url") and v.get("url"):
                    cur["url"] = v["url"]
                if not cur.get("title") and v.get("title"):
                    cur["title"] = v["title"]

    vulns = sorted(merged.values(), key=_sev_sort)
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for v in vulns:
        summary[v.get("severity") or "UNKNOWN"] = summary.get(v.get("severity") or "UNKNOWN", 0) + 1
    fixable = len(remediation.fixable_packages(vulns))

    os_info: dict = {}
    try:
        if target.get("type") in ("local", "ssh", "lxc", "ssh-lxc", "qemu",
                                  "ssh-qemu", "api-qemu", "docker-container"):
            os_info = executor.run_os_release(target["endpoint"])
    except Exception:
        os_info = {}

    return {
        "time": time.time(),
        "engines": engines_used,
        "vulns": vulns,
        "summary": summary,
        "fixable": fixable,
        "truncated": truncated,
        "scanners": check_scanners(ep),
        "os": {k: os_info.get(k) for k in ("NAME", "ID", "VERSION_ID", "PRETTY_NAME")
               if os_info.get(k)},
    }
