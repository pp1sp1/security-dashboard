"""Silnik skanowania: Trivy i Grype.

Funkcje:
  - wykrywanie zainstalowanych skanerów na celu,
  - automatyczna instalacja (pobranie statycznej binarki z GitHub Releases
    i wgranie: lokalnie / SFTP / pct push / skrypt w VM / docker cp),
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

import httpx

import executor
import remediation
import store
from executor import CommandError

GITHUB_API = "https://api.github.com"
INSTALL_SCRIPTS = {
    "trivy": "https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh",
    "grype": "https://raw.githubusercontent.com/anchore/grype/main/install.sh",
}
SCAN_TIMEOUT = 1200
INSTALL_TIMEOUT = 420

TRIVY_SKIP_DIRS = ("--skip-dirs /proc --skip-dirs /sys --skip-dirs /dev --skip-dirs /run "
                   "--skip-dirs /var/lib/docker --skip-dirs /var/lib/containerd")
GRYPE_EXCLUDES = ("--exclude /proc --exclude /sys --exclude /dev --exclude /run "
                  "--exclude /var/lib/docker --exclude /var/lib/containerd")

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


def check_scanner(endpoint: dict, name: str) -> str | None:
    try:
        rc, out, _ = executor.execute(endpoint, f"{name} --version", timeout=30)
    except CommandError:
        return None
    if rc != 0:
        return None
    return _version_from_output(out)


def check_scanners(endpoint: dict) -> dict:
    return {"trivy": check_scanner(endpoint, "trivy"),
            "grype": check_scanner(endpoint, "grype")}


# ---------------------------------------------------------------- instalacja

def _download_release(name: str, arch: str) -> tuple[str, bytes]:
    """Pobiera najnowszą statyczną binarkę z GitHub Releases. Zwraca (wersja, bajty)."""
    repo = {"trivy": "aquasecurity/trivy", "grype": "anchore/grype"}[name]
    r = httpx.get(f"{GITHUB_API}/repos/{repo}/releases/latest", timeout=40,
                  headers={"Accept": "application/vnd.github+json"})
    r.raise_for_status()
    data = r.json()
    version = (data.get("tag_name") or "").lstrip("v")
    asset = None
    if name == "trivy":
        want = "Linux-64bit.tar.gz" if arch in ("amd64", "arm") else "Linux-ARM64.tar.gz"
        for a in data.get("assets", []):
            if a.get("name", "").startswith("trivy_") and a["name"].endswith(want):
                asset = a
                break
    else:
        want = f"linux_{arch}.tar.gz"
        for a in data.get("assets", []):
            if a.get("name", "").startswith("grype_") and f"_{want}" in a["name"]:
                asset = a
                break
    if not asset:
        names = ", ".join(a.get("name", "") for a in (data.get("assets") or [])[:25])
        raise RuntimeError(f"Nie znaleziono paczki {name} dla architektury '{arch}'. "
                           f"Dostępne: {names}")
    tar_r = httpx.get(asset["browser_download_url"], timeout=300, follow_redirects=True)
    tar_r.raise_for_status()
    bio = io.BytesIO(tar_r.content)
    with tarfile.open(fileobj=bio, mode="r:gz") as tf:
        for member in tf.getmembers():
            if member.isfile() and member.name.split("/")[-1] == name:
                fobj = tf.extractfile(member)
                if fobj:
                    return version, fobj.read()
    raise RuntimeError(f"Archiwum {asset.get('name')} nie zawiera binarki '{name}'")


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
    """Wgrywa binarkę do kontenera LXC przez `pct push` (węzeł lokalny lub przez SSH)."""
    import ssh_manager
    vmid = ep["vmid"]
    node_tmp = f"/tmp/.dash-{name}-{os.getpid()}"
    if ep.get("via") == "ssh":
        host = store.get_ssh_host(ep["ssh_host_id"])
        ssh_manager.upload_file(host, local_path, node_tmp)
    else:
        shutil.copyfile(local_path, node_tmp)
    executor.execute_checked(ep, "mkdir -p /usr/local/bin", 30)
    if ep.get("via") == "ssh":
        rc, out, err = ssh_manager.run(
            store.get_ssh_host(ep["ssh_host_id"]),
            f"pct push {vmid} {shlex.quote(node_tmp)} /usr/local/bin/{name} --perms 0755", 90)
        ssh_manager.run(store.get_ssh_host(ep["ssh_host_id"]),
                        f"rm -f {shlex.quote(node_tmp)}", 15)
    else:
        rc, out, err = executor.run_local(
            ["pct", "push", str(vmid), node_tmp, f"/usr/local/bin/{name}", "--perms", "0755"], 90)
        executor.run_local(["sh", "-c", f"rm -f {shlex.quote(node_tmp)}"], 15)
    if rc != 0:
        raise CommandError(rc, out, err, "pct push nie powiódł się")


def install_scanner(target: dict, name: str, progress=None) -> str:
    """Instaluje trivy/grype dla celu. Zwraca zainstalowaną wersję."""
    if name not in ("trivy", "grype"):
        raise ValueError(f"Nieznany skaner: {name}")

    def say(msg: str):
        store.log(f"[{target.get('id')}] {msg}")
        if progress:
            progress(msg)

    ep, _rootfs = _scanner_exec_endpoint(target)
    existing = check_scanner(ep, name)
    if existing:
        say(f"{name} już jest zainstalowany (v{existing})")
        return existing

    arch = executor.run_arch(ep)
    say(f"Pobieram {name} dla architektury {arch} (GitHub Releases)…")
    version, blob = _download_release(name, arch)
    say(f"Pobrano {name} {version} ({max(1, len(blob) // 1048576)} MB). Wysyłam na cel…")

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=f"-{name}")
    tmp.write(blob)
    tmp.close()

    kind = ep.get("kind")
    try:
        if kind == "local":
            _deploy_local(tmp.name, name)
        elif kind == "ssh":
            import ssh_manager
            remote_tmp = f"/tmp/.dash-{name}-{os.getpid()}"
            ssh_manager.upload_file(store.get_ssh_host(ep["ssh_host_id"]), tmp.name, remote_tmp)
            executor.execute_checked(
                ep, f"install -m 0755 {shlex.quote(remote_tmp)} /usr/local/bin/{name} "
                    f"|| sudo -n install -m 0755 {shlex.quote(remote_tmp)} /usr/local/bin/{name}", 90)
            executor.execute_checked(ep, f"rm -f {shlex.quote(remote_tmp)}", 15)
        elif kind == "pct":
            _deploy_pct(ep, tmp.name, name)
        elif kind in ("qm", "api-qm"):
            # Do VM nie wgramo pliku przez QGA – użyj oficjalnego skryptu wewnątrz VM
            # (wymagany curl/wget oraz dostęp do internetu w VM).
            say("Instaluję wewnątrz VM (skrypt oficjalny; wymagany curl/wget)…")
            script = INSTALL_SCRIPTS[name]
            cmd = (f"(curl -sfL {script} | sh -s -- -b /usr/local/bin) || "
                   f"(wget -qO- {script} | sh -s -- -b /usr/local/bin)")
            executor.execute_checked(ep, cmd, timeout=INSTALL_TIMEOUT)
        elif kind == "docker-exec":
            cid = ep["cid"]
            executor.execute_checked(ep, "mkdir -p /usr/local/bin", 20)
            rc, out, err = executor.run_local(["docker", "cp", tmp.name,
                                               f"{cid}:/usr/local/bin/{name}"], 90)
            if rc != 0:
                raise CommandError(rc, out, err, "docker cp nie powiódł się "
                                                 "(kontener z READ-ONLY FS?)")
            executor.execute_checked(ep, f"chmod 0755 /usr/local/bin/{name}", 20)
        else:
            raise CommandError(1, "", f"Instalacja skanera nieobsługiwana dla endpointu {kind}")
        ver = check_scanner(ep, name)
        if not ver:
            raise RuntimeError(f"{name} wgrany, ale `--version` nie odpowiada")
        say(f"Zainstalowano {name} v{ver}")
        return ver
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


# ---------------------------------------------------------------- bazy CVE

def update_databases(target: dict, engines: list[str]) -> dict:
    """Aktualizuje bazy podatności (trivy DB / grype DB) tam, gdzie działa skaner."""
    ep, _rootfs = _scanner_exec_endpoint(target)
    out: dict = {}
    for name in engines:
        if name not in ("trivy", "grype"):
            continue
        cmd = "trivy image --download-db-only" if name == "trivy" else "grype db update"
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
    skip = "--skip-db-update" if skip_db else ""
    t = target.get("type")
    timeout = SCAN_TIMEOUT + 120

    if t in ("docker-container", "docker-image"):
        ref = (target.get("endpoint") or {}).get("image") or ""
        if not ref:
            raise RuntimeError("Brak referencji obrazu Dockera")
        say(f"trivy image {ref}")
        cmd = (f"trivy image {skip} --format json --scanners vuln --quiet "
               f"--timeout {SCAN_TIMEOUT}s {shlex.quote(ref)}")
        rc, out, err = _run_capture(ep, cmd, timeout)
        if rc != 0:
            raise CommandError(rc, out, err, f"trivy image nie powiódł się: {(err or out)[:300]}")
        return _parse_trivy(out), False

    if rootfs:
        say(f"trivy rootfs (z zewnątrz, rootfs węzła): {rootfs}")
        cmd = (f"trivy rootfs {skip} --format json --scanners vuln --quiet "
               f"{TRIVY_SKIP_DIRS} --timeout {SCAN_TIMEOUT}s {shlex.quote(rootfs)}")
        rc, out, err = _run_capture(ep, cmd, timeout)
        if rc != 0:
            raise CommandError(rc, out, err, f"trivy rootfs nie powiódł się: {(err or out)[:300]}")
        return _parse_trivy(out), False

    if t in ("qemu", "ssh-qemu", "api-qemu"):
        # Skan wewnątrz VM: JSON do pliku, odczyt przez agenta + detekcja ucięcia.
        say("trivy rootfs / (wewnątrz VM, przez QEMU Guest Agent)…")
        remote = (f"trivy rootfs {skip} --format json --scanners vuln --quiet "
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
            raise CommandError(scan_rc, out, errtxt, f"trivy w VM zwrócił błąd: {errtxt[:300]}")
        rc2, payload, _ = _run_capture(ep, "cat /tmp/.dash-scan.json; "
                                           "rm -f /tmp/.dash-scan.json /tmp/.dash-scan.err", 180)
        truncated = size > 0 and len(payload or "") < size * 0.97
        return _parse_trivy(payload), truncated

    # local / ssh / pct-inside
    say("trivy rootfs / …")
    cmd = (f"trivy rootfs {skip} --format json --scanners vuln --quiet "
           f"{TRIVY_SKIP_DIRS} --timeout {SCAN_TIMEOUT}s /")
    rc, out, err = _run_capture(ep, cmd, timeout)
    if rc != 0:
        raise CommandError(rc, out, err, f"trivy rootfs nie powiódł się: {(err or out)[:300]}")
    return _parse_trivy(out), False


def _scan_grype(target: dict, ep: dict, rootfs: str | None, skip_db: bool,
                say) -> tuple[list[dict], bool]:
    env_prefix = "GRYPE_DB_AUTO_UPDATE=false " if skip_db else ""
    t = target.get("type")
    timeout = SCAN_TIMEOUT + 120

    if t in ("docker-container", "docker-image"):
        ref = (target.get("endpoint") or {}).get("image") or ""
        say(f"grype {ref}")
        rc, out, err = _run_capture(ep, f"{env_prefix}grype -o json {shlex.quote(ref)}", timeout)
        if rc != 0:
            raise CommandError(rc, out, err, f"grype nie powiódł się: {(err or out)[:300]}")
        return _parse_grype(out), False

    if rootfs:
        say(f"grype dir:{rootfs} (z zewnątrz)")
        rc, out, err = _run_capture(ep, f"{env_prefix}grype -o json "
                                        f"{shlex.quote('dir:' + rootfs)}", timeout)
        if rc != 0:
            raise CommandError(rc, out, err, f"grype nie powiódł się: {(err or out)[:300]}")
        return _parse_grype(out), False

    if t in ("qemu", "ssh-qemu", "api-qemu"):
        say("grype dir:/ (wewnątrz VM, przez QEMU Guest Agent)…")
        remote = (f"{env_prefix}grype -o json {GRYPE_EXCLUDES} dir:/ "
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
            raise CommandError(scan_rc, out, errtxt, f"grype w VM zwrócił błąd: {errtxt[:300]}")
        rc2, payload, _ = _run_capture(ep, "cat /tmp/.dash-scan.json; "
                                           "rm -f /tmp/.dash-scan.json /tmp/.dash-scan.err", 180)
        truncated = size > 0 and len(payload or "") < size * 0.97
        return _parse_grype(payload), truncated

    say("grype dir:/ …")
    rc, out, err = _run_capture(ep, f"{env_prefix}grype -o json {GRYPE_EXCLUDES} dir:/", timeout)
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
