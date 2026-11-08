"""Abstrakcja wykonywania poleceń na różnych typach celów.

Endpointy (dict):
  {"kind": "local"}                                         – panel / węzeł Proxmox (subprocess)
  {"kind": "ssh", "ssh_host_id": "..."}                     – zdalny host przez SSH (paramiko)
  {"kind": "pct", "via": "local|ssh", "vmid": N, ...}       – kontener LXC przez pct exec
  {"kind": "qm",  "via": "local|ssh", "vmid": N, ...}       – VM przez QEMU Guest Agent (qm guest exec)
  {"kind": "api-qm", "node": "...", "vmid": N}              – VM przez Proxmox API (agent/exec)
  {"kind": "docker-exec", "cid": "...", "image": "..."}     – kontener Docker przez docker exec
  {"kind": "docker-image", "image": "..."}                  – obraz Docker (skanowanie na hoście lokalnym)

Każda funkcja zwraca krotkę (rc, stdout, stderr).
"""
from __future__ import annotations

import json
import os
import shlex
import subprocess

import ssh_manager
import store


class CommandError(Exception):
    """Błąd wykonania polecenia z pełnym kontekstem."""

    def __init__(self, rc: int, out: str, err: str, msg: str | None = None):
        self.rc = rc
        self.out = out or ""
        self.err = err or ""
        super().__init__(msg or f"Polecenie zwróciło kod {rc}: {(self.err or self.out)[:300]}")


def run_local(cmd: list[str], timeout: int = 60, env: dict | None = None) -> tuple[int, str, str]:
    """Uruchamia polecenie lokalnie (lista argumentów, bez shella)."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              encoding="utf-8", errors="replace",
                              env={**os.environ, **(env or {})})
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired:
        return 124, "", f"Przekroczono limit czasu ({timeout}s)"
    except FileNotFoundError:
        return 127, "", f"Nie znaleziono polecenia: {cmd[0] if cmd else '?'}"


def _ssh_host(endpoint: dict) -> dict:
    host = store.get_ssh_host(endpoint["ssh_host_id"])
    if not host:
        raise CommandError(1, "", f"Host SSH '{endpoint.get('ssh_host_id')}' nie istnieje (usunięty?)")
    return host


def _qm_parse(out: str, err: str, cli_rc: int) -> tuple[int, str, str]:
    """Parsuje wyjście `qm guest exec`.

    Format (potwierdzony w dokumentacji/forach PVE):
      {"err-data": "...", "exitcode": 0, "exited": 1, "out-data": "..."}
    (starsze wersje mogą używać "exit-code")."""
    data = None
    txt = (out or "").strip()
    if txt.startswith("{"):
        try:
            data = json.loads(txt)
        except json.JSONDecodeError:
            data = None
    if not isinstance(data, dict):
        if cli_rc == 0:
            return 0, out, err
        return cli_rc, out, err or "qm guest exec: nieoczekiwane wyjście"
    if isinstance(data.get("error"), dict):
        return 1, "", str(data["error"].get("desc") or data["error"])
    if data.get("exited") not in (None, 1):
        return 1, str(data.get("out-data", "") or ""), "Polecenie w VM nie zakończyło się"
    exit_code = data.get("exitcode", data.get("exit-code", 0))
    try:
        exit_code = int(exit_code or 0)
    except (TypeError, ValueError):
        exit_code = 0
    return (exit_code,
            str(data.get("out-data", data.get("out_data", "")) or ""),
            str(data.get("err-data", data.get("err_data", "")) or ""))


def execute(endpoint: dict, cmd: str, timeout: int = 600,
            env: dict | None = None) -> tuple[int, str, str]:
    """Wykonuje `cmd` (polecenie powłoki sh) na celu opisanym przez endpoint."""
    kind = endpoint.get("kind")

    if kind == "local":
        return run_local(["sh", "-c", cmd], timeout, env)

    if kind == "ssh":
        return ssh_manager.run(_ssh_host(endpoint), cmd, timeout, env)

    if kind == "pct":
        vmid = endpoint["vmid"]
        if endpoint.get("via") == "ssh":
            host = _ssh_host(endpoint)
            return ssh_manager.run(host, f"pct exec {vmid} -- sh -c {shlex.quote(cmd)}", timeout)
        return run_local(["pct", "exec", str(vmid), "--", "sh", "-c", cmd], timeout, env)

    if kind == "qm":
        vmid = endpoint["vmid"]
        qtimeout = max(timeout, 60)
        if endpoint.get("via") == "ssh":
            host = _ssh_host(endpoint)
            wrapped = f"qm guest exec {vmid} --timeout {qtimeout} -- sh -c {shlex.quote(cmd)}"
            cli_rc, out, err = ssh_manager.run(host, wrapped, timeout + 90)
        else:
            cli_rc, out, err = run_local(
                ["qm", "guest", "exec", str(vmid), "--timeout", str(qtimeout),
                 "--", "sh", "-c", cmd], timeout + 90, env)
        return _qm_parse(out, err, cli_rc)

    if kind == "api-qm":
        import proxmox  # import późny – unikamy cyklicznych zależności
        client = proxmox.client_from_settings()
        return client.agent_exec(endpoint["node"], endpoint["vmid"], ["sh", "-c", cmd],
                                 timeout=timeout)

    if kind == "docker-exec":
        return run_local(["docker", "exec", endpoint["cid"], "sh", "-c", cmd], timeout, env)

    if kind == "docker-image":
        # obraz Docker nie ma powłoki do wykonywania poleceń
        raise CommandError(1, "", "Obraz Docker nie wykonuje poleceń (skanowanie następuje na hoście)")

    if kind == "api-lxc":
        raise CommandError(1, "", "Skanowanie LXC przez samo API PVE nie jest możliwe – "
                                  "dodaj węzeł Proxmox przez SSH (zakładka: Dodaj hosta SSH).")

    raise CommandError(1, "", f"Nieobsługiwany typ endpointu: {kind}")


def execute_checked(endpoint: dict, cmd: str, timeout: int = 600,
                    env: dict | None = None) -> tuple[int, str, str]:
    rc, out, err = execute(endpoint, cmd, timeout, env)
    if rc != 0:
        raise CommandError(rc, out, err)
    return rc, out, err


# ---------- pomocnicze odczyty z celu ----------

def run_os_release(endpoint: dict) -> dict:
    """Zwraca sparsowane /etc/os-release celu (dict, może być pusty)."""
    try:
        rc, out, _ = execute(endpoint, "cat /etc/os-release 2>/dev/null || true", timeout=25)
        if rc != 0:
            return {}
        info: dict = {}
        for line in (out or "").splitlines():
            line = line.strip()
            if line and "=" in line and not line.startswith("#"):
                key, _, val = line.partition("=")
                info[key.strip()] = val.strip().strip('"')
        return info
    except CommandError:
        return {}


def run_arch(endpoint: dict) -> str:
    """Architektura CPU celu: amd64 | arm64 | inna."""
    try:
        rc, out, _ = execute(endpoint, "uname -m", timeout=20)
        if rc != 0:
            return "amd64"
    except CommandError:
        return "amd64"
    m = (out or "").strip()
    return {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64",
            "arm64": "arm64", "armv7l": "arm", "armv6l": "arm"}.get(m, m or "amd64")


def parent_endpoint(endpoint: dict) -> dict:
    """Endpoint węzła nadrzędnego (dla pct/qm): lokalny host lub host SSH."""
    if endpoint.get("via") == "ssh":
        return {"kind": "ssh", "ssh_host_id": endpoint["ssh_host_id"]}
    return {"kind": "local"}


def lxc_rootfs_path(endpoint: dict) -> str | None:
    """Ścieżka rootfs działającego kontenera LXC na węźle PVE (jeśli dostępna).

    Umożliwia skanowanie kontenera ZEWNĄTRZ (trivy rootfs) bez instalowania
    czegokolwiek w kontenerze – zgodnie ze specyfikacją.
    """
    if endpoint.get("kind") != "pct":
        return None
    vmid = endpoint["vmid"]
    path = f"/var/lib/lxc/{vmid}/rootfs"
    try:
        if endpoint.get("via") == "ssh":
            rc, _, _ = ssh_manager.run(_ssh_host(endpoint),
                                       f"test -f {path}/etc/os-release && test -s {path}/etc/os-release", 15)
        else:
            rc, _, _ = run_local(["sh", "-c",
                                  f"test -f {path}/etc/os-release && test -s {path}/etc/os-release"], 15)
        return path if rc == 0 else None
    except CommandError:
        return None
