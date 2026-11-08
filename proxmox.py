"""Integracja z Proxmox VE.

Zawiera:
  - wykrywanie lokalnego węzła PVE (/etc/pve),
  - listowanie LXC (`pct list`) i VM (`qm list`) lokalnie oraz przez SSH,
  - klient REST Proxmox API (token lub login/hasło) do zdalnych węzłów,
  - guest exec przez API (dla VM z QEMU Guest Agent).
"""
from __future__ import annotations

import json
import os
import subprocess

import httpx

import store

PVE_DIR = "/etc/pve"


def is_pve_node() -> bool:
    return os.path.isdir(PVE_DIR)


def _cli(cmd: list[str], timeout: int = 30) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              encoding="utf-8", errors="replace")
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except FileNotFoundError:
        return 127, "", f"Nie znaleziono polecenia: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", "Przekroczono limit czasu"


def _parse_table(out: str) -> list[dict]:
    """Parsuje tabelę tekstową pct list / qm list (nagłówek + wiersze)."""
    rows: list[dict] = []
    lines = [ln for ln in (out or "").splitlines() if ln.strip()]
    if len(lines) < 2:
        return rows
    header = [h.lower() for h in lines[0].split()]
    for line in lines[1:]:
        parts = line.split(None, len(header) - 1)
        if len(parts) < len(header):
            parts += [""] * (len(header) - len(parts))
        rows.append(dict(zip(header, parts)))
    return rows


def _rows_to_lxc(out: str) -> list[dict]:
    result = []
    for r in _parse_table(out):
        try:
            vmid = int(r.get("vmid", "0"))
        except ValueError:
            continue
        if not vmid:
            continue
        name = r.get("name") or f"LXC {vmid}"
        result.append({"vmid": vmid, "name": name,
                       "status": (r.get("status") or "unknown").lower()})
    return result


def _rows_to_qemu(out: str) -> list[dict]:
    result = []
    for r in _parse_table(out):
        try:
            vmid = int(r.get("vmid", "0"))
        except ValueError:
            continue
        if not vmid:
            continue
        name = r.get("name") or f"VM {vmid}"
        result.append({"vmid": vmid, "name": name,
                       "status": (r.get("status") or "unknown").lower()})
    return result


# ---------- lokalny węzeł ----------

def list_lxc_local() -> list[dict]:
    rc, out, err = _cli(["pct", "list"])
    if rc != 0:
        raise RuntimeError(f"pct list nie powiódł się: {(err or out).strip()[:200]}")
    return _rows_to_lxc(out)


def list_qemu_local() -> list[dict]:
    rc, out, err = _cli(["qm", "list"])
    if rc != 0:
        raise RuntimeError(f"qm list nie powiódł się: {(err or out).strip()[:200]}")
    return _rows_to_qemu(out)


def guest_ping_local(vmid: int) -> bool:
    rc, _, _ = _cli(["qm", "guest", "ping", str(vmid)], 25)
    return rc == 0


# ---------- przez SSH (zdalny węzeł PVE) ----------

def list_lxc_via_ssh(host: dict) -> list[dict]:
    import ssh_manager
    rc, out, err = ssh_manager.run(host, "pct list", 30)
    if rc != 0:
        raise RuntimeError(f"pct list przez SSH: {(err or out).strip()[:200]}")
    return _rows_to_lxc(out)


def list_qemu_via_ssh(host: dict) -> list[dict]:
    import ssh_manager
    rc, out, err = ssh_manager.run(host, "qm list", 30)
    if rc != 0:
        raise RuntimeError(f"qm list przez SSH: {(err or out).strip()[:200]}")
    return _rows_to_qemu(out)


# ---------- klient REST API ----------

class ProxmoxClient:
    """Klient Proxmox VE API.

    Autoryzacja: API Token (PVEAPIToken=...) albo login+hasło (bilet PVEAuthCookie).
    """

    def __init__(self, url: str, token: str = "", user: str = "", password: str = "",
                 verify_ssl: bool = False, timeout: int = 25):
        base = (url or "").strip().rstrip("/")
        if "/api2" in base:
            base = base.split("/api2")[0]
        if not base:
            raise RuntimeError("Brak adresu Proxmox API")
        self.base = base + "/api2/json"
        self.token = (token or "").strip()
        self.user = user or "root@pam"
        self.password = password or ""
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self._ticket: str | None = None
        self._csrf: str | None = None

    def _headers(self) -> dict:
        if self.token:
            return {"Authorization": f"PVEAPIToken={self.token}"}
        if self._ticket:
            return {"Cookie": f"PVEAuthCookie={self._ticket}",
                    "CSRFPreventionToken": self._csrf or ""}
        return {}

    def _login(self) -> None:
        r = httpx.post(f"{self.base}/access/ticket",
                       data={"username": self.user, "password": self.password},
                       verify=self.verify_ssl, timeout=self.timeout)
        r.raise_for_status()
        data = r.json().get("data") or {}
        self._ticket = data.get("ticket")
        self._csrf = data.get("CSRFPreventionToken")
        if not self._ticket:
            raise RuntimeError("Logowanie do Proxmox API nie powiodło się")

    def request(self, method: str, path: str, data: dict | None = None) -> dict:
        if not self.token and not self._ticket:
            self._login()
        url = f"{self.base}{path}"
        for attempt in (0, 1):
            try:
                r = httpx.request(method, url, headers=self._headers(), data=data,
                                  verify=self.verify_ssl, timeout=self.timeout)
            except httpx.HTTPError as exc:
                raise RuntimeError(f"Błąd połączenia z Proxmox API ({url}): {exc}")
            if r.status_code == 401 and attempt == 0 and not self.token:
                self._login()
                continue
            if r.status_code >= 400:
                raise RuntimeError(f"Proxmox API {method} {path} -> HTTP {r.status_code}: "
                                   f"{r.text[:200]}")
            return (r.json() or {}).get("data") or {}
        raise RuntimeError("Nie udało się uwierzytelnić w Proxmox API")

    def nodes(self) -> list[dict]:
        data = self.request("GET", "/nodes")
        return data if isinstance(data, list) else []

    def qemu_list(self, node: str) -> list[dict]:
        return self.request("GET", f"/nodes/{node}/qemu") or []

    def lxc_list(self, node: str) -> list[dict]:
        return self.request("GET", f"/nodes/{node}/lxc") or []

    def agent_exec(self, node: str, vmid: int, command: list[str],
                   timeout: int = 120) -> tuple[int, str, str]:
        """Wykonuje polecenie w VM przez QEMU Guest Agent (endpoint API agent/exec)."""
        data = self.request("POST", f"/nodes/{node}/qemu/{vmid}/agent/exec",
                            data={"command": json.dumps(command),
                                  "timeout": str(max(timeout, 60))})
        res = data.get("result") if isinstance(data, dict) else None
        if isinstance(res, dict):
            exit_code = res.get("exitcode", res.get("exit-code", 0))
            try:
                exit_code = int(exit_code or 0)
            except (TypeError, ValueError):
                exit_code = 0
            return (exit_code,
                    str(res.get("out-data", "") or ""),
                    str(res.get("err-data", "") or ""))
        if isinstance(data, dict) and data.get("error"):
            return 1, "", str(data["error"])
        return 0, (json.dumps(data, ensure_ascii=False) if data else ""), ""


def client_from_settings() -> ProxmoxClient:
    cfg = store.get_settings().get("proxmox_api") or {}
    if not cfg.get("enabled") or not cfg.get("url"):
        raise RuntimeError("Proxmox API nie jest skonfigurowane (Ustawienia -> Proxmox API)")
    return ProxmoxClient(cfg["url"], token=cfg.get("token") or "",
                         user=cfg.get("user") or "root@pam",
                         password=cfg.get("password") or "",
                         verify_ssl=bool(cfg.get("verify_ssl")))
