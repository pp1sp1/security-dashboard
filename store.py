"""Prosta, bezobsługowa persystencja stanu panelu.

Stan trzymamy w jednym pliku JSON (data/state.json, uprawnienia 0600).
Wszystkie operacje są odporne na awarie: zapis atomowy (tmp + rename),
automatyczne scalanie brakujących kluczy ustawień po aktualizacji kodu.
"""
from __future__ import annotations

import copy
import json
import os
import threading
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("DASH_DATA_DIR", str(BASE_DIR / "data")))
STATE_FILE = DATA_DIR / "state.json"

_lock = threading.RLock()

DEFAULT_SETTINGS: dict = {
    "scan_engine": "trivy",              # trivy | grype | both
    "update_db_before_scan": True,       # aktualizuj bazę CVE przed skanem
    "auto_install_scanner": True,        # automatycznie doinstaluj skaner przy skanie
    "scan_docker_all_images": False,     # skanuj też obrazy bez uruchomionych kontenerów
    "scan_interval_hours": 0,            # 0 = harmonogram wyłączony
    "min_notify_severity": "HIGH",       # powiadamiaj od tego poziomu w górę (HIGH | CRITICAL)
    "ntfy": {"enabled": False, "url": "", "token": ""},
    "gotify": {"enabled": False, "url": "", "token": ""},
    "homeassistant": {"enabled": False, "url": "", "token": "",
                      "sensor": "sensor.security_dashboard", "notify_service": ""},
    "discord": {"enabled": False, "webhook_url": ""},
    "telegram": {"enabled": False, "bot_token": "", "chat_id": ""},
    "proxmox_api": {"enabled": False, "url": "", "token": "",
                    "user": "root@pam", "password": "", "verify_ssl": False},
}

_state: dict = {
    "settings": copy.deepcopy(DEFAULT_SETTINGS),
    "ssh_hosts": [],       # [{id,name,host,port,username,auth_type,password,private_key,key_password,pve,created}]
    "targets": [],         # generowane przez discovery w main.py
    "results": {},         # target_id -> wynik ostatniego skanu
    "notify_cache": {},    # target_id -> {cve: ts} – dedupe powiadomień (24h)
    "logs": [],            # [{ts, level, msg}]
    "sched_last_run": 0,
}


def _merge_defaults(dst: dict, defaults: dict) -> None:
    """Dodaje brakujące klucze (rekurencyjnie) z domyślnych ustawień."""
    for key, val in defaults.items():
        if key not in dst:
            dst[key] = copy.deepcopy(val)
        elif isinstance(val, dict) and isinstance(dst[key], dict):
            _merge_defaults(dst[key], val)


def load() -> None:
    with _lock:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        if STATE_FILE.exists():
            try:
                data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
                _state.update({k: v for k, v in data.items() if k in _state})
            except Exception as exc:
                try:
                    STATE_FILE.rename(STATE_FILE.with_suffix(".corrupt"))
                except Exception:
                    pass
                _state["logs"].append({"ts": time.time(), "level": "error",
                                       "msg": f"Nie udało się wczytać state.json: {exc}"})
        _merge_defaults(_state["settings"], DEFAULT_SETTINGS)


def save() -> None:
    """Atomowy zapis całego stanu (plik + chmod 0600)."""
    with _lock:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        tmp = STATE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(_state, ensure_ascii=False, indent=1), encoding="utf-8")
        os.chmod(tmp, 0o600)
        tmp.replace(STATE_FILE)


def get_state() -> dict:
    return _state


def get_settings() -> dict:
    return _state["settings"]


def update_settings(patch: dict) -> dict:
    with _lock:
        _merge_settings(_state["settings"], patch)
        save()
        return _state["settings"]


def _merge_settings(dst: dict, patch: dict) -> None:
    """Scalanie płytke/głębokie: aktualizuje tylko istniejące klucze (whitelist wg domyślnych)."""
    for key, val in patch.items():
        if key in dst and isinstance(dst[key], dict) and isinstance(val, dict):
            _merge_settings(dst[key], val)
        elif key in dst:
            dst[key] = val


# ---------- hosty SSH ----------

def get_ssh_host(host_id: str) -> dict | None:
    for host in _state["ssh_hosts"]:
        if host["id"] == host_id:
            return host
    return None


def add_ssh_host(cfg: dict) -> dict:
    with _lock:
        _state["ssh_hosts"].append(cfg)
        save()
        return cfg


def remove_ssh_host(host_id: str) -> bool:
    with _lock:
        before = len(_state["ssh_hosts"])
        _state["ssh_hosts"] = [h for h in _state["ssh_hosts"] if h["id"] != host_id]
        changed = len(_state["ssh_hosts"]) != before
        if changed:
            save()
        return changed


# ---------- cele skanowania ----------

def get_target(target_id: str) -> dict | None:
    for t in _state["targets"]:
        if t["id"] == target_id:
            return t
    return None


# ---------- wyniki skanów ----------

def set_result(target_id: str, result: dict) -> None:
    with _lock:
        _state["results"][target_id] = result
        save()


def get_result(target_id: str) -> dict | None:
    return _state["results"].get(target_id)


# ---------- dziennik ----------

def log(msg: str, level: str = "info") -> None:
    with _lock:
        _state["logs"].append({"ts": time.time(), "level": level, "msg": str(msg)[:500]})
        if len(_state["logs"]) > 500:
            _state["logs"] = _state["logs"][-500:]
        save()
