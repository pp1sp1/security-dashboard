"""Integracja z systemami powiadomień.

Obsługiwane kanały (włączane w Ustawieniach):
  - ntfy (ntfy.sh lub self-hosted, opcjonalny token),
  - Gotify (url + token aplikacji),
  - Home Assistant (aktualizacja sensora stanu + opcjonalna usługa notify),
  - Discord (Webhook, rich embed),
  - Telegram (Bot API, sendMessage).

Powiadomienia o zagrożeniach są deduplikowane per (cel, CVE) przez 24h,
aby skanowanie nie generowało spamu.
"""
from __future__ import annotations

import time

import httpx

import store

TIMEOUT = 15
_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
_DEDUPE_WINDOW = 86400  # 24h


def _rank(sev: str) -> int:
    return _SEV_RANK.get(sev, 9)


def build_text(target: dict, result: dict, limit: int = 12) -> str:
    """Tekstowy raport zagrożeń (używany przez ntfy/Gotify/Telegram/HA)."""
    s = result.get("summary") or {}
    lines = [
        "Security Dashboard – wykryte zagrożenia",
        f"Cel: {target.get('name')} ({target.get('id')})",
        f"CRITICAL: {s.get('CRITICAL', 0)} | HIGH: {s.get('HIGH', 0)} | "
        f"MEDIUM: {s.get('MEDIUM', 0)} | LOW: {s.get('LOW', 0)}",
    ]
    top = [v for v in result.get("vulns") or []
           if v.get("severity") in ("CRITICAL", "HIGH")][:limit]
    if top:
        lines.append("Najpoważniejsze:")
        for v in top:
            fix = f" -> {v['fixed']}" if v.get("fixed") else " (brak poprawki)"
            lines.append(f"- [{v['severity']}] {v['id']} – {v['pkg']} "
                         f"{v.get('installed')}{fix}")
    if result.get("truncated"):
        lines.append("UWAGA: wyjście mogło zostać ucięte (QEMU Guest Agent) – "
                     "dodaj hosta przez SSH dla niezawodnego skanowania.")
    return "\n".join(lines)


def _discord_payload(target: dict, result: dict) -> dict:
    s = result.get("summary") or {}
    color = 0xED4245 if s.get("CRITICAL") else 0xE67E22
    fields = [
        {"name": "Cel", "value": f"{target.get('name')} (`{target.get('id')}`)", "inline": True},
        {"name": "Wynik",
         "value": (f"CRITICAL: **{s.get('CRITICAL', 0)}** | HIGH: **{s.get('HIGH', 0)}** | "
                   f"MED: {s.get('MEDIUM', 0)} | LOW: {s.get('LOW', 0)}"), "inline": True},
    ]
    top = [v for v in result.get("vulns") or []
           if v.get("severity") in ("CRITICAL", "HIGH")][:25]
    if top:
        desc = "\n".join(
            f"- **{v['id']}** – {v['pkg']} `{v.get('installed')}` -> "
            f"`{v.get('fixed') or 'brak poprawki'}`" for v in top)
        fields.append({"name": f"Top zagrożenia ({len(top)})",
                       "value": desc[:1020] or "\u200b"})
    return {"embeds": [{"title": "Wykryto podatności", "color": color,
                        "fields": fields[:25]}]}


# ---------------------------------------------------------------- kanały

def _send_ntfy(cfg: dict, target: dict, result: dict) -> str:
    """ntfy w trybie JSON – poprawnie obsługuje polskie znaki (nagłówki HTTP
    są ASCII-only, dlatego temat + tytuł idą w body JSON)."""
    import httpx as _httpx
    url = (cfg.get("url") or "").strip()
    if not url:
        return "Brak URL (np. https://ntfy.sh/twoj-temat)"
    u = _httpx.URL(url)
    segments = [s for s in u.path.split("/") if s]
    if not segments:
        return "URL musi wskazywać temat (np. https://ntfy.sh/twoj-temat)"
    topic = segments[-1]
    base = u.copy_with(path="/" + "/".join(segments[:-1]) if segments[:-1] else "/")
    payload = {"topic": topic,
               "title": f"Security: {target.get('name')}"[:250],
               "message": build_text(target, result),
               "priority": "high",
               "tags": ["warning"]}
    headers = {}
    if cfg.get("token"):
        headers["Authorization"] = f"Bearer {cfg['token']}"
    r = httpx.post(str(base), json=payload, headers=headers, timeout=TIMEOUT)
    r.raise_for_status()
    return "OK"


def _send_gotify(cfg: dict, target: dict, result: dict) -> str:
    url = (cfg.get("url") or "").strip().rstrip("/")
    if not url or not cfg.get("token"):
        return "Brak URL lub tokenu aplikacji"
    r = httpx.post(f"{url}/message", params={"token": cfg["token"]},
                   json={"title": f"Security: {target.get('name')}",
                         "message": build_text(target, result), "priority": 8},
                   timeout=TIMEOUT)
    r.raise_for_status()
    return "OK"


def _send_discord(cfg: dict, target: dict, result: dict) -> str:
    url = (cfg.get("webhook_url") or "").strip()
    if not url:
        return "Brak webhook URL"
    r = httpx.post(url, json=_discord_payload(target, result), timeout=TIMEOUT)
    r.raise_for_status()
    return "OK"


def _send_telegram(cfg: dict, target: dict, result: dict) -> str:
    token = (cfg.get("bot_token") or "").strip()
    chat = (cfg.get("chat_id") or "").strip()
    if not token or not chat:
        return "Brak bot_token lub chat_id"
    r = httpx.post(f"https://api.telegram.org/bot{token}/sendMessage",
                   json={"chat_id": chat, "text": build_text(target, result),
                         "disable_web_page_preview": True}, timeout=TIMEOUT)
    r.raise_for_status()
    return "OK"


def _send_ha(cfg: dict, target: dict, result: dict) -> str:
    update_ha_sensor()
    if cfg.get("notify_service"):
        url = (cfg.get("url") or "").strip().rstrip("/")
        r = httpx.post(f"{url}/api/services/{cfg['notify_service']}",
                       headers={"Authorization": f"Bearer {cfg.get('token')}"},
                       json={"title": f"Security: {target.get('name')}",
                             "message": build_text(target, result)}, timeout=TIMEOUT)
        r.raise_for_status()
        return "OK (sensor + notify)"
    return "OK (sensor zaktualizowany)"


# ---------------------------------------------------------------- Home Assistant sensor

def update_ha_sensor(settings: dict | None = None) -> dict | None:
    """Aktualizuje sensor stanu w Home Assistant (suma CRITICAL+HIGH).

    Sensor ma atrybuty: critical/high/medium/low oraz per_target."""
    settings = settings or store.get_settings()
    cfg = settings.get("homeassistant") or {}
    if not cfg.get("enabled") or not cfg.get("url") or not cfg.get("token"):
        return None
    totals = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    per_target: dict = {}
    for tid, res in (store.get_state().get("results") or {}).items():
        s = res.get("summary") or {}
        totals["critical"] += s.get("CRITICAL", 0)
        totals["high"] += s.get("HIGH", 0)
        totals["medium"] += s.get("MEDIUM", 0)
        totals["low"] += s.get("LOW", 0)
        per_target[tid] = {"critical": s.get("CRITICAL", 0), "high": s.get("HIGH", 0)}
    url = cfg["url"].strip().rstrip("/")
    sensor = (cfg.get("sensor") or "sensor.security_dashboard").strip()
    r = httpx.post(f"{url}/api/states/{sensor}",
                   headers={"Authorization": f"Bearer {cfg['token']}"},
                   json={"state": str(totals["critical"] + totals["high"]),
                         "attributes": {"critical": totals["critical"],
                                        "high": totals["high"],
                                        "medium": totals["medium"],
                                        "low": totals["low"],
                                        "per_target": per_target,
                                        "friendly_name": "Security Dashboard",
                                        "updated": time.strftime("%Y-%m-%d %H:%M:%S")}},
                   timeout=TIMEOUT)
    r.raise_for_status()
    return totals


# ---------------------------------------------------------------- dispatch

_CHANNELS = [("ntfy", "ntfy", _send_ntfy),
             ("gotify", "gotify", _send_gotify),
             ("homeassistant", "Home Assistant", _send_ha),
             ("discord", "Discord", _send_discord),
             ("telegram", "Telegram", _send_telegram)]


def notify_scan_result(target: dict, result: dict) -> dict:
    """Wysyła powiadomienie o nowych zagrożeniach (CRITICAL/HIGH domyślnie).

    Zwraca raport per kanał; żaden błąd kanału nie przerywa pozostałych."""
    settings = store.get_settings()
    min_sev = settings.get("min_notify_severity") or "HIGH"
    summary = result.get("summary") or {}
    interesting = [v for v in result.get("vulns") or []
                   if _rank(v.get("severity") or "UNKNOWN") <= _rank(min_sev)]
    if not interesting:
        return {"skipped": f"brak zagrożeń >= {min_sev}"}

    # dedupe 24h per (cel, CVE)
    with store._lock:
        cache = store.get_state().setdefault("notify_cache", {}).setdefault(target["id"], {})
        now = time.time()
        new_items = [v for v in interesting
                     if now - cache.get(v["id"], 0) > _DEDUPE_WINDOW]
        for v in new_items:
            cache[v["id"]] = now
        if not new_items:
            return {"skipped": "brak nowych zagrożeń (dedupe 24h)"}
        # przycinaj cache
        for tid, c in store.get_state().get("notify_cache", {}).items():
            for k in [k for k, ts in c.items() if now - ts > _DEDUPE_WINDOW * 2]:
                c.pop(k, None)
        store.save()

    out: dict = {}
    for key, _label, fn in _CHANNELS:
        cfg = settings.get(key) or {}
        if not cfg.get("enabled"):
            continue
        try:
            out[key] = fn(cfg, target, result)
        except Exception as exc:
            out[key] = f"BŁĄD: {exc}"
            store.log(f"Powiadomienie ({key}) dla {target.get('id')} nie powiodło się: {exc}",
                      "error")
    if out:
        store.log(f"Powiadomienia wysłane dla {target.get('id')}: {out}")
    return out


def send_test(settings: dict) -> dict:
    """Wysyła powiadomienie testowe na wszystkie włączone kanały."""
    fake_target = {"id": "test", "name": "Test powiadomień", "type": "test"}
    fake_result = {
        "summary": {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "UNKNOWN": 0},
        "vulns": [{"id": "CVE-0000-0001", "pkg": "przyklad-pakiet", "installed": "1.0.0",
                   "fixed": "1.0.1", "severity": "CRITICAL", "title": "Powiadomienie testowe",
                   "url": "", "desc": "Jeśli to widzisz, kanał działa poprawnie."}],
        "truncated": False,
    }
    out: dict = {}
    for key, _label, fn in _CHANNELS:
        cfg = (settings.get(key) or {})
        if not cfg.get("enabled"):
            continue
        try:
            if key == "homeassistant":
                out[key] = _send_ha(cfg, fake_target, fake_result)
            else:
                out[key] = fn(cfg, fake_target, fake_result)
        except Exception as exc:
            out[key] = f"BŁĄD: {exc}"
    return out
