"""Proxmox & Docker Security Dashboard – aplikacja FastAPI (REST API + GUI).

Uruchomienie:
    uvicorn main:app --host 0.0.0.0 --port 8080

Ochrona hasłem (opcjonalnie):
    DASH_TOKEN=mój-sekret uvicorn main:app --host 127.0.0.1 --port 8080
    (GUI poprosi o token; wszystkie /api/* wymagają nagłówka X-Dash-Token)
"""
from __future__ import annotations

import hashlib
import os
import re
import sys
import threading
import time
import uuid
from pathlib import Path

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import docker_mgr          # noqa: E402
import executor            # noqa: E402
import notifier            # noqa: E402
import proxmox             # noqa: E402
import remediation         # noqa: E402
import scanner             # noqa: E402
import ssh_manager         # noqa: E402
import store               # noqa: E402
from pydantic import BaseModel  # noqa: E402

APP_VERSION = "1.1.0"

TASKS: dict[str, dict] = {}
_tasks_lock = threading.RLock()
_discovery_cache: dict = {"ts": 0.0, "targets": None}
_probe_last: dict[str, float] = {}

# ------------------------------------------------------------------ autoryzacja


async def _auth(request: Request):
    # chronimy wyłącznie API; powłoka GUI i pliki statyczne są publiczne
    # (żadnych danych – token podaje użytkownik w GUI)
    if not request.url.path.startswith("/api/"):
        return
    token = os.environ.get("DASH_TOKEN", "").strip()
    if not token:
        return
    provided = request.headers.get("X-Dash-Token") or request.query_params.get("token") or ""
    if provided != token:
        raise HTTPException(status_code=401, detail="Nieprawidłowy token dostępu")


app = FastAPI(title="Proxmox & Docker Security Dashboard", version=APP_VERSION,
              dependencies=[Depends(_auth)])


# ------------------------------------------------------------------ rejestr zadań

def task_new(kind: str, target_id: str, label: str) -> str:
    tid = uuid.uuid4().hex[:12]
    with _tasks_lock:
        TASKS[tid] = {"id": tid, "kind": kind, "target": target_id, "label": label,
                      "status": "running", "message": "", "result": None,
                      "started": time.time(), "finished": None}
        finished = sorted((t for t in TASKS.values() if t["status"] != "running"),
                          key=lambda t: t["finished"] or 0)
        for old in finished[:max(0, len(TASKS) - 100)]:
            TASKS.pop(old["id"], None)
    return tid


def task_msg(tid: str, msg: str) -> None:
    with _tasks_lock:
        t = TASKS.get(tid)
        if t:
            t["message"] = str(msg)[:300]


def task_done(tid: str, result=None, error: str | None = None) -> None:
    with _tasks_lock:
        t = TASKS.get(tid)
        if not t:
            return
        t["finished"] = time.time()
        if error:
            t["status"] = "failed"
            t["message"] = str(error)[:600]
        else:
            t["status"] = "done"
            t["message"] = t["message"] or "Zakończono"
        t["result"] = result


def _run_task(tid: str, fn, *args, **kwargs) -> None:
    try:
        result = fn(*args, progress=lambda m: task_msg(tid, m), **kwargs)
        task_done(tid, result=result)
    except Exception as exc:
        store.log(f"Zadanie '{TASKS.get(tid, {}).get('label', tid)}' nie powiodło się: {exc}",
                  "error")
        task_done(tid, error=f"{type(exc).__name__}: {exc}")


# ------------------------------------------------------------------ wykrywanie środowiska

def env_info() -> dict:
    info = {"version": APP_VERSION, "pve_node": False, "docker": False,
            "hostname": "", "python": sys.version.split()[0]}
    try:
        info["hostname"] = os.uname().nodename
    except Exception:
        pass
    try:
        info["pve_node"] = proxmox.is_pve_node()
    except Exception:
        pass
    try:
        info["docker"] = docker_mgr.socket_available() and docker_mgr.ping()
    except Exception:
        pass
    return info


def discover(force: bool = False) -> list[dict]:
    """Automatyczne wykrywanie celów: lokalny host, PVE (pct/qm), Docker, SSH, PVE API."""
    now = time.time()
    if (not force and _discovery_cache["targets"] is not None
            and now - _discovery_cache["ts"] < 30):
        return _discovery_cache["targets"]

    targets: list[dict] = []
    old = {t["id"]: t for t in store.get_state().get("targets") or []}

    def add(t: dict) -> None:
        prev = old.get(t["id"])
        if prev:
            t.setdefault("scanners", prev.get("scanners"))
            t.setdefault("status", prev.get("status"))
            t.setdefault("os", prev.get("os"))
        else:
            t.setdefault("scanners", None)
            t.setdefault("status", "unknown")
            t.setdefault("os", None)
        targets.append(t)

    # 1) host, na którym działa panel (zawsze)
    add({"id": "local", "type": "local", "name": f"Panel ({env_info()['hostname']})",
         "desc": "Host lokalny – tutaj działa dashboard",
         "endpoint": {"kind": "local"}, "status": "online"})

    # 2) lokalny węzeł Proxmox VE (/etc/pve)
    if proxmox.is_pve_node():
        try:
            for c in proxmox.list_lxc_local():
                add({"id": f"lxc-{c['vmid']}", "type": "lxc", "name": c["name"],
                     "desc": f"LXC {c['vmid']} ({c['status']})",
                     "endpoint": {"kind": "pct", "via": "local", "vmid": c["vmid"]},
                     "status": "online" if c["status"] == "running" else "stopped"})
        except Exception as exc:
            store.log(f"Discovery LXC: {exc}", "error")
        try:
            for vm in proxmox.list_qemu_local():
                add({"id": f"qemu-{vm['vmid']}", "type": "qemu", "name": vm["name"],
                     "desc": f"VM {vm['vmid']} ({vm['status']})",
                     "endpoint": {"kind": "qm", "via": "local", "vmid": vm["vmid"]},
                     "status": "online" if vm["status"] == "running" else "stopped"})
        except Exception as exc:
            store.log(f"Discovery VM: {exc}", "error")

    # 3) Docker (socket lokalny)
    if docker_mgr.socket_available():
        try:
            for c in docker_mgr.list_containers():
                add({"id": f"docker-{c['id'][:12]}", "type": "docker-container",
                     "name": c["name"], "desc": f"Kontener • {c['image']}",
                     "endpoint": {"kind": "docker-exec", "cid": c["name"], "image": c["image"]},
                     "status": "online"})
        except Exception as exc:
            store.log(f"Discovery Docker (kontenery): {exc}", "error")
        if store.get_settings().get("scan_docker_all_images"):
            try:
                seen: set[str] = set()
                for img in docker_mgr.list_images():
                    ref = img["ref"]
                    slug = re.sub(r"[^a-zA-Z0-9._-]+", "_", ref)[:60]
                    tid = f"dimg-{slug}-{hashlib.md5(ref.encode()).hexdigest()[:8]}"
                    if tid in seen:
                        continue
                    seen.add(tid)
                    add({"id": tid, "type": "docker-image", "name": ref,
                         "desc": "Obraz Docker",
                         "endpoint": {"kind": "docker-image", "image": ref},
                         "status": "online"})
            except Exception as exc:
                store.log(f"Discovery Docker (obrazy): {exc}", "error")

    # 4) hosty SSH dodane w GUI (+ zdalne węzły PVE przez SSH)
    for host in list(store.get_state().get("ssh_hosts") or []):
        add({"id": host["id"], "type": "ssh", "name": host.get("name") or host["host"],
             "desc": f"SSH {host.get('username')}@{host['host']}:{host.get('port', 22)}",
             "endpoint": {"kind": "ssh", "ssh_host_id": host["id"]},
             "status": host.get("last_status") or "unknown"})
        if host.get("pve"):
            try:
                for c in proxmox.list_lxc_via_ssh(host):
                    add({"id": f"{host['id']}-lxc-{c['vmid']}", "type": "ssh-lxc",
                         "name": c["name"], "desc": f"LXC {c['vmid']} @ {host['host']}",
                         "endpoint": {"kind": "pct", "via": "ssh", "ssh_host_id": host["id"],
                                      "vmid": c["vmid"]},
                         "status": "online" if c["status"] == "running" else "stopped"})
            except Exception as exc:
                store.log(f"Discovery PVE/SSH LXC ({host['host']}): {exc}", "error")
            try:
                for vm in proxmox.list_qemu_via_ssh(host):
                    add({"id": f"{host['id']}-qemu-{vm['vmid']}", "type": "ssh-qemu",
                         "name": vm["name"], "desc": f"VM {vm['vmid']} @ {host['host']}",
                         "endpoint": {"kind": "qm", "via": "ssh", "ssh_host_id": host["id"],
                                      "vmid": vm["vmid"]},
                         "status": "online" if vm["status"] == "running" else "stopped"})
            except Exception as exc:
                store.log(f"Discovery PVE/SSH VM ({host['host']}): {exc}", "error")

    # 5) zdalne węzły przez Proxmox API (lista zasobów; VM przez guest agent API)
    cfg = store.get_settings().get("proxmox_api") or {}
    if cfg.get("enabled") and cfg.get("url"):
        try:
            client = proxmox.client_from_settings()
            for node in client.nodes():
                nname = node.get("node") or ""
                try:
                    for vm in client.qemu_list(nname) or []:
                        vmid = vm.get("vmid")
                        if not vmid:
                            continue
                        add({"id": f"api-{nname}-q-{vmid}", "type": "api-qemu",
                             "name": vm.get("name") or f"VM {vmid}",
                             "desc": f"VM {vmid} @ {nname} (API)",
                             "endpoint": {"kind": "api-qm", "node": nname, "vmid": vmid},
                             "status": "online" if vm.get("status") == "running" else "stopped"})
                except Exception as exc:
                    store.log(f"Proxmox API ({nname}/qemu): {exc}", "error")
                try:
                    for c in client.lxc_list(nname) or []:
                        vmid = c.get("vmid")
                        if not vmid:
                            continue
                        add({"id": f"api-{nname}-l-{vmid}", "type": "api-lxc",
                             "name": c.get("name") or f"LXC {vmid}",
                             "desc": f"LXC {vmid} @ {nname} (API – skanowanie wymaga SSH do węzła)",
                             "endpoint": {"kind": "api-lxc", "node": nname, "vmid": vmid},
                             "status": "online" if c.get("status") == "running" else "stopped"})
                except Exception as exc:
                    store.log(f"Proxmox API ({nname}/lxc): {exc}", "error")
        except Exception as exc:
            store.log(f"Proxmox API: {exc}", "error")

    with store._lock:
        store.get_state()["targets"] = targets
        store.save()
    _discovery_cache["ts"] = time.time()
    _discovery_cache["targets"] = targets
    _maybe_probe(targets)
    return targets


def _maybe_probe(targets: list[dict]) -> None:
    """W tle sprawdza obecność skanerów dla celów, których jeszcze nie sprawdzono."""
    now = time.time()
    ids = [t["id"] for t in targets
           if t.get("scanners") is None
           and t.get("status") not in ("stopped",)
           and t["type"] not in ("api-lxc", "docker-image")
           and now - _probe_last.get(t["id"], 0) > 300]
    if not ids:
        return
    for tid in ids:
        _probe_last[tid] = now
    threading.Thread(target=_probe_worker, args=(ids,), daemon=True).start()


def _probe_worker(ids: list[str]) -> None:
    for tid in ids:
        target = store.get_target(tid)
        if not target:
            continue
        try:
            ep, _rootfs = scanner._scanner_exec_endpoint(target)
            target["scanners"] = scanner.check_scanners(ep)
        except Exception:
            target["scanners"] = {"trivy": None, "grype": None}
        try:
            if target["type"] == "ssh":
                host = store.get_ssh_host(tid)
                if host:
                    host["last_status"] = "online" if _ssh_alive(host) else "offline"
                    target["status"] = host["last_status"]
        except Exception:
            pass
        store.save()


def _ssh_alive(host: dict) -> bool:
    rc, _, _ = ssh_manager.run(host, "true", 15)
    return rc == 0


# ------------------------------------------------------------------ zadania w tle

def _engines() -> list[str]:
    engine = store.get_settings().get("scan_engine", "trivy")
    return {"trivy": ["trivy"], "grype": ["grype"],
            "both": ["trivy", "grype"]}.get(engine, ["trivy"])


def _ensure_scanners(target: dict, progress) -> None:
    if not store.get_settings().get("auto_install_scanner", True):
        return
    ep, _rootfs = scanner._scanner_exec_endpoint(target)
    versions = scanner.check_scanners(ep)
    for engine in _engines():
        if not versions.get(engine):
            progress(f"Automatyczna instalacja skanera {engine}…")
            scanner.install_scanner(target, engine, progress)


def _task_scan(target_id: str, progress=None) -> dict:
    target = store.get_target(target_id)
    if not target:
        raise RuntimeError("Cel nie istnieje – odśwież listę (F5)")
    engines = _engines()
    settings = store.get_settings()
    _ensure_scanners(target, progress)
    db_ok = True
    if settings.get("update_db_before_scan", True):
        progress("Aktualizuję bazę CVE (trivy/grype)…")
        upd = scanner.update_databases(target, engines)
        db_ok = all(v["ok"] for v in upd.values())
        if not db_ok:
            store.log(f"Aktualizacja baz nie powiodła się ({upd}) – skanuję na istniejącej bazie",
                      "warn")
    progress("Skanuję…")
    result = scanner.scan_target(target, engines, skip_db_update=db_ok, progress=progress)
    store.set_result(target_id, result)
    notifier.notify_scan_result(target, result)
    notifier.update_ha_sensor()
    s = result["summary"]
    progress(f"Gotowe: C:{s.get('CRITICAL', 0)} H:{s.get('HIGH', 0)} "
             f"M:{s.get('MEDIUM', 0)} L:{s.get('LOW', 0)}")
    return {"summary": s, "fixable": result.get("fixable", 0)}


def _task_scan_all(progress=None) -> dict:
    targets = discover()
    scan_types = {"local", "ssh", "lxc", "ssh-lxc", "qemu", "ssh-qemu",
                  "api-qemu", "docker-container"}
    if store.get_settings().get("scan_docker_all_images"):
        scan_types.add("docker-image")
    scanned, agg, skipped = 0, {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}, []
    todo = [t for t in targets if t["type"] in scan_types]
    for idx, target in enumerate(todo, 1):
        progress(f"[{idx}/{len(todo)}] {target['name']}…")
        try:
            result = scanner.scan_target(
                target, _engines(),
                skip_db_update=(idx > 1),  # baza aktualizowana przed pierwszym skanem
                progress=progress)
            store.set_result(target["id"], result)
            scanned += 1
            for k in agg:
                agg[k] += (result.get("summary") or {}).get(k, 0)
            notifier.notify_scan_result(target, result)
        except Exception as exc:
            skipped.append({"target": target["id"], "error": str(exc)[:200]})
            store.log(f"Skan {target['id']}: {exc}", "error")
    notifier.update_ha_sensor()
    store.log(f"Skan wszech celów zakończony: {scanned} OK, {len(skipped)} błędów; "
              f"CRITICAL={agg['CRITICAL']}, HIGH={agg['HIGH']}")
    return {"scanned": scanned, "summary": agg, "skipped": skipped}


def _task_install(target_id: str, name: str, progress=None) -> dict:
    target = store.get_target(target_id)
    if not target:
        raise RuntimeError("Cel nie istnieje – odśwież listę")
    version = scanner.install_scanner(target, name, progress)
    t = store.get_target(target_id)
    if t:
        scanners = t.get("scanners") or {"trivy": None, "grype": None}
        scanners[name] = version
        t["scanners"] = scanners
        store.save()
    return {"scanner": name, "version": version}


def _task_update_dbs(target_id: str, progress=None) -> dict:
    target = store.get_target(target_id)
    if not target:
        raise RuntimeError("Cel nie istnieje")
    progress("Aktualizuję bazy CVE…")
    return scanner.update_databases(target, _engines())


def _task_test(target_id: str, progress=None) -> dict:
    target = store.get_target(target_id)
    if not target:
        raise RuntimeError("Cel nie istnieje")
    progress("Sprawdzam połączenie…")
    if target["type"] == "ssh":
        host = store.get_ssh_host(target_id)
        if not host:
            raise RuntimeError("Host SSH usunięty")
        out = ssh_manager.test(host)
        target["status"] = "online" if out.get("ok") else "offline"
        host["last_status"] = target["status"]
        store.save()
        if not out.get("ok"):
            raise RuntimeError(out.get("error") or "Połączenie nie powiodło się")
        return {"info": out.get("info", "")}
    rc, out, err = executor.execute(target["endpoint"], "echo ok; uname -sr", 30)
    if rc != 0:
        raise RuntimeError((err or out).strip()[:300] or f"Kod wyjścia {rc}")
    target["status"] = "online"
    target["os"] = executor.run_os_release(target["endpoint"])
    store.save()
    return {"info": out.strip()[:300]}


def _task_remediate(target_id: str, packages: list[str], progress=None) -> dict:
    target = store.get_target(target_id)
    if not target:
        raise RuntimeError("Cel nie istnieje")
    progress(f"Aktualizuję {len(packages)} pakietów (wykrywanie menedżera)…")
    result = remediation.upgrade_packages(target, packages)
    first_err = (result.get("failed") or [{}])[0].get("error", "") if result.get("failed") else ""
    first_skip = ((result.get("skipped") or [{}])[0].get("pkg", "")
                  if result.get("skipped") else "")
    store.log(f"Remediacja {target_id}: OK={len(result['ok'])}, "
              f"błędy={len(result.get('failed') or [])}, "
              f"pominięte={len(result.get('skipped') or [])} ({result.get('pm', '?')})"
              + (f" – pierwszy błąd: {first_err[:180]}" if first_err else "")
              + (f"; pominięto m.in. {first_skip}" if first_skip else ""),
              "error" if result.get("failed") else "info")
    if first_err:
        progress(f"Uwaga: część pakietów się nie zaktualizowała ({first_err[:200]})")
    progress("Gotowe – uruchom ponowny skan, aby zweryfikować.")
    return result


def _task_remediate_all(target_id: str, progress=None) -> dict:
    result = store.get_result(target_id)
    if not result:
        raise RuntimeError("Brak wyników skanu – uruchom najpierw skan")
    packages = remediation.fixable_packages(result.get("vulns") or [])
    if not packages:
        return {"ok": [], "failed": [], "out": "Brak pakietów z dostępną poprawką"}
    return _task_remediate(target_id, packages, progress)


# ------------------------------------------------------------------ harmonogram

def _scheduler_loop() -> None:
    while True:
        try:
            time.sleep(30)
            settings = store.get_settings()
            interval = float(settings.get("scan_interval_hours") or 0)
            if interval <= 0:
                continue
            state = store.get_state()
            last = state.get("sched_last_run") or 0
            if time.time() - last < interval * 3600:
                continue
            state["sched_last_run"] = time.time()
            store.save()
            store.log(f"Harmonogram: automatyczny skan wszystkich celów (co {interval} h)")
            tid = task_new("scan-all", "*", "Zaplanowany skan (harmonogram)")
            threading.Thread(target=_run_task, args=(tid, _task_scan_all), daemon=True).start()
        except Exception as exc:
            store.log(f"Harmonogram: {exc}", "error")


@app.on_event("startup")
def _startup() -> None:
    store.load()
    try:
        discover(force=True)
    except Exception as exc:
        store.log(f"Discovery: {exc}", "error")
    threading.Thread(target=_scheduler_loop, daemon=True).start()
    store.log(f"Panel uruchomiony (v{APP_VERSION})")


@app.on_event("shutdown")
def _shutdown() -> None:
    ssh_manager.close_all()


# ------------------------------------------------------------------ modele API

class SshHostIn(BaseModel):
    name: str = ""
    host: str
    port: int = 22
    username: str = "root"
    auth_type: str = "password"      # password | key
    password: str = ""
    private_key: str = ""
    key_password: str = ""
    pve: bool = False                # czy to węzeł Proxmox VE (pct/qm dostępne przez SSH)
    test: bool = True                # testuj połączenie przed zapisem


# ------------------------------------------------------------------ REST API

@app.get("/api/status")
def api_status():
    return {"version": APP_VERSION,
            "env": env_info(),
            "hosts": len(store.get_state().get("targets") or []),
            "tasks_running": sum(1 for t in TASKS.values() if t["status"] == "running"),
            "sched_last_run": store.get_state().get("sched_last_run", 0),
            "interval_hours": store.get_settings().get("scan_interval_hours", 0)}


@app.get("/api/hosts")
def api_hosts():
    targets = discover()
    results = store.get_state().get("results") or {}
    out = []
    for t in targets:
        item = dict(t)
        res = results.get(t["id"])
        item["result"] = ({"time": res.get("time"), "summary": res.get("summary"),
                           "fixable": res.get("fixable", 0),
                           "engines": res.get("engines"),
                           "truncated": res.get("truncated")} if res else None)
        out.append(item)
    return {"hosts": out, "env": env_info()}


@app.post("/api/discover")
def api_discover():
    targets = discover(force=True)
    return {"hosts": len(targets)}


@app.post("/api/hosts/ssh")
def api_add_ssh_host(cfg_in: SshHostIn):
    probe: dict = {"ok": False, "error": ""}
    host = cfg_in.host.strip()
    if not host:
        raise HTTPException(400, "Podaj adres hosta")
    temp = {"id": "tmp", "host": host, "port": cfg_in.port,
            "username": cfg_in.username, "auth_type": cfg_in.auth_type,
            "password": cfg_in.password, "private_key": cfg_in.private_key,
            "key_password": cfg_in.key_password}
    if cfg_in.test:
        probe = ssh_manager.test(temp)
        if not probe.get("ok"):
            raise HTTPException(400, f"Test połączenia nie powiódł się: {probe.get('error')}")
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", host).strip("-").lower() or "host"
    existing = {h["id"] for h in store.get_state()["ssh_hosts"]}
    hid = f"ssh-{slug}" if f"ssh-{slug}" not in existing else f"ssh-{slug}-{uuid.uuid4().hex[:4]}"
    cfg = {"id": hid, "name": cfg_in.name.strip() or host, "host": host,
           "port": cfg_in.port, "username": cfg_in.username,
           "auth_type": cfg_in.auth_type, "password": cfg_in.password,
           "private_key": cfg_in.private_key, "key_password": cfg_in.key_password,
           "pve": bool(cfg_in.pve), "created": time.time()}
    if cfg_in.test:
        cfg["last_status"] = "online"
    store.add_ssh_host(cfg)
    store.log(f"Dodano host SSH: {cfg['username']}@{host} (id={hid})")
    discover(force=True)
    return {"id": hid, "info": probe.get("info") if cfg_in.test else None}


@app.delete("/api/hosts/ssh/{host_id}")
def api_del_ssh_host(host_id: str):
    host = store.get_ssh_host(host_id)
    if not host:
        raise HTTPException(404, "Nie znaleziono hosta")
    ssh_manager.drop(host)
    store.remove_ssh_host(host_id)
    store.log(f"Usunięto host SSH: {host_id}")
    discover(force=True)
    return {"ok": True}


@app.post("/api/hosts/{target_id}/test")
def api_test_host(target_id: str, background: BackgroundTasks):
    tid = task_new("test", target_id, f"Test połączenia: {target_id}")
    background.add_task(_run_task, tid, _task_test, target_id)
    return {"task": tid}


@app.get("/api/hosts/{target_id}/scanners")
def api_scanners(target_id: str):
    target = store.get_target(target_id)
    if not target:
        raise HTTPException(404, "Nie znaleziono celu")
    ep, _rootfs = scanner._scanner_exec_endpoint(target)
    return {"scanners": scanner.check_scanners(ep)}


@app.post("/api/hosts/{target_id}/install-scanner")
def api_install_scanner(target_id: str, body: dict, background: BackgroundTasks):
    name = (body or {}).get("name")
    if name not in ("trivy", "grype"):
        raise HTTPException(400, "Parametr 'name' musi być trivy lub grype")
    tid = task_new("install-scanner", target_id, f"Instalacja {name}: {target_id}")
    background.add_task(_run_task, tid, _task_install, target_id, name)
    return {"task": tid}


@app.post("/api/hosts/{target_id}/scan")
def api_scan(target_id: str, background: BackgroundTasks):
    target = store.get_target(target_id)
    if not target:
        raise HTTPException(404, "Nie znaleziono celu")
    tid = task_new("scan", target_id, f"Skanowanie: {target['name']}")
    background.add_task(_run_task, tid, _task_scan, target_id)
    return {"task": tid}


@app.post("/api/hosts/{target_id}/update-dbs")
def api_update_dbs(target_id: str, background: BackgroundTasks):
    target = store.get_target(target_id)
    if not target:
        raise HTTPException(404, "Nie znaleziono celu")
    tid = task_new("update-dbs", target_id, f"Aktualizacja baz CVE: {target['name']}")
    background.add_task(_run_task, tid, _task_update_dbs, target_id)
    return {"task": tid}


@app.get("/api/hosts/{target_id}/vulns")
def api_vulns(target_id: str):
    result = store.get_result(target_id)
    if not result:
        raise HTTPException(404, "Brak wyników – uruchom skan")
    return result


@app.post("/api/hosts/{target_id}/remediate")
def api_remediate(target_id: str, body: dict, background: BackgroundTasks):
    packages = (body or {}).get("packages") or []
    packages = [str(p) for p in packages if str(p).strip()]
    if not packages:
        raise HTTPException(400, "Lista 'packages' jest pusta")
    target = store.get_target(target_id)
    if not target:
        raise HTTPException(404, "Nie znaleziono celu")
    tid = task_new("remediate", target_id,
                   f"Aktualizacja {len(packages)} pakietów: {target['name']}")
    background.add_task(_run_task, tid, _task_remediate, target_id, packages)
    return {"task": tid}


@app.post("/api/hosts/{target_id}/remediate-all")
def api_remediate_all(target_id: str, background: BackgroundTasks):
    target = store.get_target(target_id)
    if not target:
        raise HTTPException(404, "Nie znaleziono celu")
    result = store.get_result(target_id)
    if not result:
        raise HTTPException(400, "Brak wyników skanu – uruchom najpierw skan")
    tid = task_new("remediate-all", target_id, f"Naprawa wszystkich pakietów: {target['name']}")
    background.add_task(_run_task, tid, _task_remediate_all, target_id)
    return {"task": tid}


@app.post("/api/scan-all")
def api_scan_all(background: BackgroundTasks):
    tid = task_new("scan-all", "*", "Skan wszystkich celów")
    background.add_task(_run_task, tid, _task_scan_all)
    return {"task": tid}


@app.get("/api/tasks")
def api_tasks():
    with _tasks_lock:
        items = sorted(TASKS.values(), key=lambda t: t["started"], reverse=True)
        return {"tasks": [dict(t) for t in items[:60]]}


@app.post("/api/tasks/clear")
def api_tasks_clear():
    with _tasks_lock:
        for tid in [t["id"] for t in TASKS.values() if t["status"] != "running"]:
            TASKS.pop(tid, None)
    return {"ok": True}


@app.get("/api/settings")
def api_settings_get():
    return {"settings": _mask(store.get_settings())}


@app.post("/api/settings")
def api_settings_post(body: dict):
    patch = _unmask(body or {})
    if not patch:
        raise HTTPException(400, "Brak zmian (wszystkie wartości zamaskowane?)")
    settings = store.update_settings(patch)
    store.log("Zaktualizowano ustawienia")
    return {"settings": _mask(settings)}


@app.post("/api/settings/test-notify")
def api_test_notify():
    out = notifier.send_test(store.get_settings())
    return {"results": out or {"info": "Żaden kanał nie jest włączony"}}


@app.post("/api/settings/update-ha-sensor")
def api_update_ha():
    totals = notifier.update_ha_sensor()
    if totals is None:
        raise HTTPException(400, "Home Assistant nie jest włączony/w skonfigurowany")
    return {"totals": totals}


@app.get("/api/logs")
def api_logs():
    logs = list(store.get_state().get("logs") or [])[-150:]
    return {"logs": list(reversed(logs))}


@app.get("/")
def index():
    return FileResponse(BASE_DIR / "templates" / "index.html")


app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


# ------------------------------------------------------------------ maskowanie sekretów

_SECRET_KEYS = {"password", "private_key", "key_password", "token", "bot_token", "webhook_url"}
_MASK = "•••"


def _mask(obj):
    if isinstance(obj, dict):
        return {k: (_MASK if (k in _SECRET_KEYS and isinstance(v, str) and v) else _mask(v))
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [_mask(x) for x in obj]
    return obj


def _unmask(obj):
    if isinstance(obj, dict):
        return {k: _unmask(v) for k, v in obj.items()
                if not (k in _SECRET_KEYS and v == _MASK)}
    if isinstance(obj, list):
        return [_unmask(x) for x in obj]
    return obj
