"""Naprawa (remediacja) podatnych pakietów.

Wykrywa menedżer pakietów celu (apt / apk / dnf) i buduje bezpieczne
polecenia aktualizacji:
  - Debian/Ubuntu: apt-get install --only-upgrade <paczki>
  - Alpine:        apk add --upgrade <paczki>
  - RHEL/CentOS:   dnf update -y <paczki> (fallback: yum)

Działa na wszystkich typach celów obsługiwanych przez executor
(lokalny, SSH, LXC przez pct exec, VM przez QEMU Guest Agent, docker exec).
"""
from __future__ import annotations

import shlex

import executor

PM_BY_ID = {
    "debian": "apt", "ubuntu": "apt", "linuxmint": "apt", "raspbian": "apt",
    "kali": "apt", "mx": "apt", "astra": "apt",
    "alpine": "apk",
    "centos": "dnf", "rhel": "dnf", "rocky": "dnf", "almalinux": "dnf",
    "fedora": "dnf", "ol": "dnf", "amzn": "dnf", "openeuler": "dnf",
}


def detect_pm(endpoint: dict) -> str:
    """Rozpoznaje menedżer pakietów na celu."""
    info = executor.run_os_release(endpoint)
    os_id = (info.get("ID") or "").lower()
    like = [x.strip().lower() for x in (info.get("ID_LIKE") or "").split()]
    for cand in [os_id] + like:
        if cand in PM_BY_ID:
            return PM_BY_ID[cand]
    for probe in ("command -v apt-get", "command -v apk", "command -v dnf", "command -v yum"):
        rc, _, _ = executor.execute(endpoint, probe, 15)
        if rc == 0:
            return {"command -v apt-get": "apt", "command -v apk": "apk",
                    "command -v dnf": "dnf", "command -v yum": "dnf"}[probe]
    raise RuntimeError(f"Nie rozpoznano systemu ({os_id or 'nieznany'}): "
                       f"brak apt-get / apk / dnf-yum")


def build_upgrade_cmd(pm: str, packages: list[str], with_update: bool = True) -> str:
    pkgs = " ".join(shlex.quote(p) for p in packages if p)
    if not pkgs:
        raise ValueError("Pusta lista pakietów")
    if pm == "apt":
        prefix = "export DEBIAN_FRONTEND=noninteractive; "
        upd = "apt-get update -qq && " if with_update else ""
        return f"{prefix}{upd}apt-get install -y --only-upgrade {pkgs}"
    if pm == "apk":
        upd = "apk update -q && " if with_update else ""
        return f"{upd}apk add --upgrade {pkgs}"
    if pm == "dnf":
        return f"(command -v dnf >/dev/null 2>&1 && dnf -y update {pkgs}) || yum -y update {pkgs}"
    raise ValueError(f"Nieznany menedżer pakietów: {pm}")


def fixable_packages(vulns: list[dict]) -> list[str]:
    """Unikalne nazwy pakietów, dla których skaner podał wersję poprawki."""
    seen: set[str] = set()
    out: list[str] = []
    for v in vulns or []:
        pkg = (v.get("pkg") or "").strip()
        fixed = (v.get("fixed") or "").strip()
        if pkg and fixed and pkg not in seen:
            seen.add(pkg)
            out.append(pkg)
    return sorted(out)


def upgrade_packages(target: dict, packages: list[str]) -> dict:
    """Aktualizuje pakiety na celu. Zwraca raport {ok, failed, pm, out}.

    Jeżeli bezpośrednie wykonanie się nie powiedzie (brak uprawnień root),
    podejmowana jest jedna próba przez `sudo -n`."""
    if not packages:
        return {"ok": [], "failed": [], "pm": "", "out": "Brak pakietów do aktualizacji"}
    endpoint = target["endpoint"]
    pm = detect_pm(endpoint)
    ok: list[str] = []
    failed: list[dict] = []
    outs: list[str] = []
    for chunk in [packages[i:i + 40] for i in range(0, len(packages), 40)]:
        cmd = build_upgrade_cmd(pm, chunk)
        rc, out, err = executor.execute(endpoint, cmd, timeout=1800)
        outs.append((out or "")[-1500:])
        if rc != 0:
            rc2, out2, err2 = executor.execute(endpoint, f"sudo -n sh -c {shlex.quote(cmd)}",
                                               timeout=1800)
            if rc2 == 0:
                ok.extend(chunk)
                outs.append((out2 or "")[-800:])
                continue
            reason = (err2 or err or out2 or out or "").strip()[-400:]
            failed.extend([{"pkg": p, "error": reason or f"Kod wyjścia {rc}"} for p in chunk])
        else:
            ok.extend(chunk)
    return {"ok": ok, "failed": failed, "pm": pm, "out": "\n---\n".join(outs)[-3000:]}
