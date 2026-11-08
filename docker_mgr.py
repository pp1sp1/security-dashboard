"""Wykrywanie Dockera przez lokalny socket (/var/run/docker.sock lub DOCKER_HOST).

Listuje uruchomione kontenery i obrazy – używane przy automatycznym
wykrywaniu celów skanowania. Skanowanie obrazu wykonuje Trivy/Grype
na hoście, na którym działa panel (wymaga dostępu do socketa Dockera).
"""
from __future__ import annotations

import os


def socket_available() -> bool:
    return bool(os.environ.get("DOCKER_HOST")) or os.path.exists("/var/run/docker.sock")


def _client():
    import docker  # pakiet 'docker' (wymagany tylko gdy chcesz skanować Dockera)
    return docker.from_env(timeout=15)


def ping() -> bool:
    try:
        _client().ping()
        return True
    except Exception:
        return False


def list_containers() -> list[dict]:
    """Uruchomione kontenery: [{id, name, image, status}]."""
    out = []
    for c in _client().containers.list():
        tags = getattr(c.image, "tags", None) or []
        ref = tags[0] if tags else (getattr(c.image, "short_id", "") or c.image_id)
        out.append({"id": c.short_id, "name": c.name, "image": ref,
                    "status": c.status})
    return out


def list_images() -> list[dict]:
    """Obrazy lokalne: [{id, ref}]."""
    out = []
    for img in _client().images.list():
        ref = img.tags[0] if img.tags else ""
        if not ref:
            continue
        out.append({"id": img.short_id, "ref": ref})
    return out
