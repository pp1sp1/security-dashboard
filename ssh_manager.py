"""Zdalne wykonywanie poleceń przez SSH (paramiko).

Funkcje:
  - pool połączeń z keepalive i automatycznym reconnectem,
  - exec_command z czytaniem stderr w osobnym wątku (brak deadlocków na buforach),
  - upload plików przez SFTP (używany przy instalacji skanerów na zdalnych hostach).
"""
from __future__ import annotations

import io
import shlex
import socket
import threading
from typing import Optional

import paramiko

_POOL: dict[str, paramiko.SSHClient] = {}
_pool_lock = threading.Lock()


def _load_key(text: str, password: Optional[str] = None) -> paramiko.PKey:
    last_exc: Exception | None = None
    for cls in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            return cls.from_private_key(io.StringIO(text), password=password)
        except paramiko.PasswordRequiredException:
            raise ValueError("Klucz prywatny jest zabezpieczony hasłem – wpisz je w polu "
                             "'Hasło do klucza (opcjonalne)'")
        except Exception as exc:
            last_exc = exc
    raise ValueError(f"Nie można wczytać klucza prywatnego: {last_exc}")


def _pool_key(host: dict) -> str:
    return f"{host.get('id', 'tmp')}|{host.get('username', '')}@{host.get('host', '')}:{host.get('port', 22)}"


def _connect(host: dict) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs: dict = dict(
        hostname=host["host"], port=int(host.get("port") or 22),
        username=host.get("username") or "root",
        timeout=12, banner_timeout=20, auth_timeout=20,
        look_for_keys=False, allow_agent=False,
    )
    if host.get("auth_type") == "key":
        kwargs["pkey"] = _load_key(host.get("private_key") or "",
                                   host.get("key_password") or None)
    else:
        kwargs["password"] = host.get("password") or ""
    client.connect(**kwargs)
    transport = client.get_transport()
    if transport:
        transport.set_keepalive(25)
    return client


def _get_client(host: dict) -> paramiko.SSHClient:
    key = _pool_key(host)
    with _pool_lock:
        cli = _POOL.get(key)
    if cli is not None:
        transport = cli.get_transport()
        if transport is not None and transport.is_active():
            return cli
        try:
            cli.close()
        except Exception:
            pass
    cli = _connect(host)
    with _pool_lock:
        _POOL[key] = cli
    return cli


def drop(host: dict) -> None:
    """Zamyka i usuwa połączenie z puli (np. po usunięciu hosta)."""
    key = _pool_key(host)
    with _pool_lock:
        cli = _POOL.pop(key, None)
    if cli:
        try:
            cli.close()
        except Exception:
            pass


def _read_all(stream) -> str:
    chunks: list[str] = []
    try:
        while True:
            data = stream.read(32768)
            if not data:
                break
            chunks.append(data)
    except Exception:
        pass
    return "".join(chunks)


def _run_once(host: dict, cmd: str, timeout: int) -> tuple[int, str, str]:
    cli = _get_client(host)
    stdin, stdout, stderr = cli.exec_command(cmd, timeout=timeout)
    err_chunks: list[str] = []
    err_thread = threading.Thread(target=lambda: err_chunks.append(_read_all(stderr)), daemon=True)
    err_thread.start()
    timed_out = False
    out = ""
    try:
        out = _read_all(stdout)
        rc = stdout.channel.recv_exit_status()
    except socket.timeout:
        timed_out = True
        rc = 124
        try:
            stdout.channel.close()
        except Exception:
            pass
    err_thread.join(timeout=5)
    err = err_chunks[0] if err_chunks else ""
    if timed_out:
        err = (err + f"\nPrzekroczono limit czasu ({timeout}s)").strip()
    return rc, out, err


def run(host: dict, cmd: str, timeout: int = 600, env: dict | None = None) -> tuple[int, str, str]:
    """Wykonuje polecenie przez SSH. Zwraca (rc, stdout, stderr).

    Jedna próba ponownego połączenia w razie zerwanego tunelu."""
    if env:
        prefix = "".join(f"export {k}={shlex.quote(str(v))}; " for k, v in env.items())
        cmd = prefix + cmd
    try:
        return _run_once(host, cmd, timeout)
    except (paramiko.SSHException, EOFError, socket.error, OSError):
        drop(host)
        try:
            return _run_once(host, cmd, timeout)
        except Exception as exc:
            return 255, "", f"Błąd SSH: {exc}"
    except Exception as exc:
        return 255, "", f"Błąd SSH: {exc}"


def test(host: dict) -> dict:
    """Test połączenia: zwraca {ok, info | error}."""
    try:
        rc, out, err = run(host,
                           "uname -sr; (grep PRETTY_NAME /etc/os-release 2>/dev/null || true); id -u",
                           timeout=25)
        if rc != 0:
            return {"ok": False, "error": ((err or out).strip()[:300] or f"Kod wyjścia {rc}")}
        return {"ok": True, "info": out.strip()}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def upload_file(host: dict, local_path: str, remote_path: str) -> None:
    """SFTP upload pliku (np. binarki skanera)."""
    cli = _get_client(host)
    sftp = cli.open_sftp()
    try:
        sftp.put(local_path, remote_path)
    finally:
        try:
            sftp.close()
        except Exception:
            pass


def close_all() -> None:
    with _pool_lock:
        for cli in _POOL.values():
            try:
                cli.close()
            except Exception:
                pass
        _POOL.clear()
