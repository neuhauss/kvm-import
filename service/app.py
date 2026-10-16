"""Early KVM host inventory API. Restrict this service to an authenticated proxy."""

from __future__ import annotations

import base64
import hashlib
import os
import re
import sqlite3
import ssl
import uuid
import json
import asyncio
import io
import select
import shlex
import socket
import socketserver
import threading
import urllib.error
import urllib.request
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

import paramiko
from cryptography.fernet import Fernet, InvalidToken
import httpx
import websockets
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, WebSocket
from fastapi.responses import RedirectResponse, StreamingResponse
from pydantic import BaseModel, Field


DB_PATH = Path(os.getenv("KVM_DB_PATH", "./data/kvm-hosts.sqlite3"))
KNOWN_HOSTS = os.getenv("KVM_KNOWN_HOSTS", "./known_hosts")
credential_key = os.environ.get("KVM_CREDENTIAL_KEY", "")
RANCHER_API_URL = os.getenv("RANCHER_API_URL", "https://rancher.example.com").rstrip("/")
RANCHER_CA_FILE = os.getenv("RANCHER_CA_FILE", "/etc/rancher-ca/ca.crt")
if len(credential_key) < 32:
    raise RuntimeError("Configure KVM_CREDENTIAL_KEY with at least 32 random characters")
FERNET_KEY = base64.urlsafe_b64encode(hashlib.sha256(credential_key.encode()).digest())
cipher = Fernet(FERNET_KEY)
app = FastAPI(title="Rancher KVM Host API", version="0.5.7")
RANCHER_PUBLIC_ORIGIN = os.getenv("RANCHER_PUBLIC_ORIGIN", "https://rancher.example.com").rstrip("/")
RANCHER_PUBLIC_HOST = urlsplit(RANCHER_PUBLIC_ORIGIN).netloc
COCKPIT_PORT = 9090


@app.middleware("http")
async def disable_api_caching(request: Request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/kvm-api/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        response.headers["Pragma"] = "no-cache"
    return response


@app.on_event("startup")
def initialize_database() -> None:
    # Create the schema as soon as the pod starts so a ready API always has a
    # usable persistent database, even before the first authenticated request.
    with connect_db():
        pass


class HostInput(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    address: str = Field(min_length=1, max_length=253)
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(min_length=1, max_length=128)
    password: str | None = Field(default=None, max_length=1024)
    ssh_private_key: str | None = Field(default=None, max_length=16384)
    ssh_key_passphrase: str | None = Field(default=None, max_length=1024)
    remove_ssh_key: bool = False
    accept_new_host_key: bool = False


class VMAction(BaseModel):
    action: Literal["start", "shutdown", "reboot", "pause", "resume"]


class VMAutostart(BaseModel):
    enabled: bool


class ServiceAction(BaseModel):
    action: Literal["start", "stop", "restart"]


class NamedAdminAction(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    action: Literal["start", "stop", "enable", "disable"]


class RepositoryAction(BaseModel):
    alias: str = Field(min_length=1, max_length=128)
    action: Literal["enable", "disable", "refresh"]


class SecurityModeAction(BaseModel):
    mode: Literal["enforcing", "permissive"]


class TerminalCommand(BaseModel):
    command: str = Field(min_length=1, max_length=4000)


class NetworkConnectionAction(BaseModel):
    uuid: str = Field(min_length=1, max_length=64)
    action: Literal["up", "down"]


class AccountAction(BaseModel):
    username: str = Field(min_length=1, max_length=32)
    action: Literal["lock", "unlock", "password"]
    password: str | None = Field(default=None, min_length=8, max_length=1024)


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def connect_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    try:
        db.execute("""CREATE TABLE IF NOT EXISTS hosts (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, address TEXT NOT NULL, port INTEGER NOT NULL,
            username TEXT NOT NULL, password TEXT NOT NULL, hostname TEXT, status TEXT NOT NULL,
            cpu_count INTEGER, memory_total_bytes INTEGER, last_checked_at TEXT, last_error TEXT,
            ssh_host_key TEXT, cockpit_proxy_enabled INTEGER NOT NULL DEFAULT 0,
            ssh_private_key_enc TEXT, ssh_key_passphrase_enc TEXT
        )""")
        columns = {row[1] for row in db.execute("PRAGMA table_info(hosts)")}
        if "ssh_host_key" not in columns:
            db.execute("ALTER TABLE hosts ADD COLUMN ssh_host_key TEXT")
        if "cockpit_proxy_enabled" not in columns:
            db.execute("ALTER TABLE hosts ADD COLUMN cockpit_proxy_enabled INTEGER NOT NULL DEFAULT 0")
        if "ssh_private_key_enc" not in columns:
            db.execute("ALTER TABLE hosts ADD COLUMN ssh_private_key_enc TEXT")
        if "ssh_key_passphrase_enc" not in columns:
            db.execute("ALTER TABLE hosts ADD COLUMN ssh_key_passphrase_enc TEXT")
        db.execute("""CREATE TABLE IF NOT EXISTS audit_events (
            id TEXT PRIMARY KEY, occurred_at TEXT NOT NULL, actor TEXT NOT NULL,
            action TEXT NOT NULL, target TEXT NOT NULL, outcome TEXT NOT NULL, detail TEXT
        )""")
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def rancher_get(path: str, token: str | None = None, session_cookie: str | None = None) -> dict[str, Any]:
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    elif session_cookie:
        headers["Cookie"] = session_cookie
    request = urllib.request.Request(
        f"{RANCHER_API_URL}{path}",
        headers=headers,
    )
    context = ssl.create_default_context(cafile=RANCHER_CA_FILE)
    with urllib.request.urlopen(request, context=context, timeout=5) as response:
        return json.loads(response.read())


def require_auth(
    authorization: str | None = Header(default=None),
    cookie: str | None = Header(default=None),
) -> str:
    """Validate Rancher identity and the configured set of allowed global roles."""
    token = authorization[7:].strip() if authorization and authorization.startswith("Bearer ") else ""
    session_cookie = None
    if not token and cookie:
        session = next((part.strip() for part in cookie.split(";") if part.strip().startswith("R_SESS=")), None)
        if session:
            session_cookie = session
    if not token and not session_cookie:
        raise HTTPException(401, "A Rancher session is required")
    if token and len(token) > 8192:
        raise HTTPException(401, "The Rancher session is invalid")
    try:
        identity = rancher_get("/v3/token", token=token or None, session_cookie=session_cookie)
        user_id = identity.get("userId")
        if isinstance(user_id, str) and re.fullmatch(r"[A-Za-z0-9_-]+", user_id):
            user = rancher_get(f"/v3/users/{user_id}", token=token or None, session_cookie=session_cookie)
        else:
            current = rancher_get("/v3/users?me=true", token=token or None, session_cookie=session_cookie)
            users = current.get("data") or []
            user = users[0] if users else current
            user_id = user.get("id")
        roles = {user.get("globalRoleId")} if user.get("globalRoleId") else set()
        if isinstance(user_id, str) and re.fullmatch(r"[A-Za-z0-9_-]+", user_id):
            bindings = rancher_get(
                f"/v3/globalRoleBindings?userId={user_id}",
                token=token or None,
                session_cookie=session_cookie,
            )
            roles.update(binding.get("globalRoleId") for binding in bindings.get("data", []) if binding.get("globalRoleId"))
    except HTTPException:
        raise
    except (urllib.error.URLError, TimeoutError, ValueError, KeyError):
        raise HTTPException(401, "The Rancher session is invalid or expired") from None
    allowed_roles = {role.strip() for role in os.getenv("KVM_ALLOWED_GLOBAL_ROLES", "admin").split(",") if role.strip()}
    if not roles.intersection(allowed_roles):
        raise HTTPException(403, "Your Rancher global role is not authorized to manage KVM hosts")
    return str(user_id or user.get("id") or "unknown")


def record_audit(actor: str, action: str, target: str, outcome: str = "success", detail: str | None = None) -> None:
    with connect_db() as db:
        db.execute(
            "INSERT INTO audit_events (id,occurred_at,actor,action,target,outcome,detail) VALUES (?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), now(), actor[:255], action[:80], target[:255], outcome[:40], detail[:500] if detail else None),
        )


def public_host(row: sqlite3.Row) -> dict[str, Any]:
    return {key: row[key] for key in (
        "id", "name", "address", "port", "username", "hostname", "status",
        "cpu_count", "memory_total_bytes", "last_checked_at", "last_error",
    )}


class PinnedHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    def missing_host_key(self, client: paramiko.SSHClient, hostname: str, key: paramiko.PKey) -> None:
        raise paramiko.SSHException("The received SSH host key does not match the key pinned for this host")


def _load_private_key(host: dict[str, Any]) -> paramiko.PKey | None:
    private_key = host.get("private_key")
    if not private_key:
        return None
    failures = []
    for key_name in ("Ed25519Key", "RSAKey", "ECDSAKey", "DSSKey"):
        key_class = getattr(paramiko, key_name, None)
        if key_class is None:
            continue
        try:
            return key_class.from_private_key(io.StringIO(private_key), password=host.get("key_passphrase") or None)
        except (paramiko.SSHException, ValueError, TypeError) as exc:
            failures.append(str(exc))
    message = failures[-1] if failures else "unsupported SSH private key format"
    raise RuntimeError(f"Could not read the SSH private key: {message}")


def connect_ssh(client: paramiko.SSHClient, host: dict[str, Any]) -> None:
    kwargs = {
        "hostname": host["address"], "port": host["port"], "username": host["username"],
        "look_for_keys": False, "allow_agent": False, "timeout": 8, "banner_timeout": 8, "auth_timeout": 8,
    }
    key = _load_private_key(host)
    if key:
        kwargs["pkey"] = key
        kwargs["password"] = None
    else:
        kwargs["password"] = host["password"]
    client.connect(**kwargs)


def decrypt_host_credentials(host: dict[str, Any]) -> dict[str, Any]:
    for encrypted_name, clear_name in (("ssh_private_key_enc", "private_key"), ("ssh_key_passphrase_enc", "key_passphrase")):
        value = host.get(encrypted_name)
        if value:
            host[clear_name] = cipher.decrypt(value.encode()).decode()
    return host


def ssh_client_for_host(host: dict[str, Any]) -> paramiko.SSHClient:
    """Open SSH only to the imported endpoint and require its pinned host key."""
    pinned = host.get("ssh_host_key")
    if not pinned:
        raise RuntimeError("This host has no pinned SSH key; refresh its registration before opening Cockpit")
    try:
        key_type, key_data = pinned.split(" ", 1)
        key = paramiko.PKey.from_type_string(key_type, base64.b64decode(key_data.encode()))
    except (ValueError, TypeError) as exc:
        raise RuntimeError("The pinned SSH host key is invalid") from exc
    client = paramiko.SSHClient()
    host_label = host["address"] if host["port"] == 22 else f'[{host["address"]}]:{host["port"]}'
    client.get_host_keys().add(host_label, key_type, key)
    client.set_missing_host_key_policy(PinnedHostKeyPolicy())
    try:
        connect_ssh(client, host)
    except Exception:
        client.close()
        raise
    return client


def cockpit_url_root(host_id: str) -> str:
    return f"/kvm-cockpit/{host_id}"


def configure_cockpit_proxy(host: dict[str, Any]) -> None:
    """Configure Cockpit's reverse-proxy path once, preserving and backing up config."""
    root = cockpit_url_root(host["id"])
    script = r'''import os, pathlib, re, shutil, stat, tempfile
path = pathlib.Path('/etc/cockpit/cockpit.conf')
backup = pathlib.Path('/etc/cockpit/cockpit.conf.rancher-kvm.bak')
marker = pathlib.Path('/etc/cockpit/cockpit.conf.rancher-kvm-owner')
root = os.environ['KVM_COCKPIT_ROOT']
origin = os.environ['KVM_RANCHER_ORIGIN']
host_id = os.environ['KVM_HOST_ID']
previous_host_id = marker.read_text().strip() if marker.exists() else ''
existing_text = path.read_text() if path.exists() else ''
existing_root = re.search(r'(?im)^\s*UrlRoot\s*=\s*(.*?)\s*$', existing_text)
legacy_extension_root = bool(
    existing_root
    and existing_root.group(1) != root
    and re.fullmatch(r'/kvm-cockpit/[0-9a-fA-F-]{36}', existing_root.group(1))
    and not previous_host_id
)
if previous_host_id and previous_host_id != host_id:
    # A Rancher record can be removed while the host is unreachable. Reclaim the
    # extension-owned config on re-import, but only if its UrlRoot still matches
    # the previous record ID. Keep the original backup for eventual cleanup.
    previous_root = '/kvm-cockpit/' + previous_host_id
    old_root = re.search(r'(?im)^\s*UrlRoot\s*=\s*(.*?)\s*$', existing_text)
    if not old_root or old_root.group(1) != previous_root:
        raise SystemExit('Cockpit is already configured for another KVM registration; no changes were made')
text = path.read_text() if path.exists() else ''
section = re.search(r'(?ims)^\[WebService\]\s*$(.*?)(?=^\[|\Z)', text)
if section:
    body = section.group(1)
    original_body = body
    current = re.search(r'(?im)^\s*UrlRoot\s*=\s*(.*?)\s*$', body)
    if current and current.group(1) != root:
        if (previous_host_id and current.group(1) == '/kvm-cockpit/' + previous_host_id) or legacy_extension_root:
            body = body[:current.start(1)] + root + body[current.end(1):]
            current = re.search(r'(?im)^\s*UrlRoot\s*=\s*(.*?)\s*$', body)
        else:
            raise SystemExit('Cockpit already has UrlRoot configured; the existing configuration was not changed')
    lines = []
    if not current:
        lines.append('UrlRoot = ' + root)
    protocol = re.search(r'(?im)^\s*ProtocolHeader\s*=\s*(.*?)\s*$', body)
    if protocol and protocol.group(1) != 'X-Forwarded-Proto':
        raise SystemExit('Cockpit already uses a different ProtocolHeader; the existing configuration was not changed')
    if not protocol:
        lines.append('ProtocolHeader = X-Forwarded-Proto')
    origins = re.search(r'(?im)^\s*Origins\s*=\s*(.*?)\s*$', body)
    if origins:
        values = origins.group(1).split()
        if origin not in values:
            values.append(origin)
            body = body[:origins.start(1)] + ' '.join(values) + body[origins.end(1):]
    else:
        lines.append('Origins = ' + origin)
    if lines or body != original_body:
        # Rebuild the WebService section without disturbing other sections.
        start, end = section.span(1)
        text = text[:start] + body + ('\n' if body and not body.endswith('\n') else '') + '\n'.join(lines) + '\n' + text[end:]
else:
    text = text.rstrip() + ('\n\n' if text.strip() else '') + '[WebService]\nUrlRoot = ' + root + '\nProtocolHeader = X-Forwarded-Proto\nOrigins = ' + origin + '\n'
if path.exists() and not backup.exists() and not legacy_extension_root:
    shutil.copy2(path, backup)
path.parent.mkdir(parents=True, exist_ok=True)
mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o644
fd, tmp = tempfile.mkstemp(prefix='cockpit.conf.', dir=str(path.parent))
with os.fdopen(fd, 'w') as f:
    f.write(text)
    f.flush()
    os.fsync(f.fileno())
os.chmod(tmp, mode)
os.replace(tmp, path)
marker.write_text(host_id + '\n')
os.chmod(marker, 0o600)
'''
    env = f"KVM_COCKPIT_ROOT={shlex.quote(root)} KVM_RANCHER_ORIGIN={shlex.quote(RANCHER_PUBLIC_ORIGIN)} KVM_HOST_ID={shlex.quote(host['id'])}"
    command = f"sudo -S -p '' env {env} python3 -c {shlex.quote(script)}"
    client = ssh_client_for_host(host)
    try:
        _stdin, stdout, stderr = client.exec_command(command, timeout=20, get_pty=True)
        _stdin.write(host["password"] + "\n")
        _stdin.flush()
        _stdin.channel.shutdown_write()
        output = stdout.read().decode("utf-8", "replace").strip()
        error = stderr.read().decode("utf-8", "replace").strip()
        status = stdout.channel.recv_exit_status()
        if status:
            detail = error or output or "sudo permission is required"
            raise RuntimeError(f"Could not prepare Cockpit on this host: {detail}")
    finally:
        client.close()


def restore_cockpit_proxy(host: dict[str, Any]) -> None:
    """Restore cockpit.conf only when this extension's ownership marker matches."""
    script = r'''import os, pathlib, re
path = pathlib.Path('/etc/cockpit/cockpit.conf')
backup = pathlib.Path('/etc/cockpit/cockpit.conf.rancher-kvm.bak')
marker = pathlib.Path('/etc/cockpit/cockpit.conf.rancher-kvm-owner')
if not marker.exists() or marker.read_text().strip() != os.environ['KVM_HOST_ID']:
    raise SystemExit(0)
if backup.exists():
    os.replace(backup, path)
elif path.exists():
    text = path.read_text()
    root = os.environ['KVM_COCKPIT_ROOT']
    text = re.sub(r'(?im)^\s*UrlRoot\s*=\s*' + re.escape(root) + r'\s*\n?', '', text)
    text = re.sub(r'(?im)^\s*ProtocolHeader\s*=\s*X-Forwarded-Proto\s*\n?', '', text)
    origin = os.environ['KVM_RANCHER_ORIGIN']
    for match in list(re.finditer(r'(?im)^\s*Origins\s*=\s*(.*?)\s*$', text)):
        origins = [value for value in match.group(1).split() if value != origin]
        replacement = ('Origins = ' + ' '.join(origins) + '\n') if origins else ''
        text = text[:match.start()] + replacement + text[match.end():]
    if not text.strip() or re.fullmatch(r'\s*\[WebService\]\s*', text, re.IGNORECASE):
        path.unlink()
    else:
        path.write_text(text)
marker.unlink(missing_ok=True)
'''
    env = f"KVM_COCKPIT_ROOT={shlex.quote(cockpit_url_root(host['id']))} KVM_HOST_ID={shlex.quote(host['id'])}"
    client = ssh_client_for_host(host)
    try:
        _stdin, stdout, stderr = client.exec_command(
            f"sudo -S -p '' env {env} python3 -c {shlex.quote(script)}", timeout=20, get_pty=True,
        )
        _stdin.write(host["password"] + "\n")
        _stdin.flush()
        _stdin.channel.shutdown_write()
        output = stdout.read().decode("utf-8", "replace").strip()
        error = stderr.read().decode("utf-8", "replace").strip()
        if stdout.channel.recv_exit_status():
            raise RuntimeError(error or output or "Could not restore the original Cockpit configuration")
    finally:
        client.close()


class _ForwardHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        forward = self.server
        transport = forward.transport
        channel = transport.open_channel("direct-tcpip", ("127.0.0.1", COCKPIT_PORT), self.request.getpeername())
        if channel is None:
            return
        try:
            while True:
                readable, _, _ = select.select([self.request, channel], [], [], 30)
                if not readable:
                    continue
                for source in readable:
                    data = source.recv(65536)
                    if not data:
                        return
                    (channel if source is self.request else self.request).sendall(data)
        except (OSError, paramiko.SSHException):
            pass
        finally:
            channel.close()


class _ForwardServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class SshCockpitTunnel:
    def __init__(self, host: dict[str, Any]) -> None:
        self.client = ssh_client_for_host(host)
        self.server = _ForwardServer(("127.0.0.1", 0), _ForwardHandler)
        self.server.transport = self.client.get_transport()
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.port = self.server.server_address[1]

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.client.close()


def cockpit_host_record(host_id: str) -> dict[str, Any]:
    with connect_db() as db:
        row = read_host(db, host_id)
        host = dict(row)
    try:
        host["password"] = cipher.decrypt(host["password"].encode()).decode()
        decrypt_host_credentials(host)
    except InvalidToken as exc:
        raise HTTPException(500, "Could not decrypt the saved credentials") from exc
    return host


def cockpit_upstream_headers(request: Request, host: dict[str, Any]) -> dict[str, str]:
    headers = {
        "Host": "127.0.0.1:9090",
        "Authorization": "Basic " + base64.b64encode(f'{host["username"]}:{host["password"]}'.encode()).decode(),
        "Origin": RANCHER_PUBLIC_ORIGIN,
        "X-Forwarded-Proto": "https",
        "X-Forwarded-Host": RANCHER_PUBLIC_HOST,
    }
    cockpit_cookies = [
        part.strip() for part in request.headers.get("cookie", "").split(";")
        if part.strip().partition("=")[0] == "cockpit"
    ]
    if cockpit_cookies:
        headers["Cookie"] = "; ".join(cockpit_cookies)
    return headers


@app.post("/kvm-api/hosts/{host_id}/cockpit", dependencies=[Depends(require_auth)])
def open_cockpit(host_id: str, request: Request) -> RedirectResponse:
    if request.headers.get("origin") != RANCHER_PUBLIC_ORIGIN:
        raise HTTPException(403, "Cockpit must be opened from the Rancher interface")
    host = cockpit_host_record(host_id)
    if not host.get("cockpit_proxy_enabled"):
        try:
            configure_cockpit_proxy(host)
        except Exception as exc:
            raise HTTPException(502, str(exc)) from exc
        with connect_db() as db:
            db.execute("UPDATE hosts SET cockpit_proxy_enabled=1 WHERE id=?", (host_id,))
    return RedirectResponse(f"/kvm-cockpit/{host_id}/", status_code=303)


def _cockpit_request_headers(request: Request, host: dict[str, Any]) -> dict[str, str]:
    headers = cockpit_upstream_headers(request, host)
    for key in ("accept", "accept-language", "content-type", "if-modified-since", "if-none-match", "range"):
        if key in request.headers:
            headers[key] = request.headers[key]
    return headers


def _proxy_response_headers(upstream: httpx.Response, host_id: str) -> tuple[dict[str, str], list[str]]:
    ignored = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "www-authenticate", "te", "trailers", "transfer-encoding", "upgrade", "content-length", "content-encoding"}
    headers = {key: value for key, value in upstream.headers.items() if key.lower() not in ignored and key.lower() != "set-cookie"}
    location = headers.get("location")
    if location:
        location = location.replace("http://127.0.0.1:9090", RANCHER_PUBLIC_ORIGIN)
        location = location.replace("https://127.0.0.1:9090", RANCHER_PUBLIC_ORIGIN)
        headers["location"] = location
    cookies = []
    prefix = cockpit_url_root(host_id)
    for cookie in upstream.headers.get_list("set-cookie"):
        cookie = re.sub(r";\s*Domain=[^;]+", "", cookie, flags=re.IGNORECASE)
        if re.search(r";\s*Path=", cookie, flags=re.IGNORECASE):
            cookie = re.sub(r";\s*Path=[^;]+", f"; Path={prefix}", cookie, flags=re.IGNORECASE)
        else:
            cookie += f"; Path={prefix}"
        cookies.append(cookie)
    return headers, cookies


async def _proxy_cockpit_http(host_id: str, path: str, request: Request) -> StreamingResponse:
    try:
        require_auth(request.headers.get("authorization"), request.headers.get("cookie"))
        if request.method not in ("GET", "HEAD") and request.headers.get("origin") != RANCHER_PUBLIC_ORIGIN:
            raise HTTPException(403, "Invalid origin for the Cockpit operation")
        host = cockpit_host_record(host_id)
        suffix = f"/{path}" if path else "/"
        if any(part in (".", "..") for part in suffix.split("/")) or "\\" in suffix:
            raise HTTPException(400, "Invalid Cockpit path")
        tunnel = await asyncio.to_thread(SshCockpitTunnel, host)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(502, f"Could not open the secure tunnel to Cockpit: {exc}") from exc

    # Cockpit reads credentials on its /login endpoint. A first visit to the
    # root would otherwise return its interactive login screen, so authenticate
    # that initial navigation server-side with the stored SSH account.
    has_cockpit_cookie = any(
        part.strip().partition("=")[0] == "cockpit"
        for part in request.headers.get("cookie", "").split(";")
    )
    if suffix == "/" and not has_cockpit_cookie:
        suffix = "/login"
    target = f"http://127.0.0.1:{tunnel.port}{cockpit_url_root(host_id)}{suffix}"
    if request.url.query:
        target += "?" + request.url.query
    client = httpx.AsyncClient(follow_redirects=False, timeout=60, trust_env=False)
    try:
        upstream_request = client.build_request(
            request.method, target,
            headers=_cockpit_request_headers(request, host),
            content=request.stream() if request.method not in ("GET", "HEAD") else None,
        )
        upstream = await client.send(upstream_request, stream=True)
    except Exception as exc:
        await client.aclose()
        await asyncio.to_thread(tunnel.close)
        raise HTTPException(502, f"Could not forward the Cockpit connection: {exc}") from exc

    headers, cookies = _proxy_response_headers(upstream, host_id)

    async def body():
        try:
            async for chunk in upstream.aiter_bytes():
                yield chunk
        finally:
            await upstream.aclose()
            await client.aclose()
            await asyncio.to_thread(tunnel.close)

    response = StreamingResponse(body(), status_code=upstream.status_code, headers=headers)
    response.headers["Cache-Control"] = "private, no-store"
    for cookie in cookies:
        response.raw_headers.append((b"set-cookie", cookie.encode("latin-1")))
    return response


@app.api_route("/kvm-cockpit/{host_id}", methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
async def cockpit_root(host_id: str, request: Request) -> StreamingResponse:
    return await _proxy_cockpit_http(host_id, "", request)


@app.api_route("/kvm-cockpit/{host_id}/{path:path}", methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
async def cockpit_path(host_id: str, path: str, request: Request) -> StreamingResponse:
    return await _proxy_cockpit_http(host_id, path, request)


async def _proxy_cockpit_websocket(host_id: str, path: str, websocket: WebSocket) -> None:
    try:
        require_auth(websocket.headers.get("authorization"), websocket.headers.get("cookie"))
        if websocket.headers.get("origin") != RANCHER_PUBLIC_ORIGIN:
            await websocket.close(code=4403)
            return
        host = cockpit_host_record(host_id)
        tunnel = await asyncio.to_thread(SshCockpitTunnel, host)
    except HTTPException as exc:
        await websocket.close(code=4403 if exc.status_code == 403 else 4401)
        return
    except Exception:
        await websocket.close(code=1011)
        return

    suffix = f"/{path}" if path else "/"
    if any(part in (".", "..") for part in suffix.split("/")) or "\\" in suffix:
        await websocket.close(code=4400)
        return
    target = f"ws://127.0.0.1:{tunnel.port}{cockpit_url_root(host_id)}{suffix}"
    if websocket.url.query:
        target += "?" + websocket.url.query
    headers = {
        "Host": "127.0.0.1:9090",
        "Authorization": "Basic " + base64.b64encode(f'{host["username"]}:{host["password"]}'.encode()).decode(),
        "X-Forwarded-Proto": "https",
        "X-Forwarded-Host": RANCHER_PUBLIC_HOST,
    }
    cockpit_cookies = [
        part.strip() for part in websocket.headers.get("cookie", "").split(";")
        if part.strip().partition("=")[0] == "cockpit"
    ]
    if cockpit_cookies:
        headers["Cookie"] = "; ".join(cockpit_cookies)
    subprotocols = websocket.scope.get("subprotocols", [])
    upstream = None
    try:
        upstream = await websockets.connect(
            target, origin=RANCHER_PUBLIC_ORIGIN, additional_headers=headers, subprotocols=subprotocols,
            open_timeout=15, close_timeout=3, max_size=None,
        )
        await websocket.accept(subprotocol=upstream.subprotocol)

        async def browser_to_cockpit() -> None:
            while True:
                message = await websocket.receive()
                if message["type"] == "websocket.disconnect":
                    break
                data = message.get("bytes") if message.get("bytes") is not None else message.get("text", "")
                await upstream.send(data)

        async def cockpit_to_browser() -> None:
            async for data in upstream:
                if isinstance(data, bytes):
                    await websocket.send_bytes(data)
                else:
                    await websocket.send_text(data)

        tasks = [asyncio.create_task(browser_to_cockpit()), asyncio.create_task(cockpit_to_browser())]
        _done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        await websocket.close(code=1000)
    except Exception:
        try:
            await websocket.close(code=1011)
        except Exception:
            pass
    finally:
        if upstream is not None:
            await upstream.close()
        await asyncio.to_thread(tunnel.close)


@app.websocket("/kvm-cockpit/{host_id}/{path:path}")
async def cockpit_websocket(host_id: str, path: str, websocket: WebSocket) -> None:
    await _proxy_cockpit_websocket(host_id, path, websocket)


def probe(
    host: dict[str, Any], pinned_host_key: str | None = None,
    accept_new_host_key: bool = False,
) -> dict[str, Any]:
    """Check SSH host identity and query existing libvirt without changing host state."""
    client = paramiko.SSHClient()
    host_label = host["address"] if host["port"] == 22 else f'[{host["address"]}]:{host["port"]}'
    if pinned_host_key and not accept_new_host_key:
        try:
            key_type, key_data = pinned_host_key.split(" ", 1)
            key = paramiko.PKey.from_type_string(key_type, base64.b64decode(key_data.encode()))
        except (ValueError, TypeError) as exc:
            raise RuntimeError("The pinned SSH host key is invalid") from exc
        client.get_host_keys().add(host_label, key_type, key)
        client.set_missing_host_key_policy(PinnedHostKeyPolicy())
    elif accept_new_host_key:
        # Explicit per-import opt-in: accept this connection's key and pin it in the host record.
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    else:
        if not Path(KNOWN_HOSTS).is_file():
            raise RuntimeError(f"known_hosts file not found: {KNOWN_HOSTS}")
        client.load_host_keys(KNOWN_HOSTS)
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        connect_ssh(client, host)
        remote_key = client.get_transport().get_remote_server_key()
        ssh_host_key = f"{remote_key.get_name()} {remote_key.get_base64()}"
        # All commands are fixed constants; no form value is interpolated into a shell command.
        command = (
            "hostname; "
            "printf '\\n'; "
            "getconf _NPROCESSORS_ONLN; "
            "printf '\\n'; "
            "awk '/MemTotal:/ {print $2 * 1024}' /proc/meminfo; "
            "printf '\\n'; "
            "(virsh -c qemu:///system nodeinfo >/dev/null 2>&1 && echo libvirt-ready) "
            "|| (systemctl is-active --quiet libvirtd && echo libvirt-ready) "
            "|| (systemctl is-active --quiet virtqemud && echo libvirt-ready) "
            "|| echo libvirt-unavailable"
        )
        _stdin, stdout, stderr = client.exec_command(command, timeout=12)
        # The command separates fields with printf '\\n'; this produces empty
        # lines between values, so discard them before parsing positional fields.
        lines = [line.strip() for line in stdout.read().decode("utf-8", "replace").splitlines() if line.strip()]
        error = stderr.read().decode("utf-8", "replace").strip()
        if len(lines) < 4:
            raise RuntimeError(error or "Incomplete response while querying the host")
        hostname = lines[0]
        try:
            cpu_count = int(lines[1])
            memory_total_bytes = int(lines[2])
        except ValueError as exc:
            raise RuntimeError("Invalid response while reading host CPU or memory information") from exc
        libvirt_ready = lines[3] == "libvirt-ready"
        if not libvirt_ready:
            raise RuntimeError("SSH connected, but the libvirt service did not respond")
        return {
            "hostname": hostname, "cpu_count": cpu_count,
            "memory_total_bytes": memory_total_bytes, "status": "ready",
            "last_checked_at": now(), "last_error": None, "ssh_host_key": ssh_host_key,
        }
    finally:
        client.close()


def read_host(db: sqlite3.Connection, host_id: str) -> sqlite3.Row:
    row = db.execute("SELECT * FROM hosts WHERE id=?", (host_id,)).fetchone()
    if row is None:
        raise HTTPException(404, "Host not found")
    return row


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/kvm-api/hosts", dependencies=[Depends(require_auth)])
def list_hosts() -> list[dict[str, Any]]:
    with connect_db() as db:
        return [public_host(row) for row in db.execute("SELECT * FROM hosts ORDER BY name")]


@app.post("/kvm-api/hosts", status_code=201, dependencies=[Depends(require_auth)])
def create_host(payload: HostInput, actor: str = Depends(require_auth)) -> dict[str, Any]:
    if not payload.password:
        raise HTTPException(422, "A password is required to import the host")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]+", payload.address):
        raise HTTPException(422, "Enter a valid IPv4 address, IPv6 address, or DNS name")
    host_id = str(uuid.uuid4())
    host = payload.model_dump()
    try:
        host["private_key"] = payload.ssh_private_key
        host["key_passphrase"] = payload.ssh_key_passphrase
        facts = probe(host, accept_new_host_key=payload.accept_new_host_key)
    except Exception as exc:
        raise HTTPException(422, f"Could not validate SSH/libvirt: {exc}") from exc
    with connect_db() as db:
        db.execute(
            "INSERT INTO hosts (id,name,address,port,username,password,hostname,status,cpu_count,memory_total_bytes,last_checked_at,last_error,ssh_host_key,ssh_private_key_enc,ssh_key_passphrase_enc) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (host_id, payload.name, payload.address, payload.port, payload.username,
             cipher.encrypt(payload.password.encode()).decode(), facts["hostname"], facts["status"],
             facts["cpu_count"], facts["memory_total_bytes"], facts["last_checked_at"], None,
             facts["ssh_host_key"], cipher.encrypt(payload.ssh_private_key.encode()).decode() if payload.ssh_private_key else None,
             cipher.encrypt(payload.ssh_key_passphrase.encode()).decode() if payload.ssh_key_passphrase else None),
        )
        created = public_host(read_host(db, host_id))
    record_audit(actor, "host.import", host_id, detail=f"{payload.name} ({payload.address}:{payload.port})")
    return created


@app.put("/kvm-api/hosts/{host_id}", dependencies=[Depends(require_auth)])
def update_host(host_id: str, payload: HostInput, actor: str = Depends(require_auth)) -> dict[str, Any]:
    with connect_db() as db:
        current = read_host(db, host_id)
        try:
            password = payload.password or cipher.decrypt(current["password"].encode()).decode()
            private_key = payload.ssh_private_key
            key_passphrase = payload.ssh_key_passphrase
            if payload.remove_ssh_key:
                private_key = None
                key_passphrase = None
            elif private_key is None and current["ssh_private_key_enc"]:
                private_key = cipher.decrypt(current["ssh_private_key_enc"].encode()).decode()
                if key_passphrase is None and current["ssh_key_passphrase_enc"]:
                    key_passphrase = cipher.decrypt(current["ssh_key_passphrase_enc"].encode()).decode()
        except InvalidToken as exc:
            raise HTTPException(500, "Could not decrypt the saved credentials") from exc
        host = payload.model_dump() | {"password": password, "private_key": private_key, "key_passphrase": key_passphrase}
        same_endpoint = payload.address == current["address"] and payload.port == current["port"]
        pinned_host_key = current["ssh_host_key"] if same_endpoint and not payload.accept_new_host_key else None
        if not same_endpoint and current["cockpit_proxy_enabled"]:
            old_host = dict(current)
            try:
                old_host["password"] = cipher.decrypt(current["password"].encode()).decode()
                decrypt_host_credentials(old_host)
                restore_cockpit_proxy(old_host)
            except Exception as exc:
                raise HTTPException(502, f"Could not restore the previous Cockpit endpoint configuration: {exc}") from exc
        try:
            facts = probe(host, pinned_host_key=pinned_host_key, accept_new_host_key=payload.accept_new_host_key)
        except Exception as exc:
            raise HTTPException(422, f"Could not validate SSH/libvirt: {exc}") from exc
        db.execute(
            "UPDATE hosts SET name=?,address=?,port=?,username=?,password=?,hostname=?,status=?,cpu_count=?,memory_total_bytes=?,last_checked_at=?,last_error=NULL,ssh_host_key=?,cockpit_proxy_enabled=?,ssh_private_key_enc=?,ssh_key_passphrase_enc=? WHERE id=?",
            (payload.name, payload.address, payload.port, payload.username,
             cipher.encrypt(password.encode()).decode(), facts["hostname"], facts["status"],
             facts["cpu_count"], facts["memory_total_bytes"], facts["last_checked_at"],
             facts["ssh_host_key"], int(current["cockpit_proxy_enabled"] and same_endpoint),
             cipher.encrypt(private_key.encode()).decode() if private_key else None,
             cipher.encrypt(key_passphrase.encode()).decode() if key_passphrase else None, host_id),
        )
        updated = public_host(read_host(db, host_id))
    record_audit(actor, "host.update", host_id, detail=f"{payload.name} ({payload.address}:{payload.port})")
    return updated


@app.post("/kvm-api/hosts/{host_id}/refresh", dependencies=[Depends(require_auth)])
def refresh_host(host_id: str, actor: str = Depends(require_auth)) -> dict[str, Any]:
    with connect_db() as db:
        row = read_host(db, host_id)
        host = dict(row)
        try:
            host["password"] = cipher.decrypt(row["password"].encode()).decode()
            decrypt_host_credentials(host)
            facts = probe(host, pinned_host_key=row["ssh_host_key"])
        except Exception as exc:
            facts = {"status": "unreachable", "last_checked_at": now(), "last_error": str(exc)[:500]}
        db.execute(
            "UPDATE hosts SET hostname=COALESCE(?,hostname),status=?,cpu_count=COALESCE(?,cpu_count),memory_total_bytes=COALESCE(?,memory_total_bytes),last_checked_at=?,last_error=?,ssh_host_key=COALESCE(?,ssh_host_key) WHERE id=?",
            (facts.get("hostname"), facts["status"], facts.get("cpu_count"),
             facts.get("memory_total_bytes"), facts["last_checked_at"], facts.get("last_error"),
             facts.get("ssh_host_key"), host_id),
        )
        refreshed = public_host(read_host(db, host_id))
    record_audit(actor, "host.refresh", host_id, "success" if refreshed["status"] == "ready" else "failure", refreshed.get("last_error"))
    return refreshed


@app.delete("/kvm-api/hosts/{host_id}", status_code=204, dependencies=[Depends(require_auth)])
def delete_host(host_id: str, actor: str = Depends(require_auth)) -> Response:
    with connect_db() as db:
        current = dict(read_host(db, host_id))
    if current["cockpit_proxy_enabled"]:
        try:
            current["password"] = cipher.decrypt(current["password"].encode()).decode()
            decrypt_host_credentials(current)
            restore_cockpit_proxy(current)
        except Exception:
            # Removing an inventory record must remain possible when the host
            # cannot be reached or sudo is unavailable. The owner marker and
            # backup on the host allow the next import to safely reclaim it.
            pass
    with connect_db() as db:
        read_host(db, host_id)
        db.execute("DELETE FROM hosts WHERE id=?", (host_id,))
    record_audit(actor, "host.remove", host_id, detail=f"{current['name']} ({current['address']}:{current['port']})")
    return Response(status_code=204)


VM_LIST_SCRIPT = r'''import json, subprocess
def run(args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=20)
    if result.returncode:
        raise SystemExit(result.stderr.strip() or result.stdout.strip() or 'Comando libvirt falhou')
    return result.stdout
names = run(['virsh','-c','qemu:///system','list','--all','--name']).splitlines()
items = []
for name in filter(None, (n.strip() for n in names)):
    info = {}
    for line in run(['virsh','-c','qemu:///system','dominfo',name]).splitlines():
        if ':' in line:
            key,value = line.split(':',1); info[key.strip().lower()] = value.strip()
    items.append({'name':name,'uuid':info.get('uuid',''),'state':info.get('state') or run(['virsh','-c','qemu:///system','domstate',name]).strip(),
        'vcpus':int(info.get('cpu(s)','0') or '0'),'memory_kib':int(info.get('max memory','0').split()[0] or '0'),
        'autostart':info.get('autostart','unknown')})
print(json.dumps(items))
'''

VM_DETAIL_SCRIPT = r'''import json, subprocess, sys
name = sys.argv[1]
def run(args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=20)
    if result.returncode:
        raise SystemExit(result.stderr.strip() or result.stdout.strip() or 'Comando libvirt falhou')
    return result.stdout
names = run(['virsh','-c','qemu:///system','list','--all','--name']).splitlines()
if name not in [item.strip() for item in names]: raise SystemExit('Virtual machine not found')
info = {}
for line in run(['virsh','-c','qemu:///system','dominfo',name]).splitlines():
    if ':' in line:
        key,value = line.split(':',1); info[key.strip().lower()] = value.strip()
vcpu = {}
for line in run(['virsh','-c','qemu:///system','vcpucount',name]).splitlines():
    parts = line.split()
    if len(parts) >= 3:
        vcpu[f'{parts[0].lower()}_{parts[1].lower()}'] = parts[2]
disks = []
for line in run(['virsh','-c','qemu:///system','domblklist',name,'--details']).splitlines():
    parts = line.split(None,3)
    if len(parts) == 4 and parts[0] in ('file','block','dir','network','volume'):
        disks.append({'type':parts[0], 'device':parts[1], 'target':parts[2], 'source':parts[3]})
interfaces = []
for line in run(['virsh','-c','qemu:///system','domiflist',name]).splitlines():
    parts = line.split(None,4)
    if len(parts) == 5 and parts[0] not in ('Interface','-'):
        interfaces.append({'name':parts[0], 'type':parts[1], 'source':parts[2], 'model':parts[3], 'mac':parts[4]})
result = {'name':name, 'uuid':info.get('uuid',''), 'state':info.get('state') or run(['virsh','-c','qemu:///system','domstate',name]).strip(),
    'vcpus':int(info.get('cpu(s)','0') or '0'), 'current_vcpus':int(vcpu.get('current_live',vcpu.get('current_config','0')) or '0'),
    'max_vcpus':int(vcpu.get('maximum_live',vcpu.get('maximum_config','0')) or '0'), 'memory_kib':int(info.get('max memory','0').split()[0] or '0'),
    'used_memory_kib':int(info.get('used memory','0').split()[0] or '0'), 'persistent':info.get('persistent','unknown'),
    'autostart':info.get('autostart','unknown'), 'disks':disks, 'interfaces':interfaces}
print(json.dumps(result))
'''

HOST_ADMIN_SCRIPT = r'''import grp, json, os, platform, pwd, re, shutil, subprocess, xml.etree.ElementTree as ET
errors = []
def run(args, timeout=20):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or 'Comando falhou')
    return result.stdout
def optional_json(args, fallback):
    try: return json.loads(run(args))
    except Exception as error:
        errors.append(str(error)); return fallback
def parse_info(name):
    info = {}
    for line in run(['virsh','-c','qemu:///system','dominfo',name]).splitlines():
        if ':' in line:
            key,value = line.split(':',1); info[key.strip().lower()] = value.strip()
    vcpu = {}
    for line in run(['virsh','-c','qemu:///system','vcpucount',name]).splitlines():
        parts=line.split()
        if len(parts)>=3: vcpu[f'{parts[0].lower()}_{parts[1].lower()}']=parts[2]
    return {'name':name,'uuid':info.get('uuid',''),'state':info.get('state') or run(['virsh','-c','qemu:///system','domstate',name]).strip(),
        'vcpus':int(info.get('cpu(s)','0') or '0'),'current_vcpus':int(vcpu.get('current_live',vcpu.get('current_config','0')) or '0'),
        'max_vcpus':int(vcpu.get('maximum_live',vcpu.get('maximum_config','0')) or '0'),
        'memory_kib':int(info.get('max memory','0').split()[0] or '0'),'used_memory_kib':int(info.get('used memory','0').split()[0] or '0'),
        'persistent':info.get('persistent','unknown'),'autostart':info.get('autostart','unknown')}
vms=[]
try:
    names=run(['virsh','-c','qemu:///system','list','--all','--name']).splitlines()
    for name in filter(None,(n.strip() for n in names)):
        try: vms.append(parse_info(name))
        except Exception as error: errors.append('VM '+name+': '+str(error))
except Exception as error: errors.append('libvirt: '+str(error))
devices=[]
lsblk=optional_json(['lsblk','-J','-b','-o','NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS,MODEL'],{'blockdevices':[]})
def flatten(items):
    for item in items:
        mounts=item.get('mountpoints') or item.get('mountpoint') or []
        if isinstance(mounts,str): mounts=[mounts]
        devices.append({'name':item.get('name',''),'path':item.get('path',''),'type':item.get('type',''),
            'size':int(item.get('size') or 0),'filesystem':item.get('fstype') or '',
            'mountpoints':[p for p in mounts if p], 'model':item.get('model') or ''})
        flatten(item.get('children') or [])
flatten(lsblk.get('blockdevices',[]))
filesystems=[]
try:
    for line in run(['df','-P','-T','-B1']).splitlines()[1:]:
        parts=line.split(None,6)
        if len(parts)==7: filesystems.append({'device':parts[0],'type':parts[1],'size':int(parts[2]),'used':int(parts[3]),'available':int(parts[4]),'use_percent':parts[5],'mountpoint':parts[6]})
except Exception as error: errors.append('filesystems: '+str(error))
interfaces=optional_json(['ip','-j','address'],[])
routes=optional_json(['ip','-j','route'],[])
services=[]
try:
    for line in run(['systemctl','list-units','--type=service','--all','--no-pager','--no-legend','--plain']).splitlines():
        parts=line.split(None,4)
        if len(parts)>=4: services.append({'name':parts[0],'load':parts[1],'active':parts[2],'sub':parts[3],'description':parts[4] if len(parts)>4 else ''})
except Exception as error: errors.append('services: '+str(error))
storage_pools=[]
try:
    pool_names=run(['virsh','-c','qemu:///system','pool-list','--all','--name']).splitlines()
    for pool_name in filter(None,(name.strip() for name in pool_names)):
        pool_info={}
        for line in run(['virsh','-c','qemu:///system','pool-info',pool_name]).splitlines():
            if ':' in line:
                key,value=line.split(':',1); pool_info[key.strip().lower()]=value.strip()
        storage_pools.append({'name':pool_name,'state':pool_info.get('state','unknown'),'autostart':pool_info.get('autostart','no').lower(),'capacity':pool_info.get('capacity','—'),
            'allocation':pool_info.get('allocation','—'),'available':pool_info.get('available','—')})
except Exception as error: errors.append('storage pools: '+str(error))
libvirt_networks=[]
try:
    for line in run(['virsh','-c','qemu:///system','net-list','--all']).splitlines():
        parts=line.split()
        if len(parts)>=4 and parts[0].lower() not in ('name','-'):
            libvirt_networks.append({'name':parts[0],'state':parts[1],'autostart':parts[2],'persistent':parts[3]})
except Exception as error: errors.append('libvirt networks: '+str(error))
accounts=[]
try:
    groups_by_user={entry.pw_name:[] for entry in pwd.getpwall()}
    for group in grp.getgrall():
        for username in group.gr_mem: groups_by_user.setdefault(username,[]).append(group.gr_name)
    for entry in pwd.getpwall():
        if entry.pw_uid == 0 or entry.pw_uid >= 1000:
            status=subprocess.run(['passwd','-S',entry.pw_name],capture_output=True,text=True,timeout=10)
            parts=status.stdout.split()
            accounts.append({'username':entry.pw_name,'uid':entry.pw_uid,'gid':entry.pw_gid,
                'home':entry.pw_dir,'shell':entry.pw_shell,'groups':groups_by_user.get(entry.pw_name,[]),
                'locked':len(parts)>1 and parts[1]=='L'})
except Exception as error: errors.append('accounts: '+str(error))
repositories=[]
try:
    result=subprocess.run(['zypper','--xmlout','lr','-d'],capture_output=True,text=True,timeout=30)
    if result.returncode: raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    xml=ET.fromstring(result.stdout)
    for repo in xml.iter('repo'):
        repositories.append({'alias':repo.get('alias',''),'name':repo.get('name',''),'enabled':repo.get('enabled','0')=='1',
            'autorefresh':repo.get('autorefresh','0')=='1','uri':repo.get('url') or repo.get('uri') or ''})
except Exception as error: errors.append('repositories: '+str(error))
selinux={'available':False,'mode':'unavailable','policy':'','apparmor':'unavailable'}
try:
    if shutil.which('getenforce'):
        result=subprocess.run(['getenforce'],capture_output=True,text=True,timeout=10)
        selinux.update({'available':result.returncode==0,'mode':result.stdout.strip().lower() or 'unknown'})
    if shutil.which('sestatus'):
        result=subprocess.run(['sestatus'],capture_output=True,text=True,timeout=10)
        selinux['policy']=next((line.split(':',1)[1].strip() for line in result.stdout.splitlines() if line.lower().startswith('loaded policy name:')),'')
    if shutil.which('aa-status'):
        result=subprocess.run(['aa-status','--enabled'],capture_output=True,text=True,timeout=10)
        selinux['apparmor']='enabled' if result.returncode==0 else 'disabled'
except Exception as error: errors.append('security status: '+str(error))
subscription={'available':False,'status':'SUSEConnect is not installed'}
try:
    if shutil.which('SUSEConnect'):
        result=subprocess.run(['SUSEConnect','--status-text'],capture_output=True,text=True,timeout=30)
        subscription={'available':True,'status':(result.stdout or result.stderr).strip(),'return_code':result.returncode}
except Exception as error: errors.append('subscription status: '+str(error))
network_connections=[]
try:
    if shutil.which('nmcli'):
        active_result=subprocess.run(['nmcli','-t','-f','UUID','connection','show','--active'],capture_output=True,text=True,timeout=20)
        active_uuids=set(active_result.stdout.splitlines())
        result=subprocess.run(['nmcli','-t','-f','NAME,UUID,TYPE,DEVICE','connection','show'],capture_output=True,text=True,timeout=20)
        if result.returncode: raise RuntimeError(result.stderr.strip())
        for line in result.stdout.splitlines():
            parts=line.split(':',3)
            if len(parts)==4: network_connections.append({'name':parts[0],'uuid':parts[1],'type':parts[2],'device':parts[3],'active':parts[1] in active_uuids})
except Exception as error: errors.append('network connections: '+str(error))
release={}
try:
    for line in open('/etc/os-release'):
        if '=' in line:
            key,value=line.rstrip().split('=',1); release[key]=value.strip('"')
except Exception: pass
memory={}
try:
    for line in open('/proc/meminfo'):
        key,value=line.split(':',1); memory[key]=int(value.strip().split()[0])
except Exception: pass
try: uptime_seconds=float(open('/proc/uptime').read().split()[0])
except Exception: uptime_seconds=0
try: logs=run(['journalctl','-n','50','--no-pager','-o','short-iso'],timeout=25).splitlines()
except Exception as error: logs=[]; errors.append('journal: '+str(error))
print(json.dumps({'system':{'hostname':platform.node(),'os':release.get('PRETTY_NAME',platform.system()),'kernel':platform.release(),
    'architecture':platform.machine(),'cpu_count':os.cpu_count() or 0,'memory_total_kib':memory.get('MemTotal',0),
    'memory_available_kib':memory.get('MemAvailable',0),'uptime_seconds':int(uptime_seconds),'load_average':list(os.getloadavg())},
    'vms':vms,'storage':{'devices':devices,'filesystems':filesystems},'network':{'interfaces':interfaces,'routes':routes},
    'services':services,'logs':logs,'storage_pools':storage_pools,'libvirt_networks':libvirt_networks,
    'accounts':accounts,'repositories':repositories,'selinux':selinux,'subscription':subscription,
    'network_connections':network_connections,'errors':errors}))
'''

SERVICE_ACTION_SCRIPT = r'''import re, subprocess, sys
action, name = sys.argv[1], sys.argv[2]
if action not in ('start','stop','restart') or not re.fullmatch(r'[A-Za-z0-9_.@:-]+',name): raise SystemExit('Invalid action or service')
listed=subprocess.run(['systemctl','list-unit-files','--type=service','--no-legend','--no-pager',name],capture_output=True,text=True,timeout=15)
if listed.returncode or not any(line.split() and line.split()[0] == name for line in listed.stdout.splitlines()): raise SystemExit('Service not found')
result=subprocess.run(['systemctl',action,name],capture_output=True,text=True,timeout=30)
if result.returncode: raise SystemExit(result.stderr.strip() or result.stdout.strip() or 'The systemd operation failed')
'''


@app.get("/kvm-api/hosts/{host_id}/vms", dependencies=[Depends(require_auth)])
def list_vms(host_id: str) -> list[dict[str, Any]]:
    host = cockpit_host_record(host_id)
    try:
        output = run_sudo_python(host, VM_LIST_SCRIPT, timeout=45)
        return json.loads(output or "[]")
    except Exception as exc:
        raise HTTPException(502, f"Could not query virtual machines: {exc}") from exc


@app.get("/kvm-api/hosts/{host_id}/vms/detail", dependencies=[Depends(require_auth)])
def get_vm_details(host_id: str, vm_name: str) -> dict[str, Any]:
    host = cockpit_host_record(host_id)
    try:
        output = run_sudo_python(host, VM_DETAIL_SCRIPT, [vm_name], timeout=45)
        return json.loads(output or "{}")
    except Exception as exc:
        raise HTTPException(502, f"Could not query virtual machine details: {exc}") from exc


@app.get("/kvm-api/hosts/{host_id}/cloud-native", dependencies=[Depends(require_auth)])
def get_host_cloud_native(host_id: str) -> dict[str, Any]:
    host = cockpit_host_record(host_id)
    try:
        output = run_sudo_python(host, HOST_ADMIN_SCRIPT, timeout=90)
        return json.loads(output or "{}")
    except Exception as exc:
        raise HTTPException(502, f"Could not load host administration data: {exc}") from exc


@app.post("/kvm-api/hosts/{host_id}/repositories/actions", dependencies=[Depends(require_auth)])
def control_repository(host_id: str, payload: RepositoryAction, actor: str = Depends(require_auth)) -> dict[str, bool]:
    if payload.alias != "*" and not re.fullmatch(r"[A-Za-z0-9_.:-]+", payload.alias):
        raise HTTPException(422, "Invalid repository alias")
    host = cockpit_host_record(host_id)
    if payload.action == "refresh":
        args = ["zypper", "--non-interactive", "refresh"] + ([] if payload.alias == "*" else [payload.alias])
    else:
        args = ["zypper", "--non-interactive", "modifyrepo", "--" + payload.action, payload.alias]
    script = "import subprocess,sys; r=subprocess.run(sys.argv[1:],capture_output=True,text=True,timeout=120); print(r.stdout); print(r.stderr,file=sys.stderr); sys.exit(r.returncode)"
    try:
        run_sudo_python(host, script, args, timeout=150)
    except Exception as exc:
        record_audit(actor, f"repository.{payload.action}", f"{host_id}/{payload.alias}", "failure", str(exc)[:500])
        raise HTTPException(502, f"Could not perform the repository action: {exc}") from exc
    record_audit(actor, f"repository.{payload.action}", f"{host_id}/{payload.alias}")
    return {"success": True}


@app.post("/kvm-api/hosts/{host_id}/security/selinux", dependencies=[Depends(require_auth)])
def set_selinux_mode(host_id: str, payload: SecurityModeAction, actor: str = Depends(require_auth)) -> dict[str, bool]:
    host = cockpit_host_record(host_id)
    script = r'''import shutil,subprocess,sys
if not shutil.which('setenforce'): raise SystemExit('SELinux is not available on this host')
r=subprocess.run(['setenforce','1' if sys.argv[1]=='enforcing' else '0'],capture_output=True,text=True)
if r.returncode: raise SystemExit(r.stderr.strip() or r.stdout.strip() or 'Could not change SELinux mode')
'''
    try:
        run_sudo_python(host, script, [payload.mode], timeout=30)
    except Exception as exc:
        record_audit(actor, "selinux.mode", host_id, "failure", str(exc)[:500])
        raise HTTPException(502, f"Could not change SELinux mode: {exc}") from exc
    record_audit(actor, "selinux.mode", host_id, detail=payload.mode)
    return {"success": True}


@app.post("/kvm-api/hosts/{host_id}/libvirt/{resource}/actions", dependencies=[Depends(require_auth)])
def control_libvirt_resource(host_id: str, resource: Literal["storage-pools", "networks"], payload: NamedAdminAction, actor: str = Depends(require_auth)) -> dict[str, bool]:
    if not re.fullmatch(r"[A-Za-z0-9_.+-]+", payload.name):
        raise HTTPException(422, "Invalid libvirt resource name")
    host = cockpit_host_record(host_id)
    script = r'''import subprocess,sys
kind,action,name=sys.argv[1:]
base=['virsh','-c','qemu:///system']
if kind=='storage-pools':
    listing=subprocess.run(base+['pool-list','--all','--name'],capture_output=True,text=True,timeout=20)
    command={'start':'pool-start','stop':'pool-destroy','enable':'pool-autostart','disable':'pool-autostart'}[action]
else:
    listing=subprocess.run(base+['net-list','--all','--name'],capture_output=True,text=True,timeout=20)
    command={'start':'net-start','stop':'net-destroy','enable':'net-autostart','disable':'net-autostart'}[action]
if listing.returncode or name not in listing.stdout.splitlines(): raise SystemExit('Libvirt resource not found')
args=base+[command]
if action=='disable': args.append('--disable')
args.append(name)
r=subprocess.run(args,capture_output=True,text=True,timeout=45)
if r.returncode: raise SystemExit(r.stderr.strip() or r.stdout.strip() or 'Libvirt action failed')
'''
    try:
        run_sudo_python(host, script, [resource, payload.action, payload.name], timeout=60)
    except Exception as exc:
        record_audit(actor, f"libvirt.{resource}.{payload.action}", f"{host_id}/{payload.name}", "failure", str(exc)[:500])
        raise HTTPException(502, f"Could not perform the libvirt action: {exc}") from exc
    record_audit(actor, f"libvirt.{resource}.{payload.action}", f"{host_id}/{payload.name}")
    return {"success": True}


@app.post("/kvm-api/hosts/{host_id}/terminal/command", dependencies=[Depends(require_auth)])
def run_terminal_command(host_id: str, payload: TerminalCommand, actor: str = Depends(require_auth)) -> dict[str, Any]:
    host = cockpit_host_record(host_id)
    client = ssh_client_for_host(host)
    try:
        _stdin, stdout, stderr = client.exec_command(f"bash -lc {shlex.quote(payload.command)}", timeout=60)
        output = stdout.read().decode("utf-8", "replace")
        error = stderr.read().decode("utf-8", "replace")
        status = stdout.channel.recv_exit_status()
    except Exception as exc:
        record_audit(actor, "terminal.command", host_id, "failure", str(exc)[:500])
        raise HTTPException(502, f"Terminal command failed: {exc}") from exc
    finally:
        client.close()
    record_audit(actor, "terminal.command", host_id, detail="Command executed as the imported SSH user")
    return {"stdout": output[-32000:], "stderr": error[-32000:], "return_code": status}


@app.post("/kvm-api/hosts/{host_id}/network-connections/actions", dependencies=[Depends(require_auth)])
def control_network_connection(host_id: str, payload: NetworkConnectionAction, actor: str = Depends(require_auth)) -> dict[str, bool]:
    if not re.fullmatch(r"[A-Fa-f0-9-]{16,64}", payload.uuid):
        raise HTTPException(422, "Invalid NetworkManager connection ID")
    host = cockpit_host_record(host_id)
    script = r'''import shutil,subprocess,sys
action,uuid=sys.argv[1:]
if not shutil.which('nmcli'): raise SystemExit('NetworkManager is not installed')
listing=subprocess.run(['nmcli','-t','-f','UUID','connection','show'],capture_output=True,text=True,timeout=20)
if listing.returncode or uuid not in listing.stdout.splitlines(): raise SystemExit('Network connection not found')
r=subprocess.run(['nmcli','connection',action,uuid],capture_output=True,text=True,timeout=60)
if r.returncode: raise SystemExit(r.stderr.strip() or r.stdout.strip() or 'NetworkManager action failed')
'''
    try:
        run_sudo_python(host, script, [payload.action, payload.uuid], timeout=75)
    except Exception as exc:
        record_audit(actor, f"network-connection.{payload.action}", f"{host_id}/{payload.uuid}", "failure", str(exc)[:500])
        raise HTTPException(502, f"Could not change the network connection: {exc}") from exc
    record_audit(actor, f"network-connection.{payload.action}", f"{host_id}/{payload.uuid}")
    return {"success": True}


@app.post("/kvm-api/hosts/{host_id}/accounts/actions", dependencies=[Depends(require_auth)])
def control_account(host_id: str, payload: AccountAction, actor: str = Depends(require_auth)) -> dict[str, bool]:
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", payload.username):
        raise HTTPException(422, "Invalid account name")
    host = cockpit_host_record(host_id)
    if payload.username == host["username"] and payload.action == "lock":
        raise HTTPException(422, "The SSH account used by this extension cannot be locked here")
    if payload.username == "root" and payload.action == "lock":
        raise HTTPException(422, "The root account cannot be locked here")
    if payload.action == "password" and (not payload.password or any(char in payload.password for char in ("\n", "\r", ":"))):
        raise HTTPException(422, "Enter a new password with at least 8 characters; colons and line breaks are not allowed")
    script = r'''import pwd,subprocess,sys
username,action=sys.argv[1:]
try: account=pwd.getpwnam(username)
except KeyError: raise SystemExit('Account not found')
if account.pw_uid==0 and action=='lock': raise SystemExit('The root account cannot be locked here')
if action=='lock': args=['usermod','--lock',username]
elif action=='unlock': args=['usermod','--unlock',username]
elif action=='password':
    print('KVM_STDIN_READY',flush=True)
    password=sys.stdin.readline().rstrip('\n')
    if len(password)<8: raise SystemExit('Password must contain at least 8 characters')
    result=subprocess.run(['chpasswd'],input=f'{username}:{password}\n',text=True,capture_output=True)
    if result.returncode: raise SystemExit(result.stderr.strip() or 'Could not update password')
    sys.exit(0)
else: raise SystemExit('Invalid account action')
result=subprocess.run(args,capture_output=True,text=True)
if result.returncode: raise SystemExit(result.stderr.strip() or result.stdout.strip() or 'Account action failed')
'''
    extra_input = (payload.password or "") + "\n" if payload.action == "password" else None
    try:
        run_sudo_python(host, script, [payload.username, payload.action], timeout=30, stdin_data=extra_input)
    except Exception as exc:
        record_audit(actor, f"account.{payload.action}", f"{host_id}/{payload.username}", "failure", str(exc)[:500])
        raise HTTPException(502, f"Could not update the account: {exc}") from exc
    record_audit(actor, f"account.{payload.action}", f"{host_id}/{payload.username}")
    return {"success": True}


@app.post("/kvm-api/hosts/{host_id}/services/actions", dependencies=[Depends(require_auth)])
def control_service(host_id: str, payload: ServiceAction, service_name: str, actor: str = Depends(require_auth)) -> dict[str, bool]:
    if not re.fullmatch(r"[A-Za-z0-9_.@:-]+", service_name):
        raise HTTPException(422, "Invalid service name")
    host = cockpit_host_record(host_id)
    try:
        run_sudo_python(host, SERVICE_ACTION_SCRIPT, [payload.action, service_name], timeout=45)
    except Exception as exc:
        record_audit(actor, f"service.{payload.action}", f"{host_id}/{service_name}", "failure", str(exc))
        raise HTTPException(502, f"Could not perform the service action: {exc}") from exc
    record_audit(actor, f"service.{payload.action}", f"{host_id}/{service_name}")
    return {"success": True}


def run_sudo_python(host: dict[str, Any], script: str, args: list[str] | None = None, timeout: int = 30, stdin_data: str | None = None) -> str:
    client = ssh_client_for_host(host)
    command = f"sudo -S -p '' python3 -c {shlex.quote(script)}"
    if args:
        command += " " + " ".join(shlex.quote(arg) for arg in args)
    try:
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        stdin.write(host["password"] + "\n")
        stdin.flush()
        prelude = ""
        if stdin_data:
            ready, _, _ = select.select([stdout.channel], [], [], 8)
            if not ready:
                raise RuntimeError("The remote account command did not request its password input")
            prelude = stdout.channel.recv(4096).decode("utf-8", "replace")
            if "KVM_STDIN_READY" not in prelude:
                raise RuntimeError("The remote account command did not reach its password prompt")
            stdin.write(stdin_data)
            stdin.flush()
        stdin.channel.shutdown_write()
        output = (prelude + stdout.read().decode("utf-8", "replace")).strip()
        error = stderr.read().decode("utf-8", "replace").strip()
        if stdout.channel.recv_exit_status():
            raise RuntimeError(error or output or "Could not run the remote command with sudo")
        return output
    finally:
        client.close()


@app.post("/kvm-api/hosts/{host_id}/vms/actions", dependencies=[Depends(require_auth)])
def control_vm(host_id: str, payload: VMAction, vm_name: str, actor: str = Depends(require_auth)) -> dict[str, bool]:
    host = cockpit_host_record(host_id)
    encoded_name = base64.b64encode(vm_name.encode()).decode()
    action_script = r'''import base64,subprocess,sys
name=base64.b64decode(sys.argv[1]).decode()
action=sys.argv[2]
if action not in ('start','shutdown','reboot','pause','resume'): raise SystemExit('Action not allowed')
listing=subprocess.run(['virsh','-c','qemu:///system','list','--all','--name'],capture_output=True,text=True,timeout=20)
if listing.returncode: raise SystemExit(listing.stderr.strip() or listing.stdout.strip() or 'Could not query libvirt')
if name not in listing.stdout.splitlines(): raise SystemExit('Virtual machine not found')
command={'pause':'suspend','resume':'resume'}.get(action,action)
result=subprocess.run(['virsh','-c','qemu:///system',command,name],capture_output=True,text=True,timeout=30)
if result.returncode: raise SystemExit(result.stderr.strip() or result.stdout.strip() or 'The libvirt action failed')
'''
    try:
        run_sudo_python(host, action_script, [encoded_name, payload.action], timeout=45)
    except Exception as exc:
        record_audit(actor, f"vm.{payload.action}", f"{host_id}/{vm_name}", "failure", str(exc))
        raise HTTPException(502, f"Could not perform the libvirt action: {exc}") from exc
    record_audit(actor, f"vm.{payload.action}", f"{host_id}/{vm_name}")
    return {"success": True}


@app.post("/kvm-api/hosts/{host_id}/vms/autostart", dependencies=[Depends(require_auth)])
def set_vm_autostart(host_id: str, payload: VMAutostart, vm_name: str, actor: str = Depends(require_auth)) -> dict[str, bool]:
    host = cockpit_host_record(host_id)
    encoded_name = base64.b64encode(vm_name.encode()).decode()
    action_script = r'''import base64,subprocess,sys
name=base64.b64decode(sys.argv[1]).decode()
enabled=sys.argv[2]=='true'
listing=subprocess.run(['virsh','-c','qemu:///system','list','--all','--name'],capture_output=True,text=True,timeout=20)
if listing.returncode: raise SystemExit(listing.stderr.strip() or listing.stdout.strip() or 'Could not query libvirt')
if name not in listing.stdout.splitlines(): raise SystemExit('Virtual machine not found')
args=['virsh','-c','qemu:///system','autostart']
if not enabled: args.append('--disable')
args.append(name)
result=subprocess.run(args,capture_output=True,text=True,timeout=30)
if result.returncode: raise SystemExit(result.stderr.strip() or result.stdout.strip() or 'Could not update autostart')
'''
    try:
        run_sudo_python(host, action_script, [encoded_name, str(payload.enabled).lower()], timeout=45)
    except Exception as exc:
        record_audit(actor, "vm.autostart", f"{host_id}/{vm_name}", "failure", str(exc))
        raise HTTPException(502, f"Could not change autostart: {exc}") from exc
    record_audit(actor, "vm.autostart", f"{host_id}/{vm_name}", detail=f"enabled={payload.enabled}")
    return {"success": True}


@app.get("/kvm-api/audit", dependencies=[Depends(require_auth)])
def list_audit(limit: int = 100) -> list[dict[str, Any]]:
    limit = min(max(limit, 1), 500)
    with connect_db() as db:
        rows = db.execute("SELECT occurred_at,actor,action,target,outcome,detail FROM audit_events ORDER BY occurred_at DESC LIMIT ?", (limit,))
        return [dict(row) for row in rows]
