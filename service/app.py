"""Early KVM host inventory API. Restrict this service to an authenticated proxy."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import logging
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
import time
from concurrent.futures import ThreadPoolExecutor
import urllib.error
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
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
RANCHER_CA_FILE = os.getenv("RANCHER_CA_FILE", "").strip() or None
if len(credential_key) < 32:
    raise RuntimeError("Configure KVM_CREDENTIAL_KEY with at least 32 random characters")
FERNET_KEY = base64.urlsafe_b64encode(hashlib.sha256(credential_key.encode()).digest())
cipher = Fernet(FERNET_KEY)
app = FastAPI(title="Rancher KVM Host API", version="0.7.42")
performance_logger = logging.getLogger("kvm.performance")
RANCHER_PUBLIC_ORIGIN = os.getenv("RANCHER_PUBLIC_ORIGIN", "https://rancher.example.com").rstrip("/")
RANCHER_PUBLIC_HOST = urlsplit(RANCHER_PUBLIC_ORIGIN).netloc
COCKPIT_PORT = 9090
try:
    AUDIT_RETENTION_DAYS = max(1, int(os.getenv("KVM_AUDIT_RETENTION_DAYS", "90")))
except ValueError:
    AUDIT_RETENTION_DAYS = 90
try:
    SLOW_REQUEST_THRESHOLD_MS = max(0, int(os.getenv("KVM_SLOW_REQUEST_MS", "1000")))
except ValueError:
    SLOW_REQUEST_THRESHOLD_MS = 1000


@app.middleware("http")
async def disable_api_caching(request: Request, call_next):
    started_at = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        elapsed_ms = (time.perf_counter() - started_at) * 1000
        route = request.scope.get("route")
        route_path = getattr(route, "path", "unmatched")
        performance_logger.error(
            "api_request_failed method=%s route=%s elapsed_ms=%.1f",
            request.method,
            route_path,
            elapsed_ms,
        )
        raise

    elapsed_ms = (time.perf_counter() - started_at) * 1000
    if response.status_code >= 500:
        route = request.scope.get("route")
        performance_logger.error(
            "api_request_failed method=%s route=%s status=%s elapsed_ms=%.1f",
            request.method,
            getattr(route, "path", "unmatched"),
            response.status_code,
            elapsed_ms,
        )
    elif elapsed_ms >= SLOW_REQUEST_THRESHOLD_MS:
        route = request.scope.get("route")
        performance_logger.warning(
            "api_request_slow method=%s route=%s status=%s elapsed_ms=%.1f",
            request.method,
            getattr(route, "path", "unmatched"),
            response.status_code,
            elapsed_ms,
        )
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
    with connect_db() as db:
        db.execute("CREATE INDEX IF NOT EXISTS idx_audit_events_occurred_at ON audit_events(occurred_at DESC)")
        db.execute(
            "DELETE FROM audit_events WHERE occurred_at < ?",
            ((datetime.now(timezone.utc) - timedelta(days=AUDIT_RETENTION_DAYS)).isoformat(),),
        )


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


class VMConfig(BaseModel):
    vcpus: int = Field(ge=1, le=512)
    memory_mib: int = Field(ge=128, le=1048576)


class VMDetailsConfig(BaseModel):
    description: str = Field(default="", max_length=256)
    cpu_mode: Literal["host-model", "host-passthrough", "custom"] = "host-model"
    cpu_model: str | None = Field(default=None, max_length=100)
    boot_order: list[Literal["hd", "cdrom", "network"]] = Field(min_length=1, max_length=3)
    autostart: bool = False


class VMCreate(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    pool: str = Field(min_length=1, max_length=128)
    volume: str = Field(min_length=1, max_length=128)
    network: str = Field(min_length=1, max_length=128)
    vcpus: int = Field(ge=1, le=512)
    memory_mib: int = Field(ge=128, le=1048576)
    iso_path: str | None = Field(default=None, max_length=1024)
    autostart: bool = False


class VMSnapshotAction(BaseModel):
    action: Literal["create", "delete", "revert"]
    name: str = Field(min_length=1, max_length=64)
    description: str | None = Field(default=None, max_length=256)


class VMDeviceAction(BaseModel):
    action: Literal["attach_disk", "detach_disk", "attach_network", "detach_network"]
    pool: str | None = Field(default=None, max_length=128)
    volume: str | None = Field(default=None, max_length=128)
    target: str | None = Field(default=None, max_length=16)
    network: str | None = Field(default=None, max_length=128)
    mac: str | None = Field(default=None, max_length=32)


class ServiceAction(BaseModel):
    action: Literal["start", "stop", "restart"]


class NamedAdminAction(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    action: Literal["start", "stop", "enable", "disable"]


class StoragePoolConfig(BaseModel):
    action: Literal["create", "edit", "delete"]
    name: str = Field(min_length=1, max_length=128)
    target: str | None = Field(default=None, max_length=512)


class StorageVolumeConfig(BaseModel):
    action: Literal["create", "delete", "resize"]
    pool: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=128)
    capacity_bytes: int | None = Field(default=None, ge=1048576, le=10995116277760)
    format: Literal["qcow2", "raw"] = "qcow2"
    vm_name: str | None = Field(default=None, min_length=1, max_length=128)


class NetworkConnectionConfig(BaseModel):
    uuid: str = Field(min_length=16, max_length=64)
    method: Literal["auto", "manual", "shared", "link-local", "disabled"]
    addresses: list[str] = Field(default_factory=list, max_length=16)
    gateway: str | None = Field(default=None, max_length=64)
    dns: list[str] = Field(default_factory=list, max_length=8)
    ipv6_method: Literal["auto", "manual", "disabled"] = "auto"
    ipv6_addresses: list[str] = Field(default_factory=list, max_length=16)
    ipv6_gateway: str | None = Field(default=None, max_length=64)
    ipv6_dns: list[str] = Field(default_factory=list, max_length=8)
    autoconnect: bool = True


class LibvirtNetworkConfig(BaseModel):
    action: Literal["create", "edit", "delete"]
    name: str = Field(min_length=1, max_length=64)
    forward_mode: Literal["nat", "route", "bridge", "none"] = "nat"
    bridge: str | None = Field(default=None, max_length=15)
    ipv4_address: str | None = Field(default=None, max_length=64)
    dhcp_start: str | None = Field(default=None, max_length=45)
    dhcp_end: str | None = Field(default=None, max_length=45)
    autostart: bool = False
    start_after_create: bool = True


class RepositoryAction(BaseModel):
    alias: str = Field(min_length=1, max_length=128)
    action: Literal["enable", "disable", "refresh", "add", "remove"]
    name: str | None = Field(default=None, max_length=256)
    uri: str | None = Field(default=None, max_length=2048)


class SecurityModeAction(BaseModel):
    mode: Literal["enforcing", "permissive"]


class TerminalCommand(BaseModel):
    command: str = Field(min_length=1, max_length=4000)


class NetworkConnectionAction(BaseModel):
    uuid: str = Field(min_length=1, max_length=64)
    action: Literal["up", "down"]


class AccountAction(BaseModel):
    username: str = Field(min_length=1, max_length=32)
    action: Literal["lock", "unlock", "password", "create", "edit", "delete"]
    password: str | None = Field(default=None, min_length=8, max_length=1024)
    shell: str | None = Field(default=None, max_length=256)
    home: str | None = Field(default=None, max_length=512)
    groups: list[str] = Field(default_factory=list, max_length=64)


class SubscriptionAction(BaseModel):
    action: Literal["register", "replace", "deregister", "activate_extension", "deactivate_extension"]
    email: str | None = Field(default=None, max_length=320)
    regcode: str | None = Field(default=None, max_length=256)
    product: str | None = Field(default=None, max_length=256)


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


@dataclass(frozen=True)
class AuthorizationContext:
    user_id: str
    roles: frozenset[str]
    access_level: str


ROLE_CONFIG = {
    "viewer": {role.strip() for role in os.getenv("KVM_VIEWER_GLOBAL_ROLES", "").split(",") if role.strip()},
    "vm_operator": {role.strip() for role in os.getenv("KVM_VM_OPERATOR_GLOBAL_ROLES", "").split(",") if role.strip()},
    "host_operator": {role.strip() for role in os.getenv("KVM_HOST_OPERATOR_GLOBAL_ROLES", "").split(",") if role.strip()},
    # Keep the original setting as the host-admin tier for existing installs.
    "host_admin": {role.strip() for role in os.getenv("KVM_ALLOWED_GLOBAL_ROLES", "admin").split(",") if role.strip()},
}


ROLE_RANK = {"viewer": 1, "vm_operator": 2, "host_operator": 3, "host_admin": 4}
PERMISSION_RANK = {"viewer": 1, "vm_operator": 2, "host_resources": 3, "host_admin": 4}


def authenticate_request(authorization: str | None = None, cookie: str | None = None) -> AuthorizationContext:
    """Resolve the Rancher identity and its configured KVM access tier."""
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
    access_level = ""
    for level, configured_roles in ROLE_CONFIG.items():
        if roles.intersection(configured_roles) and ROLE_RANK[level] > ROLE_RANK.get(access_level, 0):
            access_level = level
    if not access_level:
        raise HTTPException(403, "Your Rancher global role is not authorized to access KVM hosts")
    return AuthorizationContext(str(user_id or user.get("id") or "unknown"), frozenset(roles), access_level)


def require_permission(permission: str):
    required_rank = PERMISSION_RANK[permission]

    def dependency(
        authorization: str | None = Header(default=None),
        cookie: str | None = Header(default=None),
    ) -> AuthorizationContext:
        context = authenticate_request(authorization, cookie)
        if ROLE_RANK[context.access_level] < required_rank:
            role_name = "host operator" if permission == "host_resources" else permission.replace("_", " ")
            raise HTTPException(403, f"The {role_name} role is required for this KVM operation")
        return context

    return dependency


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


VM_CONSOLE_SCRIPT = r'''import subprocess, sys, os
name = sys.argv[1]
base = ['virsh', '-c', 'qemu:///system']
listing = subprocess.run(base + ['list', '--all', '--name'], capture_output=True, text=True, timeout=20)
if listing.returncode:
    raise SystemExit(listing.stderr.strip() or listing.stdout.strip() or 'Could not query libvirt')
if name not in [item.strip() for item in listing.stdout.splitlines()]:
    raise SystemExit('Virtual machine not found')
state = subprocess.run(base + ['domstate', name], capture_output=True, text=True, timeout=15)
if state.returncode or state.stdout.strip().lower() != 'running':
    raise SystemExit('The virtual machine must be running to open its serial console')
serial = subprocess.run(base + ['ttyconsole', name], capture_output=True, text=True, timeout=15)
if serial.returncode or not serial.stdout.strip():
    raise SystemExit('This virtual machine has no serial console configured. Add a serial console to its libvirt definition and enable a login prompt in the guest (for example, serial-getty@ttyS0).')
os.execvp('virsh', base + ['console', name])
'''


def open_vm_console(host: dict[str, Any], vm_name: str) -> tuple[paramiko.SSHClient, paramiko.Channel]:
    """Open a pinned SSH session and attach a PTY to an existing VM serial console."""
    client = ssh_client_for_host(host)
    try:
        _stdin, stdout, _stderr = client.exec_command('sudo -n -v', timeout=8)
        passwordless_sudo = stdout.channel.recv_exit_status() == 0
        if not passwordless_sudo and not host.get('password'):
            raise RuntimeError('The imported SSH account needs passwordless sudo to open a VM console')
        channel = client.get_transport().open_session(timeout=10)
        channel.get_pty(term='xterm-256color', width=100, height=30)
        sudo_args = '-n' if passwordless_sudo else "-S -p ''"
        command = f"sudo {sudo_args} python3 -c {shlex.quote(VM_CONSOLE_SCRIPT)} {shlex.quote(vm_name)}"
        if not passwordless_sudo:
            # Paramiko's Channel.get_pty does not accept an echo flag. Wait for
            # the remote PTY to disable echo before sending the host password;
            # otherwise a fast send can race stty and leak it into the console.
            marker = b'\x1eKVM_SUDO_READY\x1e'
            command = f"stty -echo && printf '\\036KVM_SUDO_READY\\036' && {command}"
        channel.exec_command(command)
        if not passwordless_sudo:
            deadline = time.monotonic() + 8
            marker_buffer = bytearray()
            channel.settimeout(0.25)
            while marker not in marker_buffer:
                if time.monotonic() >= deadline:
                    raise RuntimeError('Could not prepare the secure host terminal for sudo')
                try:
                    chunk = channel.recv(1)
                except socket.timeout:
                    continue
                if not chunk:
                    raise RuntimeError('The remote host closed the terminal before sudo started')
                marker_buffer.extend(chunk)
            channel.settimeout(None)
            channel.sendall((host['password'] + '\n').encode())
        return client, channel
    except Exception:
        client.close()
        raise


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


@app.post("/kvm-api/hosts/{host_id}/cockpit")
def open_cockpit(host_id: str, request: Request, access: AuthorizationContext = Depends(require_permission("host_admin"))) -> RedirectResponse:
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
        require_permission("host_admin")(request.headers.get("authorization"), request.headers.get("cookie"))
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
        require_permission("host_admin")(websocket.headers.get("authorization"), websocket.headers.get("cookie"))
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


@app.websocket("/kvm-api/hosts/{host_id}/vms/console")
async def vm_console_websocket(host_id: str, websocket: WebSocket) -> None:
    """Relay an authenticated browser terminal to an imported VM's libvirt console."""
    if websocket.headers.get("origin") != RANCHER_PUBLIC_ORIGIN:
        await websocket.close(code=4403)
        return
    try:
        actor = await asyncio.to_thread(
            require_permission("vm_operator"), websocket.headers.get("authorization"), websocket.headers.get("cookie")
        )
    except HTTPException as exc:
        await websocket.close(code=4403 if exc.status_code == 403 else 4401)
        return

    vm_name = websocket.query_params.get("vm_name", "")
    if not vm_name or len(vm_name) > 128 or "\x00" in vm_name:
        await websocket.close(code=4400)
        return
    try:
        host = cockpit_host_record(host_id)
    except HTTPException as exc:
        await websocket.close(code=4404 if exc.status_code == 404 else 1011)
        return

    await websocket.accept()
    client: paramiko.SSHClient | None = None
    channel: paramiko.Channel | None = None
    outcome = "failure"
    detail = "Console session closed before connection"
    try:
        client, channel = await asyncio.to_thread(open_vm_console, host, vm_name)
        await websocket.send_text("KVM_CONTROL:" + json.dumps({"type": "status", "status": "connected"}))
        outcome = "success"
        detail = "Serial console session opened; terminal input is not stored"
        while True:
            if channel.recv_ready():
                data = await asyncio.to_thread(channel.recv, 65536)
                if not data:
                    break
                await websocket.send_bytes(data)
            elif channel.exit_status_ready():
                break

            try:
                message = await asyncio.wait_for(websocket.receive(), timeout=0.04)
            except asyncio.TimeoutError:
                continue
            if message["type"] == "websocket.disconnect":
                break
            if message.get("bytes") is not None:
                await asyncio.to_thread(channel.sendall, message["bytes"])
                continue
            data = message.get("text", "")
            if data.startswith("KVM_CONTROL:"):
                try:
                    control = json.loads(data[len("KVM_CONTROL:"):])
                except (json.JSONDecodeError, TypeError):
                    control = None
                if isinstance(control, dict) and control.get("type") == "resize":
                    cols = control.get("cols")
                    rows = control.get("rows")
                    if isinstance(cols, int) and isinstance(rows, int):
                        await asyncio.to_thread(channel.resize_pty, width=max(20, min(cols, 300)), height=max(5, min(rows, 120)))
                    continue
            await asyncio.to_thread(channel.sendall, data.encode("utf-8"))
    except Exception as exc:
        detail = str(exc)[:500] or "Could not open the VM serial console"
        try:
            await websocket.send_text("KVM_CONTROL:" + json.dumps({"type": "error", "message": detail}))
        except Exception:
            pass
    finally:
        if channel is not None:
            channel.close()
        if client is not None:
            client.close()
        try:
            await asyncio.to_thread(record_audit, actor.user_id, "vm.console", f"{host_id}/{vm_name}", outcome, detail)
        except Exception:
            pass
        try:
            await websocket.close(code=1000)
        except Exception:
            pass


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
            "|| echo libvirt-unavailable; "
            "os_id=$(awk -F= '$1 == \"ID\" {gsub(/\"/, \"\", $2); print $2; exit}' /etc/os-release 2>/dev/null); "
            "os_version=$(awk -F= '$1 == \"VERSION_ID\" {gsub(/\"/, \"\", $2); print $2; exit}' /etc/os-release 2>/dev/null); "
            "printf 'KVM_OS=%s|%s\\n' \"${os_id:-unknown}\" \"${os_version:-unknown}\"; "
            "if command -v virsh >/dev/null 2>&1; then "
            "printf 'KVM_LIBVIRT=%s\\n' \"$(virsh --version 2>/dev/null | awk '{print $NF}')\"; "
            "else printf 'KVM_LIBVIRT=unavailable\\n'; fi"
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
        os_release = next((line.removeprefix("KVM_OS=") for line in lines if line.startswith("KVM_OS=")), "unknown|unknown")
        os_id, _, os_version = os_release.partition("|")
        libvirt_version = next((line.removeprefix("KVM_LIBVIRT=") for line in lines if line.startswith("KVM_LIBVIRT=")), "unavailable")
        supported_releases = {
            "15.3", "15.4", "15.5", "15.6", "15.7",
            "15-SP3", "15-SP4", "15-SP5", "15-SP6", "15-SP7", "16.0",
        }
        compatibility_supported = os_id.lower() == "sles" and os_version in supported_releases and libvirt_version != "unavailable"
        return {
            "hostname": hostname, "cpu_count": cpu_count,
            "memory_total_bytes": memory_total_bytes, "status": "ready",
            "os_id": os_id, "os_version": os_version,
            "libvirt_version": libvirt_version,
            "compatibility_supported": compatibility_supported,
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


@app.get("/kvm-api/hosts", dependencies=[Depends(require_permission("viewer"))])
def list_hosts() -> list[dict[str, Any]]:
    with connect_db() as db:
        return [public_host(row) for row in db.execute("SELECT * FROM hosts ORDER BY name")]


HA_READINESS_SCRIPT = r'''import json,re,shutil,subprocess
from datetime import datetime,timezone
def run(args, timeout=15):
    try:
        result=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
        return result.returncode,(result.stdout or result.stderr).strip()
    except Exception as error:
        return 127,str(error)
extensions=[]
extension_error=''
if shutil.which('SUSEConnect'):
    code,text=run(['SUSEConnect','--list-extensions'],30)
    if code:
        extension_error=text
    else:
        label=''
        for line in text.splitlines():
            item=line.strip()
            match=re.search(r'SUSEConnect\s+(-d\s+)?-p\s+(\S+)(.*)$',item)
            if match:
                product=match.group(2)
                if product.startswith('sle-ha/'):
                    extensions.append({'product':product,'active':bool(match.group(1)),'name':label.strip()})
                label=''
            elif item.upper().startswith(('AVAILABLE EXTENSIONS','REMARKS','MORE INFORMATION')):
                label=''
            elif item and not item.startswith(('Activate with:','Deactivate with:','(')):
                label=item
ha=next((item for item in extensions if item['active']),None)
available=next(iter(extensions),None)
services={}
for name in ('pacemaker','corosync','hawk'):
    code,text=run(['systemctl','is-active',name],8)
    services[name]=text.splitlines()[0] if text else ('missing' if code==4 else 'unknown')
commands={name:shutil.which(name) is not None for name in ('crm','crm_mon','corosync-cfgtool','stonith_admin')}
cluster_status=''
cluster_detected=False
if commands['crm_mon'] and services['pacemaker']=='active':
    code,cluster_status=run(['crm_mon','-1','-r'],15)
    cluster_detected=code==0
print(json.dumps({'suseconnect_available':bool(shutil.which('SUSEConnect')),'ha_available':available is not None,
    'ha_active':ha is not None,'ha_product':(ha or available or {}).get('product',''),
    'ha_product_name':(ha or available or {}).get('name',''),'extension_error':extension_error,
    'commands':commands,'services':services,'cluster_detected':cluster_detected,
    'checked_at':datetime.now(timezone.utc).isoformat(),
    'cluster_summary':'\n'.join(cluster_status.splitlines()[:8]) if cluster_status else ''}))
'''


@app.get("/kvm-api/clusters/readiness", dependencies=[Depends(require_permission("viewer"))])
def get_cluster_readiness() -> list[dict[str, Any]]:
    """Read SUSE HA registration and cluster-stack status from imported hosts."""
    with connect_db() as db:
        rows=[dict(row) for row in db.execute('SELECT * FROM hosts ORDER BY name COLLATE NOCASE')]

    def inspect(row: dict[str, Any]) -> dict[str, Any]:
        item=public_host(row)
        try:
            row['password']=cipher.decrypt(row['password'].encode()).decode()
            decrypt_host_credentials(row)
            output=run_sudo_python(row,HA_READINESS_SCRIPT,timeout=55)
            item['ha']=json.loads(output or '{}')
        except Exception as error:
            item['ha']={'suseconnect_available':False,'ha_available':False,'ha_active':False,
                'ha_product':'','commands':{},'services':{},'cluster_detected':False,
                'cluster_summary':'','inspection_error':str(error)[:400]}
        return item

    with ThreadPoolExecutor(max_workers=3) as executor:
        return list(executor.map(inspect,rows))


@app.get("/kvm-api/permissions")
def get_permissions(access: AuthorizationContext = Depends(require_permission("viewer"))) -> dict[str, bool | str]:
    rank = ROLE_RANK[access.access_level]
    return {
        "accessLevel": access.access_level,
        "canView": True,
        "canOperateVms": rank >= PERMISSION_RANK["vm_operator"],
        "canManageHostResources": rank >= PERMISSION_RANK["host_resources"],
        "canAdministerHost": rank >= PERMISSION_RANK["host_admin"],
    }


@app.post("/kvm-api/hosts", status_code=201)
def create_host(payload: HostInput, access: AuthorizationContext = Depends(require_permission("host_admin"))) -> dict[str, Any]:
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
    record_audit(access.user_id, "host.import", host_id, detail=f"{payload.name} ({payload.address}:{payload.port})")
    return created


@app.post("/kvm-api/hosts/probe")
def probe_host(payload: HostInput, access: AuthorizationContext = Depends(require_permission("host_admin"))) -> dict[str, Any]:
    """Validate an import without persisting credentials or host data."""
    if not payload.password:
        raise HTTPException(422, "A password is required to import the host")
    host = payload.model_dump() | {"private_key": payload.ssh_private_key, "key_passphrase": payload.ssh_key_passphrase}
    checks: list[dict[str, str]] = []
    try:
        facts = probe(host, accept_new_host_key=payload.accept_new_host_key)
        checks.append({"id": "ssh_libvirt", "status": "success", "message": f"SSH identity verified; libvirt ready on {facts['hostname']}"})
    except Exception as exc:
        return {"ok": False, "checks": [{"id": "ssh_libvirt", "status": "failure", "message": str(exc)[:400]}], "facts": None}
    compatibility_status = "success" if facts["compatibility_supported"] else "warning"
    detected_os = f"{facts['os_id']} {facts['os_version']}".strip()
    checks.append({
        "id": "compatibility",
        "status": compatibility_status,
        "os_id": facts["os_id"],
        "os_version": facts["os_version"],
        "libvirt_version": facts["libvirt_version"],
        "message": (
            f"Supported host baseline: {detected_os}; libvirt {facts['libvirt_version']} detected"
            if facts["compatibility_supported"]
            else f"Compatibility is not confirmed for {detected_os} with libvirt {facts['libvirt_version']}; review the supported host matrix before importing"
        ),
    })
    try:
        client = paramiko.SSHClient()
        key_type, key_data = facts["ssh_host_key"].split(" ", 1)
        client.get_host_keys().add(host["address"] if host["port"] == 22 else f'[{host["address"]}]:{host["port"]}', key_type, paramiko.PKey.from_type_string(key_type, base64.b64decode(key_data)))
        client.set_missing_host_key_policy(PinnedHostKeyPolicy())
        connect_ssh(client, host)
        _, stdout, _ = client.exec_command("sudo -n true; printf 'SUDO=%s\\n' $?; command -v nmcli >/dev/null 2>&1; printf 'NMCLI=%s\\n' $?; command -v cockpit-ws >/dev/null 2>&1; printf 'COCKPIT=%s\\n' $?", timeout=15)
        lines = stdout.read().decode("utf-8", "replace")
        client.close()
        for key, label in (("SUDO", "sudo without password"), ("NMCLI", "NetworkManager CLI"), ("COCKPIT", "Cockpit service")):
            value = re.search(rf"{key}=(\d+)", lines)
            status = "success" if value and value.group(1) == "0" else "warning"
            checks.append({"id": key.lower(), "status": status, "message": f"{label}: {'available' if status == 'success' else 'not detected (some management actions may be unavailable)'}"})
    except Exception as exc:
        checks.append({"id": "optional", "status": "warning", "message": f"Optional capability check unavailable: {str(exc)[:250]}"})
    return {"ok": True, "checks": checks, "facts": {k: facts[k] for k in ("hostname", "cpu_count", "memory_total_bytes", "status", "os_id", "os_version", "libvirt_version", "compatibility_supported")}}


@app.put("/kvm-api/hosts/{host_id}")
def update_host(host_id: str, payload: HostInput, access: AuthorizationContext = Depends(require_permission("host_admin"))) -> dict[str, Any]:
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
    record_audit(access.user_id, "host.update", host_id, detail=f"{payload.name} ({payload.address}:{payload.port})")
    return updated


@app.post("/kvm-api/hosts/{host_id}/refresh")
def refresh_host(host_id: str, access: AuthorizationContext = Depends(require_permission("vm_operator"))) -> dict[str, Any]:
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
    record_audit(access.user_id, "host.refresh", host_id, "success" if refreshed["status"] == "ready" else "failure", refreshed.get("last_error"))
    return refreshed


@app.post("/kvm-api/hosts/refresh-stale")
def refresh_stale_hosts(max_age_seconds: int = 120, limit: int = 10, access: AuthorizationContext = Depends(require_permission("viewer"))) -> list[dict[str, Any]]:
    """Refresh a bounded number of stale host facts with at most two SSH sessions at a time."""
    max_age_seconds = min(max(30, max_age_seconds), 3600)
    limit = min(max(1, limit), 10)
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=max_age_seconds)).isoformat()
    with connect_db() as db:
        rows = [dict(row) for row in db.execute("SELECT * FROM hosts ORDER BY COALESCE(last_checked_at,'') ASC LIMIT ?", (limit * 4,))]
    stale = [row for row in rows if not row.get("last_checked_at") or row["last_checked_at"] < cutoff][:limit]
    def update(row: dict[str, Any]) -> None:
        try:
            row["password"] = cipher.decrypt(row["password"].encode()).decode()
            decrypt_host_credentials(row)
            facts = probe(row, pinned_host_key=row.get("ssh_host_key"))
        except Exception as exc:
            facts = {"status": "unreachable", "last_checked_at": now(), "last_error": str(exc)[:500]}
        with connect_db() as db:
            db.execute("UPDATE hosts SET hostname=COALESCE(?,hostname),status=?,cpu_count=COALESCE(?,cpu_count),memory_total_bytes=COALESCE(?,memory_total_bytes),last_checked_at=?,last_error=?,ssh_host_key=COALESCE(?,ssh_host_key) WHERE id=?", (facts.get("hostname"), facts["status"], facts.get("cpu_count"), facts.get("memory_total_bytes"), facts["last_checked_at"], facts.get("last_error"), facts.get("ssh_host_key"), row["id"]))
    with ThreadPoolExecutor(max_workers=2) as executor:
        list(executor.map(update, stale))
    with connect_db() as db:
        return [public_host(row) for row in db.execute("SELECT * FROM hosts ORDER BY name COLLATE NOCASE")]


@app.delete("/kvm-api/hosts/{host_id}", status_code=204)
def delete_host(host_id: str, access: AuthorizationContext = Depends(require_permission("host_admin"))) -> Response:
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
    record_audit(access.user_id, "host.remove", host_id, detail=f"{current['name']} ({current['address']}:{current['port']})")
    return Response(status_code=204)


VM_LIST_SCRIPT = r'''import json, subprocess
def run(args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=20)
    if result.returncode:
        raise SystemExit(result.stderr.strip() or result.stdout.strip() or 'Comando libvirt falhou')
    return result.stdout
def addresses_for(name, state):
    sources = ('lease','agent') if 'running' in state.lower() else ('lease',)
    for source in sources:
        try:
            result = subprocess.run(['virsh','-c','qemu:///system','domifaddr',name,'--source',source], capture_output=True, text=True, timeout=3)
            if result.returncode:
                continue
            addresses = []
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 4 and ':' in parts[1] and '/' in parts[-1]:
                    address = parts[-1].split('/',1)[0]
                    if address not in addresses:
                        addresses.append(address)
            if addresses:
                return addresses
        except Exception:
            continue
    return []
names = run(['virsh','-c','qemu:///system','list','--all','--name']).splitlines()
items = []
for name in filter(None, (n.strip() for n in names)):
    info = {}
    for line in run(['virsh','-c','qemu:///system','dominfo',name]).splitlines():
        if ':' in line:
            key,value = line.split(':',1); info[key.strip().lower()] = value.strip()
    state = info.get('state') or run(['virsh','-c','qemu:///system','domstate',name]).strip()
    items.append({'name':name,'uuid':info.get('uuid',''),'state':state,
        'vcpus':int(info.get('cpu(s)','0') or '0'),'memory_kib':int(info.get('max memory','0').split()[0] or '0'),
        'autostart':info.get('autostart','unknown'),'ip_addresses':addresses_for(name,state)})
print(json.dumps(items))
'''

SERVICE_LIST_SCRIPT = r'''import json, subprocess
result = subprocess.run(['systemctl','list-units','--all','--type=service','--no-legend','--no-pager'], capture_output=True, text=True, timeout=30)
if result.returncode:
    raise SystemExit(result.stderr.strip() or result.stdout.strip() or 'Could not query system services')
services = []
for line in result.stdout.splitlines():
    parts = line.split(None,4)
    if len(parts) >= 4:
        services.append({'name':parts[0], 'load':parts[1], 'active':parts[2], 'sub':parts[3], 'description':parts[4] if len(parts) > 4 else ''})
print(json.dumps(services))
'''

VM_DETAIL_SCRIPT = r'''import json, subprocess, sys, xml.etree.ElementTree as ET
name = sys.argv[1]
def run(args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=20)
    if result.returncode:
        raise SystemExit(result.stderr.strip() or result.stdout.strip() or 'Comando libvirt falhou')
    return result.stdout
names = run(['virsh','-c','qemu:///system','list','--all','--name']).splitlines()
if name not in [item.strip() for item in names]: raise SystemExit('Virtual machine not found')
domain = ET.fromstring(run(['virsh','-c','qemu:///system','dumpxml',name]))
try:
    config_domain = ET.fromstring(run(['virsh','-c','qemu:///system','dumpxml','--inactive',name]))
except Exception:
    config_domain = domain
def memory_kib(element):
    node = element.find('./memory')
    if node is None or not (node.text or '').strip(): return 0
    value = int(node.text.strip())
    unit = (node.get('unit') or 'KiB').lower()
    factors = {'b':1/1024, 'bytes':1/1024, 'kib':1, 'kb':1, 'mib':1024, 'mb':1024, 'gib':1024*1024, 'gb':1024*1024, 'tib':1024*1024*1024, 'tb':1024*1024*1024}
    return int(value * factors.get(unit, 1))
config_vcpu = config_domain.find('./vcpu')
config_vcpus = int(config_vcpu.get('current') or (config_vcpu.text or '0')) if config_vcpu is not None else 0
config_memory_kib = memory_kib(config_domain)
devices = domain.find('./devices')
serial_console = bool(devices is not None and (devices.find('./serial') is not None or any(
    console.find('./target') is not None and console.find('./target').get('type') == 'serial'
    for console in devices.findall('./console')
)))
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
disk_formats = {}
for disk in devices.findall('./disk') if devices is not None else []:
    target = disk.find('./target')
    driver = disk.find('./driver')
    if target is not None and target.get('dev'):
        disk_formats[target.get('dev')] = driver.get('type','unknown') if driver is not None else 'unknown'
for line in run(['virsh','-c','qemu:///system','domblklist',name,'--details']).splitlines():
    parts = line.split(None,3)
    if len(parts) == 4 and parts[0] in ('file','block','dir','network','volume'):
        disks.append({'type':parts[0], 'device':parts[1], 'target':parts[2], 'source':parts[3], 'format':disk_formats.get(parts[2],'unknown')})
interfaces = []
for line in run(['virsh','-c','qemu:///system','domiflist',name]).splitlines():
    parts = line.split(None,4)
    if len(parts) == 5 and parts[0] not in ('Interface','-'):
        interfaces.append({'name':parts[0], 'type':parts[1], 'source':parts[2], 'model':parts[3], 'mac':parts[4], 'ip_addresses':[]})
# Query the guest agent first, then libvirt DHCP leases/ARP. This is read-only;
# guests without an agent or lease simply show no address in the UI.
by_mac = {item['mac'].lower(): item for item in interfaces if item.get('mac')}
for source in ('agent','lease','arp'):
    try:
        result = subprocess.run(['virsh','-c','qemu:///system','domifaddr',name,'--source',source], capture_output=True, text=True, timeout=10)
        if result.returncode:
            continue
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4 and ':' in parts[1] and '/' in parts[-1]:
                iface = by_mac.get(parts[1].lower())
                if iface and parts[-1] not in iface['ip_addresses']:
                    iface['ip_addresses'].append(parts[-1])
    except Exception:
        continue
snapshots = []
try:
    snapshot_names = run(['virsh','-c','qemu:///system','snapshot-list',name,'--name']).splitlines()
except Exception:
    snapshot_names = []
for snapshot_name in filter(str.strip,snapshot_names):
    try:
        snapshot_xml = ET.fromstring(run(['virsh','-c','qemu:///system','snapshot-dumpxml',name,snapshot_name]))
        snapshots.append({'name':snapshot_name.strip(),'state':snapshot_xml.findtext('./state','unknown'),
            'created_at':snapshot_xml.findtext('./creationTime',''),'description':snapshot_xml.findtext('./description','')})
    except Exception:
        snapshots.append({'name':snapshot_name.strip(),'state':'unknown','created_at':'','description':''})
snapshot_disks = [disk for disk in (config_domain.findall('./devices/disk')) if disk.get('device','disk') == 'disk' and disk.find('./readonly') is None]
snapshot_supported = bool(snapshot_disks) and all((disk.find('./driver').get('type','').lower() == 'qcow2') if disk.find('./driver') is not None else False for disk in snapshot_disks)
os_node=config_domain.find('./os')
os_type=os_node.find('./type') if os_node is not None else None
loader=os_node.find('./loader') if os_node is not None else None
cpu=config_domain.find('./cpu')
cpu_model=cpu.find('./model') if cpu is not None else None
boot_order=[node.get('dev','') for node in os_node.findall('./boot')] if os_node is not None else []
result = {'name':name, 'uuid':info.get('uuid',''), 'state':info.get('state') or run(['virsh','-c','qemu:///system','domstate',name]).strip(),
    'vcpus':int(info.get('cpu(s)','0') or '0'), 'current_vcpus':int(vcpu.get('current_live',vcpu.get('current_config','0')) or '0'),
    'max_vcpus':int(vcpu.get('maximum_live',vcpu.get('maximum_config','0')) or '0'), 'configured_vcpus':config_vcpus,
    'configured_memory_kib':config_memory_kib, 'live_memory_kib':memory_kib(domain),
    'live_vcpus':int(vcpu.get('current_live','0') or '0'), 'memory_kib':int(info.get('max memory','0').split()[0] or '0'),
    'used_memory_kib':int(info.get('used memory','0').split()[0] or '0'), 'persistent':info.get('persistent','unknown'),
    'autostart':'yes' if info.get('autostart','').lower() in ('enable','yes') else 'no', 'serial_console':serial_console, 'disks':disks, 'interfaces':interfaces,
    'description':config_domain.findtext('./description',''), 'cpu_mode':cpu.get('mode','host-model') if cpu is not None else 'host-model',
    'cpu_model':cpu_model.text.strip() if cpu_model is not None and cpu_model.text else '',
    'architecture':os_type.get('arch','') if os_type is not None else '', 'machine':os_type.get('machine','') if os_type is not None else '',
    'firmware':loader.text.strip() if loader is not None and loader.text else 'BIOS', 'boot_order':boot_order,
    'snapshots':snapshots, 'snapshot_supported':snapshot_supported}
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
    state=info.get('state') or run(['virsh','-c','qemu:///system','domstate',name]).strip()
    addresses=[]
    for source in (('lease','agent') if 'running' in state.lower() else ('lease',)):
        try:
            result=subprocess.run(['virsh','-c','qemu:///system','domifaddr',name,'--source',source],capture_output=True,text=True,timeout=3)
            if result.returncode: continue
            for line in result.stdout.splitlines():
                parts=line.split()
                if len(parts)>=4 and ':' in parts[1] and '/' in parts[-1]:
                    address=parts[-1].split('/',1)[0]
                    if address not in addresses: addresses.append(address)
            if addresses: break
        except Exception: continue
    return {'name':name,'uuid':info.get('uuid',''),'state':state,'ip_addresses':addresses,
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
        pool_xml=subprocess.run(['virsh','-c','qemu:///system','pool-dumpxml',pool_name],capture_output=True,text=True,timeout=20)
        pool_root=ET.fromstring(pool_xml.stdout) if pool_xml.returncode==0 else ET.Element('pool')
        pool_target=pool_root.findtext('./target/path') or ''
        storage_pools.append({'name':pool_name,'type':pool_root.get('type','unknown'),'target':pool_target,'state':pool_info.get('state','unknown'),'autostart':pool_info.get('autostart','no').lower(),'capacity':pool_info.get('capacity','—'),
            'allocation':pool_info.get('allocation','—'),'available':pool_info.get('available','—')})
except Exception as error: errors.append('storage pools: '+str(error))
libvirt_networks=[]
try:
    for line in run(['virsh','-c','qemu:///system','net-list','--all']).splitlines():
        parts=line.split()
        if len(parts)>=4 and parts[0].lower() not in ('name','-'):
            item={'name':parts[0],'state':parts[1],'autostart':parts[2],'persistent':parts[3],
                'forward_mode':'none','bridge':'','ipv4_address':'','ipv4_netmask':'','dhcp_start':'','dhcp_end':''}
            try:
                network_xml=ET.fromstring(run(['virsh','-c','qemu:///system','net-dumpxml',parts[0]]))
                forward=network_xml.find('./forward')
                if forward is not None: item['forward_mode']=forward.get('mode','none')
                bridge=network_xml.find('./bridge')
                if bridge is not None: item['bridge']=bridge.get('name','')
                ip=network_xml.find('./ip')
                if ip is not None:
                    item['ipv4_address']=ip.get('address',''); item['ipv4_netmask']=ip.get('netmask','')
                    dhcp=ip.find('./dhcp'); pool=dhcp.find('./range') if dhcp is not None else None
                    if pool is not None: item['dhcp_start']=pool.get('start',''); item['dhcp_end']=pool.get('end','')
            except Exception as network_error: errors.append('libvirt network '+parts[0]+': '+str(network_error))
            libvirt_networks.append(item)
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
            if len(parts)==4:
                detail=subprocess.run(['nmcli','-g','ipv4.method,ipv4.addresses,ipv4.gateway,ipv4.dns,ipv6.method,ipv6.addresses,ipv6.gateway,ipv6.dns,connection.autoconnect','connection','show',parts[1]],capture_output=True,text=True,timeout=15)
                values=detail.stdout.splitlines() if detail.returncode==0 else []
                network_connections.append({'name':parts[0],'uuid':parts[1],'type':parts[2],'device':parts[3],'active':parts[1] in active_uuids,
                    'ipv4_method':values[0] if len(values)>0 else 'auto',
                    'ipv4_addresses':[value for value in values[1].split(',') if value] if len(values)>1 else [],
                    'ipv4_gateway':values[2] if len(values)>2 else '',
                    'ipv4_dns':[value for value in values[3].split(',') if value] if len(values)>3 else [],
                    'ipv6_method':values[4] if len(values)>4 else 'auto',
                    'ipv6_addresses':[value for value in values[5].split(',') if value] if len(values)>5 else [],
                    'ipv6_gateway':values[6] if len(values)>6 else '',
                    'ipv6_dns':[value for value in values[7].split(',') if value] if len(values)>7 else [],
                    'autoconnect':values[8].lower() in ('yes','true','1') if len(values)>8 else True})
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


@app.get("/kvm-api/hosts/{host_id}/vms", dependencies=[Depends(require_permission("viewer"))])
def list_vms(host_id: str) -> list[dict[str, Any]]:
    host = cockpit_host_record(host_id)
    try:
        output = run_sudo_python(host, VM_LIST_SCRIPT, timeout=45)
        return json.loads(output or "[]")
    except Exception as exc:
        raise HTTPException(502, f"Could not query virtual machines: {exc}") from exc


@app.post("/kvm-api/hosts/{host_id}/vms/create")
def create_vm(host_id: str, payload: VMCreate, access: AuthorizationContext = Depends(require_permission("vm_operator"))) -> dict[str, bool]:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", payload.name):
        raise HTTPException(422, "Use a VM name with letters, numbers, dots, underscores, or hyphens")
    if payload.iso_path and (not payload.iso_path.startswith("/") or not payload.iso_path.lower().endswith(".iso")):
        raise HTTPException(422, "The installer ISO must be an absolute path ending in .iso on the KVM host")
    host = cockpit_host_record(host_id)
    creation_script = r'''import os,re,shutil,subprocess,sys,tempfile,xml.etree.ElementTree as ET
name,pool,volume,network,vcpu_text,memory_text,iso_path,autostart=sys.argv[1:]
if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}',name): raise SystemExit('Invalid VM name')
vcpus=int(vcpu_text); memory_mib=int(memory_text)
base=['virsh','-c','qemu:///system']
def run(args):
 r=subprocess.run(args,capture_output=True,text=True,timeout=40)
 if r.returncode: raise SystemExit(r.stderr.strip() or r.stdout.strip() or 'Libvirt command failed')
 return r.stdout
if name in [line.strip() for line in run(base+['list','--all','--name']).splitlines()]: raise SystemExit('A VM with this name already exists')
pool_names=[line.strip() for line in run(base+['pool-list','--all','--name']).splitlines() if line.strip()]
if pool not in pool_names: raise SystemExit('The selected storage pool does not exist')
volume_xml=ET.fromstring(run(base+['vol-dumpxml',volume,'--pool',pool]))
volume_format=volume_xml.find('./target/format')
disk_format=volume_format.get('type','') if volume_format is not None else ''
if disk_format not in ('qcow2','raw'): raise SystemExit('The selected disk volume must use qcow2 or raw format')
disk_path=run(base+['vol-path',volume,'--pool',pool]).strip()
if not disk_path or not os.path.exists(disk_path): raise SystemExit('The selected disk volume path is not present on the host')
network_names=[line.strip() for line in run(base+['net-list','--all','--name']).splitlines() if line.strip()]
if network not in network_names: raise SystemExit('The selected virtual network does not exist')
net_info=run(base+['net-info',network])
if not any(line.strip().lower()=='active: yes' for line in net_info.splitlines()): raise SystemExit('Start the selected virtual network before creating this VM')
if iso_path:
 if not os.path.isabs(iso_path) or not iso_path.lower().endswith('.iso') or not os.path.isfile(iso_path): raise SystemExit('The installer ISO path is invalid or the file does not exist')
domain=ET.Element('domain',{'type':'kvm'})
ET.SubElement(domain,'name').text=name
ET.SubElement(domain,'memory',{'unit':'MiB'}).text=str(memory_mib)
ET.SubElement(domain,'currentMemory',{'unit':'MiB'}).text=str(memory_mib)
ET.SubElement(domain,'vcpu').text=str(vcpus)
os_node=ET.SubElement(domain,'os')
ET.SubElement(os_node,'type',{'arch':'x86_64'}).text='hvm'
ET.SubElement(os_node,'boot',{'dev':'cdrom' if iso_path else 'hd'})
ET.SubElement(os_node,'boot',{'dev':'hd'})
features=ET.SubElement(domain,'features')
ET.SubElement(features,'acpi')
ET.SubElement(features,'apic')
ET.SubElement(domain,'on_poweroff').text='destroy'
ET.SubElement(domain,'on_reboot').text='restart'
ET.SubElement(domain,'on_crash').text='destroy'
devices=ET.SubElement(domain,'devices')
emulator=shutil.which('qemu-system-x86_64') or shutil.which('qemu-kvm')
if emulator: ET.SubElement(devices,'emulator').text=emulator
disk=ET.SubElement(devices,'disk',{'type':'file','device':'disk'})
ET.SubElement(disk,'driver',{'name':'qemu','type':disk_format})
ET.SubElement(disk,'source',{'file':disk_path})
ET.SubElement(disk,'target',{'dev':'vda','bus':'virtio'})
if iso_path:
 cdrom=ET.SubElement(devices,'disk',{'type':'file','device':'cdrom'})
 ET.SubElement(cdrom,'driver',{'name':'qemu','type':'raw'})
 ET.SubElement(cdrom,'source',{'file':iso_path})
 ET.SubElement(cdrom,'target',{'dev':'sda','bus':'sata'})
 ET.SubElement(cdrom,'readonly')
iface=ET.SubElement(devices,'interface',{'type':'network'})
ET.SubElement(iface,'source',{'network':network})
ET.SubElement(iface,'model',{'type':'virtio'})
serial=ET.SubElement(devices,'serial',{'type':'pty'})
ET.SubElement(serial,'target',{'port':'0'})
console=ET.SubElement(devices,'console',{'type':'pty'})
ET.SubElement(console,'target',{'type':'serial','port':'0'})
fd,path=tempfile.mkstemp(prefix='kvm-vm-create-',suffix='.xml')
try:
 with os.fdopen(fd,'w',encoding='utf-8') as f: f.write(ET.tostring(domain,encoding='unicode'))
 run(base+['define',path])
 if autostart=='true': run(base+['autostart',name])
 run(base+['start',name])
finally:
 try: os.unlink(path)
 except FileNotFoundError: pass
print('VM created and started')
'''
    try:
        run_sudo_python(host, creation_script, [payload.name, payload.pool, payload.volume, payload.network, str(payload.vcpus), str(payload.memory_mib), payload.iso_path or "", str(payload.autostart).lower()], timeout=75)
    except Exception as exc:
        record_audit(access.user_id, "vm.create", f"{host_id}/{payload.name}", "failure", "Could not create VM with the selected resources")
        raise HTTPException(502, "Could not create the VM. Confirm its disk, active virtual network, and optional ISO are available on the host.") from exc
    record_audit(access.user_id, "vm.create", f"{host_id}/{payload.name}", detail=f"pool={payload.pool}; volume={payload.volume}; vcpus={payload.vcpus}; memory_mib={payload.memory_mib}")
    return {"success": True}


@app.post("/kvm-api/hosts/{host_id}/vms/devices")
def configure_vm_devices(host_id: str, payload: VMDeviceAction, vm_name: str, access: AuthorizationContext = Depends(require_permission("vm_operator"))) -> dict[str, bool]:
    host = cockpit_host_record(host_id)
    encoded_name = base64.b64encode(vm_name.encode()).decode()
    device_script = r'''import base64,os,re,subprocess,sys,tempfile,xml.etree.ElementTree as ET
name=base64.b64decode(sys.argv[1]).decode(); action,pool,volume,target,network,mac=sys.argv[2:]
base=['virsh','-c','qemu:///system']
def run(args):
 r=subprocess.run(args,capture_output=True,text=True,timeout=35)
 if r.returncode: raise SystemExit(r.stderr.strip() or r.stdout.strip() or 'Libvirt command failed')
 return r.stdout
domain_names=[line.strip() for line in run(base+['list','--all','--name']).splitlines() if line.strip()]
if name not in domain_names: raise SystemExit('Virtual machine not found')
root=ET.fromstring(run(base+['dumpxml','--inactive',name]))
devices=root.find('./devices')
if devices is None: raise SystemExit('This VM has no editable device configuration')
if action=='attach_disk':
 if not pool or not volume: raise SystemExit('Choose a storage pool and volume')
 pools=[line.strip() for line in run(base+['pool-list','--all','--name']).splitlines() if line.strip()]
 if pool not in pools: raise SystemExit('The selected storage pool does not exist')
 vxml=ET.fromstring(run(base+['vol-dumpxml',volume,'--pool',pool])); fmt=vxml.find('./target/format')
 disk_format=fmt.get('type','') if fmt is not None else ''
 if disk_format not in ('qcow2','raw'): raise SystemExit('Only qcow2 and raw volumes can be attached from the KVM interface')
 disk_path=run(base+['vol-path',volume,'--pool',pool]).strip()
 if not disk_path or not os.path.exists(disk_path): raise SystemExit('The storage volume path is unavailable')
 for other_name in domain_names:
  other=ET.fromstring(run(base+['dumpxml','--inactive',other_name]))
  for source in other.findall('./devices/disk/source'):
   if source.get('file')==disk_path or source.get('dev')==disk_path: raise SystemExit('This volume is already attached to a VM')
 used={item.find('./target').get('dev','') for item in devices.findall('./disk') if item.find('./target') is not None}
 candidates=['vd'+chr(letter) for letter in range(ord('b'),ord('z')+1)]
 chosen=next((candidate for candidate in candidates if candidate not in used),None)
 if not chosen: raise SystemExit('No free virtio disk target is available')
 disk=ET.SubElement(devices,'disk',{'type':'file','device':'disk'})
 ET.SubElement(disk,'driver',{'name':'qemu','type':disk_format})
 ET.SubElement(disk,'source',{'file':disk_path})
 ET.SubElement(disk,'target',{'dev':chosen,'bus':'virtio'})
elif action=='detach_disk':
 if not re.fullmatch(r'(?:vd|sd|hd|xvd)[a-z]+',target): raise SystemExit('Invalid disk target')
 item=next((disk for disk in devices.findall('./disk') if disk.get('device','disk') in ('disk','cdrom') and disk.find('./target') is not None and disk.find('./target').get('dev')==target),None)
 if item is None: raise SystemExit('The selected disk is not attached to this VM')
 devices.remove(item)
elif action=='attach_network':
 if not network: raise SystemExit('Choose a libvirt network')
 networks=[line.strip() for line in run(base+['net-list','--all','--name']).splitlines() if line.strip()]
 if network not in networks: raise SystemExit('The selected libvirt network does not exist')
 info=run(base+['net-info',network])
 if not any(line.strip().lower()=='active: yes' for line in info.splitlines()): raise SystemExit('Start the selected libvirt network before attaching it')
 iface=ET.SubElement(devices,'interface',{'type':'network'})
 ET.SubElement(iface,'source',{'network':network})
 ET.SubElement(iface,'model',{'type':'virtio'})
elif action=='detach_network':
 if not re.fullmatch(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',mac): raise SystemExit('Invalid network interface identity')
 item=next((iface for iface in devices.findall('./interface') if iface.find('./mac') is not None and iface.find('./mac').get('address','').lower()==mac.lower()),None)
 if item is None: raise SystemExit('The selected network interface is not attached to this VM')
 devices.remove(item)
else: raise SystemExit('Unsupported VM device action')
fd,path=tempfile.mkstemp(prefix='kvm-vm-device-',suffix='.xml')
try:
 with os.fdopen(fd,'w',encoding='utf-8') as f: f.write(ET.tostring(root,encoding='unicode'))
 run(base+['define',path])
finally:
 try: os.unlink(path)
 except FileNotFoundError: pass
print('Persistent VM device configuration updated')
'''
    args = [encoded_name, payload.action, payload.pool or "", payload.volume or "", payload.target or "", payload.network or "", payload.mac or ""]
    try:
        run_sudo_python(host, device_script, args, timeout=90)
    except Exception as exc:
        record_audit(access.user_id, f"vm.device.{payload.action}", f"{host_id}/{vm_name}", "failure", "Could not update persistent VM devices")
        raise HTTPException(502, "Could not update the VM devices. Confirm the VM is persistent and the selected disk or network is available.") from exc
    record_audit(access.user_id, f"vm.device.{payload.action}", f"{host_id}/{vm_name}", detail=f"pool={payload.pool or ''};volume={payload.volume or ''};target={payload.target or ''};network={payload.network or ''}")
    return {"success": True}


@app.post("/kvm-api/hosts/{host_id}/vms/snapshots")
def control_vm_snapshot(host_id: str, payload: VMSnapshotAction, vm_name: str, access: AuthorizationContext = Depends(require_permission("vm_operator"))) -> dict[str, bool]:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", payload.name):
        raise HTTPException(422, "Snapshot names may contain letters, numbers, dots, underscores, or hyphens")
    host = cockpit_host_record(host_id)
    encoded_name = base64.b64encode(vm_name.encode()).decode()
    snapshot_script = r'''import base64,re,subprocess,sys,xml.etree.ElementTree as ET
domain=base64.b64decode(sys.argv[1]).decode(); action,name,description=sys.argv[2:]
base=['virsh','-c','qemu:///system']
def run(args):
 r=subprocess.run(args,capture_output=True,text=True,timeout=50)
 if r.returncode: raise SystemExit(r.stderr.strip() or r.stdout.strip() or 'Libvirt command failed')
 return r.stdout
if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}',name): raise SystemExit('Invalid snapshot name')
if domain not in [line.strip() for line in run(base+['list','--all','--name']).splitlines()]: raise SystemExit('Virtual machine not found')
state=run(base+['domstate',domain]).strip().lower()
if 'shut off' not in state and 'shutoff' not in state: raise SystemExit('Shut down the VM before changing snapshots')
names=[line.strip() for line in run(base+['snapshot-list',domain,'--name']).splitlines() if line.strip()]
if action=='create':
 if name in names: raise SystemExit('A snapshot with this name already exists')
 root=ET.fromstring(run(base+['dumpxml','--inactive',domain]))
 disks=[disk for disk in root.findall('./devices/disk') if disk.get('device','disk')=='disk' and disk.find('./readonly') is None]
 if not disks or any(disk.find('./driver') is None or disk.find('./driver').get('type','').lower()!='qcow2' for disk in disks): raise SystemExit('Internal snapshots require every writable VM disk to use qcow2 format')
 run(base+['snapshot-create-as',domain,'--name',name,'--description',description or 'Created from Rancher KVM extension','--atomic'])
elif action=='delete':
 if name not in names: raise SystemExit('Snapshot not found')
 run(base+['snapshot-delete',domain,name])
elif action=='revert':
 if name not in names: raise SystemExit('Snapshot not found')
 run(base+['snapshot-revert',domain,name])
else: raise SystemExit('Unsupported snapshot action')
print('Snapshot action completed')
'''
    try:
        run_sudo_python(host, snapshot_script, [encoded_name, payload.action, payload.name, payload.description or ""], timeout=90)
    except Exception as exc:
        record_audit(access.user_id, f"vm.snapshot.{payload.action}", f"{host_id}/{vm_name}/{payload.name}", "failure", "Could not complete VM snapshot action")
        raise HTTPException(502, "Could not complete the snapshot action. Confirm the VM is shut down and its writable disks use qcow2 format.") from exc
    record_audit(access.user_id, f"vm.snapshot.{payload.action}", f"{host_id}/{vm_name}/{payload.name}")
    return {"success": True}


@app.get("/kvm-api/hosts/{host_id}/services", dependencies=[Depends(require_permission("viewer"))])
def list_services(host_id: str) -> list[dict[str, Any]]:
    host = cockpit_host_record(host_id)
    try:
        output = run_sudo_python(host, SERVICE_LIST_SCRIPT, timeout=45)
        return json.loads(output or "[]")
    except Exception as exc:
        raise HTTPException(502, f"Could not query system services: {exc}") from exc


@app.get("/kvm-api/hosts/{host_id}/vms/detail", dependencies=[Depends(require_permission("viewer"))])
def get_vm_details(host_id: str, vm_name: str) -> dict[str, Any]:
    host = cockpit_host_record(host_id)
    try:
        output = run_sudo_python(host, VM_DETAIL_SCRIPT, [vm_name], timeout=45)
        return json.loads(output or "{}")
    except Exception as exc:
        raise HTTPException(502, f"Could not query virtual machine details: {exc}") from exc


@app.get("/kvm-api/hosts/{host_id}/metrics", dependencies=[Depends(require_permission("viewer"))])
def get_host_metrics(host_id: str) -> dict[str, Any]:
    """Read lightweight host metrics without rebuilding the full administration inventory."""
    host = cockpit_host_record(host_id)
    script = r'''import json,os
memory={}
for line in open('/proc/meminfo'):
    key,value=line.split(':',1); memory[key]=int(value.strip().split()[0])
print(json.dumps({'cpu_count':os.cpu_count() or 0,'memory_total_kib':memory.get('MemTotal',0),
    'memory_available_kib':memory.get('MemAvailable',0),'load_average':list(os.getloadavg())}))
'''
    try:
        return json.loads(run_sudo_python(host, script, timeout=15) or "{}")
    except Exception as exc:
        raise HTTPException(502, f"Could not refresh host metrics: {exc}") from exc


@app.get("/kvm-api/hosts/{host_id}/cloud-native", dependencies=[Depends(require_permission("viewer"))])
def get_host_cloud_native(host_id: str) -> dict[str, Any]:
    host = cockpit_host_record(host_id)
    try:
        output = run_sudo_python(host, HOST_ADMIN_SCRIPT, timeout=90)
        return json.loads(output or "{}")
    except Exception as exc:
        raise HTTPException(502, f"Could not load host administration data: {exc}") from exc


STORAGE_VOLUMES_SCRIPT = r'''import json,subprocess,sys,xml.etree.ElementTree as ET,re
def run(args):
 p=subprocess.run(args,capture_output=True,text=True,timeout=20)
 if p.returncode: raise RuntimeError(p.stderr.strip() or p.stdout.strip() or 'libvirt command failed')
 return p.stdout
def info(pool,name):
 text=run(['virsh','-c','qemu:///system','vol-info',name,'--pool',pool,'--bytes'])
 values={line.split(':',1)[0].strip().lower():line.split(':',1)[1].strip() for line in text.splitlines() if ':' in line}
 xml=ET.fromstring(run(['virsh','-c','qemu:///system','vol-dumpxml',name,'--pool',pool]))
 format_node=xml.find('./target/format')
 path=xml.findtext('./target/path') or run(['virsh','-c','qemu:///system','vol-path',name,'--pool',pool]).strip()
 return {'pool':pool,'name':name,'path':path,'format':(format_node.get('type') if format_node is not None else values.get('type','unknown')),'capacity_bytes':int(values.get('capacity','0')),'allocation_bytes':int(values.get('allocation','0'))}
def names(pool):
 text=run(['virsh','-c','qemu:///system','vol-list','--pool',pool])
 result=[]
 for line in text.splitlines():
  line=line.strip()
  if not line or line.startswith('---') or line.lower().startswith('name '): continue
  cols=line.split(None,1)
  if cols: result.append(cols[0])
 return result
if sys.argv[1]=='list':
 pools=[x.strip() for x in run(['virsh','-c','qemu:///system','pool-list','--all','--name']).splitlines() if x.strip()]
 volumes=[]
 for pool in pools:
  for name in names(pool):
   if name:
    try: volumes.append(info(pool,name))
    except Exception: continue
 print(json.dumps(volumes)); raise SystemExit
action,pool,name,capacity,fmt=sys.argv[1:6]
vm_name=sys.argv[6] if len(sys.argv)>6 else ''
if not re.fullmatch(r'[A-Za-z0-9_.+-]{1,128}',name): raise SystemExit('Invalid volume name')
if pool not in [x.strip() for x in run(['virsh','-c','qemu:///system','pool-list','--all','--name']).splitlines()]: raise SystemExit('Storage pool not found')
if action=='create':
 if fmt not in ('qcow2','raw') or not capacity.isdigit() or int(capacity)<1048576: raise SystemExit('Invalid volume capacity or format')
 root=ET.fromstring(run(['virsh','-c','qemu:///system','pool-dumpxml',pool]))
 if root.get('type')!='dir': raise SystemExit('Volumes can only be created in directory-based storage pools')
 pool_info=run(['virsh','-c','qemu:///system','pool-info','--bytes',pool])
 if not any(x.lower().startswith('state:') and 'running' in x.lower() for x in pool_info.splitlines()): raise SystemExit('Storage pool must be running')
 free=next((int(x.split(':',1)[1].strip()) for x in pool_info.splitlines() if x.lower().startswith('available:')),0)
 if int(capacity)>free: raise SystemExit('Requested capacity exceeds the pool free space')
 if name in names(pool): raise SystemExit('A volume with this name already exists in the pool')
 run(['virsh','-c','qemu:///system','vol-create-as',pool,name,capacity,'--format',fmt])
 print(json.dumps(info(pool,name))); raise SystemExit
if action=='delete':
 volume=info(pool,name); path=volume['path']
 domains=[x.strip() for x in run(['virsh','-c','qemu:///system','list','--all','--name']).splitlines() if x.strip()]
 for domain in domains:
  domain_xml=ET.fromstring(run(['virsh','-c','qemu:///system','dumpxml',domain]))
  for source in domain_xml.findall('./devices/disk/source'):
   if path in source.attrib.values(): raise SystemExit('Volume is attached to virtual machine '+domain)
 run(['virsh','-c','qemu:///system','vol-delete',name,'--pool',pool]); print(json.dumps({'deleted':True})); raise SystemExit
if action=='resize':
 volume=info(pool,name); current=volume['capacity_bytes']; requested=int(capacity) if capacity.isdigit() else 0
 if volume['format'].lower() not in ('qcow2','raw'): raise SystemExit('Only qcow2 and raw volumes can be expanded')
 if requested<=current: raise SystemExit('New capacity must be greater than the current volume capacity; shrinking is not supported')
 root=ET.fromstring(run(['virsh','-c','qemu:///system','pool-dumpxml',pool]))
 if root.get('type')!='dir': raise SystemExit('Only directory-based storage pools can be resized')
 pool_info=run(['virsh','-c','qemu:///system','pool-info','--bytes',pool])
 if not any(x.lower().startswith('state:') and 'running' in x.lower() for x in pool_info.splitlines()): raise SystemExit('Storage pool must be running')
 free=next((int(x.split(':',1)[1].strip()) for x in pool_info.splitlines() if x.lower().startswith('available:')),0)
 if requested-current>free: raise SystemExit('Requested expansion exceeds the storage pool free space')
 domains=[x.strip() for x in run(['virsh','-c','qemu:///system','list','--all','--name']).splitlines() if x.strip()]
 attached=[]
 for domain in domains:
  domain_xml=ET.fromstring(run(['virsh','-c','qemu:///system','dumpxml',domain]))
  if any(volume['path'] in source.attrib.values() for source in domain_xml.findall('./devices/disk/source')):
   state=run(['virsh','-c','qemu:///system','domstate',domain]).strip().lower()
   attached.append((domain,state))
 if vm_name and not any(domain==vm_name for domain,_ in attached): raise SystemExit('Selected virtual machine is not attached to this volume')
 if any(state!='shut off' for _,state in attached): raise SystemExit('Stop every virtual machine using this volume before expanding it')
 run(['virsh','-c','qemu:///system','vol-resize',name,str(requested),'--pool',pool])
 print(json.dumps(info(pool,name))); raise SystemExit
raise SystemExit('Unsupported storage volume action')
'''


@app.get("/kvm-api/hosts/{host_id}/storage-volumes", dependencies=[Depends(require_permission("viewer"))])
def list_storage_volumes(host_id: str) -> list[dict[str, Any]]:
    try:
        return json.loads(run_sudo_python(cockpit_host_record(host_id), STORAGE_VOLUMES_SCRIPT, ["list", "", "", "", ""], timeout=45) or "[]")
    except Exception as exc:
        raise HTTPException(502, f"Could not list libvirt storage volumes: {exc}") from exc


@app.post("/kvm-api/hosts/{host_id}/storage-volumes")
def configure_storage_volume(host_id: str, payload: StorageVolumeConfig, access: AuthorizationContext = Depends(require_permission("host_resources"))) -> dict[str, Any]:
    if not re.fullmatch(r"[A-Za-z0-9_.+-]{1,128}", payload.name):
        raise HTTPException(422, "Volume name may contain letters, numbers, dot, underscore, plus, and hyphen")
    host = cockpit_host_record(host_id)
    try:
        output = run_sudo_python(host, STORAGE_VOLUMES_SCRIPT, [payload.action, payload.pool, payload.name, str(payload.capacity_bytes or ""), payload.format, payload.vm_name or ""], timeout=60)
    except Exception as exc:
        record_audit(access.user_id, f"storage-volume.{payload.action}", f"{host_id}/{payload.pool}/{payload.name}", "failure", str(exc)[:500])
        raise HTTPException(409, f"Could not {payload.action} storage volume: {exc}") from exc
    record_audit(access.user_id, f"storage-volume.{payload.action}", f"{host_id}/{payload.pool}/{payload.name}")
    return json.loads(output or "{}")


@app.post("/kvm-api/hosts/{host_id}/repositories/actions")
def control_repository(host_id: str, payload: RepositoryAction, access: AuthorizationContext = Depends(require_permission("host_resources"))) -> dict[str, bool]:
    if payload.alias != "*" and not re.fullmatch(r"[A-Za-z0-9_.:-]+", payload.alias):
        raise HTTPException(422, "Invalid repository alias")
    host = cockpit_host_record(host_id)
    if payload.action == "add":
        parsed_uri = urlsplit(payload.uri or "")
        if not payload.name or not payload.uri or parsed_uri.scheme not in ("http", "https", "ftp", "file") or (parsed_uri.scheme in ("http", "https", "ftp") and not parsed_uri.hostname):
            raise HTTPException(422, "Enter a repository name and a valid HTTP, HTTPS, FTP, or file URL")
        args = ["zypper", "--non-interactive", "addrepo", "--name", payload.name, payload.uri, payload.alias]
    elif payload.action == "remove":
        args = ["zypper", "--non-interactive", "removerepo", payload.alias]
    elif payload.action == "refresh":
        args = ["zypper", "--non-interactive", "refresh"] + ([] if payload.alias == "*" else [payload.alias])
    else:
        args = ["zypper", "--non-interactive", "modifyrepo", "--" + payload.action, payload.alias]
    script = "import subprocess,sys; r=subprocess.run(sys.argv[1:],capture_output=True,text=True,timeout=120); print(r.stdout); print(r.stderr,file=sys.stderr); sys.exit(r.returncode)"
    try:
        run_sudo_python(host, script, args, timeout=150)
    except Exception as exc:
        record_audit(access.user_id, f"repository.{payload.action}", f"{host_id}/{payload.alias}", "failure", str(exc)[:500])
        raise HTTPException(502, f"Could not perform the repository action: {exc}") from exc
    record_audit(access.user_id, f"repository.{payload.action}", f"{host_id}/{payload.alias}")
    return {"success": True}


@app.post("/kvm-api/hosts/{host_id}/subscriptions/actions")
def control_subscription(host_id: str, payload: SubscriptionAction, access: AuthorizationContext = Depends(require_permission("host_resources"))) -> dict[str, bool]:
    host = cockpit_host_record(host_id)
    if payload.action in ("activate_extension", "deactivate_extension"):
        if not payload.product or not re.fullmatch(r"[A-Za-z0-9_.+-]+/[A-Za-z0-9_.+-]+/[A-Za-z0-9_.+-]+", payload.product):
            raise HTTPException(422, "Choose a valid product identifier returned by SUSEConnect")
        args = [payload.action, payload.product]
        extension_input = json.dumps({"regcode": (payload.regcode or "").strip()}) + "\n"
        try:
            run_sudo_python(host, SUBSCRIPTION_EXTENSION_SCRIPT, args, timeout=240, stdin_data=extension_input)
        except Exception as exc:
            record_audit(access.user_id, f"subscription.{payload.action}", f"{host_id}/{payload.product}", "failure", "SUSEConnect add-on operation failed")
            raise HTTPException(502, f"Could not {payload.action.replace('_', ' ')}: {exc}") from exc
        record_audit(access.user_id, f"subscription.{payload.action}", f"{host_id}/{payload.product}")
        return {"success": True}
    if payload.action in ("register", "replace"):
        if not payload.email or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", payload.email) or not payload.regcode or len(payload.regcode.strip()) < 4:
            raise HTTPException(422, "Enter a valid account email and registration code")
        args = ["register"]
    else:
        args = ["deregister"]
    script = r'''import json,shutil,subprocess,sys
if not shutil.which('SUSEConnect'): raise SystemExit('SUSEConnect is not installed on this host')
action=sys.argv[1]
if action in ('register','replace'):
    print('KVM_STDIN_READY',flush=True)
    data=json.loads(sys.stdin.readline())
    if action=='replace':
        old=subprocess.run(['SUSEConnect','--de-register'],capture_output=True,text=True,timeout=120)
        if old.returncode: raise SystemExit(old.stderr.strip() or old.stdout.strip() or 'Could not deregister the current subscription; it was not replaced')
    args=['SUSEConnect','--regcode',data['regcode'],'--email',data['email']]
else: args=['SUSEConnect','-d']
result=subprocess.run(args,capture_output=True,text=True,timeout=180)
if result.returncode:
    detail=result.stderr.strip() or result.stdout.strip() or 'SUSEConnect action failed'
    if action=='replace': detail='The previous registration was removed, but the new registration failed. Submit the new code again to retry. ' + detail
    raise SystemExit(detail)
print(result.stdout.strip())
'''
    # The registration code is sent only for this request and is not written to
    # the host database or the audit log.
    try:
        subscription_input = json.dumps({"regcode": payload.regcode.strip(), "email": payload.email.strip()}) + "\n" if payload.action in ("register", "replace") else None
        run_sudo_python(host, script, args, timeout=210, stdin_data=subscription_input)
    except Exception as exc:
        record_audit(access.user_id, f"subscription.{payload.action}", host_id, "failure", "SUSEConnect operation failed")
        raise HTTPException(502, f"Could not {payload.action} the SUSE subscription. Check host connectivity and the SUSEConnect response on the host.") from exc
    record_audit(access.user_id, f"subscription.{payload.action}", host_id)
    return {"success": True}


SUBSCRIPTION_EXTENSION_SCRIPT = r'''import json,re,shutil,subprocess,sys
if not shutil.which('SUSEConnect'): raise SystemExit('SUSEConnect is not installed on this host')
action=sys.argv[1]
product=sys.argv[2] if len(sys.argv)>2 else ''
listed=subprocess.run(['SUSEConnect','--list-extensions'],capture_output=True,text=True,timeout=60)
if listed.returncode: raise SystemExit(listed.stderr.strip() or listed.stdout.strip() or 'Could not list available SUSE extensions')
items=[]; label=''
for line in listed.stdout.splitlines():
 text=line.strip()
 if not text: continue
 match=re.search(r'SUSEConnect\s+(-d\s+)?-p\s+(\S+)(.*)$',text)
 if match:
  identifier=match.group(2)
  if not re.fullmatch(r'[A-Za-z0-9_.+-]+/[A-Za-z0-9_.+-]+/[A-Za-z0-9_.+-]+',identifier): continue
  active=bool(match.group(1))
  name=re.sub(r'\s*\(Activated\)\s*','',label).strip()
  if not name or name.startswith(('AVAILABLE EXTENSIONS','REMARKS','MORE INFORMATION')): name=identifier.split('/')[0].replace('-',' ').title()
  items.append({'product':identifier,'name':name,'active':active,'requires_regcode':not active and bool(re.search(r'\-r\s+(?:ADDITIONAL|<)',match.group(3),re.I)),'protected':identifier.startswith(('sle-module-basesystem/','sle-module-server-applications/'))})
  label=''
 elif text.upper().startswith(('AVAILABLE EXTENSIONS','REMARKS','MORE INFORMATION')): label=''
 elif not text.startswith(('Activate with:','Deactivate with:','(')): label=text
if action=='list':
 print(json.dumps(items)); raise SystemExit
item=next((entry for entry in items if entry['product']==product),None)
if item is None: raise SystemExit('The selected product is not available for this host')
if action=='deactivate_extension' and item['protected']: raise SystemExit('This core SUSE module is protected from deactivation')
if action=='activate_extension' and item['active']: raise SystemExit('This extension is already active')
if action=='deactivate_extension' and not item['active']: raise SystemExit('This extension is not active')
print('KVM_STDIN_READY',flush=True)
data=json.loads(sys.stdin.readline() or '{}')
if action=='activate_extension':
 args=['SUSEConnect','-p',product]
 if data.get('regcode'): args.extend(['-r',data['regcode']])
 elif item['requires_regcode']: raise SystemExit('This extension requires its SUSE registration code')
else: args=['SUSEConnect','-d','-p',product]
result=subprocess.run(args,capture_output=True,text=True,timeout=210)
if result.returncode: raise SystemExit(result.stderr.strip() or result.stdout.strip() or 'SUSEConnect add-on operation failed')
print(result.stdout.strip())
'''


@app.get("/kvm-api/hosts/{host_id}/subscriptions/extensions", dependencies=[Depends(require_permission("viewer"))])
def list_subscription_extensions(host_id: str) -> list[dict[str, Any]]:
    try:
        output = run_sudo_python(cockpit_host_record(host_id), SUBSCRIPTION_EXTENSION_SCRIPT, ["list", ""], timeout=75)
        return json.loads(output or "[]")
    except Exception as exc:
        raise HTTPException(502, f"Could not list available SUSE extensions: {exc}") from exc


@app.post("/kvm-api/hosts/{host_id}/security/selinux")
def set_selinux_mode(host_id: str, payload: SecurityModeAction, access: AuthorizationContext = Depends(require_permission("host_resources"))) -> dict[str, bool]:
    host = cockpit_host_record(host_id)
    script = r'''import shutil,subprocess,sys
if not shutil.which('setenforce'): raise SystemExit('SELinux is not available on this host')
r=subprocess.run(['setenforce','1' if sys.argv[1]=='enforcing' else '0'],capture_output=True,text=True)
if r.returncode: raise SystemExit(r.stderr.strip() or r.stdout.strip() or 'Could not change SELinux mode')
'''
    try:
        run_sudo_python(host, script, [payload.mode], timeout=30)
    except Exception as exc:
        record_audit(access.user_id, "selinux.mode", host_id, "failure", str(exc)[:500])
        raise HTTPException(502, f"Could not change SELinux mode: {exc}") from exc
    record_audit(access.user_id, "selinux.mode", host_id, detail=payload.mode)
    return {"success": True}


@app.post("/kvm-api/hosts/{host_id}/libvirt/{resource}/actions")
def control_libvirt_resource(host_id: str, resource: Literal["storage-pools", "networks"], payload: NamedAdminAction, access: AuthorizationContext = Depends(require_permission("host_resources"))) -> dict[str, bool]:
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
        record_audit(access.user_id, f"libvirt.{resource}.{payload.action}", f"{host_id}/{payload.name}", "failure", str(exc)[:500])
        raise HTTPException(502, f"Could not perform the libvirt action: {exc}") from exc
    record_audit(access.user_id, f"libvirt.{resource}.{payload.action}", f"{host_id}/{payload.name}")
    return {"success": True}


@app.post("/kvm-api/hosts/{host_id}/libvirt/networks/config")
def configure_libvirt_network(host_id: str, payload: LibvirtNetworkConfig, access: AuthorizationContext = Depends(require_permission("host_resources"))) -> dict[str, bool]:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", payload.name):
        raise HTTPException(422, "Use a network name with letters, numbers, dots, underscores, or hyphens")
    if payload.bridge and not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", payload.bridge):
        raise HTTPException(422, "Enter a valid Linux bridge interface name")
    if payload.forward_mode == "bridge" and not payload.bridge:
        raise HTTPException(422, "A bridge device is required for bridged networks")
    address = None
    start = end = None
    if payload.ipv4_address:
        try:
            address = ipaddress.ip_interface(payload.ipv4_address)
            if address.version != 4:
                raise ValueError("Only IPv4 network configuration is supported here")
        except ValueError as exc:
            raise HTTPException(422, f"Enter an IPv4 address with prefix, such as 192.0.2.1/24: {exc}") from exc
    if payload.dhcp_start or payload.dhcp_end:
        if not address or not payload.dhcp_start or not payload.dhcp_end:
            raise HTTPException(422, "Enter the network address and both DHCP range addresses")
        try:
            start, end = ipaddress.ip_address(payload.dhcp_start), ipaddress.ip_address(payload.dhcp_end)
            network = address.network
            if start.version != 4 or end.version != 4 or start not in network or end not in network or int(start) > int(end):
                raise ValueError("The DHCP range must be ordered and inside the configured subnet")
            if start == address.ip or end == address.ip or start == network.network_address or end == network.broadcast_address:
                raise ValueError("The DHCP range cannot contain the gateway, network, or broadcast address")
        except ValueError as exc:
            raise HTTPException(422, f"Invalid DHCP range: {exc}") from exc
    if payload.forward_mode == "bridge" and (address or start or end):
        raise HTTPException(422, "Configure the IP address on the host bridge, not in the libvirt bridged network")

    host = cockpit_host_record(host_id)
    network_script = r'''import ipaddress,os,re,subprocess,sys,tempfile,xml.etree.ElementTree as ET
action,name,mode,bridge,address,dhcp_start,dhcp_end,autostart,start_after_create=sys.argv[1:]
base=['virsh','-c','qemu:///system']
def run(args,timeout=35):
 r=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
 if r.returncode: raise SystemExit(r.stderr.strip() or r.stdout.strip() or 'Libvirt network operation failed')
 return r.stdout
if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}',name): raise SystemExit('Invalid libvirt network name')
names=[item.strip() for item in run(base+['net-list','--all','--name']).splitlines() if item.strip()]
exists=name in names
if action=='create' and exists: raise SystemExit('A libvirt network with this name already exists')
if action in ('edit','delete') and not exists: raise SystemExit('Libvirt network not found')
if action=='delete':
 info=run(base+['net-info',name]).lower()
 if 'active: yes' in info: raise SystemExit('Stop the libvirt network before removing it')
 for domain_name in filter(str.strip,run(base+['list','--all','--name']).splitlines()):
  root=ET.fromstring(run(base+['dumpxml','--inactive',domain_name]))
  for iface in root.findall('./devices/interface'):
   source=iface.find('./source')
   if source is not None and source.get('network')==name: raise SystemExit('A VM still references this network; detach it from the VM before deleting the network')
 run(base+['net-undefine',name])
 print('Libvirt network removed'); sys.exit(0)
if action=='edit':
 info=run(base+['net-info',name]).lower()
 if 'active: yes' in info: raise SystemExit('Stop the network before editing its definition')
 root=ET.fromstring(run(base+['net-dumpxml',name]))
else:
 root=ET.Element('network'); ET.SubElement(root,'name').text=name
forward=root.find('./forward')
if mode=='none':
 if forward is not None: root.remove(forward)
else:
 if forward is None: forward=ET.Element('forward'); root.insert(1,forward)
 forward.attrib.clear(); forward.set('mode',mode)
bridge_node=root.find('./bridge')
if mode=='bridge':
 if bridge_node is None: bridge_node=ET.SubElement(root,'bridge')
 bridge_node.set('name',bridge); bridge_node.set('stp','on'); bridge_node.set('delay','0')
elif bridge_node is not None:
 root.remove(bridge_node)
for node in list(root.findall('./ip')):
 root.remove(node)
if address:
 iface=ipaddress.ip_interface(address)
 ip=ET.SubElement(root,'ip',{'address':str(iface.ip),'netmask':str(iface.network.netmask)})
 if dhcp_start and dhcp_end:
  dhcp=ET.SubElement(ip,'dhcp'); ET.SubElement(dhcp,'range',{'start':dhcp_start,'end':dhcp_end})
fd,path=tempfile.mkstemp(prefix='kvm-libvirt-network-',suffix='.xml')
try:
 with os.fdopen(fd,'w',encoding='utf-8') as handle: handle.write(ET.tostring(root,encoding='unicode'))
 run(base+['net-define',path])
finally:
 try: os.unlink(path)
 except FileNotFoundError: pass
run(base+['net-autostart']+(['--disable'] if autostart!='true' else [])+[name])
if action=='create' and start_after_create=='true': run(base+['net-start',name],timeout=60)
print('Libvirt network definition saved')
'''
    args = [payload.action, payload.name, payload.forward_mode, payload.bridge or "", str(address) if address else "", str(start) if start else "", str(end) if end else "", str(payload.autostart).lower(), str(payload.start_after_create).lower()]
    try:
        run_sudo_python(host, network_script, args, timeout=120)
    except Exception as exc:
        record_audit(access.user_id, f"libvirt.network.{payload.action}", f"{host_id}/{payload.name}", "failure", "Could not update libvirt network definition")
        raise HTTPException(502, "Could not update the libvirt network. Check its state, bridge, address range, and VM references, then retry.") from exc
    record_audit(access.user_id, f"libvirt.network.{payload.action}", f"{host_id}/{payload.name}", detail=f"mode={payload.forward_mode}; autostart={payload.autostart}")
    return {"success": True}


@app.post("/kvm-api/hosts/{host_id}/storage-pools/config")
def configure_storage_pool(host_id: str, payload: StoragePoolConfig, access: AuthorizationContext = Depends(require_permission("host_resources"))) -> dict[str, bool]:
    if not re.fullmatch(r"[A-Za-z0-9_.+-]+", payload.name):
        raise HTTPException(422, "Invalid storage pool name")
    if payload.action in ("create", "edit") and (not payload.target or not payload.target.startswith("/") or "\x00" in payload.target):
        raise HTTPException(422, "Enter an absolute directory path for the storage pool")
    host = cockpit_host_record(host_id)
    script = r'''import os,subprocess,sys,tempfile,xml.etree.ElementTree as ET
action,name,target=sys.argv[1:]
base=['virsh','-c','qemu:///system']
listing=subprocess.run(base+['pool-list','--all','--name'],capture_output=True,text=True,timeout=20)
if listing.returncode: raise SystemExit(listing.stderr.strip() or 'Could not list storage pools')
exists=name in listing.stdout.splitlines()
if action=='create':
    if exists: raise SystemExit('A storage pool with this name already exists')
    os.makedirs(target,exist_ok=True)
    cmd=base+['pool-define-as',name,'dir','--target',target]
elif action=='edit':
    if not exists: raise SystemExit('Storage pool not found')
    info=subprocess.run(base+['pool-info',name],capture_output=True,text=True,timeout=20)
    if info.returncode: raise SystemExit(info.stderr.strip() or 'Could not inspect storage pool')
    state=next((line.split(':',1)[1].strip().lower() for line in info.stdout.splitlines() if line.lower().startswith('state:')),'')
    if state=='running': raise SystemExit('Stop the storage pool before changing its target directory')
    dump=subprocess.run(base+['pool-dumpxml',name],capture_output=True,text=True,timeout=20)
    if dump.returncode: raise SystemExit(dump.stderr.strip() or 'Could not read storage pool definition')
    root=ET.fromstring(dump.stdout)
    if root.get('type')!='dir': raise SystemExit('Only directory storage pools can be edited')
    path=root.find('./target/path')
    if path is None: raise SystemExit('Storage pool has no target directory')
    os.makedirs(target,exist_ok=True)
    path.text=target
    with tempfile.NamedTemporaryFile(mode='w',encoding='utf-8',suffix='.xml') as definition:
        definition.write(ET.tostring(root,encoding='unicode')); definition.flush()
        cmd=base+['pool-define',definition.name]
else:
    if not exists: raise SystemExit('Storage pool not found')
    info=subprocess.run(base+['pool-info',name],capture_output=True,text=True,timeout=20)
    if info.returncode: raise SystemExit(info.stderr.strip() or 'Could not inspect storage pool')
    state=next((line.split(':',1)[1].strip().lower() for line in info.stdout.splitlines() if line.lower().startswith('state:')),'')
    if state=='running':
        stop=subprocess.run(base+['pool-destroy',name],capture_output=True,text=True,timeout=30)
        if stop.returncode: raise SystemExit(stop.stderr.strip() or 'Could not stop storage pool')
    cmd=base+['pool-undefine',name]
result=subprocess.run(cmd,capture_output=True,text=True,timeout=45)
if result.returncode: raise SystemExit(result.stderr.strip() or result.stdout.strip() or 'Storage pool change failed')
'''
    try:
        run_sudo_python(host, script, [payload.action, payload.name, payload.target or ""], timeout=90)
    except Exception as exc:
        record_audit(access.user_id, f"storage-pool.{payload.action}", f"{host_id}/{payload.name}", "failure", str(exc)[:500])
        raise HTTPException(502, f"Could not {payload.action} the storage pool: {exc}") from exc
    record_audit(access.user_id, f"storage-pool.{payload.action}", f"{host_id}/{payload.name}")
    return {"success": True}


@app.post("/kvm-api/hosts/{host_id}/terminal/command")
def run_terminal_command(host_id: str, payload: TerminalCommand, access: AuthorizationContext = Depends(require_permission("host_admin"))) -> dict[str, Any]:
    host = cockpit_host_record(host_id)
    client = ssh_client_for_host(host)
    try:
        _stdin, stdout, stderr = client.exec_command(f"bash -lc {shlex.quote(payload.command)}", timeout=60)
        output = stdout.read().decode("utf-8", "replace")
        error = stderr.read().decode("utf-8", "replace")
        status = stdout.channel.recv_exit_status()
    except Exception as exc:
        record_audit(access.user_id, "terminal.command", host_id, "failure", str(exc)[:500])
        raise HTTPException(502, f"Terminal command failed: {exc}") from exc
    finally:
        client.close()
    record_audit(access.user_id, "terminal.command", host_id, detail="Command executed as the imported SSH user")
    return {"stdout": output[-32000:], "stderr": error[-32000:], "return_code": status}


@app.post("/kvm-api/hosts/{host_id}/network-connections/actions")
def control_network_connection(host_id: str, payload: NetworkConnectionAction, access: AuthorizationContext = Depends(require_permission("host_resources"))) -> dict[str, bool]:
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
        record_audit(access.user_id, f"network-connection.{payload.action}", f"{host_id}/{payload.uuid}", "failure", str(exc)[:500])
        raise HTTPException(502, f"Could not change the network connection: {exc}") from exc
    record_audit(access.user_id, f"network-connection.{payload.action}", f"{host_id}/{payload.uuid}")
    return {"success": True}


@app.post("/kvm-api/hosts/{host_id}/network-connections/config")
def configure_network_connection(host_id: str, payload: NetworkConnectionConfig, access: AuthorizationContext = Depends(require_permission("host_resources"))) -> dict[str, bool]:
    if not re.fullmatch(r"[A-Fa-f0-9-]{16,64}", payload.uuid):
        raise HTTPException(422, "Invalid NetworkManager connection ID")
    try:
        addresses = [str(ipaddress.ip_interface(value)) for value in payload.addresses]
        gateway = str(ipaddress.ip_address(payload.gateway)) if payload.gateway else ""
        dns = [str(ipaddress.ip_address(value)) for value in payload.dns]
        ipv6_addresses = [str(ipaddress.ip_interface(value)) for value in payload.ipv6_addresses]
        ipv6_gateway = str(ipaddress.ip_address(payload.ipv6_gateway)) if payload.ipv6_gateway else ""
        ipv6_dns = [str(ipaddress.ip_address(value)) for value in payload.ipv6_dns]
        if any(ipaddress.ip_interface(value).version != 4 for value in addresses) or (gateway and ipaddress.ip_address(gateway).version != 4) or any(ipaddress.ip_address(value).version != 4 for value in dns):
            raise ValueError("IPv4 fields must contain IPv4 addresses")
        if any(ipaddress.ip_interface(value).version != 6 for value in ipv6_addresses) or (ipv6_gateway and ipaddress.ip_address(ipv6_gateway).version != 6) or any(ipaddress.ip_address(value).version != 6 for value in ipv6_dns):
            raise ValueError("IPv6 fields must contain IPv6 addresses")
    except ValueError as exc:
        raise HTTPException(422, f"Invalid network address: {exc}") from exc
    if payload.method == "manual" and not addresses:
        raise HTTPException(422, "At least one IP address is required for manual IPv4 configuration")
    if payload.ipv6_method == "manual" and not ipv6_addresses:
        raise HTTPException(422, "At least one IPv6 address is required for manual IPv6 configuration")
    host = cockpit_host_record(host_id)
    try:
        configure_network_with_checkpoint(host, payload.uuid, payload.method, ",".join(addresses), gateway, ",".join(dns), payload.ipv6_method, ",".join(ipv6_addresses), ipv6_gateway, ",".join(ipv6_dns), payload.autoconnect)
    except Exception as exc:
        record_audit(access.user_id, "network-connection.configure", f"{host_id}/{payload.uuid}", "failure", str(exc)[:500])
        raise HTTPException(502, f"Could not update the network connection: {exc}") from exc
    record_audit(access.user_id, "network-connection.configure", f"{host_id}/{payload.uuid}")
    return {"success": True}


def configure_network_with_checkpoint(host: dict[str, Any], connection_uuid: str, method: str, addresses: str, gateway: str, dns: str, ipv6_method: str, ipv6_addresses: str, ipv6_gateway: str, ipv6_dns: str, autoconnect: bool) -> None:
    """Use NetworkManager's built-in rollback timer and commit only after SSH recovers."""
    remote = r'''import os,select,subprocess,sys
uuid,method,addresses,gateway,dns,ipv6_method,ipv6_addresses,ipv6_gateway,ipv6_dns,autoconnect=sys.argv[1:]
check=subprocess.run(['nmcli','-t','-f','UUID','connection','show'],capture_output=True,text=True,timeout=20)
if check.returncode or uuid not in check.stdout.splitlines(): raise SystemExit('Network connection not found')
active=subprocess.run(['nmcli','-t','-f','UUID','connection','show','--active'],capture_output=True,text=True,timeout=20)
if active.returncode: raise SystemExit(active.stderr.strip() or 'Could not inspect active connections')
was_active=uuid in active.stdout.splitlines()
inner="import subprocess,sys; u,m,a,g,d,m6,a6,g6,d6,ac,wasflag=sys.argv[1:]; args=['nmcli','connection','modify',u,'ipv4.method',m,'ipv4.addresses',a,'ipv4.gateway',g,'ipv4.dns',d,'ipv6.method',m6,'ipv6.addresses',a6,'ipv6.gateway',g6,'ipv6.dns',d6,'connection.autoconnect',ac]; p=subprocess.run(args,capture_output=True,text=True); p.returncode and sys.exit(p.stderr or p.stdout); wasflag=='1' and subprocess.run(['nmcli','connection','up',u],check=True,timeout=60)"
cmd=['nmcli','device','checkpoint','--timeout','90','--','python3','-c',inner,uuid,method,addresses,gateway,dns,ipv6_method,ipv6_addresses,ipv6_gateway,ipv6_dns,autoconnect,'1' if was_active else '0']
p=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,bufsize=1)
recent=''
while p.poll() is None:
 ready,_,_=select.select([p.stdout],[],[],1)
 if not ready: continue
 chunk=os.read(p.stdout.fileno(),4096).decode('utf-8','replace')
 if not chunk: break
 sys.stdout.write(chunk); sys.stdout.flush(); recent=(recent+chunk.lower())[-1024:]
 if '?' in recent and ('keep' in recent or 'change' in recent or '[y/n]' in recent or '[yes/no]' in recent):
  print('KVM_NETWORK_CHECKPOINT_READY',flush=True)
  decision=sys.stdin.readline().strip()
  p.stdin.write(('Yes' if decision=='commit' else 'No')+'\n'); p.stdin.flush(); p.stdin.close(); break
try: out,_=p.communicate(timeout=95)
except subprocess.TimeoutExpired: p.kill(); raise SystemExit('NetworkManager checkpoint timed out and rolled back')
if out: print(out,end='')
if p.returncode: raise SystemExit('NetworkManager did not commit the checkpoint')
'''
    client = ssh_client_for_host(host)
    command = f"sudo -S -p '' python3 -c {shlex.quote(remote)} " + " ".join(shlex.quote(v) for v in (connection_uuid, method, addresses, gateway, dns, ipv6_method, ipv6_addresses, ipv6_gateway, ipv6_dns, "true" if autoconnect else "false"))
    try:
        stdin, stdout, stderr = client.exec_command(command, timeout=110)
        stdin.write(host["password"] + "\n"); stdin.flush()
        channel = stdout.channel
        output = ""
        deadline = datetime.now(timezone.utc).timestamp() + 105
        while datetime.now(timezone.utc).timestamp() < deadline:
            if channel.recv_ready():
                output += channel.recv(4096).decode("utf-8", "replace")
                if "KVM_NETWORK_CHECKPOINT_READY" in output:
                    break
            if channel.exit_status_ready():
                raise RuntimeError((output + stderr.read().decode("utf-8", "replace")).strip() or "NetworkManager checkpoint failed before applying changes")
            time.sleep(0.2)
        else:
            raise RuntimeError("Timed out waiting for the NetworkManager checkpoint; the host will roll back automatically")
        reachable = False
        last_error = "SSH reachability check failed"
        for _ in range(12):
            try:
                check_client = ssh_client_for_host(host)
                _, check_out, check_err = check_client.exec_command("true", timeout=5)
                reachable = check_out.channel.recv_exit_status() == 0
                check_client.close()
                if reachable: break
            except Exception as exc:
                last_error = str(exc)
            time.sleep(2)
        stdin.write(("commit" if reachable else "rollback") + "\n"); stdin.flush(); stdin.channel.shutdown_write()
        final_output = (output + stdout.read().decode("utf-8", "replace") + stderr.read().decode("utf-8", "replace")).replace("KVM_NETWORK_CHECKPOINT_READY", "").strip()
        if not reachable:
            raise RuntimeError(f"Could not re-establish SSH after the network change; NetworkManager rolled it back ({last_error})")
        if channel.recv_exit_status() != 0:
            raise RuntimeError(final_output or "NetworkManager checkpoint failed")
    finally:
        client.close()


@app.post("/kvm-api/hosts/{host_id}/accounts/actions")
def control_account(host_id: str, payload: AccountAction, access: AuthorizationContext = Depends(require_permission("host_resources"))) -> dict[str, bool]:
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", payload.username):
        raise HTTPException(422, "Invalid account name")
    host = cockpit_host_record(host_id)
    if payload.username == host["username"] and payload.action in ("lock", "delete"):
        raise HTTPException(422, "The SSH account used by this extension cannot be locked or deleted here")
    if payload.username == "root" and payload.action in ("lock", "delete"):
        raise HTTPException(422, "The root account cannot be locked or deleted here")
    if payload.action == "password" and (not payload.password or any(char in payload.password for char in ("\n", "\r", ":"))):
        raise HTTPException(422, "Enter a new password with at least 8 characters; colons and line breaks are not allowed")
    if payload.action == "create" and (not payload.password or any(char in payload.password for char in ("\n", "\r", ":"))):
        raise HTTPException(422, "Enter a new password with at least 8 characters; colons and line breaks are not allowed")
    if payload.action in ("create", "edit") and payload.shell and (not payload.shell.startswith("/") or "\x00" in payload.shell):
        raise HTTPException(422, "Shell must be an absolute path")
    if payload.action in ("create", "edit") and payload.home and (not payload.home.startswith("/") or "\x00" in payload.home):
        raise HTTPException(422, "Home directory must be an absolute path")
    if payload.action == "edit" and not (payload.shell or payload.home or payload.groups):
        raise HTTPException(422, "Specify a shell, home directory, or supplementary groups to update")
    if any(not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", group) for group in payload.groups):
        raise HTTPException(422, "Invalid group name")
    script = r'''import pwd,subprocess,sys
username,action,shell,home,groups=sys.argv[1:]
try: account=pwd.getpwnam(username)
except KeyError: account=None
if action=='create':
    if account: raise SystemExit('Account already exists')
    args=['useradd','--create-home']
    if shell: args += ['--shell',shell]
    if home: args += ['--home-dir',home]
    if groups: args += ['--groups',groups]
    args.append(username)
    result=subprocess.run(args,capture_output=True,text=True)
    if result.returncode: raise SystemExit(result.stderr.strip() or result.stdout.strip() or 'Account creation failed')
    print('KVM_STDIN_READY',flush=True)
    password=sys.stdin.readline().rstrip('\n')
    result=subprocess.run(['chpasswd'],input=f'{username}:{password}\n',text=True,capture_output=True)
    if result.returncode: raise SystemExit(result.stderr.strip() or 'Could not set account password')
    sys.exit(0)
if not account: raise SystemExit('Account not found')
if action=='delete':
    result=subprocess.run(['userdel',username],capture_output=True,text=True)
    if result.returncode: raise SystemExit(result.stderr.strip() or result.stdout.strip() or 'Account deletion failed')
    sys.exit(0)
if action=='lock' and account.pw_uid==0: raise SystemExit('The root account cannot be locked here')
if action=='lock': args=['usermod','--lock',username]
elif action=='unlock': args=['usermod','--unlock',username]
elif action=='edit':
    args=['usermod']
    if shell: args += ['--shell',shell]
    if home: args += ['--home',home]
    if groups: args += ['--groups',groups]
    args.append(username)
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
    if payload.action == "create":
        extra_input = (payload.password or "") + "\n"
    try:
        run_sudo_python(host, script, [payload.username, payload.action, payload.shell or "", payload.home or "", ",".join(payload.groups)], timeout=45, stdin_data=extra_input)
    except Exception as exc:
        record_audit(access.user_id, f"account.{payload.action}", f"{host_id}/{payload.username}", "failure", str(exc)[:500])
        raise HTTPException(502, f"Could not update the account: {exc}") from exc
    record_audit(access.user_id, f"account.{payload.action}", f"{host_id}/{payload.username}")
    return {"success": True}


@app.post("/kvm-api/hosts/{host_id}/services/actions")
def control_service(host_id: str, payload: ServiceAction, service_name: str, access: AuthorizationContext = Depends(require_permission("host_resources"))) -> dict[str, bool]:
    if not re.fullmatch(r"[A-Za-z0-9_.@:-]+", service_name):
        raise HTTPException(422, "Invalid service name")
    host = cockpit_host_record(host_id)
    try:
        run_sudo_python(host, SERVICE_ACTION_SCRIPT, [payload.action, service_name], timeout=45)
    except Exception as exc:
        record_audit(access.user_id, f"service.{payload.action}", f"{host_id}/{service_name}", "failure", str(exc))
        raise HTTPException(502, f"Could not perform the service action: {exc}") from exc
    record_audit(access.user_id, f"service.{payload.action}", f"{host_id}/{service_name}")
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


@app.post("/kvm-api/hosts/{host_id}/vms/actions")
def control_vm(host_id: str, payload: VMAction, vm_name: str, access: AuthorizationContext = Depends(require_permission("vm_operator"))) -> dict[str, bool]:
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
        record_audit(access.user_id, f"vm.{payload.action}", f"{host_id}/{vm_name}", "failure", str(exc))
        raise HTTPException(502, f"Could not perform the libvirt action: {exc}") from exc
    record_audit(access.user_id, f"vm.{payload.action}", f"{host_id}/{vm_name}")
    return {"success": True}


@app.post("/kvm-api/hosts/{host_id}/vms/autostart")
def set_vm_autostart(host_id: str, payload: VMAutostart, vm_name: str, access: AuthorizationContext = Depends(require_permission("vm_operator"))) -> dict[str, bool]:
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
        record_audit(access.user_id, "vm.autostart", f"{host_id}/{vm_name}", "failure", str(exc))
        raise HTTPException(502, f"Could not change autostart: {exc}") from exc
    record_audit(access.user_id, "vm.autostart", f"{host_id}/{vm_name}", detail=f"enabled={payload.enabled}")
    return {"success": True}


@app.post("/kvm-api/hosts/{host_id}/vms/config")
def configure_vm(host_id: str, payload: VMConfig, vm_name: str, access: AuthorizationContext = Depends(require_permission("vm_operator"))) -> dict[str, bool]:
    """Update a persistent VM's CPU and memory settings; changes apply after restart."""
    host = cockpit_host_record(host_id)
    encoded_name = base64.b64encode(vm_name.encode()).decode()
    config_script = r'''import base64, os, subprocess, sys, tempfile, xml.etree.ElementTree as ET
name=base64.b64decode(sys.argv[1]).decode()
vcpus=int(sys.argv[2]); memory_kib=int(sys.argv[3])
base=['virsh','-c','qemu:///system']
def run(args):
 result=subprocess.run(args,capture_output=True,text=True,timeout=30)
 if result.returncode: raise SystemExit(result.stderr.strip() or result.stdout.strip() or 'Libvirt command failed')
 return result.stdout
domains=run(base+['list','--all','--name']).splitlines()
if name not in [item.strip() for item in domains]: raise SystemExit('Virtual machine not found')
xml=run(base+['dumpxml','--inactive',name])
root=ET.fromstring(xml)
vcpu=root.find('./vcpu')
memory=root.find('./memory')
if vcpu is None or memory is None: raise SystemExit('This VM does not expose editable persistent CPU and memory settings')
vcpu.text=str(vcpus)
vcpu.attrib.pop('current',None)
memory.text=str(memory_kib)
memory.set('unit','KiB')
current=root.find('./currentMemory')
if current is None:
 current=ET.Element('currentMemory')
 memory_index=list(root).index(memory)
 root.insert(memory_index+1,current)
current.text=str(memory_kib)
current.set('unit','KiB')
fd,path=tempfile.mkstemp(prefix='kvm-vm-config-',suffix='.xml')
try:
 with os.fdopen(fd,'w',encoding='utf-8') as handle:
  handle.write(ET.tostring(root,encoding='unicode'))
 result=subprocess.run(base+['define',path],capture_output=True,text=True,timeout=30)
 if result.returncode: raise SystemExit(result.stderr.strip() or result.stdout.strip() or 'Could not save VM configuration')
finally:
 try: os.unlink(path)
 except FileNotFoundError: pass
print('VM persistent CPU and memory configuration updated')
'''
    try:
        run_sudo_python(host, config_script, [encoded_name, str(payload.vcpus), str(payload.memory_mib * 1024)], timeout=50)
    except Exception as exc:
        record_audit(access.user_id, "vm.configuration", f"{host_id}/{vm_name}", "failure", "Could not update persistent CPU and memory settings")
        raise HTTPException(502, "Could not update the VM configuration. Confirm the VM is persistent and the host is reachable.") from exc
    record_audit(access.user_id, "vm.configuration", f"{host_id}/{vm_name}", detail=f"vcpus={payload.vcpus}; memory_mib={payload.memory_mib}")
    return {"success": True}


@app.post("/kvm-api/hosts/{host_id}/vms/details-config")
def configure_vm_details(host_id: str, payload: VMDetailsConfig, vm_name: str, access: AuthorizationContext = Depends(require_permission("vm_operator"))) -> dict[str, bool]:
    if len(set(payload.boot_order)) != len(payload.boot_order):
        raise HTTPException(422, "Each boot device can appear only once")
    if payload.cpu_mode == "custom" and (not payload.cpu_model or not re.fullmatch(r"[A-Za-z0-9_.+-]{1,100}", payload.cpu_model)):
        raise HTTPException(422, "Enter a valid libvirt CPU model when using custom CPU mode")
    host = cockpit_host_record(host_id)
    encoded_name = base64.b64encode(vm_name.encode()).decode()
    config_script = r'''import base64,os,re,subprocess,sys,tempfile,xml.etree.ElementTree as ET
name=base64.b64decode(sys.argv[1]).decode(); description,mode,cpu_model,boot_text,autostart=sys.argv[2:]
boot=boot_text.split(',') if boot_text else []
if not re.fullmatch(r'[A-Za-z0-9_.+-]{1,100}',cpu_model) and mode=='custom': raise SystemExit('Invalid custom CPU model')
if not boot or len(boot)>3 or len(set(boot))!=len(boot) or any(item not in ('hd','cdrom','network') for item in boot): raise SystemExit('Invalid boot device order')
base=['virsh','-c','qemu:///system']
def run(args):
 r=subprocess.run(args,capture_output=True,text=True,timeout=35)
 if r.returncode: raise SystemExit(r.stderr.strip() or r.stdout.strip() or 'Libvirt configuration failed')
 return r.stdout
if name not in [x.strip() for x in run(base+['list','--all','--name']).splitlines()]: raise SystemExit('Virtual machine not found')
root=ET.fromstring(run(base+['dumpxml','--inactive',name]))
description_node=root.find('./description')
if description:
 if description_node is None: description_node=ET.Element('description'); root.insert(1,description_node)
 description_node.text=description
elif description_node is not None: root.remove(description_node)
cpu=root.find('./cpu')
if cpu is None: cpu=ET.Element('cpu'); root.insert(list(root).index(root.find('./devices')) if root.find('./devices') is not None else len(root),cpu)
cpu.set('mode',mode)
model=cpu.find('./model')
if mode=='custom':
 if model is None: model=ET.SubElement(cpu,'model')
 model.attrib.clear(); model.text=cpu_model
elif model is not None:
 cpu.remove(model)
os_node=root.find('./os')
if os_node is None: raise SystemExit('VM has no editable boot configuration')
for item in list(os_node.findall('./boot')): os_node.remove(item)
for device in boot: ET.SubElement(os_node,'boot',{'dev':device})
fd,path=tempfile.mkstemp(prefix='kvm-vm-details-',suffix='.xml')
try:
 with os.fdopen(fd,'w',encoding='utf-8') as handle: handle.write(ET.tostring(root,encoding='unicode'))
 run(base+['define',path])
finally:
 try: os.unlink(path)
 except FileNotFoundError: pass
run(base+(['autostart',name] if autostart=='true' else ['autostart','--disable',name]))
print('Persistent VM details updated')
'''
    try:
        run_sudo_python(host, config_script, [encoded_name, payload.description.strip(), payload.cpu_mode, payload.cpu_model or "", ",".join(payload.boot_order), str(payload.autostart).lower()], timeout=60)
    except Exception as exc:
        record_audit(access.user_id, "vm.details.configuration", f"{host_id}/{vm_name}", "failure", "Could not update persistent VM detail settings")
        raise HTTPException(502, "Could not update VM details. Confirm the VM is persistent and the selected CPU mode and boot devices are supported.") from exc
    record_audit(access.user_id, "vm.details.configuration", f"{host_id}/{vm_name}", detail=f"cpu_mode={payload.cpu_mode}; boot_order={','.join(payload.boot_order)}; autostart={payload.autostart}")
    return {"success": True}


@app.get("/kvm-api/audit")
def list_audit(limit: int = 100, access: AuthorizationContext = Depends(require_permission("host_admin"))) -> list[dict[str, Any]]:
    limit = min(max(limit, 1), 500)
    with connect_db() as db:
        rows = db.execute("SELECT occurred_at,actor,action,target,outcome,detail FROM audit_events ORDER BY occurred_at DESC LIMIT ?", (limit,))
        return [dict(row) for row in rows]
