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
import boto3
from botocore.config import Config as BotoConfig
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, WebSocket
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import RedirectResponse, StreamingResponse
from pydantic import BaseModel, Field, StrictBool, field_validator, model_validator
from starlette.websockets import WebSocketDisconnect


DB_PATH = Path(os.getenv("KVM_DB_PATH", "./data/kvm-hosts.sqlite3"))
KNOWN_HOSTS = os.getenv("KVM_KNOWN_HOSTS", "./known_hosts")
credential_key = os.environ.get("KVM_CREDENTIAL_KEY", "")
RANCHER_API_URL = os.getenv("RANCHER_API_URL", "https://rancher.example.com").rstrip("/")
RANCHER_CA_FILE = os.getenv("RANCHER_CA_FILE", "").strip() or None
if len(credential_key) < 32:
    raise RuntimeError("Configure KVM_CREDENTIAL_KEY with at least 32 random characters")
FERNET_KEY = base64.urlsafe_b64encode(hashlib.sha256(credential_key.encode()).digest())
cipher = Fernet(FERNET_KEY)
app = FastAPI(title="Rancher KVM Host API", version="0.7.143")
performance_logger = logging.getLogger("kvm.performance")


@app.exception_handler(RequestValidationError)
async def log_preflight_validation_shape(request: Request, exc: RequestValidationError):
    # Record only the received Python type and validation code, never IDs or
    # raw request values, so a recurring UI/API contract mismatch is diagnosable.
    response = await request_validation_exception_handler(request, exc)
    if request.url.path == "/kvm-api/clusters/preflight":
        response.headers["X-KVM-API-Version"] = app.version
        for issue in exc.errors():
            if "host_ids" in issue.get("loc", ()):
                received_type = type(issue.get("input")).__name__
                performance_logger.warning(
                    "preflight_request_validation_failed field=host_ids received_type=%s error_type=%s",
                    received_type,
                    issue.get("type", "unknown"),
                )
                # Expose only the input's Python type, never its contents, so
                # the UI can distinguish a transport-shape mismatch safely.
                response.headers["X-KVM-Preflight-Host-Ids-Type"] = received_type
                break
    return response


OPERATION_JOB_EXECUTOR = ThreadPoolExecutor(max_workers=4, thread_name_prefix="kvm-operation")
OPERATION_JOB_LOCK = threading.RLock()
# The API deployment runs one Uvicorn worker. Keep host-scoped mutation locks
# in-process so concurrent users cannot race crmsh or HA package operations.
CLUSTER_MUTATION_LOCK_GUARD = threading.Lock()
CLUSTER_MUTATION_LOCKS: dict[str, dict[str, Any]] = {}
try:
    MAX_ACTIVE_OPERATION_JOBS = max(1, int(os.getenv("KVM_MAX_ACTIVE_OPERATION_JOBS", "8")))
except ValueError:
    MAX_ACTIVE_OPERATION_JOBS = 8
KVM_S3_ALLOWED_ENDPOINT_HOSTS = {
    host.strip().lower().rstrip(".")
    for host in os.getenv("KVM_S3_ALLOWED_ENDPOINT_HOSTS", "").split(",")
    if host.strip()
}
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
SUPPORTED_SLES_HA_RELEASES = frozenset({
    "15.3", "15.4", "15.5", "15.6", "15.7",
    "15-SP3", "15-SP4", "15-SP5", "15-SP6", "15-SP7", "16.0", "16.1",
})


def render_sles_release_script(script: str) -> str:
    """Inject one backend-owned SLES support list into fixed remote scripts."""
    return script.replace(
        "__SLES_HA_SUPPORTED_RELEASES__",
        repr(sorted(SUPPORTED_SLES_HA_RELEASES)),
    )


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
    with connect_db() as db:
        initialize_schema(db)
        db.execute("CREATE INDEX IF NOT EXISTS idx_audit_events_occurred_at ON audit_events(occurred_at DESC)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_audit_events_target_occurred ON audit_events(target,occurred_at DESC)")
        db.execute("UPDATE operation_jobs SET status='failed',updated_at=? WHERE status IN ('queued','running')",
                   (now(),))
        for row in db.execute("SELECT id,results_json FROM operation_jobs WHERE status='failed'"):
            try:
                results = json.loads(row["results_json"])
                changed = False
                for item in results:
                    if item.get("status") in ("queued", "running"):
                        item.update({"status": "error", "error": "The API restarted before this operation completed. Refresh host status before retrying."})
                        changed = True
                if changed:
                    db.execute("UPDATE operation_jobs SET results_json=? WHERE id=?", (json.dumps(results), row["id"]))
            except (TypeError, ValueError):
                continue
        db.execute(
            "DELETE FROM audit_events WHERE occurred_at < ?",
            ((datetime.now(timezone.utc) - timedelta(days=AUDIT_RETENTION_DAYS)).isoformat(),),
        )
        db.execute(
            "DELETE FROM stonith_status_checks WHERE checked_at < ?",
            ((datetime.now(timezone.utc) - timedelta(days=AUDIT_RETENTION_DAYS)).isoformat(),),
        )
        db.execute("DELETE FROM operation_jobs WHERE created_at < ?",
                   ((datetime.now(timezone.utc) - timedelta(days=30)).isoformat(),))
    # The database contains encrypted host and backup credentials plus host
    # inventory. Keep it private even when the PVC or process umask is broader.
    for path in (DB_PATH, Path(f"{DB_PATH}-wal"), Path(f"{DB_PATH}-shm")):
        try:
            path.chmod(0o600)
        except FileNotFoundError:
            continue


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
    action: Literal["start", "shutdown", "reboot", "pause", "resume", "force_stop"]


class VMDeleteRequest(BaseModel):
    vm_names: list[str] = Field(min_length=1, max_length=10)


class ClusterPreflightRequest(BaseModel):
    host_ids: list[str] = Field(min_length=2, max_length=32)
    qnetd_host: str = Field(default="", max_length=253)

    @field_validator("host_ids", mode="before")
    @classmethod
    def decode_serialized_host_id_list(cls, value: Any) -> Any:
        # Tolerate older UI builds that wrap selections or send host records
        # instead of IDs. Only read explicit ID fields; never infer IDs from
        # arbitrary object properties (for example a Vue click event).
        def host_ids_from_list(items: list[Any]) -> list[Any]:
            ids = []
            for item in items:
                if isinstance(item, str):
                    ids.append(item)
                elif isinstance(item, dict):
                    host_id = item.get("id", item.get("host_id"))
                    if isinstance(host_id, str):
                        ids.append(host_id)
                    else:
                        # Let Pydantic return a useful type error for a list
                        # containing an unsupported entry.
                        return items
                else:
                    return items
            return ids

        if isinstance(value, list):
            return host_ids_from_list(value)
        if isinstance(value, dict):
            for key in ("host_ids", "selected_host_ids", "selectedHosts", "selected_hosts", "hosts", "ids", "value"):
                nested = value.get(key)
                if isinstance(nested, list):
                    return host_ids_from_list(nested)
            if value and all(isinstance(selected, bool) for selected in value.values()):
                return [host_id for host_id, selected in value.items() if selected]
        if isinstance(value, str):
            try:
                decoded = json.loads(value)
            except (TypeError, ValueError):
                return value
            if isinstance(decoded, list):
                return host_ids_from_list(decoded)
        return value


class ManagedKvmClusterInput(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    host_ids: list[str] = Field(min_length=2, max_length=32)


class ManagedSuseHaClusterInput(BaseModel):
    host_id: str = Field(min_length=1, max_length=128)


class ClusterPlanInput(BaseModel):
    name: str = Field(default="", max_length=64)
    cluster_type: Literal["suse-ha", "kvm-virtualization"] = "suse-ha"
    host_ids: list[str] = Field(default_factory=list, max_length=32)
    template_id: Literal["service", "vm", "web", "nfs"] | None = None
    step: int = Field(default=0, ge=0, le=4)
    quorum: Literal["pending", "qdevice", "standard"] = "pending"
    qnetd_host: str = Field(default="", max_length=253)
    qnetd_outside_cluster: bool = False
    fencing: Literal["pending", "sbd", "hardware", "manual"] = "pending"
    corosync_networks: list[str] = Field(default_factory=list, max_length=2)
    corosync_network_reviewed: bool = False


class ClusterQnetdPrepareInput(BaseModel):
    host_id: str = Field(min_length=1, max_length=64)


class ClusterQnetdWitnessPrepareInput(BaseModel):
    witness_id: str = Field(min_length=1, max_length=64)


class QnetdWitnessProbeInput(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    address: str = Field(min_length=1, max_length=253)
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)

    @field_validator("name", "username")
    @classmethod
    def require_nonblank_label(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("This field cannot be blank")
        return value


class QnetdWitnessCreateInput(QnetdWitnessProbeInput):
    expected_fingerprint: str = Field(min_length=20, max_length=80)


class QnetdWitnessFingerprintInput(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    address: str = Field(min_length=1, max_length=253)
    port: int = Field(default=22, ge=1, le=65535)


class QnetdWitnessVerifyInput(QnetdWitnessProbeInput):
    expected_fingerprint: str = Field(min_length=20, max_length=80)


class ClusterQdevicePrepareInput(BaseModel):
    host_ids: list[str] = Field(min_length=1, max_length=32)


def validate_qnetd_host(value: str) -> str:
    """Accept only a DNS host name or IP literal for the fixed TCP/5403 probe."""
    host = value.strip().rstrip(".")
    if not host or len(host) > 253 or any(ord(char) < 33 or ord(char) > 126 for char in host):
        raise HTTPException(422, "Enter a valid QNetd hostname or IP address")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    labels = host.split(".")
    if any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label) for label in labels):
        raise HTTPException(422, "Enter a valid QNetd hostname or IP address")
    return host


def validate_corosync_networks(values: list[str]) -> list[str]:
    """Canonicalize up to two distinct IP subnets saved as planning hints."""
    networks: list[str] = []
    for value in values:
        if not isinstance(value, str) or not value.strip():
            raise HTTPException(422, "Select valid Corosync network subnets")
        try:
            network = str(ipaddress.ip_network(value.strip(), strict=False))
        except ValueError as exc:
            raise HTTPException(422, "Select valid Corosync network subnets") from exc
        if network in networks:
            raise HTTPException(422, "Corosync communication channels must use different subnets")
        networks.append(network)
    if len(networks) > 2:
        raise HTTPException(422, "Select at most two Corosync communication channels")
    return networks


def normalize_cluster_endpoint(value: Any) -> str:
    """Canonicalize a selected node or QNetd endpoint for outside-cluster checks."""
    endpoint = str(value or "").strip()
    try:
        return ipaddress.ip_address(endpoint).compressed.casefold()
    except ValueError:
        return endpoint.rstrip(".").casefold()


class BackupDestinationInput(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    endpoint_url: str | None = Field(default=None, max_length=512)
    region: str = Field(default="us-east-1", min_length=1, max_length=64)
    bucket: str = Field(min_length=3, max_length=63)
    prefix: str = Field(default="rancher-kvm", max_length=512)
    auth: Literal["access-key", "workload-identity"] = "access-key"
    access_key_id: str | None = Field(default=None, max_length=256)
    secret_access_key: str | None = Field(default=None, max_length=1024)
    path_style: bool = False
    encryption: Literal["provider-default", "sse-s3", "sse-kms", "none"] = "sse-s3"
    kms_key_id: str | None = Field(default=None, max_length=256)


class BackupJobInput(BaseModel):
    destination_id: str = Field(min_length=1, max_length=64)
    host_id: str = Field(min_length=1, max_length=64)
    vm_name: str = Field(min_length=1, max_length=255)


class ClusterAction(BaseModel):
    action: Literal["node_standby", "node_online", "node_maintenance", "node_ready", "resource_start", "resource_stop", "resource_cleanup"]
    target: str = Field(min_length=1, max_length=255)


class ClusterResourceMonitorOperation(BaseModel):
    operation_id: str | None = Field(default=None, max_length=128)
    interval: str = Field(min_length=1, max_length=16)
    role: Literal["", "Started", "Stopped", "Promoted", "Unpromoted", "Master", "Slave"] = ""
    timeout: str | None = Field(default=None, max_length=16)


class ClusterResourceMutation(BaseModel):
    action: Literal["create", "create_stonith", "edit_stonith", "delete_stonith", "set_param", "delete_param", "set_meta", "delete_meta", "delete", "create_group", "create_clone", "edit_clone", "delete_clone", "add_group_member", "remove_group_member", "reorder_group", "delete_group", "set_monitor_ops"]
    resource_id: str = Field(min_length=1, max_length=128)
    agent: str | None = Field(default=None, max_length=256)
    parameters: dict[str, str] = Field(default_factory=dict)
    parameter_removals: list[str] = Field(default_factory=list, max_length=40)
    operations: list[ClusterResourceMonitorOperation] = Field(default_factory=list, max_length=16)
    expected_operation_ids: list[str] = Field(default_factory=list, max_length=16)
    expected_operations: list[ClusterResourceMonitorOperation] = Field(default_factory=list, max_length=16)
    children: list[str] = Field(default_factory=list, max_length=128)
    child_id: str | None = Field(default=None, max_length=128)
    clone_type: Literal["standard", "promotable"] = "standard"
    clone_metadata: dict[str, str] = Field(default_factory=dict, max_length=8)
    expected_clone_metadata: dict[str, str] = Field(default_factory=dict, max_length=8)
    key: str | None = Field(default=None, max_length=64)
    value: str | None = Field(default=None, max_length=2048)
    fencing_target: str | None = Field(default=None, max_length=255)
    monitor_interval: str = Field(default="30min", max_length=16)
    monitor_timeout: str = Field(default="120s", max_length=16)


class VirtualDomainPrepareRequest(BaseModel):
    vm_name: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    resource_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    config_path: str = Field(min_length=6, max_length=1024)
    shared_disks_confirmed: StrictBool
    networks_confirmed: StrictBool
    remote_libvirt_confirmed: StrictBool
    fencing_tested: StrictBool
    security_reviewed: StrictBool


class StonithStatusCheckRequest(BaseModel):
    device_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


class ClusterNfsServiceRequest(BaseModel):
    storage_mode: Literal["drbd", "shared"]
    shared_storage_confirmed: bool = False
    resource_prefix: str = Field(default="nfs", min_length=1, max_length=48, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    drbd_resource: str = Field(default="nfs", min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    state_device: str = Field(min_length=1, max_length=255)
    data_device: str = Field(min_length=1, max_length=255)
    share_directory: str = Field(default="/srv/nfs/share", min_length=2, max_length=255)
    filesystem: Literal["ext4", "xfs"] = "ext4"
    clientspec: str = Field(min_length=3, max_length=64)
    virtual_ip: str = Field(min_length=3, max_length=64)
    cidr_netmask: int = Field(ge=1, le=128)

    @field_validator("state_device", "data_device")
    @classmethod
    def validate_block_device_path(cls, value: str) -> str:
        value = value.strip()
        if not value.startswith("/dev/") or any(ord(char) < 33 for char in value) or ".." in value.split("/"):
            raise ValueError("Use an absolute device path under /dev without whitespace or parent-directory segments")
        return value

    @field_validator("share_directory")
    @classmethod
    def validate_nfs_export_directory(cls, value: str) -> str:
        value = value.strip()
        if not value.startswith("/") or value == "/" or any(ord(char) < 33 for char in value) or ".." in value.split("/"):
            raise ValueError("Use an absolute export directory other than /, without whitespace or parent-directory segments")
        return value.rstrip("/")

    @field_validator("clientspec")
    @classmethod
    def validate_nfs_clientspec(cls, value: str) -> str:
        try:
            return str(ipaddress.ip_network(value.strip(), strict=False))
        except ValueError as exc:
            raise ValueError("Enter a valid IPv4 or IPv6 client network in CIDR notation") from exc

    @field_validator("virtual_ip")
    @classmethod
    def validate_nfs_virtual_ip(cls, value: str) -> str:
        try:
            return str(ipaddress.ip_address(value.strip()))
        except ValueError as exc:
            raise ValueError("Enter a valid IPv4 or IPv6 virtual IP address") from exc

    @model_validator(mode="after")
    def validate_nfs_profile(self):
        if self.state_device == self.data_device:
            raise ValueError("The NFS client-state device and export-data device must be different")
        address = ipaddress.ip_address(self.virtual_ip)
        if self.cidr_netmask > address.max_prefixlen:
            raise ValueError("The virtual-IP prefix length does not match its address family")
        if self.storage_mode == "drbd" and (not self.state_device.startswith("/dev/drbd") or not self.data_device.startswith("/dev/drbd")):
            raise ValueError("DRBD mode requires the two existing DRBD device paths, for example /dev/drbd0 and /dev/drbd1")
        return self


class ClusterServiceVipRequest(BaseModel):
    profile: Literal["service", "apache"] = "service"
    resource_prefix: str = Field(default="app", min_length=1, max_length=48, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    service_unit: str = Field(min_length=1, max_length=128)
    apache_configfile: str | None = Field(default=None, min_length=2, max_length=255)
    apache_start_order_confirmed: bool = False
    virtual_ip: str = Field(min_length=3, max_length=64)
    cidr_netmask: int = Field(ge=1, le=128)
    shared_network_confirmed: bool = False

    @field_validator("service_unit")
    @classmethod
    def validate_service_unit(cls, value: str) -> str:
        value = value.strip()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@:-]{0,120}\.service", value):
            raise ValueError("Use an installed systemd unit name ending in .service, without paths or shell syntax")
        return value

    @field_validator("apache_configfile")
    @classmethod
    def validate_apache_configfile(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value.startswith("/") or any(ord(char) < 33 for char in value) or ".." in value.split("/"):
            raise ValueError("Use an absolute Apache configuration path without whitespace or parent-directory segments")
        return value

    @field_validator("virtual_ip")
    @classmethod
    def validate_service_vip(cls, value: str) -> str:
        try:
            return str(ipaddress.ip_address(value.strip()))
        except ValueError as exc:
            raise ValueError("Enter a valid IPv4 or IPv6 virtual IP address") from exc

    @model_validator(mode="after")
    def validate_service_profile(self):
        address = ipaddress.ip_address(self.virtual_ip)
        if self.cidr_netmask > address.max_prefixlen:
            raise ValueError("The virtual-IP prefix length does not match its address family")
        if address.is_unspecified or address.is_multicast or address.is_loopback:
            raise ValueError("Choose a usable unicast VIP, not loopback, unspecified, or multicast")
        if not self.shared_network_confirmed:
            raise ValueError("Confirm that the virtual IP is available on the same client-facing network from every cluster node")
        if self.profile == "apache" and not self.apache_configfile:
            raise ValueError("Choose the existing Apache configuration file on every cluster node")
        if self.profile == "apache" and not self.apache_start_order_confirmed:
            raise ValueError("Confirm Apache can start before the VIP is assigned, as required by the SUSE HA Apache resource group order")
        return self


class ClusterConstraintMutation(BaseModel):
    action: Literal["create_location", "create_order", "create_colocation", "delete"]
    constraint_id: str = Field(min_length=1, max_length=128)
    resource: str | None = Field(default=None, max_length=128)
    other_resource: str | None = Field(default=None, max_length=128)
    node: str | None = Field(default=None, max_length=255)
    score: str | None = Field(default=None, max_length=16)
    order_kind: Literal["Mandatory", "Optional", "Serialize"] = "Mandatory"


class ClusterInstallRequest(BaseModel):
    host_ids: list[str] = Field(min_length=1, max_length=10)


class ClusterPrerequisiteResolution(BaseModel):
    host_ids: list[str] = Field(min_length=1, max_length=10)
    action: Literal["enable_time_sync", "install_web_package", "install_nfs_package"]


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


class VMGraphicsConfig(BaseModel):
    action: Literal["enable_vnc"] = "enable_vnc"


class VMCreate(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    pool: str = Field(min_length=1, max_length=128)
    volume: str | None = Field(default=None, min_length=1, max_length=128)
    network: str = Field(min_length=1, max_length=128)
    vcpus: int = Field(ge=1, le=512)
    memory_mib: int = Field(ge=128, le=1048576)
    iso_path: str | None = Field(default=None, max_length=1024)
    iso_url: str | None = Field(default=None, max_length=2048)
    image_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")
    create_disk: bool = False
    disk_size_gib: int = Field(default=20, ge=1, le=10240)
    autostart: bool = False


def validate_public_iso_url(value: str) -> str:
    """Allow public HTTPS ISO downloads while rejecting private-network targets."""
    parsed = urlsplit(value.strip())
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Use a public HTTPS URL ending in .iso, without credentials or a custom port") from exc
    if (
        parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
        or port not in (None, 443) or parsed.fragment
        or not parsed.path.lower().endswith(".iso")
    ):
        raise ValueError("Use a public HTTPS URL ending in .iso, without credentials or a custom port")
    try:
        addresses = {ipaddress.ip_address(item[4][0].split("%", 1)[0]) for item in socket.getaddrinfo(parsed.hostname, 443, type=socket.SOCK_STREAM)}
    except (OSError, ValueError) as exc:
        raise ValueError("The ISO URL host could not be resolved") from exc
    if not addresses or any(not address.is_global for address in addresses):
        raise ValueError("The ISO URL must resolve only to public IP addresses")
    return value.strip()


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


class StoragePoolSetupSelection(BaseModel):
    mode: Literal["existing", "create"]
    name: str = Field(min_length=1, max_length=128)
    target: str | None = Field(default=None, max_length=512)


class StoragePoolSetupRequest(BaseModel):
    vm_pool: StoragePoolSetupSelection
    iso_pool: StoragePoolSetupSelection


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
    action: Literal["enable", "disable", "refresh", "add", "edit", "remove"]
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
    db = sqlite3.connect(DB_PATH, timeout=10)
    db.row_factory = sqlite3.Row
    try:
        db.execute("PRAGMA busy_timeout=10000")
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def initialize_schema(db: sqlite3.Connection) -> None:
    """Create and migrate the extension database once during API startup."""
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
    db.execute("""CREATE TABLE IF NOT EXISTS stonith_status_checks (
            host_id TEXT NOT NULL, resource_id TEXT NOT NULL, checked_at TEXT NOT NULL,
            status TEXT NOT NULL, result_code TEXT NOT NULL,
            PRIMARY KEY(host_id, resource_id)
        )""")
    db.execute("""CREATE TABLE IF NOT EXISTS operation_jobs (
            id TEXT PRIMARY KEY, actor TEXT NOT NULL, kind TEXT NOT NULL,
            status TEXT NOT NULL, results_json TEXT NOT NULL,
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        )""")
    db.execute("""CREATE TABLE IF NOT EXISTS managed_clusters (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, cluster_type TEXT NOT NULL,
            state TEXT NOT NULL, host_ids_json TEXT NOT NULL, template_id TEXT,
            created_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
            last_checked_at TEXT, capabilities_json TEXT NOT NULL DEFAULT '{}'
        )""")
    db.execute("""CREATE TABLE IF NOT EXISTS cluster_plans (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, cluster_type TEXT NOT NULL,
            host_ids_json TEXT NOT NULL, template_id TEXT, step INTEGER NOT NULL,
            config_json TEXT NOT NULL, created_by TEXT NOT NULL,
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        )""")
    db.execute("""CREATE TABLE IF NOT EXISTS managed_suse_ha_clusters (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, cluster_identity TEXT NOT NULL,
            anchor_host_id TEXT NOT NULL, member_names_json TEXT NOT NULL,
            member_host_ids_json TEXT NOT NULL, created_by TEXT NOT NULL,
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL, last_checked_at TEXT NOT NULL
        )""")
    db.execute("""CREATE TABLE IF NOT EXISTS qnetd_witnesses (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, address TEXT NOT NULL, port INTEGER NOT NULL,
            username TEXT NOT NULL, password TEXT NOT NULL, hostname TEXT NOT NULL, status TEXT NOT NULL,
            os_id TEXT NOT NULL, os_version TEXT NOT NULL, ha_product TEXT NOT NULL,
            ha_active INTEGER NOT NULL, qnetd_package_installed INTEGER NOT NULL,
            time_synchronized INTEGER NOT NULL, registered_address_is_dynamic INTEGER,
            ssh_host_key TEXT NOT NULL, created_by TEXT NOT NULL,
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL, last_checked_at TEXT NOT NULL
        )""")
    db.execute("""CREATE TABLE IF NOT EXISTS backup_destinations (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, endpoint_url TEXT, region TEXT NOT NULL,
            bucket TEXT NOT NULL, prefix TEXT NOT NULL, auth TEXT NOT NULL,
            access_key_id_enc TEXT, secret_access_key_enc TEXT, path_style INTEGER NOT NULL,
            encryption TEXT NOT NULL, kms_key_id TEXT, created_by TEXT NOT NULL,
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        )""")
    db.execute("""CREATE TABLE IF NOT EXISTS vm_backups (
            id TEXT PRIMARY KEY, destination_id TEXT NOT NULL, host_id TEXT NOT NULL,
            host_name TEXT NOT NULL, vm_name TEXT NOT NULL, object_key TEXT NOT NULL,
            size_bytes INTEGER NOT NULL, sha256 TEXT NOT NULL, created_by TEXT NOT NULL,
            created_at TEXT NOT NULL, FOREIGN KEY(destination_id) REFERENCES backup_destinations(id)
        )""")


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
    permissions: frozenset[str]


ROLE_CONFIG = {
    "viewer": {role.strip() for role in os.getenv("KVM_VIEWER_GLOBAL_ROLES", "").split(",") if role.strip()},
    "vm_operator": {role.strip() for role in os.getenv("KVM_VM_OPERATOR_GLOBAL_ROLES", "").split(",") if role.strip()},
    "host_operator": {role.strip() for role in os.getenv("KVM_HOST_OPERATOR_GLOBAL_ROLES", "").split(",") if role.strip()},
    # Keep the original setting as the host-admin tier for existing installs.
    "host_admin": {role.strip() for role in os.getenv("KVM_ALLOWED_GLOBAL_ROLES", "admin").split(",") if role.strip()},
    "network_admin": {role.strip() for role in os.getenv("KVM_NETWORK_OPERATOR_GLOBAL_ROLES", "").split(",") if role.strip()},
    "storage_admin": {role.strip() for role in os.getenv("KVM_STORAGE_OPERATOR_GLOBAL_ROLES", "").split(",") if role.strip()},
    "software_admin": {role.strip() for role in os.getenv("KVM_SOFTWARE_OPERATOR_GLOBAL_ROLES", "").split(",") if role.strip()},
    "subscription_admin": {role.strip() for role in os.getenv("KVM_SUBSCRIPTION_OPERATOR_GLOBAL_ROLES", "").split(",") if role.strip()},
    "account_admin": {role.strip() for role in os.getenv("KVM_ACCOUNT_OPERATOR_GLOBAL_ROLES", "").split(",") if role.strip()},
    "service_admin": {role.strip() for role in os.getenv("KVM_SERVICE_OPERATOR_GLOBAL_ROLES", "").split(",") if role.strip()},
    "cluster_admin": {role.strip() for role in os.getenv("KVM_CLUSTER_OPERATOR_GLOBAL_ROLES", "").split(",") if role.strip()},
}


ROLE_RANK = {"viewer": 1, "scoped_operator": 1, "vm_operator": 2, "host_operator": 3, "host_admin": 4}
PERMISSION_RANK = {"viewer": 1, "vm_operator": 2, "host_resources": 3, "host_admin": 4,
                   "network_admin": 3, "storage_admin": 3, "software_admin": 3,
                   "subscription_admin": 3, "account_admin": 3, "service_admin": 3, "cluster_admin": 3}
SCOPED_PERMISSIONS = {"network_admin", "storage_admin", "software_admin", "subscription_admin", "account_admin", "service_admin", "cluster_admin"}
RESOURCE_PERMISSIONS = SCOPED_PERMISSIONS | {"host_resources"}


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
        if level in ROLE_RANK and roles.intersection(configured_roles) and ROLE_RANK[level] > ROLE_RANK.get(access_level, 0):
            access_level = level
    matched_scopes = {level for level in SCOPED_PERMISSIONS if roles.intersection(ROLE_CONFIG[level])}
    if access_level in ("", "viewer") and matched_scopes:
        access_level = "scoped_operator"
    if not access_level:
        raise HTTPException(403, "Your Rancher global role is not authorized to access KVM hosts")
    rank = ROLE_RANK[access_level]
    permissions = {"viewer"}
    if rank >= ROLE_RANK["vm_operator"]:
        permissions.add("vm_operator")
    if rank >= ROLE_RANK["host_operator"]:
        permissions.update(SCOPED_PERMISSIONS | {"host_resources"})
    else:
        permissions.update(matched_scopes)
    if rank >= ROLE_RANK["host_admin"]:
        permissions.add("host_admin")
    return AuthorizationContext(str(user_id or user.get("id") or "unknown"), frozenset(roles), access_level, frozenset(permissions))


def require_permission(permission: str):
    required_rank = PERMISSION_RANK[permission]

    def dependency(
        authorization: str | None = Header(default=None),
        cookie: str | None = Header(default=None),
    ) -> AuthorizationContext:
        context = authenticate_request(authorization, cookie)
        if permission in RESOURCE_PERMISSIONS and permission in context.permissions:
            return context
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


STONITH_STATUS_CHECK_COOLDOWN = timedelta(hours=3)


def stonith_status_check_view(row: sqlite3.Row | dict[str, Any]) -> dict[str, str]:
    checked_at = str(row["checked_at"])
    try:
        checked_time = datetime.fromisoformat(checked_at)
        next_allowed_at = (checked_time + STONITH_STATUS_CHECK_COOLDOWN).isoformat()
        status = str(row["status"])
        if status == "checking" and datetime.now(timezone.utc) - checked_time > timedelta(minutes=2):
            status = "unknown"
    except (TypeError, ValueError):
        next_allowed_at = checked_at
        status = "unknown"
    return {
        "status": status,
        "code": str(row["result_code"]),
        "checked_at": checked_at,
        "next_allowed_at": next_allowed_at,
    }


def reserve_stonith_status_check(host_id: str, resource_id: str) -> tuple[dict[str, str], bool]:
    """Persist a three-hour per-device cooldown before contacting a STONITH agent."""
    current_time = datetime.now(timezone.utc)
    checked_at = current_time.isoformat()
    with connect_db() as db:
        # Serialize concurrent API workers as well as requests handled by this worker.
        db.execute("BEGIN IMMEDIATE")
        row = db.execute(
            "SELECT checked_at,status,result_code FROM stonith_status_checks WHERE host_id=? AND resource_id=?",
            (host_id, resource_id),
        ).fetchone()
        if row is not None:
            try:
                previous_time = datetime.fromisoformat(row["checked_at"])
            except (TypeError, ValueError):
                previous_time = current_time - STONITH_STATUS_CHECK_COOLDOWN
            if current_time - previous_time < STONITH_STATUS_CHECK_COOLDOWN:
                return stonith_status_check_view(row), False
        db.execute(
            """INSERT INTO stonith_status_checks(host_id,resource_id,checked_at,status,result_code)
               VALUES(?,?,?,'checking','check_in_progress')
               ON CONFLICT(host_id,resource_id) DO UPDATE SET
                 checked_at=excluded.checked_at,status='checking',result_code='check_in_progress'""",
            (host_id, resource_id, checked_at),
        )
    return stonith_status_check_view({"checked_at": checked_at, "status": "checking", "result_code": "check_in_progress"}), True


def save_stonith_status_check(host_id: str, resource_id: str, status: str, result_code: str) -> dict[str, str]:
    checked_at = now()
    with connect_db() as db:
        db.execute(
            "UPDATE stonith_status_checks SET checked_at=?,status=?,result_code=? WHERE host_id=? AND resource_id=?",
            (checked_at, status, result_code, host_id, resource_id),
        )
    return stonith_status_check_view({"checked_at": checked_at, "status": status, "result_code": result_code})


def acquire_cluster_host_mutation_locks(host_ids: list[str]) -> list[tuple[str, dict[str, Any]]] | None:
    """Acquire every host lock atomically in stable order, or acquire none."""
    keys = sorted({str(host_id).strip() for host_id in host_ids if str(host_id).strip()})
    entries: list[tuple[str, dict[str, Any]]] = []
    with CLUSTER_MUTATION_LOCK_GUARD:
        for key in keys:
            entry = CLUSTER_MUTATION_LOCKS.setdefault(key, {"lock": threading.Lock(), "references": 0})
            entry["references"] += 1
            entries.append((key, entry))

    acquired: list[tuple[str, dict[str, Any]]] = []
    for key, entry in entries:
        if not entry["lock"].acquire(blocking=False):
            for _acquired_key, acquired_entry in reversed(acquired):
                acquired_entry["lock"].release()
            with CLUSTER_MUTATION_LOCK_GUARD:
                for referenced_key, referenced_entry in entries:
                    referenced_entry["references"] -= 1
                    if referenced_entry["references"] == 0 and CLUSTER_MUTATION_LOCKS.get(referenced_key) is referenced_entry:
                        del CLUSTER_MUTATION_LOCKS[referenced_key]
            return None
        acquired.append((key, entry))
    return acquired


def release_cluster_host_mutation_locks(entries: list[tuple[str, dict[str, Any]]]) -> None:
    for _key, entry in reversed(entries):
        entry["lock"].release()
    with CLUSTER_MUTATION_LOCK_GUARD:
        for key, entry in entries:
            entry["references"] -= 1
            if entry["references"] == 0 and CLUSTER_MUTATION_LOCKS.get(key) is entry:
                del CLUSTER_MUTATION_LOCKS[key]


@contextmanager
def cluster_host_mutation_guard(host_ids: list[str]):
    entries = acquire_cluster_host_mutation_locks(host_ids)
    if entries is None:
        raise HTTPException(409, "Another cluster operation is already running on one or more selected hosts. Wait for it to finish, then refresh cluster status and retry.")
    try:
        yield
    finally:
        release_cluster_host_mutation_locks(entries)


def cluster_member_host_ids(status: dict[str, Any], fallback_host_id: str) -> list[str]:
    """Map live Pacemaker node names to registered extension hosts for locking."""
    member_names = {
        str(node.get("name") or "").strip().casefold().rstrip(".")
        for node in status.get("nodes", [])
        if isinstance(node, dict) and str(node.get("name") or "").strip()
    }
    if not member_names:
        return [fallback_host_id]
    with connect_db() as db:
        rows = [dict(row) for row in db.execute("SELECT id,name,hostname,address FROM hosts")]
    matching: set[str] = set()
    for row in rows:
        aliases = {str(row.get(key) or "").strip().casefold().rstrip(".") for key in ("name", "hostname", "address")}
        aliases.discard("")
        if aliases & member_names:
            matching.add(row["id"])
    return sorted(matching | {fallback_host_id})


def operation_job_snapshot(job_id: str) -> dict[str, Any] | None:
    with connect_db() as db:
        row = db.execute("SELECT * FROM operation_jobs WHERE id=?", (job_id,)).fetchone()
    if not row:
        return None
    return {"job_id": row["id"], "kind": row["kind"], "status": row["status"],
            "results": json.loads(row["results_json"]), "created_at": row["created_at"],
            "updated_at": row["updated_at"]}


def update_operation_job(job_id: str, *, status: str | None = None, results: list[dict[str, Any]] | None = None) -> None:
    with OPERATION_JOB_LOCK, connect_db() as db:
        if results is None:
            db.execute("UPDATE operation_jobs SET status=?,updated_at=? WHERE id=?", (status, now(), job_id))
        else:
            db.execute("UPDATE operation_jobs SET status=COALESCE(?,status),results_json=?,updated_at=? WHERE id=?",
                       (status, json.dumps(results), now(), job_id))


def create_operation_job(kind: str, actor: str, hosts: list[dict[str, Any]], operation) -> dict[str, Any]:
    job_id = str(uuid.uuid4())
    results = [{"host_id": host["id"], "host_name": host.get("hostname") or host.get("name"),
                "status": "queued"} for host in hosts]
    # Bound the durable queue before submitting to ThreadPoolExecutor, whose
    # internal work queue is otherwise unbounded.
    with OPERATION_JOB_LOCK, connect_db() as db:
        db.execute("DELETE FROM operation_jobs WHERE created_at < ?",
                   ((datetime.now(timezone.utc) - timedelta(days=30)).isoformat(),))
        active = db.execute(
            "SELECT COUNT(*) FROM operation_jobs WHERE status IN ('queued','running')"
        ).fetchone()[0]
        if active >= MAX_ACTIVE_OPERATION_JOBS:
            raise HTTPException(429, "The KVM API has reached its limit for queued or running operations. Wait for an operation to finish, then retry.")
        db.execute("INSERT INTO operation_jobs (id,actor,kind,status,results_json,created_at,updated_at) VALUES (?,?,?,?,?,?,?)",
                   (job_id, actor, kind, "queued", json.dumps(results), now(), now()))

    def execute() -> None:
        update_operation_job(job_id, status="running")

        def run_host(index: int, host: dict[str, Any]) -> None:
            with OPERATION_JOB_LOCK:
                current = operation_job_snapshot(job_id)
                if not current:
                    return
                items = current["results"]
                items[index] = {**items[index], "status": "running"}
                update_operation_job(job_id, results=items)
            try:
                result = operation(host)
                outcome = result.get("status", "completed")
                item = {**results[index], **result, "status": outcome}
            except Exception as exc:
                item = {**results[index], "status": "error", "error": str(exc)[:600]}
            with OPERATION_JOB_LOCK:
                current = operation_job_snapshot(job_id)
                if not current:
                    return
                items = current["results"]
                items[index] = item
                update_operation_job(job_id, results=items)

        with ThreadPoolExecutor(max_workers=min(3, len(hosts)), thread_name_prefix="kvm-host-operation") as executor:
            list(executor.map(lambda entry: run_host(*entry), enumerate(hosts)))
        final = operation_job_snapshot(job_id)
        statuses = [item.get("status") for item in (final or {}).get("results", [])]
        job_status = "succeeded" if statuses and all(value not in ("error", "failed") for value in statuses) else "partial"
        if statuses and all(value in ("error", "failed") for value in statuses):
            job_status = "failed"
        update_operation_job(job_id, status=job_status)

    OPERATION_JOB_EXECUTOR.submit(execute)
    return operation_job_snapshot(job_id) or {"job_id": job_id, "kind": kind, "status": "queued", "results": results}


def public_host(row: sqlite3.Row) -> dict[str, Any]:
    return {key: row[key] for key in (
        "id", "name", "address", "port", "username", "hostname", "status",
        "cpu_count", "memory_total_bytes", "last_checked_at", "last_error",
    )}


def public_qnetd_witness(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    """Expose witness readiness and its SSH account, never credentials or host keys."""
    item = dict(row)
    result = {key: item.get(key) for key in (
        "id", "name", "address", "port", "username", "hostname", "status",
        "os_id", "os_version", "ha_product", "ha_active", "qnetd_package_installed",
        "time_synchronized", "registered_address_is_dynamic", "created_at", "updated_at", "last_checked_at",
    )}
    for key in ("ha_active", "qnetd_package_installed", "time_synchronized"):
        result[key] = bool(result[key])
    if result["registered_address_is_dynamic"] is not None:
        result["registered_address_is_dynamic"] = bool(result["registered_address_is_dynamic"])
    return result


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


VM_PACEMAKER_VM_GUARD_SCRIPT = r'''import shutil,subprocess,xml.etree.ElementTree as ET
def _pacemaker_virtualdomain_configs():
    try:
        state=subprocess.run(['systemctl','is-active','pacemaker'],capture_output=True,text=True,timeout=8)
    except FileNotFoundError:
        if shutil.which('cibadmin'): raise SystemExit('Pacemaker is installed but its active state cannot be verified; refusing direct libvirt changes.')
        return []
    pacemaker_state=(state.stdout or '').strip().lower()
    if pacemaker_state in ('inactive','failed','deactivating','not-found'):
        return []
    if state.returncode and pacemaker_state not in ('active','activating','reloading'):
        if shutil.which('cibadmin'): raise SystemExit('Pacemaker state is uncertain; refusing direct libvirt changes until cluster health is verified.')
        return []
    if pacemaker_state != 'active':
        raise SystemExit('Pacemaker is changing state; refusing direct libvirt changes until cluster health is verified.')
    cib=subprocess.run(['cibadmin','-Q'],capture_output=True,text=True,timeout=12)
    if cib.returncode:
        raise SystemExit('Pacemaker is active but its configuration cannot be read; refusing direct libvirt changes.')
    try:
        cib_root=ET.fromstring(cib.stdout)
    except ET.ParseError:
        raise SystemExit('Pacemaker returned invalid configuration; refusing direct libvirt changes.')
    virtualdomain_resources=[item for item in cib_root.findall('.//primitive') if (item.get('type') or '').casefold()=='virtualdomain' and (item.get('provider') or '').casefold()=='heartbeat']
    if not virtualdomain_resources:
        return []
    configs=[]
    for resource in virtualdomain_resources:
        resource_id=str(resource.get('id') or '<unknown>')
        config=next((item.get('value','').strip() for item in resource.findall('./instance_attributes/nvpair') if item.get('name')=='config'), '')
        if not config:
            raise SystemExit('Pacemaker VirtualDomain resource '+resource_id+' has no readable VM configuration path; refusing direct libvirt changes.')
        try:
            configured_domain=ET.parse(config).getroot()
        except (OSError,ET.ParseError):
            raise SystemExit('Pacemaker VirtualDomain configuration '+config+' cannot be verified on this host; refusing direct libvirt changes.')
        configured_uuid=(configured_domain.findtext('./uuid') or '').strip().strip('{}').casefold()
        configured_name=(configured_domain.findtext('./name') or '').strip()
        configs.append((resource_id,configured_uuid,configured_name))
    return configs
def ensure_vm_name_not_pacemaker_managed(domain_name):
    for resource_id,_configured_uuid,configured_name in _pacemaker_virtualdomain_configs():
        if configured_name==domain_name:
            raise SystemExit('This VM name is reserved by Pacemaker resource '+resource_id+'. Choose another name or manage that workload under Clusters > Resources.')
def ensure_vm_not_pacemaker_managed(domain_name):
    configs=_pacemaker_virtualdomain_configs()
    if not configs:
        return
    uuid_result=subprocess.run(['virsh','-c','qemu:///system','domuuid',domain_name],capture_output=True,text=True,timeout=10)
    if uuid_result.returncode:
        raise SystemExit(uuid_result.stderr.strip() or uuid_result.stdout.strip() or 'Could not verify the VM UUID against Pacemaker resources.')
    domain_uuid=uuid_result.stdout.strip().strip('{}').casefold()
    if not domain_uuid:
        raise SystemExit('Libvirt returned no VM UUID; refusing direct changes while VirtualDomain resources exist.')
    for resource_id,configured_uuid,configured_name in configs:
        if (configured_uuid and configured_uuid==domain_uuid) or configured_name==domain_name:
            raise SystemExit('This VM is managed by Pacemaker resource '+resource_id+'. Use Clusters > Resources to manage it; direct libvirt changes are blocked.')
'''



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


VM_GRAPHICS_CONSOLE_SCRIPT = r'''import ipaddress, json, re, subprocess, sys, xml.etree.ElementTree as ET
name = sys.argv[1]
base = ['virsh', '-c', 'qemu:///system']
def run(args, timeout=15):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise SystemExit(result.stderr.strip() or result.stdout.strip() or 'Could not query libvirt')
    return result.stdout
names = run(base + ['list', '--all', '--name']).splitlines()
if name not in [item.strip() for item in names]:
    print(json.dumps({'available':False, 'reason':'vm-not-found'})); raise SystemExit(0)
state = run(base + ['domstate', name]).strip().lower()
if state != 'running':
    print(json.dumps({'available':False, 'reason':'not-running'})); raise SystemExit(0)
domain = ET.fromstring(run(base + ['dumpxml', name]))
devices = domain.find('./devices')
graphics = next((item for item in (devices.findall('./graphics') if devices is not None else []) if item.get('type') == 'vnc'), None)
if graphics is None:
    print(json.dumps({'available':False, 'reason':'vnc-not-configured'})); raise SystemExit(0)
listen = graphics.get('listen') or ''
listen_node = graphics.find('./listen')
if listen_node is not None:
    # Do not treat socket/none/other libvirt listen modes as localhost. The
    # SSH tunnel must target the exact address libvirt configured.
    if listen_node.get('type') not in (None, '', 'address'):
        raise SystemExit('VNC uses an unsupported libvirt listen mode')
    configured_address = listen_node.get('address')
    if not configured_address:
        raise SystemExit('VNC listen address is not configured')
    listen = configured_address
if not listen or listen == 'localhost':
    listen = '127.0.0.1'
if listen in ('0.0.0.0', '::'):
    listen = '127.0.0.1'
try:
    if not ipaddress.ip_address(listen).is_loopback:
        raise SystemExit('VNC must listen on a loopback address before it can be proxied')
except ValueError:
    raise SystemExit('The VM has an unsupported VNC listen address')
try:
    port = int(graphics.get('port', '-1'))
except ValueError:
    port = -1
if port < 5900:
    display = run(base + ['vncdisplay', name]).strip()
    match = re.search(r':([0-9]+)$', display)
    if not match:
        raise SystemExit('Could not determine the VM VNC display port')
    port = 5900 + int(match.group(1))
if port < 5900 or port > 65535:
    raise SystemExit('The VM VNC port is outside the supported range')
print(json.dumps({'available':True, 'protocol':'vnc', 'listen':listen, 'port':port}))
'''


VM_GRAPHICS_CONFIG_SCRIPT = VM_PACEMAKER_VM_GUARD_SCRIPT + r'''import os, subprocess, sys, tempfile, xml.etree.ElementTree as ET
name = sys.argv[1]
base = ['virsh', '-c', 'qemu:///system']
def run(args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=20)
    if result.returncode:
        raise SystemExit(result.stderr.strip() or result.stdout.strip() or 'Could not update the libvirt VM definition')
    return result.stdout
names = run(base + ['list', '--all', '--name']).splitlines()
if name not in [item.strip() for item in names]: raise SystemExit('Virtual machine not found')
ensure_vm_not_pacemaker_managed(name)
state = run(base + ['domstate', name]).strip().lower()
if state not in ('shut off', 'shutoff'): raise SystemExit('Stop this virtual machine before adding its VNC graphics device')
domain = ET.fromstring(run(base + ['dumpxml', '--inactive', name]))
devices = domain.find('./devices')
if devices is None: raise SystemExit('The persistent VM definition has no devices section')
graphics = devices.findall('./graphics')
if any(item.get('type') == 'vnc' for item in graphics):
    print('VNC graphics is already configured'); raise SystemExit(0)
if graphics:
    raise SystemExit('This VM already has a different graphics protocol. Remove or migrate it explicitly before adding VNC.')
if devices.find('./video') is None:
    video = ET.SubElement(devices, 'video')
    ET.SubElement(video, 'model', {'type':'vga'})
vnc = ET.SubElement(devices, 'graphics', {'type':'vnc', 'port':'-1', 'autoport':'yes', 'listen':'127.0.0.1'})
ET.SubElement(vnc, 'listen', {'type':'address', 'address':'127.0.0.1'})
fd, path = tempfile.mkstemp(prefix='kvm-vnc-config-', suffix='.xml')
try:
    with os.fdopen(fd, 'w', encoding='utf-8') as output: output.write(ET.tostring(domain, encoding='unicode'))
    run(base + ['define', path])
finally:
    try: os.unlink(path)
    except FileNotFoundError: pass
print('Loopback-only VNC graphics added to the persistent VM definition')
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


def open_vm_graphics_channel(host: dict[str, Any], listen: str, port: int) -> tuple[paramiko.SSHClient, paramiko.Channel]:
    """Open a pinned SSH TCP-forward channel to a loopback-only libvirt VNC port."""
    try:
        address = ipaddress.ip_address(listen)
    except ValueError as exc:
        raise RuntimeError("The VM graphics console has an invalid listen address") from exc
    if not address.is_loopback or not 5900 <= port <= 65535:
        raise RuntimeError("The VM graphics console target is outside the allowed loopback VNC range")
    client = ssh_client_for_host(host)
    try:
        transport = client.get_transport()
        if transport is None or not transport.is_active():
            raise RuntimeError("The SSH connection closed before the graphics console opened")
        channel = transport.open_channel(
            "direct-tcpip", (listen, port), ("127.0.0.1", 0), timeout=10
        )
        channel.settimeout(1.0)
        return client, channel
    except Exception:
        client.close()
        raise


def validate_vm_graphics_target(target: Any) -> tuple[str, int]:
    """Accept only a libvirt-reported VNC endpoint on the KVM host loopback."""
    try:
        listen = str(target.get("listen", ""))
        port = int(target.get("port", 0))
        address = ipaddress.ip_address(listen)
        if target.get("protocol") != "vnc" or not address.is_loopback or not 5900 <= port <= 65535:
            raise ValueError("unsupported graphics target")
        return listen, port
    except (AttributeError, TypeError, ValueError) as exc:
        raise RuntimeError("The VM graphics target is not an allowed loopback VNC endpoint") from exc


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


@app.websocket("/kvm-api/hosts/{host_id}/vms/graphics-console")
async def vm_graphics_console_websocket(host_id: str, websocket: WebSocket) -> None:
    """Relay noVNC RFB traffic through the imported host's pinned SSH tunnel."""
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

    accepted = False
    closed = False
    client: paramiko.SSHClient | None = None
    channel: paramiko.Channel | None = None
    outcome = "failure"
    detail = "Graphics console closed before the VNC session opened"
    try:
        host = await asyncio.to_thread(cockpit_host_record, host_id)
        try:
            output = await asyncio.to_thread(run_sudo_python, host, VM_GRAPHICS_CONSOLE_SCRIPT, [vm_name], 20)
            target = json.loads(output or "{}")
        except Exception:
            await websocket.accept()
            accepted = True
            await websocket.close(code=4502)
            closed = True
            detail = "Could not verify the VM graphics display over SSH"
            return

        if not isinstance(target, dict) or not target.get("available"):
            await websocket.accept()
            accepted = True
            reason = target.get("reason") if isinstance(target, dict) else "invalid-response"
            close_code = 4404 if reason == "vm-not-found" else 4410 if reason == "not-running" else 4409
            await websocket.close(code=close_code)
            closed = True
            detail = "VM was not found" if reason == "vm-not-found" else "VM is stopped" if reason == "not-running" else "VM has no supported VNC graphics display"
            return

        try:
            listen, port = validate_vm_graphics_target(target)
        except RuntimeError:
            await websocket.accept()
            accepted = True
            await websocket.close(code=4409)
            closed = True
            detail = "VM graphics target failed the loopback-only VNC check"
            return

        await websocket.accept()
        accepted = True
        client, channel = await asyncio.to_thread(open_vm_graphics_channel, host, listen, port)
        outcome = "success"
        detail = "Authenticated VNC graphics session opened over SSH; input and screen contents are not stored"

        async def browser_to_vnc() -> None:
            while True:
                message = await websocket.receive()
                if message["type"] == "websocket.disconnect":
                    return
                data = message.get("bytes")
                if data is None:
                    raise RuntimeError("The VNC client sent a non-binary RFB frame")
                await asyncio.to_thread(channel.sendall, data)

        async def vnc_to_browser() -> None:
            while True:
                try:
                    data = await asyncio.to_thread(channel.recv, 65536)
                except socket.timeout:
                    continue
                if not data:
                    return
                await websocket.send_bytes(data)

        tasks = [asyncio.create_task(browser_to_vnc()), asyncio.create_task(vnc_to_browser())]
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        for task in done:
            error = task.exception()
            if error is not None:
                raise error
    except WebSocketDisconnect:
        pass
    except HTTPException as exc:
        detail = "KVM host is no longer registered" if exc.status_code == 404 else "Could not access the registered KVM host"
        if not accepted:
            try:
                await websocket.accept()
                accepted = True
            except Exception:
                pass
        if accepted:
            try:
                await websocket.close(code=4404 if exc.status_code == 404 else 4502)
                closed = True
            except Exception:
                pass
    except Exception as exc:
        detail = f"Graphics console tunnel failed ({type(exc).__name__})"
        if accepted:
            try:
                await websocket.close(code=4502)
                closed = True
            except Exception:
                pass
        else:
            try:
                await websocket.accept()
                accepted = True
                await websocket.close(code=4502)
                closed = True
            except Exception:
                pass
    finally:
        if channel is not None:
            channel.close()
        if client is not None:
            client.close()
        try:
            await asyncio.to_thread(record_audit, actor.user_id, "vm.graphics_console", f"{host_id}/{vm_name}", outcome, detail)
        except Exception:
            pass
        if accepted and not closed:
            try:
                await websocket.close(code=1000)
            except Exception:
                pass


@app.websocket("/kvm-api/hosts/{host_id}/terminal")
async def host_terminal_websocket(host_id: str, websocket: WebSocket) -> None:
    """Relay an authenticated interactive SSH shell to an imported KVM host."""
    if websocket.headers.get("origin") != RANCHER_PUBLIC_ORIGIN:
        await websocket.close(code=4403)
        return
    try:
        actor = await asyncio.to_thread(
            require_permission("host_admin"), websocket.headers.get("authorization"), websocket.headers.get("cookie")
        )
    except HTTPException as exc:
        await websocket.close(code=4403 if exc.status_code == 403 else 4401)
        return
    try:
        host = await asyncio.to_thread(cockpit_host_record, host_id)
    except HTTPException as exc:
        await websocket.close(code=4404 if exc.status_code == 404 else 1011)
        return

    await websocket.accept()
    client: paramiko.SSHClient | None = None
    channel: paramiko.Channel | None = None
    outcome = "failure"
    detail = "Interactive SSH session closed before the shell opened"
    try:
        client = await asyncio.to_thread(ssh_client_for_host, host)
        channel = await asyncio.to_thread(client.invoke_shell, term="xterm-256color", width=100, height=30)
        await websocket.send_text("KVM_CONTROL:" + json.dumps({"type": "status", "status": "connected"}))
        outcome = "success"
        detail = "Interactive SSH shell opened; terminal input is not stored"
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
                    cols, rows = control.get("cols"), control.get("rows")
                    if isinstance(cols, int) and isinstance(rows, int):
                        await asyncio.to_thread(channel.resize_pty, width=max(20, min(cols, 300)), height=max(5, min(rows, 120)))
                    continue
            await asyncio.to_thread(channel.sendall, data.encode("utf-8"))
    except Exception as exc:
        detail = str(exc)[:500] or "Could not open the host SSH terminal"
        try:
            await websocket.send_text("KVM_CONTROL:" + json.dumps({"type": "error", "message": "Could not establish the SSH terminal. Check host connectivity and SSH access."}))
        except Exception:
            pass
    finally:
        if channel is not None:
            channel.close()
        if client is not None:
            client.close()
        try:
            await asyncio.to_thread(record_audit, actor.user_id, "host.terminal", host_id, outcome, detail)
        except Exception:
            pass
        try:
            await websocket.close(code=1000)
        except Exception:
            pass


def cluster_qnetd_prepare_context(plan_id: str, witness_host_id: str, actor: AuthorizationContext) -> tuple[dict[str, Any], dict[str, Any]]:
    """Require a registered, external SLES host matching the saved QNetd endpoint."""
    try:
        plan_id = str(uuid.UUID(plan_id))
    except ValueError as exc:
        raise HTTPException(404, "Cluster plan not found") from exc
    with connect_db() as db:
        plan_row = db.execute("SELECT * FROM cluster_plans WHERE id=?", (plan_id,)).fetchone()
        if not plan_row or (plan_row["created_by"] != actor.user_id and "cluster_admin" not in actor.permissions):
            raise HTTPException(404, "Cluster plan not found")
        plan = dict(plan_row)
        host_ids = json.loads(plan["host_ids_json"])
        if not isinstance(host_ids, list) or len(host_ids) < 2 or len(host_ids) > 32 or any(not isinstance(item, str) or not item.strip() for item in host_ids) or len(set(host_ids)) != len(host_ids):
            raise HTTPException(422, "The saved SUSE HA plan must contain between 2 and 32 unique hosts")
        if witness_host_id in host_ids:
            raise HTTPException(422, "QNetd must run on a registered host outside the selected cluster nodes")
        if plan["cluster_type"] != "suse-ha":
            raise HTTPException(422, "QNetd preparation is available only for SUSE HA plans")
        config = json.loads(plan["config_json"] or "{}")
        if not isinstance(config, dict):
            raise HTTPException(409, "The saved cluster plan configuration is invalid; review and save it again")
        if config.get("quorum") != "qdevice" or not config.get("qnetd_outside_cluster"):
            raise HTTPException(422, "Save a QDevice plan and confirm that its QNetd host is outside the cluster first")
        qnetd_host = validate_qnetd_host(str(config.get("qnetd_host") or ""))
        all_ids = [*host_ids, witness_host_id]
        placeholders = ",".join("?" for _ in all_ids)
        rows = [dict(row) for row in db.execute(f"SELECT * FROM hosts WHERE id IN ({placeholders})", all_ids)]
    by_id = {row["id"]: row for row in rows}
    if len(by_id) != len(all_ids):
        raise HTTPException(404, "One or more cluster or QNetd hosts are no longer registered")
    cluster_hosts = [by_id[item] for item in host_ids]
    witness = by_id[witness_host_id]
    witness_names = {normalize_cluster_endpoint(value) for value in (witness.get("name"), witness.get("hostname"), witness.get("address")) if value}
    if normalize_cluster_endpoint(qnetd_host) not in witness_names:
        raise HTTPException(422, "Select the registered host whose address or name exactly matches the saved QNetd endpoint")
    if witness.get("status") != "ready" or any(row.get("status") != "ready" for row in cluster_hosts):
        raise HTTPException(409, "The registered QNetd host and every selected cluster host must be reachable and ready")
    users = {str(row.get("username") or "").strip() for row in cluster_hosts}
    if len(users) != 1 or not next(iter(users), ""):
        raise HTTPException(422, "Use the same non-empty Linux SSH user on the selected cluster nodes")
    return ({**plan, "id": plan_id, "host_ids": host_ids, "config": config}, witness)


def cluster_qnetd_witness_prepare_context(plan_id: str, witness_id: str, actor: AuthorizationContext) -> tuple[dict[str, Any], dict[str, Any]]:
    """Validate an SSH-only SUSE witness against a saved external QDevice plan."""
    try:
        plan_id = str(uuid.UUID(plan_id))
        witness_id = str(uuid.UUID(witness_id))
    except ValueError as exc:
        raise HTTPException(404, "Cluster plan or QNetd witness not found") from exc
    with connect_db() as db:
        row = db.execute("SELECT * FROM cluster_plans WHERE id=?", (plan_id,)).fetchone()
        if not row or (row["created_by"] != actor.user_id and "cluster_admin" not in actor.permissions):
            raise HTTPException(404, "Cluster plan not found")
        plan = dict(row)
        host_ids = json.loads(plan["host_ids_json"])
        if not isinstance(host_ids, list) or not 2 <= len(host_ids) <= 32 or any(not isinstance(item, str) or not item.strip() for item in host_ids) or len(set(host_ids)) != len(host_ids):
            raise HTTPException(422, "The saved SUSE HA plan must contain between 2 and 32 unique hosts")
        if plan["cluster_type"] != "suse-ha":
            raise HTTPException(422, "QNetd preparation is available only for SUSE HA plans")
        config = json.loads(plan["config_json"] or "{}")
        if not isinstance(config, dict) or config.get("quorum") != "qdevice" or not config.get("qnetd_outside_cluster"):
            raise HTTPException(422, "Save a QDevice plan and confirm that its QNetd host is outside the cluster first")
        endpoint = normalize_cluster_endpoint(validate_qnetd_host(str(config.get("qnetd_host") or "")))
        witness_row = db.execute("SELECT * FROM qnetd_witnesses WHERE id=?", (witness_id,)).fetchone()
        placeholders = ",".join("?" for _ in host_ids)
        node_rows = [dict(item) for item in db.execute(f"SELECT id,name,hostname,address,status,username FROM hosts WHERE id IN ({placeholders})", host_ids)]
    if not witness_row:
        raise HTTPException(404, "The registered QNetd witness was not found")
    witness = dict(witness_row)
    node_names = {normalize_cluster_endpoint(value) for item in node_rows for value in (item.get("name"), item.get("hostname"), item.get("address")) if value}
    aliases = {normalize_cluster_endpoint(value) for value in (witness.get("hostname"), witness.get("address")) if value}
    if endpoint not in aliases:
        raise HTTPException(422, "Select the registered QNetd witness whose name or address exactly matches the saved endpoint")
    if endpoint in node_names:
        raise HTTPException(422, "QNetd must run outside the selected cluster nodes")
    if len(node_rows) != len(host_ids) or any(item.get("status") != "ready" for item in node_rows):
        raise HTTPException(409, "Every selected cluster node must be reachable and ready before QNetd preparation")
    users = {str(item.get("username") or "").strip() for item in node_rows}
    if len(users) != 1 or not next(iter(users), ""):
        raise HTTPException(422, "Use the same non-empty Linux SSH user on the selected cluster nodes")
    if witness.get("status") != "ready":
        raise HTTPException(409, "Verify the standalone SLES QNetd witness connection before package preparation")
    return ({**plan, "id": plan_id, "host_ids": host_ids, "config": config}, witness)


def cluster_qdevice_prepare_nodes_context(plan_id: str, actor: AuthorizationContext) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Validate a saved QDevice plan before preparing node-side package prerequisites."""
    try:
        plan_id = str(uuid.UUID(plan_id))
    except ValueError as exc:
        raise HTTPException(404, "Cluster plan not found") from exc
    with connect_db() as db:
        plan_row = db.execute("SELECT * FROM cluster_plans WHERE id=?", (plan_id,)).fetchone()
        if not plan_row or (plan_row["created_by"] != actor.user_id and "cluster_admin" not in actor.permissions):
            raise HTTPException(404, "Cluster plan not found")
        plan = dict(plan_row)
        host_ids = json.loads(plan["host_ids_json"])
        if not isinstance(host_ids, list) or not 2 <= len(host_ids) <= 32 or any(not isinstance(item, str) or not item.strip() for item in host_ids) or len(set(host_ids)) != len(host_ids):
            raise HTTPException(422, "The saved SUSE HA plan must contain between 2 and 32 unique host IDs")
        if plan["cluster_type"] != "suse-ha":
            raise HTTPException(422, "QDevice packages can be prepared only for SUSE HA plans")
        config = json.loads(plan["config_json"] or "{}")
        if not isinstance(config, dict):
            raise HTTPException(409, "The saved cluster plan configuration is invalid; review and save it again")
        if config.get("quorum") != "qdevice" or not config.get("qnetd_outside_cluster"):
            raise HTTPException(422, "Save a QDevice plan and confirm its external witness placement first")
        qnetd_host = normalize_cluster_endpoint(validate_qnetd_host(str(config.get("qnetd_host") or "")))
        placeholders = ",".join("?" for _ in host_ids)
        rows = [dict(row) for row in db.execute(f"SELECT * FROM hosts WHERE id IN ({placeholders})", host_ids)]
    by_id = {row["id"]: row for row in rows}
    if len(by_id) != len(host_ids):
        raise HTTPException(404, "One or more cluster nodes are no longer registered")
    nodes = [by_id[item] for item in host_ids]
    node_names = {normalize_cluster_endpoint(value) for row in nodes for value in (row.get("name"), row.get("hostname"), row.get("address")) if value}
    if qnetd_host in node_names:
        raise HTTPException(422, "QNetd must be outside the selected cluster nodes")
    if any(row.get("status") != "ready" for row in nodes):
        raise HTTPException(409, "Every selected node must be reachable and ready before package preparation")
    users = {str(row.get("username") or "").strip() for row in nodes}
    if len(users) != 1 or not next(iter(users), ""):
        raise HTTPException(422, "All selected nodes must use the same non-empty Linux SSH user")
    return ({**plan, "id": plan_id, "host_ids": host_ids, "config": config}, nodes)


def cluster_bootstrap_context(plan_id: str, host_id: str, operation: str, actor: AuthorizationContext) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Load and validate a saved SUSE HA draft before opening a restricted PTY."""
    try:
        plan_id = str(uuid.UUID(plan_id))
    except ValueError as exc:
        raise HTTPException(404, "Cluster plan not found") from exc
    if operation not in ("init", "join", "qdevice"):
        raise HTTPException(422, "Choose a supported SUSE cluster bootstrap action")
    with connect_db() as db:
        plan_row = db.execute("SELECT * FROM cluster_plans WHERE id=?", (plan_id,)).fetchone()
        if not plan_row or (plan_row["created_by"] != actor.user_id and "cluster_admin" not in actor.permissions):
            raise HTTPException(404, "Cluster plan not found")
        plan = dict(plan_row)
        host_ids = json.loads(plan["host_ids_json"])
        if not isinstance(host_ids, list) or len(host_ids) < 2 or len(host_ids) > 32 or len(set(host_ids)) != len(host_ids):
            raise HTTPException(422, "The saved SUSE HA plan must contain between 2 and 32 unique hosts")
        placeholders = ",".join("?" for _ in host_ids)
        rows = db.execute(f"SELECT * FROM hosts WHERE id IN ({placeholders})", host_ids).fetchall()
    by_id = {row["id"]: dict(row) for row in rows}
    if len(by_id) != len(host_ids):
        raise HTTPException(409, "One or more hosts in this cluster plan are no longer registered")
    hosts = [by_id[item] for item in host_ids]
    if plan["cluster_type"] != "suse-ha":
        raise HTTPException(422, "SUSE crmsh bootstrap is available only for SUSE HA cluster plans")
    name = str(plan["name"] or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", name):
        raise HTTPException(422, "Save a valid cluster name before starting the SUSE bootstrap")
    config = json.loads(plan["config_json"] or "{}")
    quorum, fencing = config.get("quorum"), config.get("fencing")
    if quorum not in ("qdevice", "standard") or fencing not in ("sbd", "hardware"):
        raise HTTPException(422, "Complete the quorum and fencing review before starting the SUSE bootstrap")
    if operation == "qdevice" and quorum != "qdevice":
        raise HTTPException(422, "Choose and save the QDevice/QNetd topology before configuring the witness")
    if not config.get("corosync_network_reviewed"):
        raise HTTPException(422, "Review static Corosync addressing and communication channels before starting the SUSE bootstrap")
    corosync_networks = validate_corosync_networks(config.get("corosync_networks", []))
    if quorum == "qdevice":
        witness_host = validate_qnetd_host(str(config.get("qnetd_host") or ""))
        witness = normalize_cluster_endpoint(witness_host)
        node_values = {normalize_cluster_endpoint(value) for row in hosts for value in (row.get("name"), row.get("hostname"), row.get("address"))}
        if not witness or not config.get("qnetd_outside_cluster") or witness in node_values:
            raise HTTPException(422, "QNetd must be confirmed on a host outside the selected cluster nodes")
        config["qnetd_host"] = witness_host
    if any(row.get("status") != "ready" for row in hosts):
        raise HTTPException(409, "Every selected host must be reachable and ready before SUSE bootstrap")
    usernames = {str(row.get("username") or "").strip() for row in hosts}
    if len(usernames) != 1 or not next(iter(usernames), ""):
        raise HTTPException(422, "All selected nodes must use the same non-empty Linux SSH user")
    target_index = host_ids.index(host_id) if host_id in host_ids else -1
    if operation == "init" and target_index != 0:
        raise HTTPException(422, "Initialize SUSE HA on the first selected host")
    if operation == "join" and target_index < 1:
        raise HTTPException(422, "Join actions must target a selected host after the first node")
    if operation == "qdevice" and target_index != 0:
        raise HTTPException(422, "Configure the SUSE QDevice witness from the first selected cluster host")
    config["corosync_networks"] = corosync_networks
    return {**plan, "id": plan_id, "host_ids": host_ids, "name": name, "config": config}, hosts


def require_peer_host_file_entries(checks: dict[str, Any], host_label: str) -> None:
    """Block HA bootstrap when selected peer names are absent from /etc/hosts."""
    unmapped_peers = [item.get("host_name") or item.get("address") or "peer"
                      for item in checks.get("ssh_peer_connectivity", [])
                      if item.get("hosts_file_entry_present") is False]
    if unmapped_peers:
        raise RuntimeError(
            f"{host_label} cannot find selected peer names in /etc/hosts: {', '.join(unmapped_peers)}. "
            "Add stable SUSE cluster node name mappings on every node, then run preflight again."
        )


def require_consistent_ha_product_release(results: list[dict[str, Any]]) -> None:
    """Require one confirmed active SLE HA product for a fresh cluster init."""
    products = [str(item.get("checks", {}).get("ha_product") or "").strip() for item in results]
    if any(not product.lower().startswith("sle-ha/") for product in products):
        raise RuntimeError(
            "The active SLE HA product release could not be confirmed on every selected node. "
            "Confirm SUSEConnect reports the active SLE HA extension on all selected nodes, then rerun preflight."
        )
    if len(set(products)) != 1:
        raise RuntimeError(
            "Selected nodes have different active SLE HA product releases. "
            "Align the installed SLE HA release on every node before initializing the cluster."
        )


def cluster_bootstrap_preflight(plan: dict[str, Any], hosts: list[dict[str, Any]], operation: str, target_host_id: str) -> None:
    """Recheck live SUSE, time, cluster membership, and peer reachability before mutation."""
    def inspect(host: dict[str, Any]) -> dict[str, Any]:
        current = cockpit_host_record(host["id"])
        peers = [{"host_name": peer.get("hostname") or peer.get("name"), "address": peer.get("address"), "port": peer.get("port", 22)}
                 for peer in hosts if peer["id"] != host["id"]]
        qnetd_host = str(plan.get("config", {}).get("qnetd_host") or "") if plan.get("config", {}).get("quorum") == "qdevice" else ""
        try:
            request = {"peers": peers, "qnetd_host": qnetd_host}
            checks = json.loads(run_sudo_python(current, HA_PREFLIGHT_SCRIPT, args=[json.dumps(request)], timeout=90) or "{}")
        except Exception as exc:
            raise RuntimeError(f"Fresh preflight failed on {host.get('hostname') or host.get('name')}: {str(exc)[:240]}") from exc
        label = host.get("hostname") or host.get("name")
        if not checks.get("compatibility_supported"):
            raise RuntimeError(f"{label} is not on a supported SLES release for this SLE HA bootstrap")
        tools = checks.get("tools", {})
        if not checks.get("ha_active") or not tools.get("crm") or not tools.get("crm_mon") or not tools.get("corosync-cfgtool"):
            raise RuntimeError(f"{label} does not have the active SLE HA extension and required crmsh/Corosync tools")
        if not checks.get("time_synchronized"):
            raise RuntimeError(f"{label} is not time-synchronized; configure chrony/NTP before cluster bootstrap")
        unreachable = [item.get("host_name") or item.get("address") or "peer" for item in checks.get("ssh_peer_connectivity", []) if not item.get("reachable")]
        if unreachable:
            raise RuntimeError(f"{label} cannot reach the SSH port of: {', '.join(unreachable)}")
        require_peer_host_file_entries(checks, label)
        planned_networks = plan.get("config", {}).get("corosync_networks", [])
        active_subnets = {subnet for interface in checks.get("interfaces", [])
                          for subnet in interface.get("subnets", [])}
        missing_networks = [network for network in planned_networks if network not in active_subnets]
        if missing_networks:
            raise RuntimeError(
                f"{label} no longer reports planned Corosync subnet(s) {', '.join(missing_networks)}; "
                "refresh preflight and review the network plan before retrying"
            )
        # QNetd may not listen on TCP/5403 until crm cluster init configures
        # QDevice on the external witness. Do not block that first init on the
        # connectivity check; require it before joining any additional node.
        qnetd_check = checks.get("qnetd_tcp_connectivity")
        if operation == "join" and qnetd_host and (not qnetd_check or not qnetd_check.get("reachable")):
            raise RuntimeError(
                f"{label} cannot reach QNetd at {qnetd_host}:5403/TCP before joining; "
                "complete QDevice setup on the first node, then check routing and firewall rules"
            )
        return {"host": host, "checks": checks}

    with ThreadPoolExecutor(max_workers=min(3, len(hosts))) as executor:
        results = list(executor.map(inspect, hosts))
    if operation == "init":
        # SUSE permits mixed versions only temporarily during a rolling
        # upgrade. A new cluster must begin on one active SLE HA product.
        require_consistent_ha_product_release(results)
    checks_by_id = {item["host"]["id"]: item["checks"] for item in results}
    anchor = checks_by_id[plan["host_ids"][0]]
    target = checks_by_id[target_host_id]
    configured = [item["checks"] for item in results if item["checks"].get("cluster_configured")]
    if operation == "init":
        if configured:
            raise RuntimeError("A selected host already has Corosync configuration. Review or recover that cluster before initializing another one.")
    elif operation == "join":
        if not anchor.get("cluster_configured") or not anchor.get("cluster_detected") or anchor.get("cluster_name") != plan["name"]:
            raise RuntimeError("The first selected node is not reporting the saved cluster as active. Initialize or recover it before joining nodes.")
        if target.get("cluster_configured"):
            raise RuntimeError("The selected join host already has Corosync configuration. Review its current cluster membership before retrying.")
        if any(item.get("cluster_name") not in ("", plan["name"]) for item in configured):
            raise RuntimeError("The selected hosts report different cluster names. Review their existing membership before joining them.")
    elif operation == "qdevice":
        if plan.get("config", {}).get("quorum") != "qdevice":
            raise RuntimeError("Save a QDevice/QNetd topology before configuring its witness.")
        for result in results:
            checks = result["checks"]
            label = result["host"].get("hostname") or result["host"].get("name")
            if not checks.get("cluster_configured") or not checks.get("cluster_detected") or checks.get("cluster_name") != plan["name"]:
                raise RuntimeError(f"{label} is not reporting the saved SUSE HA cluster as active; join every planned node before configuring QDevice.")
            if not checks.get("cluster_members"):
                raise RuntimeError(f"{label} did not return live cluster membership. Refresh SUSE HA status before configuring QDevice.")
        memberships = [set(item["checks"].get("cluster_members", [])) for item in results]
        if any(members != memberships[0] for members in memberships[1:]):
            raise RuntimeError("The selected nodes report different live cluster membership. Refresh cluster status and resolve membership before configuring QDevice.")
        selected_names = {str(row.get("hostname") or row.get("name") or "").strip().lower() for row in hosts}
        if not selected_names.issubset(memberships[0]):
            raise RuntimeError("The saved plan includes a host that is not a member of the live cluster. Update the plan to match actual SUSE membership.")
        try:
            anchor_host = cockpit_host_record(plan["host_ids"][0])
            live = json.loads(run_sudo_python(anchor_host, HA_CLUSTER_STATUS_SCRIPT, timeout=35) or "{}")
        except Exception as exc:
            raise RuntimeError(f"Could not verify the live cluster before QDevice configuration: {str(exc)[:220]}") from exc
        if live.get("cluster_name") != plan["name"]:
            raise RuntimeError("The first selected node no longer reports the saved cluster name. Refresh the plan and cluster inventory.")
        live_nodes = {str(node.get("name") or "").strip().lower(): node for node in live.get("nodes", []) if isinstance(node, dict)}
        if not selected_names.issubset(live_nodes) or any(not live_nodes[name].get("online") for name in selected_names):
            raise RuntimeError("Every planned cluster node must be online before configuring QDevice. Restore node membership and refresh the status.")
        quorum = live.get("quorum")
        if not isinstance(quorum, dict) or not quorum.get("available") or not quorum.get("quorate"):
            raise RuntimeError("The existing cluster must have confirmed quorum before configuring QDevice. Restore quorum and review SUSE recovery guidance first.")
        qdevice = live.get("qdevice")
        if not isinstance(qdevice, dict) or not qdevice.get("available"):
            raise RuntimeError("SUSE quorum status could not confirm whether QDevice is already configured. Resolve the status check before retrying.")
        if qdevice.get("configured"):
            raise RuntimeError("QDevice is already configured. Review its live QNetd connection status; do not rerun the setup wizard to change it.")


def cluster_bootstrap_command(plan: dict[str, Any], hosts: list[dict[str, Any]], operation: str, target_host_id: str) -> str:
    """Construct only documented, fixed SUSE crmsh cluster commands."""
    by_id = {row["id"]: row for row in hosts}
    if target_host_id not in by_id:
        raise HTTPException(404, "Cluster bootstrap target is not in the saved plan")
    if operation == "init":
        if target_host_id != plan["host_ids"][0]:
            raise HTTPException(422, "Initialize SUSE HA on the first selected host")
        return f"crm cluster init --name {shlex.quote(plan['name'])}"
    if operation == "join":
        if target_host_id not in plan["host_ids"][1:]:
            raise HTTPException(422, "Join actions must target a selected host after the first node")
        anchor = by_id[plan["host_ids"][0]]
        cluster_node = "{}@{}".format(anchor["username"], anchor["address"])
        return "crm cluster join -c " + shlex.quote(cluster_node)
    if operation == "qdevice":
        if target_host_id != plan["host_ids"][0] or plan.get("config", {}).get("quorum") != "qdevice":
            raise HTTPException(422, "Configure QDevice from the first selected host after saving a QDevice/QNetd plan")
        return "crm cluster init qdevice"
    raise HTTPException(422, "Choose a supported SUSE cluster bootstrap action")


def cluster_bootstrap_error_code(error: Exception) -> str:
    """Return a safe, stable diagnostic category without exposing exception text."""
    if isinstance(error, paramiko.AuthenticationException):
        return "ssh_authentication"
    if isinstance(error, paramiko.BadHostKeyException):
        return "ssh_host_key"
    if isinstance(error, (socket.timeout, TimeoutError)):
        return "ssh_timeout"
    if isinstance(error, (paramiko.SSHException, OSError)):
        return "ssh_connectivity"

    # RuntimeError messages here are generated by the extension's own
    # preflight. Match only fixed phrases; never return the original message,
    # since lower-level SSH exceptions can contain sensitive connection data.
    message = str(error).casefold() if isinstance(error, RuntimeError) else ""
    if "sudo" in message:
        return "sudo_required"
    if "not on a supported sles release" in message:
        return "unsupported_sles"
    if "active sle ha product release could not be confirmed" in message:
        return "ha_product_unconfirmed"
    if "different active sle ha product releases" in message:
        return "ha_product_mismatch"
    if "active sle ha extension" in message or "crmsh/corosync tools" in message:
        return "ha_not_ready"
    if "time-synchronized" in message:
        return "time_sync"
    if "qnetd" in message:
        return "qnetd_connectivity"
    if "qdevice is already configured" in message:
        return "qdevice_already_configured"
    if "qdevice" in message:
        return "qdevice_preflight"
    if "cannot find selected peer names" in message or "/etc/hosts" in message:
        return "peer_name_resolution"
    if "cannot reach the ssh port" in message:
        return "peer_connectivity"
    if "already has corosync configuration" in message:
        return "existing_cluster_configuration"
    if "first selected node is not reporting" in message:
        return "initialize_first_node"
    if "different cluster names" in message:
        return "cluster_membership_mismatch"
    if "fresh preflight failed" in message:
        return "preflight_connectivity"
    return "bootstrap_failed"


def open_cluster_bootstrap_channel(host: dict[str, Any], crm_command: str) -> tuple[paramiko.SSHClient, paramiko.Channel, bytes]:
    """Run one fixed crmsh command under a PTY; never start an unrestricted shell."""
    client = ssh_client_for_host(host)
    channel: paramiko.Channel | None = None
    prefix_output = bytearray()
    try:
        passwordless_sudo = host.get("username") == "root"
        if not passwordless_sudo:
            _stdin, stdout, _stderr = client.exec_command("sudo -n -v", timeout=8)
            passwordless_sudo = stdout.channel.recv_exit_status() == 0
        if not passwordless_sudo and not host.get("password"):
            raise RuntimeError("The imported Linux account needs sudo access to start SUSE cluster bootstrap")
        channel = client.get_transport().open_session(timeout=10)
        channel.get_pty(term="xterm-256color", width=100, height=30)
        if host.get("username") == "root":
            command = crm_command
        elif passwordless_sudo:
            command = f"sudo -n {crm_command}"
        else:
            marker = b"\x1eKVM_SUDO_READY\x1e"
            command = f"stty -echo && printf '\\036KVM_SUDO_READY\\036' && sudo -S -p '' {crm_command}"
        channel.exec_command(command)
        if host.get("username") != "root" and not passwordless_sudo:
            deadline = time.monotonic() + 8
            marker_buffer = bytearray()
            channel.settimeout(0.25)
            while marker not in marker_buffer:
                if time.monotonic() >= deadline:
                    raise RuntimeError("Could not prepare the protected SUSE bootstrap command for sudo")
                try:
                    chunk = channel.recv(1)
                except socket.timeout:
                    continue
                if not chunk:
                    raise RuntimeError("The host closed the SUSE bootstrap process before sudo started")
                marker_buffer.extend(chunk)
            marker_start = marker_buffer.find(marker)
            prefix_output.extend(marker_buffer[:marker_start])
            channel.settimeout(None)
            channel.sendall((host["password"] + "\n").encode())
        return client, channel, bytes(prefix_output)
    except Exception:
        if channel is not None:
            channel.close()
        client.close()
        raise


@app.websocket("/kvm-api/clusters/plans/{plan_id}/bootstrap/{host_id}/{operation}")
async def cluster_bootstrap_websocket(plan_id: str, host_id: str, operation: str, websocket: WebSocket) -> None:
    """Run only the approved SUSE crmsh bootstrap command in a scoped PTY."""
    if websocket.headers.get("origin") != RANCHER_PUBLIC_ORIGIN:
        await websocket.close(code=4403)
        return
    try:
        actor = await asyncio.to_thread(
            require_permission("cluster_admin"), websocket.headers.get("authorization"), websocket.headers.get("cookie")
        )
        plan, hosts = await asyncio.to_thread(cluster_bootstrap_context, plan_id, host_id, operation, actor)
        command = cluster_bootstrap_command(plan, hosts, operation, host_id)
        target = next(host for host in hosts if host["id"] == host_id)
    except HTTPException as exc:
        await websocket.close(code=4403 if exc.status_code == 403 else 4401 if exc.status_code == 401 else 4404 if exc.status_code == 404 else 4400)
        return
    except Exception:
        await websocket.close(code=4400)
        return

    await websocket.accept()
    mutation_locks = await asyncio.to_thread(acquire_cluster_host_mutation_locks, plan["host_ids"])
    if mutation_locks is None:
        detail = "Another cluster operation is already running on one or more selected hosts. Wait for it to finish, then refresh preflight before retrying."
        try:
            await websocket.send_text("KVM_CONTROL:" + json.dumps({"type": "error", "code": "operation_conflict", "message": detail}))
            await asyncio.to_thread(record_audit, actor.user_id, f"cluster.bootstrap.{operation}", f"{plan_id}/{host_id}", "failure", "conflicting cluster operation is already running")
        finally:
            await websocket.close(code=4409)
        return
    client: paramiko.SSHClient | None = None
    channel: paramiko.Channel | None = None
    outcome = "failure"
    detail = "SUSE cluster bootstrap did not complete"
    try:
        await websocket.send_text("KVM_CONTROL:" + json.dumps({"type": "progress", "step": "preflight"}))
        await asyncio.to_thread(cluster_bootstrap_preflight, plan, hosts, operation, host_id)
        current_host = await asyncio.to_thread(cockpit_host_record, host_id)
        client, channel, prefix_output = await asyncio.to_thread(open_cluster_bootstrap_channel, current_host, command)
        if prefix_output:
            await websocket.send_bytes(prefix_output)
        await websocket.send_text("KVM_CONTROL:" + json.dumps({"type": "status", "status": "connected"}))
        detail = "Restricted SUSE crmsh bootstrap PTY opened; terminal input is not stored"
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
                detail = "Restricted SUSE crmsh bootstrap PTY disconnected; terminal input is not stored"
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
                    cols, rows = control.get("cols"), control.get("rows")
                    if isinstance(cols, int) and isinstance(rows, int):
                        await asyncio.to_thread(channel.resize_pty, width=max(20, min(cols, 300)), height=max(5, min(rows, 120)))
                    continue
            await asyncio.to_thread(channel.sendall, data.encode("utf-8"))
        if channel.exit_status_ready():
            exit_status = await asyncio.to_thread(channel.recv_exit_status)
            outcome = "success" if exit_status == 0 else "failure"
            detail = f"Restricted SUSE crmsh {operation} command exited with status {exit_status}"
            await websocket.send_text("KVM_CONTROL:" + json.dumps({"type": "exit", "exit_status": exit_status}))
    except Exception as exc:
        error_code = cluster_bootstrap_error_code(exc)
        detail = f"Restricted SUSE crmsh {operation} failed ({error_code})"
        try:
            await websocket.send_text("KVM_CONTROL:" + json.dumps({"type": "error", "code": error_code}))
        except Exception:
            pass
    finally:
        if channel is not None:
            channel.close()
        if client is not None:
            client.close()
        try:
            await asyncio.to_thread(record_audit, actor.user_id, f"cluster.bootstrap.{operation}", f"{plan_id}/{host_id}", outcome, detail)
        except Exception:
            pass
        await asyncio.to_thread(release_cluster_host_mutation_locks, mutation_locks)
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
        compatibility_supported = os_id.lower() == "sles" and os_version in SUPPORTED_SLES_HA_RELEASES and libvirt_version != "unavailable"
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


HA_READINESS_SCRIPT = r'''import hashlib,json,re,shutil,subprocess,xml.etree.ElementTree as ET
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
        text=re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]','',text)
        label=''
        for line in text.splitlines():
            item=line.strip()
            match=re.search(r'\bsuseconnect\s+(.*)$',item,re.I)
            if match:
                command=match.group(1)
                product_match=re.search(r'(?:^|\s)-p\s+(\S+)',command)
                if not product_match: continue
                product=product_match.group(1)
                if product.startswith('sle-ha/'):
                    extensions.append({'product':product,'active':bool(re.search(r'(?:^|\s)-d(?:\s|$)',command)) or bool(re.search(r'\(Activated\)',label,re.I)),'name':re.sub(r'\s*\(Activated\)\s*','',label,flags=re.I).strip()})
                label=''
            elif item.upper().startswith(('AVAILABLE EXTENSIONS','REMARKS','MORE INFORMATION')):
                label=''
            elif item and not re.match(r'^(Activate|Deactivate) with:',item,re.I) and not item.startswith('('):
                label=item
ha=next((item for item in extensions if item['active']),None)
available=next(iter(extensions),None)
services={}
for name in ('pacemaker','corosync','hawk','hawk-backend'):
    code,text=run(['systemctl','is-active',name],8)
    services[name]=text.splitlines()[0] if text else ('missing' if code==4 else 'unknown')
commands={name:shutil.which(name) is not None for name in ('crm','crm_mon','corosync-cfgtool','stonith_admin')}
qnetd_package_installed=run(['rpm','-q','corosync-qnetd'],10)[0]==0
cluster_status=''
cluster_detected=False
cluster_name=''
cluster_members=[]
try:
    for line in open('/etc/corosync/corosync.conf',encoding='utf-8'):
        if line.strip().startswith('cluster_name:'):
            cluster_name=line.split(':',1)[1].strip().strip('"')
            break
except OSError: pass
if commands['crm_mon'] and services['pacemaker']=='active':
    code,cluster_status=run(['crm_mon','-1','-r'],15)
    cluster_detected=code==0 and bool(re.search(r'Current DC:|\bOnline:|nodes configured',cluster_status,re.I))
    xml_code,xml_text=run(['crm_mon','--one-shot','--output-as=xml'],20)
    if xml_code==0:
        try:
            root=ET.fromstring(xml_text)
            cluster_members=sorted({node.get('name','').strip().lower() for node in root.findall('.//nodes/node') if node.get('name','').strip()})
        except Exception: pass
cluster_identity=hashlib.sha256((cluster_name.strip().lower()+'\0'+'\0'.join(cluster_members)).encode()).hexdigest()[:20] if cluster_detected and cluster_members else ''
print(json.dumps({'suseconnect_available':bool(shutil.which('SUSEConnect')),'ha_available':available is not None,
    'ha_active':ha is not None,'ha_product':(ha or available or {}).get('product',''),
    'ha_product_name':(ha or available or {}).get('name',''),'extension_error':extension_error,
    'commands':commands,'services':services,'qnetd_package_installed':qnetd_package_installed,'cluster_detected':cluster_detected,'cluster_name':cluster_name,'cluster_identity':cluster_identity,'cluster_members':cluster_members,
    'checked_at':datetime.now(timezone.utc).isoformat(),
    'cluster_summary':'\n'.join(cluster_status.splitlines()[:8]) if cluster_status else ''}))
'''


HA_PREFLIGHT_SCRIPT = r'''import concurrent.futures,glob,ipaddress,json,os,platform,re,shutil,socket,subprocess,sys,xml.etree.ElementTree as ET
request=json.loads(sys.argv[1]) if len(sys.argv)>1 else {}
if isinstance(request,list): request={'peers':request}
peer_endpoints=request.get('peers',[])
qnetd_host=request.get('qnetd_host','')
registered_address=request.get('registered_address','')
try: registered_address=str(ipaddress.ip_address(registered_address.strip()))
except (ValueError,AttributeError): registered_address=''
hosts_file_aliases={}
try:
    with open('/etc/hosts',encoding='utf-8') as hosts_file:
        for line in hosts_file:
            fields=line.split('#',1)[0].split()
            if len(fields)>1:
                address=fields[0]
                for alias in fields[1:]: hosts_file_aliases.setdefault(alias.rstrip('.').lower(),[]).append(address)
except OSError: pass
def check_peer(peer):
    endpoint={'host_name':peer.get('host_name',''),'address':peer.get('address',''),'port':int(peer.get('port',22)),'reachable':False}
    peer_name=endpoint['host_name'].strip().rstrip('.').lower()
    short_name=peer_name.split('.',1)[0]
    fqdn_entry=bool(peer_name and hosts_file_aliases.get(peer_name))
    short_name_entry=bool(short_name and hosts_file_aliases.get(short_name))
    endpoint['hosts_file_entry_present']=fqdn_entry and (short_name==peer_name or short_name_entry)
    endpoint['hosts_file_addresses']=sorted(set(hosts_file_aliases.get(peer_name,[])+hosts_file_aliases.get(short_name,[])))[:4]
    try:
        expected_address=ipaddress.ip_address(endpoint['address'].strip().strip('[]').split('%',1)[0]).compressed
        mapped_addresses={ipaddress.ip_address(value.strip().strip('[]').split('%',1)[0]).compressed for value in endpoint['hosts_file_addresses']}
        endpoint['hosts_file_address_matches_ssh_address']=expected_address in mapped_addresses if mapped_addresses else None
    except (ValueError,AttributeError):
        endpoint['hosts_file_address_matches_ssh_address']=None
    endpoint['fqdn_entry_present']=fqdn_entry
    endpoint['short_name_entry_present']=short_name_entry
    try:
        with socket.create_connection((endpoint['address'],endpoint['port']),timeout=1.5): endpoint['reachable']=True
    except Exception as error:
        endpoint['error']=type(error).__name__
    return endpoint
with concurrent.futures.ThreadPoolExecutor(max_workers=min(10,len(peer_endpoints) or 1)) as pool:
    ssh_peer_connectivity=list(pool.map(check_peer,peer_endpoints))
qnetd_tcp_connectivity=None
if qnetd_host:
    qnetd_tcp_connectivity={'host':qnetd_host,'port':5403,'reachable':False}
    try:
        with socket.create_connection((qnetd_host,5403),timeout=2.5): qnetd_tcp_connectivity['reachable']=True
    except Exception as error:
        qnetd_tcp_connectivity['error']=type(error).__name__
def run(args, timeout=8):
    try:
        result=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
        return result.returncode,(result.stdout or result.stderr).strip()
    except Exception as error:
        return 127,str(error)
release={}
try:
    with open('/etc/os-release',encoding='utf-8') as release_file:
        for line in release_file:
            if '=' in line:
                key,value=line.rstrip().split('=',1)
                release[key]=value.strip().strip('"')
except OSError:
    pass
ha_code,ha_output=run(['SUSEConnect','--list-extensions'],25) if shutil.which('SUSEConnect') else (127,'SUSEConnect is not installed')
ha_active=False
ha_product=''
if ha_code==0:
    ha_output=re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]','',ha_output)
    label=''
    for line in ha_output.splitlines():
        item=line.strip()
        match=re.search(r'\bSUSEConnect\s+(.*)$',item,re.I)
        if match:
            command=match.group(1)
            product=re.search(r'(?:^|\s)-p\s+(\S+)',command)
            if product and product.group(1).startswith('sle-ha/'):
                ha_active=bool(re.search(r'(?:^|\s)-d(?:\s|$)',command)) or bool(re.search(r'\(Activated\)',label,re.I))
                if ha_active:
                    ha_product=product.group(1)
                    break
            label=''
        elif item and not re.match(r'^(Activate|Deactivate) with:',item,re.I) and not item.startswith('('):
            label=item
tools={name:bool(shutil.which(name)) for name in ('crm','crm_mon','corosync-cfgtool','stonith_admin')}
qnetd_package_installed=None
if request.get('check_qnetd_package'):
    qnetd_package_installed=run(['rpm','-q','corosync-qnetd'],10)[0]==0
cluster_configured=os.path.isfile('/etc/corosync/corosync.conf')
cluster_name=''
try:
    for line in open('/etc/corosync/corosync.conf',encoding='utf-8'):
        if line.strip().startswith('cluster_name:'):
            cluster_name=line.split(':',1)[1].strip().strip('"'); break
except OSError: pass
cluster_detected=False
cluster_members=[]
if tools['crm_mon']:
    cluster_code,cluster_text=run(['crm_mon','--one-shot','--output-as=xml'],20)
    if cluster_code==0:
        try:
            cluster_root=ET.fromstring(cluster_text)
            cluster_members=sorted({node.get('name','').strip().lower() for node in cluster_root.findall('.//nodes/node') if node.get('name','').strip()})
            cluster_detected=bool(cluster_members)
        except ET.ParseError: pass
supported_releases=__SLES_HA_SUPPORTED_RELEASES__
compatibility_supported=release.get('ID','').lower()=='sles' and release.get('VERSION_ID','') in supported_releases
ntp_code,ntp=run(['timedatectl','show','-p','NTPSynchronized','--value'])
time_synced=ntp_code==0 and ntp.strip().lower()=='yes'
services={}
for name in ('chronyd','chrony'):
    code,state=run(['systemctl','is-active',name])
    if code in (0,3,4): services[name]=state.splitlines()[0] if state else 'unknown'
ip_code,ip_json=run(['ip','-j','address','show'])
interfaces=[]
registered_address_is_dynamic=None
if ip_code==0:
    try:
        for item in json.loads(ip_json):
            if item.get('ifname')=='lo' or 'UP' not in item.get('flags',[]): continue
            addresses=[]
            dynamic_addresses=[]
            dynamic_subnets=set()
            subnets=set()
            for address in item.get('addr_info',[]):
                local=address.get('local','')
                if not local or address.get('scope')=='host' or {'tentative','deprecated','dadfailed'}.intersection(address.get('flags',[])): continue
                try:
                    interface=ipaddress.ip_interface(str(local)+'/'+str(address.get('prefixlen','')))
                    if interface.ip.is_loopback or interface.ip.is_link_local or interface.ip.is_multicast or interface.ip.is_unspecified: continue
                except (ValueError,TypeError): continue
                addresses.append(str(interface.ip))
                if 'dynamic' in address.get('flags',[]) or address.get('dynamic') is True:
                    dynamic_addresses.append(str(interface.ip))
                    dynamic_subnets.add(str(interface.network))
                subnets.add(str(interface.network))
            interfaces.append({'name':item.get('ifname',''),'addresses':addresses,'dynamic_addresses':dynamic_addresses,'dynamic_subnets':sorted(dynamic_subnets),'subnets':sorted(subnets)})
        if registered_address:
            visible_addresses={address for interface in interfaces for address in interface['addresses']}
            dynamic_addresses={address for interface in interfaces for address in interface['dynamic_addresses']}
            if registered_address in visible_addresses:
                registered_address_is_dynamic=registered_address in dynamic_addresses
    except Exception: pass
watchdogs=sorted(path for path in glob.glob('/dev/watchdog*') if __import__('os').path.exists(path))
watchdog_details=[]
for path in watchdogs:
    device_name=__import__('os').path.basename(path)
    sys_device='/sys/class/watchdog/'+device_name
    driver_link=sys_device+'/device/driver'
    driver=__import__('os').path.basename(__import__('os').path.realpath(driver_link)) if __import__('os').path.islink(driver_link) else ''
    try:
        with open(sys_device+'/identity','r',encoding='utf-8',errors='replace') as identity_file: identity=identity_file.read().strip()[:160]
    except OSError: identity=''
    watchdog_details.append({'path':path,'driver':driver,'identity':identity})
watchdog_query={'available':False,'ok':False,'summary':'','device_path':''}
if shutil.which('sbd'):
    watchdog_code,watchdog_summary=run(['sbd','query-watchdog'],10)
    reported_devices=[path for path in watchdogs if re.search(r'(?<![A-Za-z0-9_])'+re.escape(path)+r'(?![A-Za-z0-9_])',watchdog_summary)]
    selected_device=reported_devices[0] if len(reported_devices)==1 else ''
    watchdog_query={'available':True,'ok':watchdog_code==0,'summary':watchdog_summary[:1000],'device_path':selected_device}
resource_agents=[]
for vendor in ('heartbeat','suse','linbit'):
    for root in ('/usr/lib/ocf/resource.d','/usr/lib64/ocf/resource.d'):
        for path in glob.glob(root+'/'+vendor+'/*'):
            if __import__('os').path.isfile(path) and __import__('os').access(path,__import__('os').X_OK):
                resource_agents.append(vendor+':'+path.rsplit('/',1)[-1])
resource_agents=sorted(set(resource_agents))
pool_code,pool_output=run(['virsh','-c','qemu:///system','pool-list','--all','--name']) if shutil.which('virsh') else (127,'virsh is not installed')
libvirt_pools=[line.strip() for line in pool_output.splitlines() if line.strip()] if pool_code==0 else []
libvirt_pool_details=[]
for pool_name in libvirt_pools[:8]:
    code,pool_xml=run(['virsh','-c','qemu:///system','pool-dumpxml',pool_name],2)
    if code!=0: continue
    try:
        root=ET.fromstring(pool_xml)
        source=root.find('source')
        target=root.find('target')
        libvirt_pool_details.append({'name':pool_name,'type':root.get('type','unknown'),
            'target_path':target.findtext('path','') if target is not None else '',
            'source_path':source.findtext('dir','') if source is not None else '',
            'source_devices':[item.get('path','') for item in source.findall('device') if item.get('path')] if source is not None else [],
            'source_hosts':[item.get('name','') for item in source.findall('host') if item.get('name')] if source is not None else []})
    except Exception: pass
workload_services={}
workload_service_units={}
for name in ('apache2','nfsserver','nfs-server'):
    load_code,load_state=run(['systemctl','show','-p','LoadState','--value',name+'.service'])
    active_code,active_state=run(['systemctl','is-active',name+'.service'])
    installed=load_code==0 and load_state.strip()=='loaded'
    active=(active_state.strip() if active_code in (0,3,4) and active_state.strip() else 'unknown')
    workload_service_units[name]={'unit':name+'.service','installed':installed,'active':active}
    # Keep the legacy field's old meaning for extensions that have not yet
    # learned to distinguish package availability from Pacemaker-owned runtime.
    workload_services[name]=installed and active=='active'
workload_services['nfsserver']=workload_services.get('nfsserver',False) or workload_services.get('nfs-server',False)
if workload_service_units.get('nfs-server',{}).get('installed'):
    workload_service_units['nfsserver']={'unit':'nfs-server.service',**workload_service_units['nfs-server']}
print(json.dumps({'hostname':platform.node(),'os_id':release.get('ID',''),'os_name':release.get('PRETTY_NAME',''),'os_version':release.get('VERSION_ID',''),'architecture':platform.machine(),
 'compatibility_supported':compatibility_supported,'ha_active':ha_active,'ha_product':ha_product,'ha_check_error':ha_output[:300] if ha_code else '', 'registered_address_is_dynamic':registered_address_is_dynamic,'tools':tools,'time_synchronized':time_synced,'time_sync_state':ntp.strip() if ntp_code==0 else 'unknown',
 'time_services':services,'workload_services':workload_services,'workload_service_units':workload_service_units,'interfaces':interfaces,'watchdog_devices':watchdogs,'watchdog_details':watchdog_details,'watchdog_query':watchdog_query,'qdevice_package_installed':(run(['rpm','-q','corosync-qdevice'],10)[0]==0 if qnetd_host else None),'qnetd_package_installed':qnetd_package_installed,'resource_agents':resource_agents,'libvirt_pools':libvirt_pools,'libvirt_pool_details':libvirt_pool_details,'fencing':'requires_configuration','ssh_peer_connectivity':ssh_peer_connectivity,'qnetd_tcp_connectivity':qnetd_tcp_connectivity,'inter_node_connectivity':'ssh_tcp_only','cluster_configured':cluster_configured,'cluster_detected':cluster_detected,'cluster_name':cluster_name,'cluster_members':cluster_members}))
'''


HA_CLUSTER_STATUS_SCRIPT = r'''import json,re,shutil,subprocess,xml.etree.ElementTree as ET
if not shutil.which('crm_mon') or not shutil.which('crm'):
    raise SystemExit('SLE HA cluster tools are not installed. Install the SUSE ha_sles pattern first.')
command=['crm_mon','--one-shot','--show-node-attributes','--output-as=xml']
try:
    result=subprocess.run(command,capture_output=True,text=True,timeout=25)
except Exception as error:
    raise SystemExit('Could not query Pacemaker status: '+str(error))
if result.returncode:
    raise SystemExit((result.stderr or result.stdout or 'crm_mon could not read cluster status').strip()[:500])
try: root=ET.fromstring(result.stdout)
except Exception as error: raise SystemExit('crm_mon returned invalid status data: '+str(error))
truth=lambda value: str(value).lower() in ('true','1','yes')
summary=root.find('summary')
nodes=[]
for item in root.findall('.//nodes/node'):
    nodes.append({'name':item.get('name',''),'id':item.get('id',''),'online':truth(item.get('online')),'standby':truth(item.get('standby')),'maintenance':truth(item.get('maintenance')),'unclean':truth(item.get('unclean')),'pending':item.get('pending','')})
resources=[]
for item in root.findall('.//resources//resource'):
    running=[]
    for node in item.findall('.//node'):
        name=node.get('name') or node.get('uname')
        if name and node.get('running')!='false': running.append(name)
    resources.append({'id':item.get('id',''),'agent':item.get('resource_agent') or item.get('type',''),'role':item.get('role','Stopped'),'active':truth(item.get('active')),'failed':truth(item.get('failed')),'managed':item.get('managed','true').lower() not in ('false','0','no'),'nodes':running})
# Group membership comes from the live CIB, while activity stays sourced from
# crm_mon. This keeps the UI's group editor tied to SUSE's authoritative config.
try:
    cib_result=subprocess.run(['cibadmin','-Q','-o','resources'],capture_output=True,text=True,timeout=15)
    if cib_result.returncode==0:
        cib=ET.fromstring(cib_result.stdout)
        by_resource={item.get('id'):item for item in resources if item.get('id')}
        for primitive in cib.iter('primitive'):
            primitive_id=primitive.get('id','')
            if primitive_id not in by_resource:
                continue
            if primitive.get('class')=='stonith':
                by_resource[primitive_id]['class']='stonith'
                attributes=[nv for section in primitive.findall('instance_attributes') for nv in section.iter('nvpair')]
                targets=set()
                parameter_names=set()
                for nv in attributes:
                    name=nv.get('name','')
                    value=nv.get('value','')
                    if name=='pcmk_host_list':
                        targets.update(node.strip() for node in value.replace(',', ' ').split() if node.strip())
                    elif name=='pcmk_host_map':
                        targets.update(entry.split(':',1)[0] for entry in re.split(r'[\s,]+',value.strip()) if ':' in entry)
                    elif name and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,63}',name):
                        parameter_names.add(name)
                by_resource[primitive_id]['fencing_targets']=sorted(targets)
                # Expose parameter names only so the UI can offer a safe edit form.
                # Values can contain IPMI credentials and must never enter status JSON.
                by_resource[primitive_id]['fencing_parameter_names']=sorted(parameter_names)
            operations=primitive.find('operations')
            by_resource[primitive_id]['monitor_operations']=[
                {'operation_id':op.get('id',''),'interval':op.get('interval',''),
                 'role':op.get('role',''),'timeout':op.get('timeout','')}
                for op in (list(operations) if operations is not None else [])
                if op.tag=='op' and op.get('name')=='monitor'
            ]
        for parent in cib.iter():
            if parent.tag not in ('group','clone','master','bundle'):
                continue
            for member_item in list(parent):
                if member_item.tag not in ('primitive','group','clone','master','bundle'):
                    continue
                member_id=member_item.get('id','')
                if member_id in by_resource:
                    by_resource[member_id]['parent_id']=parent.get('id','')
                    if parent.tag=='group': by_resource[member_id]['group_id']=parent.get('id','')
        for group in cib.iter('group'):
            group_id=group.get('id','')
            members=[item.get('id','') for item in list(group) if item.tag=='primitive' and item.get('id')]
            if not group_id or not members: continue
            child_items=[by_resource[member] for member in members if member in by_resource]
            parent_id=next((parent.get('id','') for parent in cib.iter() if parent.tag in ('group','clone','master','bundle') and any(item is group for item in list(parent))), '')
            group_status={'id':group_id,'agent':'group','role':'Started' if any(item['active'] for item in child_items) else 'Stopped',
                'active':any(item['active'] for item in child_items),'failed':any(item['failed'] for item in child_items),
                'managed':not bool(parent_id),'parent_id':parent_id,'nodes':sorted({node for item in child_items for node in item['nodes']}),'children':members}
            if group_id in by_resource:
                by_resource[group_id].update(group_status)
            else:
                resources.append(group_status)
                by_resource[group_id]=group_status
        for clone in cib.iter('clone'):
            clone_id=clone.get('id','')
            members=[item.get('id','') for item in list(clone) if item.tag in ('primitive','group') and item.get('id')]
            if not clone_id or not members: continue
            child_items=[by_resource[member] for member in members if member in by_resource]
            parent_id=next((parent.get('id','') for parent in cib.iter() if parent.tag in ('group','clone','master','bundle') and any(item is clone for item in list(parent))), '')
            meta=clone.find('meta_attributes')
            promotable=bool(meta is not None and any(item.get('name')=='promotable' and item.get('value','').lower()=='true' for item in meta.iter('nvpair')))
            active=any(item['active'] for item in child_items)
            promoted=any((item.get('role') or '').lower() in ('promoted','master') for item in child_items)
            role=('Promoted' if promoted else 'Unpromoted') if promotable and active else 'Started' if active else 'Stopped'
            clone_meta_keys={'clone-max','clone-node-max','globally-unique','notify','interleave'}
            if promotable: clone_meta_keys.update(('promoted-max','promoted-node-max'))
            clone_metadata={}; duplicate_clone_meta=False
            if meta is not None:
                for nv in meta.iter('nvpair'):
                    key=nv.get('name','')
                    if key not in clone_meta_keys: continue
                    if key in clone_metadata: duplicate_clone_meta=True
                    clone_metadata[key]=nv.get('value','')
            clone_status={'id':clone_id,'agent':'promotable clone' if promotable else 'clone','clone_type':'promotable' if promotable else 'standard','role':role,
                'active':active,'failed':any(item['failed'] for item in child_items),'managed':not bool(parent_id),'parent_id':parent_id,
                'nodes':sorted({node for item in child_items for node in item['nodes']}),'children':members,
                'clone_metadata':clone_metadata,'clone_metadata_editable':len(members)==1 and not duplicate_clone_meta and not parent_id and not active and not any(item['failed'] for item in child_items)}
            if clone_id in by_resource:
                by_resource[clone_id].update(clone_status)
            else:
                resources.append(clone_status)
                by_resource[clone_id]=clone_status
except Exception: pass
cluster_name=''
try:
    for line in open('/etc/corosync/corosync.conf',encoding='utf-8'):
        if line.strip().startswith('cluster_name:'): cluster_name=line.split(':',1)[1].strip().strip('"')
except OSError: pass
quorum={}
qdevice={'available':False,'configured':False,'connected':None,'qnetd_host':'','tls_active':None,'summary':''}
if shutil.which('corosync-quorumtool'):
    q=subprocess.run(['corosync-quorumtool','-s'],capture_output=True,text=True,timeout=10)
    quorum_text=(q.stdout or q.stderr).strip()
    quorum={'available':q.returncode==0,'quorate':bool(__import__('re').search(r'Quorate:\s+Yes',quorum_text,__import__('re').I)),'summary':quorum_text[:2000]}
    qdevice_configured=bool(re.search(r'^\s*Flags:.*\bQdevice\b',quorum_text,re.I|re.M)) and not bool(re.search(r'^\s*Flags:.*\bNR\b',quorum_text,re.I|re.M))
    qdevice={'available':q.returncode==0,'configured':qdevice_configured,'connected':None,'qnetd_host':'','tls_active':None,'summary':''}
    # SUSE documents this crmsh status command as the read-only source for
    # QDevice/QNetd connection state. Only run it when quorum reports QDevice.
    if qdevice_configured and shutil.which('crm'):
        try:
            qd=subprocess.run(['crm','corosync','status','qdevice'],capture_output=True,text=True,timeout=10)
            qdevice_text=(qd.stdout or qd.stderr).strip()
            state_match=re.search(r'^\s*State:\s*(Connected|Disconnected)\s*$',qdevice_text,re.I|re.M)
            qnetd_match=re.search(r'^\s*QNetd host:\s*(.*?)\s*$',qdevice_text,re.I|re.M)
            tls_match=re.search(r'^\s*TLS active:\s*(Yes|No)\s*$',qdevice_text,re.I|re.M)
            qdevice.update({'available':qd.returncode==0,'connected':(state_match.group(1).lower()=='connected' if state_match else None),
                            'qnetd_host':qnetd_match.group(1)[:253] if qnetd_match else '',
                            'tls_active':(tls_match.group(1).lower()=='yes' if tls_match else None),
                            'summary':qdevice_text[:2000]})
        except Exception as error:
            qdevice['summary']='QDevice status could not be queried: '+str(error)[:400]
stonith_available=False
stonith_configured=False
stonith_summary=''
stonith_target_coverage={'available':False,'nodes':[],'summary':'STONITH target coverage could not be queried'}
if shutil.which('stonith_admin'):
    try:
        f=subprocess.run(['stonith_admin','-L'],capture_output=True,text=True,timeout=10)
        stonith_summary=(f.stdout or f.stderr).strip()
        stonith_available=f.returncode==0
        stonith_configured=stonith_available and bool(stonith_summary) and not bool(re.search(r'no\s+(?:stonith\s+)?devices?\s+configured',stonith_summary,re.I))
        target_results=[]
        target_checks_available=True
        for node in nodes:
            name=node.get('name','')
            if not re.fullmatch(r'[A-Za-z0-9_.-]{1,253}',name):
                target_results.append({'node':name[:253],'status':'unknown','devices':[]})
                target_checks_available=False
                continue
            try:
                target=subprocess.run(['stonith_admin','-l',name],capture_output=True,text=True,timeout=10)
                target_text=(target.stdout or target.stderr).strip()
                if target.returncode!=0:
                    target_results.append({'node':name,'status':'unknown','devices':[]})
                    target_checks_available=False
                    continue
                no_devices=bool(re.search(r'no\s+(?:stonith\s+)?devices?(?:\s+can\s+terminate|\s+configured|\s+found)',target_text,re.I))
                devices=[]
                for line in ([] if no_devices else target_text.splitlines()):
                    line=line.strip()
                    if not line or line.lower().startswith('info:') or re.search(r'\b\d+\s+fence\s+devices?\s+found\b',line,re.I): continue
                    match=re.match(r'^([A-Za-z0-9_.:-]{1,128})(?:\s|$)',line)
                    if match and match.group(1) not in devices: devices.append(match.group(1))
                if devices:
                    target_results.append({'node':name,'status':'covered','devices':devices[:32]})
                elif no_devices or not target_text:
                    target_results.append({'node':name,'status':'uncovered','devices':[]})
                else:
                    target_results.append({'node':name,'status':'unknown','devices':[]})
                    target_checks_available=False
            except Exception:
                target_results.append({'node':name,'status':'unknown','devices':[]})
                target_checks_available=False
        stonith_target_coverage={'available':target_checks_available,'nodes':target_results,
                                 'summary':'Registered STONITH device coverage by cluster node; this does not test the physical fencing device'}
    except Exception:
        stonith_summary='STONITH device status could not be queried'
sbd={'available':False,'configured':False,'type':'','summary':''}
if shutil.which('crm'):
    try:
        sbd_result=subprocess.run(['crm','sbd','status'],capture_output=True,text=True,timeout=15)
        sbd_text=(sbd_result.stdout or sbd_result.stderr).strip()
        sbd_type_match=re.search(r'\b(diskless|disk[- ]based)\s+SBD\s+configured\b',sbd_text,re.I)
        sbd_not_configured=bool(re.search(r'\bSBD\s+(?:is\s+)?not\s+configured\b|\bno\s+SBD\s+configuration\b',sbd_text,re.I))
        sbd_query_succeeded=sbd_result.returncode==0 or sbd_not_configured
        sbd={'available':sbd_query_succeeded,'configured':sbd_result.returncode==0 and bool(sbd_type_match),
             'type':(sbd_type_match.group(1).lower().replace(' ','-') if sbd_type_match else ''),
             'summary':sbd_text[:2000]}
    except Exception as error:
        sbd={'available':False,'configured':False,'type':'','summary':'SBD status could not be queried: '+str(error)[:500]}
fencing_mechanisms=[]
if sbd['configured']: fencing_mechanisms.append('SBD ('+sbd['type']+')')
if stonith_configured: fencing_mechanisms.append('Pacemaker STONITH device(s)')
fencing_summary='\n'.join(item for item in (
    ('SBD: '+sbd['summary']) if sbd['summary'] else '',
    ('STONITH: '+stonith_summary) if stonith_summary else '',
) if item)
fencing_configured=sbd['configured'] or stonith_configured
fencing={'available':(sbd['available'] and stonith_available) or fencing_configured,
         'configured':fencing_configured,
         'mechanism':'; '.join(fencing_mechanisms),
         'stonith_configured':stonith_configured,'stonith_target_coverage':stonith_target_coverage,
         'sbd':sbd,'summary':fencing_summary}
print(json.dumps({'cluster_name':cluster_name,'nodes':nodes,'resources':resources,'node_count':len(nodes),'online_count':sum(1 for n in nodes if n['online']),'resource_count':len(resources),'quorum':quorum,'qdevice':qdevice,'fencing':fencing,'checked_at':__import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat(),'summary':(summary.findtext('current_dc') if summary is not None else '')}))
'''


HA_STONITH_DEVICE_STATUS_SCRIPT = r'''import datetime,json,re,shutil,subprocess,sys,xml.etree.ElementTree as ET
device=sys.argv[1].strip() if len(sys.argv)>1 else ''
def emit(status,code):
    print(json.dumps({'status':status,'code':code,'checked_at':datetime.datetime.now(datetime.timezone.utc).isoformat()}))
if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',device):
    emit('unknown','invalid_device_id')
    raise SystemExit(0)
if not all(shutil.which(command) for command in ('crm_mon','cibadmin','stonith_admin')):
    emit('unknown','ha_tool_unavailable')
    raise SystemExit(0)
try:
    live=subprocess.run(['crm_mon','--one-shot','--output-as=xml'],capture_output=True,text=True,timeout=20)
    if live.returncode:
        emit('unknown','cluster_status_unavailable')
        raise SystemExit(0)
    live_root=ET.fromstring(live.stdout)
    if not live_root.findall('.//nodes/node'):
        emit('unknown','cluster_not_active')
        raise SystemExit(0)
    cib=subprocess.run(['cibadmin','-Q','-o','resources'],capture_output=True,text=True,timeout=15)
    if cib.returncode:
        emit('unknown','cluster_configuration_unavailable')
        raise SystemExit(0)
    cib_root=ET.fromstring(cib.stdout)
    if not any(item.tag=='primitive' and item.get('class')=='stonith' and item.get('id')==device for item in cib_root.iter()):
        emit('unknown','device_not_configured')
        raise SystemExit(0)
except subprocess.TimeoutExpired:
    emit('unknown','cluster_status_timeout')
    raise SystemExit(0)
except Exception:
    emit('unknown','cluster_status_invalid')
    raise SystemExit(0)
try:
    result=subprocess.run(['stonith_admin','--query',device,'--timeout=45'],capture_output=True,text=True,timeout=55)
    # Deliberately omit device output: fence agents may include endpoint or
    # account details. A successful query is not proof a real fence operation works.
    emit('query_succeeded' if result.returncode==0 else 'query_failed',
         'status_query_succeeded' if result.returncode==0 else 'status_query_failed')
except subprocess.TimeoutExpired:
    emit('unknown','status_query_timeout')
except Exception:
    emit('unknown','status_query_unavailable')
'''


HA_CLUSTER_DIAGNOSTICS_SCRIPT = r'''import json,os,re,shlex,shutil,subprocess,xml.etree.ElementTree as ET
def run(args, timeout=12):
 try:
  result=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
  return result.returncode,(result.stdout or result.stderr).strip()
 except Exception as error: return 127,str(error)
constraints={}
for key,selector in (('location','location'),('ordering','order'),('colocation','colocation')):
 code,text=run(['crm','configure','show','type:'+selector]) if shutil.which('crm') else (127,'crmsh is not installed')
 # Only return the requested constraint classes; never expose resource parameter values.
 lines=[]
 for line in text.splitlines():
  line=line.strip()
  if not line or line.startswith(('#','property','rsc_defaults','op_defaults','primitive','group','clone','ms','bundle','template','node')): continue
  if re.match(r'^(location|order|colocation)\s+',line): lines.append(line[:500])
 constraints[key]={'available':code==0,'items':lines[:100],'error':text[:240] if code else ''}
locking_topology={'profile':'suse-sle-ha-15-sp7','available':False,'dlm_resources':[],'gfs2_resources':[],'lock_group_ids':[],'lock_clone_ids':[],'lockspace_directory':None,'lockspace_matches_gfs2':None,'lock_stack_detected':False,'runtime_available':False,'runtime_components_available':False,'runtime_component_nodes':{},'runtime_active_nodes':[],'runtime_online_nodes':[],'runtime_active_on_all_online_nodes':None,'vm_resources':[],'vm_constraints':{},'vm_constraints_complete':False,'complete':False,'error':''}
cib_code,cib_text=run(['cibadmin','-Q'],20)
if cib_code==0:
 try:
  cib=ET.fromstring(cib_text)
  configuration=cib.find('configuration')
  resources=configuration.find('resources') if configuration is not None else None
  cib_constraints=configuration.find('constraints') if configuration is not None else None
  parents={}; metadata={}
  def walk(element,wrappers=()):
   kind=element.tag.split('}')[-1]
   next_wrappers=wrappers+((kind,str(element.get('id') or '')),) if kind in ('clone','group','master') else wrappers
   if kind=='primitive':
    rid=str(element.get('id') or '')
    agent=':'.join(part for part in (element.get('class'),element.get('provider'),element.get('type')) if part)
    params={item.get('name'):item.get('value') for item in element.findall('./instance_attributes/nvpair') if item.get('name')}
    metadata[rid]={'agent':agent,'params':params,'wrappers':next_wrappers}
    parents[rid]=next_wrappers
   for child in list(element): walk(child,next_wrappers)
  if resources is not None: walk(resources)
  dlm=[rid for rid,item in metadata.items() if item['agent'].lower()=='ocf:pacemaker:controld']
  gfs2=[rid for rid,item in metadata.items() if item['agent'].lower().endswith(':filesystem') and str(item['params'].get('fstype','')).lower()=='gfs2']
  lock_clones=set()
  for dlm_id in dlm:
   for gfs_id in gfs2:
    dlm_clones={wrapper_id for kind,wrapper_id in parents.get(dlm_id,()) if kind=='clone'}
    gfs_clones={wrapper_id for kind,wrapper_id in parents.get(gfs_id,()) if kind=='clone'}
    dlm_groups={wrapper_id for kind,wrapper_id in parents.get(dlm_id,()) if kind=='group'}
    gfs_groups={wrapper_id for kind,wrapper_id in parents.get(gfs_id,()) if kind=='group'}
    if dlm_groups & gfs_groups: lock_clones.update(dlm_clones & gfs_clones)
  def config_value(path,key):
   try:
    with open(path,encoding='utf-8',errors='replace') as config:
     for line in config:
      if line.lstrip().startswith('#') or '=' not in line: continue
      name,value=line.split('=',1)
      if name.strip()==key:
       parts=shlex.split(value,comments=True)
       return parts[0] if parts else None
   except (OSError,ValueError): pass
   return None
  lockspace_dir=config_value('/etc/libvirt/qemu-lockd.conf','file_lockspace_dir')
  safe_lockspace=bool(lockspace_dir and os.path.isabs(lockspace_dir) and '..' not in lockspace_dir.split('/'))
  gfs2_dirs=[str(metadata[rid]['params'].get('directory') or '') for rid in gfs2]
  lockspace_matches=any(os.path.commonpath((os.path.normpath(directory),os.path.normpath(lockspace_dir)))==os.path.normpath(directory) for directory in gfs2_dirs if directory.startswith('/') and safe_lockspace)
  vm_ids=[rid for rid,item in metadata.items() if item['agent'].lower().endswith(':virtualdomain')]
  order_pairs=set(); colocation_pairs=set()
  if cib_constraints is not None:
   for item in cib_constraints.iter():
    tag=item.tag.split('}')[-1]
    if tag=='rsc_order':
     first=str(item.get('first') or '').strip('() ').split(); then=str(item.get('then') or '').strip('() ').split()
     for before in first:
      for after in then: order_pairs.add((before,after))
    elif tag=='rsc_colocation':
     left=str(item.get('rsc') or '').strip('() ').split(); right=str(item.get('with-rsc') or '').strip('() ').split()
     for vm in left:
      for lock in right: colocation_pairs.add((vm,lock))
  vm_constraints={vm:{'ordered_after_lock':any((lock,vm) in order_pairs for lock in lock_clones),'colocated_with_lock':any((vm,lock) in colocation_pairs for lock in lock_clones)} for vm in vm_ids}
  lock_groups=sorted({group for rid in dlm for kind,group in parents.get(rid,()) if kind=='group'} & {group for rid in gfs2 for kind,group in parents.get(rid,()) if kind=='group'})
  lock_stack_detected=bool(lock_groups and lock_clones and lockspace_matches)
  vm_constraints_complete=bool(vm_ids and lock_clones and all(item['ordered_after_lock'] and item['colocated_with_lock'] for item in vm_constraints.values()))
  runtime_available=False; runtime_components_available=False; runtime_component_nodes={}; runtime_active_nodes=set(); runtime_online_nodes=[]; runtime_all=None
  if lock_clones:
   runtime_code,runtime_text=run(['crm_mon','--one-shot','--output-as=xml'],20)
   if runtime_code==0:
    try:
     runtime=ET.fromstring(runtime_text)
     runtime_available=True
     runtime_online_nodes=sorted({str(node.get('name') or '').strip() for node in runtime.findall('.//nodes/node') if str(node.get('name') or '').strip() and str(node.get('online','true')).lower()=='true' and str(node.get('type','member')).lower()=='member'})
     lock_component_ids=set(dlm+gfs2)
     for clone in runtime.findall('.//resources/clone'):
      if str(clone.get('id') or '') not in lock_clones: continue
      for instance in clone.iter('resource'):
       instance_id=str(instance.get('id') or '')
       component_id=instance_id.split(':',1)[0]
       if component_id not in lock_component_ids: continue
       component_nodes=runtime_component_nodes.setdefault(component_id,set())
       if str(instance.get('active','false')).lower()!='true' or str(instance.get('failed','false')).lower()=='true' or str(instance.get('role') or '').lower()!='started': continue
       for node in instance.iter('node'):
        name=str(node.get('name') or '').strip()
        if name: component_nodes.add(name)
       name=str(instance.get('node') or '').strip()
       if name: component_nodes.add(name)
     runtime_components_available=lock_component_ids.issubset(runtime_component_nodes.keys())
     if runtime_components_available:
      runtime_active_nodes=set.intersection(*(runtime_component_nodes[component] for component in lock_component_ids))
      runtime_all=all(set(runtime_online_nodes).issubset(runtime_component_nodes[component]) for component in lock_component_ids) if runtime_online_nodes else None
    except Exception:
     runtime_available=False; runtime_components_available=False; runtime_component_nodes={}; runtime_active_nodes=set(); runtime_online_nodes=[]; runtime_all=None
  locking_topology={'profile':'suse-sle-ha-15-sp7','available':True,'dlm_resources':dlm,'gfs2_resources':[{'id':rid,'directory':metadata[rid]['params'].get('directory')} for rid in gfs2],'lock_group_ids':lock_groups,'lock_clone_ids':sorted(lock_clones),'lockspace_directory':lockspace_dir,'lockspace_matches_gfs2':lockspace_matches if safe_lockspace and gfs2_dirs else False if safe_lockspace else None,'lock_stack_detected':lock_stack_detected,'runtime_available':runtime_available,'runtime_components_available':runtime_components_available,'runtime_component_nodes':{component:sorted(nodes) for component,nodes in runtime_component_nodes.items()},'runtime_active_nodes':sorted(runtime_active_nodes),'runtime_online_nodes':runtime_online_nodes,'runtime_active_on_all_online_nodes':runtime_all,'vm_resources':vm_ids,'vm_constraints':vm_constraints,'vm_constraints_complete':vm_constraints_complete,'complete':bool(lock_stack_detected and runtime_all is True and vm_constraints_complete),'error':''}
 except Exception:
  locking_topology['error']='Pacemaker CIB could not be parsed for the SLE HA 15 SP7 virtualization-lock profile.'
else:
 locking_topology['error']=cib_text[:240] or 'cibadmin is unavailable'
code,rings=run(['corosync-cfgtool','-s']) if shutil.which('corosync-cfgtool') else (127,'corosync-cfgtool is not installed')
jcode,events=run(['journalctl','-u','pacemaker','-u','corosync','--since','24 hours ago','-n','80','--no-pager','-o','short-iso'],15)
if jcode==0:
 events=re.sub(r'(?i)(password|token|secret|credential)(\s*[=:]\s*)\S+',r'\1\2[REDACTED]',events)
 events='\n'.join(events.splitlines()[-80:])[:12000]
print(json.dumps({'constraints':constraints,'locking_topology':locking_topology,'corosync':{'available':code==0,'summary':rings[:5000],'error':rings[:240] if code else ''},'activity':{'available':jcode==0,'summary':events if jcode==0 else '', 'error':events[:240] if jcode else ''}}))
'''


HA_CLUSTER_ACTION_SCRIPT = r'''import re,subprocess,sys
action,target=sys.argv[1:3]
if not re.fullmatch(r'[A-Za-z0-9_.:@-]{1,255}',target): raise SystemExit('Invalid cluster object name')
commands={
 'node_standby':['crm','--wait','node','standby',target],
 'node_online':['crm','node','online',target],
 'node_maintenance':['crm','node','maintenance',target],
 'node_ready':['crm','node','ready',target],
 'resource_start':['crm','resource','start',target],
 'resource_stop':['crm','resource','stop',target],
 'resource_cleanup':['crm','resource','cleanup',target],
}
if action not in commands: raise SystemExit('Unsupported cluster operation')
try: result=subprocess.run(commands[action],capture_output=True,text=True,timeout=125 if action=='node_standby' else 60)
except subprocess.TimeoutExpired: raise SystemExit('The cluster operation timed out. Refresh status before retrying.')
if result.returncode: raise SystemExit((result.stderr or result.stdout or 'crmsh rejected the operation').strip()[:500])
print((result.stdout or result.stderr or 'Operation completed').strip()[:500])
'''


HA_RESOURCE_AGENTS_SCRIPT = r'''import json,os,re,shlex,subprocess,sys,xml.etree.ElementTree as ET
def run(args):
 result=subprocess.run(args,capture_output=True,text=True,timeout=20)
 if result.returncode: raise SystemExit((result.stderr or result.stdout or 'crmsh command failed').strip()[:400])
 return result.stdout
def config_value(path,key):
 try:
  with open(path,encoding='utf-8',errors='replace') as config:
   for line in config:
    if line.lstrip().startswith('#') or '=' not in line: continue
    name,value=line.split('=',1)
    if name.strip()!=key: continue
    parts=shlex.split(value,comments=True)
    return parts[0] if parts else ''
 except (OSError,ValueError):
  return None
 return None
def mount_info(path):
 try:
  result=subprocess.run(['findmnt','--json','--target',path,'--output','SOURCE,FSTYPE,UUID,TARGET'],capture_output=True,text=True,timeout=8)
  filesystems=json.loads(result.stdout).get('filesystems',[]) if result.returncode==0 else []
  item=filesystems[0] if filesystems else {}
  return {key:item.get(key) for key in ('source','fstype','uuid','target')} if item else None
 except Exception:
  return None
agents=[]
classes=[line.strip().lower() for line in run(['crm','ra','classes']).splitlines() if line.strip()]
for klass in ('ocf','systemd'):
 if klass not in classes: continue
 output=run(['crm','ra','list',klass])
 for line in output.splitlines():
  for token in line.split():
   token=token.strip(',')
   if klass=='ocf' and re.fullmatch(r'[A-Za-z0-9_.+-]+:[A-Za-z0-9_.+-]+',token): agents.append('ocf:'+token)
   elif klass=='systemd' and re.fullmatch(r'[A-Za-z0-9_.@+-]+\.service',token): agents.append('systemd:'+token)
lock_manager=config_value('/etc/libvirt/qemu.conf','lock_manager')
lockspace_dir=config_value('/etc/libvirt/qemu-lockd.conf','file_lockspace_dir')
lockspace_safe=bool(lockspace_dir and lockspace_dir.startswith('/') and '..' not in lockspace_dir.split('/'))
lockspace_exists=os.path.isdir(lockspace_dir) if lockspace_safe else None
virtlockd_states={}
for unit in ('virtlockd.service','virtlockd.socket'):
 try:
  check=subprocess.run(['systemctl','is-active',unit],capture_output=True,text=True,timeout=8)
  state=(check.stdout.strip() or check.stderr.strip())
  virtlockd_states[unit]=state if check.returncode==0 else ('inactive' if state=='inactive' else 'unknown')
 except Exception:
  virtlockd_states[unit]='unknown'
virtlockd_active=True if 'active' in virtlockd_states.values() else False if 'unknown' not in virtlockd_states.values() else None
gfs2_resources=[]
gfs2_resources_available=None
try:
 cib=subprocess.run(['cibadmin','-Q'],capture_output=True,text=True,timeout=12)
 if cib.returncode==0:
  root=ET.fromstring(cib.stdout)
  gfs2_resources_available=True
  for resource in root.findall('.//resources//primitive'):
   if (resource.get('class','').lower(),resource.get('provider','').lower(),resource.get('type','').lower()) not in (('ocf','heartbeat','filesystem'),('ocf','pacemaker','filesystem')): continue
   params={item.get('name'):item.get('value') for item in resource.findall('./instance_attributes//nvpair') if item.get('name') in ('directory','fstype')}
   directory=params.get('directory') or ''
   safe=bool(directory.startswith('/') and '..' not in directory.split('/') and len(directory)<=1024)
   if params.get('fstype','').lower()=='gfs2' and safe:
    gfs2_resources.append({'id':str(resource.get('id') or '')[:128],'directory':directory,'mount':mount_info(directory) if os.path.isdir(directory) else None})
except Exception:
 pass
print(json.dumps({'agents':sorted(set(agents)),'virtualization_locking':{
 'profile':'suse-sle-ha-15-sp7',
 'lock_manager':lock_manager,
 'lock_manager_is_lockd':lock_manager=='lockd' if lock_manager is not None else None,
 'file_lockspace_dir':lockspace_dir,
 'lockspace_path_safe':lockspace_safe,
 'lockspace_directory_exists':lockspace_exists,
 'lockspace_mount':mount_info(lockspace_dir) if lockspace_exists else None,
 'gfs2_resources':gfs2_resources,
 'gfs2_resources_available':gfs2_resources_available,
 'virtlockd_active':virtlockd_active,
 'virtlockd_services':virtlockd_states,
}}))
'''


HA_RESOURCE_AGENT_INFO_SCRIPT = r'''import re,subprocess,sys
agent=sys.argv[1]
if not re.fullmatch(r'(?:ocf:[A-Za-z0-9_.+-]+:[A-Za-z0-9_.+-]+|systemd:[A-Za-z0-9_.@+-]+\.service)',agent): raise SystemExit('Unsupported resource agent identifier')
result=subprocess.run(['crm','ra','info',agent],capture_output=True,text=True,timeout=20)
if result.returncode: raise SystemExit((result.stderr or result.stdout or 'crmsh could not describe this resource agent').strip()[:400])
print((result.stdout or '').strip()[:12000])
'''


HA_NFS_SERVICE_CONFIG_SCRIPT = r'''import ipaddress,json,os,re,subprocess,sys,tempfile,xml.etree.ElementTree as ET
p=json.loads(sys.stdin.read())
prefix=p.get('resource_prefix','')
if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,47}',prefix): raise SystemExit('Use a short resource prefix containing letters, numbers, dots, underscores, or hyphens.')
mode=p.get('storage_mode')
if mode not in ('drbd','shared'): raise SystemExit('Choose DRBD replication or externally shared block storage.')
node_count=int(p.get('cluster_node_count',0))
if node_count<2: raise SystemExit('The live cluster must report at least two nodes.')
if mode=='drbd' and node_count!=2: raise SystemExit('The SUSE DRBD-backed NFS profile is supported only for a two-node cluster. Use shared storage or a separately reviewed DRBD topology.')
drbd_resource=p.get('drbd_resource','')
if mode=='drbd' and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}',drbd_resource): raise SystemExit('Enter the existing DRBD resource name.')
if mode=='shared' and p.get('shared_storage_confirmed') is not True: raise SystemExit('Confirm that both devices refer to the same externally shared block storage on every cluster node.')
state_device=p.get('state_device',''); data_device=p.get('data_device',''); export_dir=p.get('share_directory',''); fs_type=p.get('filesystem','')
for name,device in (('NFS state',state_device),('NFS data',data_device)):
 if not isinstance(device,str) or not device.startswith('/dev/') or any(ord(c)<33 for c in device) or '..' in device.split('/'): raise SystemExit(name+' device must be an absolute safe path under /dev.')
 if not os.path.exists(device) or not os.path.exists(os.path.realpath(device)): raise SystemExit(name+' device does not exist on this cluster node: '+device)
 if not os.path.exists('/dev/null'): raise SystemExit('Could not inspect the local device namespace.')
 if not __import__('stat').S_ISBLK(os.stat(device).st_mode): raise SystemExit(name+' path is not a block device: '+device)
if state_device==data_device: raise SystemExit('The NFS client-state and export-data devices must be different.')
if mode=='drbd' and (not state_device.startswith('/dev/drbd') or not data_device.startswith('/dev/drbd')): raise SystemExit('DRBD mode requires existing /dev/drbd* devices.')
if mode=='shared' and (not state_device.startswith(('/dev/disk/by-id/','/dev/mapper/')) or not data_device.startswith(('/dev/disk/by-id/','/dev/mapper/'))): raise SystemExit('Shared-storage mode requires stable /dev/disk/by-id or /dev/mapper paths.')
if not isinstance(export_dir,str) or not export_dir.startswith('/') or export_dir=='/' or any(ord(c)<33 for c in export_dir) or '..' in export_dir.split('/'): raise SystemExit('Use an absolute export directory other than /, without whitespace or parent-directory segments.')
if fs_type not in ('ext4','xfs'): raise SystemExit('Choose an existing ext4 or XFS filesystem.')
if not os.path.isdir('/var/lib/nfs') or not os.path.isdir(export_dir): raise SystemExit('Create /var/lib/nfs and the selected export directory on every cluster node before configuring Pacemaker; this operation does not create or format storage.')
for directory in ('/var/lib/nfs',export_dir):
 mounts=[]
 try:
  for line in open('/proc/mounts',encoding='utf-8'):
   fields=line.split()
   if len(fields)>1 and fields[1].replace('\\040',' ')==directory: mounts.append(fields[0])
 except OSError: raise SystemExit('Could not verify whether NFS mount points are already in use.')
 if mounts: raise SystemExit('The mount point is already mounted outside this Pacemaker profile: '+directory)
drbd_primary=False
if mode=='drbd':
 check=subprocess.run(['drbdadm','status',drbd_resource],capture_output=True,text=True,timeout=20)
 if check.returncode: raise SystemExit((check.stderr or check.stdout or 'Could not read DRBD status for the selected resource.').strip()[:350])
 drbd_output=check.stdout or ''
 uptodate=len(re.findall(r'(?:disk|peer-disk):UpToDate',drbd_output,re.I))
 if uptodate<node_count: raise SystemExit('DRBD is not UpToDate on every member; synchronize both nodes and rerun preflight before creating the NFS profile.')
 drbd_primary=bool(re.search(r'\brole:Primary\b',drbd_output,re.I))
 if not drbd_primary and not re.search(r'\brole:Secondary\b',drbd_output,re.I): raise SystemExit('Could not confirm this node’s DRBD role; refresh DRBD status and retry.')
if mode=='shared' or drbd_primary:
 for device in (state_device,data_device):
  probe=subprocess.run(['blkid','-s','TYPE','-o','value',device],capture_output=True,text=True,timeout=10)
  if probe.returncode or (probe.stdout or '').strip()!=fs_type: raise SystemExit('Device '+device+' must already contain the selected '+fs_type+' filesystem; this operation never formats a device.')
clientspec=p.get('clientspec',''); virtual_ip=p.get('virtual_ip',''); netmask=p.get('cidr_netmask')
try: clientspec=str(ipaddress.ip_network(clientspec,strict=False)); address=ipaddress.ip_address(virtual_ip)
except ValueError: raise SystemExit('Enter a valid NFS client CIDR and virtual IP address.')
if not isinstance(netmask,int) or netmask<1 or netmask>address.max_prefixlen: raise SystemExit('The virtual-IP prefix length does not match its address family.')
if address.is_unspecified or address.is_multicast or address.is_loopback: raise SystemExit('Choose a usable unicast virtual IP address for the NFS clients.')
agents=['ocf:heartbeat:Filesystem','ocf:heartbeat:nfsserver','ocf:heartbeat:exportfs','ocf:heartbeat:IPaddr2']
if mode=='drbd': agents.append('ocf:linbit:drbd')
for agent in agents:
 check=subprocess.run(['crm','ra','info',agent],capture_output=True,text=True,timeout=20)
 if check.returncode: raise SystemExit('Required resource agent is unavailable on this cluster node: '+agent)
server_units=[]
for unit in ('nfs-server.service','nfsserver.service'):
 check=subprocess.run(['systemctl','cat',unit],capture_output=True,text=True,timeout=10)
 if check.returncode==0 and (check.stdout or '').strip(): server_units.append(unit)
if not server_units: raise SystemExit('The SUSE NFS server unit is not installed on this cluster node. Install the NFS server package on every node before continuing.')
if any(subprocess.run(['systemctl','is-active','--quiet',unit],capture_output=True,text=True,timeout=10).returncode==0 for unit in server_units):
 raise SystemExit('The NFS server is active outside this new Pacemaker profile on this node. Review and stop the standalone or existing NFS service before creating another HA profile.')
ip_check=subprocess.run(['ip','-j','address','show'],capture_output=True,text=True,timeout=10)
if ip_check.returncode: raise SystemExit('Could not inspect host addresses to check whether the selected NFS virtual IP is already in use.')
try: interfaces=json.loads(ip_check.stdout or '[]')
except ValueError: raise SystemExit('The host returned invalid interface data while checking the NFS virtual IP.')
if any(address.compressed.lower()==str(addr.get('local','')).split('%',1)[0].lower() for interface in interfaces for addr in interface.get('addr_info',[])):
 raise SystemExit('The selected NFS virtual IP is already assigned to a host interface.')
if p.get('preflight_only') is True:
 print(json.dumps({'success':True,'checked_node':os.uname().nodename,'storage_mode':mode,'agents':agents,'drbd_primary':drbd_primary}))
 raise SystemExit(0)
def duration(value):
 m=re.fullmatch(r'(\d+)(s|min|h)?',value or '')
 if not m: return None
 return int(m.group(1))*{'s':1,'min':60,'h':3600,None:1}[m.group(2)]
cib=ET.fromstring(subprocess.run(['cibadmin','-Q'],capture_output=True,text=True,timeout=20,check=True).stdout)
configuration=cib.find('configuration'); resources=configuration.find('resources') if configuration is not None else None
constraints=configuration.find('constraints') if configuration is not None else None
if resources is None or constraints is None: raise SystemExit('The live CIB has no resources or constraints section; refresh cluster status and retry.')
all_ids={item.get('id') for item in cib.iter() if item.get('id')}
ids={'fs_state':'fs-state-'+prefix,'fs_share':'fs-share-'+prefix,'nfs':'nfsserver-'+prefix,'export':'exportfs-'+prefix,'vip':'vip-'+prefix,'group':'g-'+prefix,'clone':'cl-drbd-'+prefix,'drbd':'drbd-'+prefix,'colocation':'col-'+prefix+'-on-drbd','order':'ord-'+prefix+'-drbd-before-service'}
needed=[ids[k] for k in ('fs_state','fs_share','nfs','export','vip','group')]
if mode=='drbd': needed.extend([ids['clone'],ids['drbd'],ids['colocation'],ids['order']])
collision=sorted(set(needed)&all_ids)
if collision: raise SystemExit('Pacemaker IDs already exist; choose another resource prefix: '+', '.join(collision))
properties=configuration.find('crm_config')
stonith_timeout=60
if properties is not None:
 for nv in properties.iter('nvpair'):
  if nv.get('name')=='stonith-enabled' and nv.get('value','true').strip().lower() in ('false','no','off','0'):
   raise SystemExit('Pacemaker has stonith-enabled disabled. Enable fencing in the cluster and rerun the NFS review.')
  if nv.get('name')=='stonith-timeout':
   stonith_timeout=duration(nv.get('value',''))
   if stonith_timeout is None: raise SystemExit('The configured stonith-timeout uses an unsupported format; configure this NFS profile manually after review.')
   break
export_timeout=max(90,stonith_timeout+30)
def q(v):
 if not isinstance(v,str) or any(ord(c)<32 for c in v): raise SystemExit('Pacemaker parameter contains unsupported control characters.')
 return '"'+v.replace('\\','\\\\').replace('"','\\"')+'"'
lines=[]
if mode=='drbd':
 lines += [f'primitive {ids["drbd"]} ocf:linbit:drbd params drbd_resource={q(drbd_resource)} op monitor interval=15s role=Promoted op monitor interval=30s role=Unpromoted',
  f'clone {ids["clone"]} {ids["drbd"]} meta promotable="true" promoted-max="1" promoted-node-max="1" clone-max="2" clone-node-max="1" notify="true" interleave="true" target-role="Stopped"']
lines += [
 f'primitive {ids["fs_state"]} ocf:heartbeat:Filesystem params device={q(state_device)} directory="/var/lib/nfs" fstype={fs_type} op monitor timeout=40s interval=20s',
 f'primitive {ids["fs_share"]} ocf:heartbeat:Filesystem params device={q(data_device)} directory={q(export_dir)} fstype={fs_type} op monitor timeout=40s interval=20s',
 f'primitive {ids["nfs"]} ocf:heartbeat:nfsserver params nfs_server_scope="SUSE" op monitor interval=10s timeout=20s',
 f'primitive {ids["export"]} ocf:heartbeat:exportfs params directory={q(export_dir)} options="rw,mountpoint" clientspec={q(clientspec)} op monitor interval=30s timeout={export_timeout}s',
 f'primitive {ids["vip"]} ocf:heartbeat:IPaddr2 params ip={q(str(address))} cidr_netmask={netmask} op monitor timeout=20s interval=10s',
 f'group {ids["group"]} '+ ' '.join(ids[k] for k in ('fs_state','fs_share','nfs','export','vip'))+' meta target-role="Stopped"']
if mode=='drbd':
 lines += [f'colocation {ids["colocation"]} inf: {ids["group"]} {ids["clone"]}:Promoted',
           f'order {ids["order"]} Mandatory: {ids["clone"]}:promote {ids["group"]}:start']
fd,path=tempfile.mkstemp(prefix='rancher-kvm-nfs-',suffix='.crm')
try:
 with os.fdopen(fd,'w',encoding='utf-8') as handle: handle.write('\n'.join(lines)+'\n')
 result=subprocess.run(['crm','configure','load','update',path],capture_output=True,text=True,timeout=90)
 if result.returncode: raise SystemExit((result.stderr or result.stdout or 'crmsh rejected the NFS resource profile').strip()[:500])
finally:
 try: os.unlink(path)
 except OSError: pass
if mode=='drbd':
 message='NFS Pacemaker resources and ordering constraints were created in Stopped state. Review storage and recovery assumptions; start the DRBD promotable clone first, verify one node is Promoted with all devices UpToDate, then explicitly start the NFS resource group.'
 result_ids=ids
else:
 message='NFS Pacemaker resources and ordering constraints were created in Stopped state. Review shared-storage identity and recovery assumptions, then explicitly start the NFS resource group.'
 result_ids={key:value for key,value in ids.items() if key not in ('clone','drbd','colocation','order')}
print(json.dumps({'success':True,'message':message,'resources':result_ids,'storage_mode':mode,'export_timeout_seconds':export_timeout}))
'''


HA_SERVICE_VIP_CONFIG_SCRIPT = r'''import hashlib,ipaddress,json,os,re,shutil,subprocess,sys,tempfile,xml.etree.ElementTree as ET
p=json.loads(sys.stdin.read())
prefix=p.get('resource_prefix','')
unit=p.get('service_unit','')
profile=p.get('profile','service')
if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,47}',prefix): raise SystemExit('Use a short resource prefix containing letters, numbers, dots, underscores, or hyphens.')
if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.@:-]{0,120}\.service',unit): raise SystemExit('Use an installed systemd service unit name ending in .service.')
if profile not in ('service','apache'): raise SystemExit('Choose the generic systemd service profile or the SUSE Apache profile.')
if profile=='apache' and p.get('apache_start_order_confirmed') is not True: raise SystemExit('Confirm Apache can start before the VIP is assigned, as required by the SUSE HA Apache resource group order.')
try: address=ipaddress.ip_address(p.get('virtual_ip',''))
except ValueError: raise SystemExit('Enter a valid IPv4 or IPv6 virtual IP address.')
netmask=p.get('cidr_netmask')
if not isinstance(netmask,int) or netmask<1 or netmask>address.max_prefixlen: raise SystemExit('The VIP prefix length does not match its address family.')
if address.is_unspecified or address.is_multicast or address.is_loopback: raise SystemExit('Choose a usable unicast virtual IP address.')
if p.get('shared_network_confirmed') is not True: raise SystemExit('Confirm that the virtual IP is available on the same client-facing network from every cluster node.')
unit_check=subprocess.run(['systemctl','cat',unit],capture_output=True,text=True,timeout=15)
if unit_check.returncode or not (unit_check.stdout or '').strip(): raise SystemExit('The selected service unit is not installed on this cluster node: '+unit)
if subprocess.run(['systemctl','is-active','--quiet',unit],capture_output=True,text=True,timeout=10).returncode==0: raise SystemExit('The selected service is already active outside this Pacemaker profile on this node. Stop the standalone service before proceeding.')
if subprocess.run(['systemctl','is-enabled','--quiet',unit],capture_output=True,text=True,timeout=10).returncode==0: raise SystemExit('The selected service is enabled to start outside Pacemaker at boot. Disable its standalone boot activation on every node, then rerun the review; this workflow does not change systemd settings.')
agent='service:'+unit if profile=='service' else 'ocf:heartbeat:apache'
vip_agent='ocf:heartbeat:IPaddr2' if profile=='service' else 'ocf:heartbeat:IPaddr'
agents=(agent,vip_agent)
for agent in agents:
 check=subprocess.run(['crm','ra','info',agent],capture_output=True,text=True,timeout=20)
 if check.returncode: raise SystemExit('Required Pacemaker resource agent is unavailable on this node: '+agent)
configuration_hash=None
configfile=p.get('apache_configfile','')
if profile=='apache':
 if not isinstance(configfile,str) or not configfile.startswith('/') or any(ord(c)<33 for c in configfile) or '..' in configfile.split('/'): raise SystemExit('Use an absolute Apache configuration file path without whitespace or parent-directory segments.')
 if not os.path.isfile(configfile) or not os.access(configfile,os.R_OK): raise SystemExit('The selected Apache configuration file is not readable on this cluster node: '+configfile)
 apache_check=shutil.which('apachectl') or shutil.which('apache2ctl') or shutil.which('httpd')
 if not apache_check: raise SystemExit('Could not find apachectl, apache2ctl, or httpd to validate the selected Apache configuration.')
 result=subprocess.run([apache_check,'-t','-f',configfile],capture_output=True,text=True,timeout=25)
 if result.returncode: raise SystemExit('Apache configuration validation failed: '+(result.stderr or result.stdout or 'correct the Apache configuration before continuing').strip()[:300])
 try:
  with open(configfile,'rb') as handle: configuration_data=handle.read(4*1024*1024+1)
 except OSError as exc: raise SystemExit('Could not read the selected Apache configuration file: '+str(exc)[:200])
 if len(configuration_data)>4*1024*1024: raise SystemExit('The selected Apache configuration file exceeds the 4 MiB safety limit; review and configure it manually.')
 configuration_hash=hashlib.sha256(configuration_data).hexdigest()
 expected_hash=p.get('expected_configuration_sha256')
 if expected_hash is not None and (not re.fullmatch(r'[a-f0-9]{64}',expected_hash) or expected_hash!=configuration_hash): raise SystemExit('The selected Apache configuration file changed after the all-node preflight. Refresh the review and retry.')
result=subprocess.run(['ip','-j','address','show'],capture_output=True,text=True,timeout=10)
if result.returncode: raise SystemExit('Could not inspect host addresses to check whether the selected virtual IP is already assigned.')
try: interfaces=json.loads(result.stdout or '[]')
except ValueError: raise SystemExit('The host returned invalid interface data while checking the virtual IP.')
if any(address.compressed.lower()==str(item.get('local','')).split('%',1)[0].lower() for interface in interfaces for item in interface.get('addr_info',[])):
 raise SystemExit('The selected virtual IP is already assigned to a host interface.')
route=subprocess.run(['ip','-j','route','get',address.compressed],capture_output=True,text=True,timeout=10)
if route.returncode: raise SystemExit('No usable host route exists for the selected virtual IP on this cluster node.')
try: route_entries=json.loads(route.stdout or '[]')
except ValueError: raise SystemExit('The host returned invalid route data while checking the virtual IP.')
source=route_entries[0].get('prefsrc') or route_entries[0].get('src') if route_entries else None
if not route_entries or not route_entries[0].get('dev') or route_entries[0].get('dev')=='lo' or not source:
 raise SystemExit('The selected VIP has no usable client-facing network route on this cluster node.')
try: source_address=ipaddress.ip_address(source)
except ValueError: raise SystemExit('The host returned an invalid source address for the virtual-IP route.')
if source_address.version!=address.version: raise SystemExit('The selected VIP and the host route use different IP address families.')
if p.get('preflight_only') is True:
 print(json.dumps({'success':True,'checked_node':os.uname().nodename,'service_unit':unit,'profile':profile,'configuration_sha256':configuration_hash,'virtual_ip':address.compressed,'route_device':route_entries[0].get('dev')}))
 raise SystemExit(0)
cib=ET.fromstring(subprocess.run(['cibadmin','-Q'],capture_output=True,text=True,timeout=20,check=True).stdout)
configuration=cib.find('configuration'); resources=configuration.find('resources') if configuration is not None else None
if resources is None: raise SystemExit('The live CIB has no resources section; refresh cluster status and retry.')
crm_config=configuration.find('crm_config')
if crm_config is not None and any(item.get('name')=='stonith-enabled' and item.get('value','true').strip().lower() in ('false','no','off','0') for item in crm_config.iter('nvpair')):
 raise SystemExit('Pacemaker has stonith-enabled disabled. Enable and verify fencing before creating this failover profile.')
all_ids={item.get('id') for item in cib.iter() if item.get('id')}
ids={'vip':'vip-'+prefix,'service':'service-'+prefix,'group':'g-'+prefix}
collision=sorted(set(ids.values())&all_ids)
if collision: raise SystemExit('Pacemaker IDs already exist; choose another resource prefix: '+', '.join(collision))
def q(value):
 if not isinstance(value,str) or any(ord(char)<32 for char in value): raise SystemExit('Pacemaker parameter contains unsupported control characters.')
 return '"'+value.replace('\\','\\\\').replace('"','\\"')+'"'
vip_line=f'primitive {ids["vip"]} {vip_agent} params ip={q(address.compressed)} cidr_netmask={netmask} op monitor timeout=20s interval=10s'
if profile=='apache':
 service_line=f'primitive {ids["service"]} apache params configfile={q(configfile)} op monitor interval=60s timeout=120s'
 ordered=f'{ids["service"]} {ids["vip"]}'
else:
 service_line=f'primitive {ids["service"]} service:{unit} op monitor timeout=30s interval=20s'
 ordered=f'{ids["vip"]} {ids["service"]}'
lines=[vip_line,service_line,f'group {ids["group"]} {ordered} meta target-role="Stopped"']
fd,path=tempfile.mkstemp(prefix='rancher-kvm-service-',suffix='.crm')
try:
 with __import__('os').fdopen(fd,'w',encoding='utf-8') as handle: handle.write('\n'.join(lines)+'\n')
 applied=subprocess.run(['crm','configure','load','update',path],capture_output=True,text=True,timeout=60)
 if applied.returncode: raise SystemExit((applied.stderr or applied.stdout or 'crmsh rejected the application service profile').strip()[:500])
finally:
 try: __import__('os').unlink(path)
 except OSError: pass
message='The SUSE Apache resource-agent template was created in Stopped state following the documented crmsh configuration (Apache, then virtual IP). Review bind behavior, included configuration, certificates, and content consistency before explicitly starting the group.' if profile=='apache' else 'The SUSE HA group was created in Stopped state with the virtual IP starting before the service. Confirm the application is correctly configured for the VIP and then explicitly start the group. Pacemaker must own service start and stop actions after that.'
print(json.dumps({'success':True,'message':message,'resources':ids,'service_unit':unit,'profile':profile,'configuration_sha256':configuration_hash,'virtual_ip':address.compressed}))
'''


HA_STONITH_AGENTS_SCRIPT = r'''import json,re,subprocess
result=subprocess.run(['crm','ra','list','stonith'],capture_output=True,text=True,timeout=20)
if result.returncode: raise SystemExit((result.stderr or result.stdout or 'crmsh could not list fencing agents').strip()[:400])
agents=set()
for token in re.split(r'\s+',result.stdout or ''):
 token=token.strip(',;')
 if token.startswith('stonith:'): token=token[len('stonith:'):]
 if re.fullmatch(r'(?:[A-Za-z0-9_.+-]+/)?[A-Za-z0-9_.+-]+',token): agents.add('stonith:'+token)
print(json.dumps({'agents':sorted(agents)}))
'''


HA_STONITH_AGENT_INFO_SCRIPT = r'''import re,subprocess,sys
agent=sys.argv[1]
if not re.fullmatch(r'stonith:(?:[A-Za-z0-9_.+-]+/)?[A-Za-z0-9_.+-]+',agent): raise SystemExit('Unsupported fencing-agent identifier')
result=subprocess.run(['crm','ra','info',agent],capture_output=True,text=True,timeout=20)
if result.returncode: raise SystemExit((result.stderr or result.stdout or 'crmsh could not describe this fencing agent').strip()[:400])
print((result.stdout or '').strip()[:12000])
'''


HA_RESOURCE_MUTATION_SCRIPT = r'''import json,re,subprocess,sys,tempfile,xml.etree.ElementTree as ET,os,uuid
payload=json.loads(sys.stdin.read())
action=payload['action']; resource_id=payload['resource_id']
if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',resource_id): raise SystemExit('Use a resource ID with letters, numbers, dots, underscores, or hyphens; start with a letter or number.')
def run(args,timeout=30):
 result=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
 if result.returncode: raise SystemExit((result.stderr or result.stdout or 'crmsh operation failed').strip()[:500])
 return result.stdout
def resource_element():
 xml=run(['cibadmin','-Q','-o','resources'])
 root=ET.fromstring(xml)
 for item in root.iter():
  if item.get('id')==resource_id and item.tag in ('primitive','group','clone','bundle','master'):
   return item
 return None
def resource_tree():
 return ET.fromstring(run(['cibadmin','-Q','-o','resources']))
def direct_group(group_id):
 tree=resource_tree()
 for item in tree.iter('group'):
  if item.get('id')!=group_id: continue
  if any(parent.tag in ('group','clone','master','bundle') and any(child is item for child in list(parent)) for parent in tree.iter()):
   raise SystemExit('Nested groups inside clones or other containers are not editable from this workflow.')
  return item
 return None
def all_active_ids():
 status=ET.fromstring(run(['crm_mon','--one-shot','--output-as=xml'],25))
 return {item.get('id') for item in status.findall('.//resources//resource') if item.get('id') and item.get('active','false').lower() in ('true','1','yes')}
def all_failed_ids():
 status=ET.fromstring(run(['crm_mon','--one-shot','--output-as=xml'],25))
 return {item.get('id') for item in status.findall('.//resources//resource') if item.get('id') and item.get('failed','false').lower() in ('true','1','yes')}
def ensure_group_stopped(group,active):
 ids=[item.get('id') for item in list(group) if item.tag=='primitive' and item.get('id')]
 running=[item for item in ids if item in active]
 if running: raise SystemExit('Stop the group resources before changing membership: '+', '.join(running))
 return ids
def validate_group_child(child_id,tree):
 if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',child_id): raise SystemExit('Choose a valid primitive resource.')
 found=None
 for item in tree.iter('primitive'):
  if item.get('id')==child_id: found=item; break
 if found is None: raise SystemExit('The selected group member is not a primitive resource in this cluster.')
 if found.get('class')=='stonith': raise SystemExit('Fencing devices cannot be placed in workload resource groups.')
 for parent in tree.iter():
  if parent.tag in ('group','clone','master','bundle') and any(child is found for child in list(parent)):
   raise SystemExit('The selected resource already belongs to a group or clone.')
 return found
def apply_config(lines):
 fd,path=tempfile.mkstemp(prefix='rancher-kvm-group-',suffix='.crm')
 try:
  with os.fdopen(fd,'w',encoding='utf-8') as handle: handle.write('\n'.join(lines)+'\n')
  run(['crm','configure','load','update',path],timeout=60)
 finally:
  try: os.unlink(path)
  except OSError: pass
def apply_xml_config(group_id, expected_members, desired_members):
 # crmsh's XML loader expects a CIB document with the changed object under
 # configuration/resources; a bare <group> is not a valid import document.
 cib=ET.fromstring(run(['cibadmin','-Q']))
 configuration=cib.find('configuration')
 resources=configuration.find('resources') if configuration is not None else None
 if resources is None: raise SystemExit('The current CIB has no resources section; refresh cluster status and retry.')
 group=next((item for item in resources.findall('group') if item.get('id')==group_id),None)
 if group is None: raise SystemExit('The resource group disappeared; refresh cluster status and retry.')
 current_members=[item.get('id') for item in list(group) if item.tag=='primitive' and item.get('id')]
 if current_members!=expected_members: raise SystemExit('The resource group changed while this form was open; refresh cluster status and review the order again.')
 active=all_active_ids()
 running=[member for member in current_members if member in active]
 if running: raise SystemExit('The resource group started while this form was open; stop its resources and retry: '+', '.join(running))
 by_id={item.get('id'):item for item in list(group) if item.tag=='primitive' and item.get('id')}
 other_children=[item for item in list(group) if item.tag!='primitive']
 for item in list(group): group.remove(item)
 for member in desired_members: group.append(by_id[member])
 for item in other_children: group.append(item)
 # Keep the CIB's schema and generation attributes, but import only the
 # resource section so crmsh cannot touch constraints or cluster properties.
 update=ET.Element('cib',dict(cib.attrib))
 update_configuration=ET.SubElement(update,'configuration',dict(configuration.attrib))
 update_resources=ET.SubElement(update_configuration,'resources',dict(resources.attrib))
 update_resources.append(ET.fromstring(ET.tostring(group,encoding='unicode')))
 fd,path=tempfile.mkstemp(prefix='rancher-kvm-group-',suffix='.xml')
 try:
  with os.fdopen(fd,'w',encoding='utf-8') as handle: handle.write(ET.tostring(update,encoding='unicode'))
  run(['crm','configure','load','xml','update',path],timeout=60)
 finally:
  try: os.unlink(path)
  except OSError: pass
def check_primitive():
 item=resource_element()
 if item is None: raise SystemExit('Resource not found in the Pacemaker configuration.')
 if item.tag!='primitive': raise SystemExit('This action currently supports primitive resources only; groups and clones require their own workflow.')
 tree=resource_tree()
 primitive=next((candidate for candidate in tree.iter('primitive') if candidate.get('id')==resource_id),None)
 if primitive is not None and any(parent.tag in ('group','clone','master','bundle') and any(child is primitive for child in list(parent)) for parent in tree.iter()):
  raise SystemExit('A primitive inside a group or clone must be managed through its parent resource workflow.')
 if item.get('class')=='stonith': raise SystemExit('Fencing resources must be changed in the dedicated fencing workflow.')
 return item
def quote(value):
 if not isinstance(value,str) or len(value)>2048 or any(ord(ch)<32 for ch in value): raise SystemExit('Resource values must be printable single-line text up to 2048 characters.')
 return '"'+value.replace('\\','\\\\').replace('"','\\"')+'"'
def normalized_seconds(value,allow_zero=False):
 if not isinstance(value,str): raise SystemExit('Monitor intervals and timeouts must use seconds, minutes, or hours.')
 match=re.fullmatch(r'(\d+)(s|min|h)?',value.strip())
 if not match: raise SystemExit('Monitor intervals and timeouts must use a whole number followed by s, min, or h.')
 amount=int(match.group(1)); multiplier={'s':1,'min':60,'h':3600,None:1}[match.group(2)]
 seconds=amount*multiplier
 if (seconds<0 if allow_zero else seconds<1) or seconds>86400: raise SystemExit('Monitor intervals must be between 0 seconds and 24 hours; timeouts must be between 1 second and 24 hours.')
 return seconds
def validated_monitor_operations(rows,default_if_empty=False):
 if default_if_empty and not rows: rows=[{'interval':'30s','role':'','timeout':''}]
 if not isinstance(rows,list) or len(rows)<1 or len(rows)>16: raise SystemExit('Configure between one and 16 monitor operations.')
 allowed_roles={'','Started','Stopped','Promoted','Unpromoted','Master','Slave'}
 normalized=[]; intervals=[]; operation_ids=set()
 for row in rows:
  if not isinstance(row,dict): raise SystemExit('Each monitor operation must be an object.')
  interval=row.get('interval',''); seconds=normalized_seconds(interval,allow_zero=True)
  role=row.get('role','')
  if role not in allowed_roles: raise SystemExit('Choose a supported Pacemaker monitor role.')
  if any(seen_seconds==seconds and (seen_role==role or not seen_role or not role) for seen_seconds,seen_role in intervals): raise SystemExit('Monitor operations with the same interval must use distinct explicit roles.')
  intervals.append((seconds,role))
  timeout=(row.get('timeout') or '').strip()
  if timeout: normalized_seconds(timeout)
  operation_id=(row.get('operation_id') or '').strip()
  if operation_id:
   if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}',operation_id): raise SystemExit('The monitor operation ID is invalid; refresh cluster status and retry.')
   if operation_id in operation_ids: raise SystemExit('A monitor operation was submitted more than once.')
   operation_ids.add(operation_id)
  normalized.append({'operation_id':operation_id,'interval':interval.strip(),'role':role,'timeout':timeout})
 return normalized
def apply_primitive_xml_config(primitive):
 cib=ET.fromstring(run(['cibadmin','-Q']))
 configuration=cib.find('configuration')
 resources=configuration.find('resources') if configuration is not None else None
 if resources is None: raise SystemExit('The current CIB has no resources section; refresh cluster status and retry.')
 current=next((item for item in resources.findall('primitive') if item.get('id')==resource_id),None)
 if current is None: raise SystemExit('The resource is no longer a standalone primitive; refresh cluster status and retry.')
 if any(parent.tag in ('group','clone','master','bundle') and any(child is current for child in list(parent)) for parent in resources.iter()):
  raise SystemExit('This primitive is now inside a group or clone; refresh cluster status and use its parent workflow.')
 active=all_active_ids()
 if resource_id in active: raise SystemExit('Stop the primitive before editing monitor operations; the resource started while this form was open.')
 operations=current.find('operations')
 if operations is None:
  operations=ET.SubElement(current,'operations',{'id':resource_id+'-operations'})
 old_monitors=[item for item in list(operations) if item.tag=='op' and item.get('name')=='monitor']
 old_ids=[item.get('id','') for item in old_monitors]
 if not all(old_ids) or len(set(old_ids))!=len(old_ids): raise SystemExit('Existing monitor operations have missing or duplicate IDs; edit this resource with crmsh and refresh the cluster status.')
 expected=payload.get('expected_operation_ids') or []
 if not isinstance(expected,list) or len(expected)>16 or len(set(expected))!=len(expected) or set(expected)!=set(old_ids):
  raise SystemExit('Monitor operations changed while this form was open; refresh the cluster status and review the current operations.')
 expected_operations=payload.get('expected_operations') or []
 if not isinstance(expected_operations,list) or len(expected_operations)>16 or len(expected_operations)!=len(old_monitors):
  raise SystemExit('Monitor operations changed while this form was open; refresh the cluster status and review the current operations.')
 expected_by_id={row.get('operation_id'):row for row in expected_operations if isinstance(row,dict) and row.get('operation_id')}
 if set(expected_by_id)!=set(old_ids) or len(expected_by_id)!=len(expected_operations):
  raise SystemExit('Monitor operations changed while this form was open; refresh the cluster status and review the current operations.')
 for item in old_monitors:
  expected_row=expected_by_id[item.get('id')]
  if (expected_row.get('interval','')!=item.get('interval','') or expected_row.get('role','')!=item.get('role','') or expected_row.get('timeout','')!=item.get('timeout','')):
   raise SystemExit('A monitor interval, role, or timeout changed while this form was open; refresh cluster status and review the current operations.')
 monitors=validated_monitor_operations(payload.get('operations'))
 old_by_id={item.get('id'):item for item in old_monitors}
 for operation in monitors:
  operation_id=operation['operation_id']
  if operation_id and operation_id not in old_by_id: raise SystemExit('A submitted monitor operation no longer exists; refresh cluster status and retry.')
 new_monitors=[]
 for operation in monitors:
  item=old_by_id.get(operation['operation_id']) if operation['operation_id'] else None
  if item is None: item=ET.Element('op',{'id':'rancher-kvm-monitor-'+uuid.uuid4().hex,'name':'monitor'})
  item.set('name','monitor'); item.set('interval',operation['interval'])
  if operation['role']: item.set('role',operation['role'])
  else: item.attrib.pop('role',None)
  if operation['timeout']: item.set('timeout',operation['timeout'])
  else: item.attrib.pop('timeout',None)
  new_monitors.append(item)
 for item in old_monitors: operations.remove(item)
 for item in new_monitors: operations.append(item)
 update=ET.Element('cib',dict(cib.attrib))
 update_configuration=ET.SubElement(update,'configuration',dict(configuration.attrib))
 update_resources=ET.SubElement(update_configuration,'resources',dict(resources.attrib))
 update_resources.append(ET.fromstring(ET.tostring(current,encoding='unicode')))
 fd,path=tempfile.mkstemp(prefix='rancher-kvm-monitor-',suffix='.xml')
 try:
  with os.fdopen(fd,'w',encoding='utf-8') as handle: handle.write(ET.tostring(update,encoding='unicode'))
  run(['crm','configure','load','xml','update',path],timeout=60)
 finally:
  try: os.unlink(path)
  except OSError: pass
if action=='create':
 agent=payload.get('agent') or ''
 if not re.fullmatch(r'(?:ocf:[A-Za-z0-9_.+-]+:[A-Za-z0-9_.+-]+|systemd:[A-Za-z0-9_.@+-]+\.service)',agent): raise SystemExit('Choose an installed OCF or systemd resource agent.')
 params=payload.get('parameters') or {}
 if len(params)>40: raise SystemExit('A primitive resource can have at most 40 parameters in this form.')
 monitors=validated_monitor_operations(payload.get('operations'),default_if_empty=True)
 lines=[]
 for key,value in sorted(params.items()):
  if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,63}',key): raise SystemExit('Invalid resource parameter name.')
  lines.append(f'  {key}={quote(value)}')
 if resource_element() is not None: raise SystemExit('A resource with this ID already exists.')
 info=subprocess.run(['crm','ra','info',agent],capture_output=True,text=True,timeout=20)
 if info.returncode: raise SystemExit((info.stderr or info.stdout or 'The selected resource agent is not available on this host.').strip()[:400])
 config=f'primitive {resource_id} {agent}'
 if lines: config+=' \\\n  params '+' '.join(lines)
 for monitor in monitors:
  config+=' \\\n  op monitor interval='+monitor['interval']
  if monitor['role']: config+=' role='+monitor['role']
  if monitor['timeout']: config+=' timeout='+monitor['timeout']
 config+=' \\\n  meta target-role="Stopped"\n'
 fd,path=tempfile.mkstemp(prefix='rancher-kvm-resource-',suffix='.crm')
 try:
  with os.fdopen(fd,'w',encoding='utf-8') as handle: handle.write(config)
  run(['crm','configure','load','update',path],timeout=60)
 finally:
  try: os.unlink(path)
  except OSError: pass
 print('Primitive resource created in Stopped state. Review its parameters, then start it when the service is ready on the cluster nodes.')
elif action=='create_stonith':
 agent=payload.get('agent') or ''
 target_node=(payload.get('fencing_target') or '').strip()
 if not re.fullmatch(r'stonith:(?:[A-Za-z0-9_.+-]+/)?[A-Za-z0-9_.+-]+',agent): raise SystemExit('Choose an installed SUSE STONITH fencing agent.')
 if not target_node or len(target_node)>255 or any(ord(ch)<33 or ord(ch)>126 for ch in target_node): raise SystemExit('Choose a current cluster node as the fencing target.')
 parameters=payload.get('parameters') or {}
 if not isinstance(parameters,dict) or len(parameters)>40: raise SystemExit('A fencing device can have at most 40 parameters in this form.')
 if any(key.lower() in ('pcmk_host_list','pcmk_host_map') for key in parameters): raise SystemExit('The extension sets the target-node mapping; do not add pcmk_host_list or pcmk_host_map manually.')
 if resource_element() is not None: raise SystemExit('A Pacemaker object with this fencing resource ID already exists.')
 interval=payload.get('monitor_interval') or '30min'; timeout=payload.get('monitor_timeout') or '120s'
 normalized_seconds(interval); normalized_seconds(timeout)
 info=subprocess.run(['crm','ra','info',agent],capture_output=True,text=True,timeout=20)
 if info.returncode: raise SystemExit((info.stderr or info.stdout or 'The selected fencing agent is not installed on this cluster node.').strip()[:400])
 status=ET.fromstring(run(['crm_mon','--one-shot','--output-as=xml'],timeout=25))
 known_nodes={node.get('name') or node.get('uname') for node in status.findall('.//nodes/node')}
 if target_node not in known_nodes: raise SystemExit('The fencing target is no longer a member of this SUSE HA cluster; refresh status and choose a current node.')
 cib_resources=ET.fromstring(run(['cibadmin','-Q','-o','resources']))
 for existing in cib_resources.iter('primitive'):
  if existing.get('class')!='stonith': continue
  attrs=existing.find('instance_attributes')
  if attrs is not None:
   for nv in attrs.iter('nvpair'):
    name=nv.get('name'); value=nv.get('value','')
    if name=='pcmk_host_list' and target_node in value.replace(',',' ').split():
     raise SystemExit('A STONITH resource already targets this node. Review the existing fencing device before adding another.')
    if name=='pcmk_host_map':
     mapped={entry.split(':',1)[0] for entry in re.split(r'[\s,]+',value.strip()) if entry}
     if target_node in mapped: raise SystemExit('A STONITH resource already targets this node. Review the existing fencing device before adding another.')
 lines=[]
 for key,value in sorted(parameters.items()):
  if not isinstance(key,str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,63}',key): raise SystemExit('Invalid fencing parameter name.')
  lines.append(f'  {key}={quote(value)}')
 lines.insert(0,'  pcmk_host_list='+quote(target_node))
 config=f'primitive {resource_id} {agent}'
 config+=' \\\n  params '+' '.join(line.strip() for line in lines)
 config+=' \\\n  op monitor interval='+interval+' timeout='+timeout
 config+=' \\\n  meta target-role="Stopped"\n'
 fd,path=tempfile.mkstemp(prefix='rancher-kvm-stonith-',suffix='.crm')
 try:
  with os.fdopen(fd,'w',encoding='utf-8') as handle: handle.write(config)
  run(['crm','configure','load','update',path],timeout=60)
 finally:
  try: os.unlink(path)
  except OSError: pass
 print('Fencing resource created in Stopped state. Verify agent connectivity and parameters, then explicitly start it to enable fencing for its target node.')
elif action=='edit_stonith':
 target_node=(payload.get('fencing_target') or '').strip()
 parameters=payload.get('parameters') or {}
 removals=payload.get('parameter_removals') or []
 if not isinstance(parameters,dict) or len(parameters)>40 or not isinstance(removals,list) or len(removals)>40: raise SystemExit('A fencing update can change at most 40 parameters.')
 if not target_node or len(target_node)>255 or any(ord(ch)<33 or ord(ch)>126 for ch in target_node): raise SystemExit('Refresh cluster status and choose its current fencing target.')
 protected={'pcmk_host_list','pcmk_host_map'}
 if not parameters and not removals: raise SystemExit('Enter a parameter change or select a parameter to remove.')
 names=set()
 for key,value in parameters.items():
  if not isinstance(key,str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,63}',key): raise SystemExit('Invalid fencing parameter name.')
  if key.lower() in protected: raise SystemExit('The extension-managed fencing target mapping cannot be edited here.')
  if not isinstance(value,str) or not value: raise SystemExit('Enter a non-empty replacement value for each changed fencing parameter.')
  quote(value)
  names.add(key)
 if any(not isinstance(key,str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,63}',key) or key.lower() in protected for key in removals): raise SystemExit('Invalid or protected fencing parameter selected for removal.')
 if len(set(removals))!=len(removals) or names.intersection(removals): raise SystemExit('A fencing parameter cannot be changed and removed in the same request.')
 cib=ET.fromstring(run(['cibadmin','-Q']))
 configuration=cib.find('configuration')
 resources=configuration.find('resources') if configuration is not None else None
 if resources is None: raise SystemExit('The current CIB has no resources section; refresh cluster status and retry.')
 primitive=next((item for item in resources.findall('primitive') if item.get('id')==resource_id and item.get('class')=='stonith'),None)
 if primitive is None: raise SystemExit('Select a current standalone fencing device to edit.')
 current_agent='stonith:'+((primitive.get('provider')+'/') if primitive.get('provider') else '')+(primitive.get('type') or '')
 if payload.get('agent')!=current_agent: raise SystemExit('The fencing agent changed while this form was open; refresh status and retry.')
 state=ET.fromstring(run(['crm_mon','--one-shot','--output-as=xml'],25))
 current=next((entry for entry in state.findall('.//resources//resource') if entry.get('id')==resource_id),None)
 if current is None: raise SystemExit('Pacemaker did not report the fencing-resource state. Refresh cluster status before editing it.')
 if current.get('active','false').lower() in ('true','1','yes'): raise SystemExit('Stop this fencing resource before editing its parameters.')
 if current.get('failed','false').lower() in ('true','1','yes'): raise SystemExit('Clean up the failed fencing-resource state before editing its parameters.')
 known_nodes={node.get('name') or node.get('uname') for node in state.findall('.//nodes/node')}
 if target_node not in known_nodes: raise SystemExit('The fencing target is no longer a cluster member; refresh status and retry.')
 attributes=[(section,nv) for section in primitive.findall('instance_attributes') for nv in section.iter('nvpair')]
 mapped=set()
 for _section,nv in attributes:
  name=nv.get('name',''); value=nv.get('value','')
  if name=='pcmk_host_list': mapped.update(node.strip() for node in value.replace(',',' ').split() if node.strip())
  elif name=='pcmk_host_map': mapped.update(entry.split(':',1)[0] for entry in re.split(r'[\s,]+',value.strip()) if ':' in entry)
 if mapped!={target_node}: raise SystemExit('This editor supports a single-node fencing mapping. Review the target mapping with SUSE cluster tools before changing this device.')
 by_name={}
 for section,nv in attributes:
  name=nv.get('name','')
  if name in by_name: raise SystemExit('This device has duplicate parameter entries; edit its configuration with SUSE cluster tools and refresh status.')
  by_name[name]=(section,nv)
 if any(key not in by_name for key in removals): raise SystemExit('A parameter selected for removal changed while this form was open; refresh status and retry.')
 for key,value in parameters.items():
  if key in by_name: by_name[key][1].set('value',value)
  else:
   section=primitive.find('instance_attributes')
   if section is None: section=ET.SubElement(primitive,'instance_attributes',{'id':resource_id+'-params-'+uuid.uuid4().hex[:12]})
   ET.SubElement(section,'nvpair',{'id':resource_id+'-'+key+'-'+uuid.uuid4().hex[:12],'name':key,'value':value})
 for key in removals:
  section,nv=by_name[key]
  section.remove(nv)
 update=ET.Element('cib',dict(cib.attrib))
 update_configuration=ET.SubElement(update,'configuration',dict(configuration.attrib))
 update_resources=ET.SubElement(update_configuration,'resources',dict(resources.attrib))
 update_resources.append(ET.fromstring(ET.tostring(primitive,encoding='unicode')))
 fd,path=tempfile.mkstemp(prefix='rancher-kvm-stonith-edit-',suffix='.xml')
 try:
  with os.fdopen(fd,'w',encoding='utf-8') as handle: handle.write(ET.tostring(update,encoding='unicode'))
  try: run(['crm','configure','load','xml','update',path],timeout=60)
  except SystemExit: raise SystemExit('SUSE crmsh rejected the fencing parameter update. Stored device values were not returned; refresh status and inspect the resource in Hawk before retrying.')
 finally:
  try: os.unlink(path)
  except OSError: pass
 print('Stopped fencing-device parameters updated. Verify agent guidance and connectivity, then explicitly start the resource when its target is protected.')
elif action=='create_clone':
 clone_type=payload.get('clone_type','standard')
 child_id=payload.get('child_id') or ''
 if clone_type not in ('standard','promotable'): raise SystemExit('Choose a supported standard or promotable clone type.')
 if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',child_id): raise SystemExit('Choose a valid standalone primitive resource for the clone.')
 tree=resource_tree()
 if any(item.get('id')==resource_id for item in tree.iter()): raise SystemExit('A Pacemaker object with this clone ID already exists.')
 primitive=next((item for item in tree.iter('primitive') if item.get('id')==child_id),None)
 group=next((item for item in tree.iter('group') if item.get('id')==child_id),None)
 if primitive is None and group is None: raise SystemExit('The selected clone child is not a primitive or resource group in this cluster.')
 active=all_active_ids()
 if primitive is not None:
  if primitive.get('class')=='stonith': raise SystemExit('Fencing devices cannot be cloned by this workload workflow.')
  if any(parent.tag in ('group','clone','master','bundle') and any(child is primitive for child in list(parent)) for parent in tree.iter()):
   raise SystemExit('The selected resource already belongs to a group or clone.')
 else:
  group=direct_group(child_id)
  if group is None: raise SystemExit('The selected group is not a top-level resource group.')
  group_children=[item for item in list(group) if item.tag=='primitive']
  if not group_children: raise SystemExit('The selected group has no primitive members to clone.')
  if any(item.get('class')=='stonith' for item in group_children): raise SystemExit('Fencing devices cannot be cloned by this workload workflow.')
  ensure_group_stopped(group,active)
 if child_id in active: raise SystemExit('Stop the selected resource before placing it in a clone.')
 if clone_type=='promotable':
  if primitive is None: raise SystemExit('Promotable clones in this workflow require one primitive child. Use a standard clone for a resource group.')
  operations=primitive.find('operations')
  monitors=[item for item in list(operations) if item.tag=='op' and item.get('name')=='monitor'] if operations is not None else []
  role_pairs=(('promoted','unpromoted'),('master','slave'))
  def monitor_role(op):
   return (op.get('role') or '').strip().lower()
  matched=next((pair for pair in role_pairs if all(any(monitor_role(op)==role for op in monitors) for role in pair)),None)
  if not matched: raise SystemExit('A promotable clone needs separate monitor operations for Promoted and Unpromoted roles (or legacy Master and Slave roles). Add and validate those operations before creating the clone.')
  intervals={role:normalized_seconds(next((op.get('interval','') for op in monitors if monitor_role(op)==role),''),allow_zero=True) for role in matched}
  if intervals[matched[0]]==intervals[matched[1]]:
   raise SystemExit('Promoted and Unpromoted monitor operations must have different, explicit intervals.')
  agent=':'.join(part for part in (primitive.get('class'),primitive.get('provider'),primitive.get('type')) if part)
  info=subprocess.run(['crm','ra','info',agent],capture_output=True,text=True,timeout=20)
  if info.returncode: raise SystemExit((info.stderr or info.stdout or 'Could not verify promote/demote support for this resource agent.').strip()[:400])
  advertised_actions=set()
  try:
   metadata=ET.fromstring(info.stdout or '')
   advertised_actions.update((item.get('name') or '').lower() for item in metadata.iter() if item.tag.lower() in ('action','operation'))
  except ET.ParseError:
   pass
  for line in (info.stdout or '').splitlines():
   if re.match(r'^\s*(?:actions?|operations?)\s*:',line,re.I) or re.match(r'^\s*(?:start|stop|monitor|promote|demote|notify)\b',line,re.I):
    advertised_actions.update(re.findall(r'\b(?:start|stop|monitor|promote|demote|notify)\b',line.lower()))
  if 'promote' not in advertised_actions or 'demote' not in advertised_actions:
   raise SystemExit('The installed resource-agent metadata does not advertise both promote and demote actions; use a standard clone or select an agent that supports promotable roles.')
 command=f'clone {resource_id} {child_id} meta '+('promotable=true ' if clone_type=='promotable' else '')+'target-role=Stopped'
 apply_config([command])
 print(('Promotable' if clone_type=='promotable' else 'Standard')+' clone created in Stopped state. Review the clone role operations and placement policy, then start it when the service is ready on the cluster nodes.')
elif action=='edit_clone':
 cib=ET.fromstring(run(['cibadmin','-Q']))
 configuration=cib.find('configuration'); resources=configuration.find('resources') if configuration is not None else None
 if resources is None: raise SystemExit('The current CIB has no resources section; refresh cluster status and retry.')
 clone=next((item for item in resources.findall('clone') if item.get('id')==resource_id),None)
 if clone is None: raise SystemExit('Select a current top-level clone to edit.')
 original_clone_xml=ET.tostring(clone,encoding='unicode')
 if any(parent.tag in ('group','clone','master','bundle') and any(child is clone for child in list(parent)) for parent in resources.iter()):
  raise SystemExit('Nested clones are not editable from this workflow; use Hawk or crmsh for this object.')
 members=[item for item in list(clone) if item.tag in ('primitive','group')]
 if len(members)!=1: raise SystemExit('This clone does not contain exactly one supported resource; edit it with Hawk or crmsh.')
 meta=clone.find('meta_attributes')
 promotable=bool(meta is not None and any(item.get('name')=='promotable' and item.get('value','').lower()=='true' for item in meta.iter('nvpair')))
 if payload.get('clone_type')!=('promotable' if promotable else 'standard'):
  raise SystemExit('The clone type changed while this form was open; refresh status and retry.')
 allowed={'clone-max','clone-node-max','globally-unique','notify','interleave'}
 if promotable: allowed.update(('promoted-max','promoted-node-max'))
 active=all_active_ids(); failed=all_failed_ids()
 descendants={item.get('id') for item in clone.iter() if item.tag in ('clone','group','primitive') and item.get('id')}
 if descendants.intersection(active): raise SystemExit('Stop every instance of this clone before editing its options.')
 if descendants.intersection(failed): raise SystemExit('Clean up failed clone or child-resource state before editing clone options.')
 expected=payload.get('expected_clone_metadata') or {}
 desired=payload.get('clone_metadata') or {}
 if not isinstance(expected,dict) or not isinstance(desired,dict) or set(desired)!=allowed or not set(expected).issubset(allowed):
  raise SystemExit('The clone option form is incomplete or contains unsupported options; refresh cluster status and retry.')
 current={}; duplicate=False
 if meta is not None:
  for nv in meta.iter('nvpair'):
   key=nv.get('name','')
   if key not in allowed: continue
   if key in current: duplicate=True
   current[key]=nv.get('value','')
 if duplicate: raise SystemExit('This clone has duplicate supported options; edit it with Hawk or crmsh and refresh status.')
 if current!={key:value for key,value in expected.items() if key in allowed}:
  raise SystemExit('The clone options changed while this form was open; refresh status and review the changes again.')
 normalized={}
 numeric={'clone-max','clone-node-max','promoted-max','promoted-node-max'}
 boolean={'globally-unique','notify','interleave'}
 for key,value in desired.items():
  if key not in allowed or not isinstance(value,str) or len(value)>16: raise SystemExit('A clone option is invalid.')
  value=value.strip()
  if not value: continue
  if key in numeric:
   if not re.fullmatch(r'[1-9][0-9]{0,3}',value) or int(value)>4096: raise SystemExit('Clone instance limits must be whole numbers from 1 to 4096.')
  elif key in boolean:
   if value.lower() not in ('true','false'): raise SystemExit('Clone boolean options must be true or false.')
   value=value.lower()
  else: raise SystemExit('Unsupported clone option.')
  normalized[key]=value
 if normalized==current:
  print('Clone options are unchanged.')
 else:
  if meta is None:
   meta=ET.SubElement(clone,'meta_attributes',{'id':resource_id+'-meta-'+uuid.uuid4().hex[:12]})
  known={nv.get('name'):nv for nv in meta.iter('nvpair') if nv.get('name') in allowed}
  for key in allowed:
   value=normalized.get(key)
   if key in known:
    if value is None:
     for parent in list(meta.iter()):
      for child in list(parent):
       if child is known[key]: parent.remove(child)
    else: known[key].set('value',value)
   elif value is not None:
    ET.SubElement(meta,'nvpair',{'id':resource_id+'-'+key+'-'+uuid.uuid4().hex[:12],'name':key,'value':value})
  if len(meta)==0: clone.remove(meta)
  latest_cib=ET.fromstring(run(['cibadmin','-Q']))
  latest_configuration=latest_cib.find('configuration'); latest_resources=latest_configuration.find('resources') if latest_configuration is not None else None
  latest_clone=next((item for item in latest_resources.findall('clone') if item.get('id')==resource_id),None) if latest_resources is not None else None
  if latest_clone is None or ET.tostring(latest_clone,encoding='unicode')!=original_clone_xml:
   raise SystemExit('The clone configuration changed while this form was open; refresh status and review the changes again.')
  update=ET.Element('cib',dict(latest_cib.attrib)); update_configuration=ET.SubElement(update,'configuration',dict(latest_configuration.attrib)); update_resources=ET.SubElement(update_configuration,'resources',dict(latest_resources.attrib))
  update_resources.append(ET.fromstring(ET.tostring(clone,encoding='unicode')))
  fd,path=tempfile.mkstemp(prefix='rancher-kvm-clone-edit-',suffix='.xml')
  try:
   with os.fdopen(fd,'w',encoding='utf-8') as handle: handle.write(ET.tostring(update,encoding='unicode'))
   try: run(['crm','configure','load','xml','update',path],timeout=60)
   except SystemExit: raise SystemExit('SUSE crmsh rejected the clone-option update; the existing clone and child resource remain unchanged.')
  finally:
   try: os.unlink(path)
   except OSError: pass
  print('Stopped clone options updated. Review the instance limits and placement behavior before starting the clone.')
elif action=='delete_clone':
 cib=ET.fromstring(run(['cibadmin','-Q']))
 configuration=cib.find('configuration'); resources=configuration.find('resources') if configuration is not None else None
 constraints=configuration.find('constraints') if configuration is not None else None
 if resources is None: raise SystemExit('The current CIB has no resources section; refresh cluster status and retry.')
 clone=next((item for item in resources.findall('clone') if item.get('id')==resource_id),None)
 if clone is None: raise SystemExit('Select a current top-level Pacemaker clone to delete; nested clones are not supported by this workflow.')
 original_clone_xml=ET.tostring(clone,encoding='unicode')
 members=[item for item in list(clone) if item.tag in ('primitive','group','clone','master','bundle')]
 if len(members)!=1 or members[0].tag!='primitive': raise SystemExit('This workflow only deletes clones containing exactly one primitive. Clones of groups or nested resources must be reviewed with Hawk or crmsh.')
 primitive=members[0]; child_id=primitive.get('id','')
 if not child_id or payload.get('child_id')!=child_id: raise SystemExit('The clone child changed while this form was open; refresh cluster status and review the deletion again.')
 if primitive.get('class')=='stonith': raise SystemExit('STONITH fencing resources cannot be removed through the clone workflow.')
 affected={resource_id,child_id}
 active=all_active_ids(); failed=all_failed_ids()
 if affected.intersection(active): raise SystemExit('Stop every instance of this clone before deleting it.')
 if affected.intersection(failed): raise SystemExit('Clean up failed clone or child-resource state before deleting it.')
 def has_related_constraint(section):
  if section is None: return False
  # Check all attribute values rather than only the common rsc/with-rsc/first/then
  # forms. This also catches resource_set references and newer crmsh constraint
  # attributes without attempting to rewrite or silently delete any constraint.
  return any(value in affected for item in section.iter() for value in item.attrib.values())
 if has_related_constraint(constraints): raise SystemExit('This clone or its child is referenced by a Pacemaker constraint. Review and remove those constraints before deleting the clone.')
 latest_cib=ET.fromstring(run(['cibadmin','-Q']))
 latest_configuration=latest_cib.find('configuration'); latest_resources=latest_configuration.find('resources') if latest_configuration is not None else None
 latest_constraints=latest_configuration.find('constraints') if latest_configuration is not None else None
 latest_clone=next((item for item in latest_resources.findall('clone') if item.get('id')==resource_id),None) if latest_resources is not None else None
 if latest_clone is None or ET.tostring(latest_clone,encoding='unicode')!=original_clone_xml or has_related_constraint(latest_constraints):
  raise SystemExit('The clone or its related constraints changed while this form was open; refresh status and review the deletion again.')
 run(['crm','configure','delete',resource_id],timeout=60)
 print('Stopped Pacemaker clone and its child primitive removed from the cluster configuration.')
elif action=='create_group':
 children=payload.get('children') or []
 if not isinstance(children,list) or len(children)<1 or len(children)>128 or len(set(children))!=len(children): raise SystemExit('Select between one and 128 different primitive resources for the group.')
 tree=resource_tree()
 if any(item.get('id')==resource_id for item in tree.iter()): raise SystemExit('A Pacemaker object with this group ID already exists.')
 active=all_active_ids()
 for child_id in children:
  validate_group_child(child_id,tree)
  if child_id in active: raise SystemExit('Stop every selected resource before grouping them; active resources are never moved automatically.')
 apply_config([f'group {resource_id} '+' '.join(children)+' meta target-role="Stopped"'])
 print('Resource group created in Stopped state. Members start in the reviewed order and stop in reverse order; start it after validating every service on every node.')
elif action in ('add_group_member','remove_group_member','reorder_group','delete_group'):
 group=direct_group(resource_id)
 if group is None: raise SystemExit('Resource group not found in the current Pacemaker configuration.')
 active=all_active_ids(); members=ensure_group_stopped(group,active)
 if action=='delete_group':
  run(['crm','configure','delete',resource_id],timeout=60)
  print('Resource group and its member primitives were removed from the Pacemaker configuration.')
 elif action=='reorder_group':
  desired=payload.get('children') or []
  if not isinstance(desired,list) or len(desired)!=len(members) or len(set(desired))!=len(desired) or set(desired)!=set(members):
   raise SystemExit('The new order must contain every current group primitive exactly once.')
  for child_id in desired:
   if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',child_id): raise SystemExit('Choose valid primitive IDs for the group order.')
  if desired==members:
   print('The resource group already uses this start order.')
  else:
   by_id={item.get('id'):item for item in list(group) if item.tag=='primitive' and item.get('id')}
   other_children=[item for item in list(group) if item.tag!='primitive']
   for item in list(group): group.remove(item)
   for child_id in desired: group.append(by_id[child_id])
   for item in other_children: group.append(item)
   apply_xml_config(resource_id,members,desired)
   print('Stopped resource-group start order updated. Refresh cluster status to review the new order.')
 else:
  child_id=payload.get('child_id') or ''
  if action=='add_group_member':
   validate_group_child(child_id,resource_tree())
   if child_id in active: raise SystemExit('Stop the selected primitive before adding it to a group.')
   command=f'modgroup {resource_id} add {child_id}'
  else:
   if child_id not in members: raise SystemExit('The selected primitive is not a member of this group.')
   if len(members)<=1: raise SystemExit('A resource group must retain at least one primitive. Delete the group to remove the group and its members.')
   command=f'modgroup {resource_id} remove {child_id}'
  run(['crm','configure',*command.split()],60)
  print('Stopped resource-group membership updated. Refresh cluster status to review the new order.')
elif action=='set_monitor_ops':
 item=check_primitive()
 if item.get('class')=='stonith': raise SystemExit('Fencing-resource monitor operations must be managed in the dedicated fencing workflow.')
 apply_primitive_xml_config(item)
 print('Monitor operations updated. Review the resource-agent guidance before starting this resource.')
elif action in ('set_param','delete_param','set_meta','delete_meta'):
 check_primitive()
 key=payload.get('key') or ''
 if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,63}',key): raise SystemExit('Invalid parameter or meta attribute name.')
 group='param' if action.endswith('param') else 'meta'
 if action.startswith('delete_'): run(['crm','resource',group,resource_id,'delete',key])
 else:
  value=payload.get('value')
  if value is None: raise SystemExit('Provide a value for this attribute.')
  run(['crm','resource',group,resource_id,'set',key,value])
 print('Resource configuration updated.')
elif action=='delete':
 item=check_primitive()
 status=ET.fromstring(run(['crm_mon','--one-shot','--output-as=xml'],timeout=25))
 state=next((entry for entry in status.findall('.//resources//resource') if entry.get('id')==resource_id),None)
 if state is None: raise SystemExit('Pacemaker did not return a current state for this resource. Refresh cluster status and verify that it is stopped before deleting it.')
 if state is not None and state.get('failed','false').lower() in ('true','1','yes'): raise SystemExit('The resource is failed. Clean up its failed state before deleting it.')
 if state is not None and state.get('active','false').lower() in ('true','1','yes'): raise SystemExit('Stop the resource first, then retry deletion.')
 run(['crm','configure','delete',resource_id],timeout=60)
 print('Resource removed from the Pacemaker configuration.')
elif action=='delete_stonith':
 item=resource_element()
 if item is None or item.tag!='primitive' or item.get('class')!='stonith': raise SystemExit('Select a current standalone STONITH primitive to remove.')
 tree=resource_tree()
 primitive=next((entry for entry in tree.findall('primitive') if entry.get('id')==resource_id and entry.get('class')=='stonith'),None)
 if primitive is None: raise SystemExit('This fencing resource is nested or has changed; refresh status and retry.')
 state=ET.fromstring(run(['crm_mon','--one-shot','--output-as=xml'],timeout=25))
 current=next((entry for entry in state.findall('.//resources//resource') if entry.get('id')==resource_id),None)
 if current is None: raise SystemExit('Pacemaker did not report the current fencing-resource state. Refresh cluster status before removal.')
 if current.get('active','false').lower() in ('true','1','yes'): raise SystemExit('Stop this fencing resource before removing it. Confirm another working fencing path remains for the cluster.')
 if current.get('failed','false').lower() in ('true','1','yes'): raise SystemExit('Clean up the failed fencing-resource state before removing its configuration.')
 run(['crm','configure','delete',resource_id],timeout=60)
 print('Stopped fencing resource removed. Verify another supported fencing device remains configured for every cluster node.')
else: raise SystemExit('Unsupported resource operation')
'''


HA_CONSTRAINT_MUTATION_SCRIPT = r'''import json,re,subprocess,sys,xml.etree.ElementTree as ET
payload=json.loads(sys.stdin.read())
action=payload['action']; constraint_id=payload['constraint_id']
identifier=re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}')
if not identifier.fullmatch(constraint_id): raise SystemExit('Constraint IDs must start with a letter or number and contain only letters, numbers, dots, underscores, or hyphens.')
def run(args,timeout=30):
 result=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
 if result.returncode: raise SystemExit((result.stderr or result.stdout or 'crmsh operation failed').strip()[:500])
 return result.stdout
def resources():
 root=ET.fromstring(run(['cibadmin','-Q','-o','resources']))
 return {item.get('id') for item in root.iter() if item.get('id')}
def constraints():
 root=ET.fromstring(run(['cibadmin','-Q','-o','constraints']))
 return {item.get('id') for item in root.iter() if item.get('id')}
if action=='delete':
 if constraint_id not in constraints(): raise SystemExit('Constraint not found in the Pacemaker configuration.')
 run(['crm','configure','delete',constraint_id],60)
 print('Constraint removed from the Pacemaker configuration.')
 raise SystemExit(0)
known=resources(); resource=payload.get('resource') or ''
if not identifier.fullmatch(resource) or resource not in known: raise SystemExit('Choose a resource that exists in the current Pacemaker configuration.')
if constraint_id in constraints(): raise SystemExit('A constraint with this ID already exists.')
if action=='create_location':
 node=payload.get('node') or ''; score=payload.get('score') or ''
 if not identifier.fullmatch(node): raise SystemExit('Choose a valid cluster node name.')
 if score not in ('INFINITY','-INFINITY') and not re.fullmatch(r'-?\d{1,9}',score): raise SystemExit('Location score must be an integer or INFINITY / -INFINITY.')
 score={'INFINITY':'inf','-INFINITY':'-inf'}.get(score,score)
 nodes=ET.fromstring(run(['crm_mon','--one-shot','--output-as=xml'],25))
 known_nodes={item.get('name') for item in nodes.findall('.//nodes/node') if item.get('name')}
 if node not in known_nodes: raise SystemExit('The selected node is not currently reported by this cluster.')
 run(['crm','configure','location',constraint_id,resource,score+':',node],60)
elif action=='create_order':
 other=payload.get('other_resource') or ''; kind=payload.get('order_kind') or 'Mandatory'
 if not identifier.fullmatch(other) or other not in known: raise SystemExit('Choose a second resource that exists in the current Pacemaker configuration.')
 if resource==other: raise SystemExit('An order constraint must reference two different resources.')
 if kind not in ('Mandatory','Optional','Serialize'): raise SystemExit('Unsupported order constraint kind.')
 run(['crm','configure','order',constraint_id,kind+':',resource,other],60)
elif action=='create_colocation':
 other=payload.get('other_resource') or ''; score=payload.get('score') or ''
 if not identifier.fullmatch(other) or other not in known: raise SystemExit('Choose a second resource that exists in the current Pacemaker configuration.')
 if resource==other: raise SystemExit('A colocation constraint must reference two different resources.')
 if score not in ('INFINITY','-INFINITY') and not re.fullmatch(r'-?\d{1,9}',score): raise SystemExit('Colocation score must be an integer or INFINITY / -INFINITY.')
 score={'INFINITY':'inf','-INFINITY':'-inf'}.get(score,score)
 run(['crm','configure','colocation',constraint_id,score+':',resource,other],60)
else: raise SystemExit('Unsupported constraint operation.')
print('Constraint created in the live Pacemaker configuration.')
'''


HA_INSTALL_STACK_SCRIPT = r'''import json,os,re,shutil,subprocess
if not shutil.which('SUSEConnect'): raise SystemExit('SUSEConnect is unavailable; verify the SLES registration first.')
result=subprocess.run(['SUSEConnect','--list-extensions'],capture_output=True,text=True,timeout=30)
if result.returncode: raise SystemExit('Could not verify SLE HA registration: '+(result.stderr or result.stdout).strip()[:300])
text=re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]','',result.stdout)
active=False; label=''
for line in text.splitlines():
 item=line.strip(); match=re.search(r'\bSUSEConnect\s+(.*)$',item,re.I)
 if match:
  product=re.search(r'(?:^|\s)-p\s+(\S+)',match.group(1))
  if product and product.group(1).startswith('sle-ha/') and (re.search(r'(?:^|\s)-d(?:\s|$)',match.group(1)) or re.search(r'\(Activated\)',label,re.I)):
   active=True; break
  label=''
 elif item and not re.match(r'^(Activate|Deactivate) with:',item,re.I) and not item.startswith('('): label=item
if not active: raise SystemExit('The SLE HA extension is not active on this host. Activate it before installing the HA pattern.')
if not shutil.which('zypper'): raise SystemExit('zypper is unavailable on this host.')
result=subprocess.run(['zypper','--non-interactive','install','-t','pattern','ha_sles'],capture_output=True,text=True,timeout=900)
if result.returncode: raise SystemExit((result.stderr or result.stdout or 'zypper could not install the ha_sles pattern').strip()[-800:])
units=('pacemaker','corosync','hawk','hawk-backend')
services={}
for name in units:
 active=subprocess.run(['systemctl','is-active',name],capture_output=True,text=True,timeout=8)
 enabled=subprocess.run(['systemctl','is-enabled',name],capture_output=True,text=True,timeout=8)
 services[name]={'active':(active.stdout or active.stderr).strip() or 'unknown','enabled':(enabled.stdout or enabled.stderr).strip() or 'unknown'}
cluster_configured=os.path.isfile('/etc/corosync/corosync.conf')
print(json.dumps({'services':services,'cluster_configured':cluster_configured,
 'message':('SLE HA packages installed. Cluster services are managed by the supported crm cluster init workflow.' if not cluster_configured else 'SLE HA packages installed. Existing cluster service state was left unchanged.'),
 'package_output':(result.stdout or 'The ha_sles pattern was installed.').strip()[-500:]}))
'''


QNETD_PACKAGE_INSTALL_SCRIPT = r'''import json,shutil,subprocess
if not shutil.which('rpm'): raise SystemExit('rpm is unavailable on this SLES host')
installed=subprocess.run(['rpm','-q','corosync-qnetd'],capture_output=True,text=True,timeout=10).returncode==0
if installed:
 print(json.dumps({'status':'already_installed','package':'corosync-qnetd','message':'The SUSE corosync-qnetd package is already installed. The service is started by the SUSE QDevice configuration workflow.'}))
 raise SystemExit(0)
if not shutil.which('zypper'): raise SystemExit('zypper is unavailable on this SLES host')
result=subprocess.run(['zypper','--non-interactive','install','--no-recommends','corosync-qnetd'],capture_output=True,text=True,timeout=900)
if result.returncode: raise SystemExit((result.stderr or result.stdout or 'zypper could not install corosync-qnetd').strip()[-800:])
verify=subprocess.run(['rpm','-q','corosync-qnetd'],capture_output=True,text=True,timeout=10)
if verify.returncode: raise SystemExit('zypper finished but rpm does not report corosync-qnetd as installed')
print(json.dumps({'status':'installed','package':'corosync-qnetd','message':'SUSE corosync-qnetd is installed. Its service will be started by crm cluster init qdevice; it was not started or enabled separately.'}))
'''


# A standalone witness is not a KVM host. Keep its connection and package
# preparation checks focused on the facts required by SUSE's QNetd workflow;
# the generic HA preflight also inspects Pacemaker, watchdogs and libvirt.
QNETD_WITNESS_PREFLIGHT_SCRIPT = r'''import ipaddress,json,platform,re,shutil,subprocess,sys
request=json.loads(sys.argv[1]) if len(sys.argv)>1 else {}
def run(args,timeout=12):
    try:
        result=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
        return result.returncode,(result.stdout or result.stderr).strip()
    except Exception as error:
        return 127,str(error)
release={}
try:
    with open('/etc/os-release',encoding='utf-8') as handle:
        for line in handle:
            if '=' in line:
                key,value=line.rstrip().split('=',1); release[key]=value.strip().strip('"')
except OSError: pass
ha_active=False; ha_product=''
ha_code,ha_output=run(['SUSEConnect','--list-extensions'],30) if shutil.which('SUSEConnect') else (127,'SUSEConnect is unavailable')
if ha_code==0:
    ha_output=re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]','',ha_output)
    label=''
    for line in ha_output.splitlines():
        item=line.strip(); match=re.search(r'\bSUSEConnect\s+(.*)$',item,re.I)
        if match:
            command=match.group(1); product=re.search(r'(?:^|\s)-p\s+(\S+)',command)
            if product and product.group(1).startswith('sle-ha/'):
                active=bool(re.search(r'(?:^|\s)-d(?:\s|$)',command)) or bool(re.search(r'\(Activated\)',label,re.I))
                if active: ha_active=True; ha_product=product.group(1); break
            label=''
        elif item and not re.match(r'^(Activate|Deactivate) with:',item,re.I) and not item.startswith('('): label=item
supported_releases=__SLES_HA_SUPPORTED_RELEASES__
compatibility_supported=release.get('ID','').lower()=='sles' and release.get('VERSION_ID','') in supported_releases
ntp_code,ntp=run(['timedatectl','show','-p','NTPSynchronized','--value'])
time_synchronized=ntp_code==0 and ntp.strip().lower()=='yes'
registered_address=str(request.get('registered_address') or '').strip()
try: registered_address=ipaddress.ip_address(registered_address).compressed
except ValueError: registered_address=''
registered_address_is_dynamic=None
ip_code,ip_output=run(['ip','-j','address','show'])
if ip_code==0 and registered_address:
    try:
        visible=set(); dynamic=set()
        for interface in json.loads(ip_output):
            if interface.get('ifname')=='lo' or 'UP' not in interface.get('flags',[]): continue
            for address in interface.get('addr_info',[]):
                local=address.get('local','')
                if not local or address.get('scope')=='host' or {'tentative','deprecated','dadfailed'}.intersection(address.get('flags',[])): continue
                try: parsed=ipaddress.ip_address(str(local).split('%',1)[0])
                except ValueError: continue
                if parsed.is_loopback or parsed.is_link_local or parsed.is_multicast or parsed.is_unspecified: continue
                visible.add(parsed.compressed)
                if 'dynamic' in address.get('flags',[]) or address.get('dynamic') is True: dynamic.add(parsed.compressed)
        if registered_address in visible: registered_address_is_dynamic=registered_address in dynamic
    except Exception: pass
qnetd_package_installed=run(['rpm','-q','corosync-qnetd'])[0]==0 if request.get('check_qnetd_package') else None
print(json.dumps({'hostname':platform.node(),'os_id':release.get('ID',''),'os_name':release.get('PRETTY_NAME',''),
 'os_version':release.get('VERSION_ID',''),'compatibility_supported':compatibility_supported,
 'ha_active':ha_active,'ha_product':ha_product,'ha_check_error':ha_output[:300] if ha_code else '',
 'qnetd_package_installed':qnetd_package_installed,'time_synchronized':time_synchronized,
 'time_sync_state':ntp.strip() if ntp_code==0 else 'unknown',
 'registered_address_is_dynamic':registered_address_is_dynamic}))
'''


QDEVICE_PACKAGE_INSTALL_SCRIPT = r'''import json,shutil,subprocess
if not shutil.which('rpm'): raise SystemExit('rpm is unavailable on this SLES host')
installed=subprocess.run(['rpm','-q','corosync-qdevice'],capture_output=True,text=True,timeout=10).returncode==0
if installed:
 print(json.dumps({'status':'already_installed','package':'corosync-qdevice','message':'The SUSE corosync-qdevice package is already installed.'}))
 raise SystemExit(0)
if not shutil.which('zypper'): raise SystemExit('zypper is unavailable on this SLES host')
result=subprocess.run(['zypper','--non-interactive','install','--no-recommends','corosync-qdevice'],capture_output=True,text=True,timeout=900)
if result.returncode: raise SystemExit((result.stderr or result.stdout or 'zypper could not install corosync-qdevice').strip()[-800:])
verify=subprocess.run(['rpm','-q','corosync-qdevice'],capture_output=True,text=True,timeout=10)
if verify.returncode: raise SystemExit('zypper finished but rpm does not report corosync-qdevice as installed')
print(json.dumps({'status':'installed','package':'corosync-qdevice','message':'SUSE corosync-qdevice is installed. The service and quorum configuration were not changed.'}))
'''


TEMPLATE_TIME_SYNC_SCRIPT = r'''import pathlib,re,subprocess
loaded=subprocess.run(['systemctl','show','-p','LoadState','--value','chronyd.service'],capture_output=True,text=True,timeout=15)
if loaded.returncode or loaded.stdout.strip()!='loaded':
 refresh=subprocess.run(['zypper','--non-interactive','refresh'],capture_output=True,text=True,timeout=300)
 if refresh.returncode: raise SystemExit((refresh.stderr or refresh.stdout or 'Could not refresh SUSE repositories').strip()[-500:])
 install=subprocess.run(['zypper','--non-interactive','install','--no-recommends','chrony'],capture_output=True,text=True,timeout=600)
 if install.returncode: raise SystemExit((install.stderr or install.stdout or 'Could not install the SUSE chrony package').strip()[-600:])
config_files=[pathlib.Path('/etc/chrony.conf'),*pathlib.Path('/etc/chrony.d').glob('*.conf')]
sources=[]
for path in config_files:
 if path.is_file():
  sources.extend(line.strip() for line in path.read_text(errors='replace').splitlines() if re.match(r'^\s*(server|pool|peer)\s+\S+',line) and not line.lstrip().startswith('#'))
if not sources: raise SystemExit('The chrony package is ready, but no NTP server or pool is configured. Add a trusted source in /etc/chrony.conf or /etc/chrony.d before synchronization can start.')
result=subprocess.run(['systemctl','enable','--now','chronyd.service'],capture_output=True,text=True,timeout=45)
if result.returncode: raise SystemExit((result.stderr or result.stdout or 'Could not enable chronyd.service').strip()[-500:])
print('chronyd is enabled and running. Synchronization status will update after it contacts a configured source.')
'''


TEMPLATE_WORKLOAD_PACKAGE_SCRIPT = r'''import subprocess,sys
kind=sys.argv[1]
packages={'web':('apache2',('apache2.service',)),'nfs':('nfs-kernel-server',('nfsserver.service','nfs-server.service'))}
if kind not in packages: raise SystemExit('Unsupported SUSE workload package')
package,units=packages[kind]
def run(args,timeout=900):
 result=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
 if result.returncode: raise SystemExit((result.stderr or result.stdout or 'zypper operation failed').strip()[-700:])
 return result
returncode=subprocess.run(['rpm','-q',package],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode
if returncode: run(['zypper','--non-interactive','refresh'],300); run(['zypper','--non-interactive','install','--no-recommends',package])
unit=next((name for name in units if subprocess.run(['systemctl','show','-p','LoadState','--value',name],capture_output=True,text=True,timeout=15).stdout.strip()=='loaded'),None)
if not unit: raise SystemExit(f'{package} installed, but no expected service unit was found ({", ".join(units)}). Check the enabled SUSE repositories and package contents.')
print(f'{package} is installed and {unit} is available. The service was not enabled or started; configure its lifecycle through the reviewed SUSE Pacemaker resource.')
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


@app.post("/kvm-api/clusters/plans/{plan_id}/qnetd/prepare")
def prepare_cluster_qnetd(plan_id: str, payload: ClusterQnetdPrepareInput,
                          access: AuthorizationContext = Depends(require_permission("cluster_admin"))) -> dict[str, Any]:
    """Install only SUSE's QNetd package on a registered, external witness host."""
    plan, witness = cluster_qnetd_prepare_context(plan_id, payload.host_id, access)

    def prepare(host: dict[str, Any]) -> dict[str, Any]:
        host_id = host["id"]
        try:
            with cluster_host_mutation_guard([host_id]):
                _current_plan, current_host = cluster_qnetd_prepare_context(plan_id, host_id, access)
                current_host["password"] = cipher.decrypt(current_host["password"].encode()).decode()
                decrypt_host_credentials(current_host)
                preflight_request = {"check_qnetd_package": True, "registered_address": current_host["address"]}
                checks = json.loads(run_sudo_python(
                    current_host, HA_PREFLIGHT_SCRIPT, args=[json.dumps(preflight_request)], timeout=90,
                ) or "{}")
                if not checks.get("compatibility_supported"):
                    result = {"status": "error", "error_code": "qnetd_host_unsupported"}
                elif not checks.get("ha_active"):
                    result = {"status": "error", "error_code": "qnetd_host_ha_inactive"}
                elif not checks.get("time_synchronized"):
                    result = {"status": "error", "error_code": "qnetd_host_time_sync"}
                elif checks.get("registered_address_is_dynamic") is not False:
                    result = {"status": "error", "error_code": "qnetd_host_address_unstable"}
                else:
                    installed = json.loads(run_sudo_python(
                        current_host, QNETD_PACKAGE_INSTALL_SCRIPT, timeout=930,
                    ) or "{}")
                    result = {
                        "status": installed.get("status") if installed.get("status") in ("installed", "already_installed") else "error",
                        "message": installed.get("message", ""),
                        "error_code": "qnetd_prepare_failed" if installed.get("status") not in ("installed", "already_installed") else "",
                    }
                if result["status"] in ("installed", "already_installed"):
                    record_audit(access.user_id, "cluster.qnetd.prepare", host_id, "success", "SUSE corosync-qnetd package verified; service lifecycle left to crmsh")
                else:
                    record_audit(access.user_id, "cluster.qnetd.prepare", host_id, "failure", result.get("error_code", "qnetd_prepare_failed"))
                return result
        except Exception:
            record_audit(access.user_id, "cluster.qnetd.prepare", host_id, "failure", "QNetd prerequisite preparation failed; diagnostic output omitted")
            return {"status": "error", "error_code": "qnetd_prepare_failed"}

    return create_operation_job("cluster_qnetd_prepare", access.user_id, [witness], prepare)


@app.get("/kvm-api/qnetd-witnesses")
def list_qnetd_witnesses(access: AuthorizationContext = Depends(require_permission("viewer"))) -> list[dict[str, Any]]:
    with connect_db() as db:
        rows = db.execute("SELECT * FROM qnetd_witnesses ORDER BY name COLLATE NOCASE").fetchall()
    return [public_qnetd_witness(row) for row in rows]


@app.post("/kvm-api/qnetd-witnesses/probe")
def probe_qnetd_witness_route(payload: QnetdWitnessVerifyInput,
                              access: AuthorizationContext = Depends(require_permission("cluster_admin"))) -> dict[str, Any]:
    if not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{20,44}", payload.expected_fingerprint):
        raise HTTPException(422, "Fetch and confirm the SSH fingerprint before sending witness credentials")
    try:
        identity, facts = inspect_qnetd_witness(payload, expected_fingerprint=payload.expected_fingerprint)
    except HTTPException:
        raise
    except paramiko.AuthenticationException:
        return {"ok": False, "error_code": "qnetd_ssh_auth_failed"}
    except (paramiko.BadHostKeyException, paramiko.SSHException, OSError, socket.timeout):
        return {"ok": False, "error_code": "qnetd_ssh_unreachable"}
    except RuntimeError as exc:
        message = str(exc).lower()
        return {"ok": False, "error_code": "qnetd_sudo_required" if "sudo" in message else "qnetd_probe_failed"}
    except Exception:
        return {"ok": False, "error_code": "qnetd_probe_failed"}
    return {"ok": bool(facts["compatibility_supported"]), "fingerprint": identity["fingerprint"], "facts": facts,
            "error_code": "qnetd_host_unsupported" if not facts["compatibility_supported"] else ""}


@app.post("/kvm-api/qnetd-witnesses/fingerprint")
def get_qnetd_witness_fingerprint(payload: QnetdWitnessFingerprintInput,
                                  access: AuthorizationContext = Depends(require_permission("cluster_admin"))) -> dict[str, Any]:
    """Read the SSH server identity before any witness credential is sent."""
    try:
        identity = probe_qnetd_witness_fingerprint(payload)
        return {"ok": True, "fingerprint": identity["fingerprint"]}
    except (paramiko.SSHException, OSError, socket.timeout):
        return {"ok": False, "error_code": "qnetd_ssh_unreachable"}
    except HTTPException:
        raise
    except Exception:
        return {"ok": False, "error_code": "qnetd_probe_failed"}


@app.post("/kvm-api/qnetd-witnesses", status_code=201)
def register_qnetd_witness(payload: QnetdWitnessCreateInput,
                           access: AuthorizationContext = Depends(require_permission("cluster_admin"))) -> dict[str, Any]:
    if not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{20,44}", payload.expected_fingerprint):
        raise HTTPException(422, "Verify the witness SSH fingerprint and confirm it before registering")
    try:
        identity, facts = inspect_qnetd_witness(payload, expected_fingerprint=payload.expected_fingerprint)
    except HTTPException:
        raise
    except paramiko.AuthenticationException as exc:
        raise HTTPException(422, "SSH authentication failed for the QNetd witness") from exc
    except (paramiko.BadHostKeyException, paramiko.SSHException, OSError, socket.timeout) as exc:
        raise HTTPException(502, "Could not connect to the QNetd witness over SSH") from exc
    except RuntimeError as exc:
        raise HTTPException(422, "Could not inspect the witness. Check SSH and passwordless or password-based sudo access.") from exc
    except Exception as exc:
        raise HTTPException(422, "Could not inspect the QNetd witness prerequisites") from exc
    if identity["fingerprint"] != payload.expected_fingerprint:
        raise HTTPException(409, "The witness SSH fingerprint changed after verification. Probe it again and review the new fingerprint.")
    if not facts["compatibility_supported"]:
        raise HTTPException(422, "The witness must run a supported SUSE Linux Enterprise release")
    endpoint = normalize_cluster_endpoint(payload.address)
    with connect_db() as db:
        existing_host = db.execute("SELECT id FROM hosts WHERE lower(address)=lower(?) AND port=?", (payload.address, payload.port)).fetchone()
        existing_witness = db.execute("SELECT id FROM qnetd_witnesses WHERE lower(address)=lower(?) AND port=?", (payload.address, payload.port)).fetchone()
        if existing_host or existing_witness:
            raise HTTPException(409, "This endpoint is already registered. Use the existing host or witness record.")
        node_match = db.execute("SELECT id FROM hosts WHERE lower(address)=lower(?)", (endpoint,)).fetchone()
        if node_match:
            raise HTTPException(422, "The QNetd witness must be separate from registered cluster nodes")
        witness_id = str(uuid.uuid4())
        timestamp = now()
        db.execute(
            "INSERT INTO qnetd_witnesses (id,name,address,port,username,password,hostname,status,os_id,os_version,ha_product,ha_active,qnetd_package_installed,time_synchronized,registered_address_is_dynamic,ssh_host_key,created_by,created_at,updated_at,last_checked_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (witness_id, payload.name.strip(), payload.address.strip(), payload.port, payload.username.strip(),
             cipher.encrypt(payload.password.encode()).decode(), facts["hostname"], "ready", facts["os_id"], facts["os_version"],
             facts["ha_product"], int(facts["ha_active"]), int(facts["qnetd_package_installed"]),
             int(facts["time_synchronized"]), facts["registered_address_is_dynamic"], identity["ssh_host_key"],
             access.user_id, timestamp, timestamp, facts["checked_at"]),
        )
        created = dict(db.execute("SELECT * FROM qnetd_witnesses WHERE id=?", (witness_id,)).fetchone())
    record_audit(access.user_id, "cluster.qnetd.witness.register", witness_id,
                 detail=f"SLES witness registered: {payload.name.strip()} ({payload.address.strip()}:{payload.port})")
    return public_qnetd_witness(created)


@app.post("/kvm-api/qnetd-witnesses/{witness_id}/refresh")
def refresh_qnetd_witness(witness_id: str,
                          access: AuthorizationContext = Depends(require_permission("cluster_admin"))) -> dict[str, Any]:
    try:
        witness_id = str(uuid.UUID(witness_id))
    except ValueError as exc:
        raise HTTPException(404, "QNetd witness not found") from exc
    with connect_db() as db:
        row = db.execute("SELECT * FROM qnetd_witnesses WHERE id=?", (witness_id,)).fetchone()
    if not row:
        raise HTTPException(404, "QNetd witness not found")
    witness = dict(row)
    try:
        witness["password"] = cipher.decrypt(witness["password"].encode()).decode()
        payload = QnetdWitnessProbeInput(name=witness["name"], address=witness["address"],
            port=witness["port"], username=witness["username"], password=witness["password"])
        _identity, facts = inspect_qnetd_witness(payload, pinned_host_key=witness["ssh_host_key"])
    except (paramiko.BadHostKeyException, paramiko.SSHException, OSError, socket.timeout) as exc:
        record_audit(access.user_id, "cluster.qnetd.witness.refresh", witness_id, "failure", "Pinned SSH verification failed")
        raise HTTPException(502, "The witness SSH key or connection changed. Verify its identity before continuing.") from exc
    except Exception as exc:
        record_audit(access.user_id, "cluster.qnetd.witness.refresh", witness_id, "failure", "Read-only witness readiness check failed")
        raise HTTPException(502, "Could not refresh the witness readiness. Check SSH, sudo, SUSEConnect, and SLE HA.") from exc
    with connect_db() as db:
        db.execute("UPDATE qnetd_witnesses SET hostname=?,status=?,os_id=?,os_version=?,ha_product=?,ha_active=?,qnetd_package_installed=?,time_synchronized=?,registered_address_is_dynamic=?,last_checked_at=?,updated_at=? WHERE id=?",
            (facts["hostname"], "ready" if facts["compatibility_supported"] else "unsupported", facts["os_id"], facts["os_version"], facts["ha_product"], int(facts["ha_active"]),
             int(facts["qnetd_package_installed"]), int(facts["time_synchronized"]), facts["registered_address_is_dynamic"],
             facts["checked_at"], now(), witness_id))
        refreshed = dict(db.execute("SELECT * FROM qnetd_witnesses WHERE id=?", (witness_id,)).fetchone())
    record_audit(access.user_id, "cluster.qnetd.witness.refresh", witness_id, detail="Read-only SLES QNetd witness check")
    return public_qnetd_witness(refreshed)


@app.delete("/kvm-api/qnetd-witnesses/{witness_id}", status_code=204)
def delete_qnetd_witness(witness_id: str,
                         access: AuthorizationContext = Depends(require_permission("cluster_admin"))) -> Response:
    try:
        witness_id = str(uuid.UUID(witness_id))
    except ValueError as exc:
        raise HTTPException(404, "QNetd witness not found") from exc
    with cluster_host_mutation_guard([f"qnetd-witness:{witness_id}"]):
        with connect_db() as db:
            row = db.execute("SELECT id,name,address FROM qnetd_witnesses WHERE id=?", (witness_id,)).fetchone()
            if not row:
                raise HTTPException(404, "QNetd witness not found")
            db.execute("DELETE FROM qnetd_witnesses WHERE id=?", (witness_id,))
    record_audit(access.user_id, "cluster.qnetd.witness.delete", witness_id,
                 detail=f"SLES witness removed: {row['name']} ({row['address']})")
    return Response(status_code=204)


@app.post("/kvm-api/clusters/plans/{plan_id}/qnetd/prepare-witness")
def prepare_cluster_qnetd_witness(plan_id: str, payload: ClusterQnetdWitnessPrepareInput,
                                  access: AuthorizationContext = Depends(require_permission("cluster_admin"))) -> dict[str, Any]:
    """Prepare only corosync-qnetd on an SSH-only SLES witness, without KVM setup."""
    plan, witness = cluster_qnetd_witness_prepare_context(plan_id, payload.witness_id, access)

    def prepare(_queued: dict[str, Any]) -> dict[str, Any]:
        witness_id = witness["id"]
        try:
            with cluster_host_mutation_guard([f"qnetd-witness:{witness_id}"]):
                _current_plan, current = cluster_qnetd_witness_prepare_context(plan_id, witness_id, access)
                current["password"] = cipher.decrypt(current["password"].encode()).decode()
                checks = json.loads(run_sudo_python(current, QNETD_WITNESS_PREFLIGHT_SCRIPT,
                    args=[json.dumps({"check_qnetd_package": True, "registered_address": current["address"]})], timeout=75) or "{}")
                facts = (bool(checks.get("compatibility_supported")), bool(checks.get("ha_active")),
                         bool(checks.get("time_synchronized")), checks.get("registered_address_is_dynamic"),
                         bool(checks.get("qnetd_package_installed")))
                supported, ha_active, synchronized, dynamic, installed = facts
                with connect_db() as db:
                    db.execute("UPDATE qnetd_witnesses SET status=?,ha_active=?,qnetd_package_installed=?,time_synchronized=?,registered_address_is_dynamic=?,last_checked_at=?,updated_at=? WHERE id=?",
                               ("ready" if supported else "unsupported", int(ha_active), int(installed), int(synchronized), dynamic, now(), now(), witness_id))
                if not supported:
                    return {"status": "error", "error_code": "qnetd_host_unsupported"}
                if not ha_active:
                    return {"status": "error", "error_code": "qnetd_host_ha_inactive"}
                if not synchronized:
                    return {"status": "error", "error_code": "qnetd_host_time_sync"}
                if dynamic is not False:
                    return {"status": "error", "error_code": "qnetd_host_address_unstable"}
                result = json.loads(run_sudo_python(current, QNETD_PACKAGE_INSTALL_SCRIPT, timeout=930) or "{}")
                succeeded = result.get("status") in ("installed", "already_installed")
                with connect_db() as db:
                    db.execute("UPDATE qnetd_witnesses SET qnetd_package_installed=?,last_checked_at=?,updated_at=? WHERE id=?",
                               (int(succeeded), now(), now(), witness_id))
                record_audit(access.user_id, "cluster.qnetd.prepare", witness_id,
                             "success" if succeeded else "failure",
                             "SUSE corosync-qnetd package prepared; service lifecycle left to crmsh")
                return {"status": result.get("status") if succeeded else "error",
                        "message": result.get("message", ""),
                        "error_code": "" if succeeded else "qnetd_prepare_failed"}
        except Exception:
            record_audit(access.user_id, "cluster.qnetd.prepare", witness_id, "failure",
                         "Standalone QNetd preparation failed; diagnostic output omitted")
            return {"status": "error", "error_code": "qnetd_prepare_failed"}

    return create_operation_job("cluster_qnetd_prepare", access.user_id, [witness], prepare)


@app.post("/kvm-api/clusters/plans/{plan_id}/qdevice/prepare-nodes")
def prepare_cluster_qdevice_nodes(plan_id: str, payload: ClusterQdevicePrepareInput,
                                  access: AuthorizationContext = Depends(require_permission("cluster_admin"))) -> dict[str, Any]:
    """Install only corosync-qdevice on nodes in a saved, reviewed QDevice plan."""
    if len(set(payload.host_ids)) != len(payload.host_ids):
        raise HTTPException(422, "Select each QDevice node only once")
    plan, nodes = cluster_qdevice_prepare_nodes_context(plan_id, access)
    if any(host_id not in plan["host_ids"] for host_id in payload.host_ids):
        raise HTTPException(422, "Prepare QDevice packages only on nodes in the saved cluster plan")
    nodes_to_prepare = [host for host in nodes if host["id"] in set(payload.host_ids)]
    if len(nodes_to_prepare) != len(payload.host_ids):
        raise HTTPException(404, "One or more selected QDevice nodes are no longer registered")

    def prepare(host: dict[str, Any]) -> dict[str, Any]:
        host_id = host["id"]
        try:
            with cluster_host_mutation_guard([host_id]):
                current_plan, current_nodes = cluster_qdevice_prepare_nodes_context(plan_id, access)
                if current_plan["host_ids"] != plan["host_ids"] or host_id not in payload.host_ids:
                    return {"status": "error", "error_code": "qnetd_plan_changed"}
                current_host = next((item for item in current_nodes if item["id"] == host_id), None)
                if not current_host or current_host.get("status") != "ready":
                    return {"status": "error", "error_code": "qdevice_node_unavailable"}
                current_host["password"] = cipher.decrypt(current_host["password"].encode()).decode()
                decrypt_host_credentials(current_host)
                checks = json.loads(run_sudo_python(
                    current_host, HA_PREFLIGHT_SCRIPT,
                    args=[json.dumps({"check_qnetd_package": False})], timeout=90,
                ) or "{}")
                if not checks.get("compatibility_supported"):
                    result = {"status": "error", "error_code": "qnetd_host_unsupported"}
                elif not checks.get("ha_active"):
                    result = {"status": "error", "error_code": "qnetd_host_ha_inactive"}
                elif not checks.get("time_synchronized"):
                    result = {"status": "error", "error_code": "qnetd_host_time_sync"}
                else:
                    installed = json.loads(run_sudo_python(current_host, QDEVICE_PACKAGE_INSTALL_SCRIPT, timeout=930) or "{}")
                    result = {
                        "status": installed.get("status") if installed.get("status") in ("installed", "already_installed") else "error",
                        "message": installed.get("message", ""),
                        "error_code": "qnetd_prepare_failed" if installed.get("status") not in ("installed", "already_installed") else "",
                    }
                record_audit(access.user_id, "cluster.qdevice.prepare", host_id,
                             "success" if result["status"] in ("installed", "already_installed") else "failure",
                             "SUSE corosync-qdevice package prepared; cluster configuration left unchanged")
                return result
        except Exception:
            record_audit(access.user_id, "cluster.qdevice.prepare", host_id, "failure", "QDevice package preparation failed; diagnostic output omitted")
            return {"status": "error", "error_code": "qnetd_prepare_failed"}

    return create_operation_job("cluster_qdevice_prepare", access.user_id, nodes_to_prepare, prepare)


@app.post("/kvm-api/clusters/preflight")
def run_cluster_preflight(payload: ClusterPreflightRequest,
                          response: Response,
                          access: AuthorizationContext = Depends(require_permission("viewer"))) -> list[dict[str, Any]]:
    """Run bounded, read-only HA prerequisites checks on selected hosts."""
    response.headers["X-KVM-API-Version"] = app.version
    if len(set(payload.host_ids)) != len(payload.host_ids):
        raise HTTPException(422, "Select each host only once")
    qnetd_host = ""
    if payload.qnetd_host.strip():
        if "cluster_admin" not in access.permissions:
            raise HTTPException(403, "Only cluster administrators can probe a QNetd endpoint from managed hosts")
        qnetd_host = validate_qnetd_host(payload.qnetd_host)
    placeholders=','.join('?' for _ in payload.host_ids)
    with connect_db() as db:
        rows=[dict(row) for row in db.execute(f"SELECT * FROM hosts WHERE id IN ({placeholders})", payload.host_ids)]
    by_id={row['id']:row for row in rows}
    if len(by_id) != len(payload.host_ids):
        raise HTTPException(404, "One or more selected KVM hosts were not found")

    def inspect_preflight(host_id: str) -> dict[str, Any]:
        row=by_id[host_id]
        result={'host_id':host_id,'host_name':row.get('hostname') or row.get('name'),'status':'error'}
        try:
            row['password']=cipher.decrypt(row['password'].encode()).decode()
            decrypt_host_credentials(row)
            peers=[{'host_name':peer.get('hostname') or peer.get('name'),'address':peer.get('address'),'port':peer.get('port',22)}
                   for peer_id,peer in by_id.items() if peer_id != host_id]
            preflight_request={'peers':peers,'qnetd_host':qnetd_host,'registered_address':row.get('address','')}
            result['checks']=json.loads(run_sudo_python(row,HA_PREFLIGHT_SCRIPT,args=[json.dumps(preflight_request)],timeout=45) or '{}')
            result['status']='checked'
        except Exception as error:
            result['error']=str(error)[:300]
        result['checked_at']=datetime.now(timezone.utc).isoformat()
        return result

    with ThreadPoolExecutor(max_workers=min(3,len(payload.host_ids))) as executor:
        return list(executor.map(inspect_preflight,payload.host_ids))


def managed_cluster_view(db: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
    host_ids = json.loads(row["host_ids_json"])
    members = []
    for host_id in host_ids:
        member = db.execute("SELECT * FROM hosts WHERE id=?", (host_id,)).fetchone()
        if member:
            members.append(public_host(member))
    return {"id": row["id"], "name": row["name"], "type": row["cluster_type"],
            "state": row["state"], "host_ids": host_ids, "members": members,
            "template_id": row["template_id"], "capabilities": json.loads(row["capabilities_json"]),
            "created_at": row["created_at"], "updated_at": row["updated_at"],
            "last_checked_at": row["last_checked_at"]}


def cluster_plan_view(row: sqlite3.Row) -> dict[str, Any]:
    # Draft plans deliberately contain only topology choices. Never include host
    # credentials, SSH material, or preflight output in the persisted payload.
    return {"id": row["id"], "name": row["name"], "cluster_type": row["cluster_type"],
            "host_ids": json.loads(row["host_ids_json"]), "template_id": row["template_id"],
            "step": row["step"], "config": json.loads(row["config_json"]),
            "state": "draft", "preflight_required": True,
            "created_at": row["created_at"], "updated_at": row["updated_at"]}


def validate_cluster_plan(payload: ClusterPlanInput) -> tuple[str, list[str], dict[str, Any]]:
    name = payload.name.strip()
    if name and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", name):
        raise HTTPException(422, "Use 1–64 letters, numbers, dots, underscores, or hyphens for the cluster name")
    if len(set(payload.host_ids)) != len(payload.host_ids):
        raise HTTPException(422, "Select each KVM host only once")
    qnetd_host = validate_qnetd_host(payload.qnetd_host) if payload.quorum == "qdevice" and payload.qnetd_host.strip() else payload.qnetd_host.strip()
    if payload.quorum == "qdevice" and qnetd_host:
        witness = normalize_cluster_endpoint(qnetd_host)
        with connect_db() as db:
            rows = db.execute("SELECT id,name,hostname,address FROM hosts WHERE id IN (%s)" % ",".join("?" for _ in payload.host_ids), payload.host_ids).fetchall() if payload.host_ids else []
        if any(witness == normalize_cluster_endpoint(value) for row in rows for value in (row["name"], row["hostname"], row["address"])):
            raise HTTPException(422, "The QNetd witness must be outside the selected cluster nodes")
    corosync_networks = validate_corosync_networks(payload.corosync_networks)
    config = {"quorum": payload.quorum, "qnetd_host": qnetd_host,
              "qnetd_outside_cluster": payload.qnetd_outside_cluster, "fencing": payload.fencing,
              "corosync_networks": corosync_networks,
              "corosync_network_reviewed": payload.corosync_network_reviewed}
    return name, payload.host_ids, config


def save_cluster_plan(payload: ClusterPlanInput, access: AuthorizationContext, plan_id: str | None = None) -> dict[str, Any]:
    name, host_ids, config = validate_cluster_plan(payload)
    if host_ids:
        placeholders = ",".join("?" for _ in host_ids)
        with connect_db() as db:
            found = db.execute(f"SELECT id FROM hosts WHERE id IN ({placeholders})", host_ids).fetchall()
        if len(found) != len(host_ids):
            raise HTTPException(404, "One or more selected KVM hosts were not found")
    timestamp = now()
    with connect_db() as db:
        if plan_id:
            existing = db.execute("SELECT * FROM cluster_plans WHERE id=?", (plan_id,)).fetchone()
            if not existing:
                raise HTTPException(404, "Cluster plan not found")
            if existing["created_by"] != access.user_id and "cluster_admin" not in access.permissions:
                raise HTTPException(404, "Cluster plan not found")
            db.execute("UPDATE cluster_plans SET name=?,cluster_type=?,host_ids_json=?,template_id=?,step=?,config_json=?,updated_at=? WHERE id=?",
                       (name, payload.cluster_type, json.dumps(host_ids), payload.template_id, payload.step,
                        json.dumps(config), timestamp, plan_id))
            row = db.execute("SELECT * FROM cluster_plans WHERE id=?", (plan_id,)).fetchone()
        else:
            plan_id = str(uuid.uuid4())
            db.execute("INSERT INTO cluster_plans (id,name,cluster_type,host_ids_json,template_id,step,config_json,created_by,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                       (plan_id, name, payload.cluster_type, json.dumps(host_ids), payload.template_id,
                        payload.step, json.dumps(config), access.user_id, timestamp, timestamp))
            row = db.execute("SELECT * FROM cluster_plans WHERE id=?", (plan_id,)).fetchone()
    record_audit(access.user_id, "cluster.plan.save", plan_id, detail=f"state=draft; hosts={len(host_ids)}")
    return cluster_plan_view(row)


@app.get("/kvm-api/cluster-plans", dependencies=[Depends(require_permission("viewer"))])
def list_cluster_plans(access: AuthorizationContext = Depends(require_permission("viewer"))) -> list[dict[str, Any]]:
    with connect_db() as db:
        if "cluster_admin" in access.permissions:
            rows = db.execute("SELECT * FROM cluster_plans ORDER BY updated_at DESC").fetchall()
        else:
            rows = db.execute("SELECT * FROM cluster_plans WHERE created_by=? ORDER BY updated_at DESC", (access.user_id,)).fetchall()
    return [cluster_plan_view(row) for row in rows]


@app.post("/kvm-api/cluster-plans", status_code=201)
def create_cluster_plan(payload: ClusterPlanInput,
                        access: AuthorizationContext = Depends(require_permission("cluster_admin"))) -> dict[str, Any]:
    return save_cluster_plan(payload, access)


@app.put("/kvm-api/cluster-plans/{plan_id}")
def update_cluster_plan(plan_id: str, payload: ClusterPlanInput,
                        access: AuthorizationContext = Depends(require_permission("cluster_admin"))) -> dict[str, Any]:
    try:
        plan_id = str(uuid.UUID(plan_id))
    except ValueError as exc:
        raise HTTPException(404, "Cluster plan not found") from exc
    return save_cluster_plan(payload, access, plan_id)


@app.delete("/kvm-api/cluster-plans/{plan_id}", status_code=204)
def delete_cluster_plan(plan_id: str,
                        access: AuthorizationContext = Depends(require_permission("cluster_admin"))) -> Response:
    try:
        plan_id = str(uuid.UUID(plan_id))
    except ValueError as exc:
        raise HTTPException(404, "Cluster plan not found") from exc
    with connect_db() as db:
        row = db.execute("SELECT created_by FROM cluster_plans WHERE id=?", (plan_id,)).fetchone()
        if not row or (row["created_by"] != access.user_id and "cluster_admin" not in access.permissions):
            raise HTTPException(404, "Cluster plan not found")
        db.execute("DELETE FROM cluster_plans WHERE id=?", (plan_id,))
    record_audit(access.user_id, "cluster.plan.delete", plan_id)
    return Response(status_code=204)


@app.get("/kvm-api/managed-clusters", dependencies=[Depends(require_permission("viewer"))])
def list_managed_clusters() -> list[dict[str, Any]]:
    with connect_db() as db:
        rows = db.execute("SELECT * FROM managed_clusters ORDER BY name COLLATE NOCASE").fetchall()
        return [managed_cluster_view(db, row) for row in rows]


@app.post("/kvm-api/managed-clusters", status_code=201)
def create_managed_kvm_cluster(payload: ManagedKvmClusterInput,
                               access: AuthorizationContext = Depends(require_permission("cluster_admin"))) -> dict[str, Any]:
    name = payload.name.strip()
    if len(name) < 2 or len(set(payload.host_ids)) != len(payload.host_ids):
        raise HTTPException(422, "Enter a cluster name and select each host only once")
    placeholders = ",".join("?" for _ in payload.host_ids)
    with connect_db() as db:
        db.execute("BEGIN IMMEDIATE")
        hosts = db.execute(f"SELECT * FROM hosts WHERE id IN ({placeholders})", payload.host_ids).fetchall()
        if len(hosts) != len(payload.host_ids):
            raise HTTPException(404, "One or more selected KVM hosts were not found")
        unavailable = [row["hostname"] or row["name"] for row in hosts if row["status"] != "ready"]
        if unavailable:
            raise HTTPException(409, "All selected hosts must be connected and ready: " + ", ".join(unavailable))
        existing = db.execute("SELECT id,host_ids_json FROM managed_clusters").fetchall()
        claimed = {host_id for row in existing for host_id in json.loads(row["host_ids_json"])}
        overlap = [row["hostname"] or row["name"] for row in hosts if row["id"] in claimed]
        if overlap:
            raise HTTPException(409, "These hosts already belong to a KVM host group: " + ", ".join(overlap))
        cluster_id = str(uuid.uuid4())
        timestamp = now()
        # This is an extension-managed host group. It deliberately does not claim
        # shared storage, live migration, workload balancing, or HA readiness.
        capabilities = {"cross_host_inventory": False, "shared_storage_verified": False,
                        "common_networks_verified": False, "live_migration": False,
                        "automatic_placement": False, "ha": False}
        db.execute("INSERT INTO managed_clusters (id,name,cluster_type,state,host_ids_json,template_id,created_by,created_at,updated_at,last_checked_at,capabilities_json) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                   (cluster_id, name, "kvm-virtualization", "setup", json.dumps(payload.host_ids),
                    "kvm-virtualization", access.user_id, timestamp, timestamp, timestamp,
                    json.dumps(capabilities)))
        row = db.execute("SELECT * FROM managed_clusters WHERE id=?", (cluster_id,)).fetchone()
        result = managed_cluster_view(db, row)
    record_audit(access.user_id, "cluster.kvm_group.create", cluster_id,
                 detail=f"hosts={len(payload.host_ids)}; state=setup")
    return result


@app.delete("/kvm-api/managed-clusters/{cluster_id}", status_code=204)
def delete_managed_kvm_cluster(cluster_id: str,
                               access: AuthorizationContext = Depends(require_permission("cluster_admin"))) -> Response:
    try:
        cluster_id = str(uuid.UUID(cluster_id))
    except ValueError as exc:
        raise HTTPException(404, "KVM host group not found") from exc
    with connect_db() as db:
        row = db.execute("SELECT id FROM managed_clusters WHERE id=?", (cluster_id,)).fetchone()
        if not row:
            raise HTTPException(404, "KVM host group not found")
        db.execute("DELETE FROM managed_clusters WHERE id=?", (cluster_id,))
    record_audit(access.user_id, "cluster.kvm_group.delete", cluster_id)
    return Response(status_code=204)


def managed_cluster_inventory_error_code(error: Exception) -> str:
    """Return a safe, non-sensitive category for a failed remote inventory read."""
    detail = error.detail if isinstance(error, HTTPException) else str(error)
    folded = str(detail).casefold()
    if any(marker in folded for marker in (
        "authentication failed", "authenticationexception", "auth fail", "permission denied (publickey",
    )):
        return "ssh_auth_failed"
    if any(marker in folded for marker in (
        "timed out", "timeout", "connection refused", "no route to host",
        "network is unreachable", "could not resolve", "name or service not known",
    )):
        return "ssh_unreachable"
    if any(marker in folded for marker in ("libvirt", "virsh", "qemu:///system")):
        return "host_services_unavailable"
    return "inventory_failed"


@app.get("/kvm-api/managed-clusters/{cluster_id}", dependencies=[Depends(require_permission("viewer"))])
def get_managed_kvm_cluster(cluster_id: str) -> dict[str, Any]:
    try:
        cluster_id = str(uuid.UUID(cluster_id))
    except ValueError as exc:
        raise HTTPException(404, "KVM host group not found") from exc
    with connect_db() as db:
        row = db.execute("SELECT * FROM managed_clusters WHERE id=?", (cluster_id,)).fetchone()
        if not row:
            raise HTTPException(404, "KVM host group not found")
        return managed_cluster_view(db, row)


@app.get("/kvm-api/managed-clusters/{cluster_id}/inventory")
def get_managed_kvm_cluster_inventory(
    cluster_id: str,
    access: AuthorizationContext = Depends(require_permission("viewer")),
) -> dict[str, Any]:
    try:
        cluster_id = str(uuid.UUID(cluster_id))
    except ValueError as exc:
        raise HTTPException(404, "KVM host group not found") from exc
    with connect_db() as db:
        cluster = db.execute("SELECT * FROM managed_clusters WHERE id=?", (cluster_id,)).fetchone()
        if not cluster:
            raise HTTPException(404, "KVM host group not found")
        member_ids = json.loads(cluster["host_ids_json"])
        placeholders = ",".join("?" for _ in member_ids)
        rows = [dict(row) for row in db.execute(f"SELECT * FROM hosts WHERE id IN ({placeholders})", member_ids)]
    by_id = {row["id"]: row for row in rows}
    rows = [by_id[host_id] for host_id in member_ids if host_id in by_id]

    def inventory(row: dict[str, Any]) -> dict[str, Any]:
        name = row.get("hostname") or row.get("name")
        try:
            # Preserve the requester's RBAC context when reusing this route's
            # host inventory reader; a direct call must not receive Depends().
            data = get_host_cloud_native(row["id"], access)
            storage = data.get("storage") if isinstance(data.get("storage"), dict) else {}
            filesystems = storage.get("filesystems") if isinstance(storage.get("filesystems"), list) else []
            return {"host_id": row["id"], "host_name": name, "status": "ready",
                    "metrics": data.get("system", {}), "vms": data.get("vms", []),
                    "filesystems": filesystems,
                    "network_interfaces": data.get("network", {}).get("interfaces", []),
                    "libvirt_networks": data.get("libvirt_networks", []),
                    "storage_pools": data.get("storage_pools", []), "checked_at": now()}
        except Exception as exc:
            return {"host_id": row["id"], "host_name": name, "status": "error",
                    # Remote exception text can contain command output, paths, or
                    # credentials. Return only a safe category; the UI supplies
                    # localized next steps without exposing the diagnostic.
                    "error_code": managed_cluster_inventory_error_code(exc),
                    "vms": [], "checked_at": now()}

    with ThreadPoolExecutor(max_workers=min(3, len(rows))) as executor:
        hosts = list(executor.map(inventory, rows))
    vms = [{**vm, "host_id": host["host_id"], "host_name": host["host_name"]}
           for host in hosts for vm in host.get("vms", [])]
    return {"cluster_id": cluster_id, "checked_at": now(), "hosts": hosts, "vms": vms,
            "capabilities": json.loads(cluster["capabilities_json"])}


def backup_destination_view(row: sqlite3.Row) -> dict[str, Any]:
    return {"id": row["id"], "name": row["name"], "endpoint_url": row["endpoint_url"],
            "region": row["region"], "bucket": row["bucket"], "prefix": row["prefix"],
            "auth": row["auth"], "path_style": bool(row["path_style"]),
            "encryption": row["encryption"], "kms_key_id": row["kms_key_id"],
            "has_credentials": bool(row["access_key_id_enc"] and row["secret_access_key_enc"]),
            "created_at": row["created_at"]}


def validate_s3_endpoint(endpoint: str | None) -> None:
    """Require custom S3 endpoints to be explicitly approved by the operator.

    This prevents an API user with storage permissions from turning the service
    into an arbitrary HTTP client for cluster-internal addresses. Private S3
    compatible services remain supported through the exact-host allowlist.
    """
    if not endpoint:
        return
    parsed = urlsplit(endpoint)
    hostname = (parsed.hostname or "").lower().rstrip(".")
    if parsed.scheme != "https" or not hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("The S3 endpoint must be an HTTPS URL without embedded credentials, query, or fragment")
    if hostname not in KVM_S3_ALLOWED_ENDPOINT_HOSTS:
        raise ValueError("This custom S3 endpoint is not approved by the KVM administrator. Add its exact hostname to the extension allowlist and retry.")


def backup_s3_client(destination: sqlite3.Row):
    validate_s3_endpoint(destination["endpoint_url"])
    kwargs: dict[str, Any] = {
        "service_name": "s3", "region_name": destination["region"],
        "endpoint_url": destination["endpoint_url"] or None,
        "config": BotoConfig(connect_timeout=8, read_timeout=90, retries={"max_attempts": 3},
                              s3={"addressing_style": "path" if destination["path_style"] else "auto"}),
    }
    if destination["auth"] == "access-key":
        if not destination["access_key_id_enc"] or not destination["secret_access_key_enc"]:
            raise RuntimeError("The destination is missing its access key credentials")
        kwargs["aws_access_key_id"] = cipher.decrypt(destination["access_key_id_enc"].encode()).decode()
        kwargs["aws_secret_access_key"] = cipher.decrypt(destination["secret_access_key_enc"].encode()).decode()
    return boto3.client(**kwargs)


def backup_object_key(destination: sqlite3.Row, backup_id: str, vm_name: str) -> str:
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", vm_name).strip("._") or "vm"
    return "/".join(part.strip("/") for part in (destination["prefix"], backup_id, safe_name + ".tar") if part.strip("/"))


@app.get("/kvm-api/backups/destinations", dependencies=[Depends(require_permission("viewer"))])
def list_backup_destinations() -> list[dict[str, Any]]:
    with connect_db() as db:
        return [backup_destination_view(row) for row in db.execute("SELECT * FROM backup_destinations ORDER BY name COLLATE NOCASE")]


@app.post("/kvm-api/backups/destinations", status_code=201)
def create_backup_destination(payload: BackupDestinationInput,
                              access: AuthorizationContext = Depends(require_permission("storage_admin"))) -> dict[str, Any]:
    name, prefix = payload.name.strip(), payload.prefix.strip().strip("/")
    endpoint = payload.endpoint_url.strip().rstrip("/") if payload.endpoint_url else None
    try:
        validate_s3_endpoint(endpoint)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", payload.bucket) or ".." in payload.bucket:
        raise HTTPException(422, "Enter a valid S3 bucket name")
    if any(part == ".." for part in prefix.split("/")) or "\\" in prefix or "\0" in prefix:
        raise HTTPException(422, "The object prefix cannot contain parent path segments")
    if payload.auth == "access-key" and (not payload.access_key_id or not payload.secret_access_key):
        raise HTTPException(422, "Provide both the access key ID and secret access key")
    if payload.auth == "workload-identity" and (payload.access_key_id or payload.secret_access_key):
        raise HTTPException(422, "Do not send static keys when using workload identity")
    if payload.encryption == "sse-kms" and not (payload.kms_key_id or "").strip():
        raise HTTPException(422, "Provide a KMS key identifier for SSE-KMS")
    destination_id, timestamp = str(uuid.uuid4()), now()
    with connect_db() as db:
        db.execute("INSERT INTO backup_destinations (id,name,endpoint_url,region,bucket,prefix,auth,access_key_id_enc,secret_access_key_enc,path_style,encryption,kms_key_id,created_by,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                   (destination_id, name, endpoint, payload.region.strip(), payload.bucket, prefix, payload.auth,
                    cipher.encrypt(payload.access_key_id.encode()).decode() if payload.access_key_id else None,
                    cipher.encrypt(payload.secret_access_key.encode()).decode() if payload.secret_access_key else None,
                    int(payload.path_style), payload.encryption, payload.kms_key_id, access.user_id, timestamp, timestamp))
        row = db.execute("SELECT * FROM backup_destinations WHERE id=?", (destination_id,)).fetchone()
        result = backup_destination_view(row)
    record_audit(access.user_id, "backup.destination.create", destination_id)
    return result


@app.post("/kvm-api/backups/destinations/{destination_id}/test")
def test_backup_destination(destination_id: str,
                            access: AuthorizationContext = Depends(require_permission("storage_admin"))) -> dict[str, Any]:
    with connect_db() as db:
        destination = db.execute("SELECT * FROM backup_destinations WHERE id=?", (destination_id,)).fetchone()
    if not destination:
        raise HTTPException(404, "Backup destination not found")
    try:
        backup_s3_client(destination).head_bucket(Bucket=destination["bucket"])
    except Exception as exc:
        performance_logger.warning("backup_destination_test_failed id=%s class=%s", destination_id, type(exc).__name__)
        raise HTTPException(502, "Could not access the S3 bucket. Check endpoint, credentials, region, and bucket permissions.") from exc
    record_audit(access.user_id, "backup.destination.test", destination_id)
    return {"success": True, "message": "S3 bucket access verified"}


@app.delete("/kvm-api/backups/destinations/{destination_id}", status_code=204)
def delete_backup_destination(destination_id: str,
                             access: AuthorizationContext = Depends(require_permission("storage_admin"))) -> Response:
    with connect_db() as db:
        if not db.execute("SELECT 1 FROM backup_destinations WHERE id=?", (destination_id,)).fetchone():
            raise HTTPException(404, "Backup destination not found")
        if db.execute("SELECT 1 FROM vm_backups WHERE destination_id=? LIMIT 1", (destination_id,)).fetchone():
            raise HTTPException(409, "Delete this destination's backup archives before removing it")
        db.execute("DELETE FROM backup_destinations WHERE id=?", (destination_id,))
    record_audit(access.user_id, "backup.destination.delete", destination_id)
    return Response(status_code=204)


def stream_vm_backup_tar(host: dict[str, Any], vm_name: str, result: dict[str, Any], timeout: int = 7200):
    encoded = base64.b64encode(vm_name.encode()).decode()
    script = r'''import base64,json,os,subprocess,sys,tarfile,time,xml.etree.ElementTree as ET
name=base64.b64decode(sys.argv[1]).decode()
def run(args):
 p=subprocess.run(args,capture_output=True,text=True,timeout=60)
 if p.returncode: raise RuntimeError(p.stderr.strip() or p.stdout.strip() or 'libvirt command failed')
 return p.stdout
state=run(['virsh','-c','qemu:///system','domstate',name]).strip().lower()
if state!='shut off': raise RuntimeError('For a consistent archive, shut down the VM first; current state: '+state)
xml=run(['virsh','-c','qemu:///system','dumpxml','--inactive',name])
root=ET.fromstring(xml); disks=[]
for disk in root.findall('./devices/disk'):
 if disk.get('device')!='disk': continue
 source=disk.find('source'); target=disk.find('target')
 path=source.get('file') if source is not None else None
 if not path or not os.path.isfile(path) or os.path.islink(path): raise RuntimeError('Only regular file-backed VM disks are supported by this backup version')
 info=json.loads(run(['qemu-img','info','--output=json',path]))
 if info.get('backing-filename'): raise RuntimeError('VM disk has a backing chain; flatten it before backing up')
 if info.get('format') not in ('qcow2','raw'): raise RuntimeError('Only qcow2 and raw disk formats are supported')
 disks.append({'path':path,'name':'disks/disk-%d.%s'%(len(disks)+1,info['format']),'target':target.get('dev') if target is not None else None,'format':info['format'],'virtual_size':info.get('virtual-size',0)})
if not disks: raise RuntimeError('No supported VM disks were found')
manifest={'format_version':1,'vm_name':name,'uuid':root.findtext('uuid'),'created_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'consistency':'powered-off','disks':[{k:v for k,v in d.items() if k!='path'} for d in disks]}
with tarfile.open(fileobj=sys.stdout.buffer,mode='w|') as archive:
 data=json.dumps(manifest,sort_keys=True,indent=2).encode(); info=tarfile.TarInfo('manifest.json');info.size=len(data);archive.addfile(info,__import__('io').BytesIO(data))
 data=xml.encode(); info=tarfile.TarInfo('domain.xml');info.size=len(data);archive.addfile(info,__import__('io').BytesIO(data))
 for disk in disks: archive.add(disk['path'],arcname=disk['name'],recursive=False)
'''
    client = ssh_client_for_host(host)
    channel = None
    digest = hashlib.sha256()
    total = 0
    deadline = time.monotonic() + timeout
    try:
        command = f"sudo -S -p '' python3 -c {shlex.quote(script)} {shlex.quote(encoded)}"
        channel = client.get_transport().open_session(timeout=10)
        channel.settimeout(2.0)
        channel.exec_command(command)
        channel.send((host["password"] + "\n").encode())
        digest = hashlib.sha256()
        while True:
            if channel.recv_ready():
                chunk = channel.recv(1024 * 1024)
                if chunk:
                    digest.update(chunk)
                    total += len(chunk)
                    yield chunk
            if channel.recv_stderr_ready():
                # Keep stderr drained to prevent SSH channel back-pressure; do not return remote paths/details to clients.
                channel.recv_stderr(65536)
            if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                break
            if time.monotonic() > deadline:
                raise TimeoutError("The VM backup exceeded the operation time limit")
        code = channel.recv_exit_status()
        if code:
            raise RuntimeError("The host could not create a supported VM backup archive")
        result.update(sha256=digest.hexdigest(), size_bytes=total)
    finally:
        if channel:
            channel.close()
        client.close()


@app.get("/kvm-api/backups", dependencies=[Depends(require_permission("viewer"))])
def list_vm_backups() -> list[dict[str, Any]]:
    with connect_db() as db:
        rows = db.execute("SELECT * FROM vm_backups ORDER BY created_at DESC").fetchall()
    return [{"id": row["id"], "destination_id": row["destination_id"], "host_id": row["host_id"],
             "host_name": row["host_name"], "vm_name": row["vm_name"], "size_bytes": row["size_bytes"],
             "sha256": row["sha256"], "created_at": row["created_at"]} for row in rows]


@app.post("/kvm-api/backups/jobs")
def start_vm_backup(payload: BackupJobInput,
                    access: AuthorizationContext = Depends(require_permission("storage_admin"))) -> dict[str, Any]:
    host = cockpit_host_record(payload.host_id)
    if host["status"] != "ready":
        raise HTTPException(409, "The selected KVM host is not connected and ready")
    with connect_db() as db:
        destination = db.execute("SELECT * FROM backup_destinations WHERE id=?", (payload.destination_id,)).fetchone()
    if not destination:
        raise HTTPException(404, "Backup destination not found")
    if destination["auth"] == "access-key" and not destination["secret_access_key_enc"]:
        raise HTTPException(409, "The S3 destination has no saved secret access key")
    backup_id, created_at = str(uuid.uuid4()), now()
    object_key = backup_object_key(destination, backup_id, payload.vm_name)

    def perform(selected_host: dict[str, Any]) -> dict[str, Any]:
        client = backup_s3_client(destination)
        extra: dict[str, Any] = {}
        if destination["encryption"] == "sse-s3":
            extra["ServerSideEncryption"] = "AES256"
        elif destination["encryption"] == "sse-kms":
            extra.update(ServerSideEncryption="aws:kms", SSEKMSKeyId=destination["kms_key_id"])
        multipart = client.create_multipart_upload(Bucket=destination["bucket"], Key=object_key, **extra)
        upload_id = multipart["UploadId"]
        parts, part_number, buffer = [], 1, bytearray()
        try:
            stream_info: dict[str, Any] = {}
            for chunk in stream_vm_backup_tar(selected_host, payload.vm_name, stream_info):
                buffer.extend(chunk)
                while len(buffer) >= 8 * 1024 * 1024:
                    body = bytes(buffer[:8 * 1024 * 1024]); del buffer[:8 * 1024 * 1024]
                    result = client.upload_part(Bucket=destination["bucket"], Key=object_key,
                                                UploadId=upload_id, PartNumber=part_number, Body=body)
                    parts.append({"PartNumber": part_number, "ETag": result["ETag"]}); part_number += 1
            if buffer:
                result = client.upload_part(Bucket=destination["bucket"], Key=object_key,
                                            UploadId=upload_id, PartNumber=part_number, Body=bytes(buffer))
                parts.append({"PartNumber": part_number, "ETag": result["ETag"]})
            if not parts:
                raise RuntimeError("The KVM host returned an empty archive")
            client.complete_multipart_upload(Bucket=destination["bucket"], Key=object_key, UploadId=upload_id,
                                             MultipartUpload={"Parts": parts})
        except Exception:
            try:
                client.abort_multipart_upload(Bucket=destination["bucket"], Key=object_key, UploadId=upload_id)
            except Exception:
                pass
            raise
        digest = stream_info.get("sha256")
        size = stream_info.get("size_bytes")
        if not digest or not size:
            client.delete_object(Bucket=destination["bucket"], Key=object_key)
            raise RuntimeError("The host backup stream did not complete successfully")
        with connect_db() as db:
            db.execute("INSERT INTO vm_backups (id,destination_id,host_id,host_name,vm_name,object_key,size_bytes,sha256,created_by,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                       (backup_id, destination["id"], selected_host["id"], selected_host.get("hostname") or selected_host["name"],
                        payload.vm_name, object_key, size, digest, access.user_id, created_at))
        return {"status": "completed", "backup_id": backup_id, "size_bytes": size, "sha256": digest}

    record_audit(access.user_id, "backup.vm.start", f"{payload.host_id}/{payload.vm_name}", detail="manual powered-off VM archive")
    return create_operation_job("vm_backup", access.user_id, [host], perform)


@app.get("/kvm-api/backups/{backup_id}/download", dependencies=[Depends(require_permission("viewer"))])
def download_vm_backup(backup_id: str) -> StreamingResponse:
    with connect_db() as db:
        backup = db.execute("SELECT b.*,d.* FROM vm_backups b JOIN backup_destinations d ON d.id=b.destination_id WHERE b.id=?", (backup_id,)).fetchone()
    if not backup:
        raise HTTPException(404, "Backup archive not found")
    try:
        body = backup_s3_client(backup).get_object(Bucket=backup["bucket"], Key=backup["object_key"])["Body"]
    except Exception as exc:
        raise HTTPException(502, "Could not retrieve the backup archive from object storage") from exc
    filename = re.sub(r"[^A-Za-z0-9_.-]+", "_", backup["vm_name"]).strip("._") or "vm"
    return StreamingResponse(body.iter_chunks(chunk_size=1024 * 1024), media_type="application/x-tar",
                             headers={"Content-Disposition": f'attachment; filename="{filename}-{backup_id[:8]}.tar"',
                                      "Content-Length": str(backup["size_bytes"]), "X-KVM-Backup-SHA256": backup["sha256"]})


@app.delete("/kvm-api/backups/{backup_id}", status_code=204)
def delete_vm_backup(backup_id: str,
                     access: AuthorizationContext = Depends(require_permission("storage_admin"))) -> Response:
    with connect_db() as db:
        row = db.execute("SELECT b.*,d.* FROM vm_backups b JOIN backup_destinations d ON d.id=b.destination_id WHERE b.id=?", (backup_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Backup archive not found")
    try:
        backup_s3_client(row).delete_object(Bucket=row["bucket"], Key=row["object_key"])
    except Exception as exc:
        raise HTTPException(502, "Could not delete the archive from object storage; its catalog record was kept") from exc
    with connect_db() as db:
        db.execute("DELETE FROM vm_backups WHERE id=?", (backup_id,))
    record_audit(access.user_id, "backup.vm.delete", backup_id)
    return Response(status_code=204)


@app.get("/kvm-api/clusters/{host_id}/status")
def get_ha_cluster_status(host_id: str, access: AuthorizationContext = Depends(require_permission("viewer"))) -> dict[str, Any]:
    host = cockpit_host_record(host_id)
    try:
        result = json.loads(run_sudo_python(host, HA_CLUSTER_STATUS_SCRIPT, timeout=35) or '{}')
    except Exception as exc:
        raise HTTPException(502, f"Could not read SUSE HA cluster status from {host.get('hostname') or host.get('name')}: {str(exc)[:400]}") from exc
    record_audit(access.user_id, "cluster.status", f"{host_id}")
    result['source_host_id'] = host_id
    result['source_host_name'] = host.get('hostname') or host.get('name')
    stonith_ids = [resource.get("id") for resource in result.get("resources", [])
                   if isinstance(resource, dict) and (resource.get("class") == "stonith" or str(resource.get("agent", "")).startswith("stonith:"))]
    if stonith_ids:
        placeholders = ",".join("?" for _ in stonith_ids)
        with connect_db() as db:
            checks = db.execute(
                f"SELECT resource_id,checked_at,status,result_code FROM stonith_status_checks WHERE host_id=? AND resource_id IN ({placeholders})",
                [host_id, *stonith_ids],
            ).fetchall()
        checks_by_id = {row["resource_id"]: stonith_status_check_view(row) for row in checks}
        for resource in result["resources"]:
            if resource.get("id") in checks_by_id:
                resource["stonith_status_check"] = checks_by_id[resource["id"]]
    return result


def managed_suse_ha_cluster_view(db: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
    member_names = json.loads(row["member_names_json"])
    member_host_ids = json.loads(row["member_host_ids_json"])
    hosts_by_id = {
        host["id"]: host
        for host in db.execute(
            "SELECT id,name,hostname,address,status FROM hosts WHERE id IN (%s)" %
            (",".join("?" for _ in member_host_ids) or "NULL"), member_host_ids,
        ).fetchall()
    } if member_host_ids else {}
    members = []
    for node_name in member_names:
        host = next((hosts_by_id[host_id] for host_id in member_host_ids
                     if host_id in hosts_by_id and node_name.casefold().rstrip(".") in {
                         str(hosts_by_id[host_id]["name"] or "").casefold().rstrip("."),
                         str(hosts_by_id[host_id]["hostname"] or "").casefold().rstrip("."),
                         str(hosts_by_id[host_id]["address"] or "").casefold().rstrip("."),
                     }), None)
        members.append({"name": node_name, "host_id": host["id"] if host else None,
                        "host_name": (host["hostname"] or host["name"]) if host else None,
                        "connection_status": host["status"] if host else "unregistered"})
    return {"id": row["id"], "name": row["name"], "cluster_identity": row["cluster_identity"],
            "anchor_host_id": row["anchor_host_id"], "member_host_ids": member_host_ids,
            "members": members, "state": "registered", "created_at": row["created_at"],
            "updated_at": row["updated_at"], "last_checked_at": row["last_checked_at"]}


def live_suse_cluster_snapshot(host_id: str) -> tuple[dict[str, Any], list[str], list[str]]:
    host = cockpit_host_record(host_id)
    try:
        status = json.loads(run_sudo_python(host, HA_CLUSTER_STATUS_SCRIPT, timeout=35) or "{}")
    except Exception as exc:
        raise HTTPException(502, f"Could not verify the SUSE HA cluster through {host.get('hostname') or host.get('name')}: {str(exc)[:300]}") from exc
    name = str(status.get("cluster_name") or "").strip()
    nodes = status.get("nodes")
    member_names = sorted({str(node.get("name") or "").strip() for node in nodes
                           if isinstance(node, dict) and str(node.get("name") or "").strip()}, key=str.casefold) if isinstance(nodes, list) else []
    if not name or len(member_names) < 2:
        raise HTTPException(409, "The selected host is not reporting an initialized SUSE HA cluster with at least two members")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", name):
        raise HTTPException(409, "The live SUSE HA cluster name is not safe to register")
    with connect_db() as db:
        registered_hosts = [dict(row) for row in db.execute("SELECT id,name,hostname,address FROM hosts").fetchall()]
    member_keys = {name.casefold().rstrip(".") for name in member_names}
    matched_host_ids = sorted({row["id"] for row in registered_hosts if member_keys & {
        str(row.get(field) or "").casefold().rstrip(".") for field in ("name", "hostname", "address")
    }})
    if host_id not in matched_host_ids:
        raise HTTPException(409, "The selected registered host does not match a node reported by the live SUSE HA cluster")
    return status, member_names, matched_host_ids


@app.get("/kvm-api/suse-ha-clusters", dependencies=[Depends(require_permission("viewer"))])
def list_managed_suse_ha_clusters() -> list[dict[str, Any]]:
    with connect_db() as db:
        rows = db.execute("SELECT * FROM managed_suse_ha_clusters ORDER BY name COLLATE NOCASE").fetchall()
        return [managed_suse_ha_cluster_view(db, row) for row in rows]


@app.post("/kvm-api/suse-ha-clusters", status_code=201)
def register_managed_suse_ha_cluster(payload: ManagedSuseHaClusterInput,
                                     access: AuthorizationContext = Depends(require_permission("cluster_admin"))) -> dict[str, Any]:
    status, member_names, member_host_ids = live_suse_cluster_snapshot(payload.host_id)
    name = str(status["cluster_name"]).strip()
    identity = hashlib.sha256((name.casefold() + "\0" + "\0".join(value.casefold() for value in member_names)).encode()).hexdigest()[:32]
    timestamp = now()
    with connect_db() as db:
        db.execute("BEGIN IMMEDIATE")
        exact = db.execute("SELECT * FROM managed_suse_ha_clusters WHERE cluster_identity=?", (identity,)).fetchone()
        if exact:
            cluster_id = exact["id"]
            db.execute("UPDATE managed_suse_ha_clusters SET anchor_host_id=?,member_names_json=?,member_host_ids_json=?,updated_at=?,last_checked_at=? WHERE id=?",
                       (payload.host_id, json.dumps(member_names), json.dumps(member_host_ids), timestamp, timestamp, cluster_id))
        else:
            candidates = db.execute("SELECT * FROM managed_suse_ha_clusters WHERE lower(name)=lower(?)", (name,)).fetchall()
            incoming = set(member_host_ids)
            overlaps = [row for row in candidates if incoming & set(json.loads(row["member_host_ids_json"]))]
            if len(overlaps) > 1:
                raise HTTPException(409, "More than one saved SUSE HA cluster matches these registered nodes; resolve the duplicate cluster records before updating")
            if overlaps:
                cluster_id = overlaps[0]["id"]
                db.execute("UPDATE managed_suse_ha_clusters SET cluster_identity=?,anchor_host_id=?,member_names_json=?,member_host_ids_json=?,updated_at=?,last_checked_at=? WHERE id=?",
                           (identity, payload.host_id, json.dumps(member_names), json.dumps(member_host_ids), timestamp, timestamp, cluster_id))
            else:
                cluster_id = str(uuid.uuid4())
                db.execute("INSERT INTO managed_suse_ha_clusters (id,name,cluster_identity,anchor_host_id,member_names_json,member_host_ids_json,created_by,created_at,updated_at,last_checked_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                           (cluster_id, name, identity, payload.host_id, json.dumps(member_names), json.dumps(member_host_ids), access.user_id, timestamp, timestamp, timestamp))
        row = db.execute("SELECT * FROM managed_suse_ha_clusters WHERE id=?", (cluster_id,)).fetchone()
        view = managed_suse_ha_cluster_view(db, row)
    record_audit(access.user_id, "cluster.suse-ha.register", cluster_id,
                 detail=f"name={name}; registered_hosts={len(member_host_ids)}; live_nodes={len(member_names)}")
    return view


def virtualdomain_security_settings_consistent(storage_nodes: list[dict[str, Any]], mapping_complete: bool) -> bool | None:
    """Compare only host policy settings; per-VM process labels are host-specific observations."""
    keys = ("selinux_mode", "apparmor_enabled", "configured_libvirt_security_drivers",
            "security_default_confined", "security_require_confined")
    if not mapping_complete or not storage_nodes or any(
        node.get("status") != "checked" or not isinstance(node.get("security"), dict)
        for node in storage_nodes
    ):
        return None
    profiles = {
        json.dumps({key: node["security"].get(key) for key in keys}, sort_keys=True)
        for node in storage_nodes
    }
    return len(profiles) == 1


def virtualdomain_lockspace_gfs2_assessment(node_results: list[dict[str, Any]], mapping_complete: bool) -> dict[str, Any]:
    """Compare the configured libvirt lock-space mount with Pacemaker GFS2 mounts on every mapped node.

    Matching mount facts are only a candidate identity check; they do not prove shared-storage safety.
    """
    def mount_identity(mount: Any) -> tuple[str, str] | None:
        if not isinstance(mount, dict):
            return None
        filesystem = str(mount.get("fstype") or "").strip().lower()
        identity = str(mount.get("uuid") or mount.get("source") or "").strip()
        return (filesystem, identity) if filesystem and identity else None

    assessed: list[dict[str, Any]] = []
    signatures: list[tuple[Any, ...]] = []
    known_mismatches = False
    complete = bool(mapping_complete and node_results)
    for node in node_results:
        locking = node.get("virtualization_locking")
        item: dict[str, Any] = {
            "cluster_node": node.get("cluster_node", ""),
            "status": "unknown",
            "reason": "facts_unavailable",
            "lockspace_directory": None,
            "gfs2_resource_id": None,
            "gfs2_directory": None,
            "lockspace_mount": None,
            "gfs2_mount": None,
        }
        if (not isinstance(locking, dict) or node.get("mapping_status") != "mapped"
                or not node.get("node_online", False)):
            complete = False
            assessed.append(item)
            continue
        lockspace = locking.get("file_lockspace_dir")
        lockspace_safe = locking.get("lockspace_path_safe") is True
        lockspace_exists = locking.get("lockspace_directory_exists") is True
        lock_mount = locking.get("lockspace_mount")
        resources = locking.get("gfs2_resources")
        item.update({"lockspace_directory": lockspace, "lockspace_mount": lock_mount})
        if locking.get("lock_manager_is_lockd") is False:
            item.update(status="mismatch", reason="lock_manager_not_lockd")
            known_mismatches = True
            assessed.append(item)
            continue
        if lockspace_safe is False:
            item.update(status="mismatch", reason="lockspace_path_unsafe")
            known_mismatches = True
            assessed.append(item)
            continue
        if lockspace_exists is False:
            item.update(status="mismatch", reason="lockspace_missing")
            known_mismatches = True
            assessed.append(item)
            continue
        if locking.get("lock_manager_is_lockd") is not True or lockspace_safe is not True or lockspace_exists is not True:
            complete = False
            assessed.append(item)
            continue
        if (not isinstance(lockspace, str) or not lockspace.startswith("/") or ".." in lockspace.split("/")
                or locking.get("gfs2_resources_available") is not True or not isinstance(resources, list)):
            complete = False
            assessed.append(item)
            continue
        normalized_lockspace = os.path.normpath(lockspace)
        matches: list[dict[str, Any]] = []
        for resource in resources:
            if not isinstance(resource, dict):
                continue
            directory = resource.get("directory")
            if not isinstance(directory, str) or not directory.startswith("/") or ".." in directory.split("/"):
                continue
            normalized_directory = os.path.normpath(directory)
            try:
                if os.path.commonpath((normalized_directory, normalized_lockspace)) == normalized_directory:
                    matches.append(resource)
            except ValueError:
                continue
        if len(matches) != 1:
            item.update(status="mismatch", reason="gfs2_resource_not_found")
            known_mismatches = True
            assessed.append(item)
            continue
        resource = matches[0]
        gfs_mount = resource.get("mount")
        lock_identity = mount_identity(lock_mount)
        gfs_identity = mount_identity(gfs_mount)
        item.update({"gfs2_resource_id": resource.get("id"), "gfs2_directory": resource.get("directory"), "gfs2_mount": gfs_mount})
        if not lock_identity or not gfs_identity:
            complete = False
            assessed.append(item)
            continue
        lock_target = os.path.normpath(str((lock_mount or {}).get("target") or ""))
        gfs_target = os.path.normpath(str((gfs_mount or {}).get("target") or ""))
        try:
            target_matches = bool(gfs_target and lock_target and os.path.commonpath((gfs_target, lock_target)) == gfs_target)
        except ValueError:
            target_matches = False
        if lock_identity[0] != "gfs2" or gfs_identity[0] != "gfs2" or lock_identity != gfs_identity or not target_matches:
            item.update(status="mismatch", reason="gfs2_mount_identity_mismatch")
            known_mismatches = True
            assessed.append(item)
            continue
        item.update(status="candidate", reason="matching_gfs2_mount_facts")
        signatures.append((normalized_lockspace, str(resource.get("id") or ""), os.path.normpath(str(resource.get("directory") or "")), lock_identity, gfs_identity))
        assessed.append(item)

    if known_mismatches:
        status = "inconsistent"
    elif not complete or len(signatures) != len(node_results):
        status = "unknown"
    elif len(set(signatures)) != 1:
        status = "inconsistent"
        for item in assessed:
            if item["status"] == "candidate":
                item.update(status="mismatch", reason="node_mount_identity_differs")
    else:
        status = "candidate"
    return {"status": status, "nodes": assessed, "is_proof_of_shared_storage": False}


def virtualdomain_prepare_blockers(assessment: dict[str, Any], status: dict[str, Any],
                                   diagnostics: dict[str, Any], request: VirtualDomainPrepareRequest) -> list[str]:
    """Return fail-closed blockers before exporting VM XML or changing Pacemaker."""
    blockers: list[str] = []
    nodes = assessment.get("nodes") if isinstance(assessment.get("nodes"), list) else []
    if not assessment.get("mapping_complete") or not nodes or any(
        item.get("mapping_status") != "mapped" or item.get("node_online") is not True for item in nodes
    ):
        blockers.append("all_cluster_members_must_be_online_and_mapped")
    if not assessment.get("source_vm_found"):
        blockers.append("source_vm_not_found")
    source = next((item for item in nodes if item.get("host_id") == assessment.get("source_host_id")), None)
    if not source or str(source.get("state") or "").strip().casefold() not in ("shut off", "shutoff"):
        blockers.append("vm_must_be_shut_off_on_source")
    if not source or str(source.get("persistent") or "").strip().casefold() not in ("yes", "true", "1"):
        blockers.append("vm_must_be_persistent")
    if not source or str(source.get("autostart") or "").strip().casefold() not in ("no", "false", "0", "disable"):
        blockers.append("vm_autostart_must_be_disabled")
    if not source or not re.fullmatch(r"[0-9a-fA-F-]{36}", str(source.get("uuid") or "")):
        blockers.append("vm_uuid_not_verified")
    if assessment.get("vm_running_on_nodes"):
        blockers.append("vm_is_running_on_cluster_node")
    present_nodes = [item for item in nodes if item.get("vm_status") == "present"]
    if len(present_nodes) != 1 or present_nodes[0] is not source:
        blockers.append("vm_definition_must_exist_only_on_source")
    if assessment.get("virtualdomain_agent_on_all_nodes") is not True:
        blockers.append("virtualdomain_agent_missing")

    storage = assessment.get("storage_checks") if isinstance(assessment.get("storage_checks"), dict) else {}
    if storage.get("config_path") != request.config_path or storage.get("shared_mount_candidate") is not True:
        blockers.append("xml_path_must_be_on_consistent_shared_storage")
    storage_nodes = storage.get("nodes") if isinstance(storage.get("nodes"), list) else []
    if not storage_nodes or any(
        item.get("status") != "checked"
        or not isinstance(item.get("config"), dict)
        or item["config"].get("parent_exists") is not True
        or item["config"].get("file_exists") is not False
        or not isinstance(item["config"].get("parent_mount"), dict)
        or str(item["config"]["parent_mount"].get("fstype") or "").casefold() != "gfs2"
        for item in storage_nodes
    ):
        blockers.append("xml_parent_must_be_empty_existing_gfs2_mount_on_all_nodes")
    lockspace_profile = storage.get("lockspace_gfs2") if isinstance(storage.get("lockspace_gfs2"), dict) else {}
    if lockspace_profile.get("status") != "candidate":
        blockers.append("suse_gfs2_lockspace_profile_not_consistent")
    disk_paths = storage.get("disk_paths") if isinstance(storage.get("disk_paths"), list) else []
    if storage.get("disk_paths_not_checked", 0) or not disk_paths or any(
        item.get("exists_on_all_nodes") is not True or item.get("same_mount_candidate") is not True
        for item in disk_paths
    ):
        blockers.append("all_file_backed_vm_disks_must_be_verified_shared")
    for disk in disk_paths:
        path = disk.get("path")
        writable = disk.get("writable") is True
        for item in storage_nodes:
            observed = next((candidate for candidate in item.get("disk_paths", [])
                             if isinstance(candidate, dict) and candidate.get("path") == path), None)
            allowed = {"read_write"} if writable else {"read_only", "read_write"}
            if not observed or observed.get("configured_identity_access") not in allowed:
                blockers.append("qemu_identity_must_have_required_disk_access")
                break
    if storage.get("host_security_settings_consistent") is not True:
        blockers.append("host_security_profile_must_be_consistent")
    expected_peer_checks = max(0, len(nodes) - 1)
    if any(
        not isinstance(item.get("ssh_peer_auth"), list)
        or len(item["ssh_peer_auth"]) < expected_peer_checks
        or any(not isinstance(peer, dict) or peer.get("status") != "authenticated" for peer in item["ssh_peer_auth"])
        for item in storage_nodes
    ):
        blockers.append("passwordless_known_host_ssh_must_work_between_nodes")

    cluster_nodes = status.get("nodes") if isinstance(status.get("nodes"), list) else []
    if len(cluster_nodes) < 2 or any(node.get("online") is not True or node.get("unclean") is True for node in cluster_nodes):
        blockers.append("all_cluster_nodes_must_be_online_and_clean")
    quorum = status.get("quorum") if isinstance(status.get("quorum"), dict) else {}
    if quorum.get("available") is not True or quorum.get("quorate") is not True:
        blockers.append("cluster_must_have_confirmed_quorum")
    fencing = status.get("fencing") if isinstance(status.get("fencing"), dict) else {}
    if fencing.get("available") is not True or fencing.get("configured") is not True:
        blockers.append("cluster_fencing_must_be_configured")
    if fencing.get("stonith_configured") is True:
        coverage = fencing.get("stonith_target_coverage") if isinstance(fencing.get("stonith_target_coverage"), dict) else {}
        coverage_nodes = coverage.get("nodes") if isinstance(coverage.get("nodes"), list) else []
        covered = {str(item.get("node") or "").casefold() for item in coverage_nodes
                   if isinstance(item, dict) and item.get("status") == "covered"}
        online = {str(item.get("name") or "").casefold() for item in cluster_nodes if item.get("online") is True}
        if coverage.get("available") is not True or not online or not online.issubset(covered):
            blockers.append("every_online_node_must_have_registered_stonith_coverage")

    locking = diagnostics.get("locking_topology") if isinstance(diagnostics.get("locking_topology"), dict) else {}
    lock_clones = locking.get("lock_clone_ids") if isinstance(locking.get("lock_clone_ids"), list) else []
    if (locking.get("lock_stack_detected") is not True
            or locking.get("runtime_active_on_all_online_nodes") is not True
            or len(lock_clones) != 1):
        blockers.append("active_suse_dlm_gfs2_lock_clone_required")

    confirmations = {
        "shared_disks_confirmed": request.shared_disks_confirmed,
        "networks_confirmed": request.networks_confirmed,
        "remote_libvirt_confirmed": request.remote_libvirt_confirmed,
        "fencing_tested": request.fencing_tested,
        "security_reviewed": request.security_reviewed,
    }
    blockers.extend(f"operator_confirmation_required:{name}" for name, confirmed in confirmations.items() if not confirmed)
    return list(dict.fromkeys(blockers))


@app.get("/kvm-api/clusters/{host_id}/vms/virtualdomain-preflight")
def get_virtualdomain_vm_preflight(host_id: str, vm_name: str,
                                   config_path: str = "",
                                   access: AuthorizationContext = Depends(require_permission("viewer"))) -> dict[str, Any]:
    """Read-only cross-node facts for planning a SUSE VirtualDomain resource."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", vm_name):
        raise HTTPException(422, "Invalid virtual machine name")
    config_path = config_path.strip()
    if config_path and (
        len(config_path) > 1024 or not config_path.startswith("/")
        or "\x00" in config_path or ".." in config_path.split("/")
        or not config_path.lower().endswith(".xml")
    ):
        raise HTTPException(422, "Configuration path must be an absolute .xml path without parent-directory segments")
    _anchor, status = require_verified_ha_cluster(host_id)
    member_nodes = [
        {"name": str(node.get("name") or "").strip(), "online": bool(node.get("online", True))}
        for node in status.get("nodes", [])
        if isinstance(node, dict) and str(node.get("name") or "").strip()
    ]
    member_names = [node["name"] for node in member_nodes]
    with connect_db() as db:
        host_rows = [dict(row) for row in db.execute("SELECT id,name,hostname,address FROM hosts")]
    aliases_by_id = {
        row["id"]: {str(row.get(key) or "").strip().casefold().rstrip(".") for key in ("name", "hostname", "address")} - {""}
        for row in host_rows
    }
    hosts_by_id = {row["id"]: row for row in host_rows}
    used_host_ids: set[str] = set()
    assignments: list[tuple[str, str | None, str, bool]] = []
    for member in member_nodes:
        member_name = member["name"]
        normalized = member_name.casefold().rstrip(".")
        matches = [host_id for host_id, aliases in aliases_by_id.items() if normalized in aliases]
        if len(matches) == 1 and matches[0] not in used_host_ids:
            mapped_id = matches[0]
            used_host_ids.add(mapped_id)
            assignments.append((member_name, mapped_id, "mapped", member["online"]))
        else:
            assignments.append((member_name, None, "ambiguous" if matches else "unmapped", member["online"]))

    def inspect_member(item: tuple[str, str | None, str, bool]) -> dict[str, Any]:
        member_name, member_host_id, mapping_status, node_online = item
        result: dict[str, Any] = {
            "cluster_node": member_name,
            "host_id": member_host_id,
            "host_name": (hosts_by_id.get(member_host_id, {}).get("hostname") or hosts_by_id.get(member_host_id, {}).get("name")) if member_host_id else "",
            "mapping_status": mapping_status,
            "node_online": node_online,
            "vm_status": "not_checked" if node_online else "node_offline",
            "virtualdomain_agent_installed": None,
        }
        if not member_host_id or not node_online:
            return result
        host = None
        try:
            host = cockpit_host_record(member_host_id)
            detail = json.loads(run_sudo_python(host, VM_DETAIL_SCRIPT, [vm_name], timeout=45) or "{}")
            result.update({
                "vm_status": "present",
                "state": str(detail.get("state") or "unknown"),
                "persistent": str(detail.get("persistent") or "unknown"),
                "autostart": str(detail.get("autostart") or "unknown"),
                "uuid": str(detail.get("uuid") or ""),
                "configured_vcpus": detail.get("configured_vcpus"),
                "configured_memory_kib": detail.get("configured_memory_kib"),
                "disks": [
                    {"type": str(disk.get("type") or "unknown"), "target": str(disk.get("target") or ""),
                     "source": str(disk.get("source") or ""), "format": str(disk.get("format") or "unknown"),
                     "device": str(disk.get("device") or "disk"), "readonly": bool(disk.get("readonly"))}
                    for disk in detail.get("disks", []) if isinstance(disk, dict)
                ],
                "interfaces": [
                    {"type": str(interface.get("type") or "unknown"), "source": str(interface.get("source") or ""),
                     "model": str(interface.get("model") or "unknown"), "mac": str(interface.get("mac") or "")}
                    for interface in detail.get("interfaces", []) if isinstance(interface, dict)
                ],
            })
        except Exception as exc:
            result["vm_status"] = "not_defined" if "Virtual machine not found" in str(exc) else "inspection_failed"
        try:
            if host is None:
                host = cockpit_host_record(member_host_id)
            agents = json.loads(run_sudo_python(host, HA_RESOURCE_AGENTS_SCRIPT, timeout=35) or "{}")
            result["virtualdomain_agent_installed"] = "ocf:heartbeat:VirtualDomain" in agents.get("agents", [])
            result["virtualization_locking"] = agents.get("virtualization_locking")
        except Exception:
            pass
        return result

    with ThreadPoolExecutor(max_workers=min(4, len(assignments) or 1)) as executor:
        node_results = list(executor.map(inspect_member, assignments))
    mapping_complete = bool(member_names) and all(item["mapping_status"] == "mapped" for item in node_results)
    source_node = next((item for item in node_results if item.get("host_id") == host_id), None)
    storage_checks: dict[str, Any] | None = None
    source_disks = (source_node or {}).get("disks", [])
    disk_access_by_path: dict[str, bool] = {}
    disk_paths_not_checked = 0
    for disk in source_disks:
        source = disk.get("source", "") if isinstance(disk, dict) else ""
        if (isinstance(disk, dict) and disk.get("type") == "file" and isinstance(source, str) and source.startswith("/")
                and ".." not in source.split("/") and len(source) <= 1024):
            writable = disk.get("device", "disk") == "disk" and not bool(disk.get("readonly"))
            disk_access_by_path[source] = disk_access_by_path.get(source, False) or writable
        else:
            disk_paths_not_checked += 1
    all_disk_paths = sorted(disk_access_by_path)
    disk_paths_not_checked += max(0, len(all_disk_paths) - 32)
    disk_paths = [{"path": path, "writable": disk_access_by_path[path]} for path in all_disk_paths[:32]]

    if config_path or source_node:
        def inspect_storage(item: tuple[str, str | None, str, bool]) -> dict[str, Any]:
            member_name, member_host_id, mapping_status, node_online = item
            base: dict[str, Any] = {
                "cluster_node": member_name,
                "mapping_status": mapping_status,
                "status": "not_checked" if node_online else "node_offline",
                "config": None,
                "disk_paths": [],
                "security": None,
            }
            if not member_host_id or not node_online:
                return base
            try:
                host = cockpit_host_record(member_host_id)
                probe = json.loads(run_sudo_python(
                    host, VM_HA_STORAGE_PROBE_SCRIPT,
                    [config_path, json.dumps(disk_paths, separators=(",", ":")),
                     json.dumps([name for name in member_names if name.casefold() != member_name.casefold()], separators=(",", ":")),
                     vm_name], timeout=40,
                ) or "{}")
                base.update({"status": "checked", **probe})
            except Exception:
                base["status"] = "inspection_failed"
            return base

        with ThreadPoolExecutor(max_workers=min(4, len(assignments) or 1)) as executor:
            storage_nodes = list(executor.map(inspect_storage, assignments))

        def shared_mount_candidate(mounts: list[dict[str, Any] | None], paths_present: list[bool]) -> bool:
            if not mapping_complete or len(mounts) != len(member_names) or not all(paths_present) or not mounts:
                return False
            signatures = []
            for mount in mounts:
                if not isinstance(mount, dict) or not mount.get("fstype"):
                    return False
                identity = mount.get("uuid") or mount.get("source")
                if not identity:
                    return False
                signatures.append((mount.get("fstype"), identity))
            return len(set(signatures)) == 1

        config_mounts = [node.get("config", {}).get("mount") if isinstance(node.get("config"), dict) else None for node in storage_nodes]
        config_dirs = [bool(node.get("config", {}).get("parent_exists")) if isinstance(node.get("config"), dict) else False for node in storage_nodes]
        disk_candidates: list[dict[str, Any]] = []
        for disk_path in disk_paths:
            entries = [next((disk for disk in node.get("disk_paths", []) if disk.get("path") == disk_path), None) for node in storage_nodes]
            disk_candidates.append({
                "path": disk_path,
                "writable": disk_path.get("writable") is True,
                "exists_on_all_nodes": bool(entries) and all(entry and entry.get("exists") for entry in entries),
                "same_mount_candidate": shared_mount_candidate(
                    [entry.get("mount") if entry else None for entry in entries],
                    [bool(entry and entry.get("exists")) for entry in entries],
                ),
            })
        storage_checks = {
            "config_path": config_path,
            "shared_mount_candidate": shared_mount_candidate(config_mounts, config_dirs),
            "host_security_settings_consistent": virtualdomain_security_settings_consistent(storage_nodes, mapping_complete),
            "lockspace_gfs2": virtualdomain_lockspace_gfs2_assessment(node_results, mapping_complete),
            "disk_paths": disk_candidates,
            "disk_paths_not_checked": disk_paths_not_checked,
            "nodes": storage_nodes,
            "is_proof_of_shared_storage": False,
        }
    present = [item for item in node_results if item["vm_status"] == "present"]
    uuids = {item["uuid"] for item in present if item.get("uuid")}
    disk_layouts = {
        tuple(sorted((disk.get("target", ""), disk.get("source", ""), disk.get("type", "")) for disk in item.get("disks", [])))
        for item in present
    }
    network_layouts = {
        tuple(sorted((interface.get("type", ""), interface.get("source", ""), interface.get("mac", "")) for interface in item.get("interfaces", [])))
        for item in present
    }
    result = {
        "vm_name": vm_name,
        "source_host_id": host_id,
        "cluster_node_count": len(member_names),
        "mapping_complete": mapping_complete,
        "source_vm_found": bool(source_node and source_node.get("vm_status") == "present"),
        "virtualdomain_agent_on_all_nodes": mapping_complete and all(item.get("virtualdomain_agent_installed") is True for item in node_results),
        "vm_uuid_consistent": len(uuids) == 1 if len(present) > 1 and all(item.get("uuid") for item in present) else None,
        "disk_layout_consistent": len(disk_layouts) == 1 if len(present) > 1 else None,
        "network_mapping_consistent": len(network_layouts) == 1 if len(present) > 1 else None,
        "vm_running_on_nodes": [item["cluster_node"] for item in present if "running" in item.get("state", "").casefold()],
        "nodes": node_results,
        "storage_checks": storage_checks,
        "manual_checks_required": ["shared_virtualdomain_xml", "shared_disk_access", "remote_libvirt_authentication", "equivalent_networks", "shared_locking", "separate_vm_bridge", "stable_storage_ids", "security_confinement", "fencing_ready"],
    }
    record_audit(access.user_id, "cluster.virtualdomain.preflight", f"{host_id}/{vm_name}")
    return result


HA_VIRTUALDOMAIN_PREPARE_SCRIPT = r'''import hashlib,json,os,re,subprocess,sys,tempfile,xml.etree.ElementTree as ET
payload=json.loads(sys.stdin.read())
vm=payload['vm_name']; rid=payload['resource_id']; xml_path=payload['config_path']; expected_uuid=payload['expected_uuid']; lock_clone=payload['lock_clone_id']
expected_disk_paths=sorted(set(payload.get('expected_disk_paths') or []))
def fail(message): raise SystemExit(message)
if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}',vm): fail('Invalid virtual machine name.')
if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}',rid): fail('Invalid Pacemaker resource ID.')
if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',lock_clone): fail('The SUSE DLM/GFS2 clone ID is invalid; refresh cluster diagnostics.')
if not os.path.isabs(xml_path) or not xml_path.endswith('.xml') or '..' in xml_path.split('/') or len(xml_path)>1024 or any(ord(ch)<32 for ch in xml_path): fail('Choose an absolute .xml path without parent-directory segments or control characters.')
parent=os.path.dirname(xml_path)
if not parent or os.path.realpath(parent)!=parent or not os.path.isdir(parent): fail('The XML parent directory must exist and must not resolve through a symbolic link.')
try: os.lstat(xml_path); fail('The XML path already exists; choose a new shared-storage path.')
except FileNotFoundError: pass
mount=subprocess.run(['findmnt','-T',parent,'-J','-o','SOURCE,FSTYPE,UUID,TARGET,OPTIONS'],capture_output=True,text=True,timeout=10)
if mount.returncode: fail('The XML parent directory mount could not be verified.')
try: mount_data=json.loads(mount.stdout).get('filesystems',[])[0]
except Exception: fail('The XML parent directory mount could not be parsed.')
mount_identity=str(mount_data.get('uuid') or mount_data.get('source') or '')
if str(mount_data.get('fstype') or '').lower()!='gfs2' or 'rw' not in str(mount_data.get('options') or '').split(','): fail('The XML parent directory must be writable GFS2 shared storage.')
if mount_identity!=payload.get('expected_mount_identity') or os.path.normpath(str(mount_data.get('target') or ''))!=os.path.normpath(str(payload.get('expected_mount_target') or '')): fail('The XML storage mount changed after preflight; refresh the assessment and review it again.')
info=subprocess.run(['virsh','-c','qemu:///system','dominfo',vm],capture_output=True,text=True,timeout=20)
if info.returncode: fail('The source VM could not be queried with libvirt.')
fields={}
for line in info.stdout.splitlines():
 if ':' in line:
  key,value=line.split(':',1); fields[key.strip().casefold()]=value.strip()
if fields.get('state','').casefold() not in ('shut off','shutoff'): fail('The VM must be shut off before its libvirt XML can be exported.')
if fields.get('persistent','').casefold() not in ('yes','true','1'): fail('The VM must be a persistent libvirt guest.')
if fields.get('autostart','').casefold() not in ('no','false','0','disable'): fail('Disable libvirt autostart before preparing Pacemaker failover.')
actual_uuid=fields.get('uuid','')
if not actual_uuid or actual_uuid!=expected_uuid: fail('The VM UUID changed after preflight; refresh the assessment and review it again.')
xml_result=subprocess.run(['virsh','-c','qemu:///system','dumpxml','--inactive','--domain',vm],capture_output=True,text=True,timeout=30)
if xml_result.returncode: fail('Libvirt could not export the inactive VM configuration.')
try:
 root=ET.fromstring(xml_result.stdout)
 if root.findtext('name')!=vm or root.findtext('uuid')!=expected_uuid: fail('The exported VM XML name or UUID did not match preflight.')
 if root.find('./devices/hostdev') is not None or root.find('./devices/filesystem') is not None: fail('Host devices and host filesystem passthrough are not supported by the guided VirtualDomain profile.')
 os_node=root.find('./os')
 if os_node is not None and any(os_node.find('./'+tag) is not None for tag in ('nvram','kernel','initrd','loader')): fail('UEFI NVRAM or custom kernel/initrd paths need a separate shared-storage assessment before this VM can be prepared.')
 observed_disk_paths=[]
 for disk in root.findall('./devices/disk'):
  for source in disk.findall('.//source'):
   if source.get('file'):
    observed_disk_paths.append(source.get('file'))
   elif any(source.get(key) for key in ('dev','name','volume','dir')):
    fail('Only verified file-backed disks are supported by this guided VirtualDomain preparation.')
 if sorted(set(observed_disk_paths))!=expected_disk_paths: fail('The exported XML disk paths differ from the cross-node preflight; refresh the assessment before retrying.')
except ET.ParseError: fail('Libvirt returned invalid VM XML.')
resources=ET.fromstring(subprocess.run(['cibadmin','-Q','-o','resources'],capture_output=True,text=True,check=True,timeout=20).stdout)
if any(item.get('id')==rid for item in resources.iter()): fail('A Pacemaker resource with this ID already exists.')
clone=next((item for item in resources.iter('clone') if item.get('id')==lock_clone),None)
if clone is None: fail('The verified SUSE lock clone changed after preflight; refresh cluster diagnostics.')
constraints=ET.fromstring(subprocess.run(['cibadmin','-Q','-o','constraints'],capture_output=True,text=True,check=True,timeout=20).stdout)
constraint_ids={item.get('id') for item in constraints.iter() if item.get('id')}
order_id=rid+'-after-lock'; coloc_id=rid+'-with-lock'
if order_id in constraint_ids or coloc_id in constraint_ids: fail('A Pacemaker constraint with a generated ID already exists; choose another resource ID.')
if subprocess.run(['crm','ra','info','ocf:heartbeat:VirtualDomain'],capture_output=True,text=True,timeout=20).returncode: fail('The SUSE VirtualDomain resource agent is not available on this cluster node.')
def quote(value): return '"'+value.replace('\\','\\\\').replace('"','\\"')+'"'
config='primitive '+rid+' ocf:heartbeat:VirtualDomain \\\n  params config='+quote(xml_path)+' remoteuri='+quote('qemu+ssh://%n/system')+' \\\n  op monitor interval=10s timeout=30s \\\n  meta target-role="Stopped"\n'
config+='order '+order_id+' Mandatory: '+lock_clone+' '+rid+'\n'
config+='colocation '+coloc_id+' inf: '+rid+' '+lock_clone+'\n'
fd=os.open(xml_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o640)
try:
 with os.fdopen(fd,'w',encoding='utf-8') as handle:
  handle.write(xml_result.stdout); handle.flush(); os.fsync(handle.fileno())
 dfd=os.open(parent,os.O_RDONLY|getattr(os,'O_DIRECTORY',0))
 try: os.fsync(dfd)
 finally: os.close(dfd)
except Exception:
 try: os.unlink(xml_path)
 except OSError: pass
 raise
fd,crm_path=tempfile.mkstemp(prefix='rancher-kvm-virtualdomain-',suffix='.crm')
try:
 with os.fdopen(fd,'w',encoding='utf-8') as handle: handle.write(config)
 result=subprocess.run(['crm','configure','load','update',crm_path],capture_output=True,text=True,timeout=60)
 if result.returncode:
  fail((result.stderr or result.stdout or 'Pacemaker rejected the VirtualDomain resource and lock constraints.').strip()[:400]+' XML was exported at '+xml_path+'; the resource remains unconfigured.')
finally:
 try: os.unlink(crm_path)
 except OSError: pass
print(json.dumps({'success':True,'vm_name':vm,'resource_id':rid,'config_path':xml_path,'uuid':expected_uuid,'xml_sha256':hashlib.sha256(xml_result.stdout.encode()).hexdigest(),'resource_state':'Stopped','lock_clone_id':lock_clone,'message':'VM XML exported to shared GFS2 storage; VirtualDomain resource, lock ordering, and colocation were created. The VM was not started.'}))
'''


@app.post("/kvm-api/clusters/{host_id}/vms/virtualdomain-prepare")
def prepare_virtualdomain_vm(host_id: str, payload: VirtualDomainPrepareRequest,
                             access: AuthorizationContext = Depends(require_permission("cluster_admin"))) -> dict[str, Any]:
    """Queue a durable SUSE HA VM-preparation operation; it never starts the guest."""
    config_path = payload.config_path.strip()
    if (not config_path.startswith("/") or any(ord(ch) < 32 for ch in config_path) or ".." in config_path.split("/")
            or not config_path.lower().endswith(".xml")):
        raise HTTPException(422, "Configuration path must be an absolute .xml path without parent-directory segments.")

    _anchor, initial_status = require_verified_ha_cluster(host_id)
    member_ids_snapshot = cluster_member_host_ids(initial_status, host_id)
    source_record = cockpit_host_record(host_id)

    def prepare(_job_host: dict[str, Any]) -> dict[str, Any]:
        try:
            with cluster_host_mutation_guard(member_ids_snapshot):
                host, current_status = require_verified_ha_cluster(host_id)
                current_member_ids = cluster_member_host_ids(current_status, host_id)
                if current_member_ids != member_ids_snapshot:
                    raise HTTPException(409, "Cluster membership changed while the operation was queued. Refresh the cluster and repeat the VirtualDomain preflight.")
                assessment = get_virtualdomain_vm_preflight(host_id, payload.vm_name, config_path, access)
                # Preflight fetches live membership independently. Recheck after it so a
                # membership change between the first status query and inventory cannot
                # be hidden by a stale set of node facts.
                _latest_host, latest_status = require_verified_ha_cluster(host_id)
                if cluster_member_host_ids(latest_status, host_id) != member_ids_snapshot:
                    raise HTTPException(409, "Cluster membership changed during VirtualDomain preflight. Refresh and retry.")
                diagnostics = json.loads(run_sudo_python(host, HA_CLUSTER_DIAGNOSTICS_SCRIPT, timeout=45) or "{}")
                blockers = virtualdomain_prepare_blockers(assessment, latest_status, diagnostics, payload)
                if blockers:
                    raise HTTPException(409, "VirtualDomain preparation is blocked: " + ", ".join(blockers) + ". Refresh preflight and resolve every item before retrying.")
                source = next(item for item in assessment["nodes"] if item.get("host_id") == host_id)
                storage_nodes = (assessment.get("storage_checks") or {}).get("nodes") or []
                source_storage = next((item for item in storage_nodes if item.get("cluster_node") == source.get("cluster_node")), None)
                source_mount = ((source_storage or {}).get("config") or {}).get("parent_mount") or {}
                locking = diagnostics.get("locking_topology") or {}
                safe_payload = {"vm_name": payload.vm_name, "resource_id": payload.resource_id,
                                "config_path": config_path, "expected_uuid": source["uuid"],
                                "expected_disk_paths": sorted({disk.get("source", "") for disk in source.get("disks", [])
                                                                if disk.get("type") == "file" and disk.get("source", "").startswith("/")}),
                                "expected_mount_identity": source_mount.get("uuid") or source_mount.get("source"),
                                "expected_mount_target": source_mount.get("target"),
                                "lock_clone_id": locking["lock_clone_ids"][0]}
                output = run_sudo_python(host, HA_VIRTUALDOMAIN_PREPARE_SCRIPT, timeout=100, stdin_data=json.dumps(safe_payload))
                result = json.loads(output or "{}")
                if result.get("success") is not True or result.get("resource_state") != "Stopped":
                    raise HTTPException(502, "The host did not confirm a stopped VirtualDomain resource. Refresh cluster status and inspect the host before retrying.")
                record_audit(access.user_id, "cluster.virtualdomain.prepare", f"{host_id}/{payload.resource_id}")
                return {"status": "completed", **result}
        except Exception as exc:
            record_audit(access.user_id, "cluster.virtualdomain.prepare", f"{host_id}/{payload.resource_id}", "failure")
            if isinstance(exc, HTTPException):
                raise
            raise RuntimeError(f"VirtualDomain preparation failed: {str(exc)[:400]}") from exc

    return create_operation_job("cluster_virtualdomain_prepare", access.user_id, [source_record], prepare)


def require_verified_ha_cluster(host_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Require live Pacemaker membership before any cluster mutation."""
    host = cockpit_host_record(host_id)
    try:
        status = json.loads(run_sudo_python(host, HA_CLUSTER_STATUS_SCRIPT, timeout=35) or "{}")
    except Exception as exc:
        raise HTTPException(409, "Cluster changes are disabled because live SUSE HA status could not be verified. Refresh cluster status and retry.") from exc
    if not isinstance(status, dict):
        raise HTTPException(409, "Cluster changes are disabled because the host returned invalid SUSE HA status. Refresh cluster status and retry.")
    nodes = status.get("nodes")
    member_names = {
        str(node.get("name") or "").strip().casefold()
        for node in nodes if isinstance(node, dict) and str(node.get("name") or "").strip()
    } if isinstance(nodes, list) else set()
    if len(member_names) < 2:
        raise HTTPException(409, "Cluster changes require a verified Pacemaker cluster with at least two reported members. Initialize or recover the cluster, then refresh status.")
    return host, status


def validate_cluster_action_target(action: str, target: str, status: dict[str, Any]) -> None:
    """Reject stale or forged node/resource targets before sending crmsh actions."""
    node_actions = {"node_standby", "node_online", "node_maintenance", "node_ready"}
    resource_actions = {"resource_start", "resource_stop", "resource_cleanup"}
    if action in node_actions:
        known = {
            str(node.get("name") or "").strip()
            for node in status.get("nodes", [])
            if isinstance(node, dict) and str(node.get("name") or "").strip()
        }
        if target not in known:
            raise HTTPException(422, "That node is not in the current SUSE HA membership. Refresh cluster status and select a listed node.")
    elif action in resource_actions:
        known = {
            str(resource.get("id") or "").strip()
            for resource in status.get("resources", [])
            if isinstance(resource, dict) and str(resource.get("id") or "").strip()
        }
        if target not in known:
            raise HTTPException(422, "That Pacemaker resource is not in the current cluster status. Refresh resources and select a listed resource.")
    else:
        raise HTTPException(422, "Unsupported SUSE HA operation.")


@app.get("/kvm-api/clusters/{host_id}/diagnostics")
def get_ha_cluster_diagnostics(host_id: str, access: AuthorizationContext = Depends(require_permission("viewer"))) -> dict[str, Any]:
    """Return read-only constraint, Corosync-link, and recent service-log diagnostics."""
    host = cockpit_host_record(host_id)
    try:
        result = json.loads(run_sudo_python(host, HA_CLUSTER_DIAGNOSTICS_SCRIPT, timeout=45) or '{}')
    except Exception as exc:
        raise HTTPException(502, f"Could not read SUSE HA diagnostics from {host.get('hostname') or host.get('name')}: {str(exc)[:350]}") from exc
    record_audit(access.user_id, "cluster.diagnostics", host_id)
    address = str(host.get('address') or '').strip()
    try:
        parsed_address = ipaddress.ip_address(address)
        authority = f"[{address}]" if parsed_address.version == 6 else address
    except ValueError:
        hostname_pattern = r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*\.?"
        authority = address if re.fullmatch(hostname_pattern, address) else ''
    result['hawk_url'] = f"https://{authority}:{host.get('hawk_port') or 7630}/" if authority else ''
    result['checked_at'] = datetime.now(timezone.utc).isoformat()
    return result


@app.post("/kvm-api/clusters/{host_id}/actions", dependencies=[Depends(require_permission("cluster_admin"))])
def control_ha_cluster(host_id: str, payload: ClusterAction, access: AuthorizationContext = Depends(require_permission("cluster_admin"))) -> dict[str, Any]:
    host, status = require_verified_ha_cluster(host_id)
    validate_cluster_action_target(payload.action, payload.target, status)
    with cluster_host_mutation_guard(cluster_member_host_ids(status, host_id)):
        host, status = require_verified_ha_cluster(host_id)
        validate_cluster_action_target(payload.action, payload.target, status)
        try:
            output = run_sudo_python(host, HA_CLUSTER_ACTION_SCRIPT, [payload.action, payload.target], timeout=130)
        except Exception as exc:
            record_audit(access.user_id, f"cluster.{payload.action}", f"{host_id}/{payload.target}", "failure", str(exc))
            raise HTTPException(502, f"SUSE HA operation '{payload.action}' failed for '{payload.target}': {str(exc)[:350]}") from exc
        record_audit(access.user_id, f"cluster.{payload.action}", f"{host_id}/{payload.target}")
        return {"success": True, "message": output}


@app.get("/kvm-api/clusters/{host_id}/resource-agents")
def list_cluster_resource_agents(host_id: str, access: AuthorizationContext = Depends(require_permission("viewer"))) -> dict[str, Any]:
    host = cockpit_host_record(host_id)
    try:
        result = json.loads(run_sudo_python(host, HA_RESOURCE_AGENTS_SCRIPT, timeout=35) or "{}")
    except Exception as exc:
        raise HTTPException(502, f"Could not list installed Pacemaker resource agents: {str(exc)[:350]}") from exc
    record_audit(access.user_id, "cluster.resource_agents", host_id)
    return result


@app.get("/kvm-api/clusters/{host_id}/resource-agent-info")
def get_cluster_resource_agent_info(host_id: str, agent: str, access: AuthorizationContext = Depends(require_permission("viewer"))) -> dict[str, str]:
    host = cockpit_host_record(host_id)
    try:
        info = run_sudo_python(host, HA_RESOURCE_AGENT_INFO_SCRIPT, [agent], timeout=30)
    except Exception as exc:
        raise HTTPException(422, f"Could not read resource-agent guidance: {str(exc)[:350]}") from exc
    record_audit(access.user_id, "cluster.resource_agent_info", f"{host_id}/{agent}")
    return {"agent": agent, "info": info}


@app.get("/kvm-api/clusters/{host_id}/fencing-agents")
def list_cluster_fencing_agents(host_id: str, access: AuthorizationContext = Depends(require_permission("viewer"))) -> dict[str, Any]:
    host = cockpit_host_record(host_id)
    try:
        result = json.loads(run_sudo_python(host, HA_STONITH_AGENTS_SCRIPT, timeout=35) or "{}")
    except Exception as exc:
        raise HTTPException(502, f"Could not list installed SUSE fencing agents: {str(exc)[:350]}") from exc
    record_audit(access.user_id, "cluster.fencing_agents", host_id)
    return result


@app.get("/kvm-api/clusters/{host_id}/fencing-agent-info")
def get_cluster_fencing_agent_info(host_id: str, agent: str, access: AuthorizationContext = Depends(require_permission("viewer"))) -> dict[str, str]:
    host = cockpit_host_record(host_id)
    try:
        info = run_sudo_python(host, HA_STONITH_AGENT_INFO_SCRIPT, [agent], timeout=30)
    except Exception as exc:
        raise HTTPException(422, f"Could not read fencing-agent guidance: {str(exc)[:350]}") from exc
    record_audit(access.user_id, "cluster.fencing_agent_info", f"{host_id}/{agent}")
    return {"agent": agent, "info": info}


@app.post("/kvm-api/clusters/{host_id}/fencing-device-status")
def check_cluster_fencing_device_status(host_id: str, payload: StonithStatusCheckRequest,
                                       access: AuthorizationContext = Depends(require_permission("cluster_admin"))) -> dict[str, Any]:
    host, live_status = require_verified_ha_cluster(host_id)
    device = next((resource for resource in live_status.get("resources", [])
                   if isinstance(resource, dict) and resource.get("id") == payload.device_id
                   and (resource.get("class") == "stonith" or str(resource.get("agent", "")).startswith("stonith:"))), None)
    if device is None:
        raise HTTPException(404, "The selected STONITH resource is not present in the verified live cluster configuration")

    # Coordinate this device query with cluster mutations across every registered
    # member. SUSE notes that direct device checks can conflict with monitor jobs.
    member_host_ids = cluster_member_host_ids(live_status, host_id)
    with cluster_host_mutation_guard(member_host_ids):
        cached, reserved = reserve_stonith_status_check(host_id, payload.device_id)
        if not reserved:
            record_audit(access.user_id, "cluster.fencing_status", f"{host_id}/{payload.device_id}", "rate_limited")
            return {"resource_id": payload.device_id, **cached, "cached": True}
        try:
            raw = run_sudo_python(host, HA_STONITH_DEVICE_STATUS_SCRIPT, [payload.device_id], timeout=70) or "{}"
            result = json.loads(raw)
            allowed_statuses = {"query_succeeded", "query_failed", "unknown"}
            allowed_codes = {
                "status_query_succeeded", "status_query_failed", "status_query_timeout", "status_query_unavailable",
                "invalid_device_id", "ha_tool_unavailable", "cluster_status_unavailable", "cluster_not_active",
                "cluster_configuration_unavailable", "device_not_configured", "cluster_status_timeout", "cluster_status_invalid",
            }
            status = result.get("status") if isinstance(result, dict) else None
            code = result.get("code") if isinstance(result, dict) else None
            if status not in allowed_statuses or code not in allowed_codes:
                status, code = "unknown", "invalid_response"
        except Exception:
            # Do not expose remote stderr: device plugins may print sensitive
            # endpoints or account data when their status probe fails.
            status, code = "unknown", "api_query_unavailable"
        saved = save_stonith_status_check(host_id, payload.device_id, status, code)
    outcome = "success" if status == "query_succeeded" else "failure"
    record_audit(access.user_id, "cluster.fencing_status", f"{host_id}/{payload.device_id}", outcome)
    return {"resource_id": payload.device_id, **saved, "cached": False}


@app.post("/kvm-api/clusters/{host_id}/resources/config")
def mutate_cluster_resource(host_id: str, payload: ClusterResourceMutation, access: AuthorizationContext = Depends(require_permission("cluster_admin"))) -> dict[str, Any]:
    if payload.action == "create":
        if not payload.agent:
            raise HTTPException(422, "Select an installed OCF or systemd resource agent.")
        if payload.agent.casefold() == "ocf:heartbeat:virtualdomain":
            raise HTTPException(409, "VirtualDomain resources must use the guided VM preflight and preparation workflow.")
        if len(payload.parameters) > 40:
            raise HTTPException(422, "A primitive resource can have at most 40 parameters in this form.")
    if payload.action in ("create_stonith", "edit_stonith"):
        if not payload.agent or not payload.fencing_target:
            if payload.action == "create_stonith":
                raise HTTPException(422, "Select an installed STONITH agent and a current cluster node to fence.")
            raise HTTPException(422, "Refresh the fencing device and choose its current target node before editing it.")
        if len(payload.parameters) > 40:
            raise HTTPException(422, "A fencing change can affect at most 40 parameters.")
        if len(payload.parameter_removals) > 40:
            raise HTTPException(422, "A fencing change can remove at most 40 parameters.")
    if payload.action in ("set_param", "delete_param", "set_meta", "delete_meta") and not payload.key:
        raise HTTPException(422, "Provide a parameter or meta-attribute name.")
    _host, initial_status = require_verified_ha_cluster(host_id)
    with cluster_host_mutation_guard(cluster_member_host_ids(initial_status, host_id)):
        host, _status = require_verified_ha_cluster(host_id)
        safe_payload = payload.model_dump()
        try:
            output = run_sudo_python(host, HA_RESOURCE_MUTATION_SCRIPT, timeout=90, stdin_data=json.dumps(safe_payload))
        except Exception as exc:
            safe_error = str(exc)
            for value in list(payload.parameters.values()) + ([payload.value] if payload.value else []):
                if value:
                    safe_error = safe_error.replace(value, "[redacted]")
            # Resource parameters can contain credentials; keep their values out of audit details.
            record_audit(access.user_id, f"cluster.resource.{payload.action}", f"{host_id}/{payload.resource_id}", "failure")
            raise HTTPException(422, f"Pacemaker resource operation failed: {safe_error[:400]}") from exc
        record_audit(access.user_id, f"cluster.resource.{payload.action}", f"{host_id}/{payload.resource_id}")
        return {"success": True, "message": output}


@app.post("/kvm-api/clusters/{host_id}/nfs-service/config")
def configure_cluster_nfs_service(host_id: str, payload: ClusterNfsServiceRequest, access: AuthorizationContext = Depends(require_permission("cluster_admin"))) -> dict[str, Any]:
    """Create the SUSE NFS Pacemaker profile atomically, without starting or formatting storage."""
    initial_host, initial_status = require_verified_ha_cluster(host_id)
    member_names = {
        str(node.get("name") or "").strip().casefold()
        for node in initial_status.get("nodes", [])
        if isinstance(node, dict) and str(node.get("name") or "").strip()
    }
    member_ids = cluster_member_host_ids(initial_status, host_id)
    if len(member_names) < 2 or len(member_ids) != len(member_names):
        raise HTTPException(409, "Every live Pacemaker member must map to a registered KVM host before configuring shared NFS. Register or correct the missing host records, then refresh cluster status.")
    initial_quorum = initial_status.get("quorum")
    initial_fencing = initial_status.get("fencing")
    if not isinstance(initial_quorum, dict) or not initial_quorum.get("quorate"):
        raise HTTPException(409, "NFS resource creation requires a quorate SUSE HA cluster. Restore quorum, refresh cluster status, and retry.")
    if not isinstance(initial_fencing, dict) or not initial_fencing.get("configured"):
        raise HTTPException(409, "NFS resource creation requires configured fencing on the cluster. Configure and verify SBD or STONITH before retrying.")
    if payload.storage_mode == "drbd" and len(member_names) != 2:
        raise HTTPException(422, "The SUSE DRBD-backed NFS profile is supported for a two-node cluster. Select externally shared storage or use a separately reviewed topology.")
    with cluster_host_mutation_guard(member_ids):
        host, status = require_verified_ha_cluster(host_id)
        current_quorum = status.get("quorum")
        current_fencing = status.get("fencing")
        if not isinstance(current_quorum, dict) or not current_quorum.get("quorate") or not isinstance(current_fencing, dict) or not current_fencing.get("configured"):
            raise HTTPException(409, "Quorum or fencing changed while this form was open. Refresh cluster status and restore both prerequisites before retrying.")
        current_member_names = {
            str(node.get("name") or "").strip().casefold()
            for node in status.get("nodes", [])
            if isinstance(node, dict) and str(node.get("name") or "").strip()
        }
        current_member_ids = cluster_member_host_ids(status, host_id)
        if current_member_names != member_names or current_member_ids != member_ids:
            raise HTTPException(409, "Cluster membership changed while this form was open. Refresh the status and rerun the NFS review.")
        try:
            with connect_db() as db:
                rows = [dict(row) for row in db.execute(
                    f"SELECT * FROM hosts WHERE id IN ({','.join('?' for _ in member_ids)})", member_ids
                )]
            hosts_by_id = {row["id"]: row for row in rows}
            if set(hosts_by_id) != set(member_ids):
                raise HTTPException(409, "A cluster host record disappeared. Refresh the cluster hosts and retry.")
            required_agents = {"ocf:heartbeat:Filesystem", "ocf:heartbeat:nfsserver", "ocf:heartbeat:exportfs", "ocf:heartbeat:IPaddr2"}
            if payload.storage_mode == "drbd":
                required_agents.add("ocf:linbit:drbd")
            with ThreadPoolExecutor(max_workers=min(4, len(member_ids))) as executor:
                checks = list(executor.map(
                    lambda member_id: (member_id, json.loads(run_sudo_python(hosts_by_id[member_id], HA_RESOURCE_AGENTS_SCRIPT, timeout=35) or "{}")),
                    member_ids,
                ))
            missing = {
                member_id: sorted(required_agents - set(result.get("agents", [])))
                for member_id, result in checks
                if not required_agents.issubset(set(result.get("agents", [])))
            }
            if missing:
                detail = "; ".join(f"{hosts_by_id[item].get('hostname') or hosts_by_id[item].get('name')}: {', '.join(agents)}" for item, agents in missing.items())
                raise HTTPException(422, "Install the required SUSE HA resource agents on every cluster node before creating the NFS profile: " + detail)
            safe_payload = payload.model_dump()
            safe_payload["cluster_node_count"] = len(member_names)
            storage_preflight = {**safe_payload, "preflight_only": True}
            with ThreadPoolExecutor(max_workers=min(4, len(member_ids))) as executor:
                storage_results = list(executor.map(
                    lambda member_id: (member_id, json.loads(run_sudo_python(hosts_by_id[member_id], HA_NFS_SERVICE_CONFIG_SCRIPT, timeout=45, stdin_data=json.dumps(storage_preflight)) or "{}")),
                    member_ids,
                ))
            failed_preflight = [(member_id, result) for member_id, result in storage_results if result.get("success") is not True]
            if failed_preflight:
                raise HTTPException(422, "NFS storage preflight did not pass on every cluster node. Correct the device, filesystem, mount-point, DRBD synchronization, or virtual-IP issue on each node, then retry.")
            if payload.storage_mode == "drbd" and sum(1 for _member_id, result in storage_results if result.get("drbd_primary") is True) != 1:
                raise HTTPException(422, "DRBD must report exactly one Primary node after synchronization. Resolve the role state and rerun the NFS storage review.")
            output = run_sudo_python(host, HA_NFS_SERVICE_CONFIG_SCRIPT, timeout=120, stdin_data=json.dumps(safe_payload))
            result = json.loads(output or "{}")
            if not result.get("success"):
                raise RuntimeError("The KVM host did not confirm the NFS profile configuration.")
        except HTTPException:
            record_audit(access.user_id, "cluster.nfs.configure", f"{host_id}/{payload.resource_prefix}", "failure")
            raise
        except Exception as exc:
            record_audit(access.user_id, "cluster.nfs.configure", f"{host_id}/{payload.resource_prefix}", "failure")
            raise HTTPException(422, f"Could not configure the SUSE NFS Pacemaker profile: {str(exc)[:450]}") from exc
        record_audit(access.user_id, "cluster.nfs.configure", f"{host_id}/{payload.resource_prefix}")
        return result


@app.post("/kvm-api/clusters/{host_id}/service-vip/config")
def configure_cluster_service_vip(host_id: str, payload: ClusterServiceVipRequest, access: AuthorizationContext = Depends(require_permission("cluster_admin"))) -> dict[str, Any]:
    """Create a stopped Pacemaker group for an existing service and a shared VIP."""
    initial_host, initial_status = require_verified_ha_cluster(host_id)
    member_names = {
        str(node.get("name") or "").strip().casefold()
        for node in initial_status.get("nodes", [])
        if isinstance(node, dict) and str(node.get("name") or "").strip()
    }
    member_ids = cluster_member_host_ids(initial_status, host_id)
    if len(member_names) < 2 or len(member_ids) != len(member_names):
        raise HTTPException(409, "Every live Pacemaker member must map to a registered KVM host before configuring this service. Register or correct the missing host records, then refresh cluster status.")
    quorum = initial_status.get("quorum")
    fencing = initial_status.get("fencing")
    if not isinstance(quorum, dict) or not quorum.get("quorate"):
        raise HTTPException(409, "Service failover requires a quorate SUSE HA cluster. Restore quorum, refresh cluster status, and retry.")
    if not isinstance(fencing, dict) or not fencing.get("configured"):
        raise HTTPException(409, "Service failover requires configured fencing. Configure and verify SBD or STONITH before retrying.")
    with cluster_host_mutation_guard(member_ids):
        host, status = require_verified_ha_cluster(host_id)
        current_quorum = status.get("quorum")
        current_fencing = status.get("fencing")
        current_names = {
            str(node.get("name") or "").strip().casefold()
            for node in status.get("nodes", [])
            if isinstance(node, dict) and str(node.get("name") or "").strip()
        }
        if not isinstance(current_quorum, dict) or not current_quorum.get("quorate") or not isinstance(current_fencing, dict) or not current_fencing.get("configured"):
            raise HTTPException(409, "Quorum or fencing changed while this form was open. Refresh cluster status and restore both prerequisites before retrying.")
        current_ids = cluster_member_host_ids(status, host_id)
        if current_names != member_names or current_ids != member_ids:
            raise HTTPException(409, "Cluster membership changed while this form was open. Refresh the cluster status and rerun the service review.")
        try:
            with connect_db() as db:
                rows = [dict(row) for row in db.execute(
                    f"SELECT * FROM hosts WHERE id IN ({','.join('?' for _ in member_ids)})", member_ids
                )]
            hosts_by_id = {row["id"]: row for row in rows}
            if set(hosts_by_id) != set(member_ids):
                raise HTTPException(409, "A cluster host record disappeared. Refresh the cluster hosts and retry.")
            safe_payload = payload.model_dump()
            safe_payload["preflight_only"] = True
            def check_service_vip_member(member_id: str) -> tuple[str, dict[str, Any]]:
                member_host = hosts_by_id[member_id]
                member_name = member_host.get("hostname") or member_host.get("name") or member_id
                try:
                    result = json.loads(run_sudo_python(member_host, HA_SERVICE_VIP_CONFIG_SCRIPT, timeout=45, stdin_data=json.dumps(safe_payload)) or "{}")
                except Exception as exc:
                    raise RuntimeError(f"{member_name}: {str(exc)[:240]}") from exc
                return member_id, result
            with ThreadPoolExecutor(max_workers=min(4, len(member_ids))) as executor:
                checks = list(executor.map(check_service_vip_member, member_ids))
            failed = [(member_id, result) for member_id, result in checks if result.get("success") is not True]
            if failed:
                detail = "; ".join(f"{hosts_by_id[item].get('hostname') or hosts_by_id[item].get('name')}: {result.get('error') or 'preflight failed'}" for item, result in failed)
                raise HTTPException(422, "The service and VIP preflight must pass on every cluster node: " + detail)
            if payload.profile == "apache":
                hashes = {result.get("configuration_sha256") for _member_id, result in checks}
                if None in hashes or len(hashes) != 1:
                    raise HTTPException(422, "The selected Apache main configuration file must be readable and byte-for-byte identical on every cluster node. Synchronize it, review included files, certificates and content separately, then rerun the check.")
                safe_payload["expected_configuration_sha256"] = next(iter(hashes))
            safe_payload["preflight_only"] = False
            result = json.loads(run_sudo_python(host, HA_SERVICE_VIP_CONFIG_SCRIPT, timeout=90, stdin_data=json.dumps(safe_payload)) or "{}")
            if result.get("success") is not True:
                raise RuntimeError("The KVM host did not confirm the Pacemaker service profile configuration.")
        except HTTPException:
            record_audit(access.user_id, "cluster.service_vip.configure", f"{host_id}/{payload.resource_prefix}", "failure")
            raise
        except Exception as exc:
            record_audit(access.user_id, "cluster.service_vip.configure", f"{host_id}/{payload.resource_prefix}", "failure")
            raise HTTPException(422, f"Could not configure the SUSE HA service/VIP profile: {str(exc)[:450]}") from exc
        record_audit(access.user_id, "cluster.service_vip.configure", f"{host_id}/{payload.resource_prefix}")
        return result


@app.post("/kvm-api/clusters/{host_id}/constraints/config")
def mutate_cluster_constraint(host_id: str, payload: ClusterConstraintMutation, access: AuthorizationContext = Depends(require_permission("cluster_admin"))) -> dict[str, Any]:
    if payload.action != "delete" and not payload.resource:
        raise HTTPException(422, "Choose a Pacemaker resource for this constraint.")
    if payload.action in ("create_order", "create_colocation") and not payload.other_resource:
        raise HTTPException(422, "Choose the second Pacemaker resource.")
    if payload.action == "create_location" and (not payload.node or not payload.score):
        raise HTTPException(422, "Choose a cluster node and a location score.")
    if payload.action == "create_colocation" and not payload.score:
        raise HTTPException(422, "Choose a colocation score.")
    _host, initial_status = require_verified_ha_cluster(host_id)
    with cluster_host_mutation_guard(cluster_member_host_ids(initial_status, host_id)):
        host, _status = require_verified_ha_cluster(host_id)
        try:
            output = run_sudo_python(host, HA_CONSTRAINT_MUTATION_SCRIPT, timeout=90, stdin_data=json.dumps(payload.model_dump()))
        except Exception as exc:
            record_audit(access.user_id, f"cluster.constraint.{payload.action}", f"{host_id}/{payload.constraint_id}", "failure")
            raise HTTPException(422, f"Pacemaker constraint operation failed: {str(exc)[:400]}") from exc
        record_audit(access.user_id, f"cluster.constraint.{payload.action}", f"{host_id}/{payload.constraint_id}")
        return {"success": True, "message": output}


@app.post("/kvm-api/clusters/install-stack")
def install_ha_stack(payload: ClusterInstallRequest, access: AuthorizationContext = Depends(require_permission("cluster_admin"))) -> dict[str, Any]:
    if len(set(payload.host_ids)) != len(payload.host_ids):
        raise HTTPException(422, "Select each host only once")
    placeholders = ','.join('?' for _ in payload.host_ids)
    with connect_db() as db:
        rows = [dict(row) for row in db.execute(f"SELECT * FROM hosts WHERE id IN ({placeholders})", payload.host_ids)]
    by_id = {row['id']: row for row in rows}
    if len(by_id) != len(payload.host_ids):
        raise HTTPException(404, "One or more selected KVM hosts were not found")
    def install(row: dict[str, Any]) -> dict[str, Any]:
        host_id = row["id"]
        result = {"host_id": host_id, "host_name": row.get('hostname') or row.get('name'), "status": "error"}
        try:
            with cluster_host_mutation_guard([host_id]):
                row['password'] = cipher.decrypt(row['password'].encode()).decode()
                decrypt_host_credentials(row)
                output = run_sudo_python(row, HA_INSTALL_STACK_SCRIPT, timeout=930)
                result.update(json.loads(output or '{}'))
                result['status'] = "installed"
                record_audit(access.user_id, "cluster.install_ha_stack", host_id)
        except Exception as exc:
            result['error'] = str(exc)[:500]
            record_audit(access.user_id, "cluster.install_ha_stack", host_id, "failure", str(exc))
        return result
    return create_operation_job("ha_stack_install", access.user_id, rows, install)


@app.post("/kvm-api/clusters/templates/resolve-prerequisite")
def resolve_template_prerequisite(payload: ClusterPrerequisiteResolution, access: AuthorizationContext = Depends(require_permission("cluster_admin"))) -> dict[str, Any]:
    if len(set(payload.host_ids)) != len(payload.host_ids):
        raise HTTPException(422, "Select each host only once")
    placeholders = ','.join('?' for _ in payload.host_ids)
    with connect_db() as db:
        rows = [dict(row) for row in db.execute(f"SELECT * FROM hosts WHERE id IN ({placeholders})", payload.host_ids)]
    by_id = {row['id']: row for row in rows}
    if len(by_id) != len(payload.host_ids):
        raise HTTPException(404, "One or more selected KVM hosts were not found")

    def resolve(row: dict[str, Any]) -> dict[str, Any]:
        host_id = row["id"]
        name = row.get('hostname') or row.get('name')
        result: dict[str, Any] = {"host_id": host_id, "host_name": name, "action": payload.action, "status": "error"}
        try:
            with cluster_host_mutation_guard([host_id]):
                row['password'] = cipher.decrypt(row['password'].encode()).decode()
                decrypt_host_credentials(row)
                readiness = json.loads(run_sudo_python(row, HA_READINESS_SCRIPT, timeout=55) or '{}')
                if not readiness.get('ha_active'):
                    raise RuntimeError("Activate the SLE HA extension on this host before resolving workload prerequisites.")
                if payload.action == "enable_time_sync":
                    output = run_sudo_python(row, TEMPLATE_TIME_SYNC_SCRIPT, timeout=930)
                else:
                    workload = "web" if payload.action == "install_web_package" else "nfs"
                    # The supported ha_sles pattern provides the SUSE cluster tooling and agents.
                    # Workload services are prepared for the template, unless Corosync config
                    # indicates Pacemaker should retain control of service lifecycle.
                    run_sudo_python(row, HA_INSTALL_STACK_SCRIPT, timeout=930)
                    output = run_sudo_python(row, TEMPLATE_WORKLOAD_PACKAGE_SCRIPT, [workload], timeout=930)
                result.update({"status": "resolved", "message": output or "Prerequisite resolved."})
                record_audit(access.user_id, f"cluster.template.{payload.action}", host_id)
        except Exception as exc:
            result["error"] = str(exc)[:600]
            record_audit(access.user_id, f"cluster.template.{payload.action}", host_id, "failure", str(exc))
        return result

    return create_operation_job(f"template_{payload.action}", access.user_id, rows, resolve)


@app.get("/kvm-api/operations/{job_id}")
def get_operation_job(job_id: str, access: AuthorizationContext = Depends(require_permission("viewer"))) -> dict[str, Any]:
    try:
        job_id = str(uuid.UUID(job_id))
    except ValueError as exc:
        raise HTTPException(422, "Invalid operation ID") from exc
    job = operation_job_snapshot(job_id)
    if not job:
        raise HTTPException(404, "Operation was not found or has expired")
    with connect_db() as db:
        row = db.execute("SELECT actor FROM operation_jobs WHERE id=?", (job_id,)).fetchone()
    if row["actor"] != access.user_id and access.access_level != "host_admin":
        raise HTTPException(403, "Only the user who started this operation or a KVM administrator can view its progress")
    return job


@app.get("/kvm-api/permissions")
def get_permissions(access: AuthorizationContext = Depends(require_permission("viewer"))) -> dict[str, bool | str]:
    rank = ROLE_RANK[access.access_level]
    return {
        "accessLevel": access.access_level,
        "canView": True,
        "canOperateVms": "vm_operator" in access.permissions,
        "canManageHostResources": "host_resources" in access.permissions,
        "canManageNetwork": "network_admin" in access.permissions,
        "canManageStorage": "storage_admin" in access.permissions,
        "canManageRepositories": "software_admin" in access.permissions,
        "canManageSubscriptions": "subscription_admin" in access.permissions,
        "canManageAccounts": "account_admin" in access.permissions,
        "canManageServices": "service_admin" in access.permissions,
        "canManageClusters": "cluster_admin" in access.permissions,
        "canAdministerHost": "host_admin" in access.permissions,
    }


def probe_qnetd_witness_fingerprint(payload: QnetdWitnessFingerprintInput) -> dict[str, Any]:
    """Read a remote SSH host key before authentication or credential exchange."""
    address = validate_qnetd_host(payload.address)
    connection = socket.create_connection((address, payload.port), timeout=8)
    try:
        transport = paramiko.Transport(connection)
        try:
            transport.start_client(timeout=8)
            remote_key = transport.get_remote_server_key()
            ssh_host_key = f"{remote_key.get_name()} {remote_key.get_base64()}"
            fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(remote_key.asbytes()).digest()).decode().rstrip("=")
        finally:
            transport.close()
    finally:
        connection.close()
    return {"ssh_host_key": ssh_host_key, "fingerprint": fingerprint}


def inspect_qnetd_witness(payload: QnetdWitnessProbeInput,
                          pinned_host_key: str | None = None,
                          expected_fingerprint: str | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    """Authenticate only after the SSH server key has been confirmed or pinned."""
    address = validate_qnetd_host(payload.address)
    identity = probe_qnetd_witness_fingerprint(QnetdWitnessFingerprintInput(
        name=payload.name, address=address, port=payload.port,
    ))
    if pinned_host_key and identity["ssh_host_key"] != pinned_host_key:
        raise HTTPException(409, "The witness SSH fingerprint changed. Review the new fingerprint before sending credentials.")
    if expected_fingerprint and identity["fingerprint"] != expected_fingerprint:
        raise HTTPException(409, "The witness SSH fingerprint changed after confirmation. Fetch and review it again before sending credentials.")
    host: dict[str, Any] = {
        "id": "qnetd-witness-probe", "name": payload.name.strip(), "address": address,
        "port": payload.port, "username": payload.username.strip(), "password": payload.password,
        "ssh_host_key": identity["ssh_host_key"],
    }
    client = paramiko.SSHClient()
    host_label = address if payload.port == 22 else f"[{address}]:{payload.port}"
    try:
        key_type, key_data = identity["ssh_host_key"].split(" ", 1)
        key = paramiko.PKey.from_type_string(key_type, base64.b64decode(key_data.encode()))
    except (ValueError, TypeError) as exc:
        raise RuntimeError("The QNetd witness returned an invalid SSH host key") from exc
    client.get_host_keys().add(host_label, key_type, key)
    client.set_missing_host_key_policy(PinnedHostKeyPolicy())
    try:
        connect_ssh(client, host)
    finally:
        client.close()
    request = {"check_qnetd_package": True, "registered_address": address}
    checks = json.loads(run_sudo_python(host, QNETD_WITNESS_PREFLIGHT_SCRIPT, args=[json.dumps(request)], timeout=75) or "{}")
    os_id = str(checks.get("os_id") or "").lower()
    os_version = str(checks.get("os_version") or "")
    facts = {
        "hostname": str(checks.get("hostname") or "")[:253],
        "os_id": os_id, "os_name": str(checks.get("os_name") or "")[:120],
        "os_version": os_version,
        "compatibility_supported": bool(checks.get("compatibility_supported")),
        "ha_active": bool(checks.get("ha_active")),
        "ha_product": str(checks.get("ha_product") or "")[:128],
        "qnetd_package_installed": bool(checks.get("qnetd_package_installed")),
        "time_synchronized": bool(checks.get("time_synchronized")),
        "registered_address_is_dynamic": checks.get("registered_address_is_dynamic"),
        "checked_at": now(),
    }
    return identity, facts


@app.post("/kvm-api/hosts", status_code=201)
def create_host(payload: HostInput, access: AuthorizationContext = Depends(require_permission("host_admin"))) -> dict[str, Any]:
    if not payload.password and not payload.ssh_private_key:
        raise HTTPException(422, "Provide the host SSH password or a private key")
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
             cipher.encrypt((payload.password or "").encode()).decode(), facts["hostname"], facts["status"],
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
    if not payload.password and not payload.ssh_private_key:
        raise HTTPException(422, "Provide the host SSH password or a private key")
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


@app.post("/kvm-api/hosts/prepare-import")
def prepare_and_import_host(payload: HostInput, access: AuthorizationContext = Depends(require_permission("host_admin"))) -> dict[str, Any]:
    """Prepare an existing SLES machine over SSH, then save it as an imported host."""
    if not payload.password:
        raise HTTPException(422, "An SSH password is required to prepare the host")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]+", payload.address):
        raise HTTPException(422, "Enter a valid IPv4 address, IPv6 address, or DNS name")
    with connect_db() as db:
        duplicate = db.execute("SELECT id FROM hosts WHERE address=? AND port=?", (payload.address, payload.port)).fetchone()
        if duplicate:
            raise HTTPException(409, "This address is already imported. Open the existing host or update its credentials.")

    host = payload.model_dump() | {"private_key": None, "key_passphrase": None}
    client = paramiko.SSHClient()
    if payload.accept_new_host_key:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    else:
        if not Path(KNOWN_HOSTS).is_file():
            raise HTTPException(422, "SSH host key is not trusted. Select the host-key acceptance option for this first connection.")
        client.load_host_keys(KNOWN_HOSTS)
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        connect_ssh(client, host)
        remote_key = client.get_transport().get_remote_server_key()
        ssh_host_key = f"{remote_key.get_name()} {remote_key.get_base64()}"
        _stdin, os_stdout, _stderr = client.exec_command(". /etc/os-release 2>/dev/null; printf '%s|%s\\n' \"${ID:-unknown}\" \"${VERSION_ID:-unknown}\"", timeout=10)
        os_id, _, os_version = os_stdout.read().decode("utf-8", "replace").strip().partition("|")
        if os_id.lower() not in {"sles", "sle_hpc", "sled"}:
            raise HTTPException(422, f"Detected {os_id or 'an unknown operating system'} {os_version}; this preparation flow currently supports SUSE Linux Enterprise only.")

        # Fixed script and argv only; no user-provided form text enters a shell command.
        preparation_script = r'''import shutil, subprocess
def run(args, timeout=900):
    result = subprocess.run(args, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        detail = (result.stderr or result.stdout or 'command failed').strip()[-1000:]
        raise SystemExit(detail)
def installed(*packages):
    return all(shutil.which('rpm') and subprocess.run(['rpm','-q',p], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0 for p in packages)
run(['zypper','--non-interactive','refresh'], 300)
if not installed('qemu-kvm','libvirt-client'):
    run(['zypper','--non-interactive','install','-t','pattern','kvm_server','kvm_tools'])
if not installed('cockpit','cockpit-machines'):
    run(['zypper','--non-interactive','install','--no-recommends','cockpit','cockpit-machines'])
units = subprocess.run(['systemctl','list-unit-files','--type=socket','--no-legend'], text=True, capture_output=True, timeout=20).stdout
libvirt_socket = next((name for name in ('libvirtd.socket','virtqemud.socket') if name in units), None)
if not libvirt_socket:
    raise SystemExit('KVM packages are installed, but neither libvirtd.socket nor virtqemud.socket is available')
run(['systemctl','enable','--now',libvirt_socket], 60)
run(['systemctl','enable','--now','cockpit.socket'], 60)
print('KVM and Cockpit packages are ready; libvirt and cockpit sockets are enabled.')
'''
        command = f"sudo -S -p '' python3 -c {shlex.quote(preparation_script)}"
        stdin, stdout, stderr = client.exec_command(command, timeout=1100, get_pty=True)
        stdin.write(payload.password + "\n"); stdin.flush(); stdin.channel.shutdown_write()
        output = stdout.read().decode("utf-8", "replace").strip()
        error = stderr.read().decode("utf-8", "replace").strip()
        if stdout.channel.recv_exit_status():
            raise HTTPException(502, f"Host preparation failed: {(error or output or 'sudo or zypper returned an error')[-1000:]}")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(422, f"Could not prepare this machine over SSH: {str(exc)[:500]}") from exc
    finally:
        client.close()

    host["private_key"] = None
    try:
        facts = probe(host, pinned_host_key=ssh_host_key)
    except Exception as exc:
        raise HTTPException(502, f"Packages were prepared, but the host did not pass the libvirt import check: {str(exc)[:500]}") from exc
    host_id = str(uuid.uuid4())
    with connect_db() as db:
        db.execute(
            "INSERT INTO hosts (id,name,address,port,username,password,hostname,status,cpu_count,memory_total_bytes,last_checked_at,last_error,ssh_host_key,ssh_private_key_enc,ssh_key_passphrase_enc) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (host_id, payload.name, payload.address, payload.port, payload.username,
             cipher.encrypt((payload.password or "").encode()).decode(), facts["hostname"], facts["status"],
             facts["cpu_count"], facts["memory_total_bytes"], facts["last_checked_at"], None,
             facts["ssh_host_key"], None, None),
        )
        created = public_host(read_host(db, host_id))
    record_audit(access.user_id, "host.prepare_import", host_id, detail=f"{payload.name} ({payload.address}:{payload.port}); {os_id} {os_version}")
    return created


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
        memberships = []
        for cluster in db.execute("SELECT id,name,host_ids_json FROM managed_clusters"):
            try:
                if host_id in json.loads(cluster["host_ids_json"]):
                    memberships.append(cluster["name"])
            except (TypeError, ValueError):
                continue
        if memberships:
            names = ", ".join(memberships[:5])
            raise HTTPException(409, f"Remove this host from its KVM group before deleting it: {names}")
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
from concurrent.futures import ThreadPoolExecutor
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
        'autostart':info.get('autostart','unknown')})
def add_addresses(item):
    item['ip_addresses'] = addresses_for(item['name'], item['state'])
    return item
if items:
    # IP lookup is the slowest part of inventory and is independent per VM.
    # Keep a small bound to reduce page latency without flooding libvirt.
    with ThreadPoolExecutor(max_workers=min(4, len(items))) as executor:
        items = list(executor.map(add_addresses, items))
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

VM_DETAIL_SCRIPT = r'''import json, re, subprocess, sys, xml.etree.ElementTree as ET
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
graphics_console_types = [graphics.get('type','') for graphics in (devices.findall('./graphics') if devices is not None else [])]
vnc_graphics_console = 'vnc' in graphics_console_types
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
disk_access_modes = {}
for disk in devices.findall('./disk') if devices is not None else []:
    target = disk.find('./target')
    driver = disk.find('./driver')
    if target is not None and target.get('dev'):
        disk_formats[target.get('dev')] = driver.get('type','unknown') if driver is not None else 'unknown'
        disk_access_modes[target.get('dev')] = {
            'device':disk.get('device','disk'),
            'readonly':disk.find('./readonly') is not None,
        }
for line in run(['virsh','-c','qemu:///system','domblklist',name,'--details']).splitlines():
    parts = line.split(None,3)
    if len(parts) == 4 and parts[0] in ('file','block','dir','network','volume'):
        access_mode = disk_access_modes.get(parts[2], {'device':parts[1], 'readonly':False})
        disks.append({'type':parts[0], 'device':access_mode['device'], 'readonly':access_mode['readonly'],
            'target':parts[2], 'source':parts[3], 'format':disk_formats.get(parts[2],'unknown')})
interfaces = []
active_interfaces = {}
for line in run(['virsh','-c','qemu:///system','domiflist',name]).splitlines():
    parts = line.split(None,4)
    if len(parts) == 5 and parts[0] not in ('Interface','-'):
        active_interfaces[parts[4].lower()] = {'name':parts[0], 'type':parts[1], 'source':parts[2], 'model':parts[3]}
configured_devices = config_domain.find('./devices')
for iface in configured_devices.findall('./interface') if configured_devices is not None else []:
    mac_node = iface.find('./mac')
    mac = mac_node.get('address','') if mac_node is not None else ''
    source_node = iface.find('./source')
    source_value = next((source_node.get(key,'') for key in ('network','bridge','dev','name') if source_node is not None and source_node.get(key)), '')
    model_node = iface.find('./model')
    target_node = iface.find('./target')
    live = active_interfaces.get(mac.lower(), {}) if mac else {}
    interfaces.append({'name':live.get('name') or (target_node.get('dev','') if target_node is not None else ''),
        'type':iface.get('type','unknown'), 'source':source_value, 'model':model_node.get('type','unknown') if model_node is not None else 'unknown',
        'mac':mac, 'active':bool(live), 'ip_addresses':[]})
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
        raw_description=snapshot_xml.findtext('./description','')
        version_match=re.search(r'(?m)^Rancher-KVM-Version: (v[0-9TZ.-]+)$',raw_description)
        version=version_match.group(1) if version_match else 'legacy-'+snapshot_xml.findtext('./creationTime','')
        description=re.sub(r'(?m)^Rancher-KVM-Version: v[0-9TZ.-]+\s*$', '', raw_description).strip()
        snapshots.append({'name':snapshot_name.strip(),'state':snapshot_xml.findtext('./state','unknown'),
            'created_at':snapshot_xml.findtext('./creationTime',''),'description':description,'version':version})
    except Exception:
        snapshots.append({'name':snapshot_name.strip(),'state':'unknown','created_at':'','description':'','version':'legacy'})
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
    'autostart':'yes' if info.get('autostart','').lower() in ('enable','yes') else 'no', 'serial_console':serial_console,
    'vnc_graphics_console':vnc_graphics_console, 'graphics_console_type':next(iter(graphics_console_types), ''), 'disks':disks, 'interfaces':interfaces,
    'description':config_domain.findtext('./description',''), 'cpu_mode':cpu.get('mode','host-model') if cpu is not None else 'host-model',
    'cpu_model':cpu_model.text.strip() if cpu_model is not None and cpu_model.text else '',
    'architecture':os_type.get('arch','') if os_type is not None else '', 'machine':os_type.get('machine','') if os_type is not None else '',
    'firmware':loader.text.strip() if loader is not None and loader.text else 'BIOS', 'boot_order':boot_order,
    'snapshots':snapshots, 'snapshot_supported':snapshot_supported}
print(json.dumps(result))
'''

VM_HA_STORAGE_PROBE_SCRIPT = r'''import grp, json, os, pwd, re, shutil, stat, subprocess, sys
config_path = sys.argv[1]
disk_paths = json.loads(sys.argv[2])
peer_names = json.loads(sys.argv[3])
vm_name = sys.argv[4] if len(sys.argv) > 4 else ''
def safe_run(args, timeout=5):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout,
            stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        return None
def security_facts():
    result = safe_run(['getenforce']) if shutil.which('getenforce') else None
    selinux_mode = result.stdout.strip().lower() if result and result.returncode == 0 else 'unavailable'
    if selinux_mode not in ('enforcing', 'permissive', 'disabled'):
        selinux_mode = 'unknown' if result else 'unavailable'
    apparmor_enabled = None
    result = safe_run(['aa-status', '--enabled']) if shutil.which('aa-status') else None
    if result is not None:
        apparmor_enabled = True if result.returncode == 0 else False if result.returncode == 1 else None
    settings = {}
    try:
        with open('/etc/libvirt/qemu.conf', encoding='utf-8') as handle:
            for line in handle:
                match = re.match(r'^\s*(security_driver|security_default_confined|security_require_confined)\s*=\s*(.*?)\s*(?:#.*)?$', line)
                if match:
                    settings[match.group(1)] = match.group(2).strip()
    except Exception:
        pass
    drivers = re.findall(r'["\'](selinux|apparmor|dac|none)["\']', settings.get('security_driver', ''), re.I)
    def configured_bool(key):
        value = settings.get(key, '').lower()
        return True if value == '1' or value == 'true' else False if value == '0' or value == 'false' else None
    process_context = 'not_checked'
    if vm_name and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', vm_name):
        info = safe_run(['virsh', '-c', 'qemu:///system', 'dominfo', vm_name])
        if info and info.returncode == 0:
            pid_match = re.search(r'^\s*PID\s*:\s*(\d+)\s*$', info.stdout, re.M | re.I)
            if pid_match:
                try:
                    with open('/proc/' + pid_match.group(1) + '/attr/current', encoding='utf-8') as handle:
                        process_context = handle.read(256).strip() or 'unknown'
                except Exception:
                    process_context = 'unavailable'
            else:
                process_context = 'not_running'
        else:
            process_context = 'unknown'
    return {'selinux_mode':selinux_mode, 'apparmor_enabled':apparmor_enabled,
        'configured_libvirt_security_drivers':sorted(set(item.lower() for item in drivers)),
        'security_default_confined':configured_bool('security_default_confined'),
        'security_require_confined':configured_bool('security_require_confined'),
        'vm_process_context':process_context}
def parse_qemu_identity():
    values = {}
    try:
        with open('/etc/libvirt/qemu.conf', encoding='utf-8') as handle:
            for line in handle:
                match = re.match(r'^\s*(user|group)\s*=\s*["\']([^"\']{1,128})["\']\s*(?:#.*)?$', line)
                if match: values[match.group(1)] = match.group(2)
    except Exception:
        return None
    if not values.get('user') or not values.get('group'): return None
    try:
        account = pwd.getpwnam(values['user'])
        group = grp.getgrnam(values['group'])
        return {'user':values['user'], 'group':values['group'], 'uid':account.pw_uid, 'gid':group.gr_gid}
    except Exception:
        return None
def qemu_access(path, writable, identity):
    if not identity: return 'identity_unknown'
    real = os.path.realpath(path)
    if not os.path.isfile(real): return 'path_missing'
    code = 'import os,sys; mode=os.R_OK | (os.W_OK if sys.argv[2] == "1" else 0); raise SystemExit(0 if os.access(sys.argv[1], mode) else 1)'
    def drop_privileges():
        os.setgroups(os.getgrouplist(identity['user'], identity['gid']))
        os.setgid(identity['gid'])
        os.setuid(identity['uid'])
    try:
        result = subprocess.run([sys.executable, '-c', code, real, '1' if writable else '0'],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            close_fds=True, preexec_fn=drop_privileges, timeout=4)
        if result.returncode == 0: return 'read_write' if writable else 'read_only'
        return 'access_denied'
    except Exception:
        return 'access_unknown'
def peer_auth(name):
    if not isinstance(name,str) or len(name) > 253: return {'peer':str(name)[:253], 'status':'invalid_peer_name'}
    labels = name.rstrip('.').split('.')
    if not labels or any(not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label) for label in labels):
        return {'peer':name, 'status':'invalid_peer_name'}
    try:
        result = subprocess.run(['ssh','-T','-p','22','-o','BatchMode=yes','-o','PasswordAuthentication=no',
            '-o','KbdInteractiveAuthentication=no','-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no',
            '-o','ConnectTimeout=5','-o','ConnectionAttempts=1','root@'+name,'true'],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=8)
        return {'peer':name, 'status':'authenticated' if result.returncode == 0 else 'authentication_failed'}
    except subprocess.TimeoutExpired:
        return {'peer':name, 'status':'timeout'}
    except Exception:
        return {'peer':name, 'status':'check_failed'}
def mount_info(path):
    try:
        result = subprocess.run(['findmnt','--json','--target',path,'--output','SOURCE,FSTYPE,UUID,TARGET,OPTIONS'], capture_output=True, text=True, timeout=8)
        if result.returncode: return None
        filesystems = json.loads(result.stdout).get('filesystems',[])
        if not filesystems: return None
        item = filesystems[0]
        return {key:item.get(key) for key in ('source','fstype','uuid','target','options')}
    except Exception:
        return None
qemu_identity = parse_qemu_identity()
config = None
if config_path:
    parent = os.path.realpath(os.path.dirname(config_path))
    config_real = os.path.realpath(config_path)
    parent_exists = os.path.isdir(parent)
    config_exists = os.path.isfile(config_real)
    config = {
        'path':config_path,
        'parent_path':parent,
        'parent_exists':parent_exists,
        'file_exists':config_exists,
        'file_size_bytes':os.path.getsize(config_real) if config_exists else None,
        'parent_mount':mount_info(parent) if parent_exists else None,
    }
probed_disks = []
for disk in disk_paths:
    path = disk.get('path') if isinstance(disk,dict) else disk
    if not isinstance(path,str) or not path.startswith('/') or '..' in path.split('/'):
        continue
    real = os.path.realpath(path)
    exists = os.path.exists(real)
    writable = bool(disk.get('writable')) if isinstance(disk,dict) else False
    probed_disks.append({
        'path':path,
        'exists':exists,
        'kind':'block' if exists and stat.S_ISBLK(os.stat(real).st_mode) else 'file' if exists and os.path.isfile(real) else 'directory' if exists and os.path.isdir(real) else 'missing',
        'readable':bool(exists and os.access(real,os.R_OK)),
        'writable':writable,
        'configured_identity_access':qemu_access(real, writable, qemu_identity) if exists and os.path.isfile(real) else 'path_missing' if not exists else 'not_applicable',
        'mount':mount_info(real) if exists else None,
    })
print(json.dumps({'config':config,'disk_paths':probed_disks,'qemu_identity':{'user':qemu_identity['user'],'group':qemu_identity['group']} if qemu_identity else None,
    'ssh_peer_auth':[peer_auth(name) for name in peer_names if isinstance(name,str)],
    'security':security_facts()}))
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
    network_interfaces=[]
    try:
        for line in run(['virsh','-c','qemu:///system','domiflist',name]).splitlines():
            parts=line.split(None,4)
            if len(parts)==5 and parts[0] not in ('Interface','-'):
                network_interfaces.append({'name':parts[0],'type':parts[1],'source':parts[2],'model':parts[3],'mac':parts[4]})
    except Exception as error:
        errors.append('VM network '+name+': '+str(error))
    return {'name':name,'uuid':info.get('uuid',''),'state':state,'ip_addresses':addresses,
        'vcpus':int(info.get('cpu(s)','0') or '0'),'current_vcpus':int(vcpu.get('current_live',vcpu.get('current_config','0')) or '0'),
        'max_vcpus':int(vcpu.get('maximum_live',vcpu.get('maximum_config','0')) or '0'),
        'memory_kib':int(info.get('max memory','0').split()[0] or '0'),'used_memory_kib':int(info.get('used memory','0').split()[0] or '0'),
        'persistent':info.get('persistent','unknown'),'autostart':info.get('autostart','unknown'),
        'network_interfaces':network_interfaces}
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
    passwd_entries=pwd.getpwall()
    groups_by_user={entry.pw_name:[] for entry in passwd_entries}
    for group in grp.getgrall():
        for username in group.gr_mem: groups_by_user.setdefault(username,[]).append(group.gr_name)
    for entry in passwd_entries:
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
        raw_uri=repo.findtext('url') or repo.findtext('uri') or repo.get('url') or repo.get('uri') or ''
        # Some SUSE repository URLs contain short-lived entitlement tokens in
        # the query string. Keep the useful endpoint visible without returning
        # those credentials to the Rancher browser.
        safe_uri=raw_uri.split('#',1)[0]
        if '?' in safe_uri: safe_uri=safe_uri.split('?',1)[0]+'?[redacted]'
        repositories.append({'alias':repo.get('alias',''),'name':repo.get('name',''),'enabled':repo.get('enabled','0')=='1',
            'autorefresh':repo.get('autorefresh','0')=='1','uri':safe_uri})
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
        products=[]
        result=subprocess.run(['SUSEConnect','-s'],capture_output=True,text=True,timeout=30)
        overall_status=''
        if result.returncode==0:
            try:
                status_data=json.loads(result.stdout or '{}')
                overall_status=str(status_data.get('status','')) if isinstance(status_data,dict) else ''
                records=status_data if isinstance(status_data,list) else status_data.get('products',status_data.get('installed_products',[])) if isinstance(status_data,dict) else []
                if isinstance(records,dict): records=list(records.values())
                for item in records if isinstance(records,list) else []:
                    if not isinstance(item,dict): continue
                    identifier=str(item.get('identifier') or item.get('product') or item.get('product_id') or '')
                    if not identifier: continue
                    registration_data=item.get('registration') or item.get('subscription') or {}
                    if isinstance(registration_data,str): registration_name=registration_data
                    elif isinstance(registration_data,dict): registration_name=str(registration_data.get('name') or registration_data.get('subscription_name') or '')
                    else: registration_name=''
                    # SUSEConnect -s returns these fields directly on each
                    # product for current SLES releases. Older response
                    # variants may instead nest them under registration or
                    # subscription. Prefer a non-empty nested value, then
                    # fall back to the product record.
                    def subscription_field(*keys):
                        if isinstance(registration_data,dict):
                            for key in keys:
                                value=registration_data.get(key)
                                if value not in (None,''): return value
                        for key in keys:
                            value=item.get(key)
                            if value not in (None,''): return value
                        return ''
                    status_value=str(item.get('status') or item.get('current_status') or (registration_data.get('status','') if isinstance(registration_data,dict) else ''))
                    raw_name=str(item.get('friendly_name') or item.get('product_name') or item.get('display_name') or item.get('name') or '')
                    subscription_data=registration_data
                    subscription_name=registration_name
                    if not subscription_name and 'subscription' in raw_name.lower(): subscription_name=raw_name
                    product_names={'SLES':'SUSE Linux Enterprise Server','SLES_SAP':'SUSE Linux Enterprise Server for SAP Applications'}
                    product_name=raw_name if raw_name and 'subscription' not in raw_name.lower() else product_names.get(identifier,identifier)
                    product_version=str(item.get('version') or '')
                    product_arch=str(item.get('arch') or item.get('architecture') or '')
                    product_label=' '.join(part for part in (product_name,product_version,product_arch) if part)
                    expires_value=subscription_field('expires_at','expires at')
                    starts_value=subscription_field('starts_at','starts at','registered_at','registered at')
                    registration_code=subscription_field('regcode','registration_code','registration code')
                    products.append({'name':product_label,
                        'product':identifier,'active':status_value.lower() in ('registered','active','activated'),
                        'subscription_name':subscription_name,
                        'registration_code':str(registration_code or ''),
                        'subscription_status':str(subscription_field('status','subscription_status')),
                        'subscription_type':str(subscription_field('type','subscription_type')),
                        'starts_at':str(starts_value or ''),'expires_at':str(expires_value or '')})
            except Exception: pass
        if not products:
            # Older SUSEConnect builds may not provide structured product data.
            # Parse the text locally and return only safe, display-ready fields.
            text_result=subprocess.run(['SUSEConnect','--status-text'],capture_output=True,text=True,timeout=30)
            status_text=(text_result.stdout or text_result.stderr).strip()
            for block in re.split(r'(?m)^\s*-{5,}\s*$',status_text):
                lines=[line.strip() for line in block.splitlines() if line.strip()]
                product_index=next((i for i,line in enumerate(lines) if re.fullmatch(r'\([^()]+/[^()]+/[^()]+\)',line)),None)
                if product_index is None: continue
                identifier=lines[product_index][1:-1]
                subscription_start=next((i for i,line in enumerate(lines) if line.lower()=='subscription:'),None)
                subscription_fields={}
                if subscription_start is not None:
                    for line in lines[subscription_start+1:]:
                        if ':' in line:
                            key,value=line.split(':',1)
                            subscription_fields[key.strip().lower()]=value.strip()
                registered=any(line.lower()=='registered' for line in lines[product_index+1:subscription_start if subscription_start is not None else None])
                products.append({'name':lines[0],'product':identifier,'active':registered,
                    'subscription_name':subscription_fields.get('name',''),'registration_code':subscription_fields.get('regcode',subscription_fields.get('registration code','')),'subscription_status':subscription_fields.get('status',''),
                    'subscription_type':subscription_fields.get('type',''),'starts_at':subscription_fields.get('starts at',subscription_fields.get('registered at','')),'expires_at':subscription_fields.get('expires at','')})
            if result.returncode and text_result.returncode==0: result=text_result
        registered=bool(result.returncode==0 and (any(item['active'] for item in products) or overall_status.lower()=='registered'))
        subscription={'available':True,'status':'Registered' if registered else 'Not registered',
            'registration_status':'registered' if registered else 'not_registered','products':products,
            'return_code':result.returncode}
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


@app.get("/kvm-api/hosts/{host_id}/activity", dependencies=[Depends(require_permission("viewer"))])
def list_host_activity(host_id: str, vm_name: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    """Return a bounded, host-scoped activity list without exposing audit details."""
    limit = min(max(limit, 1), 100)
    with connect_db() as db:
        read_host(db, host_id)
        if vm_name:
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", vm_name):
                raise HTTPException(422, "Invalid virtual machine name")
            prefix = f"{host_id}/{vm_name}"
            rows = db.execute(
                "SELECT occurred_at,action,target,outcome FROM audit_events "
                "WHERE target=? OR target GLOB ? ORDER BY occurred_at DESC LIMIT ?",
                (prefix, prefix + "/*", limit),
            )
        else:
            rows = db.execute(
                "SELECT occurred_at,action,target,outcome FROM audit_events "
                "WHERE target=? OR target GLOB ? ORDER BY occurred_at DESC LIMIT ?",
                (host_id, host_id + "/*", limit),
            )
        return [dict(row) for row in rows]


@app.post("/kvm-api/hosts/{host_id}/vms/create")
def create_vm(host_id: str, payload: VMCreate, access: AuthorizationContext = Depends(require_permission("vm_operator"))) -> dict[str, Any]:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", payload.name):
        raise HTTPException(422, "Use a VM name with letters, numbers, dots, underscores, or hyphens")
    if payload.iso_path and (not payload.iso_path.startswith("/") or not payload.iso_path.lower().endswith(".iso")):
        raise HTTPException(422, "The installer ISO must be an absolute path ending in .iso on the KVM host")
    if payload.iso_path and payload.iso_url:
        raise HTTPException(422, "Choose either a host ISO path or a remote ISO URL, not both")
    if payload.image_id and (payload.iso_path or payload.iso_url or payload.volume):
        raise HTTPException(422, "Choose only one boot source: an existing disk, an installer ISO, or an image-library item")
    if payload.image_id and not payload.create_disk:
        raise HTTPException(422, "Creating a VM from the image library requires a new independent boot disk")
    if payload.iso_url:
        try:
            payload.iso_url = validate_public_iso_url(payload.iso_url)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
    if payload.create_disk:
        if payload.volume:
            raise HTTPException(422, "Choose a new disk or an existing disk volume, not both")
        if not (payload.iso_path or payload.iso_url or payload.image_id):
            raise HTTPException(422, "A new boot disk requires an installer ISO or an image-library item")
    elif not payload.volume:
        raise HTTPException(422, "Select an existing bootable disk volume")
    host = cockpit_host_record(host_id)
    creation_script = VM_PACEMAKER_VM_GUARD_SCRIPT + r'''import hashlib,ipaddress,json,os,re,shutil,socket,ssl,subprocess,sys,tempfile,urllib.request,xml.etree.ElementTree as ET
name,pool,volume,network,vcpu_text,memory_text,iso_path,iso_url,autostart,create_disk,disk_size_gib,image_id=sys.argv[1:]
if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}',name): raise SystemExit('Invalid VM name')
vcpus=int(vcpu_text); memory_mib=int(memory_text)
create_disk=create_disk=='true'; disk_size_bytes=int(disk_size_gib)*1024**3
if create_disk and not 1<=int(disk_size_gib)<=10240: raise SystemExit('New disk size must be between 1 and 10240 GiB')
ensure_vm_name_not_pacemaker_managed(name)
base=['virsh','-c','qemu:///system']
def run(args):
 r=subprocess.run(args,capture_output=True,text=True,timeout=40)
 if r.returncode: raise SystemExit(r.stderr.strip() or r.stdout.strip() or 'Libvirt command failed')
 return r.stdout
domain_names={line.strip() for line in run(base+['list','--all','--name']).splitlines() if line.strip()}
if name in domain_names:
 info={}
 for line in run(base+['dominfo',name]).splitlines():
  if ':' in line:
   key,value=line.split(':',1); info[key.strip().lower()]=value.strip()
 identity=(' (UUID '+info['uuid']+')') if info.get('uuid') else ''
 state=('; state: '+info['state']) if info.get('state') else ''
 raise SystemExit('Libvirt already has a domain named '+name+identity+state+'. It may be stopped or hidden by the current inventory filter; refresh the VM list and check this host before retrying.')
pool_names=[line.strip() for line in run(base+['pool-list','--all','--name']).splitlines() if line.strip()]
if pool not in pool_names: raise SystemExit('The selected storage pool does not exist')
pool_xml=ET.fromstring(run(base+['pool-dumpxml',pool]))
pool_type=pool_xml.get('type','')
pool_target=pool_xml.find('./target/path')
pool_path=pool_target.text.strip() if pool_target is not None and pool_target.text else ''
if create_disk and pool_type!='dir': raise SystemExit('Creating a new boot disk requires a directory-based storage pool; select a running directory pool or use an existing volume')
if iso_url and (pool_type not in ('dir','netfs','fs') or not pool_path or not os.path.isdir(pool_path)): raise SystemExit('Remote ISO downloads require an active directory-based storage pool')
image_template=None; image_type=None
if image_id:
 if not re.fullmatch(r'[a-f0-9]{32}',image_id): raise SystemExit('Invalid image-library reference')
 for candidate in pool_names:
  candidate_xml=ET.fromstring(run(base+['pool-dumpxml',candidate])); target=candidate_xml.find('./target/path')
  if candidate_xml.get('type')!='dir' or target is None or not target.text: continue
  library=os.path.join(target.text.strip(),'.rancher-kvm-image-library'); metadata_path=os.path.join(library,image_id+'.json')
  if not os.path.isfile(metadata_path) or os.path.islink(metadata_path) or os.path.islink(library): continue
  with open(metadata_path,encoding='utf-8') as source: metadata=json.load(source)
  image_path=os.path.join(library,image_id+'.'+('iso' if metadata.get('type')=='iso' else 'qcow2'))
  if metadata.get('id')!=image_id or not os.path.isfile(image_path) or os.path.islink(image_path): raise SystemExit('The selected image is missing or its catalog entry is invalid')
  if os.path.realpath(image_path)!=os.path.join(os.path.realpath(library),os.path.basename(image_path)): raise SystemExit('The selected image path is invalid')
  image_template=image_path; image_type=metadata.get('type'); break
 if not image_template: raise SystemExit('The selected image is no longer available in this host library; refresh the catalog')
 if image_type=='iso': iso_path=image_template
 elif image_type!='qcow2': raise SystemExit('The selected library image type is not supported')
if not create_disk:
 volume_xml=ET.fromstring(run(base+['vol-dumpxml',volume,'--pool',pool]))
 volume_format=volume_xml.find('./target/format')
 disk_format=volume_format.get('type','') if volume_format is not None else ''
 if disk_format not in ('qcow2','raw'): raise SystemExit('The selected disk volume must use qcow2 or raw format')
 disk_path=run(base+['vol-path',volume,'--pool',pool]).strip()
 if not disk_path or not os.path.exists(disk_path): raise SystemExit('The selected disk volume path is not present on the host')
# Keep the all-networks existence check separate from the active-only check.
# `net-list --name` returns active networks without parsing localized `net-info` text.
network_names=[line.strip() for line in run(base+['net-list','--all','--name']).splitlines() if line.strip()]
if network not in network_names: raise SystemExit('The selected virtual network does not exist')
active_networks={line.strip() for line in run(base+['net-list','--name']).splitlines() if line.strip()}
if network not in active_networks: raise SystemExit('The selected virtual network is not active. Start it in Network > Libvirt virtual networks, then retry.')
if iso_path:
 if not os.path.isabs(iso_path) or not iso_path.lower().endswith('.iso') or not os.path.isfile(iso_path): raise SystemExit('The installer ISO path is invalid or the file does not exist')
if iso_url:
 max_bytes=8*1024*1024*1024; reserve=256*1024*1024
 def validate_url(url):
  from urllib.parse import urlsplit
  parsed=urlsplit(url)
  if parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password or parsed.port not in (None,443) or parsed.fragment or not parsed.path.lower().endswith('.iso'): raise RuntimeError('The remote ISO URL or redirect is not allowed')
  addresses={ipaddress.ip_address(row[4][0].split('%',1)[0]) for row in socket.getaddrinfo(parsed.hostname,443,type=socket.SOCK_STREAM)}
  if not addresses or any(not address.is_global for address in addresses): raise RuntimeError('The remote ISO host must resolve only to public addresses')
  return parsed
 class SafeRedirect(urllib.request.HTTPRedirectHandler):
  def redirect_request(self,req,fp,code,msg,headers,newurl):
   validate_url(newurl)
   return super().redirect_request(req,fp,code,msg,headers,newurl)
 parsed=validate_url(iso_url)
 safe_name=os.path.basename(parsed.path)
 safe_name=re.sub(r'[^A-Za-z0-9_.+-]','_',safe_name)[:180]
 if not safe_name.lower().endswith('.iso'): raise SystemExit('The remote file name must end in .iso')
 cache_dir=os.path.join(pool_path,'.rancher-kvm-iso-cache')
 # Installer ISOs are readable artifacts consumed by the unprivileged QEMU
 # process. Every parent directory must be traversable by that account too.
 # Keep the shared cache directory world-traversable/readable and repair its
 # mode on existing pools created by an earlier extension release.
 os.makedirs(cache_dir,mode=0o755,exist_ok=True)
 os.chmod(cache_dir,0o755)
 iso_path=os.path.join(cache_dir,hashlib.sha256(iso_url.encode()).hexdigest()[:16]+'-'+safe_name)
 if not os.path.isfile(iso_path) or os.path.getsize(iso_path)<40960:
  if shutil.disk_usage(cache_dir).free < reserve+40960: raise SystemExit('The selected storage pool does not have enough free space for an ISO download')
  opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),SafeRedirect(),urllib.request.HTTPSHandler(context=ssl.create_default_context()))
  part=iso_path+'.part'
  try:
   response=opener.open(iso_url,timeout=45)
   with response:
    final_url=response.geturl(); validate_url(final_url)
    length=response.headers.get('Content-Length')
    if not length or not length.isdigit(): raise RuntimeError('The ISO server did not provide a valid content length')
    expected=int(length)
    if expected<40960 or expected>max_bytes: raise RuntimeError('The ISO size must be between 40 KiB and 8 GiB')
    if shutil.disk_usage(cache_dir).free < expected+reserve: raise RuntimeError('The selected storage pool does not have enough free space for this ISO')
    written=0
    with open(part,'wb') as output:
     while True:
      chunk=response.read(1024*1024)
      if not chunk: break
      written+=len(chunk)
      if written>max_bytes: raise RuntimeError('The ISO exceeded the 8 GiB download limit')
      output.write(chunk)
     output.flush(); os.fsync(output.fileno())
    if written!=expected: raise RuntimeError('The downloaded ISO size did not match the server response')
    os.chmod(part,0o644); os.replace(part,iso_path)
  except Exception as exc:
   try: os.unlink(part)
   except FileNotFoundError: pass
   if isinstance(exc,RuntimeError): raise SystemExit(str(exc))
   raise SystemExit('ISO download failed. Check host internet access, the source URL, and storage free space.')
disk_created=False
if create_disk:
 volume=name+'.qcow2'
 existing=[]
 for line in run(base+['vol-list','--pool',pool]).splitlines():
  fields=line.split()
  if not fields or fields[0].lower()=='name' or set(fields[0])<={'-'}: continue
  existing.append(fields[0])
 if volume in existing: raise SystemExit('A storage volume with the new disk name already exists; choose another VM name or remove the unused volume')
 pool_info=run(base+['pool-info','--bytes',pool])
 if not any(line.lower().startswith('state:') and 'running' in line.lower() for line in pool_info.splitlines()): raise SystemExit('Start the selected storage pool before creating a new boot disk')
 available=next((int(line.split(':',1)[1].strip()) for line in pool_info.splitlines() if line.lower().startswith('available:')),0)
 if image_type=='qcow2':
  info=subprocess.run(['qemu-img','info','--output=json',image_template],capture_output=True,text=True,timeout=60)
  if info.returncode: raise SystemExit(info.stderr.strip() or 'Could not inspect the selected QCOW2 image')
  image_info=json.loads(info.stdout)
  if image_info.get('format')!='qcow2' or image_info.get('backing-filename'): raise SystemExit('Only standalone QCOW2 images without backing files can be used as VM templates')
  disk_size_bytes=int(image_info.get('virtual-size',0))
  if disk_size_bytes<1: raise SystemExit('The selected QCOW2 image has an invalid virtual size')
  if available<disk_size_bytes: raise SystemExit('The selected storage pool does not have enough free space for an independent copy of this QCOW2 image')
  disk_path=os.path.join(pool_path,volume)
  if os.path.exists(disk_path): raise SystemExit('A storage volume with the new disk name already exists; choose another VM name or remove the unused volume')
  try:
   copied=subprocess.run(['qemu-img','convert','-p','-O','qcow2',image_template,disk_path],capture_output=True,text=True,timeout=14400)
   if copied.returncode: raise SystemExit(copied.stderr.strip() or 'Could not create an independent QCOW2 copy')
   os.chmod(disk_path,0o660); run(base+['pool-refresh',pool]); disk_created=True; disk_format='qcow2'
  except Exception:
   try: os.unlink(disk_path)
   except FileNotFoundError: pass
   raise
 else:
  if available<disk_size_bytes: raise SystemExit('The selected storage pool does not have enough free space for the new boot disk')
  run(base+['vol-create-as',pool,volume,str(disk_size_bytes),'--format','qcow2'])
  disk_created=True; disk_format='qcow2'
  try:
   disk_path=run(base+['vol-path',volume,'--pool',pool]).strip()
   if not disk_path or not os.path.exists(disk_path): raise SystemExit('The newly created boot disk path is not available on the host')
  except SystemExit:
   subprocess.run(base+['vol-delete',volume,'--pool',pool],capture_output=True,text=True,timeout=30)
   raise
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
video=ET.SubElement(devices,'video')
ET.SubElement(video,'model',{'type':'vga'})
graphics=ET.SubElement(devices,'graphics',{'type':'vnc','port':'-1','autoport':'yes','listen':'127.0.0.1'})
ET.SubElement(graphics,'listen',{'type':'address','address':'127.0.0.1'})
iface=ET.SubElement(devices,'interface',{'type':'network'})
ET.SubElement(iface,'source',{'network':network})
ET.SubElement(iface,'model',{'type':'virtio'})
serial=ET.SubElement(devices,'serial',{'type':'pty'})
ET.SubElement(serial,'target',{'port':'0'})
console=ET.SubElement(devices,'console',{'type':'pty'})
ET.SubElement(console,'target',{'type':'serial','port':'0'})
fd,path=tempfile.mkstemp(prefix='kvm-vm-create-',suffix='.xml')
domain_defined=False
try:
 with os.fdopen(fd,'w',encoding='utf-8') as f: f.write(ET.tostring(domain,encoding='unicode'))
 run(base+['define',path])
 domain_defined=True
 if autostart=='true': run(base+['autostart',name])
 run(base+['start',name])
except SystemExit:
 if disk_created and not domain_defined:
  subprocess.run(base+['vol-delete',volume,'--pool',pool],capture_output=True,text=True,timeout=30)
 raise
finally:
 try: os.unlink(path)
 except FileNotFoundError: pass
'''
    def safe_creation_diagnostic(error: Exception) -> str:
        detail = str(error).strip() or "The remote command failed without returning a diagnostic"
        for secret in (host.get("password"), host.get("private_key"), host.get("key_passphrase"), payload.iso_url, payload.iso_path):
            if secret:
                detail = detail.replace(secret, "[redacted]")
        return re.sub(r"\s+", " ", detail).strip()[:500]

    if payload.iso_url or (payload.image_id and payload.create_disk):
        def download_and_create(remote_host: dict[str, Any]) -> dict[str, Any]:
            try:
                output = run_sudo_python(remote_host, creation_script, [payload.name, payload.pool, payload.volume or "", payload.network, str(payload.vcpus), str(payload.memory_mib), payload.iso_path or "", payload.iso_url or "", str(payload.autostart).lower(), str(payload.create_disk).lower(), str(payload.disk_size_gib), payload.image_id or ""], timeout=14400)
                record_audit(access.user_id, "vm.create", f"{host_id}/{payload.name}", detail=f"pool={payload.pool}; disk={'new-qcow2' if payload.create_disk else payload.volume}; vcpus={payload.vcpus}; memory_mib={payload.memory_mib}; image_library={bool(payload.image_id)}")
                return {"status": "completed", "vm_name": payload.name, "message": output[:240]}
            except Exception as exc:
                record_audit(access.user_id, "vm.create", f"{host_id}/{payload.name}", "failure", "Could not create VM from the selected boot source")
                raise RuntimeError(safe_creation_diagnostic(exc)) from exc
        return create_operation_job("vm_create", access.user_id, [host], download_and_create)
    try:
        run_sudo_python(host, creation_script, [payload.name, payload.pool, payload.volume or "", payload.network, str(payload.vcpus), str(payload.memory_mib), payload.iso_path or "", payload.iso_url or "", str(payload.autostart).lower(), str(payload.create_disk).lower(), str(payload.disk_size_gib), payload.image_id or ""], timeout=14400 if payload.iso_url or payload.image_id else 75)
    except Exception as exc:
        record_audit(access.user_id, "vm.create", f"{host_id}/{payload.name}", "failure", "Could not create VM with the selected resources")
        raise HTTPException(502, f"Could not create the VM on {host.get('name', host_id)}: {safe_creation_diagnostic(exc)}") from exc
    record_audit(access.user_id, "vm.create", f"{host_id}/{payload.name}", detail=f"pool={payload.pool}; disk={'new-qcow2' if payload.create_disk else payload.volume}; vcpus={payload.vcpus}; memory_mib={payload.memory_mib}")
    return {"success": True}


@app.post("/kvm-api/hosts/{host_id}/vms/devices")
def configure_vm_devices(host_id: str, payload: VMDeviceAction, vm_name: str, access: AuthorizationContext = Depends(require_permission("vm_operator"))) -> dict[str, bool]:
    host = cockpit_host_record(host_id)
    encoded_name = base64.b64encode(vm_name.encode()).decode()
    device_script = VM_PACEMAKER_VM_GUARD_SCRIPT + r'''import base64,os,re,subprocess,sys,tempfile,xml.etree.ElementTree as ET
name=base64.b64decode(sys.argv[1]).decode(); action,pool,volume,target,network,mac=sys.argv[2:]
base=['virsh','-c','qemu:///system']
def run(args):
 r=subprocess.run(args,capture_output=True,text=True,timeout=35)
 if r.returncode: raise SystemExit(r.stderr.strip() or r.stdout.strip() or 'Libvirt command failed')
 return r.stdout
domain_names=[line.strip() for line in run(base+['list','--all','--name']).splitlines() if line.strip()]
if name not in domain_names: raise SystemExit('Virtual machine not found')
ensure_vm_not_pacemaker_managed(name)
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
 configured_networks={source.get('network','') for source in devices.findall('./interface/source') if source.get('network')}
 if network in configured_networks: raise SystemExit('This virtual network is already configured on this VM')
 active_networks={line.strip() for line in run(base+['net-list','--name']).splitlines() if line.strip()}
 if network not in active_networks: raise SystemExit('The selected libvirt network is not active. Start it in Network > Libvirt virtual networks, then retry.')
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
    snapshot_script = VM_PACEMAKER_VM_GUARD_SCRIPT + r'''import base64,datetime,re,subprocess,sys,xml.etree.ElementTree as ET
domain=base64.b64decode(sys.argv[1]).decode(); action,name,description=sys.argv[2:]
base=['virsh','-c','qemu:///system']
def run(args):
 r=subprocess.run(args,capture_output=True,text=True,timeout=50)
 if r.returncode: raise SystemExit(r.stderr.strip() or r.stdout.strip() or 'Libvirt command failed')
 return r.stdout
if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}',name): raise SystemExit('Invalid snapshot name')
if domain not in [line.strip() for line in run(base+['list','--all','--name']).splitlines()]: raise SystemExit('Virtual machine not found')
ensure_vm_not_pacemaker_managed(domain)
state=run(base+['domstate',domain]).strip().lower()
if 'shut off' not in state and 'shutoff' not in state: raise SystemExit('Shut down the VM before changing snapshots')
names=[line.strip() for line in run(base+['snapshot-list',domain,'--name']).splitlines() if line.strip()]
if action=='create':
 if name in names: raise SystemExit('A snapshot with this name already exists')
 root=ET.fromstring(run(base+['dumpxml','--inactive',domain]))
 disks=[disk for disk in root.findall('./devices/disk') if disk.get('device','disk')=='disk' and disk.find('./readonly') is None]
 if not disks or any(disk.find('./driver') is None or disk.find('./driver').get('type','').lower()!='qcow2' for disk in disks): raise SystemExit('Internal snapshots require every writable VM disk to use qcow2 format')
 version='v'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
 snapshot_description=(description.strip()+'\n' if description.strip() else '')+'Rancher-KVM-Version: '+version
 run(base+['snapshot-create-as',domain,'--name',name,'--description',snapshot_description,'--atomic'])
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


@app.get("/kvm-api/hosts/{host_id}/vms/snapshots", dependencies=[Depends(require_permission("viewer"))])
def list_vm_snapshots(host_id: str) -> list[dict[str, Any]]:
    host = cockpit_host_record(host_id)
    script = r'''import datetime,json,re,subprocess,xml.etree.ElementTree as ET
base=['virsh','-c','qemu:///system']
def run(args):
 r=subprocess.run(args,capture_output=True,text=True,timeout=25)
 if r.returncode: raise RuntimeError(r.stderr.strip() or r.stdout.strip() or 'Libvirt query failed')
 return r.stdout
names=[line.strip() for line in run(base+['list','--all','--name']).splitlines() if line.strip()]
items=[]
for domain in names:
 try: snapshot_names=[line.strip() for line in run(base+['snapshot-list',domain,'--name']).splitlines() if line.strip()]
 except Exception: continue
 for name in snapshot_names:
  try:
   root=ET.fromstring(run(base+['snapshot-dumpxml',domain,name])); raw=root.findtext('./description','')
   match=re.search(r'(?m)^Rancher-KVM-Version: (v[0-9TZ.-]+)$',raw)
   created=root.findtext('./creationTime','')
   version=match.group(1) if match else ('legacy-'+created if created else 'legacy')
   description=re.sub(r'(?m)^Rancher-KVM-Version: v[0-9TZ.-]+\s*$', '', raw).strip()
   items.append({'vm_name':domain,'name':name,'state':root.findtext('./state','unknown'),'created_at':created,'description':description,'version':version})
  except Exception: continue
items.sort(key=lambda item:(item['vm_name'].lower(),int(item['created_at'] or 0),item['name'].lower()),reverse=False)
print(json.dumps(items))
'''
    try:
        return json.loads(run_sudo_python(host, script, timeout=90) or "[]")
    except Exception as exc:
        raise HTTPException(502, f"Could not list VM snapshots: {exc}") from exc


@app.get("/kvm-api/hosts/{host_id}/vms/snapshots/download")
def download_vm_snapshot(host_id: str, vm_name: str, snapshot_name: str, access: AuthorizationContext = Depends(require_permission("vm_operator"))) -> StreamingResponse:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", snapshot_name):
        raise HTTPException(422, "Invalid snapshot name")
    host = cockpit_host_record(host_id)
    script = VM_PACEMAKER_VM_GUARD_SCRIPT + r'''import json,os,re,shutil,subprocess,sys,tarfile,tempfile,xml.etree.ElementTree as ET
domain,snapshot=sys.argv[1:]
base=['virsh','-c','qemu:///system']
def run(args,timeout=60):
 r=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
 if r.returncode: raise RuntimeError(r.stderr.strip() or r.stdout.strip() or 'Snapshot export failed')
 return r.stdout
if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}',domain) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}',snapshot): raise SystemExit('Invalid VM or snapshot name')
if domain not in [line.strip() for line in run(base+['list','--all','--name']).splitlines()]: raise SystemExit('Virtual machine not found')
ensure_vm_not_pacemaker_managed(domain)
if snapshot not in [line.strip() for line in run(base+['snapshot-list',domain,'--name']).splitlines()]: raise SystemExit('Snapshot not found')
state=run(base+['domstate',domain]).strip().lower()
if 'shut off' not in state and 'shutoff' not in state: raise SystemExit('Shut down the VM before exporting a snapshot')
root=ET.fromstring(run(base+['dumpxml','--inactive',domain]))
disks=[]
for disk in root.findall('./devices/disk'):
 if disk.get('device','disk')!='disk' or disk.find('./readonly') is not None: continue
 driver=disk.find('./driver'); source=disk.find('./source'); target=disk.find('./target')
 if driver is None or driver.get('type','').lower()!='qcow2' or source is None or not source.get('file'):
  raise SystemExit('Snapshot export requires writable qcow2 file-backed disks')
 target_name=target.get('dev','disk') if target is not None else 'disk'
 if not re.fullmatch(r'[A-Za-z0-9_.-]{1,32}',target_name): raise SystemExit('The VM contains a disk with an unsupported device name')
 disks.append((source.get('file'),target_name))
if not disks: raise SystemExit('No writable VM disks were found')
if not shutil.which('qemu-img'): raise SystemExit('qemu-img is unavailable on the KVM host')
with tempfile.TemporaryDirectory(prefix='rancher-kvm-snapshot-') as temp:
 required=0
 for source,target in disks:
  measured=subprocess.run(['qemu-img','measure','--output=json','-f','qcow2','-O','qcow2','-l','snapshot.name='+snapshot,source],capture_output=True,text=True,timeout=60)
  if measured.returncode: raise SystemExit(measured.stderr.strip() or 'Could not estimate snapshot export space')
  try: required+=int(json.loads(measured.stdout).get('required',0))
  except (ValueError,TypeError): raise SystemExit('Could not estimate snapshot export space')
 if shutil.disk_usage(temp).free < int(required*1.05): raise SystemExit('Not enough free space on the KVM host to prepare this snapshot export')
 entries=[]
 for index,(source,target) in enumerate(disks):
  if not os.path.isfile(source): raise SystemExit('A snapshot disk is not an accessible regular file')
  output=os.path.join(temp,'disk-'+str(index+1)+'.qcow2')
  run(['qemu-img','convert','-f','qcow2','-O','qcow2','-l','snapshot.name='+snapshot,source,output],timeout=3600)
  entries.append((output,target+'.qcow2'))
 sys.stdout.buffer.write(b'KVM_SNAPSHOT_ARCHIVE_START\n'); sys.stdout.buffer.flush()
 with tarfile.open(fileobj=sys.stdout.buffer,mode='w|gz') as archive:
  manifest=('VM: '+domain+'\nSnapshot: '+snapshot+'\nDisks: '+str(len(entries))+'\n').encode()
  import io
  info=tarfile.TarInfo('manifest.txt'); info.size=len(manifest); archive.addfile(info,io.BytesIO(manifest))
  for path,filename in entries: archive.add(path,arcname=filename,recursive=False)
'''
    client = ssh_client_for_host(host)
    channel = None
    try:
        command = f"sudo -S -p '' python3 -c {shlex.quote(script)} {shlex.quote(vm_name)} {shlex.quote(snapshot_name)}"
        _stdin, stdout, stderr = client.exec_command(command, timeout=3700)
        channel = stdout.channel
        _stdin.write(host["password"] + "\n")
        _stdin.flush()
        _stdin.channel.shutdown_write()
        marker = b"KVM_SNAPSHOT_ARCHIVE_START\n"
        preamble = bytearray()
        initial = b""
        deadline = time.monotonic() + 3700
        while marker not in preamble:
            if time.monotonic() > deadline:
                raise HTTPException(504, "Snapshot export timed out while preparing the archive")
            if channel.recv_ready():
                preamble.extend(channel.recv(65536))
                if len(preamble) > 65536 and marker not in preamble:
                    raise HTTPException(502, "The KVM host returned an invalid snapshot archive response")
                continue
            if channel.exit_status_ready():
                detail = stderr.read().decode("utf-8", "replace").strip()
                raise HTTPException(502, detail or "Could not prepare the snapshot archive on the KVM host")
            time.sleep(0.05)
        marker_at = preamble.index(marker)
        initial = bytes(preamble[marker_at + len(marker):])
        if preamble[:marker_at].strip():
            raise HTTPException(502, "The KVM host returned an invalid snapshot archive response")
    except HTTPException:
        if channel:
            channel.close()
        client.close()
        raise
    except Exception as exc:
        if channel:
            channel.close()
        client.close()
        raise HTTPException(502, f"Could not start snapshot export: {exc}") from exc

    def stream_archive():
        try:
            if initial:
                yield initial
            while True:
                if channel.recv_ready():
                    yield channel.recv(65536)
                    continue
                if channel.exit_status_ready():
                    if channel.recv_ready():
                        continue
                    status = channel.recv_exit_status()
                    if status:
                        performance_logger.warning("snapshot_export_stream_failed host=%s vm=%s snapshot=%s status=%s", host_id, vm_name, snapshot_name, status)
                    break
                time.sleep(0.05)
        finally:
            channel.close()
            client.close()

    filename = f"{vm_name}-{snapshot_name}.tar.gz"
    safe_filename = re.sub(r"[^A-Za-z0-9_.-]", "_", filename)
    record_audit(access.user_id, "vm.snapshot.download", f"{host_id}/{vm_name}/{snapshot_name}")
    return StreamingResponse(stream_archive(), media_type="application/gzip", headers={
        "Content-Disposition": f'attachment; filename="{safe_filename}"',
        "Cache-Control": "no-store",
    })


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


@app.post("/kvm-api/hosts/{host_id}/vms/graphics-config")
def configure_vm_graphics(host_id: str, payload: VMGraphicsConfig, vm_name: str, access: AuthorizationContext = Depends(require_permission("vm_operator"))) -> dict[str, Any]:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", vm_name):
        raise HTTPException(422, "Invalid virtual machine name")
    host = cockpit_host_record(host_id)
    try:
        output = run_sudo_python(host, VM_GRAPHICS_CONFIG_SCRIPT, [vm_name], timeout=35)
    except Exception as exc:
        record_audit(access.user_id, "vm.graphics.configure", f"{host_id}/{vm_name}", "failure", "Could not enable VNC graphics")
        message = str(exc)
        if "Stop this virtual machine" in message:
            raise HTTPException(409, message) from exc
        if "different graphics protocol" in message:
            raise HTTPException(409, message) from exc
        raise HTTPException(502, f"Could not enable VNC graphics: {message}") from exc
    record_audit(access.user_id, "vm.graphics.configure", f"{host_id}/{vm_name}", detail="Added a loopback-only VNC display to the persistent VM definition")
    return {"success": True, "message": output or "VNC graphics enabled"}


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


@app.get("/kvm-api/hosts/{host_id}/cloud-native")
def get_host_cloud_native(host_id: str, access: AuthorizationContext = Depends(require_permission("viewer"))) -> dict[str, Any]:
    host = cockpit_host_record(host_id)
    try:
        output = run_sudo_python(host, HOST_ADMIN_SCRIPT, timeout=90)
        inventory = json.loads(output or "{}")
        if "subscription_admin" not in access.permissions:
            # SUSEConnect's registration code is a credential. Keep it out of
            # the viewer inventory response and expose it only to subscription admins.
            for product in inventory.get("subscription", {}).get("products", []):
                product.pop("registration_code", None)
        return inventory
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
def configure_storage_volume(host_id: str, payload: StorageVolumeConfig, access: AuthorizationContext = Depends(require_permission("storage_admin"))) -> dict[str, Any]:
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


MAX_LIBRARY_IMAGE_BYTES = 8 * 1024**3

IMAGE_LIBRARY_LIST_SCRIPT = r'''import json,os,re,subprocess,xml.etree.ElementTree as ET
base=['virsh','-c','qemu:///system']
def run(args):
 p=subprocess.run(args,capture_output=True,text=True,timeout=45)
 if p.returncode: raise RuntimeError(p.stderr.strip() or p.stdout.strip() or 'Libvirt command failed')
 return p.stdout
images=[]
for pool in [x.strip() for x in run(base+['pool-list','--all','--name']).splitlines() if x.strip()]:
 try:
  root=ET.fromstring(run(base+['pool-dumpxml',pool])); target=root.find('./target/path')
  if root.get('type')!='dir' or target is None or not target.text: continue
  library=os.path.join(target.text.strip(),'.rancher-kvm-image-library')
  if not os.path.isdir(library) or os.path.islink(library): continue
  for entry in os.scandir(library):
   if not entry.name.endswith('.json') or not re.fullmatch(r'[a-f0-9]{32}\.json',entry.name) or not entry.is_file(follow_symlinks=False): continue
   try:
    with open(entry.path,encoding='utf-8') as f: image=json.load(f)
    image_id=entry.name[:-5]; kind=image.get('type'); suffix='iso' if kind=='iso' else 'qcow2' if kind=='qcow2' else ''
    path=os.path.join(library,image_id+'.'+suffix) if suffix else ''
    if image.get('id')!=image_id or not path or not os.path.isfile(path) or os.path.islink(path): continue
    image.pop('path',None); image['pool']=pool; images.append(image)
   except (OSError,ValueError,TypeError): continue
 except Exception: continue
print(json.dumps(sorted(images,key=lambda item:(item.get('name','').lower(),item.get('imported_at','')))))
'''

IMAGE_LIBRARY_IMPORT_SCRIPT = r'''import hashlib,json,os,re,shutil,subprocess,sys,tempfile,uuid,xml.etree.ElementTree as ET
metadata=json.load(sys.stdin); upload_path=sys.argv[1]; expected_sha=sys.argv[2]
base=['virsh','-c','qemu:///system']; pool=metadata['pool']; kind=metadata['type']
if not re.fullmatch(r'[A-Za-z0-9_.+-]{1,128}',pool): raise SystemExit('Invalid storage pool')
def run(args):
 p=subprocess.run(args,capture_output=True,text=True,timeout=60)
 if p.returncode: raise RuntimeError(p.stderr.strip() or p.stdout.strip() or 'Libvirt command failed')
 return p.stdout
root=ET.fromstring(run(base+['pool-dumpxml',pool])); target=root.find('./target/path')
if root.get('type')!='dir' or target is None or not target.text: raise SystemExit('The image library requires a directory-based libvirt storage pool')
pool_path=target.text.strip()
if not os.path.isdir(pool_path): raise SystemExit('The selected storage pool target directory is not available')
size=os.path.getsize(upload_path)
if kind=='iso' and not 40960<=size<=8*1024**3: raise SystemExit('ISO images must be between 40 KiB and 8 GiB')
if kind=='qcow2' and not 1<=size<=8*1024**3: raise SystemExit('QCOW2 images must be between 1 byte and 8 GiB')
if kind=='iso':
 with open(upload_path,'rb') as source:
  source.seek(32769)
  if source.read(5)!=b'CD001': raise SystemExit('The uploaded file does not contain a valid ISO 9660 volume descriptor')
digest=hashlib.sha256()
with open(upload_path,'rb') as source:
 for chunk in iter(lambda:source.read(1024*1024),b''): digest.update(chunk)
if digest.hexdigest()!=expected_sha: raise SystemExit('Uploaded image checksum mismatch; retry the upload')
virtual_size=0
if kind=='qcow2':
 info=subprocess.run(['qemu-img','info','--output=json',upload_path],capture_output=True,text=True,timeout=60)
 if info.returncode: raise SystemExit(info.stderr.strip() or 'The uploaded file is not a valid QCOW2 image')
 parsed=json.loads(info.stdout)
 if parsed.get('format')!='qcow2' or parsed.get('backing-filename'): raise SystemExit('Upload a standalone QCOW2 image without a backing file')
 virtual_size=int(parsed.get('virtual-size',0))
 if virtual_size<1: raise SystemExit('The QCOW2 virtual size is invalid')
elif kind!='iso': raise SystemExit('Image type must be ISO or QCOW2')
pool_info=run(base+['pool-info','--bytes',pool])
if not any(line.lower().startswith('state:') and 'running' in line.lower() for line in pool_info.splitlines()): raise SystemExit('Start the selected storage pool before importing an image')
free=next((int(line.split(':',1)[1].strip()) for line in pool_info.splitlines() if line.lower().startswith('available:')),0)
needed=virtual_size if kind=='qcow2' else size
if free<needed+64*1024*1024: raise SystemExit('The selected storage pool needs more free space for this image')
library=os.path.join(pool_path,'.rancher-kvm-image-library'); os.makedirs(library,mode=0o755,exist_ok=True); os.chmod(library,0o755)
image_id=uuid.uuid4().hex; filename=image_id+'.'+kind
destination=os.path.join(library,filename); part=destination+'.part'
try:
 shutil.copyfile(upload_path,part); os.chmod(part,0o644); os.replace(part,destination)
 metadata.update({'id':image_id,'size_bytes':size,'virtual_size_bytes':virtual_size,'sha256':expected_sha,'imported_at':__import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat()})
 meta_path=os.path.join(library,image_id+'.json'); meta_part=meta_path+'.part'
 with open(meta_part,'w',encoding='utf-8') as f: json.dump(metadata,f,ensure_ascii=False); f.flush(); os.fsync(f.fileno())
 os.chmod(meta_part,0o644); os.replace(meta_part,meta_path)
except Exception:
 for path in (part,destination,os.path.join(library,image_id+'.json.part')):
  try: os.unlink(path)
  except FileNotFoundError: pass
 raise
print(json.dumps(metadata))
'''

IMAGE_LIBRARY_DELETE_SCRIPT = r'''import json,os,re,subprocess,sys,xml.etree.ElementTree as ET
image_id=sys.argv[1]
if not re.fullmatch(r'[a-f0-9]{32}',image_id): raise SystemExit('Invalid image ID')
base=['virsh','-c','qemu:///system']
def run(args):
 p=subprocess.run(args,capture_output=True,text=True,timeout=45)
 if p.returncode: raise RuntimeError(p.stderr.strip() or p.stdout.strip() or 'Libvirt command failed')
 return p.stdout
found=None
for pool in [x.strip() for x in run(base+['pool-list','--all','--name']).splitlines() if x.strip()]:
 try:
  root=ET.fromstring(run(base+['pool-dumpxml',pool])); target=root.find('./target/path')
  if root.get('type')!='dir' or target is None or not target.text: continue
  library=os.path.join(target.text.strip(),'.rancher-kvm-image-library'); meta=os.path.join(library,image_id+'.json')
  if os.path.isfile(meta) and not os.path.islink(meta): found=(pool,library,meta); break
 except Exception: continue
if not found: raise SystemExit('Image not found in the host library')
pool,library,meta=found
with open(meta,encoding='utf-8') as f: image=json.load(f)
suffix='iso' if image.get('type')=='iso' else 'qcow2' if image.get('type')=='qcow2' else ''
if image.get('id')!=image_id or not suffix: raise SystemExit('Image catalog entry is invalid')
path=os.path.join(library,image_id+'.'+suffix)
if not os.path.isfile(path) or os.path.islink(path) or os.path.realpath(os.path.dirname(path))!=os.path.realpath(library): raise SystemExit('Image file is missing or has an invalid path')
for domain in [x.strip() for x in run(base+['list','--all','--name']).splitlines() if x.strip()]:
 try:
  xml=ET.fromstring(run(base+['dumpxml',domain]))
  sources=xml.findall('./devices/disk/source')+xml.findall('./devices/disk/backingStore/source')
  if any(path in source.attrib.values() for source in sources): raise SystemExit('This image is attached to virtual machine '+domain+' and cannot be deleted')
 except SystemExit: raise
 except Exception as error: raise SystemExit('Could not verify whether the image is attached to every VM; deletion was stopped safely: '+str(error))
os.unlink(path); os.unlink(meta); print(json.dumps({'deleted':True,'id':image_id}))
'''


@app.get("/kvm-api/hosts/{host_id}/images", dependencies=[Depends(require_permission("viewer"))])
def list_host_images(host_id: str) -> list[dict[str, Any]]:
    try:
        return json.loads(run_sudo_python(cockpit_host_record(host_id), IMAGE_LIBRARY_LIST_SCRIPT, timeout=75) or "[]")
    except Exception as exc:
        raise HTTPException(502, f"Could not list the host image library: {exc}") from exc


@app.post("/kvm-api/hosts/{host_id}/images")
async def upload_host_image(host_id: str, request: Request, pool: str, name: str, image_type: Literal["iso", "qcow2"], category: str = "other", os_name: str = "", version: str = "", description: str = "", filename: str = "", access: AuthorizationContext = Depends(require_permission("storage_admin"))) -> dict[str, Any]:
    safe_filename = os.path.basename(filename.replace("\\", "/"))
    expected_suffix = "." + image_type
    if not safe_filename or len(safe_filename) > 180 or not safe_filename.lower().endswith(expected_suffix):
        raise HTTPException(422, f"The file name must end in {expected_suffix}")
    if not re.fullmatch(r"[A-Za-z0-9_.+-]{1,128}", pool):
        raise HTTPException(422, "Invalid storage pool name")
    if not name.strip() or len(name.strip()) > 100 or category not in {"operating-system", "utility", "test", "other"} or len(os_name) > 80 or len(version) > 40 or len(description) > 512:
        raise HTTPException(422, "Image name or catalog details exceed the supported limits")
    if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/octet-stream":
        raise HTTPException(415, "Upload the image as application/octet-stream")
    declared = request.headers.get("content-length")
    if declared and (not declared.isdigit() or int(declared) > MAX_LIBRARY_IMAGE_BYTES):
        raise HTTPException(413, "Image uploads are limited to 8 GiB")
    host = cockpit_host_record(host_id)
    remote_path = f"/tmp/.rancher-kvm-image-upload-{uuid.uuid4().hex}"
    client = None
    sftp = None
    remote_file = None
    written = 0
    digest = hashlib.sha256()
    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="kvm-image-upload")
    loop = asyncio.get_running_loop()
    try:
        client = await loop.run_in_executor(executor, lambda: ssh_client_for_host(host))
        sftp = await loop.run_in_executor(executor, client.open_sftp)
        remote_file = await loop.run_in_executor(executor, lambda: sftp.open(remote_path, "wb"))
        async for chunk in request.stream():
            if not chunk:
                continue
            written += len(chunk)
            if written > MAX_LIBRARY_IMAGE_BYTES:
                raise HTTPException(413, "Image uploads are limited to 8 GiB")
            digest.update(chunk)
            await loop.run_in_executor(executor, remote_file.write, chunk)
        await loop.run_in_executor(executor, remote_file.flush)
        await loop.run_in_executor(executor, remote_file.close)
        remote_file = None
        await loop.run_in_executor(executor, sftp.close)
        sftp = None
        await loop.run_in_executor(executor, client.close)
        client = None
    except HTTPException:
        raise
    except Exception as exc:
        record_audit(access.user_id, "image.upload", f"{host_id}/{safe_filename}", "failure", "Image upload over SSH failed")
        raise HTTPException(502, f"Could not upload the image to {host.get('name', host_id)} over SSH: {str(exc)[:300]}") from exc
    finally:
        if remote_file:
            try: await loop.run_in_executor(executor, remote_file.close)
            except Exception: pass
        if sftp:
            try:
                await loop.run_in_executor(executor, lambda: sftp.remove(remote_path))
                await loop.run_in_executor(executor, sftp.close)
            except Exception: pass
        if client:
            try: await loop.run_in_executor(executor, client.close)
            except Exception: pass
        executor.shutdown(wait=False, cancel_futures=True)
    if written < (40960 if image_type == "iso" else 1):
        try: run_sudo_python(host, "import os,sys; os.unlink(sys.argv[1]) if os.path.exists(sys.argv[1]) else None", [remote_path], timeout=15)
        except Exception: pass
        raise HTTPException(422, "The uploaded image is empty or too small")
    metadata = {"pool": pool, "name": name.strip(), "type": image_type, "category": category, "os_name": os_name.strip()[:80], "version": version.strip()[:40], "description": description.strip()[:512], "filename": safe_filename}
    def cleanup_remote_upload() -> None:
        run_sudo_python(host, "import os,sys; os.unlink(sys.argv[1]) if os.path.exists(sys.argv[1]) else None", [remote_path], timeout=15)
    try:
        output = await loop.run_in_executor(None, lambda: run_sudo_python(host, IMAGE_LIBRARY_IMPORT_SCRIPT, [remote_path, digest.hexdigest()], timeout=300, stdin_data=json.dumps(metadata)))
    except Exception as exc:
        try: await loop.run_in_executor(None, cleanup_remote_upload)
        except Exception: pass
        record_audit(access.user_id, "image.upload", f"{host_id}/{safe_filename}", "failure", str(exc)[:500])
        raise HTTPException(422, f"Could not add image to the library: {str(exc)[:400]}") from exc
    try: await loop.run_in_executor(None, cleanup_remote_upload)
    except Exception: performance_logger.warning("image_upload_temp_cleanup_failed host=%s", host_id)
    record_audit(access.user_id, "image.upload", f"{host_id}/{safe_filename}", detail=f"type={image_type}; bytes={written}; pool={pool}")
    return json.loads(output)


@app.delete("/kvm-api/hosts/{host_id}/images/{image_id}")
def delete_host_image(host_id: str, image_id: str, access: AuthorizationContext = Depends(require_permission("storage_admin"))) -> dict[str, Any]:
    if not re.fullmatch(r"[a-f0-9]{32}", image_id):
        raise HTTPException(422, "Invalid image ID")
    host = cockpit_host_record(host_id)
    try:
        output = run_sudo_python(host, IMAGE_LIBRARY_DELETE_SCRIPT, [image_id], timeout=120)
    except Exception as exc:
        record_audit(access.user_id, "image.delete", f"{host_id}/{image_id}", "failure", str(exc)[:500])
        raise HTTPException(409, f"Could not delete the library image: {str(exc)[:400]}") from exc
    record_audit(access.user_id, "image.delete", f"{host_id}/{image_id}")
    return json.loads(output or "{}")


@app.post("/kvm-api/hosts/{host_id}/repositories/actions")
def control_repository(host_id: str, payload: RepositoryAction, access: AuthorizationContext = Depends(require_permission("software_admin"))) -> dict[str, bool]:
    if payload.alias != "*" and not re.fullmatch(r"[A-Za-z0-9_.:-]+", payload.alias):
        raise HTTPException(422, "Invalid repository alias")
    host = cockpit_host_record(host_id)
    if payload.action == "add":
        parsed_uri = urlsplit(payload.uri or "")
        if not payload.name or not payload.uri or parsed_uri.scheme not in ("http", "https", "ftp", "file") or (parsed_uri.scheme in ("http", "https", "ftp") and not parsed_uri.hostname):
            raise HTTPException(422, "Enter a repository name and a valid HTTP, HTTPS, FTP, or file URL")
        args = ["zypper", "--non-interactive", "addrepo", "--name", payload.name, payload.uri, payload.alias]
    elif payload.action == "edit":
        if not payload.name or not payload.name.strip():
            raise HTTPException(422, "Enter a descriptive repository name")
        args = ["zypper", "--non-interactive", "modifyrepo", "--name", payload.name.strip(), payload.alias]
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
def control_subscription(host_id: str, payload: SubscriptionAction, access: AuthorizationContext = Depends(require_permission("subscription_admin"))) -> dict[str, bool]:
    host = cockpit_host_record(host_id)
    if payload.action in ("activate_extension", "deactivate_extension"):
        if not payload.product or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+-]*/[A-Za-z0-9][A-Za-z0-9_.+-]*/[A-Za-z0-9][A-Za-z0-9_.+-]*", payload.product):
            raise HTTPException(422, "Enter a valid SUSEConnect product identifier in name/version/architecture format")
        args = [payload.action, payload.product]
        # No-code products (such as Package Hub) must not enter the interactive
        # stdin handshake. Some SUSEConnect builds inherit stdin and otherwise
        # consume that payload before the helper reads it.
        extension_input = json.dumps({"regcode": payload.regcode.strip()}) + "\n" if payload.regcode and payload.regcode.strip() else None
        try:
            run_sudo_python(host, SUBSCRIPTION_EXTENSION_SCRIPT, args, timeout=240, stdin_data=extension_input)
        except Exception as exc:
            record_audit(access.user_id, f"subscription.{payload.action}", f"{host_id}/{payload.product}", "failure", "SUSEConnect add-on operation failed")
            safe_error = str(exc)
            secrets_to_hide = [payload.regcode, host.get("password"), host.get("private_key"), host.get("key_passphrase")]
            for secret in secrets_to_hide:
                if secret:
                    safe_error = safe_error.replace(secret, "[redacted]")
            safe_diagnostic = re.sub(r"\s+", " ", safe_error).strip()[:600]
            performance_logger.error(
                "subscription_extension_failed action=%s host_id=%s product=%s diagnostic=%s",
                payload.action,
                host_id,
                payload.product,
                safe_diagnostic,
            )
            raise HTTPException(502, f"Could not {payload.action.replace('_', ' ')}: {safe_diagnostic}") from exc
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
        safe_error = str(exc).strip() or "The remote command failed without returning a diagnostic"
        secrets_to_hide = [payload.regcode, payload.email, host.get("password"), host.get("private_key"), host.get("key_passphrase")]
        for secret in secrets_to_hide:
            if secret:
                safe_error = safe_error.replace(secret, "[redacted]")
        raise HTTPException(502, f"Could not {payload.action} the SUSE subscription: {safe_error}") from exc
    record_audit(access.user_id, f"subscription.{payload.action}", host_id)
    return {"success": True}


SUBSCRIPTION_EXTENSION_SCRIPT = r'''import json,re,shutil,subprocess,sys
if not shutil.which('SUSEConnect'): raise SystemExit('SUSEConnect is not installed on this host')
action=sys.argv[1]
product=sys.argv[2] if len(sys.argv)>2 else ''
listed=subprocess.run(['SUSEConnect','--list-extensions'],capture_output=True,text=True,timeout=60)
if listed.returncode: raise SystemExit(listed.stderr.strip() or listed.stdout.strip() or 'Could not list available SUSE extensions')
listing_text=re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]','',listed.stdout)
items=[]; label=''
for line in listing_text.splitlines():
 text=line.strip()
 if not text: continue
 match=re.search(r'\bsuseconnect\s+(.*)$',text,re.I)
 if match:
  command=match.group(1)
  product_match=re.search(r'(?:^|\s)-p\s+(\S+)',command)
  if not product_match: continue
  identifier=product_match.group(1)
  if not re.fullmatch(r'[A-Za-z0-9_.+-]+/[A-Za-z0-9_.+-]+/[A-Za-z0-9_.+-]+',identifier): continue
  active=bool(re.search(r'(?:^|\s)-d(?:\s|$)',command)) or bool(re.search(r'\(Activated\)',label,re.I))
  name=re.sub(r'\s*\(Activated\)\s*','',label,flags=re.I).strip()
  if not name or name.startswith(('AVAILABLE EXTENSIONS','REMARKS','MORE INFORMATION')): name=identifier.split('/')[0].replace('-',' ').title()
  items.append({'product':identifier,'name':name,'active':active,'requires_regcode':not active and bool(re.search(r'\-r\s+(?:ADDITIONAL|<)',command,re.I)),'protected':identifier.startswith(('sle-module-basesystem/','sle-module-server-applications/'))})
  label=''
 elif text.upper().startswith(('AVAILABLE EXTENSIONS','REMARKS','MORE INFORMATION')): label=''
 elif not re.match(r'^(Activate|Deactivate) with:',text,re.I) and not text.startswith('('): label=text
if action=='list':
 print(json.dumps(items)); raise SystemExit
item=next((entry for entry in items if entry['product']==product),None)
if item is None: raise SystemExit('The selected product is not available for this host')
if action=='deactivate_extension' and item['protected']: raise SystemExit('This core SUSE module is protected from deactivation')
if action=='activate_extension' and item['active']: raise SystemExit('This extension is already active')
if action=='deactivate_extension' and not item['active']: raise SystemExit('This extension is not active')
data={}
if action=='activate_extension' and item['requires_regcode']:
 print('KVM_STDIN_READY',flush=True)
 try:
  data=json.loads(sys.stdin.readline())
 except (json.JSONDecodeError, TypeError):
  raise SystemExit('Could not read the SUSE registration code. Re-enter the code and retry.')
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
def set_selinux_mode(host_id: str, payload: SecurityModeAction, access: AuthorizationContext = Depends(require_permission("service_admin"))) -> dict[str, bool]:
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
def control_libvirt_resource(host_id: str, resource: Literal["storage-pools", "networks"], payload: NamedAdminAction, access: AuthorizationContext = Depends(require_permission("viewer"))) -> dict[str, bool]:
    required_scope = "storage_admin" if resource == "storage-pools" else "network_admin"
    if required_scope not in access.permissions:
        raise HTTPException(403, f"The {required_scope.replace('_', ' ')} role is required for this KVM operation")
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
def configure_libvirt_network(host_id: str, payload: LibvirtNetworkConfig, access: AuthorizationContext = Depends(require_permission("network_admin"))) -> dict[str, bool]:
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


STORAGE_DIRECTORY_SUGGESTIONS_SCRIPT = r'''import json,os,sys
raw=sys.argv[1]
if not raw.startswith('/') or '\x00' in raw: raise SystemExit('Enter an absolute directory path')
normalized=os.path.normpath(raw)
if raw.endswith('/'):
    parent=normalized
    prefix=''
else:
    parent,prefix=os.path.split(normalized)
    parent=parent or '/'
suggestions=[]
try:
    with os.scandir(parent) as entries:
        for entry in entries:
            if entry.name.startswith(prefix) and entry.is_dir(follow_symlinks=True):
                suggestions.append(os.path.join(parent,entry.name))
                if len(suggestions) >= 200: break
except (FileNotFoundError,NotADirectoryError,PermissionError):
    pass
suggestions.sort(key=str.casefold)
print(json.dumps({'suggestions':suggestions[:40]}))
'''


@app.get("/kvm-api/hosts/{host_id}/storage-pools/directories")
def suggest_storage_pool_directories(host_id: str, path: str = "/", access: AuthorizationContext = Depends(require_permission("storage_admin"))) -> dict[str, list[str]]:
    if len(path) > 512 or not path.startswith("/") or "\x00" in path:
        raise HTTPException(422, "Enter an absolute path up to 512 characters")
    host = cockpit_host_record(host_id)
    try:
        output = run_sudo_python(host, STORAGE_DIRECTORY_SUGGESTIONS_SCRIPT, [path], timeout=15)
        result = json.loads(output or "{}")
        return {"suggestions": result.get("suggestions", [])[:40]}
    except Exception as exc:
        raise HTTPException(502, "Could not list directories on the KVM host. Verify SSH access and storage permissions, then retry.") from exc


STORAGE_POOL_SETUP_SCRIPT = r'''import json,os,posixpath,shutil,subprocess,sys,xml.etree.ElementTree as ET
payload=json.load(sys.stdin)
action=payload.get('action','preview')
base=['virsh','-c','qemu:///system']
def run(args):
    result=subprocess.run(base+args,capture_output=True,text=True,timeout=25)
    if result.returncode: raise RuntimeError(result.stderr.strip() or result.stdout.strip() or 'libvirt command failed')
    return result.stdout
def pool_inventory():
    names=[name.strip() for name in run(['pool-list','--all','--name']).splitlines() if name.strip()]
    pools={}
    for name in names:
        root=ET.fromstring(run(['pool-dumpxml',name]))
        info=run(['pool-info',name])
        values={line.split(':',1)[0].strip().lower():line.split(':',1)[1].strip() for line in info.splitlines() if ':' in line}
        path=root.findtext('./target/path') or ''
        pools[name]={'name':name,'type':root.get('type','unknown'),'target':path,'state':values.get('state','unknown'),
                     'autostart':values.get('autostart','no').lower()=='yes'}
    return pools
def inspect_target(raw):
    if not isinstance(raw,str) or not raw.startswith('/') or '\x00' in raw or len(raw)>512 or '..' in raw.split('/'):
        raise ValueError('Use a clean absolute path up to 512 characters without parent-directory segments')
    normalized=posixpath.normpath(raw)
    if normalized=='/': raise ValueError('The filesystem root cannot be used as a storage pool target')
    cursor=normalized
    while not os.path.exists(cursor):
        parent=os.path.dirname(cursor)
        if parent==cursor: raise ValueError('Could not find an existing parent directory for the target')
        cursor=parent
    if not os.path.isdir(cursor): raise ValueError('The target or its nearest existing parent is not a directory')
    canonical=os.path.realpath(normalized)
    if os.path.exists(normalized) and not os.path.isdir(normalized): raise ValueError('The target already exists and is not a directory')
    anchor=os.path.realpath(cursor)
    usage=shutil.disk_usage(anchor)
    return {'target':canonical,'directory_exists':os.path.isdir(normalized),'filesystem_path':anchor,
            'free_bytes':usage.free,'filesystem_total_bytes':usage.total}
def validate():
    pools=pool_inventory()
    selections=[('vm',payload.get('vm_pool',{})),('iso',payload.get('iso_pool',{}))]
    plans=[]; errors=[]
    for role,item in selections:
        mode=item.get('mode'); name=item.get('name','')
        if not isinstance(name,str) or not __import__('re').fullmatch(r'[A-Za-z0-9_.+-]{1,128}',name):
            errors.append(role+': use a pool name with letters, numbers, dots, underscores, plus signs, or hyphens'); continue
        if mode=='existing':
            pool=pools.get(name)
            if not pool: errors.append(role+': selected libvirt pool was not found'); continue
            if pool['type']!='dir': errors.append(role+': only directory-based pools are supported in this setup'); continue
            target=pool['target']
            try: details=inspect_target(target)
            except (ValueError,OSError) as error: errors.append(role+': '+str(error)); continue
            state=pool['state'].lower()
            plans.append({'role':role,'mode':'existing','name':name,'target':details['target'],'directory_exists':True,
                          'filesystem_path':details['filesystem_path'],'free_bytes':details['free_bytes'],
                          'state':pool['state'],'autostart':pool['autostart'],'will_create_directory':False,
                          'will_create_pool':False,'will_start':state!='running','will_enable_autostart':not pool['autostart']})
        elif mode=='create':
            if name in pools: errors.append(role+': a libvirt pool with this name already exists; select it or choose another name'); continue
            try: details=inspect_target(item.get('target'))
            except (ValueError,OSError) as error: errors.append(role+': '+str(error)); continue
            plans.append({'role':role,'mode':'create','name':name,'target':details['target'],
                          'directory_exists':details['directory_exists'],'filesystem_path':details['filesystem_path'],
                          'free_bytes':details['free_bytes'],'state':'not created','autostart':False,
                          'will_create_directory':not details['directory_exists'],'will_create_pool':True,
                          'will_start':True,'will_enable_autostart':True})
        else: errors.append(role+': choose an existing pool or create a new one')
    if len(plans)==2:
        same_existing=all(plan['mode']=='existing' for plan in plans) and plans[0]['name']==plans[1]['name']
        if not same_existing:
            if plans[0]['name']==plans[1]['name']: errors.append('VM and ISO pools must have different names when creating separate pools')
            for left,right in ((plans[0],plans[1]),):
                if os.path.commonpath([left['target'],right['target']]) in (left['target'],right['target']):
                    errors.append('VM and ISO directories must be separate; the same existing pool may be selected for both')
        for plan in plans:
            if plan['mode']!='create': continue
            for pool in pools.values():
                if pool['type']!='dir' or not pool['target']: continue
                existing=os.path.realpath(pool['target'])
                if os.path.commonpath([plan['target'],existing]) in (plan['target'],existing):
                    errors.append(plan['role']+': target overlaps the existing '+pool['name']+' pool; select that pool or choose a separate directory')
            if len(plans)==2 and plans[0]['mode']==plans[1]['mode']=='create':
                other=plans[1] if plan is plans[0] else plans[0]
                if os.path.commonpath([plan['target'],other['target']]) in (plan['target'],other['target']):
                    errors.append('New VM and ISO directories cannot be the same or nested')
    return pools,plans,errors
try:
    pools,plans,errors=validate()
    if action=='preview':
        print(json.dumps({'valid':not errors,'errors':errors,'pools':plans}))
    elif errors:
        print(json.dumps({'success':False,'errors':errors,'completed':[]}))
    else:
        completed=[]; seen=set(); current={}
        try:
            for plan in plans:
                if plan['name'] in seen: continue
                seen.add(plan['name'])
                current={'name':plan['name'],'role':plan['role'],'target':plan['target'],'stage':'starting'}
                if plan['mode']=='create':
                    os.makedirs(plan['target'],mode=0o755,exist_ok=True)
                    if not os.path.isdir(plan['target']): raise RuntimeError('target is not a directory')
                    current['stage']='directory ready'
                    run(['pool-define-as',plan['name'],'dir','--target',plan['target']])
                    current['stage']='pool defined'
                if plan['will_start']:
                    run(['pool-start',plan['name']]); current['stage']='pool started'
                if plan['will_enable_autostart']:
                    run(['pool-autostart',plan['name']]); current['stage']='autostart enabled'
                status=run(['pool-info',plan['name']])
                values={line.split(':',1)[0].strip().lower():line.split(':',1)[1].strip() for line in status.splitlines() if ':' in line}
                if values.get('state','').lower()!='running' or values.get('autostart','').lower()!='yes':
                    raise RuntimeError('pool did not verify as running with autostart enabled')
                completed.append({'name':plan['name'],'role':plan['role'],'target':plan['target'],'state':'running','autostart':True})
                current={}
            print(json.dumps({'success':True,'completed':completed}))
        except Exception as error:
            print(json.dumps({'success':False,'completed':completed,'failed':current,'error':str(error)}))
except Exception as error:
    print(json.dumps({'valid':False,'success':False,'errors':[str(error)],'pools':[]}))
'''


@app.post("/kvm-api/hosts/{host_id}/storage-pools/setup/preview")
def preview_storage_pool_setup(host_id: str, payload: StoragePoolSetupRequest,
                               access: AuthorizationContext = Depends(require_permission("storage_admin"))) -> dict[str, Any]:
    host=cockpit_host_record(host_id)
    data=payload.model_dump()
    data["action"]="preview"
    try:
        return json.loads(run_sudo_python(host, STORAGE_POOL_SETUP_SCRIPT, timeout=45, stdin_data=json.dumps(data)))
    except Exception as exc:
        raise HTTPException(502, f"Could not validate storage pool setup: {exc}") from exc


@app.post("/kvm-api/hosts/{host_id}/storage-pools/setup")
def apply_storage_pool_setup(host_id: str, payload: StoragePoolSetupRequest,
                             access: AuthorizationContext = Depends(require_permission("storage_admin"))) -> dict[str, Any]:
    host=cockpit_host_record(host_id)
    data=payload.model_dump()
    data["action"]="apply"
    try:
        result=json.loads(run_sudo_python(host, STORAGE_POOL_SETUP_SCRIPT, timeout=120, stdin_data=json.dumps(data)))
        if not result.get("success"):
            detail=result.get("error") or "; ".join(result.get("errors",[])) or "Storage pool setup did not complete"
            completed=result.get("completed",[])
            if completed:
                detail += "; completed before failure: " + ", ".join(item.get("name", "unknown") for item in completed)
            failed=result.get("failed") or {}
            if failed.get("name"):
                detail += f"; {failed['name']} was at stage: {failed.get('stage', 'unknown')}"
            record_audit(access.user_id,"storage-pools.setup",host_id,"failure",detail)
            raise HTTPException(409,detail)
    except HTTPException:
        raise
    except Exception as exc:
        record_audit(access.user_id,"storage-pools.setup",host_id,"failure",str(exc)[:500])
        raise HTTPException(502, f"Could not prepare storage pools: {exc}") from exc
    record_audit(access.user_id,"storage-pools.setup",host_id,detail=f"pools={len(result.get('completed',[]))}")
    return result


ISO_IMAGE_SUGGESTIONS_SCRIPT = r'''import json,os,subprocess,sys,xml.etree.ElementTree as ET
raw=sys.argv[1]
if not raw.startswith('/') or '\x00' in raw: raise SystemExit('Enter an absolute path')
base=['virsh','-c','qemu:///system']
roots=['/var/lib/libvirt/images','/var/lib/libvirt/boot','/mnt','/media']
try:
    pools=subprocess.run(base+['pool-list','--all','--name'],capture_output=True,text=True,timeout=8)
    if pools.returncode==0:
        for name in pools.stdout.splitlines():
            name=name.strip()
            if not name: continue
            dumped=subprocess.run(base+['pool-dumpxml',name],capture_output=True,text=True,timeout=8)
            if dumped.returncode: continue
            target=ET.fromstring(dumped.stdout).findtext('./target/path')
            if target and target.startswith('/'): roots.append(target)
except (OSError,subprocess.TimeoutExpired):
    pass
allowed=[]
for root in roots:
    try:
        canonical=os.path.realpath(root)
        if os.path.isdir(canonical) and canonical not in allowed: allowed.append(canonical)
    except OSError: pass
normalized=os.path.normpath(raw)
trailing=raw.endswith('/')
if raw=='/':
    locations=[(root,'') for root in allowed if root in ('/var/lib/libvirt/images','/var/lib/libvirt/boot')]
elif trailing or any(normalized==root for root in allowed):
    locations=[(os.path.realpath(normalized),'')]
else:
    parent,prefix=os.path.split(normalized)
    locations=[(os.path.realpath(parent or '/'),prefix)]
suggestions=[]
for directory,prefix in locations:
    if not any(os.path.commonpath([root,directory])==root for root in allowed): continue
    try:
        with os.scandir(directory) as entries:
            for entry in entries:
                if not entry.name.lower().endswith('.iso') or not entry.name.lower().startswith(prefix.lower()): continue
                try:
                    if not entry.is_file(follow_symlinks=True): continue
                    candidate=os.path.realpath(entry.path)
                    if any(os.path.commonpath([root,candidate])==root for root in allowed): suggestions.append(candidate)
                except (OSError,ValueError): pass
                if len(suggestions)>=80: break
    except (FileNotFoundError,NotADirectoryError,PermissionError,OSError,ValueError): pass
suggestions=sorted(set(suggestions),key=str.casefold)
print(json.dumps({'suggestions':suggestions[:40]}))
'''


@app.get("/kvm-api/hosts/{host_id}/vms/iso-images")
def suggest_host_iso_images(host_id: str, path: str = "/", access: AuthorizationContext = Depends(require_permission("vm_operator"))) -> dict[str, list[str]]:
    if len(path) > 1024 or not path.startswith("/") or "\x00" in path:
        raise HTTPException(422, "Enter an absolute path up to 1024 characters")
    host = cockpit_host_record(host_id)
    try:
        output = run_sudo_python(host, ISO_IMAGE_SUGGESTIONS_SCRIPT, [path], timeout=20)
        result = json.loads(output or "{}")
        return {"suggestions": result.get("suggestions", [])[:40]}
    except Exception as exc:
        raise HTTPException(502, "Could not list ISO images on the KVM host. Verify SSH access and libvirt storage, then retry.") from exc


@app.post("/kvm-api/hosts/{host_id}/storage-pools/config")
def configure_storage_pool(host_id: str, payload: StoragePoolConfig, access: AuthorizationContext = Depends(require_permission("storage_admin"))) -> dict[str, bool]:
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
def control_network_connection(host_id: str, payload: NetworkConnectionAction, access: AuthorizationContext = Depends(require_permission("network_admin"))) -> dict[str, bool]:
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
def configure_network_connection(host_id: str, payload: NetworkConnectionConfig, access: AuthorizationContext = Depends(require_permission("network_admin"))) -> dict[str, bool]:
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
def control_account(host_id: str, payload: AccountAction, access: AuthorizationContext = Depends(require_permission("account_admin"))) -> dict[str, bool]:
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
def control_service(host_id: str, payload: ServiceAction, service_name: str, access: AuthorizationContext = Depends(require_permission("service_admin"))) -> dict[str, bool]:
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
    remote_input_path = None
    sftp = None
    try:
        remote_script = render_sles_release_script(script)
        remote_args = list(args or [])
        if stdin_data is not None:
            # Keep sudo's password and operation payload on separate channels.
            # Some sudo builds consume bytes beyond their password line when
            # both are written to stdin. The short-lived, owner-only file is
            # uploaded over the already pinned SSH connection and deleted in
            # the finally block, including on command failure.
            remote_input_path = f"/tmp/.rancher-kvm-input-{uuid.uuid4().hex}"
            sftp = client.open_sftp()
            with sftp.open(remote_input_path, "w") as remote_input:
                remote_input.chmod(0o600)
                remote_input.write(stdin_data)
            remote_script = (
                "import sys; _kvm_input_path=sys.argv.pop(); "
                "sys.stdin=open(_kvm_input_path, 'r'); "
                f"exec(compile({script!r}, '<kvm-remote>', 'exec'))"
            )
            remote_args.append(remote_input_path)
        command_args = f"python3 -c {shlex.quote(remote_script)}"
        if remote_args:
            command_args += " " + " ".join(shlex.quote(arg) for arg in remote_args)
        stdin, stdout, stderr = client.exec_command(f"sudo -n {command_args}", timeout=timeout)
        output = stdout.read().decode("utf-8", "replace").replace("KVM_STDIN_READY\n", "").strip()
        error = stderr.read().decode("utf-8", "replace").strip()
        if stdout.channel.recv_exit_status():
            password = host.get("password") or ""
            if not password:
                raise RuntimeError(error or output or "This SSH key requires passwordless sudo for host administration")
            stdin, stdout, stderr = client.exec_command(f"sudo -S -p '' {command_args}", timeout=timeout)
            stdin.write(password + "\n")
            stdin.flush()
            stdin.channel.shutdown_write()
            output = stdout.read().decode("utf-8", "replace").replace("KVM_STDIN_READY\n", "").strip()
            error = stderr.read().decode("utf-8", "replace").strip()
            if stdout.channel.recv_exit_status():
                raise RuntimeError(error or output or "Could not run the remote command with sudo")
        return output
    finally:
        if sftp and remote_input_path:
            try:
                sftp.remove(remote_input_path)
            except OSError:
                performance_logger.warning("temporary_ssh_input_cleanup_failed host=%s", host.get("id", "unknown"))
        if sftp:
            sftp.close()
        client.close()


@app.post("/kvm-api/hosts/{host_id}/vms/actions")
def control_vm(host_id: str, payload: VMAction, vm_name: str, access: AuthorizationContext = Depends(require_permission("vm_operator"))) -> dict[str, Any]:
    host = cockpit_host_record(host_id)
    encoded_name = base64.b64encode(vm_name.encode()).decode()
    action_script = VM_PACEMAKER_VM_GUARD_SCRIPT + r'''import base64,subprocess,sys,time
name=base64.b64decode(sys.argv[1]).decode()
action=sys.argv[2]
if action not in ('start','shutdown','reboot','pause','resume','force_stop'): raise SystemExit('Action not allowed')
listing=subprocess.run(['virsh','-c','qemu:///system','list','--all','--name'],capture_output=True,text=True,timeout=20)
if listing.returncode: raise SystemExit(listing.stderr.strip() or listing.stdout.strip() or 'Could not query libvirt')
if name not in listing.stdout.splitlines(): raise SystemExit('Virtual machine not found')
ensure_vm_not_pacemaker_managed(name)
command={'pause':'suspend','resume':'resume','force_stop':'destroy'}.get(action,action)
result=subprocess.run(['virsh','-c','qemu:///system',command,name],capture_output=True,text=True,timeout=30)
if result.returncode: raise SystemExit(result.stderr.strip() or result.stdout.strip() or 'The libvirt action failed')
target={'start':'running','shutdown':'shut off','force_stop':'shut off','pause':'paused','resume':'running'}.get(action)
if target:
 timeout=45 if action in ('start','shutdown') else 15
 deadline=time.monotonic()+timeout
 while True:
  state=subprocess.run(['virsh','-c','qemu:///system','domstate',name],capture_output=True,text=True,timeout=10)
  if state.returncode: raise SystemExit(state.stderr.strip() or state.stdout.strip() or 'Could not verify the virtual machine state')
  current=state.stdout.strip().lower().splitlines()[0] if state.stdout.strip() else 'unknown'
  if (target=='shut off' and (current.startswith('shut off') or current.startswith('shutoff'))) or (target!='shut off' and current==target): break
  if time.monotonic()>=deadline:
   if action=='shutdown': raise SystemExit('Libvirt accepted the graceful shutdown request, but the VM remained running after 45 seconds. The guest may not support ACPI shutdown or may be busy. Shut it down from inside the guest and check its power-management configuration, then retry. If graceful shutdown is impossible, use Force off only after reviewing the risk of unsaved-data loss.')
   raise SystemExit('Libvirt accepted the action, but the VM did not reach the expected state ('+target+') within '+str(timeout)+' seconds; current state: '+current)
  time.sleep(1)
'''

    def perform_action(operation_host: dict[str, Any]) -> dict[str, str]:
        try:
            run_sudo_python(operation_host, action_script, [encoded_name, payload.action], timeout=70)
        except Exception as exc:
            record_audit(access.user_id, f"vm.{payload.action}", f"{host_id}/{vm_name}", "failure", str(exc)[:500])
            raise
        record_audit(access.user_id, f"vm.{payload.action}", f"{host_id}/{vm_name}")
        return {"status": "completed"}

    # Keep host-side state verification off the synchronous Rancher proxy path.
    # The UI polls this durable job and displays the guest/libvirt diagnostic.
    return create_operation_job(f"vm_{payload.action}", access.user_id, [host], perform_action)


@app.post("/kvm-api/hosts/{host_id}/vms/delete")
def delete_vms(host_id: str, payload: VMDeleteRequest, access: AuthorizationContext = Depends(require_permission("vm_operator"))) -> dict[str, Any]:
    """Remove stopped libvirt definitions while deliberately preserving disks."""
    names = [name.strip() for name in payload.vm_names]
    if any(not name or len(name) > 255 or "\x00" in name for name in names):
        raise HTTPException(422, "Each virtual machine name must contain 1–255 valid characters")
    if len(set(names)) != len(names):
        raise HTTPException(422, "The virtual machine selection contains duplicate names")
    host = cockpit_host_record(host_id)
    # Names travel as JSON on stdin and are passed to virsh as argv elements;
    # they are never interpolated into shell source or command text.
    delete_script = VM_PACEMAKER_VM_GUARD_SCRIPT + r'''import json,subprocess,sys
names=json.load(sys.stdin)
def run(args):
 try: return subprocess.run(['virsh','-c','qemu:///system']+args,capture_output=True,text=True,timeout=8)
 except subprocess.TimeoutExpired: return subprocess.CompletedProcess(args,124,'','Libvirt did not respond within 8 seconds; check the host libvirt service and retry.')
listing=run(['list','--all','--name'])
if listing.returncode: raise SystemExit(listing.stderr.strip() or listing.stdout.strip() or 'Could not query libvirt')
known=set(line for line in listing.stdout.splitlines() if line)
results=[]
for name in names:
 if name not in known:
  results.append({'name':name,'status':'error','message':'Virtual machine was not found on this host.'})
  continue
 try: ensure_vm_not_pacemaker_managed(name)
 except Exception as exc:
  results.append({'name':name,'status':'error','message':str(exc)})
  continue
 state=run(['domstate',name])
 if state.returncode:
  results.append({'name':name,'status':'error','message':state.stderr.strip() or state.stdout.strip() or 'Could not check the virtual machine state.'})
  continue
 normalized=' '.join(state.stdout.strip().lower().split())
 if normalized not in ('shut off','shutoff'):
  results.append({'name':name,'status':'error','message':'Shut down this virtual machine before deleting it. The extension will not power it off automatically.'})
  continue
 removed=run(['undefine',name])
 if removed.returncode:
  results.append({'name':name,'status':'error','message':removed.stderr.strip() or removed.stdout.strip() or 'Libvirt could not remove the virtual machine definition. Check snapshots or firmware metadata, then retry.'})
 else:
  results.append({'name':name,'status':'deleted','message':'Virtual machine definition removed; storage volumes were preserved.'})
print(json.dumps({'vms':results}))
    '''

    def perform_delete(operation_host: dict[str, Any]) -> dict[str, Any]:
        try:
            output = run_sudo_python(operation_host, delete_script, timeout=180, stdin_data=json.dumps(names))
            result = json.loads(output or "{}")
            vm_results = result.get("vms")
            if not isinstance(vm_results, list) or len(vm_results) != len(names):
                raise RuntimeError("The host returned an incomplete virtual machine deletion result")
        except Exception as exc:
            record_audit(access.user_id, "vm.delete", host_id, "failure", str(exc)[:500])
            raise
        deleted = [item for item in vm_results if item.get("status") == "deleted"]
        failures = [item for item in vm_results if item.get("status") != "deleted"]
        for item in deleted:
            record_audit(access.user_id, "vm.delete", f"{host_id}/{item.get('name', '')}", detail="definition removed; storage preserved")
        for item in failures:
            record_audit(access.user_id, "vm.delete", f"{host_id}/{item.get('name', '')}", "failure", str(item.get("message", ""))[:500])
        return {"status": "failed" if failures else "completed", "vms": vm_results,
                "error": f"{len(failures)} virtual machine(s) could not be deleted" if failures else None}

    return create_operation_job("vm_delete", access.user_id, [host], perform_delete)


@app.post("/kvm-api/hosts/{host_id}/vms/autostart")
def set_vm_autostart(host_id: str, payload: VMAutostart, vm_name: str, access: AuthorizationContext = Depends(require_permission("vm_operator"))) -> dict[str, bool]:
    host = cockpit_host_record(host_id)
    encoded_name = base64.b64encode(vm_name.encode()).decode()
    action_script = VM_PACEMAKER_VM_GUARD_SCRIPT + r'''import base64,subprocess,sys
name=base64.b64decode(sys.argv[1]).decode()
enabled=sys.argv[2]=='true'
listing=subprocess.run(['virsh','-c','qemu:///system','list','--all','--name'],capture_output=True,text=True,timeout=20)
if listing.returncode: raise SystemExit(listing.stderr.strip() or listing.stdout.strip() or 'Could not query libvirt')
if name not in listing.stdout.splitlines(): raise SystemExit('Virtual machine not found')
ensure_vm_not_pacemaker_managed(name)
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
    config_script = VM_PACEMAKER_VM_GUARD_SCRIPT + r'''import base64, os, subprocess, sys, tempfile, xml.etree.ElementTree as ET
name=base64.b64decode(sys.argv[1]).decode()
vcpus=int(sys.argv[2]); memory_kib=int(sys.argv[3])
base=['virsh','-c','qemu:///system']
def run(args):
 result=subprocess.run(args,capture_output=True,text=True,timeout=30)
 if result.returncode: raise SystemExit(result.stderr.strip() or result.stdout.strip() or 'Libvirt command failed')
 return result.stdout
domains=run(base+['list','--all','--name']).splitlines()
if name not in [item.strip() for item in domains]: raise SystemExit('Virtual machine not found')
ensure_vm_not_pacemaker_managed(name)
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
    config_script = VM_PACEMAKER_VM_GUARD_SCRIPT + r'''import base64,os,re,subprocess,sys,tempfile,xml.etree.ElementTree as ET
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
ensure_vm_not_pacemaker_managed(name)
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
