"""Regression tests for the restricted SUSE crmsh bootstrap PTY."""

from __future__ import annotations

import ast
import shlex
import socket
import time
from pathlib import Path
from types import SimpleNamespace
import unittest


SOURCE = Path(__file__).resolve().parents[1] / "app.py"


class FakeChannel:
    def __init__(self, marker: bytes = b"\x1eKVM_SUDO_READY\x1e"):
        self.marker = bytearray(marker)
        self.commands: list[str] = []
        self.sent: list[bytes] = []
        self.pty = None
        self.timeout = None
        self.closed = False

    def get_pty(self, **kwargs):
        self.pty = kwargs

    def exec_command(self, command):
        self.commands.append(command)

    def settimeout(self, value):
        self.timeout = value

    def recv(self, count):
        if not self.marker:
            return b""
        result = bytes(self.marker[:count])
        del self.marker[:count]
        return result

    def sendall(self, data):
        self.sent.append(data)

    def close(self):
        self.closed = True


class FakeTransport:
    def __init__(self, channel):
        self.channel = channel

    def open_session(self, **_kwargs):
        return self.channel


class FakeClient:
    def __init__(self, channel, sudo_status=0):
        self.channel = channel
        self.sudo_status = sudo_status
        self.exec_commands: list[str] = []
        self.closed = False

    def exec_command(self, command, **_kwargs):
        self.exec_commands.append(command)
        stdout = SimpleNamespace(channel=SimpleNamespace(recv_exit_status=lambda: self.sudo_status))
        return SimpleNamespace(), stdout, SimpleNamespace()

    def get_transport(self):
        return FakeTransport(self.channel)

    def close(self):
        self.closed = True


def load_open_channel():
    tree = ast.parse(SOURCE.read_text())
    node = next(
        item for item in tree.body
        if isinstance(item, ast.FunctionDef) and item.name == "open_cluster_bootstrap_channel"
    )
    namespace = {
        "paramiko": SimpleNamespace(SSHClient=FakeClient, Channel=FakeChannel),
        "socket": socket,
        "time": time,
        "shlex": shlex,
        "ssh_client_for_host": lambda _host: None,
    }
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(SOURCE), "exec"), namespace)
    return namespace["open_cluster_bootstrap_channel"], namespace


class ClusterBootstrapChannelTests(unittest.TestCase):
    def setUp(self):
        self.open_channel, self.namespace = load_open_channel()

    def call_with(self, username, password, sudo_status=0, marker=b"\x1eKVM_SUDO_READY\x1e"):
        channel = FakeChannel(marker)
        client = FakeClient(channel, sudo_status=sudo_status)
        self.namespace["ssh_client_for_host"] = lambda _host: client
        result = self.open_channel(
            {"username": username, "password": password},
            "crm cluster init --name ha-lab",
        )
        return client, channel, result

    def test_root_runs_only_the_prebuilt_crmsh_command_without_sudo_password(self):
        client, channel, (returned_client, returned_channel, prefix) = self.call_with("root", "root-secret")
        self.assertIs(returned_client, client)
        self.assertIs(returned_channel, channel)
        self.assertEqual(prefix, b"")
        self.assertEqual(channel.commands, ["crm cluster init --name ha-lab"])
        self.assertEqual(channel.pty, {"term": "xterm-256color", "width": 100, "height": 30})
        self.assertEqual(client.exec_commands, [])
        self.assertNotIn(b"root-secret", b" ".join(channel.sent))

    def test_passwordless_sudo_uses_noninteractive_validation(self):
        client, channel, _ = self.call_with("cluster-admin", "stored-secret", sudo_status=0)
        self.assertEqual(client.exec_commands, ["sudo -n -v"])
        self.assertEqual(channel.commands, ["sudo -n crm cluster init --name ha-lab"])
        self.assertEqual(channel.sent, [])

    def test_password_fallback_sends_secret_only_after_the_sudo_marker(self):
        client, channel, (_returned_client, _returned_channel, prefix) = self.call_with(
            "cluster-admin", "one-time-secret", sudo_status=1,
            marker=b"bootstrap-started:\x1eKVM_SUDO_READY\x1e",
        )
        self.assertEqual(client.exec_commands, ["sudo -n -v"])
        self.assertEqual(channel.commands, ["stty -echo && printf '\\036KVM_SUDO_READY\\036' && sudo -S -p '' crm cluster init --name ha-lab"])
        self.assertEqual(prefix, b"bootstrap-started:")
        self.assertEqual(channel.sent, [b"one-time-secret\n"])
        self.assertNotIn("one-time-secret", " ".join(client.exec_commands + channel.commands))
        self.assertIsNone(channel.timeout)

    def test_rejects_missing_sudo_password_before_opening_a_pty(self):
        channel = FakeChannel()
        client = FakeClient(channel, sudo_status=1)
        self.namespace["ssh_client_for_host"] = lambda _host: client
        with self.assertRaisesRegex(RuntimeError, "needs sudo access"):
            self.open_channel({"username": "operator", "password": ""}, "crm cluster join -c node-a")
        self.assertEqual(channel.commands, [])
        self.assertTrue(client.closed)

    def test_closes_channel_and_client_if_remote_sudo_process_exits_early(self):
        channel = FakeChannel(marker=b"")
        client = FakeClient(channel, sudo_status=1)
        self.namespace["ssh_client_for_host"] = lambda _host: client
        with self.assertRaisesRegex(RuntimeError, "closed.*before sudo started"):
            self.open_channel({"username": "operator", "password": "secret"}, "crm cluster init --name ha-lab")
        self.assertTrue(channel.closed)
        self.assertTrue(client.closed)
        self.assertNotIn("secret", " ".join(channel.commands))


if __name__ == "__main__":
    unittest.main()
