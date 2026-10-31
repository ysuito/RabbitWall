#!/usr/bin/env python3
"""Fixed-purpose local controller; accepts only validated node settings, never nft commands from HTTP."""
import argparse
import concurrent.futures
import datetime as dt
import grp
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import socketserver
import struct
import subprocess
import tempfile
import time

from settings import SETTINGS, AI_INTERFACE, AI_IP, UPLINK_IP, monitored, NODES_CONFIG
import node_config

SOCKET = Path("/run/rabbitwall/control.sock")
TOKEN = Path("/etc/rabbitwall/control.token")
GROUP = "rabbitwall-control"
from firewall import LEASE, PROBE_COMMENT, DNS_COMMENT, gate, dns_rule, probe_rules

GATE_RULES = gate(SETTINGS)
DNS_RULE = dns_rule(SETTINGS)
PROBE_RULE = probe_rules(SETTINGS)


def utc_now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def nft(args, script=None):
    result = subprocess.run(["nft"] + args, input=script, text=True,
                            capture_output=True, timeout=5)
    if result.returncode:
        raise RuntimeError(result.stderr.strip()[:500] or "nft command failed")
    return result.stdout


TIMED_DURATIONS = (60, 300, 1800)


def validate_duration(enabled, duration):
    if duration is not None and (not enabled or type(duration) is not int or duration not in TIMED_DURATIONS):
        raise ValueError("duration_seconds must be 60, 300 or 1800 when enabling")


def request_control(action, path=SOCKET, payload=None):
    if action not in {"status", "enable", "disable", "nodes", "save_nodes"}:
        raise ValueError("unsupported action")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(15 if action == "save_nodes" else 4)
        client.connect(str(path))
        request = {"action":action}
        if action == "save_nodes" or (action == "enable" and payload is not None): request["payload"] = payload
        client.sendall((json.dumps(request) + "\n").encode())
        chunks = bytearray()
        while b"\n" not in chunks:
            part = client.recv(4096)
            if not part:
                raise RuntimeError("controller closed connection")
            chunks.extend(part)
            if len(chunks) > 65536:
                raise RuntimeError("controller response too large")
        data = json.loads(chunks.split(b"\n", 1)[0])
        if not data.get("ok"):
            if data.get("conflict"): raise node_config.RevisionConflict(data.get("error", "Node settings changed"))
            if data.get("invalid"): raise ValueError(data.get("error", "Invalid node settings"))
            raise RuntimeError(data.get("error", "controller error"))
        return data["status"]


def read_gate():
    document = json.loads(nft(["-j", "-a", "list", "table", "inet", "rabbitwall_console"]))
    objects = document.get("nftables", [])
    table = next(item["table"] for item in objects if "table" in item)
    enabled = next(item["set"] for item in objects
                   if item.get("set", {}).get("name") == "online_sources")
    chains = {item["chain"]["name"]: item["chain"] for item in objects if "chain" in item}
    if (enabled.get("type") != "ipv4_addr" or "timeout" not in enabled.get("flags", [])
            or "ai_egress" not in chains or chains.get("forward", {}).get("hook") != "forward"
            or chains["forward"].get("prio") != -10
            or any(chains.get(name, {}).get("hook") != name
                   or chains.get(name, {}).get("prio") != -10 for name in ("input", "output"))
            or not {"dns_request", "dns_reply"}.issubset(chains)):
        raise RuntimeError("gate structure differs; reinstall required")
    return {"handle": table["handle"], "enabled": bool(enabled.get("elem"))}


def baseline():
    data = json.loads(nft(["-j", "-a", "list", "ruleset"]))
    objects = data.get("nftables", [])
    chains = {item["chain"]["name"]: item["chain"] for item in objects
              if item.get("chain", {}).get("table") == "rabbitwall_filter"}
    if any(chains.get(name, {}).get("policy") != "drop" for name in ("input", "forward", "output")):
        raise RuntimeError("expected rabbitwall_filter input/forward/output drop policy is missing")
    if any("flowtable" in item for item in objects):
        raise RuntimeError("flowtable offload is not supported by the internet gate")
    return objects


def install_runtime():
    objects = baseline()
    exists = any(item.get("table", {}).get("name") == "rabbitwall_console" and
                 item["table"].get("family") == "inet" for item in objects)
    script = ("delete table inet rabbitwall_console\n" if exists else "") + GATE_RULES
    script += node_config.node_rule_batch(SETTINGS, objects)
    if not any(item.get("rule", {}).get("comment") == DNS_COMMENT for item in objects):
        script += DNS_RULE
    # Delete+create is one atomic nft transaction; no open interval in between.
    nft(["-f", "-"], script)
    return read_gate()["handle"]


def apply_enabled(enabled, lease_ms=None):
    script = "flush set inet rabbitwall_console online_sources\n"
    if enabled:
        timeout = f"{LEASE}s" if lease_ms is None else f"{lease_ms}ms"
        script += f"add element inet rabbitwall_console online_sources {{ {AI_INTERFACE.network} timeout {timeout} }}\n"
    nft(["-f", "-"], script)


def probe_nodes(previous=None, config=None):
    config = config or SETTINGS
    previous = {node["id"]: node for node in (previous or [])}
    checked = utc_now()
    nodes = [{"id": "rabbitwall", "name": SETTINGS['label'], "ip": f"{UPLINK_IP} / {AI_IP}",
              "state": "up", "method": "local controller", "checked_at": checked,
              "last_success": checked, "latency_ms": None}]
    for configured in config['nodes']:
        identity, name, address, interface = (configured[key] for key in ('id', 'label', 'ip', 'interface'))
        node = {"id": identity, "name": name, "ip": address, "state": "unknown",
                "method": "ICMP", "checked_at": utc_now(),
                "last_success": previous.get(identity, {}).get("last_success"), "latency_ms": None}
        if not monitored(configured):
            node["state"] = "disabled"; node["method"] = "disabled"
            nodes.append(node); continue
        try:
            proc = subprocess.run(["ping", "-n", "-c", "1", "-W", "1", "-I", interface, address],
                                  text=True, capture_output=True, timeout=3,
                                  env=dict(os.environ, LC_ALL="C"))
            node["state"] = "up" if proc.returncode == 0 else "no_reply" if proc.returncode == 1 else "unknown"
            match = re.search(r"time[=<]([\d.]+)\s*ms", proc.stdout)
            if match:
                node["latency_ms"] = float(match[1])
            if proc.returncode == 0:
                node["last_success"] = node["checked_at"]
            elif proc.returncode != 1:
                node["detail"] = proc.stderr.strip()[:200]
        except (OSError, subprocess.TimeoutExpired) as exc:
            node["detail"] = str(exc)[:200]
        nodes.append(node)
    return nodes


class Controller:
    def __init__(self):
        self.handle = install_runtime()
        self.desired = False
        self.deadline = None
        self.error = None
        self.nodes = []
        self.config = SETTINGS
        self.node_revision = node_config.revision(self.config)

    def status(self):
        actual = read_gate()
        if actual["handle"] != self.handle:
            # nftables reload recreates an empty gate: never restore ON silently.
            self.desired = False
            self.handle = actual["handle"]
            apply_enabled(False)
            actual = read_gate()
        if self.deadline is not None and time.monotonic() >= self.deadline:
            self.desired = False
            apply_enabled(False)
            actual = read_gate()
        if not actual["enabled"]:
            self.desired = False
            self.deadline = None
        remaining = max(0, self.deadline - time.monotonic()) if self.deadline is not None else None
        return {"remaining_seconds": remaining, "enabled": actual["enabled"], "available": True, "checked_at": utc_now(),
                "lease_seconds": LEASE, "nodes": self.nodes, "error": self.error}

    def node_settings(self):
        return node_config.document(self.config)

    def save_nodes(self, payload):
        self.status()
        try:
            self.config = node_config.save(self.config, payload, nft, baseline)
        except (ValueError, node_config.RevisionConflict):
            raise
        except Exception:
            # A failure must never widen the Internet gate.
            self.desired = False
            apply_enabled(False)
            raise
        self.node_revision = node_config.revision(self.config)
        checked = utc_now()
        self.nodes = [{"id":"rabbitwall", "name":self.config['label'], "ip":f"{UPLINK_IP} / {AI_IP}",
                       "state":"up", "checked_at":checked, "last_success":checked, "latency_ms":None},
                      *[{"id":node['id'], "name":node['label'], "ip":node['ip'],
                         "state":"unknown" if monitored(node) else "disabled", "checked_at":checked,
                         "last_success":None, "latency_ms":None} for node in self.config['nodes']]]
        return self.node_settings()

    def set_enabled(self, enabled, duration_seconds=None):
        validate_duration(enabled, duration_seconds)
        self.status()
        self.deadline = time.monotonic() + duration_seconds if duration_seconds is not None else None
        apply_enabled(enabled)
        self.desired = enabled
        self.error = None
        current = self.status()
        if current["enabled"] != enabled:
            raise RuntimeError("kernel gate state did not match request")
        return current

    def tick(self):
        try:
            current = self.status()
            # Expiry (e.g. suspended process) requires a fresh ON action.
            if self.desired and not current["enabled"]:
                self.desired = False
            if self.desired:
                if self.deadline is None:
                    apply_enabled(True)
                else:
                    # Kernel expiry must never extend beyond the user's deadline.
                    remaining = self.deadline - time.monotonic()
                    if remaining <= 0:
                        self.desired = False
                        self.deadline = None
                        apply_enabled(False)
                    else:
                        apply_enabled(True, lease_ms=min(LEASE * 1000, max(1, int(remaining * 1000))))
            self.error = None
        except (OSError, RuntimeError, ValueError, KeyError, StopIteration, subprocess.TimeoutExpired) as exc:
            self.desired = False
            self.error = str(exc)[:500]
            try:
                apply_enabled(False)
            except Exception:
                pass  # Existing kernel lease expires even if control is unavailable.


def run_controller():
    controller = Controller()
    print(json.dumps({"event": "controller-start", "enabled": False, "at": utc_now()}), flush=True)
    running = True
    def stop(*_):
        nonlocal running
        running = False
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.request.settimeout(1)
            try:
                raw = self.rfile.readline(16385)
                if len(raw) > 16384 or not raw.endswith(b"\n"):
                    raise ValueError("invalid control request")
                data = json.loads(raw)
                if not isinstance(data, dict) or set(data) != ({"action", "payload"} if data.get("action") == "save_nodes" or (data.get("action") == "enable" and "payload" in data) else {"action"}):
                    raise ValueError("invalid control request")
                action = data["action"]
                if action == "status":
                    status = controller.status()
                elif action == "nodes":
                    status = controller.node_settings()
                elif action == "save_nodes":
                    status = controller.save_nodes(data["payload"])
                    pid, uid, gid = struct.unpack("3i", self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                    print(json.dumps({"event":action,"at":utc_now(),"pid":pid,"uid":uid,"gid":gid,"count":len(status["nodes"])}), flush=True)
                elif action in {"enable", "disable"}:
                    status = controller.set_enabled(action == "enable", data.get("payload"))
                    pid, uid, gid = struct.unpack("3i", self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                    print(json.dumps({"event": action, "at": utc_now(), "pid": pid, "uid": uid, "gid": gid,
                                      "enabled": status["enabled"], "duration_seconds": data.get("payload")}), flush=True)
                else:
                    raise ValueError("unsupported action")
                response = {"ok": True, "status": status}
            except Exception as exc:
                response = {"ok": False, "error": str(exc)[:500], "conflict":isinstance(exc, node_config.RevisionConflict), "invalid":isinstance(exc, ValueError)}
            try:
                self.wfile.write((json.dumps(response) + "\n").encode())
            except OSError:
                pass

    SOCKET.parent.mkdir(parents=True, exist_ok=True)
    if SOCKET.exists():
        SOCKET.unlink()
    with socketserver.UnixStreamServer(str(SOCKET), Handler) as server, concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        os.chmod(SOCKET, 0o660)
        server.timeout = 0.5
        last_tick, last_probe, future = 0.0, 0.0, None
        try:
            while running:
                now = time.monotonic()
                if now - last_tick >= 4:
                    controller.tick()
                    last_tick = now
                if future and future.done():
                    revision, nodes = future.result()
                    if revision == controller.node_revision: controller.nodes = nodes
                    else: last_probe = 0.0
                    future = None
                if future is None and now - last_probe >= 10:
                    config = controller.config
                    revision = controller.node_revision
                    previous = controller.nodes
                    future = executor.submit(lambda c=config, r=revision, p=previous: (r, probe_nodes(p, c)))
                    last_probe = now
                server.handle_request()
        finally:
            controller.desired = False
            apply_enabled(False)
            SOCKET.unlink(missing_ok=True)


def install_persistent(config=Path("/etc/nftables.conf"), snippet=Path("/etc/nftables.d/rabbitwall.nft"), token=TOKEN):
    """Preserve the actual existing config; add only a validated include."""
    # Node metadata is readable like the base JSON; operation keys stay private.
    NODES_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(NODES_CONFIG.parent, 0o755)
    original = config.read_text()
    if "flush ruleset" not in original or not re.search(r"table\s+inet\s+rabbitwall_filter\b", original):
        raise RuntimeError("Expected generated rabbitwall_filter config with flush ruleset; integrate manually")
    if original.count(str(snippet)) > 1:
        raise RuntimeError("duplicate rabbitwall includes; integrate manually")
    include = f'include "{snippet}"'
    candidate = original if include in original else original.rstrip() + "\n\n# RABBITWALL console: boot defaults to OFF\n" + include + "\n"
    snippet.parent.mkdir(parents=True, exist_ok=True)
    old_snippet = snippet.read_bytes() if snippet.exists() else None
    snippet.write_text(GATE_RULES + "\n" + PROBE_RULE + DNS_RULE)
    os.chmod(snippet, 0o644)
    fd, temporary = tempfile.mkstemp(prefix=".rabbitwall-nft-check-", dir=config.parent)
    try:
        with os.fdopen(fd, "w") as output:
            output.write(candidate)
        nft(["-c", "-f", temporary])
        if candidate != original:
            stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            backup = config.with_name(config.name + ".rabbitwall-" + stamp + ".bak")
            backup.write_text(original)
            os.chmod(backup, 0o600)
            shutil.copystat(config, temporary)
            os.chown(temporary, config.stat().st_uid, config.stat().st_gid)
            os.replace(temporary, config)
    except Exception:
        if old_snippet is None:
            snippet.unlink(missing_ok=True)
        else:
            snippet.write_bytes(old_snippet)
        raise
    finally:
        Path(temporary).unlink(missing_ok=True)
    token.parent.mkdir(parents=True, exist_ok=True)
    group_id = grp.getgrnam(GROUP).gr_gid
    os.chown(token.parent, 0, group_id)
    os.chmod(token.parent, 0o750)
    if not token.exists():
        descriptor = os.open(token, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
        with os.fdopen(descriptor, "w") as output:
            output.write(secrets.token_urlsafe(32) + "\n")
    os.chown(token, 0, group_id)
    os.chmod(token, 0o640)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["run", "install", "off"])
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("run on RABBITWALL as root")
    from settings import require_config
    try: require_config()
    except ValueError as error: parser.error(str(error))
    os.umask(0o027)
    if args.mode == "install":
        install_persistent()
    elif args.mode == "off":
        try:
            request_control("disable")
        except (OSError, RuntimeError, ValueError):
            apply_enabled(False)
    else:
        run_controller()


if __name__ == "__main__":
    main()
