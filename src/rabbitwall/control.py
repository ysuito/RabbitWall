#!/usr/bin/env python3
"""Fixed-purpose local controller; accepts only validated node settings, never nft commands from HTTP."""
import argparse
import audit
import concurrent.futures
import datetime as dt
import grp
import json
import os
from pathlib import Path
import re
import secrets
import select
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
import domain_approvals
from domain_requests import Requests, PUBLIC_ACTIONS, REQUEST_SOCKET, RequestLimit

SOCKET = Path("/run/rabbitwall/control.sock")
TOKEN = Path("/etc/rabbitwall/control.token")
GROUP = "rabbitwall-control"
from firewall import LEASE, PROBE_COMMENT, DNS_COMMENT, REQUEST_COMMENT, request_rule, persistent_rules, gate, dns_rule, probe_rules
from firewall import DOMAIN_TARGET_TABLES, domain_forward_rules

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
    if action not in {"status", "audit_log", "enable", "disable", "nodes", "save_nodes", "approve_domains", "revoke_domain", "decide_domain_request", *PUBLIC_ACTIONS}:
        raise ValueError("unsupported action")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(25 if action in {"save_nodes","approve_domains","revoke_domain", "decide_domain_request", *PUBLIC_ACTIONS} else 4)
        client.connect(str(path))
        request = {"action":action}
        if action in {"save_nodes","approve_domains","revoke_domain", "decide_domain_request", *PUBLIC_ACTIONS} or (action == "enable" and payload is not None): request["payload"] = payload
        client.sendall((json.dumps(request) + "\n").encode())
        chunks = bytearray()
        while b"\n" not in chunks:
            part = client.recv(4096)
            if not part:
                raise RuntimeError("controller closed connection")
            chunks.extend(part)
            if len(chunks) > 4194304:
                raise RuntimeError("controller response too large")
        data = json.loads(chunks.split(b"\n", 1)[0])
        if not data.get("ok"):
            if data.get("limited"): raise RequestLimit(data.get("error", "Too many requests"))
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
    domain_sources = next(item['set'] for item in objects if item.get('set',{}).get('name')=='domain_sources')
    return {"handle": table["handle"], "enabled": bool(enabled.get("elem")), "restricted":bool(domain_sources.get('elem'))}


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
    script += domain_forward_rules(SETTINGS, objects)
    script += node_config.node_rule_batch(SETTINGS, objects)
    if not any(item.get("rule", {}).get("comment") == DNS_COMMENT for item in objects):
        script += DNS_RULE
    if not any(item.get("rule", {}).get("comment") == REQUEST_COMMENT for item in objects):
        script += request_rule(SETTINGS)
    # Delete+create is one atomic nft transaction; no open interval in between.
    nft(["-f", "-"], script)
    return read_gate()["handle"]


def apply_enabled(enabled, lease_ms=None):
    script = "".join(f"flush set inet rabbitwall_console {name}\n" for name in ("online_sources","domain_sources","domain_resolver_sources","device_sources"))
    script += "".join(f"flush set inet {table} domain_targets\n" for table in DOMAIN_TARGET_TABLES)
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
        self.approvals = domain_approvals.Approvals(nft)
        self.requests = Requests()

    def status(self):
        actual = read_gate()
        if actual["handle"] != self.handle:
            audit.record({'event':'gate-ended','reason':'kernel-reload'})
            # nftables reload recreates an empty gate: never restore ON silently.
            self.desired = False
            self.approvals.clear()
            self.handle = actual["handle"]
            apply_enabled(False)
            actual = read_gate()
        if self.deadline is not None and time.monotonic() >= self.deadline:
            audit.record({'event':'gate-ended','reason':'expired'})
            self.desired = False
            apply_enabled(False)
            actual = read_gate()
        if not actual["enabled"]:
            self.desired = False
            self.deadline = None
        remaining = max(0, self.deadline - time.monotonic()) if self.deadline is not None else None
        approvals = self.approvals.snapshot()
        if approvals and not actual.get('restricted',False):
            # A lost kernel lease requires new human approval, just like full-open.
            self.approvals.clear()
            apply_enabled(False)
            approvals = []
        restricted = bool(approvals) and actual.get('restricted',False)
        return {"domain_requests":self.requests.snapshot(approvals), "domain_approvals":approvals, "mode":"full" if actual["enabled"] else "restricted" if restricted else "closed",
                "remaining_seconds": remaining, "enabled": actual["enabled"] or restricted, "available": True, "checked_at": utc_now(),
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
        if self.approvals.grants:
            self.desired = False
            self.deadline = None
            apply_enabled(False)
            self.approvals.clear(sync=True)
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
        apply_enabled(False)
        self.approvals.clear(sync=True)
        self.deadline = time.monotonic() + duration_seconds if duration_seconds is not None else None
        apply_enabled(enabled)
        self.desired = enabled
        self.error = None
        current = self.status()
        if current["enabled"] != enabled:
            raise RuntimeError("kernel gate state did not match request")
        return current

    def approve_domains(self, payload):
        spec = domain_approvals.validate_request(self.config,payload,allow_any=True)
        self.desired = False
        self.deadline = None
        apply_enabled(False)
        try:
            self.approvals.approve(self.config,spec)
        except Exception:
            self.approvals.clear()
            apply_enabled(False)
            raise
        self.error = None
        audit.record({'event':'domain-approval','at':utc_now(),'id':self.approvals.grants[spec['node_id']]['id'],'node_id':spec['node_id'],'source':spec['source'],'domains':spec['domains'],
                          'scope':spec['scope'],'ports':spec['ports'],'duration_seconds':spec['duration_seconds'],'purpose':spec['purpose']})
        return self.status()

    def agent_request(self, action, payload):
        if action not in PUBLIC_ACTIONS: raise ValueError('Invalid agent action')
        if not isinstance(payload, dict) or set(payload) != {'source', 'request'}:
            raise ValueError('source and request required')
        source, data = payload['source'], payload['request']
        if not isinstance(source, str): raise ValueError('Invalid source')
        if action == 'submit_domain_request':
            item = self.requests.submit(self.config, source, data)
            audit.record({'event':'domain-request', 'at':utc_now(), **{k:v for k,v in item.items() if not k.startswith('_')}})
        else:
            if not isinstance(data, dict) or set(data) != {'id'}: raise ValueError('id required')
            item = self.requests.get(data['id'])
            if item['source'] != source: raise ValueError('Request not found')
            if not any(n['id'] == item['node_id'] and n['ip'] == source and n['interface'] == self.config['ai_if'] for n in self.config['nodes']):
                raise ValueError('Node registration changed')
            if action == 'revoke_domain_request':
                if item['status'] != 'approved': raise ValueError('Request is not approved')
                grant = self.approvals.grants.get(item['node_id'])
                # Never revoke a replacement grant, including one issued manually.
                if grant and grant['id'] == item['grant_id']:
                    self.revoke_domain({'id':item['grant_id']})
        # Do not expose other nodes, requests or administrative state.
        return self.requests.view(item, self.status()['domain_approvals'])

    def decide_domain_request(self, payload):
        if not isinstance(payload, dict) or set(payload) != {'id', 'decision'} or payload['decision'] not in ('approve', 'reject'):
            raise ValueError('id and decision (approve/reject) required')
        item = self.requests.get(payload['id'])
        if item['status'] != 'pending': raise ValueError('Request already decided')
        if payload['decision'] == 'approve':
            spec = self.requests.validate_current(self.config, item)
            self.approve_domains({k:spec[k] for k in ('node_id','domains','duration_seconds','purpose','ports')})
            self.requests.decided(item, 'approved', self.approvals.grants[item['node_id']]['id'])
        else:
            self.requests.decided(item, 'rejected')
        audit.record({'event':'domain-request-decision', 'at':utc_now(), **payload, 'grant_id':item.get('grant_id')})
        return self.status()

    def revoke_domain(self, payload):
        if not isinstance(payload,dict) or set(payload)!={'id'}: raise ValueError('id required')
        if not any(g['id']==payload['id'] for g in self.approvals.grants.values()): raise ValueError('Approval no longer exists')
        selected = next(g for g in self.approvals.grants.values() if g['id']==payload['id'])
        detail = {key:selected[key] for key in ('node_id','source','domains','ports','purpose','duration_seconds') if key in selected}
        apply_enabled(False)
        try: self.approvals.revoke(payload['id'])
        except Exception:
            self.approvals.clear()
            apply_enabled(False)
            raise
        audit.record({'event':'domain-revoke','at':utc_now(),'id':payload['id'], **detail})
        return self.status()

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
            if self.approvals.grants or self.approvals.jobs: self.approvals.tick()
            self.error = None
        except (OSError, RuntimeError, ValueError, KeyError, StopIteration, subprocess.TimeoutExpired) as exc:
            audit.record({'event':'controller-failure','error_type':type(exc).__name__})
            self.desired = False
            self.error = str(exc)[:500]
            self.approvals.clear()
            try:
                apply_enabled(False)
            except Exception:
                pass  # Existing kernel lease expires even if control is unavailable.


def make_control_handler(controller):
    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.request.settimeout(1)
            peer = {'channel':'agent' if getattr(self.server, 'request_only', False) else 'administrator'}
            try:
                pid, uid, gid = struct.unpack('3i', self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                peer.update(pid=pid, uid=uid, gid=gid)
            except (AttributeError, OSError):
                pass
            token = audit.actor.set(peer)
            action, payload = 'invalid', None
            try:
                raw = self.rfile.readline(16385)
                if len(raw) > 16384 or not raw.endswith(b"\n"):
                    raise ValueError("invalid control request")
                data = json.loads(raw)
                if not isinstance(data, dict) or set(data) != ({"action", "payload"} if data.get("action") in {"save_nodes","approve_domains","revoke_domain", "decide_domain_request", *PUBLIC_ACTIONS} or (data.get("action") == "enable" and "payload" in data) else {"action"}):
                    raise ValueError("invalid control request")
                known = {'status','audit_log','nodes','enable','disable','save_nodes','approve_domains','revoke_domain','decide_domain_request', *PUBLIC_ACTIONS}
                if not isinstance(data['action'], str) or data['action'] not in known:
                    raise ValueError('unsupported action')
                action = data["action"]
                payload = data.get('payload')
                if getattr(self.server, 'request_only', False) and action not in PUBLIC_ACTIONS:
                    raise ValueError('Request socket cannot perform administrative operations')
                if action not in {'status','audit_log','nodes','domain_request_status'}:
                    audit.operation(action, payload, 'started')
                if action in PUBLIC_ACTIONS:
                    status = controller.agent_request(action, data['payload'])
                elif action == 'decide_domain_request':
                    status = controller.decide_domain_request(data['payload'])
                elif action == "status":
                    status = controller.status()
                elif action == 'audit_log':
                    status = audit.recent(permissions_only=True)
                elif action == "nodes":
                    status = controller.node_settings()
                elif action in {"approve_domains","revoke_domain"}:
                    status = controller.approve_domains(data['payload']) if action == 'approve_domains' else controller.revoke_domain(data['payload'])
                elif action == "save_nodes":
                    status = controller.save_nodes(data["payload"])
                    audit.record({"event":action,"count":len(status["nodes"])})
                elif action in {"enable", "disable"}:
                    status = controller.set_enabled(action == "enable", data.get("payload"))
                    audit.record({"event": action,
                                      "enabled": status["enabled"], "duration_seconds": data.get("payload")})
                else:
                    raise ValueError("unsupported action")
                response = {"ok": True, "status": status}
                if action not in {'status','audit_log','nodes','domain_request_status'}:
                    audit.operation(action, payload, 'success')
            except Exception as exc:
                audit.operation(action, payload, 'failure', exc)
                response = {"ok": False, "error": str(exc)[:500], "conflict":isinstance(exc, node_config.RevisionConflict), "invalid":isinstance(exc, ValueError), "limited":isinstance(exc, RequestLimit)}
            try:
                self.wfile.write((json.dumps(response) + "\n").encode())
            except OSError:
                pass
            finally:
                audit.actor.reset(token)

    return Handler


def run_controller():
    audit.configure()
    audit.record({'event':'controller-starting','reason':'volatile-grants-reset-on-start'})
    controller = Controller()
    controller.approvals.reset_runtime()
    audit.record({"event": "controller-start", "enabled": False, "at": utc_now()})
    running = True
    def stop(*_):
        nonlocal running
        running = False
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    Handler = make_control_handler(controller)

    SOCKET.parent.mkdir(parents=True, exist_ok=True)
    if SOCKET.exists():
        SOCKET.unlink()
    request_path = Path(REQUEST_SOCKET)
    request_path.parent.mkdir(parents=True, exist_ok=True)
    os.chown(request_path.parent, 0, grp.getgrnam('rabbitwall-requests').gr_gid)
    os.chmod(request_path.parent, 0o750)
    request_path.unlink(missing_ok=True)
    with socketserver.UnixStreamServer(str(SOCKET), Handler) as server, socketserver.UnixStreamServer(REQUEST_SOCKET, Handler) as ingress, concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        ingress.request_only = True
        os.chown(request_path, 0, grp.getgrnam('rabbitwall-requests').gr_gid)
        os.chmod(request_path, 0o660)
        os.chmod(SOCKET, 0o660)
        server.timeout = 0.5
        last_tick, last_probe, future = 0.0, 0.0, None
        try:
            while running:
                now = time.monotonic()
                if now - last_tick >= (.5 if controller.approvals.grants else 4):
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
                ready, _, _ = select.select([server, ingress], [], [], .5)
                for selected in ready:
                    selected.handle_request()
        finally:
            audit.record({'event':'controller-stopping'})
            controller.desired = False
            controller.approvals.close()
            apply_enabled(False)
            audit.record({'event':'controller-stop','enabled':False})
            SOCKET.unlink(missing_ok=True)
            request_path.unlink(missing_ok=True)


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
    snippet.write_text(persistent_rules(SETTINGS))
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
