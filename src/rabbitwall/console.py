#!/usr/bin/env python3
"""Gateway connection monitor and authenticated fixed-purpose internet control."""
import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import sqlite3
import subprocess
import tempfile
import time
from http.server import ThreadingHTTPServer
from http_limits import DeadlineHandler
import threading
from urllib.parse import urlsplit
from control import TOKEN, request_control, validate_duration
from geoip import CountryLookup, DEFAULT_DATABASE
from dns_observations import load_observations, domain_hints, record_answer_history, drop_country_candidates
from traffic_analytics import collect_analytics
from settings import SETTINGS, AI_INTERFACE, AI_IP, UPLINK_IP, metadata, load
import node_config
import domain_approvals
from domain_requests import Requests

AI = AI_INTERFACE.network
LAN = ipaddress.ip_network(SETTINGS["management_cidr"])
RABBITWALL_IPS = {UPLINK_IP, AI_IP}
STATIC = Path(__file__).resolve().parent / "static"
SERVICES = {("tcp", 443): "HTTPS", ("tcp", 80): "HTTP", ("tcp", 22): "SSH",
            ("tcp", 53): "DNS", ("udp", 53): "DNS", ("udp", 123): "NTP",
            ("tcp", 445): "SMB"}


def utc_now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def scope(src):
    if src in RABBITWALL_IPS:
        return "RABBITWALL"
    try:
        if ipaddress.ip_address(src) in AI:
            return "AI"
    except ValueError:
        pass
    return None


def flow_scope(src, dst):
    outgoing = scope(src)
    if outgoing:
        return outgoing
    try:
        if ipaddress.ip_address(src) in LAN and (ipaddress.ip_address(dst) in AI or dst in RABBITWALL_IPS):
            return "MANAGEMENT"
    except ValueError:
        pass
    return None


def parse_conntrack(text):
    """Keep the original tuple, never confuse it with the reply tuple."""
    result = []
    for line in text.splitlines():
        head = re.match(r"(?:ipv4\s+\d+\s+)?(\w+)\s+\d+\s+\d+\s+(.*)", line)
        if not head:
            continue
        proto, tail = head.groups()
        pairs = re.findall(r"(\w+)=([^\s]+)", tail)
        original, reply = {}, {}
        target = original
        for key, value in pairs:
            if key == "src" and "src" in original:
                target = reply
            target.setdefault(key, value)
        category = flow_scope(original.get("src", ""), original.get("dst", ""))
        if not category:
            continue
        def number(mapping, key):
            value = mapping.get(key)
            return int(value) if value and value.isdigit() else None
        state = tail.split()[0] if tail and "=" not in tail.split()[0] else "TRACKED"
        if "[UNREPLIED]" in tail:
            state = "UNREPLIED"
        elif proto != "tcp" and "[ASSURED]" in tail:
            state = "ASSURED"
        sport, dport = number(original, "sport"), number(original, "dport")
        identity = [proto, original["src"], original["dst"], sport, dport,
                    original.get("type"), original.get("code"), original.get("id"),
                    # conntrack id separates re-used tuples where supported.
                    re.findall(r"\bid=(\d+)", tail)[-1:] ]
        result.append({"key": hashlib.sha256(json.dumps(identity).encode()).hexdigest()[:24],
                       "scope": category, "proto": proto.upper(),
                       "src": original["src"], "dst": original["dst"],
                       "sport": sport, "dport": dport, "state": state,
                       "service": SERVICES.get((proto, dport), proto.upper()),
                       "tx_bytes": number(original, "bytes"),
                       "rx_bytes": number(reply, "bytes")})
    return result


def parse_journal(text):
    result = []
    for line in text.splitlines():
        try:
            entry = json.loads(line)
            message = str(entry.get("MESSAGE", ""))
            match = re.search(r"rabbitwall-(input|forward|output)-drop", message)
            fields = dict(re.findall(r"\b([A-Z]+)=([^\s]*)", message))
            category = flow_scope(fields.get("SRC", ""), fields.get("DST", ""))
            if not match or not category:
                continue
            result.append({"time": dt.datetime.fromtimestamp(
                int(entry["__REALTIME_TIMESTAMP"]) / 1e6, dt.timezone.utc).isoformat(),
                "scope": category, "chain": match.group(1),
                "src": fields["SRC"], "dst": fields.get("DST", ""),
                "proto": fields.get("PROTO", ""), "sport": fields.get("SPT", ""),
                "dport": fields.get("DPT", ""), "in": fields.get("IN", ""),
                "out": fields.get("OUT", "")})
        except (ValueError, TypeError, KeyError, OverflowError):
            continue
    return sorted(result, key=lambda item: item["time"], reverse=True)


def command(args, empty_ok=False):
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=15)
        empty_match = empty_ok and proc.returncode == 1 and not proc.stdout.strip() and not proc.stderr.strip()
        if proc.returncode and not empty_match:
            return "", f"{args[0]}: {proc.stderr.strip()[:400] or 'exit ' + str(proc.returncode)}"
        return proc.stdout, None
    except (OSError, subprocess.TimeoutExpired) as exc:
        return "", f"{args[0]}: {exc}"


def update_history(db, flows, now, retention_hours=24, row_limit=20000, dns_records=None, commit=True):
    """Poll observations, not a claim of complete connection-event capture."""
    db.execute("CREATE TABLE IF NOT EXISTS flows (key TEXT PRIMARY KEY, first_seen TEXT, "
               "last_seen TEXT, ended_at TEXT, data TEXT)")
    keys = {flow["key"] for flow in flows}
    for key, in db.execute("SELECT key FROM flows WHERE ended_at IS NULL").fetchall():
        if key not in keys:
            db.execute("UPDATE flows SET ended_at=? WHERE key=?", (now, key))
    for flow in flows:
        # An observed gap starts a new observation interval for a reused key.
        row = db.execute("SELECT first_seen, ended_at, data FROM flows WHERE key=?", (flow["key"],)).fetchone()
        first = row[0] if row and row[1] is None else now
        flow["first_seen"], flow["last_seen"] = first, now
        # Keep evidence attached to the observation interval, even after DNS TTL expiry.
        previous = json.loads(row[2]) if row and row[1] is None else {}
        flow["domain_hints"] = previous.get("domain_hints", [])
        if not flow["domain_hints"] and flow.get("scope") == "AI":
            flow["domain_hints"] = domain_hints(dns_records or [], flow["src"], flow["dst"],
                                                dt.datetime.fromisoformat(first).timestamp())
        db.execute("INSERT OR REPLACE INTO flows VALUES (?,?,?,NULL,?)",
                   (flow["key"], first, now, json.dumps(flow)))
    cutoff = (dt.datetime.fromisoformat(now) - dt.timedelta(hours=retention_hours)).isoformat(timespec="seconds")
    db.execute("DELETE FROM flows WHERE last_seen < ? AND ended_at IS NOT NULL", (cutoff,))
    db.execute("DELETE FROM flows WHERE key IN (SELECT key FROM flows WHERE ended_at IS NOT NULL "
               "ORDER BY last_seen DESC LIMIT -1 OFFSET ?)", (max(0, row_limit - len(flows)),))
    if commit:
        db.commit()
    rows = db.execute("SELECT data,ended_at FROM flows ORDER BY last_seen DESC LIMIT 500").fetchall()
    return [dict(json.loads(data), ended_at=ended) for data, ended in rows]


def atomic_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".state-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as output:
            json.dump(data, output, ensure_ascii=False)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o640)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def collect_once(db, state_path, interval, dns_drops=None):
    now, errors = utc_now(), []
    dns_records = load_observations()
    record_answer_history(db, dns_records, dt.datetime.fromisoformat(now).timestamp())
    raw, error = command(["conntrack", "-L", "-f", "ipv4", "-o", "extended,id"])
    if error:
        errors.append(error)
        flows = []
        # Collector failure must not falsely close previous observations.
        history = []
    else:
        flows = parse_conntrack(raw)
        history = update_history(db, flows, now, dns_records=dns_records, commit=False)
    analytics = collect_analytics(db, flows if error is None else None, dns_records, now, history)
    journal, journal_error = command(["journalctl", "-k", "--since", "5 minutes ago",
                                     "-n", "1000", "--no-pager", "--quiet", "-o", "json",
                                     "--grep", "rabbitwall-(input|forward|output)-drop"], empty_ok=True)
    if journal_error:
        errors.append(journal_error)
    dropped, drop_error = dns_drops.snapshot() if dns_drops is not None else ([], None)
    for entry in dropped:
        entry['dns_country_candidates'] = drop_country_candidates(db, entry, dt.datetime.fromisoformat(now).timestamp())
        entry['scope'] = flow_scope(entry['src'], entry['dst'])
        if entry['chain'] == 'input' and not entry.get('in'): entry['chain'] = 'output'
    if drop_error: errors.append(drop_error)
    drops = sorted(parse_journal(journal) + [entry for entry in dropped if entry['scope']],
                   key=lambda entry:entry['time'], reverse=True)[:200]
    atomic_json(state_path, {"updated_at": now, "interval": interval, "demo": False,
                            "collector_ok": error is None, "errors": errors,
                            "flows": flows, "history": history, "analytics": analytics,
                            "drops": drops})


def demo_state():
    now = utc_now()
    host = next((node['ip'] for node in SETTINGS['nodes'] if node['interface']==SETTINGS['ai_if']), AI_IP)
    admin = SETTINGS['admin_ip']
    raw = "\n".join([
        f"ipv4 2 tcp 6 431999 ESTABLISHED src={host} dst=1.1.1.1 sport=52318 dport=443 packets=45 bytes=8120 src=1.1.1.1 dst={host} sport=443 dport=52318 packets=120 bytes=450000 [ASSURED] mark=0 id=10",
        f"ipv4 2 udp 17 28 src={host} dst={AI_IP} sport=45218 dport=53 packets=1 bytes=68 src={AI_IP} dst={host} sport=53 dport=45218 packets=1 bytes=150 mark=0 id=11",
        f"ipv4 2 tcp 6 431999 ESTABLISHED src={UPLINK_IP} dst=8.8.8.8 sport=53712 dport=443 packets=40 bytes=9400 src=8.8.8.8 dst={UPLINK_IP} sport=443 dport=53712 packets=350 bytes=1840000 [ASSURED] mark=0 id=12",
        f"ipv4 2 tcp 6 431999 ESTABLISHED src={admin} dst={host} sport=50105 dport=22 packets=54 bytes=4200 src={host} dst={admin} sport=22 dport=50105 packets=40 bytes=18200 [ASSURED] mark=0 id=13"])
    flows = parse_conntrack(raw)
    for flow in flows:
        flow.update(first_seen=now, last_seen=now)
        flow["domain_hints"] = ([{"domain": "one.one.one.one", "observed_at": dt.datetime.fromisoformat(now).timestamp()-10,
                                  "expires_at": time.time()+300, "client": flow["src"], "address": flow["dst"]}]
                                if flow["dst"] == "1.1.1.1" else [])
    demo_db = sqlite3.connect(":memory:")
    collect_analytics(demo_db, flows, [], (dt.datetime.fromisoformat(now)-dt.timedelta(seconds=5)).isoformat())
    for flow in flows:
        if flow['scope'] == 'AI':
            flow['tx_bytes'] *= 3; flow['rx_bytes'] *= 4
    analytics = collect_analytics(demo_db, flows, [], now)
    observed = [hint for flow in flows for hint in flow.get('domain_hints', [])]
    record_answer_history(demo_db, observed, dt.datetime.fromisoformat(now).timestamp())
    country_drop = {"time":now, "scope":"AI", "chain":"input", "src":host,
                    "dst":str(AI_IP), "proto":"UDP", "sport":"50322", "dport":"53",
                    "in":SETTINGS['ai_if'], "out":"", "dns_reason":"closed",
                    "dns_questions":[{"name":"one.one.one.one.", "type":"A"}], "dns_error":None}
    country_drop['dns_country_candidates'] = drop_country_candidates(demo_db, country_drop, dt.datetime.fromisoformat(now).timestamp())
    demo_db.close()
    return {"analytics": analytics, "updated_at": now, "interval": 5, "demo": True, "collector_ok": True,
            "errors": [], "flows": flows, "history": [dict(f, ended_at=None) for f in flows],
            "drops": [country_drop, {"time": now, "scope": "AI", "chain": "forward", "src": next((n['ip'] for n in SETTINGS['nodes'] if n['interface']==SETTINGS['ai_if']), AI_IP),
                       "dst": SETTINGS['admin_ip'], "proto": "TCP", "sport": "50123", "dport": "22",
                       "in": SETTINGS["ai_if"], "out": SETTINGS["uplink_if"]},
                      {"time":now, "scope":"AI", "chain":"input", "src":host,
                       "dst":str(AI_IP), "proto":"UDP", "sport":"50321", "dport":"53",
                       "in":SETTINGS['ai_if'], "out":"", "dns_reason":"closed",
                       "dns_questions":[{"name":"example.com.", "type":"AAAA"}], "dns_error":None}]}


class ConsoleServer(ThreadingHTTPServer):
    """Bound total and per-source workers; receive deadlines live in DeadlineHandler."""
    max_workers = 32
    max_per_source = 8
    header_timeout = 5
    body_timeout = 3
    request_queue_size = 16
    daemon_threads = True

    def __init__(self, *args, **kwargs):
        self.slots = threading.BoundedSemaphore(self.max_workers)
        self.source_lock = threading.Lock()
        self.source_counts = {}
        super().__init__(*args, **kwargs)

    def get_request(self):
        request, address = super().get_request()
        request.settimeout(5)
        return request, address

    def process_request(self, request, address):
        source = address[0]
        with self.source_lock:
            accepted = self.source_counts.get(source, 0) < self.max_per_source and self.slots.acquire(blocking=False)
            if accepted:
                self.source_counts[source] = self.source_counts.get(source, 0) + 1
        if not accepted:
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.release_slot(source)
            raise

    def release_slot(self, source):
        with self.source_lock:
            remaining = self.source_counts[source] - 1
            if remaining:
                self.source_counts[source] = remaining
            else:
                del self.source_counts[source]
            self.slots.release()

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.release_slot(address[0])


def make_handler(state_path, port, demo=False, control_callback=None, token_file=TOKEN, geoip_path=DEFAULT_DATABASE):
    callback = control_callback or request_control
    countries = CountryLookup(geoip_path)
    demo_control = {"enabled": False, "available": True, "checked_at": utc_now(),
                    "lease_seconds": 20, "error": None, "nodes": [
                        {"id": "rabbitwall", "name": SETTINGS['label'], "ip": f"{UPLINK_IP} / {AI_IP}", "state": "up", "latency_ms": None, "checked_at": utc_now(), "last_success": utc_now()},
                        *[{"id": node['id'], "name": node['label'], "ip": node['ip'], "state": "up", "latency_ms": 0.6, "checked_at": utc_now(), "last_success": utc_now()} for node in SETTINGS['nodes']]]}


    demo_deadline = None
    demo_grants = {}
    demo_requests = Requests()

    def control_status(action="status", duration_seconds=None):
        nonlocal demo_deadline
        if demo:
            if action != "status":
                demo_control["enabled"] = action == "enable"
                demo_control["mode"] = "full" if action == "enable" else "closed"
                demo_grants.clear()
                demo_deadline = time.monotonic() + duration_seconds if duration_seconds is not None else None
            if demo_deadline is not None and time.monotonic() >= demo_deadline:
                demo_control["enabled"] = False
                demo_control["mode"] = "closed"
                demo_deadline = None
            for key,grant in list(demo_grants.items()):
                if grant['_deadline'] <= time.monotonic(): del demo_grants[key]
            if demo_control.get('mode') != 'full':
                demo_control['mode'] = 'restricted' if demo_grants else 'closed'
            demo_control['enabled'] = demo_control['mode'] != 'closed'
            demo_control['domain_approvals'] = [dict({k:v for k,v in g.items() if k!='_deadline'},remaining_seconds=max(0,g['_deadline']-time.monotonic())) for g in demo_grants.values()]
            demo_control["domain_requests"] = demo_requests.snapshot(demo_control["domain_approvals"])
            demo_control["remaining_seconds"] = max(0, demo_deadline-time.monotonic()) if demo_deadline is not None else None
            demo_control["checked_at"] = utc_now()
            for node in demo_control["nodes"]:
                node["checked_at"] = demo_control["checked_at"]
                node["last_success"] = demo_control["checked_at"]
            return dict(demo_control)
        return callback(action) if duration_seconds is None else callback(action, payload=duration_seconds)

    demo_config = json.loads(json.dumps(SETTINGS))
    demo_lock = threading.Lock()
    if demo:
        node = next((n for n in demo_config['nodes'] if n['interface'] == demo_config['ai_if']), None)
        if node:
            demo_requests.submit(demo_config, node['ip'], {'domains':['example.com'], 'duration_seconds':300,
                                 'purpose':'試験表示：依存パッケージの取得（実通信なし）'})

    def nodes_status(payload=None):
        nonlocal demo_config
        if demo:
            with demo_lock:
                if payload is not None:
                    demo_config = node_config.candidate(demo_config, payload)
                    demo_control['nodes'] = [demo_control['nodes'][0], *[
                        {'id':node['id'], 'name':node['label'], 'ip':node['ip'],
                         'state':'up' if node.get('monitor',True) else 'disabled',
                         'latency_ms':0.6, 'checked_at':utc_now(), 'last_success':utc_now()}
                        for node in demo_config['nodes']]]
                return node_config.document(demo_config)
        return callback('nodes') if payload is None else callback('save_nodes', payload=payload)

    def change_domains(action, request):
        nonlocal demo_deadline
        if action in ('approve_request','reject_request') and (not isinstance(request,dict) or set(request) != {'id'}):
            raise ValueError('id required')
        if not demo:
            operation = 'decide_domain_request' if action in ('approve_request','reject_request') else 'approve_domains' if action == 'approve' else 'revoke_domain'
            data = dict(request, decision='approve' if action == 'approve_request' else 'reject') if action in ('approve_request','reject_request') else request
            return callback(operation, payload=data)
        if action in ('approve_request','reject_request'):
            if not isinstance(request,dict) or set(request) != {'id'}: raise ValueError('id required')
            item = demo_requests.get(request['id'])
            if item['status'] != 'pending': raise ValueError('Request already decided')
            if action == 'approve_request':
                spec = demo_requests.validate_current(demo_config,item)
                change_domains('approve',{k:spec[k] for k in ('node_id','domains','duration_seconds','purpose')})
                demo_requests.decided(item,'approved',demo_grants[item['node_id']]['id'])
            else: demo_requests.decided(item,'rejected')
            return control_status()
        if action == 'approve':
            spec = domain_approvals.validate_request(demo_config,request)
            demo_deadline = None
            demo_control['mode'] = 'restricted'
            grant = dict(spec,id=secrets.token_hex(8),_deadline=time.monotonic()+spec['duration_seconds'],
                         expires_at=(dt.datetime.now(dt.timezone.utc)+dt.timedelta(seconds=spec['duration_seconds'])).isoformat(),
                         records=[{'domain':name,'addresses':['1.1.1.1'],'error':None,'resolving':False} for name in spec['domains']])
            demo_grants[spec['node_id']] = grant
        else:
            if not isinstance(request,dict) or set(request)!={'id'}: raise ValueError('id required')
            key=next((key for key,g in demo_grants.items() if g['id']==request['id']),None)
            if key is None: raise ValueError('Approval no longer exists')
            del demo_grants[key]
        return control_status()

    class Handler(DeadlineHandler):
        server_version = "RabbitWall"

        def log_message(self, fmt, *args):
            pass

        def valid_token(self):
            try:
                expected = token_file.read_text().strip()
            except OSError:
                return False
            provided = self.headers.get("Authorization", "")
            return len(expected) >= 32 and secrets.compare_digest(provided.encode(), ("Bearer " + expected).encode())

        def access_status(self):
            # The proxy header alone grants nothing: the server-only bearer must also match.
            proxy = self.headers.get("X-RabbitWall-Auth") == "mtls" and self.valid_token()
            return {"mode": "demo" if demo else "mtls" if proxy else "local",
                    "can_control": bool(demo or proxy)}

        def valid_request(self, mutation=False):
            # Reject DNS rebinding and cross-origin reads; no CORS is enabled.
            allowed = {f"127.0.0.1:{port}", f"localhost:{port}"}
            if self.headers.get("Host", "") not in allowed:
                self.send_error(403, "Use the localhost SSH tunnel URL")
                return False
            if self.headers.get("Sec-Fetch-Site") == "cross-site":
                self.send_error(403)
                return False
            if mutation and self.headers.get("Origin") != "http://" + self.headers["Host"]:
                self.send_error(403, "Same-origin request required")
                return False
            return True

        def send_payload(self, status, payload, mime="application/json; charset=utf-8"):
            self.connection.settimeout(5)
            if isinstance(payload, dict):
                payload = json.dumps(payload, ensure_ascii=False).encode()
            self.send_response(status)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'")
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()
            self.wfile.write(payload)

        def do_POST(self):
            if not self.valid_request(mutation=True):
                return
            path = urlsplit(self.path).path
            if path not in {"/api/internet", "/api/nodes", "/api/domain-approvals"}:
                self.send_error(404)
                return
            if path in {"/api/nodes","/api/domain-approvals"} and not self.access_status()["can_control"]:
                self.send_payload(403, {"error":"この操作には証明書付きHTTPSで接続してください。"})
                return
            if not demo:
                try:
                    expected = token_file.read_text().strip()
                except OSError:
                    self.send_payload(503, {"error": "操作キーが未導入です。インストール手順を確認してください。"})
                    return
                provided = self.headers.get("Authorization", "")
                if len(expected) < 32 or not secrets.compare_digest(provided.encode(), ("Bearer " + expected).encode()):
                    self.send_payload(403, {"error": "操作キーが正しくありません。"})
                    return
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= (12288 if path in {"/api/nodes","/api/domain-approvals"} else 128) or self.headers.get_content_type() != "application/json":
                    raise ValueError("invalid body")
                data = json.loads(self.rfile.read(size))
                if path == "/api/domain-approvals":
                    if not isinstance(data,dict) or set(data)!={'action','request'} or data['action'] not in ('approve','revoke','approve_request','reject_request'):
                        raise ValueError('action and request required')
                elif path == "/api/nodes":
                    if not isinstance(data, dict) or set(data) != {"nodes", "revision"}: raise ValueError("nodes and revision required")
                elif not isinstance(data, dict) or set(data) not in ({"enabled"}, {"enabled", "duration_seconds"}) or type(data["enabled"]) is not bool:
                    raise ValueError("enabled must be boolean")
                if path == "/api/internet": validate_duration(data["enabled"], data.get("duration_seconds"))
            except (TimeoutError, socket.timeout):
                self.send_payload(408, {"error":"リクエストの受信期限を超えました。"})
                return
            except (ValueError, OSError):
                self.send_payload(400, {"error": "入力形式またはリクエストサイズが正しくありません。"})
                return
            if path == '/api/domain-approvals':
                try:
                    self.send_payload(200,{'control':change_domains(data['action'],data['request']),'demo':demo})
                except ValueError as exc: self.send_payload(400,{'error':str(exc)})
                except Exception as exc: self.send_payload(503,{'error':'限定許可の結果を確認できません。状態を再確認してください。','detail':str(exc)[:300]})
                return
            if path == '/api/nodes':
                try:
                    self.send_payload(200, {'settings':nodes_status(data), 'demo':demo, 'auth':self.access_status()})
                except node_config.RevisionConflict as exc:
                    self.send_payload(409, {'error':str(exc)})
                except ValueError as exc:
                    self.send_payload(400, {'error':str(exc)})
                except Exception as exc:
                    self.send_payload(503, {'error':'保存結果を確認できません。再読み込みして確認してください。', 'detail':str(exc)[:300]})
                return
            try:
                status = control_status("enable" if data["enabled"] else "disable", data.get("duration_seconds"))
                self.send_payload(200, {"control": status, "demo": demo})
            except Exception as exc:
                self.send_payload(503, {"error": "通信状態の変更を確認できませんでした。", "detail": str(exc)[:300]})

        def do_GET(self):
            if not self.valid_request():
                return
            path = urlsplit(self.path).path
            status = 200
            if path == '/api/domain-approvals':
                try: self.send_payload(200, {'control':control_status(), 'demo':demo})
                except Exception: self.send_payload(503, {'error':'制御状態を取得できません。'})
                return
            if path == '/api/nodes':
                try:
                    self.send_payload(200, {'settings':nodes_status(), 'demo':demo, 'auth':self.access_status()})
                except Exception as exc:
                    self.send_payload(503, {'error':'ノード設定を読み込めません。', 'detail':str(exc)[:300]})
                return
            if path == "/api/control":
                try:
                    self.send_payload(200, {"control": control_status(), "demo": demo, "auth": self.access_status()})
                except Exception as exc:
                    self.send_payload(503, {"error": "制御サービスに接続できません。", "detail": str(exc)[:300]})
                return
            elif path == "/api/state":
                try:
                    data = countries.enrich(demo_state() if demo else json.loads(state_path.read_text()))
                    age = (dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(data["updated_at"])).total_seconds()
                    data["network"] = metadata(demo_config if demo else load())
                    data["stale"] = age > max(20, data.get("interval", 5) * 3)
                    payload, mime = json.dumps(data, ensure_ascii=False).encode(), "application/json; charset=utf-8"
                except (OSError, ValueError, KeyError, TypeError) as exc:
                    status, mime = 503, "application/json; charset=utf-8"
                    payload = json.dumps({"error": "収集データを読み込めません。collectorサービスを確認してください。",
                                          "detail": str(exc)[:200]}, ensure_ascii=False).encode()
            elif path in {"/", "/index.html", "/app.js", "/atlas.js", "/request-notifications.js", "/world.json", "/style.css"}:
                filename = "index.html" if path == "/" else path[1:]
                mime = {"html": "text/html; charset=utf-8", "js": "text/javascript; charset=utf-8",
                        "css": "text/css; charset=utf-8", "json": "application/json; charset=utf-8"}[filename.split(".")[-1]]
                payload = (STATIC / filename).read_bytes()
            else:
                self.send_error(404)
                return
            self.send_payload(status, payload, mime)
    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["collect", "serve", "demo"])
    parser.add_argument("--state-dir", type=Path, default=Path("/var/lib/rabbitwall"))
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--interval", type=int, default=5)
    parser.add_argument("--geoip-db", type=Path, default=DEFAULT_DATABASE)
    args = parser.parse_args()
    if args.interval < 2 or not 1 <= args.port <= 65535:
        parser.error("interval >= 2 and valid TCP port required")
    if args.mode != 'demo':
        from settings import require_config
        try: require_config()
        except ValueError as error: parser.error(str(error))
    state_path = args.state_dir / "state.json"
    if args.mode == "collect":
        os.umask(0o027)
        args.state_dir.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(str(args.state_dir / "history.sqlite3"))
        os.chmod(args.state_dir / "history.sqlite3", 0o600)
        from dns_drops import Observer
        dns_drops = Observer().start()
        running = True
        def stop(*_):
            nonlocal running
            running = False
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        try:
            while running:
                collect_once(db, state_path, args.interval, dns_drops)
                for _ in range(args.interval * 10):
                    if not running:
                        break
                    time.sleep(0.1)
        finally:
            dns_drops.close()
            db.close()
    else:
        server = ConsoleServer(("127.0.0.1", args.port), make_handler(state_path, args.port, args.mode == "demo", geoip_path=args.geoip_db))
        print(f"RabbitWall: http://127.0.0.1:{args.port}" + (" [DEMO]" if args.mode == "demo" else ""), flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()


if __name__ == "__main__":
    main()
