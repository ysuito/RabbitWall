import test_environment
import importlib.util
import io
import gzip
import json
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
import sys
from unittest.mock import patch

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / "src/rabbitwall"))


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, str(file))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


console = module("console", BASE / "src/rabbitwall/console.py")
control = module("gate", BASE / "src/rabbitwall/control.py")
geoip = module("countries", BASE / "src/rabbitwall/geoip.py")
geoip_update = module("geoip_update", BASE / "tools/update_geoip.py")


class Connections(unittest.TestCase):
    def test_rabbitwall_downlink_is_not_counted_as_an_ai_endpoint(self):
        self.assertEqual(console.scope("10.1.0.1"), "RABBITWALL")
        self.assertEqual(console.scope("10.2.0.2"), "RABBITWALL")
        self.assertEqual(console.scope("10.1.0.10"), "AI")

    def test_original_reply_and_accounting(self):
        line = "ipv4 2 tcp 6 431999 ESTABLISHED src=10.1.0.10 dst=1.1.1.1 sport=51234 dport=443 packets=2 bytes=150 src=1.1.1.1 dst=10.1.0.10 sport=443 dport=51234 packets=4 bytes=700 [ASSURED] mark=0 id=42"
        flow, = console.parse_conntrack(line)
        self.assertEqual((flow["src"], flow["dst"], flow["sport"], flow["dport"]), ("10.1.0.10", "1.1.1.1", 51234, 443))
        self.assertEqual((flow["tx_bytes"], flow["rx_bytes"]), (150, 700))
        self.assertEqual(flow["state"], "ESTABLISHED")

    def test_filter_and_missing_counters(self):
        lines = "\n".join([
            "udp 17 29 src=10.1.0.10 dst=10.0.0.254 sport=42 dport=53 [UNREPLIED] src=10.0.0.254 dst=10.1.0.10 sport=53 dport=42 mark=0 id=3",
            "tcp 6 10 ESTABLISHED src=10.0.0.9 dst=10.2.0.2 sport=50 dport=22 src=10.2.0.2 dst=10.0.0.9 sport=22 dport=50 id=4",
            "tcp 6 10 ESTABLISHED src=10.2.0.2 dst=1.1.1.1 sport=52 dport=443 src=1.1.1.1 dst=10.2.0.2 sport=443 dport=52 id=5"])
        flows = console.parse_conntrack(lines)
        self.assertEqual(len(flows), 3)
        self.assertEqual(flows[0]["state"], "UNREPLIED")
        self.assertIsNone(flows[0]["tx_bytes"])
        self.assertEqual(flows[1]["scope"], "MANAGEMENT")
        self.assertEqual(flows[2]["scope"], "RABBITWALL")

    def test_management_to_spark_is_recorded_with_original_direction(self):
        line = "ipv4 2 tcp 6 431999 ESTABLISHED src=10.0.0.9 dst=10.1.0.10 sport=50105 dport=22 packets=4 bytes=500 src=10.1.0.10 dst=10.0.0.9 sport=22 dport=50105 packets=6 bytes=1500 [ASSURED] mark=0 id=99"
        flow, = console.parse_conntrack(line)
        self.assertEqual(flow["scope"], "MANAGEMENT")
        self.assertEqual((flow["src"], flow["dst"], flow["service"]), ("10.0.0.9", "10.1.0.10", "SSH"))
        self.assertEqual((flow["tx_bytes"], flow["rx_bytes"]), (500, 1500))
        self.assertIsNone(console.flow_scope("10.0.0.9", "1.1.1.1"))

    def test_icmp_identity(self):
        flow, = console.parse_conntrack("icmp 1 29 src=10.1.0.10 dst=10.1.0.1 type=8 code=0 id=20 src=10.1.0.1 dst=10.1.0.10 type=0 code=0 id=20 mark=0 id=100")
        self.assertEqual(flow["proto"], "ICMP")
        self.assertIsNone(flow["dport"])

    def test_journal_only_ai_scoped_drop_messages(self):
        entry = {"__REALTIME_TIMESTAMP": "1792962000000000", "MESSAGE": "rabbitwall-forward-drop IN=eth1 OUT=eth0 SRC=10.1.0.10 DST=10.0.0.9 PROTO=TCP SPT=123 DPT=22"}
        unrelated = dict(entry, MESSAGE="unrelated SRC=10.1.0.10")
        rows = console.parse_journal(json.dumps(entry) + "\n" + json.dumps(unrelated) + "\nnot json")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["dport"], "22")

    def test_history_closes_missing_and_retains_first_observation(self):
        db = sqlite3.connect(":memory:")
        self.addCleanup(db.close)
        flow = console.demo_state()["flows"][0]
        console.update_history(db, [flow], "2026-10-26T00:00:00+00:00")
        history = console.update_history(db, [flow], "2026-10-26T00:00:05+00:00")
        self.assertEqual(history[0]["first_seen"], "2026-10-26T00:00:00+00:00")
        history = console.update_history(db, [], "2026-10-26T00:00:10+00:00")
        self.assertEqual(history[0]["ended_at"], "2026-10-26T00:00:10+00:00")
        console.update_history(db, [], "2026-10-28T00:00:00+00:00")
        self.assertEqual(db.execute("SELECT COUNT(*) FROM flows").fetchone()[0], 0)

    def test_collection_error_does_not_claim_empty_healthy_network(self):
        with tempfile.TemporaryDirectory() as directory:
            db = sqlite3.connect(":memory:")
            self.addCleanup(db.close)
            with patch.object(console, "command", side_effect=[("", "permission denied"), ("", None)]):
                file = Path(directory) / "state.json"
                console.collect_once(db, file, 5)
                data = json.loads(file.read_text())
                self.assertFalse(data["collector_ok"])
                self.assertIn("permission denied", data["errors"])

    def test_empty_journal_match_is_not_collector_error(self):
        proc = subprocess.CompletedProcess([], 1, "", "")
        with patch.object(console.subprocess, "run", return_value=proc):
            self.assertEqual(console.command(["journalctl"], empty_ok=True), ("", None))
            self.assertIsNotNone(console.command(["conntrack"])[1])


class HTTP(unittest.TestCase):
    def request(self, path, host="127.0.0.1:8765", headers="", state_path=None, demo=True,
                method="GET", body="", handler=None):
        class Connection:
            def __init__(self):
                self.output = bytearray()
            def makefile(self, mode, *args):
                return io.BytesIO(f"{method} {path} HTTP/1.0\r\nHost: {host}\r\n{headers}\r\n{body}".encode())
            def sendall(self, data):
                self.output.extend(data)
            def settimeout(self, _):
                pass
        conn = Connection()
        handler = handler or console.make_handler(state_path or Path("/no-state-file"), 8765, demo)
        handler(conn, ("127.0.0.1", 50000), object())
        return bytes(conn.output)

    def test_demo_api_and_headers(self):
        response = self.request("/api/state")
        head, body = response.split(b"\r\n\r\n", 1)
        self.assertIn(b"200 OK", head)
        self.assertIn(b"Content-Security-Policy:", head)
        data = json.loads(body)
        self.assertTrue(data["demo"])
        self.assertTrue(any(flow["scope"] == "MANAGEMENT" and flow["dst"] == "10.1.0.10" for flow in data["flows"]))
        self.assertEqual(data["flows"][0]["src_country"]["kind"], "private")
        self.assertIn("geoip", data)

    def test_reject_rebinding_cross_site_and_path_traversal(self):
        self.assertIn(b"403", self.request("/api/state", host="attacker.example"))
        self.assertIn(b"403", self.request("/api/state", headers="Sec-Fetch-Site: cross-site\r\n"))
        self.assertIn(b"404", self.request("/../console.py"))

    def test_atlas_assets_are_served_locally(self):
        script = self.request("/atlas.js")
        self.assertIn(b"200 OK", script.split(b"\r\n\r\n",1)[0])
        self.assertIn(b"text/javascript", script)
        response = self.request("/world.json")
        head, body = response.split(b"\r\n\r\n",1)
        self.assertIn(b"application/json",head)
        self.assertTrue(json.loads(body)["countries"]["JP"]["point"])

    def test_missing_collector_state_is_unavailable(self):
        self.assertIn(b"503", self.request("/api/state", demo=False))

    def test_stale_snapshot_marked(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "state.json"
            data = console.demo_state()
            data["updated_at"] = "2000-01-01T00:00:00+00:00"
            console.atomic_json(file, data)
            response = self.request("/api/state", state_path=file, demo=False)
            self.assertTrue(json.loads(response.split(b"\r\n\r\n", 1)[1])["stale"])

    def test_mutation_requires_same_origin_and_valid_token(self):
        body = '{"enabled":true}'
        headers = f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n"
        with tempfile.TemporaryDirectory() as directory:
            token = Path(directory) / "token"
            token.write_text("x" * 43)
            callback = unittest.mock.Mock(return_value={"enabled": True, "available": True})
            handler = console.make_handler(Path(directory) / "state", 8765, control_callback=callback, token_file=token)
            response = self.request("/api/internet", method="POST", headers=headers, body=body, handler=handler)
            self.assertIn(b"403", response)
            response = self.request("/api/internet", method="POST", headers=headers + "Origin: http://127.0.0.1:8765\r\n", body=body, handler=handler)
            self.assertIn(b"403", response)
            callback.assert_not_called()
            headers += "Origin: http://127.0.0.1:8765\r\nAuthorization: Bearer " + "x" * 43 + "\r\n"
            response = self.request("/api/internet", method="POST", headers=headers, body=body, handler=handler)
            self.assertIn(b"200 OK", response)
            callback.assert_called_once_with("enable")
            callback.reset_mock()
            body = '{"enabled":true,"duration_seconds":300}'
            headers = f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\nOrigin: http://127.0.0.1:8765\r\nAuthorization: Bearer " + "x" * 43 + "\r\n"
            response = self.request("/api/internet", method="POST", headers=headers, body=body, handler=handler)
            self.assertIn(b"200 OK", response)
            callback.assert_called_once_with("enable", payload=300)

    def test_proxy_auth_metadata_needs_server_only_key(self):
        with tempfile.TemporaryDirectory() as directory:
            token = Path(directory) / "token"
            token.write_text("x" * 43)
            handler = console.make_handler(Path(directory) / "state", 8765,
                        control_callback=lambda _: {"enabled": False, "available": True}, token_file=token)
            for headers, permitted in [("", False), ("X-RabbitWall-Auth: mtls\r\n", False),
                    ("X-RabbitWall-Auth: mtls\r\nAuthorization: Bearer wrong\r\n", False),
                    ("X-RabbitWall-Auth: mtls\r\nAuthorization: Bearer " + "x" * 43 + "\r\n", True)]:
                response = self.request("/api/control", headers=headers, handler=handler)
                body = response.split(b"\r\n\r\n", 1)[1]
                self.assertEqual(json.loads(body)["auth"]["can_control"], permitted)
                self.assertNotIn(b"x" * 43, body)

    def test_mutation_rejects_unexpected_fields_and_non_boolean(self):
        callback = unittest.mock.Mock()
        handler = console.make_handler(Path("/none"), 8765, demo=True, control_callback=callback)
        for body in ['{"enabled":"false"}', '{"enabled":true,"command":"flush ruleset"}', '[]']:
            headers = f"Origin: http://127.0.0.1:8765\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n"
            self.assertIn(b"400", self.request("/api/internet", method="POST", headers=headers, body=body, handler=handler))
        callback.assert_not_called()

    def test_timed_gate_api_validation_and_demo_expiry(self):
        callback = unittest.mock.Mock()
        handler = console.make_handler(Path("/none"), 8765, demo=True, control_callback=callback)
        def post(data):
            body = json.dumps(data)
            headers = f"Origin: http://127.0.0.1:8765\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n"
            return self.request("/api/internet", method="POST", headers=headers, body=body, handler=handler)
        for duration in (True, 0, "60", 60.0, 61):
            self.assertIn(b"400", post({"enabled":True, "duration_seconds":duration}))
        self.assertIn(b"400", post({"enabled":False, "duration_seconds":60}))
        with patch.object(console.time, "monotonic", return_value=100) as now:
            self.assertIn(b"200 OK", post({"enabled":True, "duration_seconds":60}))
            now.return_value = 161
            response = self.request("/api/control", handler=handler)
            state = json.loads(response.split(b"\r\n\r\n",1)[1])["control"]
            self.assertFalse(state["enabled"])
            self.assertIsNone(state["remaining_seconds"])
        callback.assert_not_called()

    def test_demo_toggle_has_no_real_controller_side_effect(self):
        callback = unittest.mock.Mock()
        handler = console.make_handler(Path("/none"), 8765, demo=True, control_callback=callback)
        body = '{"enabled":true}'
        headers = f"Origin: http://127.0.0.1:8765\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n"
        self.assertIn(b"200 OK", self.request("/api/internet", method="POST", headers=headers, body=body, handler=handler))
        response = self.request("/api/control", handler=handler)
        self.assertTrue(json.loads(response.split(b"\r\n\r\n", 1)[1])["control"]["enabled"])
        callback.assert_not_called()


class Gate(unittest.TestCase):
    def controller(self):
        with patch.object(control, "install_runtime", return_value=42):
            return control.Controller()

    def test_off_is_empty_set_on_has_bounded_lease(self):
        with patch.object(control, "nft") as nft:
            control.apply_enabled(False)
            self.assertNotIn("add element", nft.call_args[0][1])
            control.apply_enabled(True)
            self.assertIn("10.1.0.0/24 timeout 20s", nft.call_args[0][1])
            self.assertNotIn("flush ruleset", nft.call_args[0][1])

    def test_expiry_and_reload_do_not_restore_on(self):
        controller = self.controller()
        controller.desired = True
        with patch.object(control, "read_gate", return_value={"handle": 42, "enabled": False}), patch.object(control, "apply_enabled") as apply:
            controller.tick()
            self.assertFalse(controller.desired)
            apply.assert_not_called()
        controller.desired = True
        with patch.object(control, "read_gate", return_value={"handle": 50, "enabled": False}), patch.object(control, "apply_enabled") as apply:
            controller.status()
            self.assertFalse(controller.desired)
            apply.assert_called_once_with(False)

    def test_nft_failure_stops_renewing_lease(self):
        controller = self.controller()
        controller.desired = True
        with patch.object(control, "read_gate", side_effect=RuntimeError("netlink failed")), patch.object(control, "apply_enabled") as apply:
            controller.tick()
            self.assertFalse(controller.desired)
            self.assertEqual(controller.error, "netlink failed")
            apply.assert_called_once_with(False)

    def test_probe_uses_fixed_addresses_and_preserves_last_success(self):
        success = subprocess.CompletedProcess([], 0, "64 bytes time=0.43 ms", "")
        failed = subprocess.CompletedProcess([], 1, "", "")
        with patch.object(control.subprocess, "run", side_effect=[success, failed]) as run:
            nodes = control.probe_nodes([{"id": "ai-host", "last_success": "previous"}])
            self.assertEqual(nodes[1]["state"], "up")
            self.assertEqual(nodes[2]["state"], "no_reply")
            self.assertEqual(nodes[2]["last_success"], "previous")
            self.assertEqual(run.call_args_list[1][0][0][-1], "10.1.0.10")

    def test_timed_gate_expires_and_cannot_renew_after_deadline(self):
        controller = self.controller()
        gate = {"handle": 42, "enabled": False}
        def apply(enabled, **kwargs):
            gate["enabled"] = enabled
        with patch.object(control, "read_gate", side_effect=lambda: dict(gate)), patch.object(control, "apply_enabled", side_effect=apply) as change, patch.object(control.time, "monotonic", return_value=100) as now:
            status = controller.set_enabled(True, 60)
            self.assertEqual(status["remaining_seconds"], 60)
            now.return_value = 155
            controller.tick()
            change.assert_called_with(True, lease_ms=5000)
            now.return_value = 160
            controller.tick()
            self.assertFalse(controller.status()["enabled"])
            self.assertFalse(controller.desired)
            self.assertIsNone(controller.deadline)
            change.assert_called_with(False)
            now.return_value = 200
            change.reset_mock()
            controller.tick()
            change.assert_not_called()

    def test_timed_gate_reset_manual_close_and_validation(self):
        controller = self.controller()
        gate = {"handle":42, "enabled":False}
        def apply(enabled, **kwargs): gate["enabled"] = enabled
        with patch.object(control, "read_gate", side_effect=lambda: dict(gate)), patch.object(control, "apply_enabled", side_effect=apply) as change, patch.object(control.time, "monotonic", return_value=100) as now:
            for duration in (0, -1, True, 61, "60", 60.0):
                with self.assertRaises(ValueError): controller.set_enabled(True, duration)
            with self.assertRaises(ValueError): controller.set_enabled(False, 60)
            change.assert_not_called()
            controller.set_enabled(True, 60)
            now.return_value = 110
            self.assertEqual(controller.set_enabled(True, 300)["remaining_seconds"], 300)
            controller.set_enabled(False)
            self.assertIsNone(controller.deadline)
            controller.set_enabled(True, 1800)
            controller.set_enabled(True)
            self.assertIsNone(controller.deadline)
            controller.tick()
            change.assert_called_with(True)

    def test_persistent_install_validates_before_replacing_config(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "nftables.conf"
            original = "flush ruleset\ntable inet rabbitwall_filter {}\n"
            config.write_text(original)
            snippet = Path(directory) / "snippet.nft"
            nodes_config = Path(directory) / "nodes" / "nodes.json"
            with patch.object(control, "NODES_CONFIG", nodes_config), patch.object(control, "nft", side_effect=RuntimeError("syntax error")) as nft:
                with self.assertRaisesRegex(RuntimeError, "syntax error"):
                    control.install_persistent(config, snippet, Path(directory) / "token")
            nft.assert_called_once()
            self.assertEqual(config.read_text(), original)
            self.assertFalse(snippet.exists())


class Countries(unittest.TestCase):
    def build(self, directory, code="AU"):
        source = Path(directory) / "country.csv.gz"
        with gzip.open(source, "wt", encoding="utf-8") as output:
            output.write(f"1.0.0.0,1.0.0.255,{code}\n8.8.8.0,8.8.8.255,US\n2001:4860::,2001:4860::ffff,US\n")
        database = Path(directory) / "country.sqlite3"
        self.assertEqual(geoip_update.build_database(source, database, "2026-10"), 2)
        return database

    def test_offline_lookup_private_special_unknown_and_range_boundaries(self):
        with tempfile.TemporaryDirectory() as directory:
            lookup = geoip.CountryLookup(self.build(directory))
            self.addCleanup(lambda: lookup.connection and lookup.connection.close())
            self.assertEqual(lookup.lookup("1.0.0.0")["code"], "AU")
            self.assertEqual(lookup.lookup("1.0.0.255")["code"], "AU")
            self.assertEqual(lookup.lookup("1.0.1.0")["kind"], "unknown")
            self.assertEqual(lookup.lookup("8.8.8.8")["code"], "US")
            self.assertEqual(lookup.lookup("10.1.0.10")["kind"], "private")
            self.assertEqual(lookup.lookup("203.0.113.10")["kind"], "special")
            self.assertTrue(lookup.status()["available"])
            self.assertEqual(lookup.status()["edition"], "2026-10")

    def test_database_replacement_reloads_cached_countries(self):
        with tempfile.TemporaryDirectory() as directory:
            lookup = geoip.CountryLookup(self.build(directory))
            self.addCleanup(lambda: lookup.connection and lookup.connection.close())
            self.assertEqual(lookup.lookup("1.0.0.1")["code"], "AU")
            self.build(directory, "NZ")
            self.assertEqual(lookup.lookup("1.0.0.1")["code"], "NZ")

    def test_missing_or_corrupt_database_does_not_break_session_display(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "missing.sqlite3"
            lookup = geoip.CountryLookup(file)
            self.addCleanup(lambda: lookup.connection and lookup.connection.close())
            self.assertFalse(lookup.status()["available"])
            self.assertEqual(lookup.lookup("8.8.8.8")["kind"], "unknown")
            file.write_text("not a database")
            state = lookup.enrich(console.demo_state())
            self.assertTrue(state["flows"])
            self.assertFalse(state["geoip"]["available"])
            self.assertIn("読み込めません", state["geoip"]["error"])

    def test_bad_download_import_preserves_existing_database(self):
        with tempfile.TemporaryDirectory() as directory:
            file = self.build(directory)
            original = file.read_bytes()
            source = Path(directory) / "invalid.csv.gz"
            with gzip.open(source, "wt") as output:
                output.write("8.8.8.255,8.8.8.0,US\n")
            with self.assertRaises(ValueError):
                geoip_update.build_database(source, file, "2026-11")
            self.assertEqual(file.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
