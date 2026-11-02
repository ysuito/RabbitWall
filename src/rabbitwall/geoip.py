"""Offline IPv4 country lookup. No destination addresses leave this machine."""
import ipaddress
from pathlib import Path
import sqlite3
import threading

DEFAULT_DATABASE = Path("/var/lib/rabbitwall/geoip-country.sqlite3")
PRIVATE = tuple(ipaddress.ip_network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


class CountryLookup:
    def __init__(self, path=DEFAULT_DATABASE):
        self.path = Path(path)
        self.lock = threading.Lock()
        self.signature = None
        self.connection = None
        self.cache = {}
        self.error = None
        self.metadata = {}

    def _reload(self):
        try:
            stat = self.path.stat()
            signature = (stat.st_ino, stat.st_mtime_ns, stat.st_size)
        except OSError:
            signature = None
        if signature == self.signature:
            return
        if self.connection:
            self.connection.close()
        self.connection, self.signature, self.cache, self.metadata = None, signature, {}, {}
        self.error = None
        if signature is None:
            return
        connection = None
        try:
            connection = sqlite3.connect(self.path.resolve().as_uri() + "?mode=ro", uri=True, check_same_thread=False)
            connection.execute("PRAGMA query_only=ON")
            metadata = dict(connection.execute("SELECT key,value FROM metadata"))
            connection.execute("SELECT start,end,country FROM ipv4 LIMIT 1").fetchone()
            self.connection, self.metadata = connection, metadata
        except sqlite3.Error:
            if connection:
                connection.close()
            self.error = "国別IPデータベースを読み込めません。"

    def status(self):
        with self.lock:
            self._reload()
            return {"available": self.connection is not None, "error": self.error,
                    "source": self.metadata.get("source", "DB-IP Lite"),
                    "updated_at": self.metadata.get("updated_at"),
                    "edition": self.metadata.get("edition"), "records": self.metadata.get("records"),
                    "attribution_url": "https://db-ip.com"}

    def lookup(self, address):
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return {"code": None, "kind": "unknown"}
        if any(ip in network for network in PRIVATE):
            return {"code": None, "kind": "private"}
        if not ip.is_global:
            return {"code": None, "kind": "special"}
        if ip.version != 4:
            return {"code": None, "kind": "unknown"}
        with self.lock:
            self._reload()
            if address in self.cache:
                return self.cache[address]
            result = {"code": None, "kind": "unknown"}
            if self.connection:
                try:
                    row = self.connection.execute("SELECT end,country FROM ipv4 WHERE start<=? ORDER BY start DESC LIMIT 1", (int(ip),)).fetchone()
                    if row and int(ip) <= row[0] and row[1] != "ZZ":
                        result = {"code": row[1], "kind": "country"}
                except sqlite3.Error:
                    self.error = "国別IPデータベースの照合に失敗しました。"
            if len(self.cache) >= 4096:
                self.cache.clear()
            self.cache[address] = result
            return result

    def enrich(self, state):
        for section in ("flows", "history", "drops"):
            for flow in state.get(section, []):
                flow["src_country"] = self.lookup(flow["src"])
                flow["dst_country"] = self.lookup(flow["dst"])
                if section == "drops":
                    for candidate in flow.get("dns_country_candidates", [])[:8]:
                        candidate["country"] = self.lookup(candidate["address"])
        state["geoip"] = self.status()
        return state
