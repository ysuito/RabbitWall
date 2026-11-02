"""Bounded observation of DNS packets copied by the nftables drop rules.

libnetfilter_log handles NFLOG framing. These are packet copies, never NFQUEUE
verdicts: loss or collector failure cannot permit or delay the original packet.
"""
from collections import deque
import ctypes as C
import datetime as dt
import ipaddress
import socket
import struct
import threading
import time

GROUP = 100
SNAPLEN = 4096
PREFIX = 'rabbitwall-dns-drop '
CALLBACK = C.CFUNCTYPE(C.c_int, C.c_void_p, C.c_void_p, C.c_void_p, C.c_void_p)


def library():
    try:
        lib = C.CDLL('libnetfilter_log.so.1', use_errno=True)
    except OSError as error:
        raise ValueError('Install libnetfilter-log1 for dropped DNS observation') from error
    signatures = {
        'nflog_open': (C.c_void_p, []),
        'nflog_close': (C.c_int, [C.c_void_p]),
        'nflog_bind_group': (C.c_void_p, [C.c_void_p, C.c_uint16]),
        'nflog_set_mode': (C.c_int, [C.c_void_p, C.c_uint8, C.c_uint32]),
        'nflog_set_qthresh': (C.c_int, [C.c_void_p, C.c_uint32]),
        'nflog_callback_register': (C.c_int, [C.c_void_p, CALLBACK, C.c_void_p]),
        'nflog_fd': (C.c_int, [C.c_void_p]),
        'nflog_handle_packet': (C.c_int, [C.c_void_p, C.c_char_p, C.c_int]),
        'nflog_get_payload': (C.c_int, [C.c_void_p, C.POINTER(C.c_void_p)]),
        'nflog_get_prefix': (C.c_char_p, [C.c_void_p]),
        'nflog_get_indev': (C.c_uint32, [C.c_void_p]),
        'nflog_get_outdev': (C.c_uint32, [C.c_void_p]),
    }
    for name, (result, args) in signatures.items():
        function = getattr(lib, name)
        function.restype, function.argtypes = result, args
    return lib


def decode_packet(packet, chain, now=None):
    """Decode one captured IPv4 UDP query. Do not reassemble IP fragments."""
    if chain not in {'input', 'output', 'forward'} or len(packet) < 20 or packet[0] >> 4 != 4:
        return None
    ihl = (packet[0] & 15)*4
    total = struct.unpack_from('!H', packet, 2)[0]
    if ihl < 20 or total < ihl+8 or len(packet) < ihl+8:
        return None
    proto = packet[9]
    if proto != 17 or struct.unpack_from('!H', packet, 6)[0] & 0x3fff:
        return None
    sport, dport = struct.unpack_from('!HH', packet, ihl)
    if dport != 53:
        return None
    entry = {'time':dt.datetime.fromtimestamp(time.time() if now is None else now, dt.timezone.utc).isoformat(),
             'chain':chain, 'src':str(ipaddress.IPv4Address(packet[12:16])),
             'dst':str(ipaddress.IPv4Address(packet[16:20])),
             'proto':'UDP', 'sport':str(sport), 'dport':'53',
             'dns_questions':[], 'dns_reason':'closed' if chain != 'forward' else 'direct-dns',
             'dns_error':None}
    end = min(total, len(packet))
    length = struct.unpack_from('!H', packet, ihl+4)[0]
    if length < 8 or ihl+length > end:
        entry['dns_error'] = 'UDP DNSパケットが不完全です'
        return entry
    wire = packet[ihl+8:ihl+length]
    try:
        import dns.message
        import dns.flags
        import dns.rdatatype
        message = dns.message.from_wire(wire)
        if message.flags & dns.flags.QR:
            return None
        entry['dns_questions'] = [{'name':q.name.to_text()[:1024],
                                   'type':dns.rdatatype.to_text(q.rdtype)} for q in message.question[:5]]
        if not entry['dns_questions']:
            entry['dns_error'] = '問い合わせ名なし'
    except Exception:
        entry['dns_error'] = 'DNS形式不正・取得範囲外'
    return entry


class Observer:
    def __init__(self):
        self.records = deque(maxlen=200)
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.error = 'DNS拒否の収集を開始中'
        self.thread = None

    def start(self):
        self.thread = threading.Thread(target=self.run, daemon=True, name='dns-drop-observer')
        self.thread.start()
        return self

    def close(self):
        self.stop.set()
        if self.thread: self.thread.join(timeout=3)

    def snapshot(self):
        cutoff = time.monotonic()-300
        with self.lock:
            while self.records and self.records[0][0] < cutoff:
                self.records.popleft()
            return [entry.copy() for _, entry in self.records], self.error

    def run(self):
        while not self.stop.is_set():
            try:
                self.receive()
            except Exception as error:
                with self.lock: self.error = 'DNS拒否の収集失敗: ' + str(error)[:200]
            self.stop.wait(2)

    def receive(self):
        lib = library()
        handle = lib.nflog_open()
        if not handle: raise OSError(C.get_errno(), 'nflog_open')
        try:
            group = lib.nflog_bind_group(handle, GROUP)
            if not group: raise OSError(C.get_errno(), 'NFLOG group 100 unavailable')
            if lib.nflog_set_mode(group, 2, SNAPLEN) < 0 or lib.nflog_set_qthresh(group, 1) < 0:
                raise OSError(C.get_errno(), 'NFLOG configuration failed')

            @CALLBACK
            def observe(_group, _message, data, _unused):
                try:
                    prefix = (lib.nflog_get_prefix(data) or b'').decode('ascii', 'replace')
                    if not prefix.startswith(PREFIX): return 0
                    payload = C.c_void_p()
                    length = lib.nflog_get_payload(data, C.byref(payload))
                    if not 0 < length <= SNAPLEN or not payload.value: return 0
                    entry = decode_packet(C.string_at(payload, length), prefix[len(PREFIX):].strip())
                    if entry:
                        for key, getter in [('in',lib.nflog_get_indev), ('out',lib.nflog_get_outdev)]:
                            index = getter(data)
                            try: entry[key] = socket.if_indextoname(index) if index else ''
                            except OSError: entry[key] = str(index)
                        with self.lock: self.records.append((time.monotonic(), entry))
                except Exception:
                    pass  # A malformed observation must not terminate packet collection.
                return 0

            if lib.nflog_callback_register(group, observe, None) < 0:
                raise OSError(C.get_errno(), 'NFLOG callback registration failed')
            with socket.fromfd(lib.nflog_fd(handle), socket.AF_NETLINK, socket.SOCK_RAW) as connection:
                connection.settimeout(1)
                with self.lock: self.error = None
                while not self.stop.is_set():
                    try:
                        raw = connection.recv(65536)
                    except socket.timeout:
                        continue
                    if lib.nflog_handle_packet(handle, raw, len(raw)) < 0:
                        raise OSError(C.get_errno(), 'NFLOG packet processing failed')
        finally:
            lib.nflog_close(handle)
