"""Bounded local audit trail; no credentials or arbitrary request bodies."""
import contextvars
import datetime as dt
import ipaddress
import json
import logging.handlers
import os
from pathlib import Path
import re
import sys
import threading

PATH = Path('/var/log/rabbitwall/audit.jsonl')
actor = contextvars.ContextVar('audit_actor', default=None)
_handler = None
_lock = threading.Lock()


class PrivateRotatingFile(logging.handlers.RotatingFileHandler):
    def _open(self):
        fd = os.open(self.baseFilename, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        os.fchmod(fd, 0o600)
        return os.fdopen(fd, 'a', encoding='utf-8')

    def handleError(self, record):
        raise  # Let record() report failure to the service journal.


def configure(path=PATH, max_bytes=5*1024*1024, backups=10):
    global _handler
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with _lock:
        if _handler is not None:
            _handler.close()
        _handler = PrivateRotatingFile(path, maxBytes=max_bytes, backupCount=backups, encoding='utf-8')
        _handler.setFormatter(logging.Formatter('%(message)s'))


def record(data):
    entry = dict(data)
    entry.setdefault('at', dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds'))
    if actor.get() is not None:
        entry['actor'] = actor.get()
    line = json.dumps(entry, ensure_ascii=True, separators=(',', ':'))
    # Preserve journal output even if storage becomes unavailable.
    print(line, flush=True)
    with _lock:
        if _handler is not None:
            try:
                _handler.emit(logging.LogRecord('rabbitwall.audit', logging.INFO, '', 0, line, (), None))
                os.fsync(_handler.stream.fileno())
            except (OSError, ValueError):
                print('{"event":"audit-write-failed","fallback":"service-journal"}', file=sys.stderr, flush=True)


def operation(action, payload, outcome, error=None):
    """Allowlist metadata even for invalid/hostile operations; never log raw JSON."""
    entry = {'event':'control-operation', 'action':action, 'outcome':outcome}
    if isinstance(payload, dict):
        if isinstance(payload.get('request'), dict):
            data = payload['request']
            try: entry['source'] = str(ipaddress.IPv4Address(payload.get('source')))
            except (ValueError, ipaddress.AddressValueError): pass
        else:
            data = payload
        identity = data.get('id')
        if isinstance(identity, str) and re.fullmatch('[0-9a-f]{16}|[0-9a-f]{32}', identity):
            entry['id'] = identity
    if error is not None:
        entry['error_type'] = type(error).__name__
    record(entry)


def permission_event(entry):
    if entry.get('event') in {'domain-request','domain-approval','domain-request-decision',
                              'domain-revoke','domain-ended','enable','disable','gate-ended'}:
        return True
    return (entry.get('event') == 'control-operation' and entry.get('outcome') == 'failure'
            and entry.get('action') in {'submit_domain_request','revoke_domain_request',
                'decide_domain_request','approve_domains','revoke_domain','enable','disable'})


def recent(path=PATH, limit=200, budget=1024*1024, permissions_only=False):
    """Read a bounded tail across rotations; paths are never supplied by clients."""
    entries = []
    available = False
    for index in range(11):
        file = Path(str(path) + (f'.{index}' if index else ''))
        try:
            with file.open('rb') as stream:
                available = True
                size = stream.seek(0, os.SEEK_END)
                start = max(0, size-budget)
                stream.seek(start)
                raw = stream.read(budget)
        except FileNotFoundError:
            continue
        budget -= len(raw)
        lines = raw.splitlines()
        if start: lines = lines[1:]  # Discard a possibly incomplete first record.
        for line in reversed(lines):
            try: entry = json.loads(line)
            except (ValueError, UnicodeDecodeError): continue
            if not isinstance(entry, dict): continue
            if permissions_only and not permission_event(entry): continue
            entries.append(entry)
            if len(entries) >= limit:
                return {'entries':entries, 'available':available, 'limited':True}
        if budget <= 0:
            return {'entries':entries, 'available':available, 'limited':True}
    return {'entries':entries, 'available':available, 'limited':False}
