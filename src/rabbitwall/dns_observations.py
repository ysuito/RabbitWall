"""Bounded, short-lived DNS evidence; this is a hint, never an HTTP host claim."""
import json
from pathlib import Path
import time

OBSERVATIONS = Path('/run/rabbitwall-dns/observations.json')
MAX_RECORDS = 10000


def load_observations(path=OBSERVATIONS):
    try:
        if path.stat().st_size > 8_000_000:
            return []
        data = json.loads(path.read_text())
        return data.get('records', [])[:MAX_RECORDS]
    except (OSError, ValueError, TypeError, AttributeError):
        return []


def domain_hints(records, client, address, now=None):
    now = time.time() if now is None else now
    candidates = {}
    for item in records:
        try:
            if (item['client'] == client and item['address'] == address
                    and item['observed_at'] <= now < item['expires_at']):
                name = item['domain']
                if isinstance(name, str) and len(name) <= 254:
                    candidates[name] = item
        except (KeyError, TypeError):
            continue
    return sorted(candidates.values(), key=lambda item: item['observed_at'], reverse=True)[:8]


HISTORY_DAYS = 30
HISTORY_LIMIT = 10000


def normalized_domain(value):
    if not isinstance(value, str) or not 0 < len(value) <= 254 or '\x00' in value:
        return None
    return value.rstrip('.').lower() or None


def record_answer_history(db, records, now):
    """Persist bounded passive evidence, not a DNS cache or a resolver."""
    import ipaddress
    import math
    from settings import AI_INTERFACE
    db.execute('''CREATE TABLE IF NOT EXISTS dns_answer_history
                  (client TEXT, domain TEXT, address TEXT, observed_at REAL, expires_at REAL,
                   PRIMARY KEY(client,domain,address))''')
    db.execute('CREATE INDEX IF NOT EXISTS dns_answer_domain ON dns_answer_history(domain,observed_at)')
    db.execute('CREATE INDEX IF NOT EXISTS dns_answer_time ON dns_answer_history(observed_at)')
    cutoff = now-HISTORY_DAYS*86400
    for item in records[:MAX_RECORDS]:
        try:
            domain = normalized_domain(item['domain'])
            client, address = ipaddress.ip_address(item['client']), ipaddress.ip_address(item['address'])
            observed, expires = item['observed_at'], item['expires_at']
            if (not domain or client not in AI_INTERFACE.network or not address.is_global
                    or any(type(v) not in (int,float) or not math.isfinite(v) for v in (observed, expires))
                    or not cutoff <= observed <= now or expires <= observed):
                continue
            db.execute('''INSERT INTO dns_answer_history VALUES (?,?,?,?,?)
                          ON CONFLICT(client,domain,address) DO UPDATE SET
                          observed_at=excluded.observed_at,expires_at=excluded.expires_at
                          WHERE excluded.observed_at>dns_answer_history.observed_at''',
                       (str(client),domain,str(address),observed,expires))
        except (KeyError, TypeError, ValueError):
            continue
    db.execute('DELETE FROM dns_answer_history WHERE observed_at<?', (cutoff,))
    db.execute('''DELETE FROM dns_answer_history WHERE rowid IN
                  (SELECT rowid FROM dns_answer_history ORDER BY observed_at DESC,rowid DESC
                   LIMIT -1 OFFSET ?)''', (HISTORY_LIMIT,))


def drop_country_candidates(db, drop, now):
    """Historical address candidates only. Never resolve a dropped question."""
    import datetime as dt
    try:
        at = min(now, dt.datetime.fromisoformat(drop['time']).timestamp())
    except (KeyError, TypeError, ValueError):
        return []
    candidates, seen = [], set()
    for question in drop.get('dns_questions', [])[:5]:
        domain = normalized_domain(question.get('name'))
        if not domain:
            continue
        rows = db.execute('''SELECT address,observed_at,expires_at,client FROM dns_answer_history
                             WHERE domain=? AND observed_at>=? AND observed_at<=?
                             ORDER BY (client=?) DESC,observed_at DESC,address LIMIT 64''',
                          (domain,at-HISTORY_DAYS*86400,at,drop['src'])).fetchall()
        for address, observed, expires, client in rows:
            key = (domain,address)
            if key in seen:
                continue
            seen.add(key)
            candidates.append({'domain':domain,'address':address,'observed_at':observed,
                               'expires_at':expires,'same_client':client==drop['src']})
            if len(candidates) >= 8:
                return candidates
    return candidates
