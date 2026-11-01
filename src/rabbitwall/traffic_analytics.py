"""Persistent DNS first-seen catalogue and sampled counter deltas for AI egress."""
import datetime as dt
import ipaddress
import json
import math
from settings import AI_INTERFACE

DOMAIN_LIMIT = 100000
DAY = 86400
WINDOWS = (("1h", 3600), ("24h", DAY), ("7d", 7*DAY), ("30d", 30*DAY))


def schema(db, now):
    statements = '''
        CREATE TABLE IF NOT EXISTS analytics_meta (key TEXT PRIMARY KEY, value REAL);
        CREATE TABLE IF NOT EXISTS known_domains
          (name TEXT PRIMARY KEY, first_seen REAL NOT NULL, last_seen REAL NOT NULL);
        CREATE INDEX IF NOT EXISTS domain_first_seen ON known_domains(first_seen);
        CREATE TABLE IF NOT EXISTS traffic_samples
          (key TEXT PRIMARY KEY, first_seen TEXT, sampled_at REAL, tx INTEGER, rx INTEGER);
        CREATE TABLE IF NOT EXISTS traffic_minutes
          (minute INTEGER, client TEXT, destination TEXT, domains TEXT,
           tx INTEGER NOT NULL, rx INTEGER NOT NULL,
           PRIMARY KEY(minute,client,destination,domains));
    '''
    for statement in statements.split(';'):
        if statement.strip():
            db.execute(statement)
    db.execute("INSERT OR IGNORE INTO analytics_meta VALUES ('since',?)", (now,))
    db.execute("""CREATE TABLE IF NOT EXISTS traffic_hours
                  (hour INTEGER, client TEXT, destination TEXT, domains TEXT,
                   tx INTEGER NOT NULL, rx INTEGER NOT NULL,
                   PRIMARY KEY(hour,client,destination,domains))""")
    # Existing minute samples remain usable; already expired data cannot be recovered.
    db.execute("""INSERT OR IGNORE INTO analytics_meta
                  SELECT 'long_since',COALESCE(MIN(minute),?) FROM traffic_minutes""", (now,))


def public_ai(flow):
    try:
        return flow.get('scope') == 'AI' and ipaddress.ip_address(flow['dst']).is_global
    except (KeyError, ValueError):
        return False


def names_of(flow):
    return sorted({hint['domain'].lower() for hint in flow.get('domain_hints', [])
                   if isinstance(hint.get('domain'), str) and 0 < len(hint['domain']) <= 254})[:8]


def counter(value):
    return value if type(value) is int and value >= 0 else None


def register_domains(db, records, flows, now):
    observations = {}
    for record in list(records) + [hint for flow in flows for hint in flow.get('domain_hints', [])]:
        name, observed = record.get('domain'), record.get('observed_at')
        if (not isinstance(name, str) or not 0 < len(name) <= 254 or '\x00' in name
                or type(observed) not in (int, float) or not 0 < observed <= now):
            continue
        try:
            if ipaddress.ip_address(record.get('client', '')) not in AI_INTERFACE.network:
                continue
        except ValueError:
            continue
        name = name.lower()
        observations[name] = max(observations.get(name, 0), observed)
    count = db.execute('SELECT COUNT(*) FROM known_domains').fetchone()[0]
    for name, observed in observations.items():
        row = db.execute('SELECT last_seen FROM known_domains WHERE name=?', (name,)).fetchone()
        if row:
            if observed > row[0]:
                db.execute('UPDATE known_domains SET last_seen=? WHERE name=?', (observed, name))
        elif count < DOMAIN_LIMIT:
            # First seen by this collector, rather than a guessed Internet registration date.
            db.execute('INSERT INTO known_domains VALUES (?,?,?)', (name, observed, observed))
            count += 1
    return count >= DOMAIN_LIMIT


def sample_traffic(db, flows, now):
    tracked = missing = 0
    keys = set()
    for flow in flows:
        if not public_ai(flow):
            continue
        key = flow['key']; keys.add(key)
        tx, rx = counter(flow.get('tx_bytes')), counter(flow.get('rx_bytes'))
        tracked += tx is not None and rx is not None
        missing += tx is None or rx is None
        old = db.execute('SELECT first_seen,sampled_at,tx,rx FROM traffic_samples WHERE key=?', (key,)).fetchone()
        delta_tx = delta_rx = 0
        # First observation is a baseline, not traffic supposedly sent in this time window.
        # Do not assign a counter spanning a collector outage to the current minute.
        if old and old[0] == flow['first_seen'] and 0 < now-old[1] <= 30:
            if tx is not None and old[2] is not None and tx >= old[2]: delta_tx = tx-old[2]
            if rx is not None and old[3] is not None and rx >= old[3]: delta_rx = rx-old[3]
        db.execute('INSERT OR REPLACE INTO traffic_samples VALUES (?,?,?,?,?)',
                   (key, flow['first_seen'], now, tx, rx))
        if delta_tx or delta_rx:
            domains = json.dumps(names_of(flow), ensure_ascii=False)
            db.execute('''INSERT INTO traffic_minutes VALUES (?,?,?,?,?,?)
                ON CONFLICT(minute,client,destination,domains) DO UPDATE SET
                tx=tx+excluded.tx,rx=rx+excluded.rx''',
                (int(now)//60*60, flow['src'], flow['dst'], domains, delta_tx, delta_rx))
    for key, in db.execute('SELECT key FROM traffic_samples').fetchall():
        if key not in keys:
            db.execute('DELETE FROM traffic_samples WHERE key=?', (key,))
    return {'tracked': tracked, 'missing': missing}


def rankings(rows):
    by_ip, by_domain = {}, {}
    for client, destination, encoded, tx, rx in rows:
        names = json.loads(encoded)
        ip_item = by_ip.setdefault(destination, {'label': destination, 'addresses': {destination},
                                                 'domains': set(), 'tx_bytes': 0, 'rx_bytes': 0})
        ip_item['domains'].update(names)
        # A shared IP's bytes must not be copied into every candidate domain's total.
        label = names[0] if len(names) == 1 else ('複数候補 / ' if names else 'ドメイン不明 / ') + destination
        domain_item = by_domain.setdefault(label, {'label': label, 'addresses': set(),
                                                   'domains': set(), 'tx_bytes': 0, 'rx_bytes': 0})
        domain_item['addresses'].add(destination); domain_item['domains'].update(names)
        for item in (ip_item, domain_item):
            item['tx_bytes'] += tx; item['rx_bytes'] += rx
    def serialize(items):
        # Union of each sort's top 20: bound the API without hiding TX-heavy rows.
        selected = {}
        for metric in ('tx_bytes', 'rx_bytes', 'total'):
            score = lambda item: item['tx_bytes']+item['rx_bytes'] if metric == 'total' else item[metric]
            for item in sorted(items.values(), key=lambda item: (-score(item), item['label']))[:20]:
                selected[item['label']] = item
        return [dict(item, addresses=sorted(item['addresses'])[:16], domains=sorted(item['domains'])[:8])
                for item in selected.values()]
    return {'by_ip': serialize(by_ip), 'by_domain': serialize(by_domain),
            'tx_bytes': sum(row[3] for row in rows), 'rx_bytes': sum(row[4] for row in rows)}


def compact_traffic(db, now):
    # Move complete hours older than a day exactly once, in the collector transaction.
    cutoff = int((now-DAY)//3600)*3600
    db.execute("""INSERT INTO traffic_hours
        SELECT (minute/3600)*3600,client,destination,domains,SUM(tx),SUM(rx)
        FROM traffic_minutes WHERE minute<? GROUP BY 1,2,3,4
        ON CONFLICT(hour,client,destination,domains) DO UPDATE SET
        tx=tx+excluded.tx,rx=rx+excluded.rx""", (cutoff,))
    db.execute('DELETE FROM traffic_minutes WHERE minute<?', (cutoff,))
    db.execute('DELETE FROM traffic_hours WHERE hour<?', (now-30*DAY,))


def summarize(db, now, coverage, limit_reached=False):
    windows = {}
    for name, duration in WINDOWS:
        # Round up to a complete bucket at the selected window resolution.
        resolution = 3600 if duration > DAY else 60
        cutoff = math.ceil((now-duration)/resolution)*resolution
        rows = db.execute('''SELECT client,destination,domains,SUM(tx),SUM(rx)
                             FROM traffic_minutes WHERE minute>=? AND minute<=?
                             GROUP BY client,destination,domains''', (cutoff, now)).fetchall()
        if duration > DAY:
            rows += db.execute("""SELECT client,destination,domains,SUM(tx),SUM(rx)
                                  FROM traffic_hours WHERE hour>=? AND hour<=?
                                  GROUP BY client,destination,domains""", (cutoff, now)).fetchall()
        windows[name] = rankings(rows)
        since_key = 'long_since' if duration > DAY else 'since'
        since = db.execute('SELECT value FROM analytics_meta WHERE key=?', (since_key,)).fetchone()[0]
        windows[name]['available_since'] = max(cutoff, since)
        windows[name]['resolution_seconds'] = resolution
    recent = db.execute('SELECT name,first_seen,last_seen FROM known_domains WHERE first_seen>? '
                        'ORDER BY first_seen DESC,name LIMIT 100', (now-DAY,)).fetchall()
    return {'since': db.execute("SELECT value FROM analytics_meta WHERE key='since'").fetchone()[0],
            'windows': windows, 'coverage': coverage, 'domain_limit_reached': limit_reached,
            'known_domain_count': db.execute('SELECT COUNT(*) FROM known_domains').fetchone()[0],
            'new_domain_count': db.execute('SELECT COUNT(*) FROM known_domains WHERE first_seen>?', (now-DAY,)).fetchone()[0],
            'new_domains': [{'domain': name, 'first_seen': first, 'last_seen': last} for name, first, last in recent]}


def collect_analytics(db, flows, records, now, history=()):
    timestamp = dt.datetime.fromisoformat(now).timestamp()
    schema(db, timestamp)
    limited = register_domains(db, records, flows or [], timestamp)
    coverage = sample_traffic(db, flows, timestamp) if flows is not None else {'tracked': 0, 'missing': 0}
    coverage['available'] = flows is not None
    compact_traffic(db, timestamp)
    # Domains persist across restarts and session-history expiry. No automatic catalogue eviction.
    for flow in list(flows or []) + list(history):
        for hint in flow.get('domain_hints', []):
            row = db.execute('SELECT first_seen FROM known_domains WHERE name=?', (hint['domain'].lower(),)).fetchone()
            hint['first_seen'] = row[0] if row else None
            hint['is_new'] = bool(row and timestamp-DAY < row[0] <= timestamp)
    result = summarize(db, timestamp, coverage, limited)
    db.commit()
    return result
