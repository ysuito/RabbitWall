import test_environment
import copy
import datetime as dt
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src/rabbitwall'))
import traffic_analytics as analytics

BASE = dt.datetime(2026, 10, 28, tzinfo=dt.timezone.utc).timestamp()

def stamp(seconds):
    return dt.datetime.fromtimestamp(BASE+seconds, dt.timezone.utc).isoformat()

def flow(tx=100, rx=1000, key='a', **kwargs):
    return dict({'key': key, 'first_seen': stamp(0), 'scope': 'AI', 'src': '10.1.0.10',
                 'dst': '1.1.1.1', 'tx_bytes': tx, 'rx_bytes': rx, 'domain_hints': []}, **kwargs)

def hint(name='example.com', observed=0):
    return {'domain': name, 'client': '10.1.0.10', 'address': '1.1.1.1',
            'observed_at': BASE+observed, 'expires_at': BASE+observed+300}

class Analytics(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        self.addCleanup(self.db.close)

    def collect(self, flows, seconds, records=(), history=()):
        return analytics.collect_analytics(self.db, flows, records, stamp(seconds), history)

    def test_first_seen_persists_beyond_history_and_restart_and_expires_badge(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'history.sqlite3'
            db = sqlite3.connect(path)
            data = analytics.collect_analytics(db, [], [hint()], stamp(0))
            self.assertEqual(data['new_domain_count'], 1)
            db.close()
            db = sqlite3.connect(path)
            f = flow(domain_hints=[hint(observed=86401)])
            data = analytics.collect_analytics(db, [f], [hint(observed=86401)], stamp(86401))
            self.assertEqual(data['known_domain_count'], 1)
            self.assertEqual(data['new_domain_count'], 0)
            self.assertFalse(f['domain_hints'][0]['is_new'])
            self.assertEqual(f['domain_hints'][0]['first_seen'], BASE)
            db.close()

    def test_dns_without_connection_and_history_annotation(self):
        old = flow(domain_hints=[hint()])
        data = self.collect([], 5, [hint()], history=[old])
        self.assertEqual(data['new_domains'][0]['domain'], 'example.com')
        self.assertTrue(old['domain_hints'][0]['is_new'])
        self.assertEqual(data['windows']['24h']['tx_bytes'], 0)

    def test_counter_deltas_no_repeated_sum_and_rebaseline_on_reset_or_gap(self):
        first = self.collect([flow()], 0)
        self.assertEqual(first['windows']['24h']['tx_bytes'], 0)
        data = self.collect([flow(160, 1300)], 5)
        self.assertEqual((data['windows']['24h']['tx_bytes'], data['windows']['24h']['rx_bytes']), (60, 300))
        data = self.collect([flow(160, 1300)], 10)
        self.assertEqual(data['windows']['24h']['tx_bytes'], 60)
        data = self.collect([flow(10, 20)], 15)
        self.assertEqual(data['windows']['24h']['tx_bytes'], 60)
        data = self.collect([flow(1010, 2020)], 100)
        self.assertEqual(data['windows']['24h']['tx_bytes'], 60)
        data = self.collect([flow(1020, 2040)], 105)
        self.assertEqual(data['windows']['24h']['tx_bytes'], 70)

    def test_missing_counters_then_first_available_is_baseline(self):
        data = self.collect([flow(None, None)], 0)
        self.assertEqual(data['coverage']['missing'], 1)
        data = self.collect([flow(200, 400)], 5)
        self.assertEqual(data['windows']['24h']['tx_bytes'], 0)
        data = self.collect([flow(250, None)], 10)
        self.assertEqual(data['windows']['24h']['tx_bytes'], 50)
        self.assertEqual(data['windows']['24h']['rx_bytes'], 0)

    def test_reused_key_new_interval_and_disappeared_flow_not_double_counted(self):
        self.collect([flow()], 0)
        self.collect([flow(150, 1100)], 5)
        self.collect([], 10)
        data = self.collect([flow(500, 3000, first_seen=stamp(15))], 15)
        self.assertEqual(data['windows']['24h']['tx_bytes'], 50)
        data = self.collect([flow(600, 4000, first_seen=stamp(20))], 20)
        self.assertEqual(data['windows']['24h']['tx_bytes'], 50)

    def test_only_ai_public_destinations_and_domain_totals_not_duplicated(self):
        a = flow(domain_hints=[hint('a.example'), hint('b.example')])
        b = flow(key='b', dst='8.8.8.8', domain_hints=[hint('a.example')])
        c = flow(key='c', dst='9.9.9.9', domain_hints=[hint('a.example')])
        excluded = [flow(key='m', scope='MANAGEMENT'), flow(key='t', scope='RABBITWALL'), flow(key='dns', dst='10.1.0.1')]
        self.collect([a,b,c]+excluded, 0)
        for f in [a,b,c]+excluded: f['tx_bytes'] += 100; f['rx_bytes'] += 200
        data = self.collect([a,b,c]+excluded, 5)['windows']['24h']
        self.assertEqual(data['tx_bytes'], 300)
        self.assertEqual(sum(r['tx_bytes'] for r in data['by_domain']), 300)
        named = next(r for r in data['by_domain'] if r['label']=='a.example')
        self.assertEqual(named['tx_bytes'], 200)
        self.assertEqual(len(data['by_domain']), 2)

    def test_failed_poll_keeps_totals_and_coverage_signals_failure(self):
        self.collect([flow()], 0)
        self.collect([flow(200, 2000)], 5)
        data = self.collect(None, 10)
        self.assertFalse(data['coverage']['available'])
        self.assertEqual(data['windows']['24h']['tx_bytes'], 100)

    def test_window_expiry_catalogue_cap_and_untrusted_source(self):
        with patch.object(analytics, 'DOMAIN_LIMIT', 1):
            data = self.collect([], 0, [hint('a.example'), hint('b.example')])
        self.assertTrue(data['domain_limit_reached'])
        self.assertEqual(data['known_domain_count'], 1)
        invalid = dict(hint('other.example'), client='10.0.0.9')
        data = self.collect([], 5, [invalid])
        self.assertEqual(data['known_domain_count'], 1)
        self.collect([flow()], 10)
        self.collect([flow(200, 2000)], 15)
        data = self.collect([], 3660)
        self.assertEqual(data['windows']['1h']['tx_bytes'], 0)
        self.assertEqual(data['windows']['24h']['tx_bytes'], 100)
        data = self.collect([], 86500)
        self.assertEqual(data['windows']['24h']['tx_bytes'], 0)
        self.assertEqual(data['known_domain_count'], 1)

    def test_hourly_rollup_preserves_long_totals_without_double_counting(self):
        self.collect([], 0)
        for offset, tx in [(0, 10), (60, 20), (86400+3600, 40)]:
            self.db.execute('INSERT INTO traffic_minutes VALUES (?,?,?,?,?,?)',
                            (int(BASE+offset), '10.1.0.10', '1.1.1.1', '["example.com"]', tx, tx*2))
        data = self.collect([], 2*86400)
        self.assertEqual(data['windows']['24h']['tx_bytes'], 40)
        self.assertEqual(data['windows']['7d']['tx_bytes'], 70)
        self.assertEqual(data['windows']['30d']['rx_bytes'], 140)
        self.assertEqual(data['windows']['30d']['by_domain'][0]['tx_bytes'], 70)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM traffic_hours').fetchone()[0], 1)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM traffic_minutes').fetchone()[0], 1)
        again = self.collect([], 2*86400+5)
        self.assertEqual(again['windows']['30d']['tx_bytes'], 70)
        self.assertEqual(again['windows']['30d']['resolution_seconds'], 3600)
        data = self.collect([], 8*86400)
        self.assertEqual(data['windows']['7d']['tx_bytes'], 40)
        self.assertEqual(data['windows']['30d']['tx_bytes'], 70)
        data = self.collect([], 33*86400)
        self.assertEqual(data['windows']['30d']['tx_bytes'], 0)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM traffic_hours').fetchone()[0], 0)

    def test_long_window_cutoff_and_existing_minute_data(self):
        analytics.schema(self.db, BASE)
        self.db.execute("DELETE FROM analytics_meta WHERE key='long_since'")
        self.db.execute('INSERT INTO traffic_minutes VALUES (?,?,?,?,?,?)',
                        (int(BASE-3600), '10.1.0.10', '1.1.1.1', '[]', 11, 22))
        data = self.collect([], 0)
        self.assertEqual(data['windows']['30d']['available_since'], BASE-3600)
        data = self.collect([], 7*86400-3600)
        self.assertEqual(data['windows']['7d']['tx_bytes'], 11)
        data = self.collect([], 7*86400-3599)
        self.assertEqual(data['windows']['7d']['tx_bytes'], 0)
        self.assertEqual(data['windows']['30d']['tx_bytes'], 11)
        self.assertEqual(data['windows']['30d']['available_since'], BASE-3600)

    def test_collector_pipeline_and_restart_keep_baseline_and_annotations(self):
        import console
        raw = "tcp 6 100 ESTABLISHED src=10.1.0.10 dst=1.1.1.1 sport=12345 dport=443 bytes=100 src=1.1.1.1 dst=10.1.0.10 sport=443 dport=12345 bytes=200 id=9"
        later = raw.replace('bytes=100', 'bytes=150').replace('bytes=200', 'bytes=300')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'history.sqlite3'
            state = Path(directory)/'state.json'
            with patch.object(console, 'load_observations', return_value=[hint()]), patch.object(console, 'utc_now', side_effect=[stamp(0), stamp(5), stamp(10)]), patch.object(console, 'command', side_effect=[(raw,None),('',None),(later,None),('',None),(later,None),('',None)]):
                db = sqlite3.connect(path)
                console.collect_once(db, state, 5)
                db.close()
                db = sqlite3.connect(path)
                console.collect_once(db, state, 5)
                data = json.loads(state.read_text())
                self.assertEqual(data['analytics']['windows']['24h']['tx_bytes'], 50)
                self.assertEqual(data['analytics']['windows']['24h']['rx_bytes'], 100)
                self.assertTrue(data['flows'][0]['domain_hints'][0]['is_new'])
                self.assertTrue(data['history'][0]['domain_hints'][0]['is_new'])
                console.collect_once(db, state, 5)
                self.assertEqual(json.loads(state.read_text())['analytics']['windows']['24h']['tx_bytes'], 50)
                db.close()

    def test_top_lists_keep_heavy_uploads_and_downloads(self):
        rows = [('10.1.0.10', f'1.1.1.{n}', '[]', n, 100-n) for n in range(1,80)]
        data = analytics.rankings(rows)
        self.assertEqual(max(r['tx_bytes'] for r in data['by_ip']), 79)
        self.assertEqual(max(r['rx_bytes'] for r in data['by_ip']), 99)
        self.assertLessEqual(len(data['by_ip']), 60)

if __name__ == '__main__': unittest.main()
