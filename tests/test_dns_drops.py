import test_environment
from contextlib import closing
import json
import socket
import struct
import sqlite3
import sys
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'src/rabbitwall'))
from dns_drops import decode_packet, Observer
from dns_observations import record_answer_history, drop_country_candidates
import dns_observations
import dns.message
import dns.rdatatype


def packet(wire=None, tcp=False, fragment=0, port=53):
    wire = dns.message.make_query('example.com', 'AAAA').to_wire() if wire is None else wire
    if tcp:
        body=struct.pack('!HHIIBBHHH',50000,port,0,0,5<<4,2,4096,0,0) + wire
    else:
        body=struct.pack('!HHHH',50000,port,len(wire)+8,0) + wire
    return struct.pack('!BBHHHBBH4s4s',0x45,0,len(body)+20,0,fragment,64,6 if tcp else 17,0,
                       socket.inet_aton('10.1.0.10'),socket.inet_aton('10.1.0.1')) + body


class DNSDrops(unittest.TestCase):
    def test_udp_query_is_actual_question_not_domain_hint(self):
        entry = decode_packet(packet(), 'input', 1700000000)
        self.assertEqual(entry['dns_questions'], [{'name':'example.com.','type':'AAAA'}])
        self.assertEqual(entry['src'], '10.1.0.10')
        self.assertEqual(entry['dport'], '53')
        self.assertIsNone(entry['dns_error'])
        self.assertEqual(entry['dns_reason'], 'closed')
        self.assertEqual(decode_packet(packet(), 'forward')['dns_reason'], 'direct-dns')

    def test_tcp_packets_are_not_observed(self):
        self.assertIsNone(decode_packet(packet(b'', tcp=True), 'forward'))
        wire = dns.message.make_query('example.com', 'A').to_wire()
        framed = struct.pack('!H',len(wire))+wire
        self.assertIsNone(decode_packet(packet(framed,tcp=True),'input'))

    def test_malformed_truncated_fragmented_and_response(self):
        self.assertIsNone(decode_packet(b'', 'input'))
        self.assertIsNone(decode_packet(packet(fragment=1), 'input'))
        self.assertIsNone(decode_packet(packet(port=443), 'input'))
        self.assertIsNone(decode_packet(packet(), 'arbitrary'))
        self.assertTrue(decode_packet(packet(b'bad'),'input')['dns_error'])
        self.assertTrue(decode_packet(packet()[:-1],'input')['dns_error'])
        response=dns.message.make_response(dns.message.make_query('example.com','A')).to_wire()
        self.assertIsNone(decode_packet(packet(response),'input'))
        # All short prefixes must be rejected safely, without struct/index errors.
        for length in range(28):
            decode_packet(packet()[:length],'input')

    def test_memory_limit_expiry_and_snapshot_isolation(self):
        observer=Observer()
        for index in range(250): observer.records.append((10,{'index':index}))
        with patch('dns_drops.time.monotonic',return_value=11):
            entries,error=observer.snapshot()
        self.assertEqual(len(entries),200)
        self.assertEqual(entries[0]['index'],50)
        entries[0]['index']=-1
        self.assertEqual(observer.records[0][1]['index'],50)
        with patch('dns_drops.time.monotonic',return_value=311):
            self.assertEqual(observer.snapshot()[0],[])
        self.assertEqual(len(observer.records),0)

    def test_collector_merges_dns_drops_with_journal_and_reports_failure(self):
        import console
        entry=decode_packet(packet(),'input')
        entry.update({'in':'eth1','out':''})
        observer=Observer()
        response={'domain':'example.com','client':entry['src'],'address':'1.0.0.1',
                  'observed_at':time.time()-10,'expires_at':time.time()+300}
        with tempfile.TemporaryDirectory() as directory, closing(sqlite3.connect(':memory:')) as db:
            state=Path(directory)/'state.json'
            with patch.object(observer,'snapshot',return_value=([entry],None)), patch.object(console,'command',return_value=('',None)), patch.object(console,'load_observations',return_value=[response]), patch('socket.socket',side_effect=AssertionError('No active DNS')):
                console.collect_once(db,state,5,observer)
            data=json.loads(state.read_text())
            self.assertEqual(data['drops'][0]['scope'],'AI')
            self.assertEqual(data['drops'][0]['chain'],'input')
            self.assertEqual(data['drops'][0]['dns_questions'][0]['name'],'example.com.')
            self.assertNotIn('payload',data['drops'][0])
            self.assertEqual(data['drops'][0]['dns_country_candidates'][0]['address'],'1.0.0.1')
            with patch.object(observer,'snapshot',return_value=([],'observer stopped')), patch.object(console,'command',return_value=('',None)), patch.object(console,'load_observations',return_value=[]):
                console.collect_once(db,state,5,observer)
            self.assertIn('observer stopped',json.loads(state.read_text())['errors'])

class DNSCountryHistory(unittest.TestCase):
    def setUp(self):
        self.db=sqlite3.connect(':memory:')
        self.addCleanup(self.db.close)
        record_answer_history(self.db,[],2000)

    def answer(self, address='1.0.0.1', client='10.1.0.10', observed=1000):
        return {'domain':'Example.COM.', 'address':address, 'client':client,
                'observed_at':observed,'expires_at':observed+1}

    def drop(self, name='example.com.'):
        entry=decode_packet(packet(),'input',2000)
        entry['dns_questions'][0]['name']=name
        return entry

    def test_expired_response_is_passive_hint_and_unknown_stays_unknown(self):
        record_answer_history(self.db,[self.answer()],2000)
        with patch('socket.socket',side_effect=AssertionError('No active DNS allowed')):
            hints=drop_country_candidates(self.db,self.drop('EXAMPLE.com.'),2000)
            self.assertEqual(hints[0]['address'],'1.0.0.1')
            self.assertLess(hints[0]['expires_at'],2000)
            self.assertEqual(drop_country_candidates(self.db,self.drop('unseen.example.'),2000),[])

    def test_same_client_preferred_other_clients_and_multiple_ips_preserved(self):
        record_answer_history(self.db,[self.answer(),self.answer('8.8.8.8','10.1.0.11',1100)],2000)
        hints=drop_country_candidates(self.db,self.drop(),2000)
        self.assertEqual([h['address'] for h in hints],['1.0.0.1','8.8.8.8'])
        self.assertEqual([h['same_client'] for h in hints],[True,False])
        record_answer_history(self.db,[self.answer()],2000)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM dns_answer_history').fetchone()[0],2)
        # Newer observations must never be attributed to an earlier dropped question.
        record_answer_history(self.db,[self.answer('9.9.9.9',observed=2001)],2001)
        self.assertNotIn('9.9.9.9',[h['address'] for h in drop_country_candidates(self.db,self.drop(),2001)])

    def test_limits_retention_and_invalid_sources(self):
        invalid=[dict(self.answer(),client='10.0.0.9'),dict(self.answer(),address='10.0.0.254'),
                 dict(self.answer(),observed_at=float('nan')),dict(self.answer(),domain='bad\x00name')]
        record_answer_history(self.db,invalid,2000)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM dns_answer_history').fetchone()[0],0)
        with patch.object(dns_observations,'HISTORY_LIMIT',2):
            record_answer_history(self.db,[self.answer('1.0.0.1',observed=1000),self.answer('8.8.8.8',observed=1001),self.answer('9.9.9.9',observed=1002)],2000)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM dns_answer_history').fetchone()[0],2)
        record_answer_history(self.db,[],2000+31*86400)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM dns_answer_history').fetchone()[0],0)

    def test_evidence_survives_restart_and_geoip_preserves_real_dns_destination(self):
        import geoip
        import test_management
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'history.sqlite3'
            with closing(sqlite3.connect(path)) as db:
                record_answer_history(db,[self.answer(),self.answer('8.8.8.8')],2000)
                db.commit()
            with closing(sqlite3.connect(path)) as db:
                drop=self.drop()
                drop['dns_country_candidates']=drop_country_candidates(db,drop,2000)
            database=test_management.Countries().build(directory)
            lookup=geoip.CountryLookup(database)
            self.addCleanup(lambda: lookup.connection and lookup.connection.close())
            result=lookup.enrich({'drops':[drop]})['drops'][0]
            self.assertEqual(result['dst'],'10.1.0.1')
            self.assertEqual(result['dst_country']['kind'],'private')
            self.assertEqual({c['country']['code'] for c in result['dns_country_candidates']},{'AU','US'})
            missing=geoip.CountryLookup(Path(directory)/'missing')
            self.assertTrue(all(c['country']['kind']=='unknown' for c in missing.enrich({'drops':[drop]})['drops'][0]['dns_country_candidates']))


if __name__=='__main__':unittest.main()
