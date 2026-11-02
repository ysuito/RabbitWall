import test_environment
from contextlib import closing
import json
import socket
import struct
import sqlite3
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'src/rabbitwall'))
from dns_drops import decode_packet, Observer
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
        with tempfile.TemporaryDirectory() as directory, closing(sqlite3.connect(':memory:')) as db:
            state=Path(directory)/'state.json'
            with patch.object(observer,'snapshot',return_value=([entry],None)), patch.object(console,'command',return_value=('',None)), patch.object(console,'load_observations',return_value=[]):
                console.collect_once(db,state,5,observer)
            data=json.loads(state.read_text())
            self.assertEqual(data['drops'][0]['scope'],'AI')
            self.assertEqual(data['drops'][0]['chain'],'input')
            self.assertEqual(data['drops'][0]['dns_questions'][0]['name'],'example.com.')
            self.assertNotIn('payload',data['drops'][0])
            with patch.object(observer,'snapshot',return_value=([],'observer stopped')), patch.object(console,'command',return_value=('',None)), patch.object(console,'load_observations',return_value=[]):
                console.collect_once(db,state,5,observer)
            self.assertIn('observer stopped',json.loads(state.read_text())['errors'])

if __name__=='__main__':unittest.main()
