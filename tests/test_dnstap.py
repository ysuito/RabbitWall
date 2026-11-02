import test_environment
import ipaddress
from pathlib import Path
import socket
import struct
import sys
import threading
import time
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'src/rabbitwall'))
import dns.message
import dns.rrset
import dns.flags
import dnstap_pb2 as pb
import dnstap_observer as observer
from dns_evidence import Evidence
from settings import SETTINGS
from unbound_config import render


def event(client='10.1.0.10', address='1.1.1.1', stamp=None):
    stamp = time.time() - .01 if stamp is None else stamp
    message = dns.message.make_response(dns.message.make_query('app.example', 'A'))
    message.answer = [dns.rrset.from_text('app.example.', 30, 'IN', 'A', address)]
    result = pb.Dnstap(type=pb.Dnstap.MESSAGE)
    result.message.type = pb.Message.CLIENT_RESPONSE
    result.message.socket_family = pb.INET
    result.message.socket_protocol = pb.UDP
    result.message.query_address = ipaddress.ip_address(client).packed
    result.message.response_address = ipaddress.ip_address('10.1.0.1').packed
    result.message.response_port = 53
    result.message.response_time_sec = int(stamp)
    result.message.response_time_nsec = int((stamp-int(stamp))*1e9)
    result.message.response_message = message.to_wire()
    return result


class Dnstap(unittest.TestCase):
    def test_client_response_time_ttl_and_isolation(self):
        evidence = Evidence()
        observer.ingest(event(stamp=100).SerializeToString(), evidence, now=101)
        record = list(evidence.records.values())[0]
        self.assertEqual(record['client'], '10.1.0.10')
        self.assertAlmostEqual(record['expires_at'], 130)
        self.assertEqual(record['domain'], 'app.example')

    def test_optional_responder_fields_from_older_unbound(self):
        message = event(stamp=100)
        message.message.ClearField('response_address')
        message.message.ClearField('response_port')
        evidence = Evidence()
        observer.ingest(message.SerializeToString(), evidence, now=101)
        self.assertEqual(len(evidence.records), 1)

    def test_foreign_wrong_endpoint_old_future_or_wrong_event_not_recorded(self):
        for mode in ('client','server','time','future','type','port','qr','truncated'):
            evidence = Evidence()
            message = event(stamp=100)
            if mode=='client': message.message.query_address=ipaddress.ip_address('10.0.0.9').packed
            if mode=='server': message.message.response_address=ipaddress.ip_address('10.2.0.2').packed
            if mode=='time': message.message.response_time_sec=1
            if mode=='future': message.message.response_time_sec=9999
            if mode=='type': message.message.type=pb.Message.FORWARDER_RESPONSE
            if mode=='port': message.message.response_port=443
            if mode in ('qr','truncated'):
                response=dns.message.from_wire(message.message.response_message)
                if mode=='qr': response.flags &= ~dns.flags.QR
                else: response.flags |= dns.flags.TC
                message.message.response_message=response.to_wire()
            observer.ingest(message.SerializeToString(),evidence,now=4000 if mode=='time' else 101)
            self.assertFalse(evidence.records,mode)

    def test_bidirectional_framestream_and_malformed_event_survive(self):
        left,right=socket.socketpair()
        stopping=threading.Event()
        evidence=Evidence()
        failures=[]
        def receive():
            try: observer.FrameSession(right,evidence,stopping).run()
            except Exception as error: failures.append(error)
        worker=threading.Thread(target=receive);worker.start()
        try:
            left.settimeout(2)
            left.sendall(observer.control_frame(observer.READY,True))
            expected=observer.control_frame(observer.ACCEPT,True)
            data=b''
            while len(data)<len(expected): data+=left.recv(len(expected)-len(data))
            self.assertEqual(data,expected)
            left.sendall(observer.control_frame(observer.START,True))
            for payload in (b'not protobuf',event().SerializeToString()):
                left.sendall(struct.pack('!I',len(payload))+payload)
            left.sendall(observer.control_frame(observer.STOP))
            self.assertEqual(left.recv(12),observer.control_frame(observer.FINISH))
            worker.join(2)
            self.assertFalse(failures)
            self.assertEqual(len(evidence.records),1)
        finally:
            stopping.set();left.close();worker.join(2);right.close()

    def test_reject_oversized_frame_before_reading_payload(self):
        connection=Mock()
        # The first header is an overlarge data frame, before any handshake.
        connection.recv.return_value=struct.pack('!I',observer.MAX_FRAME+1)
        with self.assertRaises(ValueError):
            observer.FrameSession(connection,Evidence(),threading.Event()).run()

    def test_partial_frame_has_deadline(self):
        connection=Mock();connection.recv.return_value=b'x'
        with patch.object(observer.time,'monotonic',side_effect=[0,1,11]):
            with self.assertRaises(TimeoutError):
                observer.FrameSession(connection,Evidence(),threading.Event()).read_exact(4)

    def test_publication_failure_does_not_stop_receiver(self):
        evidence=Mock();stopping=threading.Event()
        def fail(*args):
            stopping.set()
            raise OSError('read-only output')
        evidence.publish.side_effect=fail
        observer.publish_loop(evidence,stopping,Path('/unused'))
        evidence.publish.assert_called_once()

    def test_unbound_source_gate_and_no_observer_dependency(self):
        text=render(SETTINGS)
        for fragment in ('interface: 10.1.0.1','outgoing-interface: 10.1.0.1',
                         'forward-addr: 10.0.0.254','forward-first: no',
                         'dnstap-log-client-response-messages: yes','module-config: "respip iterator"'):
            self.assertIn(fragment,text)
        root=Path(__file__).resolve().parents[1]
        unit=(root/'systemd/rabbitwall-dns.service').read_text()
        self.assertIn('/usr/sbin/unbound',unit)
        self.assertNotIn('rabbitwall-dns-observer.service',unit)
        self.assertNotIn('Requires=rabbitwall-dns.service',(root/'systemd/rabbitwall-dns-observer.service').read_text())


if __name__=='__main__':
    unittest.main()
