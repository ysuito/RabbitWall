import test_environment
import json
from pathlib import Path
import socket
import sys
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src/rabbitwall'))
import console
import request_api


class HTTPLimits(unittest.TestCase):
    def exercise_request(self, prefix, trickle=b'', header_timeout=.3, body_timeout=.3, callback=None):
        left,right=socket.socketpair()
        errors=[]
        server=SimpleNamespace(header_timeout=header_timeout,body_timeout=body_timeout)
        handler=request_api.make_handler(callback=callback or Mock(return_value={'status':'pending'}))
        def serve():
            try: handler(left,('10.1.0.10',50000),server)
            except Exception as error: errors.append(error)
            finally: left.close()
        worker=threading.Thread(target=serve,daemon=True)
        start=time.monotonic();worker.start()
        try:
            right.sendall(prefix)
            if trickle:
                # Keep every individual receive well inside the idle timeout.
                for _ in range(30):
                    time.sleep(.02)
                    try: right.sendall(trickle)
                    except (BrokenPipeError,ConnectionResetError): break
                    if not worker.is_alive(): break
            right.settimeout(2)
            result=bytearray()
            while True:
                try: part=right.recv(4096)
                except ConnectionResetError: break
                if not part: break
                result.extend(part)
            worker.join(2)
            self.assertFalse(worker.is_alive(),'receive deadline must release the worker')
            self.assertEqual(errors,[])
            return bytes(result),time.monotonic()-start
        finally:
            right.close()
            try: left.shutdown(socket.SHUT_RDWR)
            except OSError: pass
            worker.join(2)

    def test_trickled_headers_cannot_reset_the_total_header_deadline(self):
        callback=Mock()
        response,elapsed=self.exercise_request(b'POST /api/domain-requests HTTP/1.0\r\nHost: 10.1.0.1:8767\r\nX-Slow: ',b'x',header_timeout=.15,callback=callback)
        callback.assert_not_called()
        self.assertNotIn(b'201',response)
        self.assertLess(elapsed,1.5)

    def test_trickled_body_times_out_without_submitting_a_partial_request(self):
        callback=Mock()
        response,elapsed=self.exercise_request(b'POST /api/domain-requests HTTP/1.0\r\nHost: 10.1.0.1:8767\r\nContent-Type: application/json\r\nContent-Length: 1024\r\n\r\n',b' ',body_timeout=.15,callback=callback)
        self.assertIn(b'408 Request Timeout',response)
        callback.assert_not_called()
        self.assertLess(elapsed,1.5)

    def test_normal_body_and_controller_work_are_not_cut_off_by_receive_budget(self):
        data={'domains':['allowed.example'],'duration_seconds':60,'purpose':'download'}
        body=json.dumps(data).encode()
        prefix=b'POST /api/domain-requests HTTP/1.0\r\nHost: 10.1.0.1:8767\r\nContent-Type: application/json\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body
        def controller(*args,**kwargs):
            time.sleep(.1)
            return {'status':'pending'}
        callback=Mock(side_effect=controller)
        response,_=self.exercise_request(prefix,body_timeout=.05,callback=callback)
        self.assertIn(b'201 Created',response)
        callback.assert_called_once_with('submit_domain_request',payload={'source':'10.1.0.10','request':data})

    def test_source_quota_leaves_capacity_for_other_hosts_and_is_released(self):
        with console.ConsoleServer(('127.0.0.1',0),request_api.make_handler(),bind_and_activate=False) as server:
            with patch.object(console.ThreadingHTTPServer,'process_request') as dispatch, patch.object(server,'shutdown_request') as drop:
                for port in range(server.max_per_source): server.process_request(Mock(),('10.1.0.10',port))
                server.process_request(Mock(),('10.1.0.10',100))
                drop.assert_called_once()
                server.process_request(Mock(),('10.1.0.11',101))
                self.assertEqual(dispatch.call_count,server.max_per_source+1)
                for _ in range(server.max_per_source): server.release_slot('10.1.0.10')
                server.release_slot('10.1.0.11')
                self.assertEqual(server.source_counts,{})
                # Worker failures must also release their source and global slots.
                server.process_request(Mock(),('10.1.0.10',102))
                with patch.object(console.ThreadingHTTPServer,'process_request_thread',side_effect=RuntimeError('failed')):
                    with self.assertRaises(RuntimeError): server.process_request_thread(Mock(),('10.1.0.10',102))
                self.assertEqual(server.source_counts,{})
                self.assertTrue(all(server.slots.acquire(blocking=False) for _ in range(server.max_workers)))
