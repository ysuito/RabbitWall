import test_environment
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'src/rabbitwall'))
import audit
import control
import console
import domain_approvals
import test_management


class Audit(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)/'logs/audit.jsonl'
        self.output = patch('sys.stdout', new_callable=io.StringIO)
        self.output.start()
        self.addCleanup(self.output.stop)
        self.previous = audit._handler
        audit._handler = None
        self.addCleanup(self.restore)

    def restore(self):
        if audit._handler is not None: audit._handler.close()
        audit._handler = self.previous

    def rows(self):
        return [json.loads(line) for line in self.path.read_text().splitlines()]

    def test_append_survives_reopen_and_escapes_newlines(self):
        audit.configure(self.path)
        token = audit.actor.set({'channel':'agent','uid':123})
        try: audit.record({'event':'domain-request','purpose':'first\nforged event'})
        finally: audit.actor.reset(token)
        audit.configure(self.path)
        audit.record({'event':'controller-start'})
        rows=self.rows()
        self.assertEqual(len(rows),2)
        self.assertEqual(rows[0]['purpose'],'first\nforged event')
        self.assertEqual(rows[0]['actor']['uid'],123)
        self.assertNotIn('actor',rows[1])
        self.assertIn('at',rows[1])
        self.assertEqual(self.path.stat().st_mode & 0o777,0o600)
        self.assertEqual(self.path.parent.stat().st_mode & 0o777,0o700)

    def test_rotation_is_bounded_and_private(self):
        audit.configure(self.path,max_bytes=220,backups=2)
        for index in range(25): audit.record({'event':'test','index':index,'value':'x'*60})
        files=list(self.path.parent.iterdir())
        self.assertEqual(len(files),3)
        for file in files:
            self.assertEqual(file.stat().st_mode & 0o777,0o600)
            for line in file.read_text().splitlines(): json.loads(line)
        self.assertEqual(self.rows()[-1]['index'],24)

    def test_disk_failure_keeps_journal_and_reports_failure(self):
        audit.configure(self.path)
        with patch.object(audit._handler,'emit',side_effect=OSError('disk full')), patch('sys.stderr',new_callable=io.StringIO) as error:
            audit.record({'event':'domain-revoke'})
            self.assertIn('audit-write-failed',error.getvalue())
        self.assertIn('domain-revoke',sys.stdout.getvalue())

    def test_failure_metadata_never_includes_raw_body_or_exception_text(self):
        audit.configure(self.path)
        audit.operation('submit_domain_request',{'source':'10.1.0.10','request':{'purpose':'secret','token':'credential','id':'a'*32}},'failure',ValueError('secret'))
        row=self.rows()[0]
        self.assertEqual(row['source'],'10.1.0.10')
        self.assertEqual(row['id'],'a'*32)
        self.assertEqual(row['error_type'],'ValueError')
        self.assertNotIn('secret',self.path.read_text())
        self.assertNotIn('credential',self.path.read_text())

    def test_rejected_agent_operation_has_actor_and_does_not_dispatch(self):
        audit.configure(self.path)
        controller=Mock()
        class Server: request_only=True
        class Connection:
            def settimeout(self,_): pass
            def makefile(self,*_): return io.BytesIO(b'{"action":"disable"}\n')
            def sendall(self,data): pass
        control.make_control_handler(controller)(Connection(),'',Server())
        row=self.rows()[0]
        self.assertEqual(row['action'],'disable')
        self.assertEqual(row['outcome'],'failure')
        self.assertEqual(row['actor']['channel'],'agent')
        self.assertIsNone(audit.actor.get())
        self.assertEqual(controller.mock_calls,[])

    def test_expiry_records_grant_identity_once(self):
        audit.configure(self.path)
        approvals=domain_approvals.Approvals(Mock(),guard=Mock())
        self.addCleanup(approvals.close)
        approvals.grants['node']={'id':'a'*16,'node_id':'node','deadline':0,'source':'10.1.0.10','domains':['example.com'],'cancel':threading.Event()}
        approvals.expire()
        approvals.expire()
        row=self.rows()[0]
        self.assertEqual(len(self.rows()),1)
        self.assertEqual(row['reason'],'expired')
        self.assertEqual(row['id'],'a'*16)

    def test_reader_crosses_rotations_skips_corrupt_records_and_limits_output(self):
        self.path.parent.mkdir()
        self.path.write_text('{"event":"new"}\ninvalid\n{"event":"newest"}\n')
        Path(str(self.path)+'.1').write_text('{"event":"old"}\n')
        result=audit.recent(self.path)
        self.assertEqual([r['event'] for r in result['entries']],['newest','new','old'])
        self.assertTrue(result['available'])
        result=audit.recent(self.path,limit=1)
        self.assertEqual([r['event'] for r in result['entries']],['newest'])
        self.assertTrue(result['limited'])
        result=audit.recent(self.path,budget=20)
        self.assertTrue(result['limited'])
        self.assertLessEqual(len(result['entries']),1)
        self.assertFalse(audit.recent(self.path.parent/'missing')['available'])

    def test_permission_filter_precedes_limit_and_preserves_full_file(self):
        self.path.parent.mkdir()
        events=[{'event':'domain-request-decision','decision':'reject'},
                {'event':'control-operation','action':'revoke_domain_request','outcome':'failure'},
                {'event':'domain-ended','reason':'expired'},
                {'event':'control-operation','action':'approve_domains','outcome':'started'},
                {'event':'control-operation','action':'approve_domains','outcome':'success'},
                {'event':'control-operation','action':'save_nodes','outcome':'failure'},
                {'event':'controller-start'}]
        original=''.join(json.dumps(e)+'\n' for e in events)
        self.path.write_text(original)
        result=audit.recent(self.path,limit=3,permissions_only=True)
        self.assertEqual(result['entries'],list(reversed(events[:3])))
        self.assertEqual(len(audit.recent(self.path)['entries']),len(events))
        self.assertEqual(self.path.read_text(),original)


class AuditHTTP(unittest.TestCase):
    request=test_management.HTTP.request

    def test_real_audit_requires_mtls_and_server_token_before_controller_access(self):
        with tempfile.TemporaryDirectory() as directory:
            token=Path(directory)/'token';token.write_text('x'*43)
            callback=Mock(return_value={'entries':[{'event':'domain-request'}],'available':True,'limited':False})
            handler=console.make_handler(Path('/none'),8765,control_callback=callback,token_file=token)
            for headers in ('','X-RabbitWall-Auth: mtls\r\n','Authorization: Bearer '+('x'*43)+'\r\n'):
                self.assertIn(b'403',self.request('/api/audit',headers=headers,handler=handler))
            callback.assert_not_called()
            headers='X-RabbitWall-Auth: mtls\r\nAuthorization: Bearer '+('x'*43)+'\r\n'
            response=self.request('/api/audit',headers=headers,handler=handler)
            self.assertIn(b'200 OK',response)
            self.assertEqual(json.loads(response.split(b'\r\n\r\n',1)[1])['audit']['entries'][0]['event'],'domain-request')
            callback.assert_called_once_with('audit_log')
            callback.side_effect=RuntimeError('secret')
            response=self.request('/api/audit',headers=headers,handler=handler)
            self.assertIn(b'503',response)
            self.assertNotIn(b'secret',response)

    def test_demo_never_reads_real_audit_records(self):
        callback=Mock(side_effect=AssertionError('real controller'))
        handler=console.make_handler(Path('/none'),8765,demo=True,control_callback=callback)
        with patch.object(audit,'recent',side_effect=AssertionError('real audit')):
            response=self.request('/api/audit',handler=handler)
        self.assertIn(b'200 OK',response)
        callback.assert_not_called()
