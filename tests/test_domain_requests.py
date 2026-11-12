import test_environment
import copy
import concurrent.futures
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'src/rabbitwall'))
import control
import console
import domain_requests
import request_api
from settings import SETTINGS
import test_management


def payload(**changes):
    return dict(domains=['allowed.example'], duration_seconds=60, purpose='Download dependency', **changes)


class Requests(unittest.TestCase):
    def test_source_binding_limits_and_expiry(self):
        store = domain_requests.Requests()
        with patch.object(domain_requests.time, 'monotonic', return_value=100) as now:
            item = store.submit(SETTINGS, '10.1.0.10', payload())
            self.assertEqual(item['node_id'], 'ai-host')
            with self.assertRaises(domain_requests.RequestLimit): store.submit(SETTINGS, '10.1.0.10', payload())
            with self.assertRaises(ValueError): store.submit(SETTINGS, '10.1.0.11', payload())
            with self.assertRaises(ValueError): store.submit(SETTINGS, '10.1.0.10', payload(node_id='gateway'))
            now.return_value = 701
            with self.assertRaises(ValueError): store.get(item['id'])
            store.submit(SETTINGS, '10.1.0.10', payload())

    def test_queue_capacity_recovers_after_retention_and_cooldown(self):
        store=domain_requests.Requests()
        with patch.object(domain_requests.time,'monotonic',return_value=100) as now:
            for index in range(domain_requests.MAX_REQUESTS):
                now.return_value=100+index*10
                item=store.submit(SETTINGS,'10.1.0.10',payload())
                store.decided(item,'rejected')
            now.return_value+=10
            with self.assertRaises(domain_requests.RequestLimit): store.submit(SETTINGS,'10.1.0.10',payload())
            now.return_value=3000
            self.assertEqual(store.submit(SETTINGS,'10.1.0.10',payload())['status'],'pending')

    def controller(self):
        with patch.object(control, 'install_runtime', return_value=42): instance = control.Controller()
        self.addCleanup(instance.approvals.close)
        return instance

    def test_submission_never_grants_and_hides_other_nodes(self):
        instance = self.controller()
        with patch.object(instance, 'status', return_value={'domain_approvals':[]}), patch.object(instance, 'approve_domains') as approve:
            result = instance.agent_request('submit_domain_request', {'source':'10.1.0.10','request':payload()})
            self.assertEqual(result['status'], 'pending'); approve.assert_not_called()
            self.assertEqual(instance.approvals.grants, {})
            with self.assertRaises(ValueError):
                instance.agent_request('domain_request_status', {'source':'10.1.0.11','request':{'id':result['id']}})
            self.assertNotIn('_until', result)
            with self.assertRaises(ValueError):
                instance.agent_request('submit_domain_request', {'source':'10.1.0.10','request':dict(payload(),domains=['Any'])})

    def test_decision_starts_duration_at_approval_and_tracks_revoke(self):
        instance = self.controller()
        grants = []
        ports = [{'protocol': 'udp', 'port': 123}]
        def approve(spec):
            self.assertEqual(spec['duration_seconds'],60)
            self.assertEqual(spec['ports'], ports)
            instance.approvals.grants['ai-host']={'id':'grant'}
            grants.append({'id':'grant','remaining_seconds':60})
        with patch.object(domain_requests.time,'monotonic',return_value=100) as now, patch.object(instance,'status',side_effect=lambda:{'domain_approvals':list(grants)}), patch.object(instance,'approve_domains',side_effect=approve) as change:
            result=instance.agent_request('submit_domain_request',{'source':'10.1.0.10','request':payload(ports=ports)})
            now.return_value=200
            status=instance.decide_domain_request({'id':result['id'],'decision':'approve'})
            change.assert_called_once()
            self.assertEqual(status['domain_approvals'][0]['remaining_seconds'],60)
            result=instance.agent_request('domain_request_status',{'source':'10.1.0.10','request':{'id':result['id']}})
            self.assertEqual(result['status'],'approved')
            with self.assertRaises(ValueError): instance.decide_domain_request({'id':result['id'],'decision':'approve'})
            grants.clear()
            result=instance.agent_request('domain_request_status',{'source':'10.1.0.10','request':{'id':result['id']}})
            self.assertEqual(result['status'],'ended')
            # Test fixture grant has no cancellation object.
            instance.approvals.grants.clear()

    def test_real_grant_uses_approval_deadline_and_kernel_target_expiry(self):
        instance=self.controller()
        instance.approvals.guard=Mock()
        instance.approvals.nft=Mock()
        instance.approvals.executor.shutdown(wait=False)
        class ImmediateExecutor:
            def submit(self, fn, *args):
                future=concurrent.futures.Future();future.set_result(fn(*args));return future
            def shutdown(self, **kwargs): pass
        instance.approvals.executor=ImmediateExecutor()
        instance.approvals.resolver=lambda *args:{'allowed.example':{'addresses':['1.1.1.1'],'until':1000,'error':None}}
        with patch.object(control.time,'monotonic',return_value=100) as now, patch.object(control,'apply_enabled'), patch.object(control,'read_gate',side_effect=lambda:{'handle':42,'enabled':False,'restricted':bool(instance.approvals.grants)}):
            item=instance.agent_request('submit_domain_request',{'source':'10.1.0.10','request':payload()})
            self.assertEqual(instance.approvals.grants,{})
            now.return_value=200
            instance.decide_domain_request({'id':item['id'],'decision':'approve'})
            instance.approvals.tick()
            grant=instance.approvals.grants['ai-host']
            self.assertEqual(grant['deadline'],260)
            self.assertIn('10.1.0.10 . 1.1.1.1 . tcp . 443 timeout 20000ms',instance.approvals.nft.call_args[0][1])
            now.return_value=259
            instance.approvals.tick()
            self.assertIn('timeout 1000ms',instance.approvals.nft.call_args[0][1])
            now.return_value=260
            instance.approvals.tick()
            self.assertNotIn('add element',instance.approvals.nft.call_args[0][1])
            status=instance.agent_request('domain_request_status',{'source':'10.1.0.10','request':{'id':item['id']}})
            self.assertEqual(status['status'],'ended')
            now.return_value=300
            item=instance.agent_request('submit_domain_request',{'source':'10.1.0.10','request':payload()})
            instance.decide_domain_request({'id':item['id'],'decision':'approve'})
            grant=instance.approvals.grants['ai-host']
            args={'source':'10.1.0.10','request':{'id':item['id']}}
            status=instance.agent_request('revoke_domain_request',args)
            self.assertEqual(status['status'],'ended')
            self.assertTrue(grant['cancel'].is_set())
            self.assertEqual(instance.approvals.grants,{})
            instance.approvals.guard.apply.assert_called_with([])
            self.assertNotIn('add element',instance.approvals.nft.call_args[0][1])
            self.assertEqual(instance.agent_request('revoke_domain_request',args)['status'],'ended')

    def test_rejection_failure_and_node_change_never_approve(self):
        instance=self.controller()
        with patch.object(instance,'status',return_value={'domain_approvals':[]}), patch.object(instance,'approve_domains') as approve:
            item=instance.requests.submit(SETTINGS,'10.1.0.10',payload())
            instance.decide_domain_request({'id':item['id'],'decision':'reject'})
            self.assertEqual(item['status'],'rejected');approve.assert_not_called()
            item['status']='pending'
            instance.config=copy.deepcopy(SETTINGS)
            next(n for n in instance.config['nodes'] if n['id']=='ai-host')['ip']='10.1.0.12'
            with self.assertRaises(ValueError): instance.decide_domain_request({'id':item['id'],'decision':'approve'})
            approve.assert_not_called()
            instance.config=SETTINGS;approve.side_effect=RuntimeError('Firewall failed')
            with self.assertRaises(RuntimeError): instance.decide_domain_request({'id':item['id'],'decision':'approve'})
            self.assertEqual(item['status'],'pending')

    def test_self_revoke_is_source_bound_and_cannot_revoke_replacements(self):
        instance=self.controller()
        item=instance.requests.submit(SETTINGS,'10.1.0.10',payload())
        args={'source':'10.1.0.10','request':{'id':item['id']}}
        with patch.object(instance,'status',side_effect=lambda:{'domain_approvals':list(instance.approvals.grants.values())}), patch.object(instance,'revoke_domain') as revoke:
            with self.assertRaises(ValueError): instance.agent_request('revoke_domain_request',args)
            instance.requests.decided(item,'approved','a'*16)
            instance.approvals.grants['ai-host']={'id':'a'*16}
            with self.assertRaises(ValueError):
                instance.agent_request('revoke_domain_request',dict(args,source='10.1.0.11'))
            with self.assertRaises(ValueError):
                instance.agent_request('revoke_domain_request',dict(args,request={'id':item['id'],'grant_id':'a'*16}))
            revoke.assert_not_called()
            def remove(_): instance.approvals.grants.clear()
            revoke.side_effect=remove
            self.assertEqual(instance.agent_request('revoke_domain_request',args)['status'],'ended')
            revoke.assert_called_once_with({'id':'a'*16})
            instance.agent_request('revoke_domain_request',args)
            revoke.assert_called_once()
            instance.approvals.grants['ai-host']={'id':'b'*16}
            self.assertEqual(instance.agent_request('revoke_domain_request',args)['status'],'ended')
            revoke.assert_called_once()
            instance.approvals.grants.clear()


class RestrictedSocket(unittest.TestCase):
    def test_ingress_socket_rejects_every_admin_action_before_dispatch(self):
        instance=Mock()
        handler=control.make_control_handler(instance)
        class Server:
            request_only=True
        class Connection:
            def __init__(self, data):
                self.input=io.BytesIO((json.dumps(data)+'\n').encode());self.output=bytearray()
            def settimeout(self,_): pass
            def makefile(self,*_): return self.input
            def sendall(self,data): self.output.extend(data)
        for action in ('enable','disable','status','audit_log','nodes','save_nodes','approve_domains','revoke_domain','decide_domain_request'):
            data={'action':action}
            if action in ('save_nodes','approve_domains','revoke_domain','decide_domain_request'):data['payload']={}
            conn=Connection(data);handler(conn, '', Server())
            self.assertFalse(json.loads(conn.output)['ok'])
        self.assertEqual(instance.mock_calls,[])
        instance.agent_request.return_value={'status':'pending'}
        conn=Connection({'action':'submit_domain_request','payload':{'source':'10.1.0.10','request':payload()}})
        handler(conn, '', Server())
        self.assertTrue(json.loads(conn.output)['ok'])
        instance.agent_request.assert_called_once()


class AgentHTTP(unittest.TestCase):
    def request(self, method='POST', path='/api/domain-requests', data=None, source='10.1.0.10', extra='', host='10.1.0.1:8767', callback=None):
        raw='' if data == '' else json.dumps(payload() if data is None else data)
        wire=f'{method} {path} HTTP/1.0\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {len(raw)}\r\n{extra}\r\n{raw}'
        class Connection:
            output=bytearray()
            def makefile(self,*_): return io.BytesIO(wire.encode())
            def sendall(self,data): self.output.extend(data)
            def settimeout(self,_): pass
        conn=Connection()
        request_api.make_handler(callback=callback)(conn,(source,50000),object())
        return bytes(conn.output)

    def test_create_poll_and_no_admin_routes(self):
        callback=Mock(return_value={'id':'a'*32,'status':'pending'})
        self.assertIn(b'201 Created',self.request(callback=callback))
        callback.assert_called_with('submit_domain_request',payload={'source':'10.1.0.10','request':payload()})
        callback.reset_mock()
        self.assertIn(b'200 OK',self.request(method='GET',path='/api/domain-requests/'+'a'*32,callback=callback))
        callback.assert_called_once_with('domain_request_status',payload={'source':'10.1.0.10','request':{'id':'a'*32}})
        callback.reset_mock()
        for path in ['/api/domain-approvals','/api/internet','/api/nodes']:
            self.assertIn(b'404',self.request(path=path,callback=callback))
        callback.assert_not_called()

    def test_browser_foreign_source_invalid_body_and_rate_limit(self):
        callback=Mock()
        for args in [dict(extra='Origin: http://10.1.0.1:8767\r\n'),dict(host='evil.example'),dict(source='10.0.0.10'),dict(extra='Sec-Fetch-Site: same-site\r\n')]:
            self.assertIn(b'403',self.request(callback=callback,**args))
        self.assertIn(b'400',self.request(callback=callback,extra='Transfer-Encoding: chunked\r\n'))
        callback.assert_not_called()
        callback.side_effect=domain_requests.RequestLimit('pending')
        self.assertIn(b'429',self.request(callback=callback))

    def test_self_revoke_route_requires_post_empty_body_and_valid_id(self):
        callback=Mock(return_value={'status':'ended'})
        path='/api/domain-requests/'+'a'*32+'/revoke'
        self.assertIn(b'200 OK',self.request(path=path,callback=callback,data=''))
        callback.assert_called_once_with('revoke_domain_request',payload={'source':'10.1.0.10','request':{'id':'a'*32}})
        callback.reset_mock()
        for args in [dict(method='GET'), dict(data={}), dict(extra='Transfer-Encoding: chunked\r\n'), dict(path='/api/domain-requests/bad/revoke'), dict(source='10.0.0.10')]:
            options=dict(path=path,data='',callback=callback)
            options.update(args)
            self.assertNotIn(b'200 OK',self.request(**options))
        callback.assert_not_called()


class AdminHTTP(unittest.TestCase):
    request=test_management.HTTP.request

    def test_demo_request_approval_has_no_real_side_effects(self):
        callback=Mock()
        handler=console.make_handler(Path('/none'),8765,demo=True,control_callback=callback)
        response=self.request('/api/control',handler=handler)
        item=json.loads(response.split(b'\r\n\r\n',1)[1])['control']['domain_requests'][0]
        raw=json.dumps({'action':'approve_request','request':{'id':item['id']}})
        headers=f'Origin: http://127.0.0.1:8765\r\nContent-Type: application/json\r\nContent-Length: {len(raw)}\r\n'
        response=self.request('/api/domain-approvals',method='POST',headers=headers,body=raw,handler=handler)
        result=json.loads(response.split(b'\r\n\r\n',1)[1])['control']
        self.assertEqual(result['domain_requests'][0]['status'],'approved')
        self.assertEqual(result['mode'],'restricted')
        callback.assert_not_called()

    def test_request_decisions_require_mtls_and_fixed_id(self):
        callback=Mock(return_value={'available':True,'enabled':False})
        with tempfile.TemporaryDirectory() as directory:
            token=Path(directory)/'token';token.write_text('x'*43)
            handler=console.make_handler(Path('/none'),8765,control_callback=callback,token_file=token)
            raw=json.dumps({'action':'approve_request','request':{'id':'a'*32}})
            headers=f'Origin: http://127.0.0.1:8765\r\nContent-Type: application/json\r\nContent-Length: {len(raw)}\r\nAuthorization: Bearer '+('x'*43)+'\r\n'
            self.assertIn(b'403',self.request('/api/domain-approvals',method='POST',headers=headers,body=raw,handler=handler))
            callback.assert_not_called()
            self.assertIn(b'200 OK',self.request('/api/domain-approvals',method='POST',headers=headers+'X-RabbitWall-Auth: mtls\r\n',body=raw,handler=handler))
            callback.assert_called_once_with('decide_domain_request',payload={'id':'a'*32,'decision':'approve'})
