import test_environment
import concurrent.futures
import copy
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src/rabbitwall'))
import domain_approvals as domains
from firewall import domain_lease_rules
from unbound_guard import rpz_zone
from settings import SETTINGS
import console
import control
import test_management


def payload(**changes):
    data={'node_id':'ai-host','domains':['allowed.example'],'duration_seconds':300,'purpose':'dependency download'}
    data.update(changes);return data


class ImmediateExecutor:
    def submit(self,fn,*args):
        result=concurrent.futures.Future()
        try:result.set_result(fn(*args))
        except Exception as error:result.set_exception(error)
        return result
    def shutdown(self,**kwargs):pass


class DomainApprovals(unittest.TestCase):
    def test_exact_names_normalization_and_reject_arbitrary_targets(self):
        self.assertEqual(domains.parse_domains(['GITHUB.com.','github.com','api.github.com']),['github.com','api.github.com'])
        for bad in [['*.example.com'],['1.1.1.1'],['https://github.com'],['github.com:443'],['foo/bar.com'],['foo\nbar.com'],['a..com'],[],['a.com']*33]:
            with self.subTest(bad=bad),self.assertRaises(ValueError):domains.parse_domains(bad)
        for changes in [{'node_id':'gateway'},{'duration_seconds':True},{'duration_seconds':0},{'purpose':''},{'purpose':'x\ny'},{'source':'1.1.1.1'}]:
            with self.subTest(changes=changes),self.assertRaises(ValueError):domains.validate_request(SETTINGS,payload(**changes))

    def test_rpz_exact_allow_does_not_open_ancestor_or_descendant(self):
        zone=rpz_zone(['api.github.com','github.com'])
        self.assertIn('* CNAME .',zone)
        self.assertIn('com CNAME .',zone)
        self.assertIn('*.com CNAME .',zone)
        self.assertIn('*.github.com CNAME .',zone)
        self.assertIn('*.api.github.com CNAME .',zone)
        self.assertIn('github.com CNAME rpz-passthru.',zone)
        self.assertIn('api.github.com CNAME rpz-passthru.',zone)

    def manager(self,resolver=None):
        nft=Mock();guard=Mock()
        manager=domains.Approvals(nft,guard=guard,resolver=resolver or (lambda *args:{'allowed.example':{'addresses':['1.1.1.1'],'until':time.monotonic()+10,'error':None}}))
        manager.executor.shutdown(wait=False);manager.executor=ImmediateExecutor()
        self.addCleanup(manager.close)
        return manager,nft,guard

    def test_grants_expire_do_not_survive_restart_and_cannot_renew_old_dns(self):
        manager,nft,guard=self.manager()
        with patch.object(domains.time,'monotonic',return_value=100) as now:
            spec=domains.validate_request(SETTINGS,payload(duration_seconds=60))
            manager.approve(SETTINGS,spec);manager.tick()
            self.assertEqual(manager.snapshot()[0]['records'][0]['addresses'],['1.1.1.1'])
            script=nft.call_args[0][1]
            self.assertIn('10.1.0.10 . 1.1.1.1 timeout 10000ms',script)
            self.assertNotIn('online_sources',script)
            now.return_value=111
            self.assertEqual(manager.snapshot()[0]['records'][0]['addresses'],[])
            # Resolution failure removes an address rather than renewing a stale TTL.
            manager.resolver=lambda *args:{'allowed.example':{'addresses':[],'until':0,'error':'timeout'}}
            manager.tick();manager.tick()
            self.assertNotIn(' . 1.1.1.1',nft.call_args[0][1])
            now.return_value=161
            manager.tick();self.assertEqual(manager.snapshot(),[])
            self.assertNotIn('add element',nft.call_args[0][1])
        fresh,_,_=self.manager();self.assertEqual(fresh.snapshot(),[])

    def test_kernel_lease_is_bounded_by_dns_ttl_and_human_deadline(self):
        record={'source':'10.1.0.10','deadline':105,'records':{'x':{'addresses':['1.1.1.1','10.0.0.254'],'until':103}}}
        text=domain_lease_rules([record],100)
        self.assertIn('10.1.0.10 timeout 5000ms',text)
        self.assertIn('10.1.0.10 . 1.1.1.1 timeout 3000ms',text)
        self.assertNotIn('10.0.0.254',text)
        self.assertNotIn('add element',domain_lease_rules([record],106))

    def test_replacing_and_revoking_grants_cancels_old_work(self):
        manager,nft,guard=self.manager()
        spec=domains.validate_request(SETTINGS,payload())
        manager.approve(SETTINGS,spec)
        previous=manager.grants['ai-host'];old_id=previous['id']
        manager.approve(SETTINGS,spec)
        self.assertTrue(previous['cancel'].is_set())
        self.assertNotEqual(manager.grants['ai-host']['id'],old_id)
        with self.assertRaises(ValueError):manager.revoke(old_id)
        manager.revoke(manager.snapshot()[0]['id'])
        self.assertEqual(manager.snapshot(),[])
        self.assertNotIn('add element',nft.call_args[0][1])

    def test_policy_failure_does_not_install_a_grant(self):
        manager,nft,guard=self.manager();guard.apply.side_effect=RuntimeError('reload failed')
        with self.assertRaises(RuntimeError):manager.approve(SETTINGS,domains.validate_request(SETTINGS,payload()))
        self.assertEqual(manager.snapshot(),[])
        nft.assert_not_called()

    def test_expired_or_lost_grants_still_clear_loaded_dns_policy_before_full_open(self):
        manager,nft,guard=self.manager()
        manager.approve(SETTINGS,domains.validate_request(SETTINGS,payload()))
        manager.grants['ai-host']['deadline']=0
        self.assertEqual(manager.snapshot(),[])
        guard.reset_mock()
        manager.clear(sync=True)
        guard.apply.assert_called_once_with([])
        manager.reset_runtime()
        guard.reset_mock()
        manager.clear(sync=True)
        guard.apply.assert_called_once_with([])

    def test_controller_failure_and_lost_kernel_lease_close_permissions(self):
        with patch.object(control,'install_runtime',return_value=42):controller=control.Controller()
        self.addCleanup(controller.approvals.close)
        controller.approvals=Mock()
        controller.approvals.approve.side_effect=RuntimeError('DNS reload failed')
        with patch.object(control,'apply_enabled') as apply:
            with self.assertRaises(RuntimeError):controller.approve_domains(payload())
            controller.approvals.clear.assert_called_once()
            apply.assert_called_with(False)
        controller.approvals.reset_mock();controller.approvals.snapshot.return_value=[{'id':'test'}]
        with patch.object(control,'read_gate',return_value={'handle':42,'enabled':False,'restricted':False}),patch.object(control,'apply_enabled') as apply:
            self.assertFalse(controller.status()['enabled'])
            controller.approvals.clear.assert_called_once();apply.assert_called_once_with(False)


class DomainHTTP(unittest.TestCase):
    request = test_management.HTTP.request
    def post_domains(self,handler,body,headers=''):
        raw=json.dumps(body)
        headers+='Origin: http://127.0.0.1:8765\r\nContent-Type: application/json\r\nContent-Length: '+str(len(raw))+'\r\n'
        return self.request('/api/domain-approvals',method='POST',headers=headers,body=raw,handler=handler)

    def test_approval_requires_mtls_and_server_key_and_has_fixed_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            token=Path(directory)/'token';token.write_text('x'*43)
            callback=Mock(return_value={'enabled':True,'mode':'restricted'})
            handler=console.make_handler(Path('/unused'),8765,control_callback=callback,token_file=token)
            body={'action':'approve','request':payload()}
            key='Authorization: Bearer '+'x'*43+'\r\n'
            self.assertIn(b'403',self.post_domains(handler,body,key));callback.assert_not_called()
            self.assertIn(b'403',self.post_domains(handler,body,'X-RabbitWall-Auth: mtls\r\n'));callback.assert_not_called()
            self.assertIn(b'200 OK',self.post_domains(handler,body,key+'X-RabbitWall-Auth: mtls\r\n'))
            callback.assert_called_once_with('approve_domains',payload=payload())
            callback.reset_mock()
            self.assertIn(b'400',self.post_domains(handler,{'action':'enable','request':{}},key+'X-RabbitWall-Auth: mtls\r\n'));callback.assert_not_called()

    def test_demo_approval_expiry_without_network_or_root_side_effects(self):
        callback=Mock();handler=console.make_handler(Path('/unused'),8765,demo=True,control_callback=callback)
        with patch.object(console.time,'monotonic',return_value=100) as now:
            self.assertIn(b'200 OK',self.post_domains(handler,{'action':'approve','request':payload(duration_seconds=60)}))
            data=self.request('/api/control',handler=handler).split(b'\r\n\r\n',1)[1]
            self.assertEqual(json.loads(data)['control']['mode'],'restricted')
            now.return_value=161
            data=self.request('/api/control',handler=handler).split(b'\r\n\r\n',1)[1]
            self.assertEqual(json.loads(data)['control']['mode'],'closed')
        callback.assert_not_called()

if __name__=='__main__':unittest.main()
