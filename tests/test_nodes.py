import test_environment
import copy
import json
from pathlib import Path
import tempfile
import unittest
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"src/rabbitwall"))
from unittest.mock import Mock, patch

import control
import console
import node_config
import settings
from firewall import node_rule_batch
import test_management


class NodeSettings(unittest.TestCase):
    def config(self):
        return copy.deepcopy(settings.SETTINGS)

    def payload(self, config, nodes):
        return {'nodes':node_config.document(dict(config,nodes=nodes))['nodes'], 'revision':node_config.revision(config)}

    def test_monitoring_does_not_grant_management_access(self):
        config = self.config()
        ai = next(node for node in config['nodes'] if node['interface'] == config['ai_if'])
        ai.update(monitor=True, allow_ssh=False, allow_ping=False)
        text = node_rule_batch(config, [])
        self.assertNotIn(f'ip daddr {ai["ip"]} tcp dport 22', text)
        self.assertIn(f'ip daddr {ai["ip"]} icmp type echo-request counter accept', text)
        ai.update(monitor=False, allow_ssh=True)
        text = node_rule_batch(config, [])
        self.assertIn(f'ip daddr {ai["ip"]} tcp dport 22', text)
        self.assertNotIn(f'ip daddr {ai["ip"]} icmp type echo-request counter accept', text)
        self.assertNotIn('flush ruleset', text)
        self.assertNotIn('online_sources', text)

    def test_https_is_opt_in_and_independent_of_ssh_and_monitoring(self):
        config = self.config()
        ai = next(node for node in config['nodes'] if node['interface'] == config['ai_if'])
        ai.pop('allow_https', None)
        self.assertFalse(settings.management_allowed(ai, 'https', config))
        self.assertFalse(node_config.document(config)['nodes'][-1]['allow_https'])
        text = node_rule_batch(config, [])
        self.assertNotIn(f'ip daddr {ai["ip"]} tcp dport 443', text)
        ai.update(allow_https=True, allow_ssh=False, allow_ping=False, monitor=False)
        text = node_rule_batch(config, [])
        self.assertIn(f'ip saddr {config["admin_ip"]} ip daddr {ai["ip"]} tcp dport 443 ct state {{ new, established }} accept', text)
        self.assertIn(f'ip saddr {ai["ip"]} ip daddr {config["admin_ip"]} tcp sport 443 ct state established ct direction reply accept', text)
        self.assertNotIn(f'ip daddr {ai["ip"]} tcp dport 22', text)
        self.assertIn('tcp dport { 22, 443 } counter drop', text)
        self.assertIn('tcp sport { 22, 443 } ct direction reply counter drop', text)
        self.assertNotIn('online_sources', text)
        self.assertTrue(node_config.candidate(config, self.payload(config,config['nodes']))['nodes'][-1]['allow_https'])
        nodes = node_config.document(config)['nodes']
        del nodes[-1]['allow_https']
        with self.assertRaisesRegex(ValueError, 'explicit'):
            node_config.candidate(config, {'nodes':nodes,'revision':node_config.revision(config)})
        config['nodes'][0]['allow_https'] = True
        with self.assertRaisesRegex(ValueError, 'AI-side'):
            settings.validate(config)

    def test_validation_rejects_duplicate_injection_wrong_subnet_flags_and_stale_revision(self):
        config = self.config()
        for edit in ({'ip':'127.0.0.1'}, {'interface':'eth1; reboot'}, {'monitor':'yes'}, {'allow_ssh':1}, {'allow_https':1}):
            nodes = copy.deepcopy(config['nodes']); nodes[-1].update(edit)
            with self.subTest(edit=edit), self.assertRaises(ValueError):
                node_config.candidate(config, self.payload(config, nodes))
        nodes = copy.deepcopy(config['nodes']);nodes.append(copy.deepcopy(nodes[-1]))
        with self.assertRaises(ValueError): node_config.candidate(config,self.payload(config,nodes))
        with self.assertRaises(node_config.RevisionConflict): node_config.candidate(config,{'nodes':[],'revision':'stale'})
        with self.assertRaises(ValueError): node_config.candidate(config,dict(self.payload(config,[]),admin_ip='1.1.1.1'))
        self.assertEqual(node_config.candidate(config,self.payload(config,[]))['nodes'],[])

    def test_save_requires_explicit_management_choices(self):
        config=self.config()
        nodes=node_config.document(config)['nodes']
        del nodes[-1]['allow_ssh']
        with self.assertRaisesRegex(ValueError,'explicit'):
            node_config.candidate(config,{'nodes':nodes,'revision':node_config.revision(config)})

    def test_disabled_monitor_is_not_probed(self):
        config = self.config()
        for node in config['nodes']: node['monitor'] = False
        with patch.object(control.subprocess,'run') as run:
            result = control.probe_nodes(config=config)
        run.assert_not_called()
        self.assertTrue(all(node['state']=='disabled' for node in result[1:]))

    def test_save_rolls_back_files_and_live_permissions_on_write_failure(self):
        config = self.config()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory);nodes=root/'nodes.json';snippet=root/'rabbitwall.nft'
            nodes.write_bytes(b'old nodes');snippet.write_bytes(b'old firewall')
            nft = Mock()
            real_write = node_config.atomic_write
            failed = False
            def write(path, content, mode=0o644):
                nonlocal failed
                if Path(path)==snippet and not failed:
                    failed=True;raise OSError('disk full')
                return real_write(path,content,mode)
            with patch.object(node_config,'atomic_write',side_effect=write):
                with self.assertRaises(OSError): node_config.save(config,self.payload(config,[]),nft,lambda:[],nodes,snippet)
            self.assertEqual(nodes.read_bytes(),b'old nodes');self.assertEqual(snippet.read_bytes(),b'old firewall')
            self.assertEqual(len(nft.call_args_list),3)  # validate, apply, restore
            self.assertNotIn('online_sources',nft.call_args_list[-1].args[1])

    def test_persistent_nodes_override_only_runtime_load(self):
        config = self.config()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)/'base.json';base.write_text(json.dumps(config))
            override = Path(directory)/'nodes.json';override.write_text('{"nodes":[]}')
            with patch.object(settings,'NODES_CONFIG',override),patch.dict(settings.os.environ,{'RABBITWALL_CONFIG':str(base)}):
                self.assertEqual(settings.load()['nodes'],[])
                self.assertEqual(settings.load(base)['nodes'],config['nodes'])

    def test_demo_crud_and_stale_write_conflict(self):
        http=test_management.HTTP()
        handler=console.make_handler(Path('/unused'),8765,True)
        def request(method, data=None):
            body=json.dumps(data) if data is not None else ''
            headers='Origin: http://127.0.0.1:8765\r\nContent-Type: application/json\r\nContent-Length: '+str(len(body.encode()))+'\r\n'
            return http.request('/api/nodes',headers=headers,method=method,body=body,handler=handler)
        doc=json.loads(request('GET').split(b'\r\n\r\n',1)[1])['settings']
        response=request('POST',{'nodes':[],'revision':doc['revision']})
        self.assertIn(b'200 OK',response)
        self.assertEqual(json.loads(response.split(b'\r\n\r\n',1)[1])['settings']['nodes'],[])
        self.assertIn(b'409 Conflict',request('POST',{'nodes':doc['nodes'],'revision':doc['revision']}))

    def test_authenticated_save_is_forwarded_as_nodes_only(self):
        http=test_management.HTTP()
        config=self.config();callback=Mock(return_value=node_config.document(config))
        with tempfile.TemporaryDirectory() as directory:
            token=Path(directory)/'token';token.write_text('x'*40)
            handler=console.make_handler(Path('/unused'),8765,False,callback,token)
            payload=self.payload(config,config['nodes']);body=json.dumps(payload)
            headers=('Origin: http://127.0.0.1:8765\r\nContent-Type: application/json\r\n'
                     'X-RabbitWall-Auth: mtls\r\nAuthorization: Bearer '+'x'*40+'\r\nContent-Length: '+str(len(body))+'\r\n')
            response=http.request('/api/nodes',method='POST',body=body,headers=headers,handler=handler)
            self.assertIn(b'200 OK',response)
            callback.assert_called_once_with('save_nodes',payload=payload)

    def test_node_mutations_require_mtls_token_and_same_origin(self):
        http=test_management.HTTP();callback=Mock()
        with tempfile.TemporaryDirectory() as directory:
            token=Path(directory)/'token';token.write_text('x'*40)
            handler=console.make_handler(Path('/unused'),8765,False,callback,token)
            body=json.dumps(self.payload(self.config(),[]))
            common='Content-Type: application/json\r\nContent-Length: '+str(len(body))+'\r\n'
            for security in ('', 'Authorization: Bearer '+'x'*40+'\r\n', 'X-RabbitWall-Auth: mtls\r\n'):
                response=http.request('/api/nodes',method='POST',body=body,headers=common+'Origin: http://127.0.0.1:8765\r\n'+security,handler=handler)
                self.assertIn(b'403',response)
            response=http.request('/api/nodes',method='POST',body=body,headers=common+'Authorization: Bearer '+'x'*40+'\r\nX-RabbitWall-Auth: mtls\r\n',handler=handler)
            self.assertIn(b'403',response);callback.assert_not_called()
