"""Real Unbound RPZ + routed nftables approvals. Disposable Docker only."""
import test_environment
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src/rabbitwall'))
from linux_gate_smoke import ip,run,client,SERVER
import control
from firewall import baseline,gate,dns_rule,probe_rules
from settings import SETTINGS
from unbound_config import render,CONFIG_PATH,POLICY_FILE
from domain_approvals import Approvals,validate_request
from unbound_guard import DNSGuard

DNS_SERVER = '''import socketserver,dns.message,dns.rrset,threading,sys
class DNS(socketserver.BaseRequestHandler):
 def handle(self):
  request=dns.message.from_wire(self.request[0]);response=dns.message.make_response(request)
  name=request.question[0].name.to_text();print(name,flush=True)
  response.answer.append(dns.rrset.from_text(name,3,'IN','A','1.1.1.1' if name=='allowed.example.' else '2.2.2.2'))
  self.request[1].sendto(response.to_wire(),self.client_address)
server=socketserver.UDPServer(('10.0.0.254',53),DNS)
print('ready',flush=True);server.serve_forever()
'''


def dns_query(name,expected,source='10.1.0.10',tcp=False):
    code='''import dns.message,dns.query,dns.rcode,sys
try:
 answer=dns.query.METHOD(dns.message.make_query(sys.argv[1],'A'),'10.1.0.1',source=sys.argv[2],timeout=.7)
 print(dns.rcode.to_text(answer.rcode()))
except Exception:print('blocked')
'''.replace('METHOD','tcp' if tcp else 'udp')
    actual=run(['ip','netns','exec','ai',sys.executable,'-c',code,name,source]).strip()
    assert actual==expected,(name,source,tcp,actual,expected)


def main():
    if not Path('/.dockerenv').exists() or os.environ.get('RABBITWALL_DISPOSABLE_TEST')!='1' or Path('/sys/class/net/eth0').exists():
        raise SystemExit('Disposable --network none Docker required')
    for ns,iface,peer,local,remote in [('ai','eth1','ai-side','10.1.0.1/24','10.1.0.10/24'),('upstream','eth0','up-side','10.2.0.2/30','10.2.0.1/30')]:
        ip('netns','add',ns);ip('link','add',iface,'type','veth','peer','name',peer);ip('link','set',peer,'netns',ns)
        ip('addr','add',local,'dev',iface);ip('link','set',iface,'up');ip('-n',ns,'addr','add',remote,'dev',peer);ip('-n',ns,'link','set',peer,'up');ip('-n',ns,'link','set','lo','up')
    ip('-n','ai','addr','add','10.1.0.11/24','dev','ai-side');ip('-n','ai','route','add','default','via','10.1.0.1')
    ip('-n','upstream','route','add','10.1.0.0/24','via','10.2.0.2');ip('route','add','default','via','10.2.0.1')
    for address in ['1.1.1.1/32','2.2.2.2/32','10.0.0.254/32']:ip('-n','upstream','addr','add',address,'dev','lo')
    cfg=copy.deepcopy(SETTINGS)
    cfg['nodes'].append({'id':'second','label':'Second','ip':'10.1.0.11','interface':'eth1','monitor':False,'allow_ssh':False,'allow_https':False,'allow_ping':False})
    control.nft(['-f','-'],baseline(cfg).replace('include "/etc/nftables.d/rabbitwall.nft"',gate(cfg)+dns_rule(cfg)+probe_rules(cfg)))
    POLICY_FILE.parent.mkdir(parents=True,exist_ok=True);POLICY_FILE.write_text('');POLICY_FILE.chmod(0o644)
    Path('/run/rabbitwall-dns').mkdir(exist_ok=True)
    CONFIG_PATH.write_text(render(cfg));CONFIG_PATH.chmod(0o644)
    children=[];manager=Approvals(control.nft)
    try:
        for args in [ ['ip','netns','exec','upstream',sys.executable,'-u','-c',DNS_SERVER],
                      ['ip','netns','exec','upstream',sys.executable,'-u','-c',SERVER,'80,443','none','10.0.0.254'] ]:
            process=subprocess.Popen(args,stdout=subprocess.PIPE,text=True);children.append(process);assert process.stdout.readline().strip()=='ready'
        unbound=subprocess.Popen(['unbound','-d','-c',str(CONFIG_PATH)],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True);children.append(unbound)
        deadline=time.monotonic()+5
        while not Path('/run/rabbitwall-dns/control.sock').exists():
            assert unbound.poll() is None,unbound.stderr.read();assert time.monotonic()<deadline;time.sleep(.05)
        dns_query('allowed.example','blocked')
        spec=validate_request(cfg,{'node_id':'ai-host','domains':['allowed.example'],'duration_seconds':60,'purpose':'test download'})
        manager.approve(cfg,spec)
        deadline=time.monotonic()+5
        while not any(record['addresses'] for grant in manager.snapshot() for record in grant['records']):
            manager.tick();assert time.monotonic()<deadline,manager.snapshot();time.sleep(.05)
        for name in ['other.example','www.allowed.example','x.unknown.example','allowed.example.evil','example']:
            dns_query(name,'NXDOMAIN')
        dns_query('allowed.example','NOERROR');dns_query('allowed.example','NOERROR',tcp=True)
        dns_query('allowed.example','blocked',source='10.1.0.11')
        client('ai','1.1.1.1',443);client('ai','1.1.1.1',80)
        client('ai','2.2.2.2',443,expected=False);client('ai','1.1.1.1',443,source='10.1.0.11',expected=False)
        print('PASS: exact DNS QNAME, subdomain/default deny, UDP/TCP DNS, per-node IP targets and direct-IP deny',flush=True)
        # Different clients receive different DNS policies even when both have grants.
        second=validate_request(cfg,{'node_id':'second','domains':['other.example'],'duration_seconds':60,'purpose':'other host'})
        control.apply_enabled(False);manager.approve(cfg,second)
        deadline=time.monotonic()+5
        while not all(any(r['addresses'] for r in g['records']) for g in manager.snapshot()):
            manager.tick();assert time.monotonic()<deadline;time.sleep(.05)
        dns_query('other.example','NOERROR',source='10.1.0.11')
        dns_query('other.example','NXDOMAIN');dns_query('allowed.example','NXDOMAIN',source='10.1.0.11')
        client('ai','2.2.2.2',443,source='10.1.0.11');client('ai','2.2.2.2',443,expected=False)
        print('PASS: Unbound tags isolate DNS policies for simultaneous nodes',flush=True)
        # A held connection must stop immediately after its approval is revoked.
        held_code='''import socket,sys
s=socket.create_connection(('1.1.1.1',443),timeout=.7);print('ready',flush=True)
for line in sys.stdin:
 try:s.sendall(b'test');print('ok' if s.recv(20)==b'test' else 'bad',flush=True)
 except OSError:print('blocked',flush=True)
'''
        held=subprocess.Popen(['ip','netns','exec','ai',sys.executable,'-u','-c',held_code],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True);children.append(held)
        assert held.stdout.readline().strip()=='ready'
        approval=next(g for g in manager.snapshot() if g['node_id']=='ai-host')
        control.apply_enabled(False);manager.revoke(approval['id'])
        held.stdin.write('send\n');held.stdin.flush();assert held.stdout.readline().strip()=='blocked'
        dns_query('allowed.example','blocked');client('ai','2.2.2.2',443,source='10.1.0.11')
        # Shortened deadline tests actual kernel expiry without waiting a minute.
        grant=manager.grants['second'];grant['deadline']=time.monotonic()+.3;manager.tick()
        time.sleep(.5)
        client('ai','2.2.2.2',443,source='10.1.0.11',expected=False);dns_query('other.example','blocked',source='10.1.0.11')
        print('PASS: revoke blocks established TCP; kernel expiry closes DNS and web without another tick',flush=True)
        assert manager.snapshot()==[]
        manager.clear(sync=True);control.apply_enabled(True)
        dns_query('other.example','NOERROR');client('ai','2.2.2.2',443)
        control.apply_enabled(False)
        print('PASS: explicit full-open mode and global OFF remain available',flush=True)
    finally:
        manager.close();control.apply_enabled(False)
        for process in children:process.terminate()
        for process in children:process.wait(timeout=4)

if __name__=='__main__':main()
