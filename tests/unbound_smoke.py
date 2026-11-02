#!/usr/bin/env python3
"""Real Unbound + dnstap and nftables tests, only in disposable network-none Docker."""
import test_environment
import json
import os
from pathlib import Path
import signal
import shutil
import socketserver
import subprocess
import sys
import tempfile
import threading
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src/rabbitwall'))
import dns.flags
import dns.message
import dns.rrset
import control
from dns_observations import OBSERVATIONS, domain_hints, load_observations
from firewall import baseline, gate, dns_rule, probe_rules
from settings import SETTINGS
from unbound_config import render, check_config, require_unbound

CLIENT = '''
import dns.query,dns.message,sys
server,name,tcp,expect,count,source=sys.argv[1:]
for _ in range(int(count)):
 try:
  fn=dns.query.tcp if tcp=="tcp" else dns.query.udp
  result=fn(dns.message.make_query(name,"A"),server,timeout=.7,source=source)
  assert expect=="ok" and any(rr.rdtype==1 and rr[0].address=="1.1.1.1" for rr in result.answer),result
 except (OSError,dns.exception.Timeout):
  assert expect=="blocked"
print("ok")
'''


def upstream(directory):
    def answer(wire,tcp):
        query=dns.message.from_wire(wire)
        with (directory/'queries').open('a') as log:log.write(query.question[0].name.to_text()+'\n')
        response=dns.message.make_response(query)
        response.flags |= dns.flags.RA
        if query.question[0].name.to_text().startswith('fallback.') and not tcp:
            response.flags |= dns.flags.TC
        else:
            response.answer=[dns.rrset.from_text('edge.example.',90,'IN','A','1.1.1.1')]
            if query.question[0].name.to_text()!='edge.example.':
                response.answer.insert(0,dns.rrset.from_text(query.question[0].name.to_text(),120,'IN','CNAME','edge.example.'))
        return response.to_wire()
    class UDP(socketserver.BaseRequestHandler):
        def handle(self):
            wire,sock=self.request;sock.sendto(answer(wire,False),self.client_address)
    class TCP(socketserver.BaseRequestHandler):
        def handle(self):
            import struct
            def read(size):
                data=b''
                while len(data)<size:
                    part=self.request.recv(size-len(data))
                    if not part:raise EOFError
                    data+=part
                return data
            try:
                size,=struct.unpack('!H',read(2));wire=answer(read(size),True)
                self.request.sendall(struct.pack('!H',len(wire))+wire)
            except OSError:pass
    with socketserver.ThreadingUDPServer(('10.0.0.254',53),UDP) as udp, socketserver.ThreadingTCPServer(('10.0.0.254',53),TCP) as tcp:
        threading.Thread(target=udp.serve_forever,daemon=True).start()
        threading.Thread(target=tcp.serve_forever,daemon=True).start()
        print('ready',flush=True)
        while True:time.sleep(1)


def restricted_unbound(config, without_netlink=False):
    """Exercise the unit's socket-family restriction without a systemd PID 1."""
    import ctypes
    import ctypes.util
    import socket
    lib = ctypes.CDLL(ctypes.util.find_library('seccomp'))
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
    class Comparison(ctypes.Structure):
        _fields_ = [('arg',ctypes.c_uint),('op',ctypes.c_uint),
                    ('a',ctypes.c_uint64),('b',ctypes.c_uint64)]
    lib.seccomp_rule_add_array.argtypes = [ctypes.c_void_p,ctypes.c_uint32,
                                         ctypes.c_int,ctypes.c_uint,ctypes.POINTER(Comparison)]
    lib.seccomp_load.argtypes = [ctypes.c_void_p]
    lib.seccomp_release.argtypes = [ctypes.c_void_p]
    line = next(line for line in (ROOT/'systemd/rabbitwall-dns.service').read_text().splitlines()
                if line.startswith('RestrictAddressFamilies='))
    allowed = {int(getattr(socket, name)) for name in line.split('=',1)[1].split()}
    if without_netlink: allowed.discard(int(socket.AF_NETLINK))
    context = lib.seccomp_init(0x7fff0000)  # SCMP_ACT_ALLOW
    assert context
    try:
        number = lib.seccomp_syscall_resolve_name(b'socket')
        for family in range(64):
            if family not in allowed:
                comparison = Comparison(0,4,family,0)  # SCMP_CMP_EQ
                assert lib.seccomp_rule_add_array(context,0x50000 | 97,number,1,ctypes.byref(comparison)) == 0
        assert lib.seccomp_load(context) == 0
    finally:
        lib.seccomp_release(context)
    os.execvp('unbound',['unbound','-d','-c',str(config)])


def main():
    if not Path('/.dockerenv').exists() or os.environ.get('RABBITWALL_DISPOSABLE_TEST')!='1' or Path('/sys/class/net/eth0').exists():
        raise SystemExit('Requires disposable privileged --network none Docker')
    require_unbound()
    children=[]
    def run(*args):
        return subprocess.run(list(args),check=True,capture_output=True,text=True).stdout
    def start(args,**kwargs):
        child=subprocess.Popen(list(map(str,args)),**kwargs);children.append(child);return child
    try:
        for ns,iface,peer,local,remote in [('ai','eth1','ai-side','10.1.0.1/24','10.1.0.10/24'),
                                         ('upstream','eth0','up-side','10.2.0.2/30','10.2.0.1/30')]:
            run('ip','netns','add',ns);run('ip','link','add',iface,'type','veth','peer','name',peer)
            run('ip','link','set',peer,'netns',ns);run('ip','addr','add',local,'dev',iface)
            run('ip','link','set',iface,'up')
            run('ip','-n',ns,'addr','add',remote,'dev',peer);run('ip','-n',ns,'link','set',peer,'up')
            run('ip','-n',ns,'link','set','lo','up')
        run('ip','-n','ai','addr','add','10.1.0.11/24','dev','ai-side')
        run('ip','-n','ai','route','add','default','via','10.1.0.1')
        run('ip','-n','upstream','addr','add','10.0.0.254/32','dev','lo')
        run('ip','-n','upstream','route','add','10.1.0.0/24','via','10.2.0.2')
        run('ip','route','add','10.0.0.254/32','via','10.2.0.1')
        script=baseline(SETTINGS).replace('include "/etc/nftables.d/rabbitwall.nft"',gate(SETTINGS)+dns_rule(SETTINGS)+probe_rules(SETTINGS))
        control.nft(['-f','-'],script)
        controller=control.Controller()
        def client(name='cache.example',tcp=False,expect='ok',count=1,source='10.1.0.10'):
            proc=start(['ip','netns','exec','ai',sys.executable,'-B','-c',CLIENT,'10.1.0.1',name,
                        'tcp' if tcp else 'udp',expect,str(count),source],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            deadline=time.monotonic()+30;last_tick=0
            while proc.poll() is None:
                if time.monotonic()>deadline:
                    proc.kill();raise AssertionError('DNS client stalled')
                if time.monotonic()-last_tick>2:
                    controller.tick();last_tick=time.monotonic()
                time.sleep(.01)
            output,errors=proc.communicate()
            assert proc.returncode==0,(name,output,errors,(directory/'unbound.log').read_text()[-9000:],(directory/'queries').read_text() if (directory/'queries').exists() else 'no upstream query')
        def wait_hint(name,client_ip='10.1.0.10'):
            deadline=time.monotonic()+12
            while time.monotonic()<deadline:
                controller.tick()
                records=domain_hints(load_observations(),client_ip,'1.1.1.1')
                match=next((r for r in records if r['domain']==name),None)
                if match:return match
                client(name,source=client_ip);time.sleep(.2)
            raise AssertionError('Missing dnstap domain: '+name)
        with tempfile.TemporaryDirectory() as directory:
            directory=Path(directory)
            directory.chmod(0o755)
            runtime=Path('/run/rabbitwall-dns');runtime.mkdir(exist_ok=True)
            shutil.chown(runtime,user='unbound',group='unbound');runtime.chmod(0o750)
            up=start(['ip','netns','exec','upstream',sys.executable,'-B',__file__,'--upstream',directory],stdout=subprocess.PIPE,text=True)
            assert up.stdout.readline().strip()=='ready'
            from unbound_config import POLICY_FILE
            POLICY_FILE.parent.mkdir(parents=True,exist_ok=True);POLICY_FILE.parent.chmod(0o755)
            POLICY_FILE.write_text('');POLICY_FILE.chmod(0o644)
            config=directory/'unbound.conf';config.write_text(render(SETTINGS));config.chmod(0o644);check_config(config.read_text())
            with (directory/'unbound.log').open('w') as log:
                # Reproduce the reported failure when NETLINK_ROUTE is denied.
                bad=start([sys.executable,'-B',__file__,'--restricted-unbound',config,'--without-netlink'],
                          stdout=log,stderr=log,user='unbound',group='unbound',extra_groups=[])
                assert bad.wait(timeout=5) != 0
                assert 'failed to list interfaces' in (directory/'unbound.log').read_text()
                unbound=start([sys.executable,'-B',__file__,'--restricted-unbound',config],
                              stdout=log,stderr=log,user='unbound',group='unbound',extra_groups=[])
                time.sleep(.3);assert unbound.poll() is None
                controller.set_enabled(True)
                # Unbound starts and serves DNS even before the observer exists.
                client('before-observer.example');client('fallback.example',tcp=True)
                observer=start([sys.executable,'-B',ROOT/'src/rabbitwall/dnstap_observer.py'],user='unbound',group='unbound',extra_groups=[])
                record=wait_hint('observed.example')
                assert 0<record['expires_at']-record['observed_at']<=90.1,record
                assert not domain_hints(load_observations(),'10.1.0.11','1.1.1.1')
                wait_hint('second-client.example','10.1.0.11')
                assert not any(r['domain']=='second-client.example' for r in domain_hints(load_observations(),'10.1.0.10','1.1.1.1'))
                before=(directory/'queries').read_text().count('observed.example.')
                time.sleep(1.1);client('observed.example',tcp=True);time.sleep(2.1)
                after=(directory/'queries').read_text().count('observed.example.')
                assert before==after,'Expected cache hit'
                deadline=time.monotonic()+8
                while time.monotonic()<deadline:
                    cached=next(r for r in load_observations() if r['domain']=='observed.example')
                    if cached['observed_at']>record['observed_at']:break
                    time.sleep(.1)
                assert cached['observed_at']>record['observed_at'],(cached,record)
                assert cached['expires_at']-cached['observed_at']<90
                client('fallback.example')  # Real upstream UDP TC → TCP fallback.
                wait_hint('fallback.example')
                print('PASS: real Unbound UDP/TCP, dnstap client/TTL/CNAME hints, cache hits and TCP fallback',flush=True)
                observer.terminate();observer.wait(timeout=4)
                client('stopped-observer.example');client('observed.example',tcp=True)
                assert unbound.poll() is None
                observer=start([sys.executable,'-B',ROOT/'src/rabbitwall/dnstap_observer.py'],user='unbound',group='unbound',extra_groups=[])
                wait_hint('reconnected.example')
                # Freeze a connected observer and fill its transport/producer queues.
                observer.send_signal(signal.SIGSTOP)
                client('reconnected.example',count=12000)
                assert unbound.poll() is None
                observer.send_signal(signal.SIGCONT)
                wait_hint('resumed.example')
                print('PASS: observer absent/stopped/restarted/paused under 12000 cache queries; DNS continues',flush=True)
                controller.set_enabled(False)
                client('observed.example',expect='blocked')
                client('observed.example',tcp=True,expect='blocked')
                client('never-cached.example',expect='blocked')
                assert unbound.poll() is None
                controller.set_enabled(True);client('after-reopen.example');wait_hint('after-reopen.example')
                control.nft(['-f','-'],'flush set inet rabbitwall_console online_sources\nadd element inet rabbitwall_console online_sources { 10.1.0.0/24 timeout 1s }\n')
                time.sleep(1.2)
                client('observed.example',expect='blocked')
                print('PASS: CLOSED blocks cached and uncached UDP/TCP DNS; reopening and kernel lease expiry preserved',flush=True)
    finally:
        for child in children:
            if child.poll() is None:
                child.send_signal(signal.SIGCONT);child.terminate()
        for child in children:
            try:child.wait(timeout=4)
            except subprocess.TimeoutExpired:child.kill();child.wait()


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--upstream':upstream(Path(sys.argv[2]))
    elif len(sys.argv)>1 and sys.argv[1]=='--restricted-unbound':restricted_unbound(Path(sys.argv[2]),'--without-netlink' in sys.argv)
    else:main()
