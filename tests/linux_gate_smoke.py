import test_environment
"""Kernel forwarding tests. ONLY in disposable --network none Docker container."""
import os
import copy
import tempfile
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src/rabbitwall"))
import control


def run(args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def ip(*args):
    return run(["ip", *args])


def client(namespace, destination, port, expected=True, source=None, udp=False):
    code = '''import socket,sys
s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM if sys.argv[4]=="udp" else socket.SOCK_STREAM)
s.settimeout(0.7)
try:
 if sys.argv[3]!="none": s.bind((sys.argv[3],0))
 s.connect((sys.argv[1],int(sys.argv[2])));s.sendall(b"test");print("ok" if s.recv(100)==b"test" else "bad")
except OSError: print("blocked")
'''
    prefix = ["ip", "netns", "exec", namespace] if namespace else []
    actual = run(prefix + [sys.executable, "-c", code, destination, str(port), source or "none", "udp" if udp else "tcp"]).strip()
    assert actual == ("ok" if expected else "blocked"), (namespace, destination, port, actual, expected)


SERVER = '''import socketserver,sys,threading,time
class TCP(socketserver.BaseRequestHandler):
 def handle(self):
  while True:
   data=self.request.recv(1000)
   if not data: break
   if data==b"push-later":
    self.request.sendall(b"armed");time.sleep(0.6);self.request.sendall(b"push");return
   self.request.sendall(data)
class UDP(socketserver.BaseRequestHandler):
 def handle(self): self.request[1].sendto(self.request[0],self.client_address)
socketserver.ThreadingTCPServer.allow_reuse_address=True
for port in map(int,sys.argv[1].split(",")):
 server=socketserver.ThreadingTCPServer(("0.0.0.0",port),TCP)
 threading.Thread(target=server.serve_forever,daemon=True).start()
if sys.argv[2]!="none":
 server=socketserver.ThreadingUDPServer((sys.argv[3],int(sys.argv[2])),UDP)
 threading.Thread(target=server.serve_forever,daemon=True).start()
print("ready",flush=True)
threading.Event().wait()
'''


def main():
    if not Path("/.dockerenv").exists() or os.environ.get("RABBITWALL_DISPOSABLE_TEST") != "1":
        raise SystemExit("Refusing: requires explicit disposable Docker test environment")
    if Path("/sys/class/net/eth0").exists():
        raise SystemExit("Refusing: run with --network none, never on production RABBITWALL")
    children = []
    for namespace, iface, peer, local, remote in [
        ("ai", "eth1", "ai-side", "10.1.0.1/24", "10.1.0.10/24"),
        ("upstream", "eth0", "up-side", "10.2.0.2/30", "10.2.0.1/30")]:
        ip("netns", "add", namespace)
        ip("link", "add", iface, "type", "veth", "peer", "name", peer)
        ip("link", "set", peer, "netns", namespace)
        ip("addr", "add", local, "dev", iface)
        ip("link", "set", iface, "up")
        ip("-n", namespace, "addr", "add", remote, "dev", peer)
        ip("-n", namespace, "link", "set", peer, "up")
        ip("-n", namespace, "link", "set", "lo", "up")
    ip("-n", "ai", "route", "add", "default", "via", "10.1.0.1")
    ip("-n", "upstream", "route", "add", "10.1.0.0/24", "via", "10.2.0.2")
    ip("route", "add", "default", "via", "10.2.0.1")
    for address in ("1.1.1.1/32", "10.0.0.9/32", "10.0.0.254/32"):
        ip("-n", "upstream", "addr", "add", address, "dev", "lo")
    from firewall import baseline, gate, dns_rule, probe_rules
    from settings import SETTINGS
    script=baseline(SETTINGS).replace('include "/etc/nftables.d/rabbitwall.nft"', gate(SETTINGS)+dns_rule(SETTINGS)+probe_rules(SETTINGS))
    control.nft(['-f','-'],script)
    controller = control.Controller()
    from dns_drops import Observer
    observer = Observer().start()
    try:
        deadline=time.monotonic()+5
        while observer.snapshot()[1] is not None and time.monotonic()<deadline: time.sleep(.05)
        assert observer.snapshot()[1] is None,observer.snapshot()[1]
        def query_dns(destination):
            run(['ip','netns','exec','ai',sys.executable,'-c',
                 "import socket,dns.message; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(dns.message.make_query('blocked.example','AAAA').to_wire(),('"+destination+"',53))"])
            deadline=time.monotonic()+2
            while time.monotonic()<deadline:
                entries=observer.snapshot()[0]
                if any(entry['dst']==destination and entry['dns_questions']==[{'name':'blocked.example.','type':'AAAA'}] for entry in entries): return
                time.sleep(.02)
            raise AssertionError(('DNS question not captured',entries,observer.snapshot()[1]))
        query_dns('10.1.0.1')
        client('ai','10.1.0.1',53,expected=False)
        assert all(entry['proto']=='UDP' for entry in observer.snapshot()[0])
        print('PASS: closed DNS stays blocked and NFLOG captures UDP questions only; TCP stays blocked',flush=True)
        for namespace, ports, udp in [("upstream", "443,53", "53"), ("ai", "22,443", "none"), (None, "22,53", "53")]:
            prefix = ["ip", "netns", "exec", namespace] if namespace else []
            child = subprocess.Popen(prefix + [sys.executable, "-u", "-c", SERVER, ports, udp, "10.0.0.254" if namespace == "upstream" else "10.1.0.1"], stdout=subprocess.PIPE, text=True)
            children.append(child)
            assert child.stdout.readline().strip() == "ready"
        local_echo = child
        assert not controller.status()["enabled"]
        client("ai", "1.1.1.1", 443, expected=False)
        client("ai", "10.0.0.254", 53, expected=False, udp=True)
        client("upstream", "10.1.0.10", 22, source="10.0.0.9")
        client("upstream", "10.2.0.2", 22, source="10.0.0.9")
        client(None, "1.1.1.1", 443)  # RABBITWALL updates stay available while AI is OFF.
        nodes = control.probe_nodes()
        assert all(node["state"] == "up" for node in nodes), nodes
        client("ai", "10.1.0.1", 53, expected=False)
        client("ai", "10.1.0.1", 53, expected=False, udp=True)
        client(None, "10.0.0.254", 53, source="10.1.0.1", expected=False)
        client(None, "10.0.0.254", 53, source="10.1.0.1", expected=False, udp=True)
        client(None, "10.0.0.254", 53)  # RabbitWall OS DNS still works.
        print("PASS: boot OFF, DNS blocked, management SSH and health preserved, RABBITWALL online", flush=True)
        from firewall import node_rule_batch
        https_config = copy.deepcopy(SETTINGS)
        for node in https_config['nodes']:
            if node['interface'] == https_config['ai_if']:
                node.update(allow_https=True,allow_ssh=False,allow_ping=False,monitor=False)
        client('upstream','10.1.0.10',443,source='10.0.0.9',expected=False)
        control.nft(['-f','-'],node_rule_batch(https_config,control.baseline()))
        client('upstream','10.1.0.10',443,source='10.0.0.9')
        client('upstream','10.1.0.10',443,source='10.0.0.254',expected=False)
        client('upstream','10.1.0.10',22,source='10.0.0.9',expected=False)
        assert not controller.status()['enabled']
        https_code = """import socket,sys
s=socket.socket();s.settimeout(.7);s.bind(("10.0.0.9",0));s.connect(("10.1.0.10",443))
print("ready",flush=True)
for line in sys.stdin:
 try:
  s.sendall(b"test");print("ok" if s.recv(100)==b"test" else "bad",flush=True)
 except OSError: print("blocked",flush=True)
"""
        https_process=subprocess.Popen(['ip','netns','exec','upstream',sys.executable,'-u','-c',https_code],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
        children.append(https_process)
        assert https_process.stdout.readline().strip()=='ready'
        control.nft(['-f','-'],node_rule_batch(SETTINGS,control.baseline()))
        https_process.stdin.write('send\n');https_process.stdin.flush()
        assert https_process.stdout.readline().strip()=='blocked'
        client('upstream','10.1.0.10',443,source='10.0.0.9',expected=False)
        print('PASS: opt-in TCP 443 works while closed, excludes other sources/SSH and revokes established access',flush=True)

        controller.set_enabled(True)
        query_dns('8.8.8.8')
        assert any(entry['dns_reason']=='direct-dns' for entry in observer.snapshot()[0])
        observer.close()
        client("ai", "1.1.1.1", 443)
        client("ai", "10.0.0.254", 53, expected=False)
        client("ai", "10.0.0.254", 53, udp=True, expected=False)
        client("ai", "10.1.0.1", 53)
        client("ai", "10.1.0.1", 53, udp=True)
        client(None, "10.0.0.254", 53, source="10.1.0.1")
        client(None, "10.0.0.254", 53, source="10.1.0.1", udp=True)
        client("ai", "10.0.0.9", 443, expected=False)  # ON never widens existing LAN restrictions.
        print("PASS: ON permits local DNS and relay upstream, direct DNS bypass blocked", flush=True)
        # Live node edits must not recreate/close the Internet gate.
        import node_config
        ip('-n','ai','addr','add','10.1.0.11/24','dev','ai-side')
        management_code = '''import socket,sys
s=socket.socket();s.settimeout(.7);s.bind(("10.0.0.9",0));s.connect(("10.1.0.10",22))
print("ready",flush=True)
for line in sys.stdin:
 try:
  s.sendall(b"test");print("ok" if s.recv(100)==b"test" else "bad",flush=True)
 except OSError: print("blocked",flush=True)
'''
        management = subprocess.Popen(['ip','netns','exec','upstream',sys.executable,'-u','-c',management_code],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
        children.append(management)
        assert management.stdout.readline().strip()=='ready'
        management.stdin.write('send\n');management.stdin.flush();assert management.stdout.readline().strip()=='ok'
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);original=copy.deepcopy(SETTINGS);edited=copy.deepcopy(original)
            for node in edited['nodes']:
                if node['interface']==edited['ai_if']: node.update(monitor=False,allow_ssh=False,allow_ping=False)
            edited['nodes'].append({'id':'second-ai','label':'Second AI','ip':'10.1.0.11','interface':'eth1','monitor':False,'allow_ssh':False,'allow_ping':True})
            gate_handle=controller.handle
            def save_nodes(current, nodes):
                result=node_config.save(current,{'nodes':node_config.document(dict(current,nodes=nodes))['nodes'],'revision':node_config.revision(current)},control.nft,control.baseline,root/'nodes.json',root/'rabbitwall.nft')
                assert controller.status()['enabled'] and controller.handle==gate_handle
                controller.tick()
                return result
            edited=save_nodes(original,edited['nodes'])
            management.stdin.write('send\n');management.stdin.flush();assert management.stdout.readline().strip()=='blocked'
            client('upstream','10.1.0.10',22,source='10.0.0.9',expected=False)
            client('upstream','10.1.0.11',22,source='10.0.0.9',expected=False)
            ping=['ip','netns','exec','upstream','ping','-n','-c','1','-W','1','-I','10.0.0.9']
            assert subprocess.run(ping+['10.1.0.11'],capture_output=True).returncode==0
            assert subprocess.run(ping+['10.1.0.10'],capture_output=True).returncode!=0
            probes=control.probe_nodes(config=edited)
            assert all(node['state']=='disabled' for node in probes if node['id'] in ('ai-host','second-ai'))
            edited['nodes'][-1]['allow_ssh']=True
            edited['nodes'][-1]['allow_https']=True
            # Use the revision of the unmodified saved document.
            import json
            current=dict(edited,nodes=json.loads((root/'nodes.json').read_text())['nodes'])
            edited=save_nodes(current,edited['nodes'])
            client('upstream','10.1.0.11',22,source='10.0.0.9')
            client('upstream','10.1.0.11',443,source='10.0.0.9')
            client('upstream','10.1.0.10',443,source='10.0.0.9',expected=False)
            assert 'ip daddr 10.1.0.11 tcp dport 443' in (root/'rabbitwall.nft').read_text()
            client('ai','1.1.1.1',443)
            client('ai','10.1.0.1',53,udp=True)
            save_nodes(edited,original['nodes'])
            persisted=(root/'rabbitwall.nft').read_text()
        print('PASS: live multi-node edits preserve ON/DNS, independently grant SSH/Ping, revoke established SSH and disable probes',flush=True)
        held_code = '''import socket,sys
s=socket.create_connection(("1.1.1.1",443),timeout=0.7)
print("ready",flush=True)
for line in sys.stdin:
 try:
  s.sendall(b"test");print("ok" if s.recv(100)==b"test" else "bad",flush=True)
 except OSError: print("blocked",flush=True)
'''
        held = subprocess.Popen(["ip", "netns", "exec", "ai", sys.executable, "-u", "-c", held_code],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        children.append(held)
        assert held.stdout.readline().strip() == "ready"
        held.stdin.write("send\n"); held.stdin.flush()
        assert held.stdout.readline().strip() == "ok"
        controller.set_enabled(False)
        held.stdin.write("send\n"); held.stdin.flush()
        assert held.stdout.readline().strip() == "blocked"
        client("upstream", "10.1.0.10", 22, source="10.0.0.9")
        controller.set_enabled(True)
        push_code = '''import socket,sys
s=socket.create_connection(("1.1.1.1",443),timeout=1.2)
s.sendall(b"push-later");assert s.recv(5)==b"armed";print("ready",flush=True)
sys.stdin.readline()
try: print("leaked" if s.recv(100) else "closed",flush=True)
except OSError: print("blocked",flush=True)
'''
        push = subprocess.Popen(["ip", "netns", "exec", "ai", sys.executable, "-u", "-c", push_code], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        children.append(push)
        assert push.stdout.readline().strip() == "ready"
        controller.set_enabled(False)
        push.stdin.write("receive\n"); push.stdin.flush()
        assert push.stdout.readline().strip() == "blocked"
        controller.set_enabled(True)
        dns_held = subprocess.Popen(["ip", "netns", "exec", "ai", sys.executable, "-u", "-c",
                                     held_code.replace('("1.1.1.1",443)', '("10.1.0.1",53)')],
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        children.append(dns_held)
        assert dns_held.stdout.readline().strip() == "ready"
        dns_held.stdin.write("send\n"); dns_held.stdin.flush()
        assert dns_held.stdout.readline().strip() == "ok"
        controller.set_enabled(False)
        dns_held.stdin.write("send\n"); dns_held.stdin.flush()
        assert dns_held.stdout.readline().strip() == "blocked"
        client("ai", "10.1.0.1", 53, expected=False, udp=True)
        client(None, "10.0.0.254", 53, source="10.1.0.1", expected=False)
        # A DNS response already scheduled by the server must not escape OFF.
        controller.set_enabled(True)
        dns_push = subprocess.Popen(["ip", "netns", "exec", "ai", sys.executable, "-u", "-c",
                                     push_code.replace('("1.1.1.1",443)', '("10.1.0.1",53)')],
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        children.append(dns_push)
        assert dns_push.stdout.readline().strip() == "ready"
        controller.set_enabled(False)
        dns_push.stdin.write("receive\n"); dns_push.stdin.flush()
        assert dns_push.stdout.readline().strip() == "blocked"
        print("PASS: OFF blocks established TCP/local DNS, relay upstream and in-flight DNS replies", flush=True)
        controller.set_enabled(True, 60)
        assert 0 < controller.status()['remaining_seconds'] <= 60
        # Shorten the deadline to exercise real kernel expiry without a minute's wait.
        controller.deadline = time.monotonic() + 0.3
        controller.tick()
        time.sleep(0.5)
        assert not control.read_gate()['enabled']
        client('ai', '1.1.1.1', 443, expected=False)
        client('ai', '10.1.0.1', 53, expected=False, udp=True)
        controller.tick()
        assert not controller.desired and controller.deadline is None
        print('PASS: timed access expires in the kernel without another controller tick', flush=True)
        controller.set_enabled(True)
        control.nft(["-f", "-"], "flush set inet rabbitwall_console online_sources\nadd element inet rabbitwall_console online_sources { 10.1.0.0/24 timeout 1s }\n")
        time.sleep(1.3)
        assert not controller.status()["enabled"]
        client("ai", "10.1.0.1", 53, expected=False)
        client("ai", "10.1.0.1", 53, expected=False, udp=True)
        controller.tick()
        assert not controller.desired
        client("ai", "1.1.1.1", 443, expected=False)
        controller.set_enabled(True)
        control.install_runtime()
        assert not controller.status()["enabled"] and not controller.desired
        control.nft(['-f','-'],baseline(SETTINGS).replace('include "/etc/nftables.d/rabbitwall.nft"',persisted))
        assert not control.read_gate()['enabled']
        client('upstream','10.1.0.10',22,source='10.0.0.9')
        print("PASS: kernel lease expiry and controller/table restart default OFF", flush=True)
        # Exercise the actual root controller socket and durable node storage.
        Path('/etc/rabbitwall').mkdir(exist_ok=True)
        Path('/etc/rabbitwall-nodes').mkdir(mode=0o755,exist_ok=True)
        Path('/etc/nftables.d').mkdir(exist_ok=True)
        Path('/etc/nftables.d/rabbitwall.nft').write_text(persisted)
        def start_controller():
            process=subprocess.Popen([sys.executable,'-B',ROOT/'src/rabbitwall/control.py','run'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            children.append(process)
            deadline=time.monotonic()+5
            while not control.SOCKET.exists():
                assert process.poll() is None,process.stderr.read()
                assert time.monotonic()<deadline
                time.sleep(.02)
            return process
        # The controller clears any RPZ left in a surviving Unbound before
        # opening. Replace the earlier echo fixture with the real DNS service
        # for this end-to-end socket test, just as an installed host provides.
        local_echo.terminate();local_echo.wait(timeout=3)
        from unbound_config import POLICY_FILE, CONFIG_PATH, render
        POLICY_FILE.parent.mkdir(parents=True,exist_ok=True);POLICY_FILE.write_text('')
        Path('/run/rabbitwall-dns').mkdir(exist_ok=True)
        CONFIG_PATH.write_text(render(SETTINGS))
        dns_process=subprocess.Popen(['unbound','-d','-c',str(CONFIG_PATH)],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
        children.append(dns_process)
        deadline=time.monotonic()+5
        while not Path('/run/rabbitwall-dns/control.sock').exists():
            assert dns_process.poll() is None,dns_process.stderr.read()
            assert time.monotonic()<deadline,'Unbound control socket did not start'
            time.sleep(.02)
        process=start_controller()
        doc=control.request_control('nodes')
        timed = control.request_control('enable', payload=60)
        assert timed['enabled'] and 0 < timed['remaining_seconds'] <= 60
        try:
            control.request_control('enable', payload=True)
        except ValueError: pass
        else: raise AssertionError('Socket accepted an invalid duration')
        control.request_control('enable')
        saved=control.request_control('save_nodes',payload={'nodes':[],'revision':doc['revision']})
        assert saved['nodes']==[] and control.request_control('status')['enabled']
        assert control.request_control('status')['nodes'][0]['id']=='rabbitwall'
        try:
            control.request_control('save_nodes',payload={'nodes':doc['nodes'],'revision':doc['revision']})
        except node_config.RevisionConflict: pass
        else: raise AssertionError('Socket accepted a stale revision')
        assert Path('/etc/rabbitwall-nodes/nodes.json').is_file()
        # Ordinary CLI plan/inspect users must be able to load non-secret metadata.
        subprocess.run([sys.executable,'-B','-c',
            "import sys;sys.path.insert(0,sys.argv[1]);import settings;assert settings.load()['nodes']==[]",
            str(ROOT/'src/rabbitwall')],user='nobody',group='nogroup',check=True)
        process.terminate();process.wait(timeout=3)
        process=start_controller()
        assert control.request_control('nodes')['nodes']==[]
        assert not control.request_control('status')['enabled']
        print('PASS: actual controller socket saves/loads nodes, rejects stale writes, preserves ON on save and retains settings across restart',flush=True)
    finally:
        observer.close()
        for child in children:
            child.terminate()
        for child in children:
            child.wait(timeout=3)


if __name__ == "__main__":
    main()
