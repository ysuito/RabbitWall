"""Exact-QNAME RPZ policies, scoped to approved clients by Unbound tags."""
from pathlib import Path
import subprocess
import time
from node_config import atomic_write
from unbound_config import CONFIG_PATH, POLICY_FILE


def rpz_zone(domains):
    entries = {'*':'.'}
    # RPZ wildcard matching observes empty ancestor nodes: deny each ancestor
    # and its wildcard explicitly, then override only the approved exact names.
    for domain in domains:
        labels = domain.split('.')
        for index in range(len(labels)):
            ancestor = '.'.join(labels[index:])
            entries[ancestor] = '.'
            entries['*.'+ancestor] = '.'
    for domain in domains: entries[domain] = 'rpz-passthru.'
    return ('$TTL 60\n@ SOA localhost. root.localhost. 1 60 60 60 60\n@ NS localhost.\n' +
            ''.join(f'{name} CNAME {target}\n' for name,target in sorted(entries.items())))


class DNSGuard:
    def __init__(self, config_path=CONFIG_PATH, policy_file=POLICY_FILE):
        self.config_path = Path(config_path)
        self.policy_file = Path(policy_file)

    def command(self, *args):
        result = subprocess.run(['unbound-control','-c',str(self.config_path),*args],capture_output=True,text=True,timeout=3)
        if result.returncode: raise RuntimeError('DNS policy: '+(result.stderr or result.stdout).strip()[:300])
        return result.stdout

    def reset(self):
        if not self.policy_file.parent.is_dir():
            raise RuntimeError('Domain approval support is not installed; run setup.py update')
        atomic_write(self.policy_file,b'',0o640)
        for path in self.policy_file.parent.glob('rw-*.zone'): path.unlink()

    def apply(self, grants):
        if not self.policy_file.exists(): raise RuntimeError('Run setup.py update to install DNS policy support')
        previous = self.policy_file.read_bytes()
        lines, zones = [], set()
        if grants:
            lines = ['server:', '    define-tag: "'+' '.join('rw'+str(i) for i in range(len(grants)))+'"']
            for index, grant in enumerate(grants):
                lines.append(f'    access-control-tag: {grant["source"]}/32 "rw{index}"')
            for index, grant in enumerate(grants):
                name = 'rw-'+grant['id']+'.invalid.'
                zone = self.policy_file.parent/('rw-'+grant['id']+'.zone')
                atomic_write(zone, ('$ORIGIN '+name+'\n'+rpz_zone(grant['domains'])).encode(),0o640)
                zones.add(name)
                lines.extend(['rpz:',f'    name: "{name}"', f'    zonefile: "{zone}"',f'    tags: "rw{index}"'])
        try:
            atomic_write(self.policy_file, ('\n'.join(lines)+'\n').encode(),0o640)
            check = subprocess.run(['unbound-checkconf',str(self.config_path)],capture_output=True,text=True,timeout=5)
            if check.returncode: raise RuntimeError('Invalid DNS policy: '+(check.stderr or check.stdout)[:300])
            self.command('reload')
            deadline = time.monotonic()+5
            while True:
                try: loaded = {line.split()[0] for line in self.command('list_auth_zones').splitlines() if line.startswith('rw-')}
                except (RuntimeError,OSError,subprocess.TimeoutExpired): loaded = None
                if loaded == zones: break
                if time.monotonic()>=deadline: raise RuntimeError('DNS policy reload did not complete')
                time.sleep(.1)
            self.command('flush_zone','.')
        except Exception:
            atomic_write(self.policy_file, previous,0o640)
            try: self.command('reload')
            except Exception: pass
            raise
        for path in self.policy_file.parent.glob('rw-*.zone'):
            if path.name.removesuffix('.zone')+'.invalid.' not in zones: path.unlink()
