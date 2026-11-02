"""Install the complete application after network setup, with the gate closed."""
import datetime as dt
import grp
import os
from pathlib import Path
import pwd
import shutil
import socket
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SERVICES = ('rabbitwall-control', 'rabbitwall-dns', 'rabbitwall-dns-observer', 'rabbitwall-collector', 'rabbitwall-web')


def run(*args):
    return subprocess.run(list(map(str, args)), check=True)


def close_installed():
    """Use the old code before replacing files; never restore the previous ON state."""
    if Path('/opt/rabbitwall/control.py').exists():
        run('/usr/bin/python3', '-B', '/opt/rabbitwall/control.py', 'off')


def deployment_files():
    targets = {Path('/opt/rabbitwall') / p.relative_to(ROOT/'src/rabbitwall'): p
               for p in (ROOT/'src/rabbitwall').rglob('*')
               if p.is_file() and '__pycache__' not in p.parts and p.suffix in ('.py', '.html', '.js', '.json', '.css', '.md')}
    targets[Path('/opt/rabbitwall/update_geoip.py')] = ROOT/'tools/update_geoip.py'
    for p in (ROOT/'systemd').rglob('*'):
        if p.is_file() and 'caddy' not in p.name:
            targets[Path('/etc/systemd/system')/p.relative_to(ROOT/'systemd')] = p
    return targets


def deploy(config):
    if os.geteuid() != 0:
        raise ValueError('Run setup.py install/update as root')
    sys.path.insert(0, str(ROOT/'src/rabbitwall'))
    from dependencies import require_observer, require_drop_dns
    from unbound_config import render, check_config, require_unbound, CONFIG_PATH, POLICY_FILE
    require_observer()
    require_drop_dns()
    require_unbound()
    unbound_text = render(config)
    check_config(unbound_text)
    targets = deployment_files()
    # Validate the entire source set before closing services.
    for source in targets.values():
        if source.suffix == '.py':
            compile(source.read_bytes(), str(source), 'exec')
    caddy_installed = Path('/etc/systemd/system/rabbitwall-caddy.service').is_file()
    restore_caddy = caddy_installed and (
        subprocess.run(['systemctl','is-active','--quiet','rabbitwall-caddy'], capture_output=True).returncode == 0
        or subprocess.run(['systemctl','is-enabled','--quiet','rabbitwall-caddy'], capture_output=True).returncode == 0)
    close_installed()
    # Stop the controller too, so concurrent UI requests cannot reopen during update.
    # Nonexistent units are expected during the initial installation.
    for service in SERVICES:
        result = subprocess.run(['systemctl', 'show', '-p', 'LoadState', '--value', service],
                                check=True, capture_output=True, text=True)
        if result.stdout.strip() != 'not-found':
            run('systemctl', 'stop', service)
    # A stopped controller's lease must also be cleared if a UI request raced off.
    if Path('/opt/rabbitwall/control.py').exists():
        run('/usr/bin/python3', '-B', '/opt/rabbitwall/control.py', 'off')
    address = str(__import__('ipaddress').IPv4Interface(config['ai_cidr']).ip)
    for kind in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
        try:
            with socket.socket(socket.AF_INET, kind) as sock:
                sock.bind((address, 53))
        except OSError as error:
            raise ValueError(f'DNS cannot bind {address}:53: {error}. Gate remains closed; inspect ip -br -4 addr and sudo ss -luntp.') from error
    backup = Path('/var/backups/rabbitwall') / ('application-' + dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
    backup.mkdir(parents=True, mode=0o700)
    saved = list(targets) + [CONFIG_PATH, Path('/etc/nftables.conf'), Path('/etc/nftables.d/rabbitwall.nft'), Path('/etc/rabbitwall.json'), Path('/etc/rabbitwall-nodes/nodes.json')]
    for target in saved:
        if target.is_file():
            destination = backup / str(target).lstrip('/')
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.copy2(target, destination)
    print(f'Application backup: {backup}', flush=True)
    for group in ('rabbitwall-control', 'rabbitwall-dns', 'rabbitwall-read'):
        try: grp.getgrnam(group)
        except KeyError: run('groupadd', '--system', group)
    try: pwd.getpwnam('rabbitwall-dns')
    except KeyError:
        run('useradd', '--system', '--gid', 'rabbitwall-dns', '--no-create-home',
            '--shell', '/usr/sbin/nologin', 'rabbitwall-dns')
    state = Path('/var/lib/rabbitwall')
    state.mkdir(parents=True, exist_ok=True)
    os.chown(state, 0, grp.getgrnam('rabbitwall-read').gr_gid)
    state.chmod(0o750)
    for target, source in targets.items():
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        shutil.copyfile(source, target)
        target.chmod(0o644)
    POLICY_FILE.parent.mkdir(parents=True, exist_ok=True)
    os.chown(POLICY_FILE.parent,0,grp.getgrnam('rabbitwall-dns').gr_gid)
    POLICY_FILE.parent.chmod(0o2750)
    POLICY_FILE.write_text('')
    os.chown(POLICY_FILE,0,grp.getgrnam('rabbitwall-dns').gr_gid)
    POLICY_FILE.chmod(0o640)
    CONFIG_PATH.write_text(unbound_text)
    CONFIG_PATH.chmod(0o644)
    run('/usr/bin/python3', '-B', '/opt/rabbitwall/control.py', 'install')
    run('systemctl', 'daemon-reload')
    run('systemctl', 'enable', *SERVICES)
    for service in SERVICES:
        run('systemctl', 'restart', service)
        run('systemctl', 'is-active', '--quiet', service)
    if restore_caddy:
        run('systemctl', 'restart', 'rabbitwall-caddy')
        run('systemctl', 'is-active', '--quiet', 'rabbitwall-caddy')
    print('Application and DNS installed. Internet gate is CLOSED.')
