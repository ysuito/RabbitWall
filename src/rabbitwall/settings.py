"""Validated installation settings shared by collection, DNS, firewall and UI."""
import copy
import ipaddress
import json
import os
from pathlib import Path
import re

CONFIG = Path('/etc/rabbitwall.json')
NODES_CONFIG = Path('/etc/rabbitwall-nodes/nodes.json')
DEFAULTS = {'schema_version': 1,
 'label': 'RabbitWall',
 'uplink_if': 'eth0',
 'uplink_cidr': '192.168.10.2/24',
 'gateway': '192.168.10.1',
 'management_cidr': '192.168.10.0/24',
 'admin_ip': '192.168.10.10',
 'ai_if': 'eth1',
 'ai_cidr': '192.168.20.1/24',
 'dns_upstream': '192.168.10.1',
 'nat': True,
 'console_name': 'rabbitwall.home.arpa',
 'site_label': 'LAN拠点',
 'site_location': [139, 36],
 'nodes': [{'id': 'gateway', 'label': 'Gateway', 'ip': '192.168.10.1', 'interface': 'eth0', 'monitor': True, 'allow_ssh': False, 'allow_ping': False, 'allow_https': False},
           {'id': 'ai-host', 'label': 'AI Host', 'ip': '192.168.20.10', 'interface': 'eth1', 'monitor': True, 'allow_ssh': True, 'allow_ping': True, 'allow_https': False}]}


def interface(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,14}', value) or value == 'lo':
        raise ValueError(f'Invalid dedicated interface: {value!r}')
    return value


def validate(data):
    if not isinstance(data, dict) or set(data) != set(DEFAULTS):
        raise ValueError('Required configuration keys: ' + ', '.join(sorted(DEFAULTS)))
    result = copy.deepcopy(data)
    if type(data['schema_version']) is not int or data['schema_version'] != 1:
        raise ValueError('Unsupported schema_version (expected 1)')
    up = ipaddress.IPv4Interface(data['uplink_cidr']); ai = ipaddress.IPv4Interface(data['ai_cidr'])
    lan = ipaddress.IPv4Network(data['management_cidr'])
    if up.network.overlaps(ai.network) or lan.overlaps(ai.network):
        raise ValueError('AI subnet must not overlap uplink or management subnet')
    def usable(value, network):
        address = ipaddress.IPv4Address(value)
        if address not in network or address in (network.network_address, network.broadcast_address):
            raise ValueError(f'{address} is not a usable host in {network}')
        return str(address)
    result['uplink_cidr'], result['ai_cidr'], result['management_cidr'] = str(up), str(ai), str(lan)
    result['gateway'] = usable(data['gateway'], up.network)
    result['admin_ip'] = usable(data['admin_ip'], lan)
    usable(str(up.ip), up.network); usable(str(ai.ip), ai.network)
    if up.ip == ipaddress.IPv4Address(result['gateway']) or result['admin_ip'] in (str(up.ip), result['gateway'], str(data['dns_upstream'])):
        raise ValueError('Console, gateway and management PC addresses must differ')
    dns = ipaddress.IPv4Address(data['dns_upstream'])
    if dns.is_unspecified or dns.is_multicast or dns.is_loopback or dns in ai.network or dns == up.ip:
        raise ValueError('DNS upstream must be a reachable IPv4 address outside the AI subnet and this host')
    result['dns_upstream'] = str(dns)
    for key in ('uplink_if', 'ai_if'): result[key] = interface(data[key])
    if result['uplink_if'] == result['ai_if']: raise ValueError('Use two different interfaces')
    if type(data['nat']) is not bool: raise ValueError('nat must be true or false')
    host = data['console_name']
    if not isinstance(host, str) or len(host) > 253 or len(host.split('.')) < 3 or not host.endswith('.home.arpa') or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part) for part in host.split('.')):
        raise ValueError('console_name must be a lowercase hostname below home.arpa')
    for key in ('label', 'site_label'):
        if not isinstance(data[key], str) or not 1 <= len(data[key]) <= 48 or any(ord(c) < 32 for c in data[key]):
            raise ValueError(f'{key} must contain 1–48 printable characters')
    point = data['site_location']
    if not isinstance(point, list) or len(point) != 2 or any(type(x) not in (int, float) for x in point) or not -180 <= point[0] <= 180 or not -85 <= point[1] <= 85:
        raise ValueError('site_location must be [longitude, latitude]')
    if not isinstance(data['nodes'], list) or not 0 <= len(data['nodes']) <= 12:
        raise ValueError('Configure 0–12 nodes')
    ids, addresses = {'rabbitwall', 'admin'}, {str(up.ip), str(ai.ip), result['admin_ip']}
    for node in data['nodes']:
        if not isinstance(node, dict) or not {'id', 'label', 'ip', 'interface'} <= set(node) or set(node) - {'id', 'label', 'ip', 'interface', 'monitor', 'allow_ssh', 'allow_ping', 'allow_https'}:
            raise ValueError('Each node requires id, label, ip and interface')
        if not isinstance(node['id'], str) or not re.fullmatch(r'[a-z][a-z0-9_-]{0,31}', node['id']) or node['id'] in ids:
            raise ValueError('Node ids must be unique; rabbitwall and admin are reserved')
        if not isinstance(node['label'], str) or not 1 <= len(node['label']) <= 32 or any(ord(c) < 32 for c in node['label']):
            raise ValueError('Invalid node label')
        address = ipaddress.IPv4Address(node['ip'])
        if str(address) in addresses: raise ValueError('Node IPs must be unique')
        if node['interface'] not in (data['ai_if'], data['uplink_if']): raise ValueError('Node interface must match uplink_if or ai_if')
        for flag in ('monitor', 'allow_ssh', 'allow_ping', 'allow_https'):
            default = True if flag == 'monitor' else flag != 'allow_https' and node['interface'] == data['ai_if']
            if type(node.get(flag, default)) is not bool: raise ValueError(f'{flag} must be boolean')
            # Optional fields preserve the behavior of existing JSON configurations.
        if node['interface'] == data['uplink_if'] and (node.get('allow_ssh', False) or node.get('allow_ping', False) or node.get('allow_https', False)):
            raise ValueError('Management access applies only to AI-side nodes')
        node['ip'] = str(address)
        usable(node['ip'], ai.network if node['interface'] == data['ai_if'] else up.network)
        ids.add(node['id']); addresses.add(str(address))
    return result


def load(path=None):
    selected = Path(path or os.environ.get('RABBITWALL_CONFIG', CONFIG))
    if path is None and 'RABBITWALL_CONFIG' not in os.environ and not selected.exists():
        return validate(DEFAULTS)
    data = json.loads(selected.read_text())
    if path is None and NODES_CONFIG.exists():
        override = json.loads(NODES_CONFIG.read_text())
        if not isinstance(override, dict) or set(override) != {'nodes'}:
            raise ValueError('Invalid saved node configuration')
        data['nodes'] = override['nodes']
    return validate(data)


SETTINGS = load()
AI_INTERFACE = ipaddress.IPv4Interface(SETTINGS['ai_cidr'])
UPLINK_INTERFACE = ipaddress.IPv4Interface(SETTINGS['uplink_cidr'])
AI_IP, UPLINK_IP = str(AI_INTERFACE.ip), str(UPLINK_INTERFACE.ip)


def monitored(node):
    return node.get('monitor', True)


def management_allowed(node, kind, config=SETTINGS):
    return node['interface'] == config['ai_if'] and node.get('allow_' + kind, kind != 'https')


def metadata(config=SETTINGS):
    ai = str(ipaddress.IPv4Interface(config['ai_cidr']).ip)
    up = str(ipaddress.IPv4Interface(config['uplink_cidr']).ip)
    hosts = [{'label': '管理PC', 'glyph': '管', 'ip': config['admin_ip'], 'ips': [config['admin_ip']]},
             {'label': config['label'], 'glyph': '継', 'ip': up, 'secondaryIP': ai, 'ips': [up, ai]}]
    hosts += [{'label': node['label'], 'glyph': '端', 'ip': node['ip'], 'ips': [node['ip']]} for node in config['nodes']]
    return {'label': config['label'], 'local_ips': [up, ai], 'hosts': hosts,
            'site_label': config['site_label'], 'site_location': config['site_location']}


def require_config():
    path = Path(os.environ.get('RABBITWALL_CONFIG', CONFIG))
    if not path.is_file():
        raise ValueError(f'RabbitWall configuration not found: {path}; run setup.py init and install first')
