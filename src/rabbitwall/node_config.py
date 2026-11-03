"""Validated node-only configuration, independent of network installation settings."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time

from settings import validate, NODES_CONFIG
from firewall import persistent_rules, node_rule_batch

SNIPPET = Path('/etc/nftables.d/rabbitwall.nft')


class RevisionConflict(ValueError):
    pass


def revision(config):
    return hashlib.sha256(json.dumps(config, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def document(config):
    nodes = copy.deepcopy(config['nodes'])
    for node in nodes:
        node.setdefault('allow_https', False)
        node.setdefault('monitor', True)
        node.setdefault('allow_ssh', node['interface'] == config['ai_if'])
        node.setdefault('allow_ping', node['interface'] == config['ai_if'])
    return {'nodes': nodes, 'revision': revision(config),
            'interfaces': [{'name':config['ai_if'], 'side':'AI', 'cidr':config['ai_cidr']},
                           {'name':config['uplink_if'], 'side':'UPLINK', 'cidr':config['uplink_cidr']}]}


def candidate(config, payload):
    if not isinstance(payload, dict) or set(payload) != {'nodes', 'revision'}:
        raise ValueError('nodes and revision are required')
    if payload['revision'] != revision(config):
        raise RevisionConflict('Node settings changed; reload before saving')
    required = {'id','label','ip','interface','monitor','allow_ssh','allow_ping','allow_https'}
    if not isinstance(payload['nodes'], list) or any(not isinstance(node, dict) or set(node) != required for node in payload['nodes']):
        raise ValueError('Each saved node needs explicit monitoring, SSH, HTTPS and Ping permissions')
    result = copy.deepcopy(config)
    result['nodes'] = payload['nodes']
    result = validate(result)
    # Store explicit choices so monitoring never silently grants management access.
    result['nodes'] = document(result)['nodes']
    return result


def atomic_write(path, content, mode=0o644):
    path = Path(path)
    descriptor, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as output:
            os.fchmod(output.fileno(), mode)
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)


def save(config, payload, nft, objects, node_path=NODES_CONFIG, snippet_path=SNIPPET):
    """Apply only node chains; roll back both files and rules on write failure."""
    updated = candidate(config, payload)
    node_path, snippet_path = Path(node_path), Path(snippet_path)
    batch = node_rule_batch(updated, objects())
    nft(['-c','-f','-'], batch)
    previous = {path: path.read_bytes() if path.exists() else None
                for path in (node_path, snippet_path)}
    backup = node_path.parent / 'node-backups' / str(time.time_ns())
    backup.mkdir(parents=True, mode=0o700)
    atomic_write(backup/'config.json', json.dumps(config, ensure_ascii=False, indent=2).encode(), 0o600)
    for index, (path, content) in enumerate(previous.items()):
        if content is not None: atomic_write(backup/f'{index}-{path.name}', content, 0o600)
    nft(['-f','-'], batch)
    try:
        atomic_write(node_path, (json.dumps({'nodes':updated['nodes']}, ensure_ascii=False, indent=2)+'\n').encode())
        atomic_write(snippet_path, persistent_rules(updated).encode())
    except Exception:
        # Even if restoring a file fails, still attempt to undo live permissions.
        failures = []
        for path, content in previous.items():
            try:
                if content is None: path.unlink(missing_ok=True)
                else: atomic_write(path, content)
            except Exception as error: failures.append(error)
        try: nft(['-f','-'], node_rule_batch(config, objects()))
        except Exception as error: failures.append(error)
        if failures:
            raise RuntimeError('Node rollback failed; inspect saved node backups and firewall') from failures[0]
        raise
    return updated
