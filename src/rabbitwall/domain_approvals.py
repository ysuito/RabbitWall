"""Human-approved, volatile domain grants. IPv4 address filtering is not TLS-host isolation."""
import concurrent.futures
import datetime as dt
import ipaddress
import re
import secrets
import threading
import time
import audit

from firewall import LEASE, domain_lease_rules
from unbound_guard import DNSGuard

DURATIONS = (60, 300, 1800)
MAX_DOMAINS = 32


def log_end(grant, reason):
    audit.record({'event':'domain-ended', 'reason':reason,
                  **{key:grant[key] for key in ('id','node_id','source','domains','purpose','duration_seconds','expires_at') if key in grant}})


def parse_domains(values):
    if not isinstance(values, list) or not 1 <= len(values) <= MAX_DOMAINS:
        raise ValueError('Specify 1–32 exact domain names')
    result = []
    for value in values:
        if not isinstance(value, str) or len(value) > 254:
            raise ValueError('Invalid domain name')
        try: name = value.strip().rstrip('.').encode('idna').decode('ascii').lower()
        except UnicodeError as error: raise ValueError('Invalid domain name') from error
        labels = name.split('.')
        if (len(name) > 253 or len(labels) < 2
                or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in labels)
                or not re.search('[a-z]', labels[-1])):
            raise ValueError('Use exact domain names, without URLs, IPs, wildcards or ports')
        if name not in result: result.append(name)
    return result


def validate_request(config, payload):
    if not isinstance(payload, dict) or set(payload) != {'node_id','domains','duration_seconds','purpose'}:
        raise ValueError('node_id, domains, duration_seconds and purpose are required')
    node = next((node for node in config['nodes'] if node['id'] == payload['node_id'] and node['interface'] == config['ai_if']), None)
    if node is None: raise ValueError('Select a registered AI-side node')
    duration = payload['duration_seconds']
    if type(duration) is not int or duration not in DURATIONS:
        raise ValueError('Choose 60, 300 or 1800 seconds')
    purpose = payload['purpose']
    if not isinstance(purpose, str) or not 1 <= len(purpose.strip()) <= 200 or any(ord(c)<32 for c in purpose):
        raise ValueError('Specify a purpose, up to 200 characters')
    return {'node_id':node['id'], 'node_name':node['label'], 'source':node['ip'],
            'domains':parse_domains(payload['domains']), 'duration_seconds':duration, 'purpose':purpose.strip()}


def resolve_domains(config, domains, deadline, cancel):
    """Resolve only human-approved names through the configured upstream, never OS search paths."""
    import dns.resolver
    import dns.exception
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [config['dns_upstream']]
    resolver.timeout = 1
    source = str(ipaddress.IPv4Interface(config['uplink_cidr']).ip)
    result = {}
    for name in domains:
        remaining = deadline-time.monotonic()
        if cancel.is_set() or remaining <= 0: break
        try:
            answer = resolver.resolve(name, 'A', source=source, search=False, lifetime=min(2,remaining))
            ttl = min([rr.ttl for rr in answer.response.answer] or [0])
            ips = sorted({str(ipaddress.IPv4Address(item.address)) for item in answer
                          if ipaddress.IPv4Address(item.address).is_global})[:8]
            if not ips or ttl <= 0: raise ValueError('No public IPv4 answer with positive TTL')
            result[name] = {'addresses':ips, 'until':time.monotonic()+min(ttl,3600), 'error':None}
        except (dns.exception.DNSException, OSError, ValueError) as error:
            result[name] = {'addresses':[], 'until':0, 'error':str(error)[:160] or 'DNS resolution failed'}
    return result


class Approvals:
    def __init__(self, nft, guard=None, resolver=resolve_domains):
        self.nft = nft
        self.guard = guard or DNSGuard()
        self.resolver = resolver
        self.grants = {}
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=2, thread_name_prefix='approved-dns')
        self.jobs = {}
        self.policy_dirty = False

    def reset_runtime(self):
        self.guard.reset()
        # Unbound may outlive a controller restart and still have an old RPZ.
        self.policy_dirty = True

    def clear(self, sync=False):
        for grant in self.grants.values():
            grant['cancel'].set()
            log_end(grant, 'cleared')
        self.grants.clear()
        for _, future in self.jobs.values(): future.cancel()
        # Running jobs retain at most one bounded query; their results are discarded.
        if sync and self.policy_dirty:
            self.guard.apply([])
            self.policy_dirty = False

    def close(self):
        self.clear()
        self.executor.shutdown(wait=False, cancel_futures=True)

    def approve(self, config, spec):
        now = time.monotonic()
        grant = dict(spec, id=secrets.token_hex(8), deadline=now+spec['duration_seconds'],
                     expires_at=(dt.datetime.now(dt.timezone.utc)+dt.timedelta(seconds=spec['duration_seconds'])).isoformat(),
                     records={}, next_refresh=now, cancel=threading.Event(), config=config)
        previous = self.grants.get(spec['node_id'])
        planned = [g for key,g in self.grants.items() if key != spec['node_id'] and g['deadline']>now] + [grant]
        self.policy_dirty = True
        self.guard.apply(planned)
        if previous:
            previous['cancel'].set()
            log_end(previous, 'replaced')
        self.grants[spec['node_id']] = grant
        self.tick()

    def revoke(self, grant_id):
        if not isinstance(grant_id, str) or not re.fullmatch('[0-9a-f]{16}',grant_id):
            raise ValueError('Invalid approval id')
        selected = next((g for g in self.grants.values() if g['id']==grant_id),None)
        if selected is None: raise ValueError('Approval no longer exists; refresh')
        selected['cancel'].set()
        del self.grants[selected['node_id']]
        self.guard.apply(list(self.grants.values()))
        self.policy_dirty = bool(self.grants)
        self.tick()

    def expire(self):
        now = time.monotonic()
        for key, grant in list(self.grants.items()):
            if grant['deadline'] <= now:
                grant['cancel'].set()
                del self.grants[key]
                log_end(grant, 'expired')

    def tick(self):
        self.expire()
        now = time.monotonic()
        for key,(grant_id, future) in list(self.jobs.items()):
            if not future.done(): continue
            del self.jobs[key]
            grant = self.grants.get(key)
            if grant is None or grant['id'] != grant_id: continue
            try: records = future.result()
            except Exception: records = {name:{'addresses':[], 'until':0, 'error':'DNS worker failed'} for name in grant['domains']}
            grant['records'] = records
            life = min([record['until']-now for record in records.values() if record['until']>now] or [10])
            grant['next_refresh'] = now+max(.25,min(60,life/2))
        for key, grant in self.grants.items():
            if key not in self.jobs and grant['next_refresh'] <= now:
                future = self.executor.submit(self.resolver, grant['config'], grant['domains'], grant['deadline'], grant['cancel'])
                self.jobs[key] = (grant['id'],future)
        self.nft(['-f','-'], domain_lease_rules(list(self.grants.values()),now))

    def snapshot(self):
        self.expire()
        now = time.monotonic()
        result = []
        for grant in self.grants.values():
            records = []
            for name in grant['domains']:
                record = grant['records'].get(name,{})
                records.append({'domain':name, 'addresses':record.get('addresses',[]) if record.get('until',0)>now else [],
                                'error':record.get('error'), 'resolving':not bool(record)})
            result.append({key:grant[key] for key in ('id','node_id','node_name','source','domains','purpose','duration_seconds','expires_at')} |
                          {'remaining_seconds':max(0,grant['deadline']-now), 'records':records})
        return result
