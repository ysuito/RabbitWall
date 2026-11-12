"""Bounded, volatile requests; only the administrator can turn a request into a grant."""
import datetime as dt
import secrets
import time

from domain_approvals import validate_request

REQUEST_PORT = 8767
REQUEST_SOCKET = '/run/rabbitwall-requests/requests.sock'
PUBLIC_ACTIONS = {'submit_domain_request', 'domain_request_status', 'revoke_domain_request'}
MAX_REQUESTS = 64


class RequestLimit(ValueError):
    pass


class Requests:
    def __init__(self):
        self.items = {}
        self.last_submit = {}

    def prune(self):
        now = time.monotonic()
        for key, item in list(self.items.items()):
            if now >= item['_until']:
                del self.items[key]
        self.last_submit = {key:value for key,value in self.last_submit.items() if now-value < 10}

    def submit(self, config, source, payload):
        self.prune()
        node = next((n for n in config['nodes'] if n['ip'] == source and n['interface'] == config['ai_if']), None)
        if node is None:
            raise ValueError('Source is not a registered downlink node')
        if not isinstance(payload, dict) or set(payload) - {'ports'} != {'domains', 'duration_seconds', 'purpose'}:
            raise ValueError('domains, duration_seconds and purpose are required')
        spec = validate_request(config, dict(payload, node_id=node['id']))
        if (len(self.items) >= MAX_REQUESTS or node['id'] in self.last_submit
                or any(i['node_id'] == node['id'] and i['status'] == 'pending' for i in self.items.values())):
            raise RequestLimit('One pending request per node; retry later (at least 10 seconds)')
        now = time.monotonic()
        item = dict(spec, id=secrets.token_hex(16), status='pending',
                    created_at=dt.datetime.now(dt.timezone.utc).isoformat(), _until=now+600)
        self.items[item['id']] = item
        self.last_submit[node['id']] = now
        return item

    def get(self, identity):
        self.prune()
        if not isinstance(identity, str) or identity not in self.items:
            raise ValueError('Request not found or expired')
        return self.items[identity]

    def validate_current(self, config, item):
        fields = ('node_id', 'domains', 'duration_seconds', 'purpose', 'ports')
        spec = validate_request(config, {key:item[key] for key in fields if key in item})
        if spec['source'] != item['source']:
            raise ValueError('Node address changed; submit a new request')
        if item['status'] != 'pending':
            raise ValueError('Request already decided')
        return spec

    def decided(self, item, status, grant_id=None):
        item.update(status=status, grant_id=grant_id, _until=time.monotonic()+1800)

    def view(self, item, grants):
        result = {key:value for key,value in item.items() if not key.startswith('_')}
        if item['status'] == 'approved':
            grant = next((g for g in grants if g['id'] == item['grant_id']), None)
            result['status'] = 'approved' if grant else 'ended'
            result['approval'] = grant
        return result

    def snapshot(self, grants):
        self.prune()
        result = []
        for item in self.items.values():
            view = self.view(item, grants)
            view.pop('approval', None)  # Active grants are already in the console snapshot.
            result.append(view)
        return result
