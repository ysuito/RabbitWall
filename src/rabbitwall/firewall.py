"""nftables configuration generated directly from RabbitWall installation settings."""
import ipaddress
from settings import validate, monitored, management_allowed

LEASE = 20
PROBE_COMMENT = 'rabbitwall-health-probe'
DNS_COMMENT = 'rabbitwall-local-dns'
REQUEST_COMMENT = 'rabbitwall-domain-requests'
BLOCKED = ('0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
           '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.168.0.0/16',
           '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4')

SYSCTL = '''net.ipv4.ip_forward = 1
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.all.forwarding = 0
net.netfilter.nf_conntrack_acct = 1
'''


def dns_rule(config):
    c = validate(config); ai = ipaddress.IPv4Interface(c['ai_cidr'])
    return (f'insert rule inet rabbitwall_filter input iifname "{c["ai_if"]}" '
            f'ip saddr {ai.network} ip daddr {ai.ip} meta l4proto {{ tcp, udp }} th dport 53 '
            f'counter accept comment "{DNS_COMMENT}"\n')


def request_rule(config):
    c = validate(config); ai = ipaddress.IPv4Interface(c['ai_cidr'])
    return (f'insert rule inet rabbitwall_filter input iifname "{c["ai_if"]}" '
            f'ip saddr {ai.network} ip daddr {ai.ip} tcp dport 8767 '
            f'limit rate 10/second burst 20 packets counter accept comment "{REQUEST_COMMENT}"\n')


NODE_ACCESS_COMMENT = 'rabbitwall-node-access'
NODE_PROBE_COMMENT = 'rabbitwall-node-probes'
ACCESS_CHAIN = 'rabbitwall_node_access'
PROBE_CHAIN = 'rabbitwall_node_probes'


def node_rule_batch(config, objects):
    """Replace only node ACL/probe chains; never flush the gate or conntrack."""
    c = validate(config)
    ai = ipaddress.IPv4Interface(c['ai_cidr'])
    lines = []
    chains = {obj['chain']['name'] for obj in objects
              if obj.get('chain', {}).get('table') == 'rabbitwall_filter'}
    for obj in objects:
        rule = obj.get('rule', {})
        if rule.get('table') == 'rabbitwall_filter' and rule.get('comment') in {
                PROBE_COMMENT, NODE_ACCESS_COMMENT, NODE_PROBE_COMMENT}:
            lines.append(f'delete rule inet rabbitwall_filter {rule["chain"]} handle {int(rule["handle"])}')
    for chain in (ACCESS_CHAIN, PROBE_CHAIN):
        lines.append(f'{"flush" if chain in chains else "add"} chain inet rabbitwall_filter {chain}')
    lines += [f'insert rule inet rabbitwall_filter forward jump {ACCESS_CHAIN} comment "{NODE_ACCESS_COMMENT}"',
              f'insert rule inet rabbitwall_filter output jump {PROBE_CHAIN} comment "{NODE_PROBE_COMMENT}"',
              f'add rule inet rabbitwall_filter {ACCESS_CHAIN} ct state invalid return']
    for node in c['nodes']:
        if monitored(node):
            source = ipaddress.IPv4Interface(c['ai_cidr'] if node['interface'] == c['ai_if'] else c['uplink_cidr']).ip
            lines.append(f'add rule inet rabbitwall_filter {PROBE_CHAIN} oifname "{node["interface"]}" '
                         f'ip saddr {source} ip daddr {node["ip"]} icmp type echo-request counter accept')
        if node['interface'] != c['ai_if']: continue
        outbound = f'iifname "{c["uplink_if"]}" oifname "{c["ai_if"]}" ip saddr {c["admin_ip"]} ip daddr {node["ip"]}'
        inbound = f'iifname "{c["ai_if"]}" oifname "{c["uplink_if"]}" ip saddr {node["ip"]} ip daddr {c["admin_ip"]}'
        for kind, port in (('ssh', 22), ('https', 443)):
            if management_allowed(node, kind, c):
                lines += [f'add rule inet rabbitwall_filter {ACCESS_CHAIN} {outbound} tcp dport {port} ct state {{ new, established }} accept',
                          f'add rule inet rabbitwall_filter {ACCESS_CHAIN} {inbound} tcp sport {port} ct state established ct direction reply accept']
        if management_allowed(node, 'ping', c):
            lines += [f'add rule inet rabbitwall_filter {ACCESS_CHAIN} {outbound} icmp type echo-request accept',
                      f'add rule inet rabbitwall_filter {ACCESS_CHAIN} {inbound} icmp type echo-reply ct state established accept']
    # These denies precede the baseline established rule, revoking existing access too.
    outbound = f'iifname "{c["uplink_if"]}" oifname "{c["ai_if"]}" ip saddr {c["admin_ip"]} ip daddr {ai.network}'
    inbound = f'iifname "{c["ai_if"]}" oifname "{c["uplink_if"]}" ip saddr {ai.network} ip daddr {c["admin_ip"]}'
    lines += [f'add rule inet rabbitwall_filter {ACCESS_CHAIN} {outbound} tcp dport {{ 22, 443 }} counter drop',
              f'add rule inet rabbitwall_filter {ACCESS_CHAIN} {outbound} icmp type echo-request counter drop',
              f'add rule inet rabbitwall_filter {ACCESS_CHAIN} {inbound} tcp sport {{ 22, 443 }} ct direction reply counter drop',
              f'add rule inet rabbitwall_filter {ACCESS_CHAIN} {inbound} icmp type echo-reply counter drop']
    return '\n'.join(lines) + '\n'


def probe_rules(config):
    return node_rule_batch(config, [])


def gate(config):
    c = validate(config); ai = ipaddress.IPv4Interface(c['ai_cidr'])
    return f'''table inet rabbitwall_console {{
    set online_sources {{
        type ipv4_addr
        flags interval,timeout
        timeout {LEASE}s
    }}
    set domain_sources {{ type ipv4_addr; flags timeout; timeout {LEASE}s; }}
    set device_sources {{ type ipv4_addr; flags timeout; timeout {LEASE}s; }}
    set domain_resolver_sources {{ type ipv4_addr; flags timeout; timeout {LEASE}s; }}
    set domain_targets {{ type ipv4_addr . ipv4_addr; flags timeout; timeout {LEASE}s; }}
    chain ai_egress {{
        ct original ip saddr @online_sources counter return
        ct original ip saddr @device_sources counter return
        meta l4proto tcp ct original proto-dst {{ 80, 443 }} ct original ip saddr . ct original ip daddr @domain_targets counter return
        limit rate 5/second burst 10 packets log prefix "rabbitwall-forward-drop gate "
        counter drop
    }}
    chain dns_request {{
        ip saddr @online_sources counter return
        ip saddr @domain_sources counter return
        meta l4proto udp limit rate 5/second burst 10 packets log prefix "rabbitwall-dns-drop input" group 100 snaplen 4096 queue-threshold 1
        counter drop
    }}
    chain dns_direct {{
        meta l4proto udp limit rate 5/second burst 10 packets log prefix "rabbitwall-dns-drop forward" group 100 snaplen 4096 queue-threshold 1
        counter drop
    }}
    chain dns_upstream {{
        ip saddr @online_sources counter return
        ip saddr @domain_resolver_sources counter return
        counter drop
    }}
    chain dns_reply {{
        ip daddr @online_sources counter return
        ip daddr @domain_sources counter return
        counter drop
    }}
    chain input {{
        type filter hook input priority -10; policy accept;
        iifname "{c['ai_if']}" ip saddr {ai.ip} counter drop
        iifname "{c['ai_if']}" ip daddr {ai.ip} meta l4proto {{ tcp, udp }} th dport 53 jump dns_request
    }}
    chain output {{
        type filter hook output priority -10; policy accept;
        ip saddr {ai.ip} ip daddr {c['dns_upstream']} meta l4proto {{ tcp, udp }} th dport 53 jump dns_upstream
        oifname "{c['ai_if']}" ip saddr {ai.ip} meta l4proto {{ tcp, udp }} th sport 53 jump dns_reply
    }}
    chain forward {{
        type filter hook forward priority -10; policy accept;
        iifname "{c['ai_if']}" meta l4proto {{ tcp, udp }} th dport 53 jump dns_direct
        iifname "{c['ai_if']}" oifname "{c['uplink_if']}" meta nfproto ipv6 counter drop
        iifname "{c['uplink_if']}" oifname "{c['ai_if']}" meta nfproto ipv6 counter drop
        iifname "{c['ai_if']}" oifname "{c['uplink_if']}" ip saddr {ai.network} ct direction original jump ai_egress
        iifname "{c['uplink_if']}" oifname "{c['ai_if']}" ct original ip saddr {ai.network} jump ai_egress
    }}
}}
'''


def persistent_rules(config):
    """Complete boot snippet. Keep request ingress when rewriting node settings."""
    return gate(config) + probe_rules(config) + dns_rule(config) + request_rule(config)


def baseline(config):
    c = validate(config); ai = ipaddress.IPv4Interface(c['ai_cidr']); up = ipaddress.IPv4Interface(c['uplink_cidr'])
    result = f'''#!/usr/sbin/nft -f
# RabbitWall owns this machine's nftables ruleset.
flush ruleset

define uplink = "{c['uplink_if']}"
define ai = "{c['ai_if']}"
define admin = {c['admin_ip']}

table inet rabbitwall_filter {{
    set non_public_v4 {{
        type ipv4_addr
        flags interval
        elements = {{ {', '.join(BLOCKED)} }}
    }}
    chain input {{
        type filter hook input priority 0; policy drop;
        iifname "lo" accept
        meta nfproto ipv6 counter drop
        iifname $ai ip saddr != {ai.network} counter drop
        iifname $uplink ip saddr {ai.network} counter drop
        ct state invalid counter drop
        ct state established,related accept
        iifname $uplink ip saddr $admin ip daddr {up.ip} tcp dport 22 ct state new accept
        iifname $uplink ip saddr $admin ip daddr {up.ip} icmp type echo-request accept
        iifname $ai ip daddr {ai.ip} icmp type echo-request accept
        limit rate 5/second burst 10 packets log prefix "rabbitwall-input-drop "
        counter drop
    }}
    chain forward {{
        type filter hook forward priority 0; policy drop;
        meta nfproto ipv6 counter drop
        iifname $ai ip saddr != {ai.network} counter drop
        iifname $uplink ip saddr {ai.network} counter drop
        ct state invalid counter drop
        ct state established,related accept
        iifname $ai ip daddr @non_public_v4 counter drop
        iifname $ai oifname $uplink tcp dport {{ 80, 443 }} ct state new accept
        iifname $ai oifname $uplink udp dport 123 accept
        limit rate 5/second burst 10 packets log prefix "rabbitwall-forward-drop "
        counter drop
    }}
    chain output {{
        type filter hook output priority 0; policy drop;
        oifname "lo" accept
        meta nfproto ipv6 counter drop
        ct state invalid counter drop
        ct state established,related accept
        oifname $uplink ip daddr {c['dns_upstream']} meta l4proto {{ tcp, udp }} th dport 53 accept
        oifname $uplink ip daddr {c['gateway']} icmp type echo-request accept
        ip protocol icmp icmp type {{ destination-unreachable, time-exceeded, parameter-problem }} accept
        ip daddr @non_public_v4 counter drop
        oifname $uplink tcp dport {{ 80, 443 }} ct state new accept
        oifname $uplink udp dport 123 accept
        limit rate 5/second burst 10 packets log prefix "rabbitwall-output-drop "
        counter drop
    }}
}}

include "/etc/nftables.d/rabbitwall.nft"
'''
    if c['nat']:
        result += f'''
table ip rabbitwall_nat {{
    chain postrouting {{
        type nat hook postrouting priority srcnat; policy accept;
        oifname "{c['uplink_if']}" ip saddr {ai.network} masquerade
    }}
}}
'''
    return result


def domain_lease_rules(grants, now):
    """Renew per-source DNS and public IPv4 destinations without changing full-open leases."""
    lines = [f'flush set inet rabbitwall_console {name}' for name in ('domain_sources','domain_resolver_sources','domain_targets','device_sources')]
    resolver_life = 0
    targets = {}
    for grant in grants:
        life = min(LEASE, grant['deadline']-now)
        if life <= 0: continue
        source = str(ipaddress.IPv4Address(grant['source']))
        resolver_life = max(resolver_life,life)
        lines.append(f'add element inet rabbitwall_console domain_sources {{ {source} timeout {max(1,int(life*1000))}ms }}')
        if grant.get('scope') == 'any':
            lines.append(f'add element inet rabbitwall_console device_sources {{ {source} timeout {max(1,int(life*1000))}ms }}')
            continue
        for record in grant['records'].values():
            valid = min(life,record.get('until',0)-now)
            if valid <= 0: continue
            for address in record.get('addresses',[]):
                ip = ipaddress.IPv4Address(address)
                if not ip.is_global: continue
                targets[(source,str(ip))] = max(valid,targets.get((source,str(ip)),0))
    if resolver_life:
        from settings import AI_IP
        lines.append(f'add element inet rabbitwall_console domain_resolver_sources {{ {AI_IP} timeout {max(1,int(resolver_life*1000))}ms }}')
    for (source,address),life in sorted(targets.items()):
        lines.append(f'add element inet rabbitwall_console domain_targets {{ {source} . {address} timeout {max(1,int(life*1000))}ms }}')
    return '\n'.join(lines)+'\n'
