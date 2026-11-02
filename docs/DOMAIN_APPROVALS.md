# Temporary domain approvals

[English](DOMAIN_APPROVALS.md) | [日本語](DOMAIN_APPROVALS.ja.md)

RabbitWall offers a separate restricted mode for human-approved network access. A human opens **許 / Temporary approvals** through the management PC's mTLS console, selects an AI-side node, pastes exact domains (one per line), supplies a purpose and chooses 1, 5 or 30 minutes. **Approve and open restricted access** replaces that node's previous grant and closes any full-open access. Other active node grants are retained. DNS-policy changes briefly close external access while Unbound reloads.

Each node has at most one grant containing up to 32 domains. Subdomains and HTTP redirect destinations need their own explicit approval. URLs, literal IPs, ports and wildcards are rejected. Names are normalized to lower-case IDNA ASCII. The normal toggle and time buttons still open the whole AI subnet; switching from restricted mode to full-open requires confirmation in the console.

## Enforcement

- Unbound uses exact-QNAME response policy zones (RPZ), with per-client tags. Only the selected client's approved names are allowed, including over UDP and TCP. Parent and descendant names remain denied unless explicitly listed. Cached answers do not bypass the policy.
- A separate controller worker resolves the approved names' public IPv4 A answers through `dns_upstream`, using the host's uplink address. DNS search paths and arbitrary user-provided DNS servers are never used. CNAME chains are handled by dnspython; the shortest answer TTL bounds address permissions. Up to eight public addresses per name are retained.
- nftables permits only TCP 80/443 for approved `(source IP, destination IP)` pairs. All other AI Internet traffic, including UDP 123 in restricted mode, stays closed. Direct external DNS remains blocked. Normal registered management SSH/HTTPS/Ping and host update traffic keep their existing rules.
- The kernel lease is at most 20 seconds, and never intentionally exceeds the DNS TTL or approval deadline. Missing/zero-TTL/private answers do not grant access. DNS resolution is refreshed while approval is active; expired or failed answers cannot renew address permissions.
- Revoke, expiry and global OFF block existing external connections as well. Restart, update, network reconfiguration, node-setting saves or a lost kernel lease discard grants. No automatic resumption occurs. DNS-control or firewall failures close access.

This is IP-based containment, not strict HTTPS hostname or URL isolation: other services sharing an approved IP can be reachable, and uploads or unsafe operations to an approved service are not prevented. An explicit proxy plus direct-egress denial is needed for stronger hostname enforcement. Node identity is the configured source IP; hostile endpoints with network-administration privileges require separate VLANs or equivalent network isolation. External model/API connections routed through RabbitWall also require approval; do not create implicit permanent exceptions.

## Install and diagnose [RabbitWall host]

Run the normal update from the checked-out source:

```sh
sudo python3 setup.py update
```

No additional package beyond the documented dependencies is required; `unbound-control` ships with Unbound. Update enables a **local Unix control socket**, not a TCP control listener. The root controller joins the `rabbitwall-dns` supplementary group so it can use that socket. Generated RPZ policy files are in `/etc/rabbitwall-domain-policy/`, owned by root and readable by the DNS group. DNS observations remain separate; stopping the dnstap observer does not disable resolution or approve traffic.

```sh
sudo nft list set inet rabbitwall_console domain_sources
sudo nft list set inet rabbitwall_console domain_targets
sudo unbound-control -c /etc/rabbitwall-unbound.conf list_auth_zones
sudo journalctl -u rabbitwall-control --since '10 minutes ago' --no-pager
```

A pending DNS worker is shown in the console; access is available only after public addresses are installed. Private, missing, expired or unsupported answers are shown without usable addresses. Approval/revocation events, domains, purpose and duration are recorded in the controller journal. Grant state is in memory; generated files are cleared on controller start and are never a persistent authorization.

## Agent instructions and future request API

Copy the [example agent instructions](../examples/AGENTS.network-approval.md) into the AI agent's applicable `AGENTS.md`, merging existing instructions. The file guides behavior; RabbitWall enforces access independently. Requests should include exact domains, purpose and requested duration; the human selects the trusted node identity in the console.

This version implements **manual submission and administrator approval only**. The console's `POST /api/domain-approvals` endpoint is an **administrator action**, not an agent request endpoint. It requires the management-PC firewall rule, client certificate, server-side key and same-origin checks. Never copy the management certificate or control token onto an AI node. A future request-only API must use separate credentials and allow only creation/status of the caller's requests, with bounded queues/rate limits and no approval, extension or full-open permission.

The administrator API accepts only these bodies:

```json
{"action":"approve","request":{"node_id":"ai-host","domains":["github.com","api.github.com"],"duration_seconds":300,"purpose":"Download project dependencies"}}
```

```json
{"action":"revoke","request":{"id":"<approval-id>"}}
```

Active grants are included in the existing `GET /api/control` response. Agent-supplied text is treated as request data, not as instructions to the administrator or controller.
