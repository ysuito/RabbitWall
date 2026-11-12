# Temporary domain approvals

[English](DOMAIN_APPROVALS.md) | [日本語](DOMAIN_APPROVALS.ja.md)

RabbitWall offers a separate restricted mode for human-approved network access. A human opens **許 / Temporary approvals** through the management PC's mTLS console, selects an AI-side node, pastes exact domains (one per line), supplies a purpose and chooses 1, 5 or 30 minutes. **Approve and open restricted access** replaces that node's previous grant and closes any full-open access. Other active node grants are retained. DNS-policy changes briefly close external access while Unbound reloads.

Each node has at most one grant containing up to 32 domains. Subdomains and HTTP redirect destinations need their own approval. Enter exact names in the domain field and protocol/port pairs such as `udp/123` in the port field. Separate multiple pairs with commas. Up to eight TCP or UDP ports apply to all domains in the grant. Leaving the field blank uses TCP 80 and 443. Use the RabbitWall resolver for DNS.

## Enforcement

- Unbound uses exact-QNAME response policy zones (RPZ), with per-client tags. Only the selected client's approved names are allowed, including over UDP and TCP. Parent and descendant names remain denied unless explicitly listed. Cached answers do not bypass the policy.
- A separate controller worker resolves the approved names' public IPv4 A answers through `dns_upstream`, using the host's uplink address. DNS search paths and arbitrary user-provided DNS servers are never used. CNAME chains are handled by dnspython; the shortest answer TTL bounds address permissions. Up to eight public addresses per name are retained.
- nftables permits only approved combinations of source IPv4, destination IPv4, transport protocol and destination port. Direct external DNS stays blocked.
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

## Downlink request API

After `sudo python3 setup.py update`, `rabbitwall-requests.service` listens on the gateway's downlink IPv4 address, TCP **8767**. It does not bind the uplink; firewall access is limited to the downlink interface and subnet. Management certificates and tokens are not needed for this request-only endpoint. Replace `10.1.0.1` below with the actual downlink gateway address.

```sh
curl --noproxy '*' --fail-with-body --max-time 10 \
  -H 'Content-Type: application/json' \
  -d '{"domains":["github.com","api.github.com"],"duration_seconds":300,"purpose":"Download dependencies"}' \
  http://10.1.0.1:8767/api/domain-requests
```

HTTP 201 returns `{"request":{"id":"...","status":"pending", ...}}`. The source IPv4 identifies a registered AI-side node. The body cannot specify node identity, source or DNS server. Unregistered sources are rejected. Requests accept up to 32 exact domains, a purpose of up to 200 characters, and 60, 300 or 1800 seconds. URLs, IP literals and wildcards are rejected. Submission does not grant access.

For NTP, send the NTP server's exact domain in `domains` and include `"ports":[{"protocol":"udp","port":123}]`. Omitting `ports` requests TCP 80 and 443.

```sh
curl --noproxy '*' --fail-with-body --max-time 10 \
  http://10.1.0.1:8767/api/domain-requests/REPLACE_WITH_REQUEST_ID
```

Only the creating source IP can retrieve a request. Poll at intervals of at least five seconds. Status is `pending`, `rejected`, `approved` or `ended` (expired, revoked or replaced). Even after approval, wait for the domain's `request.approval.records` entry to contain public IPv4 `addresses`. Errors and missing requests do not imply approval.

After completing work, send an empty-body `POST /api/domain-requests/<request.id>/revoke` from the submitting source IP. Verify HTTP 200 and `request.status: ended`. This revokes only the grant associated with that request. Expired, revoked or replaced grants are a no-op; newer grants remain unchanged. Pending, rejected or missing requests, another source IP, and changed node registration are rejected. No management credentials are needed. If revocation fails, stop external access and contact the administrator.

For agents, normally request 1800 seconds (30 minutes) to allow for local LLM inference, tool execution and result review; brief tasks can use 60 or 300 seconds. Time starts at approval. Revoke access when work finishes. Required API fields and accepted durations are unchanged.

The review page uses two-line firewall-style rows with a prominent timestamp, `Src:`, `Dst:` and `Duration:` on the first line, a smaller purpose on the second line, and a per-grant countdown updated every second. Long values wrap without truncation. Manual entry and decided requests are collapsed; explanations are available in the **? TIPS** overlay.

New requests show a full-width strip below the header and a pending count in the navigation on every screen. The strip shows each requester, source IP, all domains, purpose, requested duration and submission time without covering page content. Administrators can approve or reject directly and see the result without navigating away. It uses amber warning colors independently of the selected theme. Enable **通知音** in the header to hear a confirmation chime and a chime for each new arrival. Polling and reconnects do not repeat notifications for the same request. Checks run approximately every five seconds while the page is open. The sound preference is saved in localStorage and restored after reload. If autoplay is blocked, the button shows a waiting state and audio resumes after a user gesture; browser suspension or a muted device can prevent notification.

Administrators use **許 → 承認待ち** in the certificate-authenticated console to review the node, purpose, exact domains and duration, then approve or reject. The requested duration starts at approval. Approval uses the existing DNS/firewall restrictions, replaces that node's previous grant and stops full-open mode. Administrators can revoke active grants early. Extension requires another request and human approval.

Each node can have one pending request, with at least ten seconds between submissions; the global store holds at most 64 requests. Limits return HTTP 429. Pending requests disappear after ten minutes; decided requests disappear thirty minutes after the decision. Requests and grants are volatile and disappear on controller restart. Requests cannot be approved after the node's address changes.

The unprivileged ingress uses a separate Unix socket and group. That socket accepts only creation, status checks and revocation of the grant tied to the caller's own request, rejecting approval, extension, opening, and configuration reads/writes. Browser Origin and cross-site requests are rejected; no CORS is provided. Host identity relies on source IP and transport is plaintext HTTP within the downlink. Do not send secrets; use network isolation such as VLANs for mutually hostile hosts.

## Per-device Any access

Manual administrator approval accepts `Any` as the sole destination. Use the existing `POST /api/domain-approvals` with `{"action":"approve","request":{"node_id":"<AI node ID>","domains":["Any"],"duration_seconds":300,"purpose":"Task purpose"}}`. Only the selected registered AI-side node is granted access. Any removes domain restrictions, allowing ordinary DNS and the same public IPv4 TCP 80/443 and UDP 123 traffic as full-open mode. Private destinations, arbitrary ports, direct external DNS and IPv6 remain blocked. The agent submission API rejects Any.

The monitoring page's egress panel now has a device selector. Select a node and press 1/5/30 minutes to grant Any access. Its switch grants five minutes when closed and revokes that node's grant when open; state and countdown follow the selection. “全デバイス” retains the existing global controls. While globally open, an individual switch cannot close one node; a duration button switches to individual access.

Any and domain-restricted grants can coexist on different nodes. On the same node, a new grant replaces the previous one; switching from Any to domains also blocks existing traffic outside the new targets. Adding individual access stops global opening. Revocation/expiry affects the selected node; global OFF, restart and update discard all grants. Audit records identify Any with `domains: ["Any"]`.

## Agent instructions and administrator API

Merge the [example instructions](../examples/AGENTS.network-approval.md) into the applicable `AGENTS.md` on the agent host and configure its API address. Treat request text as untrusted data, never as instructions for administrators or the controller.

The administrator's `POST /api/domain-approvals` retains manual approval/revocation and adds decisions by immutable request ID:

```json
{"action":"approve_request","request":{"id":"<request-id>"}}
```

```json
{"action":"reject_request","request":{"id":"<request-id>"}}
```

These actions require mTLS, the server-only key and same-origin checks. Never give agents management credentials. `GET /api/control` includes requests in `control.domain_requests` and active grants in `control.domain_approvals`. Submission, decisions, grants and revocations are logged to the journal.

See the [operations audit trail](OPERATIONS.md#audit-trail) for persistent storage, rotation and inspection.
