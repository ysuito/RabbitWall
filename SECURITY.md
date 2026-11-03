# Security

Residual concerns and decisions: [日本語](docs/SECURITY_REMAINING.ja.md).

RabbitWall is for a dedicated Linux gateway on a trusted management network. It is not an Internet-facing service or a general-purpose firewall manager.

- The backend listens on loopback. Caddy requires a trusted, explicitly permitted client certificate and the configured management-PC source IP.
- The Internet gate starts closed. Its kernel permission expires after 20 seconds unless renewed by the controller. Closing also blocks established AI-originated connections and AI DNS input/relay/replies. Management SSH and gateway-originated updates remain available.
- Node edits require the same mTLS management access and same-origin protection as gate operations. The controller accepts only validated node settings, never arbitrary commands or network changes. Monitoring and management SSH/Ping permissions are independent; revoking access blocks established management SSH too. Node saves preserve the gate on success; application failures close it.
- The baseline permits public IPv4 HTTP/HTTPS and NTP. HTTPS includes potential DoH, tunnels and data upload. Domain hints and country estimates are observations, not enforcement of application identity. IPv6 and alternate network paths need attention on the AI hosts too.
- DNS forwarding uses Unbound with the configured upstream only; local DNSSEC validation and upstream encryption are not enabled. The separate dnstap observer receives a bounded local stream. Observer failure can lose domain evidence but does not stop DNS or bypass the kernel gate.
- DNS first-seen information, session history and traffic aggregates reveal network activity. Keep the host, backups and generated reports private. The original CA key and client private key stay on the management PC.
- Installing replaces this dedicated host's nftables ruleset. UFW/firewalld/Docker, hardware flow offload, custom routing and other network managers are outside automatic integration. Use a local recovery console and review the generated plan.

Please do not include certificates, private keys, passwords, actual traffic logs or device backups in public issues. If the repository owner has enabled GitHub private vulnerability reporting, use that channel. Otherwise contact the owner privately before publishing an exploit; no private reporting address is bundled with this source.

HTTP ingress uses a total five-second header receive budget and a separate three-second body receive budget. Small periodic reads do not restart these deadlines. Each HTTP server accepts at most 32 active workers and eight per source IP; counters are released on completion or failure. Controller/DNS-policy application time is outside the receive budget. Responses have a separate five-second socket timeout.

Mitigation of [dnspython CVE-2026-114605](https://github.com/rthalley/dnspython/security/advisories/GHSA-45c3-73f7-pv4m) is deferred while retaining OS-managed dependencies. RabbitWall keeps its existing dnspython >=2.6.1,<3 requirement and does not require pip, a separate Python environment, or the new compression-pointer startup probe. This deferral does not mean the CPU-exhaustion issue has been fixed; follow the distribution's security updates.

Installation, controller installation and node saves use the same closed-by-default persistent firewall renderer, including downlink request ingress on TCP 8767. Node edits must not remove that rule on a subsequent firewall reload.
