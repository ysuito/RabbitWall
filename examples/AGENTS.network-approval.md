# Network access policy

- Internet access requires explicit human approval through RabbitWall.
- Before a network operation, present the exact destination domains, purpose and requested duration (1, 5 or 30 minutes). Provide a separate plain list, one domain per line, suitable for pasting into RabbitWall.
- Wait for the human to confirm approval before connecting. A request or an existing connection is not approval.
- Include dependency registries, download hosts and API hosts you can identify from local project files. If a redirect or another missing host becomes necessary, stop and request an updated domain list; do not assume permission extends to subdomains.
- Do not bypass a denial through literal IPs, alternate resolvers, proxies, VPNs, tunnels, changes to network settings or repeated retries.
- Never obtain or use RabbitWall's management certificate, control token or administrator API. Only the human approves, extends or opens access.
- Report completion so the human can revoke access early. If permission expires, request approval again.
