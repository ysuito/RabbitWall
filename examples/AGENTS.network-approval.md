# Network access policy

- External access requires explicit human approval in RabbitWall.
- The request API is `http://10.1.0.1:8767`. The administrator must replace this with the gateway's actual downlink IPv4 address. Local API calls to submit requests and check their status are permitted.
- Before external access, inspect local project configuration to identify the exact domains, purpose and shortest necessary duration (60, 300 or 1800 seconds). Send JSON to `POST /api/domain-requests`, for example `{"domains":["github.com","api.github.com"],"duration_seconds":300,"purpose":"Download dependencies"}`. Set `Content-Type: application/json`, bypass proxies and connect directly. Do not supply a node ID or source address.
- Save `request.id` from HTTP 201 and ask the administrator to review the domains, purpose and duration in the console. Submission and an existing connection do not imply approval.
- Poll `GET /api/domain-requests/<request.id>` from the same host at intervals of at least five seconds. Wait while `request.status` is `pending`. Connect only after it is `approved` and the domain's `request.approval.records` entry contains public IPv4 `addresses`.
- Stop external access on `rejected`, `ended`, errors or missing requests. Pending requests disappear after ten minutes. Do not submit duplicates while pending; wait at least ten seconds after HTTP 429. Do not automatically resubmit rejected requests; await administrator instructions. Continuing after expiry requires a new request and approval.
- Subdomains and redirect destinations require individual approval. Stop and submit a new complete domain list when additional destinations are needed. Include domains still needed because approval replaces the previous grant for the node.
- Do not bypass restrictions using direct IPs, another DNS server, proxies, VPNs, tunnels, network changes or repeated retries.
- Never obtain or use RabbitWall management certificates, control tokens or administrator APIs. Approval, revocation, extension and full opening belong to the human administrator. Do not include secrets in the purpose.
- Report completion and ask the administrator to revoke access early.
