# Daily operation

[English](OPERATIONS.md) | [日本語](OPERATIONS.ja.md)

## Console pages

- **観 — Monitor:** traffic map, route list, monitored nodes and the AI network's Internet-access toggle.
- **覧 — Sessions:** current connections, observed history and firewall rejection logs. Search by IP, domain, port, country or state.
- **析 — Analytics:** traffic rankings and newly observed domains.
- **設 — Settings:** color scheme and the status of the IP-country database.

Sessions are collected about every five seconds; nodes are checked with Ping about every ten seconds. Short connections that finish between observations may not appear. In the current view, moving lights indicate observed sessions. In History, thicker lines, more lights and more frequent movement indicate greater cumulative sent-plus-received bytes, including ended sessions. This uses a capped logarithmic scale, not real-time speed or packet counts. Unknown byte counts remain thin and static; pausing animation or stale data stops movement. History remains limited to the displayed session records (up to 500), independently of analytics periods.

Node status labels are **正** (healthy), **断** (no Ping response), **不** (unable to check), and **古** (monitoring data is stale). A host configured not to respond to Ping can appear as **断** even while running.

Use the mouse wheel over the map to zoom between 1× and 6× around the cursor. The LAN layout, labels and routes zoom together. Drag to pan; Initial view resets both zoom and position. Ctrl/Command wheel gestures remain available to the browser.

## Opening and closing Internet access

Use the toggle through the management PC's mTLS connection. The gate starts **閉 (closed)** after a reboot, controller restart, installation or update. While **開 (open)**, access is maintained by a 20-second kernel lease that the controller renews. If renewal stops, the lease expires and access closes.

The **1分 / 5分 / 30分** buttons open access for 1, 5 or 30 minutes and then automatically close it, including DNS and existing external sessions. Remaining time is shown in the gate panel. The deadline is enforced by the controller and kernel lease even after closing the browser. Clicking a timed button again sets a new deadline starting now; the toggle closes access immediately. Opening with the toggle uses no time limit. Reboots and controller restarts discard the timer and start closed.

Closing blocks AI outbound traffic, in-flight traffic and its replies, and DNS reception, forwarding and responses. Management SSH/HTTPS, monitoring Ping and RabbitWall's own update traffic remain available. Even while open, traffic is limited to the baseline firewall policy: TCP 80/443 and UDP 123 to public IPv4 addresses, plus DNS through RabbitWall.

## Adding, editing and removing nodes

Connect from the management PC over certificate-authenticated HTTPS and open **Settings → Node management**. Set the name, IPv4 address and AI/uplink side, then choose **Health monitoring**, **Management PC SSH**, **Management PC HTTPS** and **Management PC Ping** independently. Select **Save and apply**. Up to 12 nodes, including uplink nodes, can be registered; an empty list is allowed. New UI nodes have management access disabled. Management SSH/HTTPS/Ping permissions apply only to AI-side nodes.

Disabled monitoring is displayed as **休 (not monitored)**. Monitoring never grants management access by itself. Removing a node does not exclude its traffic from subnet-wide observation or DNS. Map labels and layout refresh after saving; additional map nodes are grouped when space is limited.

Saving updates only node settings and dedicated firewall chains, without changing NICs, DNS, the Internet gate state or restarting services. Revoking management access or removing a node blocks existing management SSH/HTTPS connections too. Concurrent edits are rejected instead of overwriting another save; reload and edit again. Invalid input changes nothing. A failed save attempts to restore prior files and rules; an application failure closes the Internet gate.

Initial nodes come from `/etc/rabbitwall.json`. UI saves are stored in `/etc/rabbitwall-nodes/nodes.json` and take precedence. They survive `setup.py update` and reboot. Previous settings are backed up under `/etc/rabbitwall-nodes/node-backups/`; include both JSON files in configuration backups.

`setup.py reconfigure --config rabbitwall.json --apply-network` reapplies the supplied JSON as the complete network configuration and clears UI node overrides. Copy wanted nodes into the input JSON first. Optional per-node boolean fields are `monitor`, `allow_ssh`, `allow_https` and `allow_ping`. If omitted, monitoring and AI-side management SSH/Ping are enabled, while HTTPS is disabled. HTTPS permission applies to TCP 443 and remains available when Internet access is closed. Set each field explicitly when editing JSON manually.

## DNS and inferred domains

Configure AI hosts to use the host IP from `ai_cidr` as both gateway and DNS server. Unbound (`rabbitwall-dns.service`) queries `dns_upstream` over UDP/TCP port 53 and caches answers. Direct port-53 traffic from AI hosts to upstream or external DNS servers is rejected.

The independent `rabbitwall-dns-observer.service` receives Unbound client-response events through a dnstap Unix socket. Positive A/AAAA answers for the same client are matched against destination IPs and shown as inferred domains. For CNAME chains, the original queried name is displayed and the shortest TTL along the chain is used, capped at one hour. If several names share an IP, all candidates are shown. This does not establish the HTTPS hostname or URL. Unbound cache responses are matched using their remaining TTL. DoH, answers cached only on the client, and connections to literal IP addresses may not produce a match.

Up to 10,000 observations are stored in `/run/rabbitwall-dns/observations.json`, a temporary file in memory-backed storage that disappears on reboot. DNS packets and per-query disk logs are not stored. Candidate names attached to a session are retained with that session's history.

Unbound continues serving open-gate DNS when the observer stops or restarts. Slow observation can lose events; buffered events may arrive late, but dropped events cannot be recovered. Existing session hints remain in history, while new hints require DNS responses after observation resumes. The closed gate blocks DNS in the kernel independently of the observer, including Unbound cache responses.

Only the configured upstream DNS is used; failure does not fall back to direct recursive resolution. This configuration does not enable local DNSSEC validation or encryption of upstream DNS.

## Newly observed domains

The first observed queried name in a DNS answer is added to the domain catalog and labeled **新 (new)** for 24 hours. Immediately after installation, familiar domains will also appear as new. Names are case-insensitive; subdomains are treated as separate names.

Known domains persist across restarts. The catalog is limited to 100,000 names. At the limit, new registrations stop and the console shows that the limit has been reached. The recent list shows up to 100 entries. Observing a DNS answer does not prove that a connection to that name succeeded.

## Traffic rankings

Traffic from the AI network to public IPv4 addresses is ranked over the last hour, 24 hours, 7 days or 30 days, by destination IP or inferred domain, and by sent, received or total bytes. The console displays the top 20 entries. Management SSH/HTTPS, RabbitWall's own traffic and local DNS are excluded.

About every five seconds, differences are taken from cumulative conntrack counters and stored in one-minute buckets. Complete hours older than one day are compacted into hourly totals, retained for 30 days. The 7/30-day windows round their starting boundary up to a full hour; the UI shows the available starting time. Existing retained data is used after an update, but previously deleted traffic cannot be recovered. The same cumulative value is not repeatedly added. The first observation establishes a baseline; a decrease in counters or a collection gap longer than 30 seconds also resets the baseline.

When there is one candidate domain, multiple IPs for that name are grouped together. Traffic with multiple candidates is grouped by IP as “multiple candidates,” without counting its bytes against every candidate. Bytes transferred before the first observation, after the last observation, during collection gaps or by connections ending between observations are omitted. These figures are not precise billing measurements.

## Storage and capacity

Session history, known domains and traffic data are stored in `/var/lib/rabbitwall/history.sqlite3`. Ended sessions are retained for 24 hours, with an approximate overall target of 20,000 entries. Traffic aggregates cover up to 30 days; older minute data is compacted into hourly totals. The known-domain catalog is not subject to session-history expiry. The database is updated with each collection transaction; monitor free space and write volume in your environment.

The rejection view combines kernel journal logs and dropped-DNS observations, showing up to 200 entries from the last five minutes. Firewall log rate limits and rules that reject without logging mean that this is not a count of all rejected packets.

UDP DNS entries show actual query names and record types, rather than inferred domains. Both closed-gate UDP DNS and direct external UDP port-53 DNS are observed; search accepts query names and types. The existing collector receives packet copies via the OS libnetfilter_log library and NFLOG group 100. Observation failure cannot change or delay packet verdicts. Each DNS rule logs at most 5 packets/second with a burst of 10 and copies at most 4096 bytes. Up to 200 parsed observations are held in memory for five minutes and included in state JSON; raw packets and a separate DNS-rejection database are not written. Collector restart clears these observations. TCP DNS remains blocked according to the firewall policy, but its content is not observed: new connections are dropped at SYN before a DNS query is sent. Fragmented IP packets, malformed/truncated messages and encrypted DNS cannot reliably be decoded.

## Audit trail

Open **録 / 監査ログ** in the console over certificate-authenticated HTTPS. The view shows only requests, approval/rejection, revocation, grant endings, gate changes and failures of these operations. Startup/shutdown, node saves and duplicate operation started/success records remain in the files only. The view reads up to 200 recent matching entries within a 1 MiB budget across the current file and rotations, newest first. Search IPs, domains, purpose and IDs within that fetched range, filter by event or failures, and expand raw JSON details. It refreshes every ten seconds while visible. Inspect the files for older records.

The controller appends JSON Lines to `/var/log/rabbitwall/audit.jsonl` for submissions, approval/rejection, administrator/agent revocation, grant replacement/expiry/clearing, gate changes, node saves and controller startup/shutdown. Control-socket operations record started/success/failure outcomes; successful polling is omitted. HTTP requests rejected before reaching the controller and individual traffic packets are outside this trail.

Events include UTC time, request/grant IDs, source IP, domains, purpose and duration where applicable. Decision events link request `id` to `grant_id`. `actor.channel` distinguishes `agent` from `administrator`; PID/UID/GID identify the Unix-socket client service, not the individual administrator or certificate. Failure records include action, outcome and error type without unvalidated bodies or credentials. Never put secrets in a request purpose.

```sh
sudo tail -n 50 /var/log/rabbitwall/audit.jsonl
sudo journalctl -u rabbitwall-control --since '1 hour ago' --no-pager -o cat
```

This uses only the standard library. Installation/update supplies the control service's log directory: mode 0700, files 0600, accessible only by root. Each append is synced. Files rotate at approximately 5 MiB with ten backups (`.1` newest) plus the current file, approximately 55 MiB total. Retention is capacity-based, with no guaranteed number of days. Restart/update preserves files; older journal entries are not imported.

The same JSON is written to the service journal. Runtime file-write failures emit `audit-write-failed` to the journal while traffic control and revocation continue. Failure to create the audit file initially prevents controller startup. Journal persistence depends on OS configuration. Arrange external archival for long-term retention; this local trail does not resist modification or deletion by root.

## IP-country database

Run this on the RabbitWall machine:

```sh
sudo python3 /opt/rabbitwall/update_geoip.py
```

IP-country lookups are performed locally; destination IPs are not sent to an external service. See the [third-party notices](../src/rabbitwall/static/THIRD_PARTY.md) for data sources and licenses. Countries are estimates and may differ from the location of the actual user behind a VPN or CDN.

## Backups and troubleshooting

```sh
sudo python3 setup.py doctor
sudo journalctl -u rabbitwall-control -u rabbitwall-dns -u rabbitwall-dns-observer -u rabbitwall-collector -u rabbitwall-caddy -n 60 --no-pager
sudo nft list table inet rabbitwall_console
```

To back up the database, use SQLite's backup facility or stop the collector before copying it. Do not put backups containing configuration, certificates or traffic history in a public repository. See the [installation guide](INSTALL.md) for certificate registration, renewal and installation recovery.

For IP, NIC, gateway, NAT or DNS configuration corrections, use `setup.py reconfigure --config rabbitwall.json --apply-network` from the RabbitWall host local console. It also updates the application; `update` alone does not apply network changes. See [correcting and reapplying configuration](INSTALL.md#correcting-ip-addresses-and-reapplying-configuration-rabbitwall-host-local-console).

### Countries for dropped DNS

The map uses previously observed successful DNS answer IPs to estimate the country of a dropped UDP DNS question. No new DNS or external GeoIP query is sent, including while closed. Exact domain names are matched case-insensitively; the same client is preferred, with other AI clients as fallback. Answer evidence persists in `history.sqlite3` for up to 30 days, capped at 10,000 client/domain/address records; each dropped question has up to eight address candidates. TTL expiry does not erase this historical evidence, but the map labels it as **DNS inferred**: it is neither the current DNS answer nor proof of a connection. Multiple country candidates produce multiple map routes for one dropped entry; the entry count remains unchanged. The actual DNS destination is preserved in the table and detail panel. Unobserved names, missing country data and addresses unsupported by the local country DB remain unknown; the existing country DB supports IPv4. Evidence begins accumulating after update, using still-retained observations; deleted DNS evidence cannot be recovered.

[Temporary domain approvals and agent request workflow](DOMAIN_APPROVALS.md).
