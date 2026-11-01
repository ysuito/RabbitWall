# OS command reference

[English](OS_COMMANDS.md) | [日本語](OS_COMMANDS.ja.md)

This reference lists external programs launched by RabbitWall's production source, including installation, updates, reconfiguration, certificate tooling and recovery. Test-only Docker and network-namespace commands are excluded. `<...>` represents a configurable value or path; `-f -` supplies generated rules through standard input. These tables are not a script to execute in sequence.

## 1. Normal operation [RabbitWall host]

| Caller / timing | Command example | Purpose / changes |
| --- | --- | --- |
| Collector, about every 5 seconds | `conntrack -L -f ipv4 -o extended,id` | Read IPv4 connection state and counters; does not delete connections |
| Collector, about every 5 seconds | `journalctl -k --since '5 minutes ago' -n 1000 --no-pager --quiet -o json --grep 'rabbitwall-(input\|forward\|output)-drop'` | Read recent firewall rejection logs. The vertical bars are regex alternatives, not shell pipes |
| Controller, status requests / roughly 4-second control cycle | `nft -j -a list table inet rabbitwall_console` | Inspect the Internet gate state and table identifier |
| Controller, startup / node saves | `nft -j -a list ruleset` | Inspect baseline policies, dedicated chains, rule identifiers and offload |
| Controller, startup / gate changes / roughly every 4 seconds while open | `nft -f -` | Initialize the closed gate or update its permission set; open permissions expire after 20 seconds |
| Controller, about every 10 seconds per monitored node | `ping -n -c 1 -W 1 -I <interface> <IPv4>` | Probe node health; disabled monitors are skipped |
| Controller, node saves | `nft -c -f -` → `nft -f -` | Validate and apply management SSH/HTTPS/Ping and probe rules without rebuilding NICs, DNS or the gate |
| Controller, failed node-save recovery | `nft -f -` | Attempt to restore previous node permissions |

Sources: [console.py](../src/rabbitwall/console.py), [control.py](../src/rabbitwall/control.py), [node_config.py](../src/rabbitwall/node_config.py). Generated nftables statements are in [firewall.py](../src/rabbitwall/firewall.py). Collection intervals are configurable; probes take time and are not a strict real-time schedule.

The web service does not execute these commands. It sends control requests over a Unix socket. The separate collector executes the read-only inspection commands.

## 2. Preflight and diagnostics [RabbitWall host]

| Command | Caller / purpose |
| --- | --- |
| `systemctl is-active --quiet <service>` | `setup.py check`: require NetworkManager; detect conflicting ufw, firewalld, docker and default unbound services |
| `ss -H -lntup 'sport = :<port>'` | Inspect bind conflicts on ports 53, 443 and 8765 |
| `ip -j -4 addr` | Verify configured IPv4 addresses are active, including after reconfiguration |
| `unbound -V` | Verify the Unbound build supports dnstap |
| `unbound-checkconf <temporary-config>` | Validate generated Unbound configuration |
| `systemctl is-active <service>` | `setup.py doctor`: display nftables and RabbitWall service states |
| `ip -br -4 addr` | `doctor`: display IPv4 addresses |
| `ss -lntup` | `doctor`: display TCP/UDP listeners |
| `nft list table inet rabbitwall_console` | `doctor`: display gate rules |

Sources: [setup.py](../setup.py), [unbound_config.py](../src/rabbitwall/unbound_config.py). Preflight does not install packages.

## 3. Installation, reconfiguration and application updates [RabbitWall host]

| Command | Condition / purpose |
| --- | --- |
| `nft -c -f -` | Initial install / reconfiguration: validate the baseline, closed gate and node rules |
| `nft list ruleset` | Save runtime rules for recovery |
| `systemctl is-enabled --quiet nftables` | Record automatic-start state for recovery |
| `systemctl show -p LoadState --value <service>` | Check whether a service exists before stopping it |
| `systemctl stop <service>` | Stop RabbitWall services before update / reconfiguration; reconfiguration also stops Caddy |
| `nmcli -t -f UUID,DEVICE connection show --active` | Reconfiguration: identify active profiles on target NICs |
| `nmcli connection modify uuid <UUID> connection.autoconnect no` | Reconfiguration: prevent former active profiles from competing at boot |
| `modprobe nf_conntrack` | Initial install / reconfiguration: load connection tracking |
| `sysctl -p /etc/sysctl.d/90-rabbitwall-router.conf` | Initial install / reconfiguration: apply forwarding and connection-tracking kernel settings |
| `nft -f /etc/nftables.conf` or `nft -f -` | Initial install / reconfiguration: replace the dedicated gateway's complete ruleset |
| `systemctl enable nftables` | Enable loading rules at boot |
| `nmcli general reload`, `nmcli connection reload` | Initial install / reconfiguration: reload NetworkManager and saved profiles |
| `nmcli connection up uuid <UUID>` | Initial install / reconfiguration: activate generated uplink and AI profiles |
| `/usr/bin/python3 -B /opt/rabbitwall/control.py off` | Close with the installed code before replacement and clear remaining permissions after service stops |
| `groupadd --system <group>` | Create rabbitwall-control, rabbitwall-dns and rabbitwall-read groups only if missing |
| `useradd --system --gid rabbitwall-dns --no-create-home --shell /usr/sbin/nologin rabbitwall-dns` | Create the DNS service account only if missing |
| `/usr/bin/python3 -B /opt/rabbitwall/control.py install` | Prepare the closed persistent snippet, node settings directory and operation key; internally validates with `nft -c -f <temporary-file>` |
| `systemctl daemon-reload` | Reload updated service definitions |
| `systemctl enable <services>`, `systemctl restart <service>`, `systemctl is-active --quiet <service>` | Enable and start/check control, dns, dns-observer, collector and web in order |
| `systemctl is-active --quiet rabbitwall-caddy`, `systemctl is-enabled --quiet rabbitwall-caddy` | Determine whether installed Caddy should be restored after update |
| `systemctl restart rabbitwall-caddy`, `systemctl is-active --quiet rabbitwall-caddy` | Restore/check previously active or enabled Caddy after the web service starts |

Reconfiguration of an installed mTLS endpoint also verifies its server certificate and invokes `caddy validate`, as listed below. Ordinary `update` does not reapply NICs, the baseline firewall or sysctl. A node save is separate from `update` and preserves the gate state on success.

Sources: [setup.py](../setup.py), [deploy.py](../tools/deploy.py), [control.py](../src/rabbitwall/control.py).

## 4. Certificate generation and mTLS installation

### Management PC: `tools/mtls.py`

| Command example | Purpose |
| --- | --- |
| `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -aes-256-cbc …` | Generate an encrypted CA private key |
| `openssl req -new -x509 -sha256 -days 3650 …` | Generate the CA certificate |
| `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 …` | Generate server/client private keys |
| `openssl req -new -sha256 -key <key.pem> -subj /CN=<name> …` | Generate a certificate signing request |
| `openssl x509 -req -sha256 -days <days> -CA <ca.crt> -CAkey <ca.key> …` | Sign server/client certificates |
| `openssl version` | Detect OpenSSL/LibreSSL for PKCS#12 compatibility |
| `openssl pkcs12 -export …` | Package the client identity for browser import |
| `openssl verify -CAfile <ca.crt> -purpose sslserver <cert.pem>` | Verify the distribution server certificate chain |
| `openssl verify -CAfile <ca.crt> -purpose sslclient <cert.pem>` | Verify distribution client certificate chains |

`…` omits output paths, extension files and password-file options; see [mtls.py](../tools/mtls.py) for complete arguments. When password files are supplied, arguments contain `file:<path>`, not the password itself.

### RabbitWall host: `tools/install_mtls.py` / reconfiguration

| Command example | Purpose |
| --- | --- |
| `/usr/bin/caddy version` | Check the required Caddy version |
| `openssl verify -CAfile <ca.crt> -purpose sslserver -verify_hostname <console_name> <server.crt>` | Verify CA, purpose and hostname |
| `openssl x509 -in <server.crt> -checkend 86400 -noout` | Check sufficient certificate lifetime during mTLS installation |
| `/usr/bin/caddy validate --config /etc/rabbitwall-mtls/Caddyfile --adapter caddyfile` | Validate HTTPS, client authentication and proxy settings; reconfiguration uses a temporary file |
| `nft -j list chain inet rabbitwall_filter input` | Inspect existing HTTPS permissions |
| `nft -c -f <config-or-temporary-file>`, `nft -f <temporary-file>` | Validate/apply management-PC HTTPS rules; attempt restoration on failure |
| `systemctl daemon-reload`, `systemctl restart rabbitwall-caddy`, `systemctl enable rabbitwall-caddy` | Reload the unit, start Caddy and enable boot startup |
| `systemctl is-active --quiet rabbitwall-caddy`, `systemctl stop rabbitwall-caddy` | Inspect the prior state and restore it after a failure |

Sources: [install_mtls.py](../tools/install_mtls.py), [setup.py](../setup.py). Certificate/configuration copies and permissions are handled through Python file APIs.

## 5. Processes launched by systemd [RabbitWall host]

| Service | Command |
| --- | --- |
| `rabbitwall-control` | `/usr/bin/python3 /opt/rabbitwall/control.py run`; after stopping: `/usr/bin/python3 /opt/rabbitwall/control.py off` |
| `rabbitwall-collector` | `/usr/bin/python3 /opt/rabbitwall/console.py collect` |
| `rabbitwall-web` | `/usr/bin/python3 /opt/rabbitwall/console.py serve` |
| `rabbitwall-dns` | `/usr/sbin/unbound -d -c /etc/rabbitwall-unbound.conf` |
| `rabbitwall-dns-observer` | `/usr/bin/python3 -B /opt/rabbitwall/dnstap_observer.py` |
| `rabbitwall-caddy` | First `caddy validate`, then `/usr/bin/caddy run --config /etc/rabbitwall-mtls/Caddyfile --adapter caddyfile` |

See [systemd/](../systemd/) for definitions. The demo uses the Python running `setup.py` to launch `<python> -B <source>/src/rabbitwall/console.py demo --port <port> --state-dir <dir>`.

## 6. Generated recovery script [only when manually invoked]

`/var/backups/rabbitwall/<timestamp>/restore.sh` stops services (also disables them for initial-install recovery), runs `nft -f <backup>/runtime.nft`, optionally `systemctl disable nftables`, restores files with `cp -a <backup>/etc/. /etc/`, uses `rm -f` for targeted files absent from the backup, and runs `nmcli general reload` and `nmcli connection reload`. Paths are fixed in the generated script, not supplied over HTTP. It uses `dirname` and the shell builtin `cd` to locate itself, and finishes with an `echo` message. It does not execute `reboot`; the operator does so locally.

## 7. Operations without external commands, and Unix sockets

- GeoIP downloads use Python `urllib.request`; database generation/history use the `sqlite3` library. No `curl`, `wget` or `sqlite3` command is launched.
- Most file copies, JSON/configuration writes, backups and permissions use Python file APIs. Shell `cp` and `rm` are used by the recovery script above.
- Unbound performs DNS resolution. The observer parses response copies with dnspython; it does not run `dig`. `tcpdump` is a manual diagnostic tool, not automatically launched.
- Package installation, stopping the default Unbound, and SSH/SCP are operator steps in the installation guide. RabbitWall does not automatically install packages.
- Normal Internet packets are forwarded by the kernel, not by launching Python or an external command for every connection.

| Unix socket | Purpose / access control |
| --- | --- |
| `/run/rabbitwall/control.sock` | Web-to-controller status, gate actions and validated node settings. Owned by `root:rabbitwall-control`; socket mode `0660`, parent directory `0750`. Keeps the web service unprivileged and privileged operations in the controller |
| `/run/rabbitwall-dns/dnstap.sock` | Copies DNS responses from Unbound to the observer. Both run as `rabbitwall-dns`; socket mode `0600`. Observer absence/slowness does not directly stop DNS forwarding |

Both channels stay on the host, require no additional externally reachable TCP listener and use filesystem ownership/group permissions to limit connections. The control service also records peer PID/UID/GID for gate changes and node saves as audit information. Unix sockets do not replace external authentication: management-PC traffic is protected separately by Caddy HTTPS/mTLS.
