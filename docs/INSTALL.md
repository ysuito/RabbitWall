# Installation and update guide

[English](INSTALL.md) | [日本語](INSTALL.ja.md)

## Where to perform each step

| Location | Meaning in this guide | Main tasks |
| --- | --- | --- |
| **Management PC** | Your PC used to operate RabbitWall in a browser | Create, transfer and import certificates; operate the console |
| **RabbitWall host** | The Linux gateway with two wired NICs | Install packages, create configuration, apply network settings, update and recover services |
| **AI host** | A machine accessing the Internet through RabbitWall | Configure its static IP, gateway and DNS; test connectivity |
| **Upstream router** | The existing router upstream of RabbitWall | Add routes or access permissions when needed |

Each command block identifies its execution location. Unless stated otherwise, run commands with relative paths from the **RabbitWall source root on that PC**. If you connect through SSH from the management PC, commands after connecting execute on the remote PC. Initial network application and recovery require a local console on the RabbitWall host.

## 1. [RabbitWall host] Prepare the machine

- Use a Linux machine with two wired NICs. arm64 and amd64 are the intended architectures. Check interface names with `ip -br link`.
- Use Debian 13 or later, or Ubuntu 24.04, with Python 3.11 or later, and systemd. Both NICs must **already be managed by NetworkManager**. On derivatives such as Raspberry Pi OS, verify package, NIC and service differences on the actual machine.
- **Debian 12 and earlier are not supported.** Their standard `python3-dnspython` package does not meet the required version (>=2.6.1,<3). Use Debian 13 or later.
- **Prepare on the management PC / upstream router:** assign the management PC a static IP or configure a DHCP reservation on the router. Keep the upstream and AI networks on separate, non-overlapping subnets.
- For initial installation, have a local display and keyboard, a serial console, or equivalent access. Do not change NIC settings using SSH as your only connection.
- Automatic integration with Docker, UFW, firewalld, existing VPNs or complex policy routing is not supported.

Obtain the public repository and work from its root directory. Run the following on the machine where you will install RabbitWall.

**Run on: RabbitWall host terminal**

```sh
sudo apt update
sudo apt install python3 python3-dnspython python3-protobuf unbound conntrack nftables iproute2 iputils-ping kmod
python3 -c "import dns, google.protobuf; print(dns.__version__, google.protobuf.__version__)"
unbound -V
sudo systemctl disable --now unbound
systemctl is-active NetworkManager
ip -br -4 addr
nmcli -f NAME,DEVICE connection show --active
```

If the machine does not use NetworkManager, configure it using the appropriate procedure for that OS, or install a supported OS. Do not automatically replace the current network manager over an existing SSH connection.

**DNS components on the RabbitWall host:** Unbound forwards DNS; a separate dnstap receiver provides domain evidence. Unbound must be built with dnstap support: confirm that `unbound -V` above includes `--enable-dnstap`. Setup also checks this capability.

The command above stops and disables the package's default `unbound.service`. RabbitWall uses its dedicated `rabbitwall-dns.service`; automatic integration with an Unbound instance serving other purposes is not supported. Observation requires dnspython >=2.6.1,<3 and the OS `python3-protobuf` package. No extra DNS installer is needed.

## 2. [RabbitWall host] Create the configuration

**Run on: RabbitWall host terminal**

```sh
python3 setup.py init
```

The interactive command creates `rabbitwall.json`. You can edit the JSON later to add monitored nodes or change the site's map display. To start without prompts:

**Run on: RabbitWall host terminal**

```sh
cp examples/rabbitwall.example.json rabbitwall.json
```

| Setting | Meaning |
| --- | --- |
| `uplink_if` / `uplink_cidr` | Upstream NIC and the RabbitWall machine's static IP/prefix |
| `gateway` | Router directly reachable through the upstream NIC |
| `management_cidr` / `admin_ip` | Management network and the one PC allowed to connect |
| `ai_if` / `ai_cidr` | AI-side NIC and the RabbitWall machine's AI-side IP/prefix |
| `dns_upstream` | Upstream DNS server. Do not use the RabbitWall machine itself or an address in the AI subnet |
| `nat` | `true` enables upstream NAT; `false` requires an upstream return route to the AI subnet |
| `console_name` | A hostname under `.home.arpa`, used in the certificate |
| `label` | Display name of the RabbitWall machine |
| `nodes` | Monitored nodes: `id`, `label`, `ip` and the `interface` used to reach each node; up to 12 |
| `site_label` / `site_location` | Site name on the map and `[longitude, latitude]` |

The example uses management PC `192.168.10.10`, RabbitWall upstream `192.168.10.2/24`, upstream router/DNS `192.168.10.1`, AI-side interface `192.168.20.1/24`, and AI host `192.168.20.10`.

With NAT, upstream DNS normally sees queries from RabbitWall's upstream NIC address. In routed mode, provide an upstream return route to the AI subnet and permit DNS queries from that subnet. If the management PC is on another subnet, also provide routing and access permissions from that network to the RabbitWall machine.

## 3. [RabbitWall host] Review and apply the plan

**Run on: RabbitWall host terminal**

```sh
python3 setup.py plan
sudo python3 setup.py check
cat output/install-plan/PLAN.txt
```

Generated files include nftables, NetworkManager, kernel settings and Unbound configuration (`unbound.conf`). `plan` does not change the OS and refuses to overwrite existing output. After changing the configuration, generate another plan with `--output output/another-plan`. `check` checks required packages, NICs, NetworkManager, conflicting services and ports.

Review `nftables.conf` and `*.nmconnection`, then run the following **from a local console on the RabbitWall machine**.

**Run on: RabbitWall host local console**

```sh
sudo python3 setup.py install --plan output/install-plan --apply-network
```

This replaces the firewall with dedicated rules, enables IP forwarding and connection-tracking byte accounting, and installs static IP profiles with IPv6 disabled. The AI-side profile keeps its IP address even without carrier. If existing profiles automatically connect on either NIC, inspect `nmcli connection show` and disable `connection.autoconnect` on unwanted profiles so that an old profile does not return after reboot.

Configuration is stored in `/etc/rabbitwall.json`, generated Unbound configuration in `/etc/rabbitwall-unbound.conf`, code in `/opt/rabbitwall`, and history in `/var/lib/rabbitwall`. Original files and firewall rules are backed up under `/var/backups/rabbitwall/TIMESTAMP/`. If RabbitWall is already installed, use the update procedure below.

## 4. Set up mTLS for the management PC

There is no browser token to enter. Install a client certificate on the management PC; the private operation key is used only between Caddy and the backend. SSH port forwarding remains available for read-only access, but gate operations require an mTLS connection.

### 4.1 [RabbitWall host] Install Caddy

Install the official package using the [Caddy Debian/Ubuntu instructions](https://caddyserver.com/docs/install#debian-ubuntu-raspbian). **Version 2.11.7 or later** is required. An older distribution package may be insufficient.

On a new installation only, stop the package's default service. RabbitWall uses a separate `rabbitwall-caddy.service`. Automatic integration with a machine already running Caddy for other purposes is not supported.

**Run on: RabbitWall host terminal**

```sh
caddy version
sudo systemctl disable --now caddy
```

### 4.2 [Management PC] Retrieve configuration and create certificates

Prepare Python, OpenSSL and the same source version as the RabbitWall host on the management PC. From the management PC's source root, retrieve the configuration already applied to the RabbitWall host. Replace `USER` and the IP below with that host's SSH username and upstream IP. Skip this copy if an identical configuration file is already present.

**Run on: management PC terminal**

```sh
scp USER@192.168.10.2:/etc/rabbitwall.json ./rabbitwall.json
```

Create the certificates on this same management PC. Do not transfer the CA private key or the management PC's private key to the RabbitWall machine. The following commands prompt for passwords. Store the CA password and the client-certificate import password securely.

**Run on: management PC terminal**

```sh
python3 tools/mtls.py --config rabbitwall.json init
python3 tools/mtls.py --config rabbitwall.json issue-server server
python3 tools/mtls.py --config rabbitwall.json issue-client admin
python3 tools/mtls.py --config rabbitwall.json bundle --server server --client admin --output output/mtls-bundle
```

### 4.3 [Management PC] Send the certificate bundle to the RabbitWall host

Transfer **only** `output/mtls-bundle` to the RabbitWall machine. Replace the example destination and username with your own.

**Run on: management PC terminal**

```sh
scp -r output/mtls-bundle USER@192.168.10.2:~/
```

### 4.4 [RabbitWall host] Apply the certificate bundle

Switch to the RabbitWall host and run this from its source root:

**Run on: RabbitWall host terminal**

```sh
sudo python3 tools/install_mtls.py ~/mtls-bundle
```

### 4.5 [Management PC] Import certificates and open the browser

Return to the management PC. In this example, add `192.168.10.2 rabbitwall.home.arpa` to the management PC's hosts file. On macOS, use Keychain Access to trust `output/rabbitwall-pki/ca.crt` as a root CA and import `output/rabbitwall-pki/admin/identity.p12` into the login keychain. On Windows, import the CA into Trusted Root Certification Authorities and the P12 into Personal. If Firefox does not use the OS certificate store in your configuration, import the CA and client certificate through Firefox's certificate manager.

Open `https://rabbitwall.home.arpa/` and select the management PC's client certificate when prompted. If you see a warning, fix the hosts entry, certificate SAN or CA trust; do not bypass the warning. Server and client certificates are valid for 365 days by default. To renew, run `issue-server` / `issue-client` with new names and create another `bundle` on the management PC. Reapply it to the RabbitWall host using steps 4.3–4.4, then import the new P12 on the management PC. Keep the CA key on the management PC.

**Configure on: upstream router (only when needed)**

If an upstream router sits between the management PC and RabbitWall, allow the management PC to reach RabbitWall on TCP port 443.

## 5. Configure and check AI hosts

### 5.1 [AI host] Configure IP, gateway and DNS

The example AI host uses `192.168.20.10/24`, with gateway and DNS both set to `192.168.20.1`. RabbitWall does not provide DHCP. Remove alternate paths through other Wi-Fi connections or DNS servers.

On an AI host using NetworkManager, replace the connection and NIC placeholders below with their actual names. If its existing IP settings are already correct, change only DNS.

**Run on: AI host terminal**

```sh
nmcli -f NAME,DEVICE connection show --active
sudo nmcli connection modify 'CONNECTION_NAME' ipv4.method manual ipv4.addresses '192.168.20.10/24' ipv4.gateway '192.168.20.1' ipv4.dns '192.168.20.1' ipv4.ignore-auto-dns yes ipv6.method disabled
sudo nmcli device reapply 'AI_HOST_NIC'
```

### 5.2 [Management PC → AI host] Test access and gate operation

On the management PC, open the RabbitWall console in the browser and set the gate to **開 (open)**. Then switch to the AI host and run:

**Run on: AI host terminal**

```sh
dig +time=2 +tries=1 @192.168.20.1 example.com
dig +tcp +time=2 +tries=1 @192.168.20.1 example.com
curl -I --connect-timeout 5 https://example.com
```

Return to the management PC's browser and set the gate to **閉 (closed)**. Repeat the connectivity checks on the AI host and confirm that DNS and outbound traffic stop. Also confirm from the management PC that SSH to the RabbitWall host remains available. Short connections may finish between collection intervals of about five seconds and go unobserved. Inferred domains match positive DNS answers for the same client against destination IPs; they do not establish the HTTPS hostname. Traffic rankings accumulate observed counter differences after installation and omit bytes transferred before the first observation or during collection gaps.

### 5.3 [RabbitWall host → AI host] Verify DNS and observer independence

**Run on: RabbitWall host terminal**

```sh
systemctl is-active rabbitwall-dns rabbitwall-dns-observer
sudo unbound-checkconf /etc/rabbitwall-unbound.conf
sudo systemctl stop rabbitwall-dns-observer
```

With the gate open in the management PC's console, repeat the DNS checks from step 5.2 on the AI host. Unbound continues resolving while the observer is stopped. New DNS responses during this gap do not update domain hints. Restart observation after the check.

**Run on: RabbitWall host terminal**

```sh
sudo systemctl start rabbitwall-dns-observer
```

Resolve again from the AI host and check inferred domains for new sessions in the management PC's console. Unbound cache responses are also observed. Then close the gate from the management PC and repeat UDP/TCP DNS checks on the AI host; cached names must also be blocked.

### 5.4 [Management PC / upstream router] Add an SSH route to AI hosts (optional)

Even in NAT mode, the management PC needs a route to reach the AI subnet. In this example, add `192.168.20.0/24 → 192.168.10.2` on the management PC, or add that route on the upstream router. A temporary check on a Linux management PC:

**Run on: management PC terminal (Linux example)**

```sh
sudo ip route add 192.168.20.0/24 via 192.168.10.2
```

Make the route persistent using your management PC's OS configuration. The generated firewall controls SSH, HTTPS and Ping from the configured management PC to AI hosts according to their node permissions. This additional route is not needed just to access the console.

## 6. [RabbitWall host] Download IP-country data (optional)

To enable country labels, download DB-IP Country Lite after installation. **Setup does not download it automatically.** The console works without it, but cannot display countries for public IP addresses.

**Run on: RabbitWall host terminal**

```sh
sudo python3 /opt/rabbitwall/update_geoip.py
```

This downloads the current month's data, converts it into a local IP-country database, and saves it to `/var/lib/rabbitwall/geoip-country.sqlite3`. The RabbitWall host itself needs Internet access. The AI network's Internet gate can remain closed during this operation.

Afterward, reload the console in the management PC's browser and check the database status and edition under **設 — Settings**. Use the same command for later updates. No automatic update schedule is configured. See the [daily operation guide](OPERATIONS.md) for data attribution, licensing and operational notes.

## Updates [RabbitWall host → management PC]

After updating the RabbitWall source, run this on the RabbitWall machine:

**Run on: RabbitWall host terminal**

```sh
sudo python3 setup.py update
```

This updates the application, DNS and service definitions together while preserving configuration, NAT, mTLS and saved UI node settings. An installed Caddy service that was active or enabled is restarted and checked after the web service starts. **The gate is closed immediately after an update.** After the command finishes, return to the management PC's browser, force-reload it, verify the displayed state, and then reopen the gate if appropriate.

## Correcting IP addresses and reapplying configuration [RabbitWall host local console]

`init` creates an input file; it does not change an installed system. `update` uses `/etc/rabbitwall.json` and does not reconfigure NICs or the baseline firewall. To correct an installation or change network settings, edit `rabbitwall.json` in the source directory, including node addresses, interfaces, management PC address, gateway, DNS and NAT as appropriate. Then run:

**Run on: RabbitWall host local console, in the source directory**

```sh
sudo python3 setup.py reconfigure --config rabbitwall.json --apply-network
sudo python3 setup.py doctor
```

Do not run the network change over SSH: changing the addresses or firewall can disconnect it. The command validates the input, Unbound configuration and firewall, then backs up the existing configuration and runtime firewall. It applies both NetworkManager profiles, routing settings, firewall, NAT and DNS, saves `/etc/rabbitwall.json`, and deploys the application and services. A separate `update` is unnecessary. This clears `/etc/rabbitwall-nodes/nodes.json` and applies the supplied JSON nodes; copy wanted UI nodes into the input file first. The gate finishes **closed**. Check management access and DNS before reopening it.

Existing mTLS certificates, keys, operation key and history are retained. Caddy's bind address, management PC restriction and HTTPS firewall rule are regenerated when mTLS is installed. A changed console hostname requires a matching server certificate; an incompatible certificate is rejected before network changes. If the uplink IP changes, update the management PC's hosts/DNS entry for the console hostname; AI hosts also need their gateway/DNS settings adjusted if the AI-side address changes. Upstream static routes must match the new subnets when NAT is disabled.

Previously active connection profiles on the two target NICs have automatic connection disabled; the generated `rabbitwall-uplink` and `rabbitwall-ai` profiles are activated by UUID to avoid ambiguous names. This is not a migration tool for moving to different physical NICs; disconnect or retire unused NIC profiles separately.

The backup location and `restore.sh` path are printed **before** application. After services stop, a failure leaves the gate closed; fix the cause locally and rerun the same command. To restore the saved network configuration instead:

**Run on: RabbitWall host local console; replace TIMESTAMP with the printed backup directory**

```sh
sudo sh /var/backups/rabbitwall/TIMESTAMP/restore.sh
sudo reboot
```

Restore returns to the saved configuration, which may itself contain the original mistake. Keep the backup private. Full service operation, NetworkManager activation and reboot behavior should be checked on the actual host after reconfiguration.

## Troubleshooting and recovery [RabbitWall host]

**Run on: RabbitWall host terminal**

```sh
sudo python3 setup.py doctor
sudo journalctl -u rabbitwall-control -u rabbitwall-dns -u rabbitwall-dns-observer -u rabbitwall-collector -u rabbitwall-caddy -n 60 --no-pager
```

- Missing DNS listen address: check the AI-side profile, NIC name and NetworkManager carrier settings.
- Missing byte counters: check that `sysctl net.netfilter.nf_conntrack_acct` is 1. Accounting applies to new connections established after enabling it.
- DNS returns SERVFAIL: check Unbound logs, upstream DNS access rules and routing. Timeouts while the gate is closed are expected.
- Unbound exits with `getifaddrs: Address family not supported by protocol`: check `systemctl cat rabbitwall-dns`. Its `RestrictAddressFamilies` must permit `AF_NETLINK` as well as `AF_INET` and `AF_UNIX`; Linux interface enumeration uses Netlink. Apply the current service definition with `setup.py update`, then check DNS again with the gate open.
- DNS works but no new domain hints appear: check the observer service/logs, `/run/rabbitwall-dns/dnstap.sock` and observation JSON updates. Buffered events may arrive late, but dropped events cannot be recovered; query again from the client after observation resumes.
- mTLS connection fails: check the management PC's IP, hosts entry, CA trust, client certificate and expiry, and Caddy version.

To undo the initial installation, run the displayed backup's `restore.sh` **from a local console**. It stops services and restores the original firewall and saved settings. Reboot locally afterward to reactivate the original NIC profiles and kernel settings.

**Run on: RabbitWall host local console**

```sh
sudo sh /var/backups/rabbitwall/ACTUAL_TIMESTAMP/restore.sh
sudo reboot
```

Recovery does not delete the history database or source. Separate mTLS installation backups are stored in `/etc/rabbitwall/backups`.

Before a code update, application files are saved under the displayed `/var/backups/rabbitwall/application-TIMESTAMP/`. If an update fails, Internet access remains closed. Fix the cause from a local console and rerun `setup.py update`. To restore old code, stop all five services (control, dns, dns-observer, collector and web), restore the backup's `opt/rabbitwall/` and `etc/` to their original paths, run `systemctl daemon-reload`, and restart control, dns, dns-observer, collector and web in that order. Keep the new groups and directory permissions. This application backup does not contain the initial network recovery script.
