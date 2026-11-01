# Program flow overview

[English](PROGRAM_FLOW.md) | [日本語](PROGRAM_FLOW.ja.md)

These diagrams group the main function calls and data paths by responsibility. Solid arrows indicate requests, calls or I/O; dotted arrows indicate file handoffs. Function names match the implementation. Main successful paths are simplified; helpers appear in the index below. Diagrams use GitHub-compatible Mermaid syntax.

See the [OS command reference](OS_COMMANDS.md) for external commands, callers and the two Unix sockets.

## 1. Runtime overview

Linux kernel nftables rules forward or block normal traffic; Python does not relay every packet. Unbound handles DNS, while an independent Python dnstap observer parses copies of responses. Web, collection, control, DNS and DNS observation run as separate systemd services.

```mermaid
flowchart TB
    Browser["Management PC / browser"] -->|HTTPS / mTLS| Caddy["Caddy"]
    Caddy -->|HTTP / loopback| Web["console.py / serve"]
    Web -->|Unix socket| Control["control.py / run"]
    Control -->|nft command| Kernel["Linux kernel / nftables"]
    AI["AI host"] -->|Internet traffic| Kernel
    Kernel -->|Allowed traffic| Up["Upstream router"]
    AI -->|DNS / kernel gate| DNS["Unbound / rabbitwall-dns"]
    DNS -->|UDP or TCP| Resolver["Upstream DNS"]
    DNS -.->|dnstap / Unix socket| Observer["dnstap_observer.py"]
    Observer -.->|observations.json| Collector["console.py / collect"]
    Kernel -->|conntrack + journalctl| Collector
    Collector -.->|state.json| Web
    Collector -->|sqlite3| History[("history.sqlite3")]
    Country[("geoip-country.sqlite3")] -->|sqlite3 / read only| Web
```

## 2. Installation and updates

The entry point is setup.main(). plan only generates configuration files. Initial install changes firewall and NIC settings; update preserves installed settings while deploying the application. deploy() closes the gate using old code, stops services and clears any remaining permission before replacing files.

```mermaid
flowchart TB
    Main["setup.main()"] --> Init["init()"]
    Init -.-> Config["rabbitwall.json"]
    Main --> Load["settings.load() / validate()"]
    Config -.-> Load
    Load --> Plan["plan() / assets()"]
    Plan --> Rules["firewall.baseline(), gate(), dns_rule(), probe_rules()"]
    Rules --> NAT{"nat enabled?"}
    NAT -->|yes| Masq["Include masquerade rules"]
    NAT -->|no| Routed["Keep original source IP"]
    Masq -.-> Files["output/install-plan"]
    Routed -.-> Files
    Main --> Install["install()"]
    Install --> Check["check() / port_conflicts() / require_observer()"]
    Check --> Apply["Backup / nft validation / sysctl / nmcli"]
    Files -.-> Apply
    Apply --> Deploy["deploy_application() → deploy.deploy()"]
    Main -->|reconfigure| Reconfigure["reconfigure(): validate / backup / apply NIC + firewall + mTLS"]
    Reconfigure --> Deploy
    Main -->|update| Deploy
    Deploy --> HTTPS["Restart/check installed active or enabled Caddy after web starts"]
    Deploy --> DNSCheck["require_unbound() / render() / check_config()"]
    DNSCheck --> Close["close_installed() / stop services / clear lease"]
    Close --> Copy["deployment_files() / backup / copy files"]
    Copy --> Persist["control.main(install) → install_persistent()"]
    Persist --> Start["systemctl / start five services / gate CLOSED"]
```

## 3. Collection and rankings

After collect_once() finishes, the collector waits about five seconds by default. Failure does not mark previous connections ended; errors are included in JSON. Rankings use cumulative-counter deltas, with the first observation establishing a baseline.

```mermaid
flowchart TB
    Main["console.main(collect)"] --> Collect["collect_once()"]
    Collect --> Observe["load_observations()"]
    Obs["observations.json"] -.-> Observe
    Collect --> Cmd["command() → subprocess.run()"]
    Cmd --> Conn["conntrack -L"]
    Conn --> Parse["parse_conntrack() → flow_scope() / scope()"]
    Observe --> Hist["update_history() → domain_hints()"]
    Parse --> Hist
    Hist --> DB[("history.sqlite3 / flows")]
    Collect --> Analytics["collect_analytics()"]
    Analytics --> Schema["schema() → register_domains()"]
    Schema --> Sample["sample_traffic()"]
    Sample --> Compact["compact_traffic(): minutes → hours / 30 days"]
    Compact --> Summary["summarize() → rankings(): 1h / 24h / 7d / 30d"]
    Summary --> Commit["Annotate first_seen / commit"]
    Commit --> DB2[("known_domains / traffic_samples / traffic_minutes / traffic_hours")]
    Cmd --> Journal["journalctl -k → parse_journal()"]
    Hist --> State["atomic_json()"]
    Commit --> State
    Journal --> State
    State -.-> JSON["state.json"]
```

## 4. DNS forwarding and domain evidence

Unbound owns upstream UDP/TCP queries, caching and DNS responses. CLIENT_RESPONSE dnstap events include cached replies. The observer decodes events with Protocol Buffers and parses DNS responses with dnspython. It matches client IP, answer IP, CNAME and remaining TTL, then publishes the existing observation JSON format.

Unbound and the observer have no startup dependency on each other. DNS continues when observation stops or falls behind, at the cost of lost events. nftables blocks closed-gate DNS, including cache replies. The observer is outside the DNS forwarding path.

```mermaid
flowchart TB
    Config["unbound_config.render() / check_config()"] -.-> File["/etc/rabbitwall-unbound.conf"]
    File -.-> DNS["Unbound / rabbitwall-dns.service"]
    Client["AI host"] -->|DNS through kernel gate| DNS
    DNS --> Cache{"Cache hit?"}
    Cache -->|yes| Answer["Client response / remaining TTL"]
    Cache -->|no| Up["Configured upstream / UDP or TCP"]
    Up --> Answer
    Answer -->|Through kernel gate| Client
    Answer -.->|Asynchronous dnstap event| Socket["Unix socket / Frame Streams"]
    Socket --> Session["dnstap_observer.main() → ObserverServer / FrameSession.run()"]
    Session --> Decode["ingest() / dnstap_pb2 + protobuf"]
    Decode --> Filter["Check client, endpoint, event type and response time"]
    Filter --> Parse["dnspython: dns.message.from_wire()"]
    Parse --> Evidence["dns_evidence.Evidence.observe() / CNAME and TTL"]
    Evidence --> Memory["Bounded records / memory"]
    Loop["publish_loop() / every 2 seconds"] --> Publish["Evidence.publish()"]
    Memory --> Publish
    Publish -.-> Obs["observations.json"]
    Obs -.-> Hints["Collector: load_observations() / domain_hints()"]
    Socket -.-> Loss["Observer absent or slow: evidence may be lost"]
```

## 5. Gate control and node health

The web service sends fixed gate actions and validated node-only settings over a Unix socket. Node saves replace dedicated management-access and probe chains without touching the gate, NICs or DNS. Settings are backed up and atomically written per file to `/etc/rabbitwall-nodes/nodes.json` and the persistent firewall snippet; write failures attempt to restore files and live permissions. Monitoring and management SSH/HTTPS/Ping are independent. While open, a 20-second permission lease is renewed about every four seconds. Restart, table recreation or lease expiry does not automatically restore access. Health probes run about every ten seconds in a separate thread.

```mermaid
flowchart TB
    UI["app.js: setInternet() / refreshControl()"] --> API["Handler.do_POST() / do_GET()"]
    API --> Request["control_status() → request_control()"]
    Request --> Socket["Unix socket / JSON action"]
    Socket --> Handler["run_controller(): Handler.handle()"]
    Handler --> SaveNodes["Controller.save_nodes() / node_config.save()"]
    SaveNodes --> ACL["node_rule_batch() / node ACL + probe chains"]
    SaveNodes -.-> SavedNodes["nodes.json + backups + persistent nft snippet"]
    Handler --> Status["Controller.status() → read_gate()"]
    Handler --> Set["Controller.set_enabled()"]
    Set --> Status
    Set --> Apply["apply_enabled()"]
    Apply --> Nft["nft() → subprocess.run(nft)"]
    Nft --> Kernel["online_sources / kernel timeout 20s"]
    Loop["run_controller() loop"] -->|About every 4 seconds| Tick["Controller.tick()"]
    Tick --> Status
    Tick -->|Renew while enabled| Apply
    Loop -->|About every 10 seconds| Probe["probe_nodes()"]
    Probe --> Ping["ThreadPoolExecutor / subprocess.run(ping)"]
    Ping --> Nodes["Controller.nodes / health status"]
    Nodes --> Status
    Boot["Controller.__init__()"] --> Runtime["install_runtime() → baseline() / nft()"]
    Runtime --> Closed["Replace gate atomically / starts CLOSED"]
```

## 6. Web API and browser rendering

Caddy checks client certificates and source IP, injects the server-side operation key, and rewrites Host and Origin for the backend. Country labels are added from a local DB when the web service reads JSON. Demo mode uses demo_state() and an in-memory simulated gate. Rendering, animation and theme storage use browser APIs without external JavaScript libraries.

```mermaid
flowchart TB
    Browser["Browser / app.js"] --> Caddy["Caddy / mTLS + source IP"]
    Caddy --> Guard["make_handler(): Handler.valid_request()"]
    Guard --> GET["Handler.do_GET()"]
    Guard --> POST["Handler.do_POST() / body and token checks"]
    GET -->|/api/state| State["Read state.json"]
    State --> Enrich["CountryLookup.enrich()"]
    Enrich --> Lookup["lookup() / _reload() / status()"]
    Lookup --> SQL["sqlite3 / local country database"]
    Enrich --> Meta["settings.metadata() / stale flag"]
    Meta --> Payload["send_payload() / JSON"]
    GET -->|/api/control| Control["control_status() / access_status()"]
    Control --> Payload
    POST -->|/api/internet| Change["control_status(enable or disable)"]
    Change --> Payload
    Payload --> Refresh["refresh() / refreshControl()"]
    Refresh --> Render["render() / renderControl() / renderAnalytics() / renderGeoip()"]
    Render --> Map["SessionAtlas.update() → groupFlows()"]
    Map --> Layout["layout() / projection / paintList() / paintDetail()"]
    Layout --> Draw["draw() / paintBackground() / requestAnimationFrame"]
    World["world.json / Natural Earth"] -.-> Layout
    Theme["applyTheme() / localStorage"] --> Render
```

## 7. Certificates, country data and release assets

These tools run on demand. CA and client private keys stay on the management PC. Country data is an optional HTTPS download, converted from CSV into SQLite and atomically replaced; conversion failure preserves the old DB. The map builder converts input GeoJSON, while release packaging uses a file allowlist.

```mermaid
flowchart TB
    subgraph Admin["Management PC / tools/mtls.py"]
        Init["init_ca()"] --> OpenSSL["openssl() → OpenSSL command"]
        Issue["issue() / server or client"] --> OpenSSL
        OpenSSL --> PKI["Certificates and keys"]
        PKI --> Bundle["bundle() / caddyfile() / validate_network()"]
    end
    Bundle -.-> Transfer["Copy server bundle to RabbitWall host"]
    Transfer --> Install["install_mtls.install()"]
    Install --> Validate["OpenSSL verify / Caddy validate / nft check"]
    Validate --> Apply["persistent_config() / web_rule() / runtime_batch()"]
    Apply --> Live["Write private files / nft transaction / Caddy service"]
    Geo["tools/update_geoip.main()"] --> HTTP["urllib.request / HTTPS"]
    HTTP --> Build["build_database() / gzip / csv / ipaddress"]
    Build --> SQL["sqlite3 / atomic replacement"]
    SQL -.-> Country["geoip-country.sqlite3"]
    Map["tools/build_world_map.main()"] --> Convert["convert() / rounded() / hashlib"]
    Convert -.-> World["world.json"]
    Release["tools/release.build()"] --> Sources["sources() / release-files.txt"]
    Sources --> Archive["tarfile / source archive / SHA-256"]
```

## Dependency boundaries

| Dependency | Purpose | Main integration points | Type |
| --- | --- | --- | --- |
| dnspython | Observed DNS response parsing | ingest(), Evidence.observe() | External Python package |
| protobuf / dnstap_pb2 | Decode dnstap events using the official schema | ingest() | External Python package + generated binding |
| Unbound | DNS forwarding, caching and asynchronous dnstap output | unbound_config.render(), rabbitwall-dns.service | External DNS service |
| sqlite3 | History, analytics and country DB | console, traffic_analytics, geoip, update_geoip | Python standard library |
| socket, socketserver, http.server, threading | HTTP listeners, Unix sockets and concurrency limits | dnstap_observer, console, control | Python standard library |
| subprocess, concurrent.futures | OS commands and probe worker | command(), nft(), probe_nodes(), run() | Python standard library |
| urllib.request, gzip, csv, ipaddress | DB-IP download, decompression and validation | update_geoip.main(), build_database() | Python standard library |
| nft, conntrack, journalctl, ping | Firewall, connections, logs and health | control.nft(), console.command(), probe_nodes() | OS commands |
| nmcli, sysctl, modprobe, systemctl | NIC, kernel and service setup | setup.install(), deploy.deploy() | OS commands |
| OpenSSL, Caddy | Certificate generation, verification and mTLS | mtls.openssl(), install_mtls.install() | External programs |
| fetch, Canvas 2D, requestAnimationFrame, localStorage | API requests, map, animation and theme storage | app.js, atlas.js | Browser APIs |
| Natural Earth, DB-IP Country Lite | Map geometry and IP-country mapping | world.json, geoip-country.sqlite3 | Data |

## Python function index

Helpers and methods are included; constructors and generated code are omitted. See [dnstap_pb2.py](../src/rabbitwall/dnstap_pb2.py) for the official schema binding and [schema notes](../third_party/dnstap/README.md) for provenance and regeneration.

### [setup.py](../setup.py)

`run()`, `init()`, `assets()`, `plan()`, `port_conflicts()`, `check()`, `mtls_assets()`, `reconfigure()`, `install()`, `deploy_application()`, `doctor()`, `main()`

### [src/rabbitwall/console.py](../src/rabbitwall/console.py)

`utc_now()`, `scope()`, `flow_scope()`, `parse_conntrack()`, `parse_journal()`, `command()`, `update_history()`, `atomic_json()`, `collect_once()`, `demo_state()`, `ConsoleServer.__init__()`, `ConsoleServer.get_request()`, `ConsoleServer.process_request()`, `ConsoleServer.process_request_thread()`, `make_handler()`, `make_handler.control_status()`, `make_handler.nodes_status()`, `make_handler.Handler.log_message()`, `make_handler.Handler.valid_token()`, `make_handler.Handler.access_status()`, `make_handler.Handler.valid_request()`, `make_handler.Handler.send_payload()`, `make_handler.Handler.do_POST()`, `make_handler.Handler.do_GET()`, `main()`

### [src/rabbitwall/control.py](../src/rabbitwall/control.py)

`utc_now()`, `nft()`, `request_control()`, `read_gate()`, `baseline()`, `install_runtime()`, `apply_enabled()`, `probe_nodes()`, `Controller.__init__()`, `Controller.status()`, `Controller.node_settings()`, `Controller.save_nodes()`, `Controller.set_enabled()`, `Controller.tick()`, `run_controller()`, `run_controller.stop()`, `run_controller.Handler.handle()`, `install_persistent()`, `main()`

### [src/rabbitwall/dependencies.py](../src/rabbitwall/dependencies.py)

`check_dns_version()`, `require_dns()`, `require_observer()`

### [src/rabbitwall/dns_evidence.py](../src/rabbitwall/dns_evidence.py)

`Evidence.observe()`, `Evidence.publish()`

### [src/rabbitwall/dns_observations.py](../src/rabbitwall/dns_observations.py)

`load_observations()`, `domain_hints()`

### [src/rabbitwall/dnstap_observer.py](../src/rabbitwall/dnstap_observer.py)

`control_frame()`, `parse_control()`, `ingest()`, `FrameSession.read_exact()`, `FrameSession.run()`, `ObserverServer.handle_error()`, `ObserverHandler.handle()`, `publish_loop()`, `main()`

### [src/rabbitwall/firewall.py](../src/rabbitwall/firewall.py)

`dns_rule()`, `node_rule_batch()`, `probe_rules()`, `gate()`, `baseline()`

### [src/rabbitwall/geoip.py](../src/rabbitwall/geoip.py)

`CountryLookup._reload()`, `CountryLookup.status()`, `CountryLookup.lookup()`, `CountryLookup.enrich()`

### [src/rabbitwall/node_config.py](../src/rabbitwall/node_config.py)

`revision()`, `document()`, `candidate()`, `atomic_write()`, `save()`

### [src/rabbitwall/settings.py](../src/rabbitwall/settings.py)

`interface()`, `validate()`, `validate.usable()`, `load()`, `monitored()`, `management_allowed()`, `metadata()`, `require_config()`

### [src/rabbitwall/traffic_analytics.py](../src/rabbitwall/traffic_analytics.py)

`schema()`, `public_ai()`, `names_of()`, `counter()`, `register_domains()`, `sample_traffic()`, `compact_traffic()`, `rankings()`, `rankings.serialize()`, `summarize()`, `collect_analytics()`

### [src/rabbitwall/unbound_config.py](../src/rabbitwall/unbound_config.py)

`render()`, `require_unbound()`, `check_config()`

### [tools/build_world_map.py](../tools/build_world_map.py)

`rounded()`, `convert()`, `main()`

### [tools/deploy.py](../tools/deploy.py)

`run()`, `close_installed()`, `deployment_files()`, `deploy()`

### [tools/install_mtls.py](../tools/install_mtls.py)

`run()`, `persistent_config()`, `web_rule()`, `runtime_batch()`, `install()`

### [tools/mtls.py](../tools/mtls.py)

`configure()`, `openssl()`, `new_directory()`, `write()`, `password_args()`, `valid_name()`, `init_ca()`, `issue()`, `validate_network()`, `caddyfile()`, `bundle()`, `main()`

### [tools/release.py](../tools/release.py)

`sources()`, `build()`

### [tools/update_geoip.py](../tools/update_geoip.py)

`build_database()`, `main()`

## Browser function index

Named functions and SessionAtlas methods are listed below. Constructors and anonymous event handlers are omitted.

### [src/rabbitwall/static/app.js](../src/rabbitwall/static/app.js)

`setSessionView()`, `resetAtlasView()`, `countryText()`, `direction()`, `navigate()`, `renderGeoip()`, `endpoint()`, `clock()`, `bytes()`, `cell()`, `renderControl()`, `refreshControl()`, `setInternet()`, `render()`, `newDomainBadge()`, `timestampText()`, `renderAnalytics()`, `refresh()`, `applyTheme()`

### [src/rabbitwall/static/atlas.js](../src/rabbitwall/static/atlas.js)

`endpointNode()`, `routeColor()`, `groupFlows()`, `quadratic()`, `hash()`, `wrapLongitude()`, `projection()`, `unwrapRing()`, `pacificInset()`, `toggledSelection()`, `SessionAtlas.color()`, `SessionAtlas.setTheme()`, `SessionAtlas.resetPosition()`, `SessionAtlas.wheelZoom()`, `SessionAtlas.startPan()`, `SessionAtlas.movePan()`, `SessionAtlas.endPan()`, `SessionAtlas.setActive()`, `SessionAtlas.setPaused()`, `SessionAtlas.update()`, `SessionAtlas.paintSummary()`, `SessionAtlas.paintList()`, `SessionAtlas.select()`, `SessionAtlas.clearSelection()`, `SessionAtlas.paintDetail()`, `SessionAtlas.resize()`, `SessionAtlas.project()`, `SessionAtlas.layout()`, `SessionAtlas.paintBackground()`, `SessionAtlas.draw()`, `SessionAtlas.schedule()`, `SessionAtlas.pick()`

See the [installation guide](INSTALL.md) for deployment and the [operations guide](OPERATIONS.md) for retention and console usage.
