# 導入・更新ガイド

[English](INSTALL.md) | [日本語](INSTALL.ja.md)

## 作業場所の見方

| 作業場所 | この資料での意味 | 主な作業 |
| --- | --- | --- |
| **管理PC** | ブラウザーでRabbitWallを操作する手元のPC | 証明書の作成・転送・登録、画面操作 |
| **RabbitWall導入先PC** | 有線NICを2つ備えたLinuxゲートウェイ | パッケージ導入、設定作成、ネットワーク適用、サービス更新・復旧 |
| **AI端末** | RabbitWall経由でインターネットへ接続する端末 | 固定IP・ゲートウェイ・DNS設定、通信確認 |
| **上流ルーター** | RabbitWallの上流側にある既存ルーター | 必要な場合の経路・アクセス許可 |

各コマンドの直前に実行場所を記載します。特記がない相対パスのコマンドは、**そのPC上に置いたRabbitWallソースのルートディレクトリ**で実行してください。管理PCのターミナルからSSHで接続している場合、接続後のコマンドの実行場所は接続先PCです。初回のネットワーク適用・復旧はRabbitWall導入先PCのローカルコンソールで行います。

## 1. 【RabbitWall導入先PC】マシンを準備する

- 有線NICが2つあるLinux機。arm64・amd64を想定。NIC名は `ip -br link` で確認する。
- Debian 13以上 / Ubuntu 24.04系、Python 3.11以上、systemd。NICは **既にNetworkManagerで管理されている**こと。Raspberry Pi OSなど派生OSはパッケージ・NIC・サービスの差を実機で確認する。
- **Debian 12以前は対象外**。標準の `python3-dnspython` が必要バージョン（2.6.1以上・3未満）を満たさないため、Debian 13以上を使用する。
- **管理PC／上流ルーターで事前準備**：管理PCのIPを固定するか、ルーターにDHCP予約を設定する。上流ネットワークとAI側ネットワークを重複させない。
- 初回はローカル画面・キーボード、シリアル、または同等のコンソールを確保する。SSHだけでNICを変更しない。
- Docker/UFW/firewalldとの併用、既存のVPNや複雑なポリシールーティングへの自動統合は対象外。

公開リポジトリの資材を取得して、そのルートディレクトリで作業する。以下は管理対象のRabbitWallを導入するマシンで行う。

**実行場所：RabbitWall導入先PCのターミナル**

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

NetworkManagerを使用していない機器では、OSに合った方法でNetworkManagerを設定するか、対応するOSをインストールする。既存SSH接続上でネットワーク管理方式を自動的に切り替えることはしない。

**RabbitWall導入先PCのDNS構成**：DNS転送はUnbound、推定ドメイン用の観測は独立したdnstap受信プロセスが担当します。Unboundはdnstap対応ビルドが必要です。上の `unbound -V` に `--enable-dnstap` が含まれることを確認してください。setupの検査でも対応状況を確認します。

公式パッケージの標準 `unbound.service` は上のコマンドで停止・無効化します。RabbitWallは専用の `rabbitwall-dns.service` を使います。他用途のUnboundとの自動統合は対象外です。観測用のdnspythonは2.6.1以上・3未満、Protocol BuffersはOSの `python3-protobuf` が必要です。DNSの追加インストーラーを実行する必要はありません。

## 2. 【RabbitWall導入先PC】設定を作る

**実行場所：RabbitWall導入先PCのターミナル**

```sh
python3 setup.py init
```

対話形式で `rabbitwall.json` を作る。複数ノードや拠点表示は後からJSONを編集できる。非対話なら：

**実行場所：RabbitWall導入先PCのターミナル**

```sh
cp examples/rabbitwall.example.json rabbitwall.json
```

| 設定 | 内容 |
|---|---|
| `uplink_if` / `uplink_cidr` | 上流NIC、RabbitWallを導入するマシン自身の固定IP／プレフィックス |
| `gateway` | 上流NICから直接届くルーター |
| `management_cidr` / `admin_ip` | 管理PCのネットワークと許可する1台のIP |
| `ai_if` / `ai_cidr` | AI側NIC、RabbitWallを導入するマシンのAI側IP／プレフィックス |
| `dns_upstream` | DNSフォワーダーの上流。RabbitWallを導入するマシンやAI側サブネットを指定しない |
| `nat` | `true`は上流向けNAT。`false`は上流にAI側サブネットの戻り経路が必要 |
| `console_name` | 証明書に使用する `.home.arpa` のホスト名 |
| `label` | RabbitWallを導入するマシンの表示名 |
| `nodes` | 監視ノード。`id`、`label`、`ip`、到達側の`interface`。最大12台 |
| `site_label` / `site_location` | 地図の拠点名と `[経度, 緯度]` |

例では管理PC `192.168.10.10`、RabbitWallを導入するマシンの上流 `192.168.10.2/24`、上流ルーター・DNS `192.168.10.1`、AI側 `192.168.20.1/24`、AI端末 `192.168.20.10`。

NATであれば、上流のDNSには通常の上流NICアドレスから接続する。経路方式の場合は上流にAI側サブネットの戻り経路とDNSの受信許可を用意する。管理PCが別サブネットにいる場合は、そのネットワークからRabbitWallを導入するマシンへの経路・許可も用意する。

## 3. 【RabbitWall導入先PC】計画を確認して適用する

**実行場所：RabbitWall導入先PCのターミナル**

```sh
python3 setup.py plan
sudo python3 setup.py check
cat output/install-plan/PLAN.txt
```

生成物にはnftables・NetworkManager・カーネル設定・Unbound設定（`unbound.conf`）が含まれる。`plan` はOSを変更しない。既存出力を上書きせず、設定を直したときは `--output output/別の名前` で再生成する。`check` は不足パッケージ、NIC、NetworkManager、競合サービスやポートを確認する。

`nftables.conf` と `*.nmconnection` を確認後、**RabbitWallを導入するマシンのローカルコンソール**で実行する。

**実行場所：RabbitWall導入先PCのローカルコンソール**

```sh
sudo python3 setup.py install --plan output/install-plan --apply-network
```

この処理はFWを専用ルールへ置換し、IP転送・接続追跡のバイト計測を有効にし、IPv6を無効化した固定IPプロファイルを導入する。AI側はキャリアがなくてもIPを維持する設定にする。上流やAI側に既存の自動接続プロファイルがある場合は、再起動時に古いプロファイルへ戻らないよう `nmcli connection show` で確認し、不要な接続の `connection.autoconnect` を無効にする。

設定は `/etc/rabbitwall.json`、生成したUnbound設定は `/etc/rabbitwall-unbound.conf`、コードは `/opt/rabbitwall`、履歴は `/var/lib/rabbitwall` に置く。変更前のファイルとFWは `/var/backups/rabbitwall/日時/` へ保存する。RabbitWallが導入済みの場合は、下記の更新手順を使う。

## 4. 管理PC用mTLSを設定する

ブラウザーにトークンを入力する必要はない。クライアント証明書を管理PCへ登録し、秘密の操作キーはCaddyとバックエンド間だけで使用する。読み取り用のSSHポート転送も利用可能だが、開閉操作はmTLS接続で行う。

### 4.1 【RabbitWall導入先PC】Caddyを導入する

[Caddy公式のDebian/Ubuntu向け手順](https://caddyserver.com/docs/install#debian-ubuntu-raspbian)で公式パッケージを導入する。**2.11.7以上**が必要。ディストリビューション標準の古いパッケージでは不足する場合がある。

新規導入時に限り、公式パッケージの初期サービスを止める。本システムは別の `rabbitwall-caddy.service` を使用する。他用途のCaddyが既にあるRabbitWallを導入するマシンへの自動統合は対象外。

**実行場所：RabbitWall導入先PCのターミナル**

```sh
caddy version
sudo systemctl disable --now caddy
```

### 4.2 【管理PC】設定を受け取り、証明書を作る

管理PCにPython・OpenSSLと導入先PCと同じ版のソース資材を用意します。管理PCのソースルートで、導入先PCに適用済みの設定を受け取ります。以下の `USER` とIPは導入先PCのSSHユーザーと上流側IPに置き換えてください。すでに同じ内容の設定ファイルがある場合、このコピーは不要です。

**実行場所：管理PCのターミナル**

```sh
scp USER@192.168.10.2:/etc/rabbitwall.json ./rabbitwall.json
```

同じ管理PC上で証明書を作成します。秘密CA鍵と管理PCの秘密鍵をRabbitWallを導入するマシンへ転送しない。以下はパスワードを対話入力する。CAパスワードとクライアント証明書のインポート用パスワードを安全に保管する。

**実行場所：管理PCのターミナル**

```sh
python3 tools/mtls.py --config rabbitwall.json init
python3 tools/mtls.py --config rabbitwall.json issue-server server
python3 tools/mtls.py --config rabbitwall.json issue-client admin
python3 tools/mtls.py --config rabbitwall.json bundle --server server --client admin --output output/mtls-bundle
```

### 4.3 【管理PC】導入先PCへ証明書バンドルを送る

`output/mtls-bundle` **だけ**をRabbitWallを導入するマシンへ転送する。例の接続先・ユーザー名は自環境へ置き換える。

**実行場所：管理PCのターミナル**

```sh
scp -r output/mtls-bundle USER@192.168.10.2:~/
```

### 4.4 【RabbitWall導入先PC】証明書バンドルを適用する

ここで作業場所を導入先PCに切り替えます。導入先PCのソースルートで実行します。

**実行場所：RabbitWall導入先PCのターミナル**

```sh
sudo python3 tools/install_mtls.py ~/mtls-bundle
```

### 4.5 【管理PC】証明書を登録してブラウザーで開く

作業場所を管理PCに戻します。管理PCのhostsファイルに例では `192.168.10.2 rabbitwall.home.arpa` を登録する。macOSではキーチェーンアクセスで `output/rabbitwall-pki/ca.crt` をルートCAとして信頼し、`output/rabbitwall-pki/admin/identity.p12` をログインキーチェーンへ読み込む。Windowsでは信頼されたルート証明機関へCA、個人へP12を登録する。FirefoxでOSのストアが使用されない構成ではFirefoxの証明書管理からCA・クライアント証明書を登録する。

`https://rabbitwall.home.arpa/` を開き、求められたら管理PCのクライアント証明書を選ぶ。警告が出た場合はhosts・SAN・CA信頼を修正し、警告を無視して進まない。サーバー・クライアント証明書の標準有効期間は365日。更新時は、管理PCで別名の `issue-server` / `issue-client` と `bundle` を実行し、4.3〜4.4の手順で導入先PCへ再適用してから、管理PCに新しいP12を登録する。CA鍵は管理PCで保持する。

**作業場所：上流ルーター（必要な場合のみ）**

上流ルーターが管理PCとRabbitWallの間にある場合は、管理PCからRabbitWallのTCP443へ許可を設定する。

## 5. AI端末を設定して確認する

### 5.1 【AI端末】IP・ゲートウェイ・DNSを設定する

例のAI端末は `192.168.20.10/24`、ゲートウェイとDNSは `192.168.20.1`。DHCPは提供しない。別のWi-FiやDNSに迂回する経路を残さない。

NetworkManagerを使うAI端末では、実際の接続名・NICへ置き換えて実行する。既存のIP設定が正しければDNSだけ変更すればよい。

**実行場所：AI端末のターミナル**

```sh
nmcli -f NAME,DEVICE connection show --active
sudo nmcli connection modify '接続名' ipv4.method manual ipv4.addresses '192.168.20.10/24' ipv4.gateway '192.168.20.1' ipv4.dns '192.168.20.1' ipv4.ignore-auto-dns yes ipv6.method disabled
sudo nmcli device reapply 'AI端末のNIC'
```

### 5.2 【管理PC → AI端末】開閉と通信を確認する

管理PCのブラウザーでRabbitWallコンソールを開き、対外接続を「開」にします。その後、AI端末に切り替えて以下を実行します。

**実行場所：AI端末のターミナル**

```sh
dig +time=2 +tries=1 @192.168.20.1 example.com
dig +tcp +time=2 +tries=1 @192.168.20.1 example.com
curl -I --connect-timeout 5 https://example.com
```

管理PCのブラウザーで「閉」に戻し、AI端末で同じ通信確認を再実行してDNS・外向き通信が止まることを確認する。管理PCから導入先PCへのSSHが維持されることも確認する。宛先不明の短い通信は約5秒の収集から漏れる。推定ドメインは同一端末の正のDNS応答とIPの照合であり、HTTPSホスト名の確定結果ではない。通信量ランキングは導入後の差分を蓄積し、最初の観測までの値や収集停止中の増分を含まない。

### 5.3 【RabbitWall導入先PC → AI端末】DNSと観測の独立動作を確認する

**実行場所：RabbitWall導入先PCのターミナル**

```sh
systemctl is-active rabbitwall-dns rabbitwall-dns-observer
sudo unbound-checkconf /etc/rabbitwall-unbound.conf
sudo systemctl stop rabbitwall-dns-observer
```

管理PCのコンソールで対外接続を「開」にした状態で、AI端末から5.2のDNS確認を再実行します。観測サービスを停止しても、Unboundの名前解決は継続します。停止中の新しいDNS応答は推定ドメインへ反映されません。確認後は観測を再開します。

**実行場所：RabbitWall導入先PCのターミナル**

```sh
sudo systemctl start rabbitwall-dns-observer
```

AI端末から再度名前解決し、管理PCのコンソールで新しいセッションの推定ドメインを確認してください。Unboundのキャッシュからの応答も観測対象です。次に管理PCで「閉」にし、AI端末からUDP・TCPのDNS確認を繰り返して、キャッシュ済みの名前でも遮断されることを確認します。

### 5.4 【管理PC／上流ルーター】AI端末へのSSH経路を追加する（任意）

NAT方式でも、管理PCがAI側サブネットへ到達するには経路が必要。例では管理PCに `192.168.20.0/24 → 192.168.10.2` を設定するか、上流ルーターに同じ経路を追加する。Linuxの管理PCでの一時的な確認例：

**実行場所：管理PCのターミナル（Linuxの例）**

```sh
sudo ip route add 192.168.20.0/24 via 192.168.10.2
```

永続化は管理PCのOSに従う。生成FWは指定管理PCからAI端末へのSSH・HTTPS・Pingをノードの個別許可に従って制御する。コンソール自体へのアクセスだけなら、この追加経路は不要。

## 6. 【RabbitWall導入先PC】国別IPデータを取得する（任意）

国表示を利用する場合は、導入完了後にDB-IP Country Liteを取得します。**セットアップでは自動取得しません。** 未導入でもコンソールは動作しますが、公開IPの国は表示できません。

**実行場所：RabbitWall導入先PCのターミナル**

```sh
sudo python3 /opt/rabbitwall/update_geoip.py
```

当月のデータをダウンロードし、ローカルの国別IPデータベースへ変換して `/var/lib/rabbitwall/geoip-country.sqlite3` に保存します。導入先PC自身がインターネットへ接続できる必要があります。AI側の対外接続は「閉」のまま実行できます。

完了後、管理PCのブラウザーでコンソールを再読み込みし、「設」で国別IPデータの状態と版を確認してください。更新時も同じコマンドを使います。自動定期更新は設定されません。データの出典・ライセンスと運用上の注意は、[日常運用ガイド](OPERATIONS.ja.md)を参照してください。

## 更新【RabbitWall導入先PC → 管理PC】

RabbitWallのソースを更新したら、RabbitWallを導入するマシンで：

**実行場所：RabbitWall導入先PCのターミナル**

```sh
sudo python3 setup.py update
```

設定・NAT・mTLS・画面で保存したノード情報を維持して、アプリ本体・DNS・サービス定義をまとめて更新する。導入済みで稼働中または有効化済みのCaddyは、Webサービス起動後に自動で再起動・稼働確認する。**更新直後は「閉」**。更新コマンドが完了したら、管理PCのブラウザーへ戻って強制再読み込みし、状態確認後に開く。

## IP設定の訂正と再適用【RabbitWall導入先PCのローカルコンソール】

`init` は入力ファイルを作るだけで、導入済み環境には反映しません。`update` は `/etc/rabbitwall.json` を使い、NICと基本Firewallを変更しません。インストール時の誤りやネットワーク設定を変更する場合は、ソースディレクトリの `rabbitwall.json` を修正してください。ノードのIP・IF、管理PCのIP、ゲートウェイ、DNS、NATも必要に応じて合わせます。

**実行場所：RabbitWall導入先PCのローカルコンソール。ソースのルートディレクトリで実行**

```sh
sudo python3 setup.py reconfigure --config rabbitwall.json --apply-network
sudo python3 setup.py doctor
```

IPやFirewall変更で切断されるため、SSH経由で実行しないでください。入力・Unbound設定・Firewallの検証後に、既存設定と稼働中のFirewallをバックアップします。NetworkManagerの2つの接続設定・ルーティング設定・Firewall・NAT・DNSを反映し、`/etc/rabbitwall.json` を保存してアプリとサービスも更新します。別途 `update` を実行する必要はありません。画面で保存した `/etc/rabbitwall-nodes/nodes.json` は解除し、指定JSONの `nodes` を適用します。必要なノードは事前に入力JSONへ転記してください。完了時の対外接続は **「閉」** です。管理接続とDNSを確認してから開いてください。

mTLSの証明書・秘密鍵、操作キー、履歴は保持します。mTLS導入済みの場合、Caddyの待受IP・管理PCの制限・HTTPSのFirewallルールも再生成します。コンソールのホスト名を変更する場合は一致するサーバー証明書が必要で、不一致ならネットワーク変更前に停止します。上流側IPを変更した場合は管理PCのhosts／DNS登録を変更し、AI側IPを変更した場合はAI端末のゲートウェイとDNSも変更してください。NAT無効時は上流ルーターの静的経路も合わせます。

対象NICで稼働中だった接続設定は自動接続を無効にし、生成した `rabbitwall-uplink` と `rabbitwall-ai` をUUID指定で有効化します。同名の接続設定が残っていても、名前の曖昧さを避けられます。別の物理NICへの移設用ツールではないため、使わなくなったNICの接続設定は別途無効化してください。

適用前にバックアップ先と `restore.sh` のパスを表示します。サービス停止後に失敗した場合は「閉」を維持するので、ローカルで原因を修正し同じコマンドを再実行してください。保存したネットワーク設定へ戻す場合は：

**実行場所：RabbitWall導入先PCのローカルコンソール。TIMESTAMPは表示されたバックアップ先に置換**

```sh
sudo sh /var/backups/rabbitwall/TIMESTAMP/restore.sh
sudo reboot
```

復元先は保存時点の設定なので、元の誤りが含まれる場合があります。バックアップは非公開で保管してください。再適用後のサービス動作・NetworkManagerの接続切り替え・再起動時の挙動は実機で確認してください。

## 切り分けと復旧【RabbitWall導入先PC】

**実行場所：RabbitWall導入先PCのターミナル**

```sh
sudo python3 setup.py doctor
sudo journalctl -u rabbitwall-control -u rabbitwall-dns -u rabbitwall-dns-observer -u rabbitwall-collector -u rabbitwall-caddy -n 60 --no-pager
```

- DNS待受IPがない：AI側プロファイル、NIC名、NetworkManagerのキャリア設定を確認。
- カウンターがない：`sysctl net.netfilter.nf_conntrack_acct` が1か確認。設定後の新規接続から有効。
- Unboundが `getifaddrs: Address family not supported by protocol` で停止：`systemctl cat rabbitwall-dns` を確認。LinuxのIF情報取得にはNetlinkが必要なため、`RestrictAddressFamilies` で `AF_INET AF_UNIX AF_NETLINK` を許可する。最新のサービス定義を `setup.py update` で適用し、対外接続を「開」にしてDNSを再確認する。
- DNSがSERVFAIL：Unboundのログ、上流DNSの受信制限と経路を確認。閉状態のタイムアウトは正常。
- 名前解決はできるが推定ドメインが増えない：`rabbitwall-dns-observer` の状態・ログ、`/run/rabbitwall-dns/dnstap.sock` と観測JSONの更新を確認。バッファ分が遅れて届くことはあるが欠落イベントは復元できないため、再開後に端末から名前解決をやり直す。
- mTLS接続できない：管理PCのIP、hosts、CA信頼、クライアント証明書・期限、Caddyの版を確認。

初回適用から戻す場合は、表示されたバックアップの `restore.sh` を **ローカルコンソール**で実行する。サービスを止め、元のFWと保存設定を戻す。元のNICプロファイルとカーネル設定を確実に再適用するため、復元後はローカルから再起動する。

**実行場所：RabbitWall導入先PCのローカルコンソール**

```sh
sudo sh /var/backups/rabbitwall/実際の日時/restore.sh
sudo reboot
```

履歴DBとソースは復旧時に削除しない。証明書導入後のmTLS個別バックアップは `/etc/rabbitwall/backups` にある。

コード更新前の資材は、表示された `/var/backups/rabbitwall/application-日時/` に保存されます。更新に失敗した場合、対外接続は閉じたままです。ローカルコンソールから原因を直して `setup.py update` を再実行してください。旧コードに戻す場合は、5サービス（control・dns・dns-observer・collector・web）を停止して当該バックアップの `opt/rabbitwall/` と `etc/` をそれぞれ元のパスへ戻し、`systemctl daemon-reload` 後にcontrol・dns・dns-observer・collector・webの順で再起動します。新たなグループとディレクトリ権限は維持してください。このアプリ用バックアップには初回ネットワーク設定の復元スクリプトは含みません。
