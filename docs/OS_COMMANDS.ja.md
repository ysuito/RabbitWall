# OSコマンド参考資料

[English](OS_COMMANDS.md) | [日本語](OS_COMMANDS.ja.md)

RabbitWallの本番用ソースが起動する外部プログラムと、その用途を示します。初回導入・更新・設定再適用・証明書作成・復旧を含みます。テスト専用のDocker／ネットワーク名前空間操作は含みません。`<...>` は設定値・パスなどの可変部分、`-f -` は標準入力で生成ルールを渡す指定です。一括実行用の手順ではありません。

## 1. 通常運用中【RabbitWall導入先PC】

| 発行元・タイミング | コマンド例 | 用途・変更内容 |
| --- | --- | --- |
| collector・約5秒ごと | `conntrack -L -f ipv4 -o extended,id` | カーネルのIPv4接続情報・カウンターを参照。接続を削除しない |
| collector・約5秒ごと | `journalctl -k --since '5 minutes ago' -n 1000 --no-pager --quiet -o json --grep 'rabbitwall-(input\|forward\|output)-drop'` | 直近のFirewall拒否ログを参照。`--grep` の縦棒は正規表現で、シェルのパイプではない |
| control・状態取得／約4秒の制御周期 | `nft -j -a list table inet rabbitwall_console` | 対外接続ゲートの状態・テーブル識別子を参照 |
| control・起動／ノード保存 | `nft -j -a list ruleset` | 基本FWの構造、専用チェーン、ルール識別子、offloadの有無を参照 |
| control・起動／開閉操作／開状態の約4秒ごとの更新 | `nft -f -` | 起動時はゲートを閉じて構成。開閉時は許可集合を更新。開状態の許可期限は20秒 |
| control・約10秒ごと、監視有効な各ノード | `ping -n -c 1 -W 1 -I <IF> <IPv4>` | ICMPによる死活確認。監視無効のノードには実行しない |
| control・ノード保存 | `nft -c -f -` → `nft -f -` | ノードのSSH・HTTPS・Ping許可と監視用ルールを検証して反映。NIC・DNS・開閉ゲートは再構成しない |
| control・ノード保存の復元処理 | `nft -f -` | 保存に失敗した場合、元のノード用ルールへの復元を試みる |

発行箇所：[console.py](../src/rabbitwall/console.py)、[control.py](../src/rabbitwall/control.py)、[node_config.py](../src/rabbitwall/node_config.py)。生成するnftables文は [firewall.py](../src/rabbitwall/firewall.py) にあります。collectorの周期は変更可能です。スレッドによるノード確認には時間がかかるため、監視間隔は厳密な定周期ではありません。

Webサービスはこれらのコマンドを直接実行しません。制御要求はUnixソケットでcontrolサービスへ渡します。collectorは別プロセスで読み取り用コマンドを実行します。

## 2. 導入前検査・診断【RabbitWall導入先PC】

| コマンド | 発行元・用途 |
| --- | --- |
| `systemctl is-active --quiet <service>` | `setup.py check`：NetworkManagerが稼働中か、競合するufw・firewalld・docker・標準unboundが稼働していないか確認 |
| `ss -H -lntup 'sport = :<port>'` | `check`：53・443・8765・8767番の待受競合を確認 |
| `ip -j -4 addr` | 再適用後など、指定IPv4が有効か確認 |
| `unbound -V` | Unboundのdnstap対応ビルドを確認 |
| `unbound-checkconf <一時設定ファイル>` | 生成したUnbound設定の構文を確認 |
| `systemctl is-active <service>` | `setup.py doctor`：nftablesおよびRabbitWall各サービスの状態を表示 |
| `ip -br -4 addr` | `doctor`：IPv4アドレスを表示 |
| `ss -lntup` | `doctor`：TCP・UDPの待受を表示 |
| `nft list table inet rabbitwall_console` | `doctor`：開閉ゲートのルールを表示 |

発行箇所：[setup.py](../setup.py)、[unbound_config.py](../src/rabbitwall/unbound_config.py)。検査はパッケージを自動インストールしません。

## 3. 初回導入・再適用・アプリ更新【RabbitWall導入先PC】

| コマンド | 発行条件・用途 |
| --- | --- |
| `nft -c -f -` | 初回／再適用：生成した基本FW・閉状態のゲート・ノード用ルールを事前検証 |
| `nft list ruleset` | 現在のルールを復旧用に保存 |
| `systemctl is-enabled --quiet nftables` | 復旧用に自動起動状態を確認 |
| `systemctl show -p LoadState --value <service>` | 停止対象のサービスが存在するか確認 |
| `systemctl stop <service>` | 更新・再適用前にRabbitWallサービスを停止。再適用ではCaddyも対象 |
| `nmcli -t -f UUID,DEVICE connection show --active` | 再適用：対象NICで現在使われている接続を識別 |
| `nmcli connection modify uuid <UUID> connection.autoconnect no` | 再適用：以前の対象接続が自動接続で競合しないようにする |
| `modprobe nf_conntrack` | 初回／再適用：接続追跡用のカーネルモジュールを読み込む |
| `sysctl -p /etc/sysctl.d/90-rabbitwall-router.conf` | 初回／再適用：転送・接続追跡等のカーネル設定を反映 |
| `nft -f /etc/nftables.conf` または `nft -f -` | 初回／再適用：専用ゲートウェイのFW全体を置き換える |
| `systemctl enable nftables` | FWの起動時読み込みを有効化 |
| `nmcli general reload`、`nmcli connection reload` | 初回／再適用：NetworkManagerと保存した接続設定を再読み込み |
| `nmcli connection up uuid <UUID>` | 初回／再適用：生成した上流側・AI側接続を有効化 |
| `/usr/bin/python3 -B /opt/rabbitwall/control.py off` | 更新前後に旧コードでも閉操作を実行し、残った許可を消す |
| `groupadd --system <group>` | 未作成の場合のみ、rabbitwall-control・rabbitwall-dns・rabbitwall-readグループを作成 |
| `useradd --system --gid rabbitwall-dns --no-create-home --shell /usr/sbin/nologin rabbitwall-dns` | 未作成の場合のみ、DNS用サービスアカウントを作成 |
| `/usr/bin/python3 -B /opt/rabbitwall/control.py install` | 閉状態の永続FW断片・ノード設定用ディレクトリ・操作キーを準備。内部で `nft -c -f <一時ファイル>` を実行 |
| `systemctl daemon-reload` | 更新したサービス定義を読み込み |
| `systemctl enable <services>`、`systemctl restart <service>`、`systemctl is-active --quiet <service>` | control・dns・dns-observer・collector・webを有効化し、順に起動・確認 |
| `systemctl is-active --quiet rabbitwall-caddy`、`systemctl is-enabled --quiet rabbitwall-caddy` | 更新前にCaddyを復帰させる必要があるか確認 |
| `systemctl restart rabbitwall-caddy`、`systemctl is-active --quiet rabbitwall-caddy` | 導入済みで稼働中または有効化済みだったCaddyを、Web起動後に復帰・確認 |

再適用時にmTLSが導入済みなら、次節のサーバー証明書の検証と `caddy validate` も実行します。通常の `update` はNIC・基本FW・sysctlを再適用しません。ノード設定の保存は `update` とは別で、通常の開状態は維持します。ドメイン限定許可は保存時に破棄します。

発行箇所：[setup.py](../setup.py)、[deploy.py](../tools/deploy.py)、[control.py](../src/rabbitwall/control.py)。

## 4. 証明書作成・mTLS導入

### 管理PC：`tools/mtls.py`

| コマンド例 | 用途 |
| --- | --- |
| `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -aes-256-cbc …` | 暗号化したCA秘密鍵を作成 |
| `openssl req -new -x509 -sha256 -days 3650 …` | CA証明書を作成 |
| `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 …` | サーバー／クライアントの秘密鍵を作成 |
| `openssl req -new -sha256 -key <key.pem> -subj /CN=<name> …` | 証明書署名要求（CSR）を作成 |
| `openssl x509 -req -sha256 -days <days> -CA <ca.crt> -CAkey <ca.key> …` | CAでサーバー／クライアント証明書を署名 |
| `openssl version` | PKCS#12の互換性用にOpenSSL／LibreSSLを判別 |
| `openssl pkcs12 -export …` | ブラウザー登録用のクライアント証明書・秘密鍵をP12に格納 |
| `openssl verify -CAfile <ca.crt> -purpose sslserver <cert.pem>` | 配布用サーバー証明書のチェーンを検証 |
| `openssl verify -CAfile <ca.crt> -purpose sslclient <cert.pem>` | 配布用クライアント証明書のチェーンを検証 |

`…` は出力先、拡張設定、パスワードファイル等の省略です。実際の全引数は [mtls.py](../tools/mtls.py) を参照してください。パスワードファイルを指定した場合は `file:<path>` で渡し、パスワードそのものを引数へ埋め込みません。

### RabbitWall導入先PC：`tools/install_mtls.py`／再適用

| コマンド例 | 用途 |
| --- | --- |
| `/usr/bin/caddy version` | 必要なCaddyバージョンを確認 |
| `openssl verify -CAfile <ca.crt> -purpose sslserver -verify_hostname <console_name> <server.crt>` | CA・用途・ホスト名を検証 |
| `openssl x509 -in <server.crt> -checkend 86400 -noout` | 証明書の有効期限に余裕があるか確認（mTLS導入時） |
| `/usr/bin/caddy validate --config /etc/rabbitwall-mtls/Caddyfile --adapter caddyfile` | HTTPS・クライアント認証・プロキシ設定を検証。再適用時は一時ファイルを使う |
| `nft -j list chain inet rabbitwall_filter input` | HTTPS許可ルールの現状を確認 |
| `nft -c -f <設定／一時ファイル>`、`nft -f <一時ファイル>` | 管理PC向けHTTPSルールを検証・適用。失敗時は元のルールへの復元を試みる |
| `systemctl daemon-reload`、`systemctl restart rabbitwall-caddy`、`systemctl enable rabbitwall-caddy` | Caddy定義を読み込み、起動・自動起動を設定 |
| `systemctl is-active --quiet rabbitwall-caddy`、`systemctl stop rabbitwall-caddy` | 導入前状態の確認と、失敗時の状態復元に使用 |

発行箇所：[install_mtls.py](../tools/install_mtls.py)、[setup.py](../setup.py)。証明書・設定ファイルのコピーや権限設定はPythonから行います。

## 5. systemdが起動するプロセス【RabbitWall導入先PC】

| サービス | 起動コマンド |
| --- | --- |
| `rabbitwall-control` | `/usr/bin/python3 /opt/rabbitwall/control.py run`。停止後は `/usr/bin/python3 /opt/rabbitwall/control.py off` |
| `rabbitwall-collector` | `/usr/bin/python3 /opt/rabbitwall/console.py collect` |
| `rabbitwall-web` | `/usr/bin/python3 /opt/rabbitwall/console.py serve` |
| `rabbitwall-dns` | `/usr/sbin/unbound -d -c /etc/rabbitwall-unbound.conf` |
| `rabbitwall-dns-observer` | `/usr/bin/python3 -B /opt/rabbitwall/dnstap_observer.py` |
| `rabbitwall-caddy` | 事前に `caddy validate`、続いて `/usr/bin/caddy run --config /etc/rabbitwall-mtls/Caddyfile --adapter caddyfile` |

定義は [systemd/](../systemd/) を参照。デモでは `setup.py` が実行中のPythonを使い、`<python> -B <source>/src/rabbitwall/console.py demo --port <port> --state-dir <dir>` を起動します。

## 6. 生成された復旧スクリプト【手動実行時のみ】

`/var/backups/rabbitwall/<日時>/restore.sh` は、サービス停止（初回導入の復旧では無効化も実施）、`nft -f <backup>/runtime.nft`、必要に応じた `systemctl disable nftables`、`cp -a <backup>/etc/. /etc/`、保存前に存在しなかった対象ファイルの `rm -f`、`nmcli general reload`、`nmcli connection reload` を実行します。対象は生成スクリプト内の固定パスで、任意パスをHTTPから受け取りません。`dirname` とシェル組み込みの `cd` でスクリプト自身の場所を求め、最後に `echo` で案内を表示します。`reboot` 自体はスクリプトから実行せず、利用者がローカルで行います。

## 7. OSコマンドを使わない処理とUnixソケット

- GeoIPのダウンロードはPythonの `urllib.request`、DB作成・履歴保存は `sqlite3`。`curl`・`wget`・`sqlite3` コマンドは起動しません。
- JSON／設定の保存、バックアップ、権限設定は主にPythonのファイルAPI。`cp`・`rm` 等のシェルコマンドを使うのは上記の復旧スクリプトです。
- DNSの実処理はUnbound。観測プロセスはdnspythonで応答を解析し、`dig` は起動しません。`tcpdump` は手動診断用で、自動実行しません。
- `apt install`、標準Unboundの停止、SSH／SCPは導入ガイドで利用者が実行する作業です。RabbitWallがパッケージを自動導入する処理はありません。
- 通常の外向き通信はカーネルが転送し、通信のたびにPythonや外部コマンドが動く仕組みではありません。

| Unixソケット | 用途・アクセス制御 |
| --- | --- |
| `/run/rabbitwall/control.sock` | Webから権限を持つcontrolサービスへ状態取得・開閉・検証済みノード設定を渡す。`root:rabbitwall-control`、ソケットは `0660`、親ディレクトリは `0750`。Webをrootにせず、操作権限を制御サービスに集約する |
| `/run/rabbitwall-dns/dnstap.sock` | Unboundから観測プロセスへDNS応答のコピーを渡す。同じ `rabbitwall-dns` ユーザーを使い、ソケットは `0600`。観測停止・遅延がDNS転送の停止に直結しない構成 |

いずれも同一マシン内の通信で、外部向けTCPポートを追加せず、ファイルの所有者・グループ・権限で接続を制限できます。制御ソケットでは接続元PID・UID・GIDも監査ログに記録します（開閉・保存操作）。Unixソケット自体がmTLSの代わりになるわけではなく、管理PCとの通信は別途CaddyのHTTPS／mTLSで保護します。

DNS拒否の観測は、既存collector内のスレッドがOSの共有ライブラリ libnetfilter_log とローカルAF_NETLINKソケットで行います。追加のOSコマンド・TCP/UDP待受・権限追加はありません。


## 8. ドメイン一時許可【RabbitWall導入先PC】

root制御プロセスが `unbound_guard.py` から以下の固定コマンドを追加で発行します。

| コマンド | 用途 |
| --- | --- |
| `unbound-checkconf /etc/rabbitwall-unbound.conf` | 生成した端末別RPZを含む設定全体を適用前に検証 |
| `unbound-control -c /etc/rabbitwall-unbound.conf reload` | 承認した完全一致の名前を反映、または全体開通前に制限を解除 |
| `unbound-control -c /etc/rabbitwall-unbound.conf list_auth_zones` | 非同期RPZ読み込みの完了を確認 |
| `unbound-control -c /etc/rabbitwall-unbound.conf flush_zone .` | ポリシー変更後にキャッシュを消去 |
| `nft -f -` | 限定許可中は約0.5秒ごとにDNS許可元と送信元IP・宛先IPのTCP 80/443許可期限を更新 |

Unbound制御は `/run/rabbitwall-dns/control.sock`（DNSグループのUnixソケット）を使い、TCP制御ポートは開きません。制御プロセスは `rabbitwall-dns` グループに参加します。承認名の解決はdnspythonから直接行い、`dig` は起動しません。ノード保存時は限定許可を破棄してDNSポリシーを解除します。[一時許可の手順](DOMAIN_APPROVALS.ja.md)も参照してください。
