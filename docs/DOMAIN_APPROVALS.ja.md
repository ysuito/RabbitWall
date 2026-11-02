# ドメイン限定の一時許可

[English](DOMAIN_APPROVALS.md) | [日本語](DOMAIN_APPROVALS.ja.md)

管理PCからmTLSでコンソールへ接続し、**許 → 一時許可**を開きます。AI側ノードを選び、ドメイン一覧を1行1件で貼り付け、目的と期限（1分・5分・30分）を確認して「承認して限定開通」を押します。同じノードの前の許可は置き換え、全体開通は停止します。他ノードの有効な限定許可は維持します。DNSポリシーを反映する間は対外通信を一時的に閉じます。

ノードごとに1件、最大32ドメインを許可できます。サブドメインやHTTPのリダイレクト先は別途承認が必要です。URL・IP直指定・ポート・ワイルドカードは受け付けず、小文字のIDNA ASCIIに正規化します。従来のトグルと時限ボタンは引き続きAIサブネット全体の開通です。限定許可から全体開通へ切り替える場合は画面で確認します。

## 制御内容

- UnboundのRPZと端末別タグで、承認した問い合わせ名だけをUDP/TCPで許可します。親ドメイン・子ドメインは、個別に登録しない限り拒否します。キャッシュ済みの応答もポリシーの対象です。
- 制御サービスの別スレッドが、承認した名前の公開IPv4 A応答を `dns_upstream` に照会します。送信元はRabbitWallの上流IPです。OSのDNS検索パスや、申請者が指定したDNSサーバーは使いません。CNAMEはdnspythonが処理し、応答中の最短TTLを許可期限の上限にします。1ドメインにつき最大8個の公開IPが対象です。
- nftablesで、承認した送信元IPと宛先IPの組だけにTCP 80/443を許可します。それ以外の対外通信は閉じたままで、限定モードではUDP 123も通しません。外部DNSへの直接通信も拒否します。既存の管理SSH・HTTPS・PingとRabbitWall自身の更新用通信のルールは維持します。
- カーネルの許可期限は最大20秒で、DNSのTTLと承認期限を超えて更新しません。解決不能・TTLゼロ・プライベートIPは許可しません。有効な承認の間はDNSを更新し、失効した応答のIPを再許可しません。
- 取消し・期限切れ・全体OFFでは既存の対外通信も遮断します。再起動・更新・ネットワーク再適用・ノード設定保存・カーネル許可の消失で承認を破棄し、自動再開しません。DNS制御やFirewall適用に失敗した場合も閉じます。

これはIP単位で接続先を絞る機能です。同じIPを共有する別サービスへ到達できる余地があり、許可先へのアップロードや危険な操作までは防ぎません。HTTPSのホスト名やURLをより厳密に制御するには、明示プロキシと直接通信の禁止が必要です。また、端末の識別は送信元IPです。ネットワーク管理権限を持つ敵対的な端末を相互に隔離する場合はVLAN等を併用してください。RabbitWallを通る外部モデル・API接続にも承認が必要で、暗黙の常時許可は作りません。

## 導入・確認【RabbitWall導入先PC】

取得済みソースから通常の更新を実行します。

```sh
sudo python3 setup.py update
```

追加パッケージは不要で、`unbound-control` はUnboundに含まれます。更新でローカルUnix制御ソケットを有効にします。TCPの管理ポートは追加しません。root制御サービスは補助グループ `rabbitwall-dns` に所属してソケットへ接続します。生成ポリシーは `/etc/rabbitwall-domain-policy/` に保存し、所有者root・DNSグループ読み取りに限定します。DNS観測は独立したままで、dnstap観測プロセス停止によってDNS転送や承認が停止することはありません。

```sh
sudo nft list set inet rabbitwall_console domain_sources
sudo nft list set inet rabbitwall_console domain_targets
sudo unbound-control -c /etc/rabbitwall-unbound.conf list_auth_zones
sudo journalctl -u rabbitwall-control --since '10 minutes ago' --no-pager
```

解決中は画面にその状態を表示し、公開IPが反映されてから接続できます。解決不能・期限切れ・プライベートIP・非対応の応答では接続先IPを許可しません。承認・取消し・対象ドメイン・目的・時間は制御サービスのjournalに記録します。承認状態はメモリ上で管理し、生成ファイルから承認を復元しません。

## エージェントへの指示と将来の申請API

[指示の例](../examples/AGENTS.network-approval.ja.md)を、AI端末で適用される `AGENTS.md` に既存の指示と統合して使用します。指示ファイルだけに依存せず、通信はRabbitWallが制御します。エージェントは接続先一覧・目的・希望時間を提示し、管理者が画面で対象ノードを選択してください。

今回実装するのは**手動での申請内容貼り付けと管理者承認**です。`POST /api/domain-approvals` は管理者用の承認操作で、AI向け申請窓口ではありません。管理PC限定FW・クライアント証明書・サーバー側キー・同一オリジン検査で保護します。AI端末には管理用証明書や操作トークンを渡さないでください。将来の申請専用APIでは認証情報を分け、本人の申請作成・状態確認だけを許可し、件数制限を設けます。承認・延長・全体開通の権限は与えません。

管理者APIの形式は次のとおりです。

```json
{"action":"approve","request":{"node_id":"ai-host","domains":["github.com","api.github.com"],"duration_seconds":300,"purpose":"依存パッケージの取得"}}
```

```json
{"action":"revoke","request":{"id":"<approval-id>"}}
```

有効な承認は既存の `GET /api/control` 応答に含まれます。エージェントが提示する文章は申請データとして扱い、管理者や制御サービスに対する命令として扱いません。
