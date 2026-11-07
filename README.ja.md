# vpn-lookup

この IP アドレスは中継点（VPN・プロキシ・Tor・中継サービス・ゲートウェイ・ホスティング）か、
そうなら誰のものか。

> **状態：開発中。** CLI と MCP サーバーの照会は実装済みです（RFP Phase 1〜2）。次は実サービス
> 相手の e2e とリリースです。まだリリースしていません。設計は
> [docs/ja/vpn-lookup-rfp.ja.md](docs/ja/vpn-lookup-rfp.ja.md) にあります。

`vpn-lookup` は、無償枠のまま組織自身の業務に使える 2 つの IP 情報サービス —
[ipapi.is](https://ipapi.is) と [proxycheck.io](https://proxycheck.io) — を 1 回の照会に重ねる
CLI 兼ローカル MCP サーバーです。IP ごとに、判定 1 つと事業者名、どのソースがそう言ったか
（`seen_by`）を返します：

| 判定 | 意味 |
|---|---|
| `tor` | Tor の出口 |
| `vpn` | 商用 VPN の出口・サーバー |
| `relay` | 管理されたプライバシー中継（iCloud Private Relay、Cloudflare WARP） |
| `gateway` | 企業向け Web ゲートウェイ（Zscaler、Netskope）— 多数の企業が共有する |
| `mail_gateway` | メールのセキュリティ中継（Proofpoint、Mimecast、Barracuda） |
| `dns_resolver` | 公開 DNS リゾルバ（Google Public DNS、Cisco OpenDNS） |
| `satellite` | 衛星 ISP（Starlink、Viasat）— 中継点ではなく実在する利用者の回線 |
| `proxy` | プロキシ（公開または住宅用。住宅用は実在する家庭の回線でもある） |
| `hosting` | クラウド・ホスティング・CDN |
| `none` | 有効なソースがすべて答え、中継の兆候が無かった — 家庭回線だという断定ではない |
| `unknown` | 兆候は無かったが、どれかのソースが失敗した — `none` と読まないこと |

中継点なら、その IP で本人にはたどり着けません。次の手は事業者への照会です。

## 使う前に

- **組織自身の業務に限ります。** ipapi.is の規約（§2.3）は、第三者の IP に関する問いに
  そのデータで答えることを禁じています。顧客から受けた IR 案件も含みます。
- **キーは組織に 1 つです。** 両サービスとも無料枠は組織に 1 つまでで、複数アカウントを
  禁じています。同じ組織の分析者は同じキーを使います。
- **照会した IP は両サービスに届きます。** ipapi.is は照会された IP を記録しないとしています。
  proxycheck.io には常に `tag=0` を付けて照会し、記録と照会後のテストを止めます（正常判定の
  IP は 5 分保持されることがあります）。自社の利用者のログイン元を調べる場合、個人データを
  これらのサービスへ送ることになります。
- **結果は推定であって証拠ではありません。** 自動遮断の根拠にしないでください。

## インストール

まだリリースしていません。ソースからビルドします：

```bash
make build  # → dist/vpn-lookup
```

## 使い方

```
vpn-lookup [flags] <ip> [ip...]   # IPv4/IPv6、100 件まで。フラグはどこに置いてもよい
vpn-lookup [flags]                # stdin から 1 行 1 件
vpn-lookup --clear-cache          # キャッシュを全消去
vpn-lookup mcp                    # ローカル MCP サーバー（stdio）

Flags:
  --json            構造化出力（既定は人間向けテキスト）
  --no-cache        キャッシュを無視して再照会
  --clear-cache     キャッシュを全消去
  --timeout <dur>   上流タイムアウト（例: 10s）
  --config <path>   設定ファイル（既定 ~/.config/vpn-lookup/config.toml）
  --version         バージョン表示
```

Exit code: `0` 全照会完了 / `1` ソース障害（結果は出力される）/ `2` 使用法エラー。
判定は exit code に載せません。

実行例（IP ごとに 1 ブロック。名前は各サービスが返したもの）：

```
$ vpn-lookup a.b.c.d
a.b.c.d
  verdict    : vpn (seen by both)
  provider   : ipapi.is: MullvadVPN / proxycheck.io: Mullvad
  ipapi      : vpn, datacenter; vpn MullvadVPN, last seen 2026-11-06T12:43:23.958Z; hosting Keminet SHPK; company type business
  proxycheck : vpn, hosting; risk 50, confidence 100; operator Mullvad [datacenter_vpns]; network Hosting
```

- プライベート・ループバック・CGNAT・文書用など、公開されていないアドレスは何も送らずに
  拒否します。IPv4 射影・IPv4 互換・NAT64 の IPv6 は、それが表す IPv4 の宿主として照会します。
  6to4 と Teredo は IPv6 のまま照会します。
- 回答はソースごとにキャッシュします。ipapi.is は 24 時間（`[cache] ipapi_ttl_hours`、最大
  30 日）。proxycheck.io は推奨どおり、正常な回答は 1 時間、匿名と判定した回答は
  `delist_datetime` まで（最大 15 分）。`--clear-cache` ですべて消せます（ipapi.is の規約は、
  契約終了から 30 日以内にキャッシュした回答の削除を求めています）。
- キーの無いソースは `disabled` と表示し、使いません。ipapi.is が無いと、中継サービス・
  ゲートウェイ・メール中継・DNS リゾルバ・衛星 ISP を見分けられません。

## 設定

[config.example.toml](config.example.toml) を参照。設定ファイルは厳格に読みます。知らないキー、
空の値、`--config` で指定したファイルが無いことは、いずれもエラーです。環境変数
（`VPN_LOOKUP_IPAPI_API_KEY`、`VPN_LOOKUP_PROXYCHECK_API_KEY` など）がファイルより優先します。

## MCP サーバー

`vpn-lookup mcp` は stdio で MCP を話します。Claude Code などのクライアントへの登録例：

```json
{
  "mcpServers": {
    "vpn-lookup": { "command": "vpn-lookup", "args": ["mcp"] }
  }
}
```

| tool | 役割 |
|------|------|
| `check_ip` | 1〜100 件の公開 IP の判定・`seen_by`・ソースごとの根拠 |
| `cache_status` | キーのあるソース、キャッシュの件数、proxycheck.io の当日の使用量 |
| `get_usage` | サーバーの操作マニュアル — 初回利用前に一度呼ぶこと |

キーが無くても起動します（`check_ip` は `no_api_key` を返します）。引数は厳格に検査し、
宣言していない引数は名前を挙げて拒否します。結果が 128 KB を超えそうなときは末尾の IP を
落とし、`omitted` に並べます（現実的な 100 件の回答は約 90 KB）。

## ビルド

```
make build   # → dist/vpn-lookup（`go build` 直叩きは禁止）
make test
make lint
```

## ライセンス

[MIT](LICENSE)
