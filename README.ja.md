# vpn-lookup

この IP アドレスは中継点（VPN・プロキシ・Tor・中継サービス・ゲートウェイ・ホスティング）か、
そうなら誰のものか。

> **状態：雛形。** 構成・設定・MCP の初期化までは入っていますが、照会そのものはまだ
> 実装していません。設計は [docs/ja/vpn-lookup-rfp.ja.md](docs/ja/vpn-lookup-rfp.ja.md) にあります。

`vpn-lookup` は、無償枠のまま組織自身の業務に使える 2 つの IP 情報サービス —
[ipapi.is](https://ipapi.is) と [proxycheck.io](https://proxycheck.io) — を 1 回の照会に重ねる
CLI 兼ローカル MCP サーバーです。IP ごとに、判定 1 つと事業者名、どのソースがそう言ったかを
返します（予定）：

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

## 使い方（予定）

```
vpn-lookup [flags] <ip> [ip...]   # IPv4/IPv6、100 件まで
vpn-lookup [flags]                # stdin から 1 行 1 件
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

## 設定

[config.example.toml](config.example.toml) を参照。設定ファイルは厳格に読みます。知らないキー、
空の値、`--config` で指定したファイルが無いことは、いずれもエラーです。環境変数
（`VPN_LOOKUP_IPAPI_API_KEY`、`VPN_LOOKUP_PROXYCHECK_API_KEY` など）がファイルより優先します。

## MCP サーバー

`vpn-lookup mcp` は stdio で MCP を話し、キーが無くても起動します。雛形の段階で答えるのは
`get_usage` と `cache_status` で、`check_ip` は照会の実装とともに加わります。

## ビルド

```
make build   # → dist/vpn-lookup（`go build` 直叩きは禁止）
make test
make lint
```

## ライセンス

[MIT](LICENSE)
