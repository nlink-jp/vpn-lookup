# RFP: vpn-lookup

> Generated: 2026-11-07
> Status: Draft（段階 0 の実測済み・利用者と全 7 項目合意済み・設計の独立検証を反映済み）

## 1. Problem Statement

インシデント対応やログ分析で見つけた IP アドレスが、攻撃者や利用者自身の回線なのか、
それとも誰でも借りられる、または多くの利用者が共有する中継点 — 商用 VPN、プロキシ、
クラウドやホスティングのデータセンター、Tor、iCloud Private Relay のような管理された
中継サービス、Zscaler のような企業向け Web ゲートウェイ、Proofpoint のようなメールの
中継、公開 DNS リゾルバ — なのかを、事業者名と合わせて答える。中継点なら、その IP で
本人にはたどり着けない。調べるべきは事業者への照会であり、IP のブロックや所在地の
推定は意味が薄い、と判断が変わる。現在のツール群が見分けられる中継点は
Tor（tor-exit-lookup）と iCloud Private Relay（icloud-relay-lookup）だけである。

vpn-lookup は、無償枠のまま組織自身の業務で使える 2 つのソース — **ipapi.is** と
**proxycheck.io** — を 1 回の照会で重ね、中継点の分類と事業者名、どのソースがそう
言ったかを返す CLI 兼ローカル MCP サーバーである。評判（悪用者フラグ・リスク
スコア）は参考として添えるだけで、評判の判断は abuse-lookup が担う。

想定する使い方は 2 つで、**どちらも組織自身の業務に限る**。(1) 調査中の不審な IP の
トリアージ（MCP 経由のエージェントとアナリスト）、(2) 自社の利用者のログイン元が中継点
かの確認。(2) では自社の利用者の IP（個人データ）を外部サービスへ送ることになる（§7）。
顧客から受けた調査（IR 案件）での利用は ipapi.is の規約 §2.3 が禁じるため、範囲外とする。

## 2. Functional Specification

### Commands / API Surface

**CLI**

```
vpn-lookup [flags] <ip> [ip...]   # 引数で 1〜複数件。引数なしなら stdin から 1 行 1 件
  --json            # 構造化出力（既定は人間向けテキスト）
  --no-cache        # キャッシュを無視して再照会
  --timeout <dur>   # 上流タイムアウト
  --config <path>   # 設定ファイル
  --clear-cache     # キャッシュを全消去（ipapi.is §2.5 の削除義務に応えるため）
  --version         # 必須応答（brew test が叩く）
vpn-lookup mcp      # ローカル MCP サーバー（stdio）
```

- IPv4 / IPv6 を自動判定。サブコマンド分割はしない（入力から意図が一意に決まる）
- **公開 IP 以外はその場で拒否し、外部へ送らない**（exit 2）。判定は shodan-lookup の
  `internal/ipaddr` を移植する。これは 100.64/10（CGNAT）、文書用・ベンチマーク用の範囲、
  ULA、サイトローカル、2000::/3 の許可リストを持ち、IPv4 射影・NAT64・6to4・Teredo・
  IPv4 互換の IPv6 は中の IPv4 を取り出して判定する。**送るのは取り出した後の IPv4**
- 入力は `netip.Addr` で正規化（`String()`）し、重複を除いてから送る。全件の検証が
  通ってから照会を始める（1 件でも不正なら何も送らない）
- 1 回の呼び出しは 100 件まで。数千件の一括処理は範囲外

**MCP ツール**

| tool | 役割 |
|---|---|
| `check_ip` | 1〜100 件の IP に判定と根拠を返す |
| `cache_status` | キャッシュの件数・TTL・場所、有効なソース、各ソースの残り照会回数（取れる範囲で） |
| `get_usage` | 操作マニュアル（usage.md を埋め込み、メタテストでコードと照合）。ログイン元の確認（使い方 2）は照会回数をすぐ使い切ることも書く |

キーが 1 つも無くても MCP サーバーは起動し、`cache_status` と `get_usage` は答える。
`check_ip` は構造化エラー `no_api_key` を返す。CLI はキーが無ければ使用法エラー（exit 2）。

### Input / Output

**判定（`verdict`）**

| 値 | 意味 |
|---|---|
| `tor` | Tor の出口 |
| `vpn` | 商用 VPN の出口・サーバー |
| `relay` | 管理されたプライバシー中継（iCloud Private Relay、Cloudflare WARP）。裏にいるのはその利用者 |
| `gateway` | 企業向け Web ゲートウェイ（Zscaler、Netskope 等）。**多数の企業が共有するので、IP から組織は特定できない** |
| `mail_gateway` | メールのセキュリティ中継（Proofpoint、Mimecast、Barracuda）。受信ヘッダに現れるのはこの事業者の中継 |
| `dns_resolver` | 公開 DNS リゾルバ（Google Public DNS、Cisco OpenDNS）。通信はリゾルバの問い合わせで、利用者本人ではない |
| `satellite` | 衛星 ISP（Starlink、Viasat）。**中継点ではなく実在する利用者の回線**だが、CGNAT で多数が共有し所在地も当てにならない |
| `proxy` | プロキシ（公開プロキシ、または住宅用プロキシ）。**住宅用プロキシは実在する家庭の回線**でもある — `proxy_kind` と運営者のサービスを読む |
| `hosting` | クラウド・ホスティング・CDN（誰でも借りられるサーバー）。クローラーなら `crawler` に名前が付く |
| `none` | 有効なソースがすべて答え、中継の兆候が無かった。**家庭回線だという断定ではない** |
| `unknown` | 兆候は見つからなかったが、有効なソースのどれかが失敗した。`none` と読んではならない |

**合成の規則（段階 0 の実測と独立検証で決定）**

1. ipapi.is が管理されたサービス（`egress_service`）を名指ししたら、その種類で判定する:
   `private_relay` → `relay`、`secure_web_gateway` → `gateway`、`email_gateway` →
   `mail_gateway`、`dns_resolver` → `dns_resolver`、`satellite` → `satellite`。未知の種類は
   `egress_service` をそのまま根拠に出し、規則 2 へ進む
2. 名指しがなければ、どちらかのソースが挙げた最も強い分類: `tor` > `vpn` > `proxy` > `hosting`
3. どちらも何も挙げず、有効なソースがすべて答えたら `none`。どれかが失敗していたら `unknown`
4. 判定と別に `seen_by`（`both` / `ipapi` / `proxycheck`）を返す。片方だけの検出は
   食い違いではなく検出範囲の差として扱う（`conflicting` は設けない）
5. ipapi.is のキーが無いときは規則 1 が使えない。proxycheck.io は iCloud Relay を `vpn`、
   Zscaler を `hosting` と答えるので、結果に「relay / gateway 等の識別は使えない」と示す

**判定に添える情報**

- `mobile`（携帯回線）、`crawler`（ボットの名前）、`proxy_kind`（公開／住宅用、運営者の
  サービスから分かる範囲）、ipapi.is の `vpn.last_seen`（古い VPN 判定を見分ける）
- 評判（ipapi.is の `is_abuser`、proxycheck.io の `risk`）は参考情報として出すだけ
- 地理位置は出さない

**1 件分の結果（JSON、項目は段階 1 で確定）**

```json
{
  "ip": "45.142.26.2",
  "verdict": "vpn",
  "seen_by": "both",
  "mobile": false,
  "crawler": null,
  "providers": { "ipapi": "MullvadVPN", "proxycheck": "Mullvad" },
  "ipapi": {
    "enabled": true,
    "is_vpn": true, "is_proxy": false, "is_tor": false, "is_datacenter": true,
    "is_mobile": false, "is_abuser": false, "is_crawler": false,
    "vpn_service": "MullvadVPN", "vpn_last_seen": "2026-11-06T12:43:23Z",
    "datacenter": "Keminet SHPK",
    "egress_service": null, "company_type": "business"
  },
  "proxycheck": {
    "enabled": true,
    "vpn": true, "proxy": false, "tor": false, "hosting": true,
    "risk": 50, "confidence": 100,
    "operator": "Mullvad", "operator_services": ["datacenter_vpns"],
    "network_type": "Hosting", "delist_datetime": "2026-11-07T03:35:58Z"
  },
  "degraded": false,
  "from_cache": false
}
```

- キーの無いソースは `enabled: false`（照会していない）とし、その真偽値はすべて `null`
  にする（`false` は「照会して違った」の意味に限る）
- `egress_service` は `{type, provider}` のオブジェクトのまま出す
- 事業者名・運営者名・会社名・WHOIS 由来の名前・上流のエラー文は**第三者が書いた文字列**
  として扱い、制御文字と書式文字（双方向制御・ゼロ幅）を取り除く。MCP の結果にもその旨を
  書く（malware-lookup v0.4.0 と同じ規則）
- exit code: `0` 全件完了 / `1` ソース障害（結果は出す）/ `2` 使用法・入力エラー。
  判定は exit code に載せない

### Configuration

`~/.config/vpn-lookup/config.toml`（XDG 準拠）と `VPN_LOOKUP_*` 環境変数（環境変数が優先）。

```toml
[ipapi]
api_key = "..."

[proxycheck]
api_key = "..."

[cache]
ipapi_ttl_hours = 24   # 既定 24 時間。30 日（720 時間）を超える値は拒否

[network]
timeout_seconds = 15
```

- キーはどちらも任意で、**キーの無いソースは使わない**
- ipapi.is はキーなしだと判定フラグが返らない（実測）ので、キーなしで使う意味が無い
- **キーは組織に 1 つずつ。** 無料枠は ipapi.is が「1 人または 1 法人に 1 回」（§2.9）、
  proxycheck.io が「1 顧客に無料アカウント 1 つ」で、複数アカウントはどちらも禁止。
  同じ組織の分析者はキーを共有する（proxycheck.io のキーは組織内なら共有できる）
- TOML の読み込みは組織のデコーダ `nlink-jp/toml`（ADR-026）を使う

### External Dependencies

| 依存 | 用途 | 認証 |
|---|---|---|
| ipapi.is API（`https://api.ipapi.is`） | VPN・プロキシ・Tor・データセンター・モバイル・クローラー・管理されたサービスの判定、事業者名 | 組織の無料アカウントのキー。POST の JSON 本文で送る（URL に載せない） |
| proxycheck.io v3 API（`https://proxycheck.io/v3/`） | VPN・プロキシ・Tor・ホスティングの判定、運営者名、リスク | 組織の無料アカウントのキー（置き場所は §7 の未決） |

Go 標準ライブラリ以外の依存は持たない（TOML は組織内ライブラリ）。

## 3. Design Decisions

- **言語は Go、標準ライブラリのみ。** 組織のサプライチェーン方針。MCP の骨格は lookup 系の
  兄弟から移植し、移植元はパッケージ単位で最新のもの（`git log -1 -- internal/<pkg>`）を
  選ぶ。公開 IP の判定は shodan-lookup の `internal/ipaddr` を移植する
- **1 つのツールで 2 つのソースを重ねる。** 問いは「中継点か」の 1 つで、2 つのソースの
  一致・不一致がそのまま判断材料になる（malware-lookup と同じ型）
- **判定は 1 つにまとめ、`seen_by` で裏付けを示す。** 当初案の `conflicting` は、VPN が
  データセンターに置かれることと検出範囲の差から頻発すると見込み、実測（9 見本中 4 件で
  分類が異なる）を受けて廃止した
- **ipapi.is の `egress_service` を最優先し、種類ごとに別の判定値にする**（利用者の判断）。
  iCloud Private Relay を proxycheck.io は `vpn`、Zscaler を `hosting` と答えた。裏にいる
  人が違えば次の行動が違う（企業の利用者・メールの送信者・DNS の利用者・衛星回線の利用者）
- **失敗を `none` と読ませない。** 兆候なしでもソースが失敗していれば `unknown`
- **既存ツールの結果は取り込まない。** tor-exit-lookup・icloud-relay-lookup（手元の確実な
  リスト）、asn-lookup（ASN・組織）、abuse-lookup（評判）との使い分けは mcp-tactics の IP の
  手順で示す。vpn-lookup はその「匿名化の出口か」の段を広げる
- **見られ方の順位付けでは段階 2（第三者への照会）・キー付き。** 照会した IP は 2 つのソースに届く
- **proxycheck.io には常に `tag=0` を付け、設定で外せないようにする。** 付けないと、匿名と
  判定した IP はアカウントの検出ログに 180 日残り、非匿名と判定した IP には中身が公開されて
  いない「照会後のテスト」がかかる（GDPR ページ）。`tag=0` でも正常判定の IP は推論のために
  5 分保持されうる。アカウント全体の「Address Logging」をダッシュボードで切ることを README で
  勧める
- **キーを運ぶ HTTP クライアントはリダイレクトを追わない**（Go は独自ヘッダを別ホストへ
  送る）。**エラー文に URL を含めない**（Go の `url.Error` は URL 全文を引用する）
- **「無し」は本文で確かめる**（knowledge「Decide `not_found` on the shape of the 404's
  body」）。ipapi.is の一括は無効な要素を黙って落とすので、**応答に無い要素は
  その IP の失敗**として扱う（「何も検出されなかった」と読まない）
- **キャッシュはソースごと。** ipapi.is は既定 24 時間（上限 30 日、規約 §2.2）。
  proxycheck.io は推奨に従い、正常は 1 時間、匿名は `delist_datetime` まで（最大 15 分）。
  ソースごとに保存するので、片方の障害がもう片方の照会回数を浪費させない。キャッシュの鍵には
  有効なソースの組を含める（キーを足したら引き直す）
- **proxycheck.io の `warning`（上限に近い、HTTP 200）は答えとして扱い、注意を添える**
- **範囲外:** 地理位置、評判を主眼にすること、proxycheck.io の使い捨てメール判定、有料プランや
  データベースのダウンロード、数千件規模の一括処理、自動の遮断判断、顧客の IR 案件での利用

## 4. Development Plan

### Phase 0: 実測（完了 2026-11-07）

利用者の無料キーで 9 つの見本（Tor 出口・iCloud Relay・Mullvad・AWS・Cloudflare IPv6・
フランスの家庭回線・NTT docomo・proxycheck.io の例・Zscaler）を照会し、§2 の合成規則と
キャッシュを決めた。続く設計の独立検証の指摘を反映した。結果は Discussion Log に記す。

### Phase 1: Core

- 入力の検証（`internal/ipaddr` の移植・正規化・重複除去）、2 つのクライアント（ipapi.is は
  POST 本文にキー・一括 100 件、proxycheck.io は常に `tag=0`）、判定の合成（純関数）、
  ソースごとのキャッシュ（`--clear-cache`）、設定、CLI
- **段階 1 の実測:** 両 API の未登録・誤ったパス・不正キー・上限超過・`warning` の応答、
  proxycheck.io の一括での要素ごとの失敗と途中での上限到達、`satellite` /
  `dns_resolver` / `email_gateway` / 住宅用プロキシ / クローラーの実例。応答の形は
  クライアントとテストに固定する
- **proxycheck.io のキーの置き場所を確定する:** ダッシュボードのカスタムルールで目印の
  項目を足し、本文にだけキーを入れて目印が返るかで判定する
- 残りの照会回数の取得（proxycheck.io はダッシュボード API。ipapi.is は調べる）
- テストはすべてオフライン（上流は偽のサーバー）。単独でレビュー可能

### Phase 2: MCP

- `check_ip` / `cache_status` / `get_usage`、閉じたスキーマと厳格な引数デコード（ADR-021）
- usage.md とツール・引数・判定値・エラーコードの一致をメタテストで固定
- stdio での動作確認。単独でレビュー可能

### Phase 3: Release

- 実サービス相手の e2e（キーは環境変数、無ければスキップ）、README（日英）、AGENTS.md、CHANGELOG
- README に書くこと: 組織自身の業務に限る（顧客の IR 案件は不可）、キーは組織に 1 つ、
  データは推定で自動遮断に使わない、照会した IP の行き先と保存場所、proxycheck.io の
  カスタムルールを設定しない（応答が書き換わる）、Address Logging を切る
- リリース前に独立検証
- 署名・notarize・リリース、Homebrew tap、cybersecurity-series への統合、org プロフィール・
  サイト・About、check-org

**他リポジトリへの依存（本計画の段ではない）:** リリース後、mcp-tactics（skills-series）に
サーバーの収載が必要になる。収載の判断と時期は mcp-tactics の所有者が決める。

## 5. Required API Scopes / Permissions

OAuth・IAM は無し。必要なのは無料アカウントの API キー 2 つだけ。

- ipapi.is: 組織の登録アカウントのキー（無料枠 1 日 1,000 件）
- proxycheck.io: 組織の登録アカウントのキー（無料枠 1 日 1,000 件）

無料枠はどちらも組織に 1 つまで（ipapi.is §2.9「1 人または 1 法人に 1 回」・複数アカウント
禁止、proxycheck.io「1 顧客に無料アカウント 1 つ」）。同じ組織の分析者はキーを共有し、
キーを組織の外には出さない（proxycheck.io）。「利用者が自分のキーを入れるソフト」の許可が
指す利用者は別の組織であって、同僚ではない。

## 6. Series Placement

Series: cybersecurity-series
Reason: IP の調査ツール群（asn・whois・abuse・tor-exit・icloud-relay・shodan-lookup）の
一員で、中継点の判定という未充足の段を埋める。

## 7. External Platform Constraints

| 項目 | ipapi.is | proxycheck.io |
|---|---|---|
| 無料枠 | キー付きで 1 日 1,000 件・完全な応答。キーなしは 1 日 30 件・判定フラグ無し・一括不可 | 登録で 1 日 1,000 件（ダッシュボードの Daily Limit で確認）。未登録は 100 件 |
| 一括 | POST で 100 件まで、1 件 1 カウント。重複と無効な要素は黙って落とされる | POST で 1,000 件まで（文書内に 10,000 の記述もあり食い違う） |
| 使える用途 | 社内用途のみ（§2.2）。無料枠も商用可と明記（§2.9）。第三者の IP に関する問いに答えるサービスは 1 件ずつでも不可（§2.3）→ 顧客の IR 案件は不可 | 目的の制限なし。利用者が自分のキーを入れるソフトを明示的に許可 |
| 照会した IP | 記録しない（プライバシー §3.3）。個人データは EEA 内に留めるとする（サーバーの所在地の明記は無い） | `tag=0` で記録も照会後テストも止まる。ただし正常判定の IP は推論のために 5 分保持されうる。データは生成された地域（カナダ・英国・EU・シンガポール）に保存 |
| キャッシュ | 30 日まで（§2.2）。契約終了から 30 日以内に削除（§2.5、個別事象の記録は保持可） | 推奨は正常 10 分〜1 時間・匿名 1〜15 分、または `delist_datetime` まで |
| エラー | JSON の `error_code`（`ERR_QUOTA_EXCEEDED` 等）。キーなし上限の無視はファイアウォールで 24 時間遮断 | v3 は HTTP の状態コード。上限に近いと `warning`（200）。**無効なキーは黙って未登録扱い**（実測） |
| その他 | — | ダッシュボードのカスタムルールは応答を書き換えられる（`type` 等）→ 設定しないことを前提にする |

**共通の注意**

- **データは確率的な推定。** ipapi.is §2.8 は、個人に法的な影響を与える判断の唯一の根拠に
  しないよう求める（GDPR 22 条）。ログイン元の確認でも自動遮断の根拠にしない、と README に明記する
- **自社の利用者の IP は個人データ。** 照会すると 2 つの外部サービスに届く。どこへ送られ、
  どこに保存されうるかを README に書く
- **TLS を検査する自社のゲートウェイは URL を丸ごと記録しうる。** proxycheck.io のキーを
  URL で送る場合、キーがそこに残る（未決の置き場所が本文で通るなら解消）

**未決（段階 1 で確定）**

- **proxycheck.io のキーを本文と URL のどちらで受け取るか。** 無効なキーでもエラーにならず、
  ダッシュボードの照会数も数分間 0 のままで、段階 0 では決められなかった。カスタムルールの
  目印で判定する（§4）。それまでは文書どおり URL とし、エラー文に URL を出さない
- ipapi.is の残り照会回数を取得できるか

---

## Discussion Log

- **発端（2026-11-07）:** 組織の OSINT ツール群を補う、無償枠のまま業務で使えるソースの調査
  （約 70 サービス）で、ipapi.is と proxycheck.io が条件を満たし、既存ツールに無い
  「中継点か・事業者は誰か」に答えると分かった。規約は本人が原文で再確認した
- **範囲:** 評判は参考扱いに留める（abuse-lookup の担当）。自社の利用者のログイン元確認も
  想定に含める。独立検証の指摘を受け、顧客の IR 案件では使わない（組織自身の業務に限る）と
  利用者が決めた
- **名前:** `egress-lookup`（出口の判定）を提案したが、利用者が分かりやすさから `vpn-lookup` を選んだ
- **件数と非公開 IP:** 1 回 100 件まで、数千件の一括は範囲外。プライベート等はその場で拒否
- **判定の規則:** 当初は `vpn` / `proxy` / `tor` / `hosting` / `none` / `conflicting` の案。
  `conflicting` が頻発する懸念から規則を実測後に決めることにし、実測を受けて `relay` /
  `gateway` を加え `conflicting` を廃止、`seen_by` で裏付けを示す形にした。独立検証で
  `egress_service` の未定義の 3 種類と「失敗が `none` に見える」問題が指摘され、利用者の
  判断で `mail_gateway` / `dns_resolver` / `satellite` を独立した値にし、`unknown` を加えた
- **段階 0 の実測（9 見本）:**
  - 両者一致: Tor 出口、Mullvad（事業者名 MullvadVPN / Mullvad まで一致）、AWS、
    Cloudflare IPv6（ipapi.is は anycast も付ける）、フランスの家庭回線
  - iCloud Relay: ipapi.is は datacenter＋`egress_service: private_relay`、proxycheck.io は vpn（運営者 iCloud）
  - Zscaler: ipapi.is は `egress_service: secure_web_gateway`（データセンター扱いにしない）、proxycheck.io は hosting
  - proxycheck.io の文書の例の IP: proxycheck.io だけが vpn、ipapi.is はデータセンターのみ
  - NTT docomo: ipapi.is だけが mobile、proxycheck.io は network type を "Business" とした
  - Tor 出口に ipapi.is は proxy と abuser も付けた。proxycheck.io の運営者は "TOR"
- **キャッシュ:** 当初は一律 24 時間、実測後に一律 1 時間。独立検証で「匿名判定の推奨は
  15 分まで」「劣化結果を保存しないと健全な側の回数を浪費する」「鍵に有効なソースを含める」と
  指摘され、ソースごとのキャッシュに改めた
- **キーの数:** 当初「利用者がそれぞれ自分のキー」と書いたが、独立検証で、両者とも無料枠は
  組織に 1 つで複数アカウントを禁じていると指摘され、「組織に 1 つ・組織内で共有」に改めた
- **proxycheck.io のキー:** 無効なキーを URL に入れても本文に入れても 200 で答え、照会数も
  増えないため、応答から判別できない。カスタムルールの目印で確かめる方法を独立検証が提案した
- **malware-lookup v0.4.0 の独立検証の教訓を引き継ぐ:** リダイレクト拒否、「無し」を本文で
  確かめる、第三者の文字列の消毒
