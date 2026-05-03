# SecretEnv: Local Trust Store の導入

---

## 1. このアップデートの概要

本アップデートでは、利用者のローカル環境に **local trust store** が追加されます。

ひとことで言えば、**「この鍵を以前に自分が確認した」という記録をローカルに保存できるようにする更新**です。

### 何が変わるのか

- secret の読み書き時に、signer / recipient の鍵（`kid`）が**自分の確認済みリストにあるかどうか**のチェックが入ります
- 未確認の `kid` に遭遇すると、対話的に承認を求められます
- 一度承認した `kid` は `known_keys` に記録され、次回以降は再確認なしで通ります
- `trust list` / `trust remove` / `trust purge` コマンドで承認履歴を管理できます

### 何が変わらないのか

- 署名検証の仕組み（埋め込み `signer_pub`）はそのままです
- 「誰が current member か」は引き続き repo 上の `members/active` が決めます
- チーム全体の trust policy や権限管理が追加されるわけではありません

つまり local trust store は、メンバー管理の代わりではなく、**利用者個人の承認キャッシュ**です。

---

## 2. 導入の背景

旧版では、日常的に `decrypt`、`get`、`run`、`set` などを使うたびに、signer や recipient が正当か毎回ゼロから判断する必要がありました。しかし現実には、同じチームメンバーの鍵を毎回確認し直すのは負担が大きすぎます。

負担が大きいと、利用者は確認を流しがちになり、結果として「確認する設計」が「何も見ずに進める運用」になってしまいます。

local trust store は、**最初の確認は利用者自身が行い、その結果を覚えておくことで次回以降の確認を省略する**仕組みです。確認そのものをやめるのではなく、同じ確認を繰り返さずに済むようにします。

---

## 3. 三つの検証レイヤー

local trust store を理解する上で重要なのは、以下の三つの役割を混同しないことです。

| レイヤー | 何を見るか | 担う役割 |
|----------|-----------|---------|
| `signer_pub` | 暗号 artifact に埋め込まれた署名者鍵 | 署名の暗号学的検証 |
| `members/active` | repo 上のメンバー一覧 | current member / recipient の判定 |
| `known_keys` | 利用者ローカルの trust store | 「自分が確認済みか」の記録 |

**`signer_pub`** は、artifact がどの鍵で署名されたかを自己完結に検証します。workspace への依存なく、署名の正しさだけを確認します。

**`members/active`** は、「その signer / recipient を今のチームとして認めるか」の判定基準です。repo 上にあるため、Git のアクセス制御と PR レビューで保護されます。

**`known_keys`** は、「この `kid` を自分が以前確認したかどうか」だけを覚えるキャッシュです。workspace やロール（signer / recipient）の区別なく、利用者ごと・グローバルに保持します。

### なぜ `known_keys` は workspace をまたいで共通なのか

`kid` は鍵ステートメントの識別子です。同じ鍵を別の clone や別の workspace で見かけたとき、毎回確認し直すのは非効率です。workspace ごとの状態は repo 側（`members/active`）が持ち、利用者の確認履歴は local 側が持つ、という分担です。

---

## 4. 日常操作への影響

### 4.1 読み取り時（decrypt / get / run）

本アップデートでは、暗号 artifact を読むとき、以下のすべてを満たす必要があります。

1. 署名が暗号学的に正しい（`signer_pub` で検証）
2. signer の `(member_handle, kid)` が `members/active` に存在する
3. signer の `kid` が `known_keys` にある、**または**今回対話で承認する

つまり、**署名が正しいだけでは足りず、その signer を自分が確認済みであることも求められます**。

自分自身（self）の鍵は、ローカルキーストアで既に trust 済みのため、`known_keys` チェックは省略されます。

### 4.2 書き込み時（encrypt / set / unset / import / rewrap）

書き込み時の recipient は `members/active` から導出されます。本アップデートでは、導出された各 recipient の `kid` についても、`known_keys` にあるか対話承認を求めます。

つまり、**読み取りだけでなく「誰に向けて暗号化するか」にも承認チェックが入ります**。

### 4.3 承認の対話プロンプト

未確認の `kid` に遭遇すると、以下のような情報が表示されます。

```
Trust review for signer:
  member_handle: bob@example.com
  kid: 7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD
  attestation fingerprint: SHA256:xxxx...
  GitHub アカウント id: 12345678 (bob-gh)
  Warning: First-contact trust is TOFU. Verify kid / GitHub id / fingerprint out of band.

Approve this key and add it to local trust store? [y/N]
```

`kid`、GitHub アカウント、SSH attestation fingerprint を、Slack やビデオ通話など**別の経路で本人に確認する**ことを推奨します。

---

## 5. 移行後にまずやること

### 5.1 既存メンバーの鍵を承認する

更新したら、まず active member の鍵を確認・承認します。

```bash
# 全 active member をまとめて検証・承認
secretenv member verify --approve

# 特定のメンバーだけ承認
secretenv member verify --approve alice@example.com bob@example.com
```

このコマンドは各メンバーについて以下を実行します。

1. PublicKey の offline 検証（スキーマ、自己署名、attestation）
2. GitHub binding がある場合は online 検証（GitHub API で SSH 鍵を照合）
3. 検証結果と判断材料（`kid`、attestation fingerprint、GitHub アカウント id/login）の表示
4. 対話的な承認確認

承認すると `known_keys` に記録され、以降の読み書きで同じ `kid` への再確認は不要になります。
すでに `known_keys` に存在する鍵は、このコマンドの結果には表示されません。

出力例:

```
✓ approved alice@example.com
✓ approved bob@example.com

Approved 2/2 members
```

### 5.2 trust store の状態を確認する

```bash
# 承認済みの鍵一覧を表示
secretenv trust list
```

出力例:

```
alice@example.com  3KX9V2D7... (approved: 2026-04-01T10:00:00Z, via: manual-review)
bob@example.com    7M2Q9D4R... (approved: 2026-04-01T10:05:00Z, via: manual-review)

2 known key(s)
```

---

## 6. 運用シナリオ

### 6.1 新規 workspace のセットアップ

`secretenv init` で workspace を作成すると、自分の PublicKey が `members/active` に配置されます。trust store は自動的には作成されません。自分の鍵は `known_keys` なしで信頼されるため、**一人目のメンバーは trust store なしでそのまま運用を開始できます**。

trust store は、他のメンバーの鍵を初めて承認した時点で自動作成されます。

### 6.2 新メンバーの受け入れ

```bash
# 1. 新メンバーが join する（incoming に入る）
#    ※新メンバー側で実行
secretenv join --member-handle newuser@example.com

# 2. 新メンバーの PR をレビュー・マージ後、
#    まだ承認していなければ先に verify --approve で確認
secretenv member verify --approve newuser@example.com

# 3. rewrap で incoming → active に昇格し、暗号ファイルを更新
secretenv rewrap
```

`rewrap` は以下の順序で処理します。

1. incoming candidate の検証（offline verify 必須）
2. `kid` 衝突検査（`known_keys` に別メンバーの同一 `kid` があれば拒否）
3. 未確認 `kid` がある場合は対話的に承認（non-interactive 実行では失敗）
4. candidate を active に昇格
5. 昇格後の member set で recipients を導出し、全暗号ファイルを再暗号化

**推奨:** `rewrap` の前に `member verify --approve` で承認を済ませておくと、`rewrap` 中の対話が減りスムーズです。

### 6.3 日常の secret 読み書き

承認済みの鍵しかないチームでは、旧版とほぼ同じ操作感で使えます。

```bash
secretenv get DB_PASSWORD       # 承認済みなら追加確認なし
secretenv set API_KEY=xxx       # 全 recipient が承認済みなら追加確認なし
secretenv run -- ./deploy.sh    # 承認済みなら追加確認なし
```

未承認の `kid` がある場合だけ対話プロンプトが表示されます。

### 6.4 鍵ローテーション

メンバーが新しい鍵（新しい `kid`）を使い始めた場合:

```bash
# 新しい kid を確認・承認
secretenv member verify --approve alice@example.com

# 暗号ファイルを新しい鍵で更新
secretenv rewrap
```

旧 `kid` を `known_keys` からすぐに削除する必要はありません。`known_keys` はあくまで確認履歴であり、「この `kid` は current member の鍵である」という意味は `members/active` が担います。

### 6.5 退役した signer の artifact を読みたい場合

`members/active` から外れた元メンバーが署名した artifact は、通常の read-path では拒否されます。一回限りの例外読み取りが必要な場合は、**non-member acceptance** が対話的に提示されます。

```
Non-member acceptance for signer:
  member_handle: ex-member@example.com
  kid: 5FT8K3N2...
  ...
Accept this artifact one time only? [y/N]
```

この受理は:
- **その 1 回限り**で、次回は再度確認が必要です
- `known_keys` は更新されません
- signer を active に戻したことにはなりません

---

## 7. trust store の管理コマンド

以下のコマンドは、利用者ローカルの承認キャッシュだけを操作します。`members/active` やチームの状態には影響しません。

### `trust list` — 承認済み鍵の一覧

```bash
secretenv trust list
```

### `trust remove <kid>` — 特定の鍵の承認を取り消す

```bash
secretenv trust remove 7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD
```

`trust remove` は、その member をチームから外す操作ではありません。次回その `kid` に遭遇したとき、改めて対話承認を求められるようになるだけです。

用途: 承認を誤った場合のやり直し、確認のリフレッシュなど。

### `trust purge --older-than <期間>` — 古い承認の一括削除

```bash
# 180日以上前の承認を削除
secretenv trust purge --older-than 180d

# 確認プロンプトをスキップ（CI 等）
secretenv trust purge --older-than 180d --force
```

対話実行では削除対象のプレビューと確認プロンプトが表示されます。non-interactive 実行には `-f` または `--force` が必要です。

定期的な purge により、古くなった承認を一掃して再確認を促すことができます。

---

## 8. CI/CD での利用

### `SECRETENV_STRICT_KEY_CHECKING=no`

CI 環境など non-interactive な実行では、対話的な承認ができません。`SECRETENV_STRICT_KEY_CHECKING=no` を設定することで、**read-path に限って** `known_keys` チェックを省略できます。

```bash
SECRETENV_STRICT_KEY_CHECKING=no secretenv get DB_PASSWORD
SECRETENV_STRICT_KEY_CHECKING=no secretenv run -- ./deploy.sh
```

**省略されるもの:**
- `known_keys` による承認チェック（read-path のみ）

**省略されないもの:**
- 署名の暗号学的検証
- `signer_pub` の検証
- `members/active` によるメンバーチェック

**注意:**
- **write-path には効きません**。`encrypt` / `set` / `rewrap` は引き続き全 recipient の承認が必要です
- bootstrap 直後の未レビュー clone での使用は推奨しません
- 信頼できる CI 環境で、`members/active` のレビュー体制が整っている前提で使ってください

---

## 9. trust store の保存場所

```text
${SECRETENV_HOME:-~/.config/secretenv}/trust/<owner_handle>.json
```

- repo 外に配置されるため、Git の管理対象にはなりません
- clone や branch をまたいで同じ承認キャッシュを再利用できます
- ファイルは自分の鍵で署名されており、改ざんや破損を検知できます

---

## 10. 変更前後の比較

| 観点 | 旧版 | 本アップデート |
|------|------|-----|
| 署名検証 | 埋め込み `signer_pub` | 同じ |
| メンバー判定 | `members/active` | 同じ |
| 未確認の鍵への対応 | 都度確認、または確認なしで通過 | 対話的な承認が必須 |
| 確認結果の記録 | なし | `known_keys` に保存 |
| workspace をまたぐ承認 | なし | 同一 trust store で再利用 |
| read-path の追加条件 | なし | signer `kid` が承認済みであること |
| write-path の追加条件 | なし | 全 recipient `kid` が承認済みであること |
| trust store 管理 | なし | `trust list` / `remove` / `purge` |

---

## 11. 知っておくべきこと

### TOFU（Trust On First Use）の限界

local trust store は SSH の known_hosts と同様の TOFU モデルを採用しています。初回の承認時に誤った鍵を承認すると、その誤りがキャッシュされます。暗号学的にこれを防ぐ仕組みはありません。

初回承認時は、**別の経路（Slack、ビデオ通話、対面）で `kid` や GitHub アカウント id を確認する**ことが重要です。

### `members/active` は repo governance に依存する

`members/active` はメンバー判定の基準ですが、repo 上のデータです。Git のアクセス制御と PR レビューの体制が trust の前提です。

### local trust store はローカルファイル

trust store は署名で整合性を検知できますが、ローカルファイルシステムの安全性は OS レベルのセキュリティに依存します。

---

## 12. まとめ

local trust store は、secretenv の基本思想を変えるものではありません。

- workspace をそのまま信頼しない
- 各ユーザーが受理判断に関与する
- 判断材料はツールが提示する

変わるのは、**確認結果を利用者ローカルに保存して再利用できるようになること**だけです。

移行のポイント:

1. **まず `member verify --approve` を実行**して、既存メンバーの鍵を承認する
2. 日常操作は承認済みなら旧版と同じ感覚で使える
3. 未確認の鍵に遭遇したら対話承認が求められる — これは安全のために必要な確認
4. `trust list` / `trust remove` / `trust purge` で承認キャッシュを管理できる
5. CI では `SECRETENV_STRICT_KEY_CHECKING=no` で read-path の承認チェックを省略可能
