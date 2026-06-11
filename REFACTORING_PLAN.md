# kapsaro リファクタリング計画

作成日: 2026-06-10
対象リビジョン: 36c6565 (main)

## 1. 目的

長期間の開発で蓄積した構造的な無駄（重複コード、過剰な間接層、肥大化したモジュール）を
段階的に解消し、保守コストと変更コストを下げる。外部から見た機能・CLI 仕様・
ワイヤーフォーマット・公開 API の互換性は維持する。

## 2. 現状分析

### 2.1 規模の概況

| 領域 | 行数 |
| --- | --- |
| ルート crate `src/`（CLI） | 約 7,500 行 |
| `crates/kapsaro-core/src/` | 約 40,400 行 |
| ルート crate `tests/` | 約 16,200 行 |
| `crates/kapsaro-core/tests/` | 約 39,600 行 |

テストコード（約 56,000 行）が実装コード（約 48,000 行）を上回っており、
テスト基盤そのものが最大の保守負債になっている。

core 内部のモジュール別では `app/` が約 12,000 行、`feature/` が約 9,800 行、
`io/` が約 6,100 行で、ユースケース層に重量が偏っている。

### 2.2 健全な点（リファクタリング対象外）

- `cargo clippy --workspace --all-targets` は警告ゼロ
- `#[allow(dead_code)]` は 4 箇所のみ、TODO/FIXME はほぼなし
- レイヤー依存方向は文書化されており、`feature/recipient` など共通化済みの部分も多い
- 公開 API 境界テスト（`tests/public_api.rs`）が存在する

つまり「小さな汚れ」は少なく、問題は以下のような構造レベルに集中している。

### 2.3 特定した構造的な無駄

A. テストヘルパーの二重管理
`tests/test_utils/` と `crates/kapsaro-core/tests/test_support/` に同名ファイルが並存し、
`crypto_context.rs` と `ed25519_backend.rs` は完全に同一、`constants.rs` と
`fixture.rs` もほぼ同一。修正が常に 2 箇所必要になっている。

B. `cli_api::test_support` ブリッジの肥大化
727 行・145 の `pub use` 文で 429 個の名前を再エクスポートしており、「内部 layer root
の mirror は作らない」という設計意図に反して、実質的に core 内部構造の写し鏡に
なりつつある。内部モジュールの改名・移動のたびにこのファイルの追従が必要。

C. テスト登録の手作業ボイラープレート
core の外部ユニットテスト 118 ファイル、内部ユニットテスト 70 ファイルがすべて
`#[path]` 属性による手動登録で、テスト追加のたびに 2〜3 箇所の編集が要る。

D. file / kv の並行二重構造
`model/file_enc` と `model/kv_enc`、`format/file` と `format/kv`、
`feature/rewrap/file_op` と `feature/rewrap/kv_op`、`api/file.rs` と `api/kv.rs` のように、
ファイル暗号化と KV 暗号化で同型の階層が全レイヤーを貫いて並走している。
共通ヘルパーへの抽出は部分的に済んでいるが、受信者操作・署名検証・rewrap の
オーケストレーションには同型ロジックが残る。

E. app 層の肥大化
`app/` は production コードの約 25% を占める。`app/file/inspect.rs`（642 行）、
`app/trust/enforcement.rs`（401 行）など、1 ファイル内に複数の責務が同居している。
各コマンドの workspace / config / keystore / 信頼ストア解決の前処理が
コマンドごとに繰り返されている。

F. エラー型の多層化
`Error`/`ErrorKind`（crate 共通）に加えて `CryptoError`、`SshError`、`FormatError`、
`KeyPossessionProofError` が併存し、層間の変換コードが分散している。

G. リファクタリング履歴の示す高い変更コスト
全 361 コミット中 102 件（約 28%）が refactor コミットであり、構造変更のたびに
広範囲の追従修正が発生してきたことを示す。上記 A〜C の解消はこの追従コストを
直接削減する。

## 3. 進め方の原則

- 1 フェーズ = 複数の小さな PR に分割し、各 PR は単一の関心事に限定する
- 全フェーズを通して機能追加・仕様変更は行わない（純粋なリファクタリング）
- 各 PR で `cargo test --workspace`、`cargo clippy --workspace --all-targets`、
  `cargo fmt -- --check` を通す
- 旧構造との互換ラッパーは残さず、呼び出し側を一括で移行する
- フェーズ開始時と完了時に `cargo llvm-cov --workspace` でカバレッジを記録し、
  低下していないことを確認する
- 各フェーズの完了条件を満たすまで次フェーズに着手しない（ただし独立性の高い
  Phase 3 と Phase 4 は並行可能）

## 4. フェーズ計画

### Phase 0: 計測基盤とベースライン確立

目的: 以降のフェーズで「削って壊れていない」ことを機械的に確認できる状態を作る。

作業項目:
1. `cargo llvm-cov --workspace` でカバレッジのベースラインを取得し記録する
2. `tests/public_api.rs` の API スナップショットが現状の公開面を網羅しているか点検し、
   不足があれば追補する（`api/` 配下の全公開型・関数）
3. `cli_api::app` / `cli_api::presentation` の allow-list についても境界テストの
   カバー状況を確認する
4. 規模メトリクス（モジュール別行数、`test_support` の再エクスポート数）を
   本書末尾の付録に記録し、フェーズごとに更新する

完了条件:
- カバレッジと API スナップショットのベースラインが記録されている
- 公開 API・`cli_api` 境界の変化を CI で検知できる

リスク: ほぼなし。実装コードに触れない。

規模感: 小（PR 1〜2 本）

### Phase 1: テスト基盤の統一

目的: 二重管理されたテストヘルパーを一本化し、テスト追加・修正のコストを半減させる。

作業項目:
1. `tests/test_utils/` と `crates/kapsaro-core/tests/test_support/` の差分を精査し、
   共有可能なヘルパー（`crypto_context.rs`、`ed25519_backend.rs`、`constants.rs`、
   `fixture.rs`、`context_options.rs`）を単一の置き場に統合する
   - 推奨: workspace 内に dev 専用 crate `crates/kapsaro-test-support` を新設し、
     両 crate の dev-dependencies から参照する
   - CLI 固有ヘルパー（`internal_cli.rs`、`tests/cli/common.rs`）はルート crate 側に残す
2. 統合後、旧ヘルパーファイルを削除し、全テストの import を新パスへ移行する
3. `tests/cli/common.rs`（748 行）を責務単位（ワークスペース構築、コマンド実行、
   アサーション補助）に分割する

完了条件:
- 同一内容のヘルパーファイルが workspace 内に 1 つも残っていない
- テスト総数が減っていない（テスト本体は変更しない）
- カバレッジがベースラインから低下していない

リスクと対策:
- dev 専用 crate が誤って production 依存に入るリスク
  → `[dev-dependencies]` のみで参照し、Phase 0 の境界テストで検知する
- feature flag（`cli-test-support`）との関係整理が必要
  → ヘルパー crate は `cli_api::test_support` 経由のアクセスのみ行い、境界は変えない

規模感: 中（PR 3〜4 本）

### Phase 2: test_support ブリッジの縮減とテスト配置の適正化

目的: 429 個の再エクスポート名を棚卸しし、core 内部の構造変更がテスト基盤に
波及しない状態にする。

作業項目:
1. `cli_api::test_support` の再エクスポートごとに、参照しているテストを分類する
   - (a) crate 内部の実装詳細を検証しているもの
     → `tests/unit/internal/`（`#[cfg(test)] #[path]` 方式）へ移設し、
       ブリッジ経由のアクセスを廃止する
   - (b) 実質的に公開 API / `cli_api::app` 相当の振る舞いを検証しているもの
     → `api` / `cli_api::app` 経由の呼び出しに書き換える
   - (c) どのテストからも参照されていないもの → 即時削除する
2. 上記により `test_support` の再エクスポート名を削減する（目標: 429 → 100 以下）
3. `tests/unit.rs` の `#[path]` 手動登録を、ディレクトリ単位の `mod` 宣言ファイル
   自動生成（build script もしくは単純な `mod.rs` 階層化）に置き換え、
   テスト追加時の編集箇所を 1 箇所にする
4. 外部ユニットテスト（118 ファイル）のうち、内部実装の検証になっているものを
   internal 側へ移し、external は境界検証に純化する

完了条件:
- `test_support` の再エクスポート数が目標値以下
- テスト追加手順が「ファイルを置くだけ + 1 箇所登録」以下になっている
- カバレッジ非低下、テスト実行時間の悪化なし

リスクと対策:
- テスト移設時の意図しないカバレッジ欠落
  → 移設は 1 モジュール群ずつ行い、PR ごとにカバレッジ差分を確認する

規模感: 大（PR 6〜10 本）。Phase 1 完了が前提。

### Phase 3: file / kv 並行構造の統合

目的: 全レイヤーを貫く file-enc / kv-enc の同型コードを、共通抽象に寄せて
将来のフォーマット変更コストを半減させる。

作業項目:
1. 現状調査: 両系統で同型になっている処理を一覧化する
   （受信者 wrap の追加・削除、removed history 管理、署名・検証フロー、
   rewrap オーケストレーション、inspect の共通項目）
2. `model` 層に共通トレイト（例: 署名対象ドキュメント、受信者保持ドキュメント）を
   定義し、`FileEnc` / `KvEnc` 双方に実装する
3. `feature/rewrap/file_op` と `feature/rewrap/kv_op`、`feature/recipient`、
   `feature/disclosure` の同型ロジックをトレイト境界のジェネリクスへ統合する
4. `app/rewrap/artifact.rs`（362 行）のファイル / KV 分岐を共通パスに整理する
5. `api/file.rs` と `api/kv.rs` の facade は外部互換のため現状のシグネチャを保ち、
   内部実装のみ共通化する

完了条件:
- 受信者操作・rewrap の中核ロジックが単一実装になっている
- `kapsaro_file_enc_schema.json` / `kapsaro_kv_enc_schema.json` への適合テストが
  すべて通過し、ワイヤーフォーマットに変化がない
- 公開 API スナップショットに意図しない差分がない

リスクと対策:
- 過度な抽象化により可読性が落ちるリスク
  → 統合は「3 箇所以上で同型」の処理に限定し、2 系統しかない単純な分岐は残す
- 暗号処理の挙動差異の混入リスク
  → 統合前に両系統の既存テストでゴールデン出力（既知のドキュメント JSON）を固定し、
    統合後も同一出力であることを検証する

規模感: 大（PR 5〜8 本）。Phase 0 完了が前提。Phase 1・2 とは独立に進められる。

### Phase 4: app 層のスリム化

目的: ユースケース層の繰り返しパターンを共通化し、コマンド追加時の定型コードを減らす。

作業項目:
1. 各コマンドの前処理（workspace 検出 → config 解決 → keystore ロード →
   信頼ストア検証）を共通のコンテキスト構築パイプラインに集約する
   （既存の `app/context` を起点に、コマンド側は必要なコンテキスト種別を宣言するだけにする）
2. 30 行を大きく超える関数を持つ大型ファイルを責務単位に分割する
   - `app/file/inspect.rs`（642 行）: 収集・整形・検証の分離
   - `app/trust/enforcement.rs`（401 行）
   - `app/doctor/` 配下（types.rs 271 行を含む計 1,200 行超）: 診断項目の共通インターフェース化
3. CLI 側 `src/cli/common/output/` のテキスト整形（member 277 行、key 266 行）の
   共通整形ヘルパー抽出
4. 分割・共通化に伴い不要になった結果 DTO・変換コードを削除する

完了条件:
- コマンド実装ファイルから重複した前処理コードが消えている
- 1 関数 30 行程度の目安を超える関数が app 層に残っていない
- app 層の総行数が現状（約 12,000 行）から有意に減少している

リスクと対策:
- コンテキスト構築の共通化で各コマンド固有のエラーメッセージが失われるリスク
  → CLI E2E テスト（`tests/cli/`）のメッセージ検証を先に確認し、文言を維持する

規模感: 大（PR 6〜10 本）。Phase 3 との並行可。

### Phase 5: エラー処理とサポート層の整理

目的: 分散したエラー型と変換コードを整理し、エラー分類の一貫性を高める。

作業項目:
1. `CryptoError` / `SshError` / `FormatError` / `KeyPossessionProofError` から
   crate 共通 `Error` / `ErrorKind` への変換経路を棚卸しし、変換ロジックを
   各エラー型定義の隣（`From` 実装）に集約する
2. 同一の失敗状況に複数の `ErrorKind` が割り当てられていないか点検し、分類を統一する
3. `support/` 配下のユーティリティで、Phase 1〜4 の結果使われなくなったものを削除する
4. エラーメッセージ文言の重複（同文言の手書き重複）を定数または構築関数に集約する

完了条件:
- エラー変換が `From` 実装に統一され、呼び出し側に手書き変換が残っていない
- `cargo llvm-cov` で support 層に未使用コード由来の未カバー領域がない

規模感: 中（PR 3〜5 本）。Phase 1〜4 完了後。

### Phase 6: テストスイートの再編と総仕上げ

目的: E2E・外部ユニット・内部ユニットの三層で重複しているカバレッジを整理し、
テスト実行時間と保守量を削減する。

作業項目:
1. カバレッジレポートを使い、同一分岐を三層すべてで検証しているテストを特定する
2. 検証の役割分担を再定義する
   - CLI E2E: 引数解釈・出力・終了コードの確認に限定
   - 外部ユニット: `api` / `cli_api` 境界の契約検証
   - 内部ユニット: アルゴリズム・エッジケースの検証
3. 役割の重複したテストケースを、最も適切な層 1 箇所に統合する
4. 最終メトリクス計測と本書付録の更新、残課題の棚卸し

完了条件:
- カバレッジがベースラインから低下していない
- テスト総行数とワークスペース全テストの実行時間が削減されている
- 全フェーズの完了条件が維持されている（回帰なし）

リスクと対策:
- テスト削減による検出力低下
  → 削除ではなく「層の移動・統合」を原則とし、カバレッジ差分ゼロを各 PR の条件にする

規模感: 中〜大（PR 4〜6 本）

## 5. フェーズ依存関係

```text
Phase 0 ──> Phase 1 ──> Phase 2 ──┐
   │                              ├──> Phase 5 ──> Phase 6
   ├──────> Phase 3 ──────────────┤
   └──────> Phase 4 ──────────────┘
```

Phase 3（file/kv 統合）と Phase 4（app 層）は Phase 1・2 と独立しており並行可能。
Phase 5・6 は全体の整理フェーズのため最後に行う。

## 6. 全体の完了基準

- 機能・CLI 仕様・ワイヤーフォーマット・公開 API に変化がない
- テストカバレッジがベースライン以上
- production コード・テストコードの総行数がそれぞれ削減されている
- テスト追加・モジュール移動時の編集箇所が削減されている
  （ヘルパー一本化、登録自動化、ブリッジ縮減の効果）
- clippy 警告ゼロ、fmt 違反ゼロを維持

## 7. 付録: ベースラインメトリクス（2026-06-10 時点、対象リビジョン 36c6565）

### 7.1 規模

| 指標 | 値 |
| --- | --- |
| production 総行数（src + core src） | 47,891 行（src 7,517 / core src 40,374） |
| テスト総行数（両 tests） | 55,774 行（ルート tests 16,153 / core tests 39,621） |
| core `app/` 行数 | 11,990 行 |
| core `feature/` 行数 | 9,798 行 |
| core `io/` 行数 | 6,082 行 |
| core `format/` 行数 | 3,384 行 |
| core `model/` 行数 | 1,985 行 |
| core `support/` 行数 | 1,637 行 |
| core `api/` 行数 | 1,603 行 |
| core `config/` 行数 | 1,138 行 |
| core `crypto/` 行数 | 1,118 行 |
| core `cli_api/` 行数 | 1,055 行 |
| `cli_api/test_support.rs` | 727 行 / 145 `pub use` 文 / 再エクスポート名 429 個 |
| 重複テストヘルパーファイル | 5 ペア（完全一致 2、ほぼ一致 2、拡張 1） |
| core 外部ユニットテストファイル数 | 120（直下 117 + サブモジュール 3、`#[path]` 登録 118） |
| core 内部ユニットテストファイル数 | 70 |
| `#[allow(dead_code)]` | 4 箇所 |
| clippy 警告 | 0 |

重複テストヘルパーの内訳（`tests/test_utils/` と
`crates/kapsaro-core/tests/test_support/` の同名ペア）:

| ファイル | 状態 |
| --- | --- |
| crypto_context.rs | 完全一致 |
| ed25519_backend.rs | 完全一致 |
| constants.rs | ほぼ一致（core 側に定数 1 件追加） |
| fixture.rs | ほぼ一致（core 側に関数 1 件追加） |
| context_options.rs | core 側が拡張版（22 行 / 49 行） |

### 7.2 カバレッジ（cargo llvm-cov --workspace）

| 指標 | 値 |
| --- | --- |
| Line | 88.88%（26,816 行中 2,983 未実行） |
| Function | 86.42%（3,306 個中 449 未実行） |
| Region | 86.82%（33,395 個中 4,401 未実行） |

### 7.3 テスト数と実行時間（llvm-cov 計測下の参考値）

| テストバイナリ | テスト数 | 実行時間 |
| --- | --- | --- |
| kapsaro bin 内部テスト | 122 | 0.3 秒 |
| ルート tests/unit.rs | 23 | 3.6 秒 |
| ルート tests/cli_integration.rs | 259 | 258.7 秒 |
| kapsaro-core lib 内部テスト | 493 | 66.7 秒 |
| kapsaro-core tests/unit.rs | 984 | 46.0 秒 |
| kapsaro-core tests/public_api.rs | 10 | 0.1 秒未満 |
| 合計 | 1,891（ignored 2 を含む） | 約 375 秒 |

### 7.4 API 境界テストのカバー状況（Phase 0 点検結果）

- `kapsaro_core::api` の公開 148 項目中 74 項目が `tests/public_api.rs` で未参照
  だったため、Phase 0 で全項目を参照するスナップショットテストを追補した
- `cli_api::app` / `cli_api::presentation` の allow-list 165 項目中 155 項目に
  境界テストの参照がなかったため、Phase 0 で再エクスポート名一覧の
  スナップショット照合テストを追補した（追加・削除の双方を検知）

各フェーズ完了時にこの表を更新し、効果を定量的に確認する。

### 7.5 Phase 6: 層別カバレッジと E2E テスト分類台帳（2026-06-11 計測）

#### 層別カバレッジ計測

`scripts/coverage-layers.sh` により、ユニット層（bin 内部・lib 内部・独立ユニット・
public_api）のみのカバレッジと、CLI E2E（cli_integration）を上乗せしたカバレッジを
分離計測した。

| 指標 | 値 |
| --- | --- |
| ユニット層の実行行（hit > 0） | 20,697 行 |
| ユニット層 + E2E の実行行 | 24,438 行 |
| E2E のみ到達の行（全体） | 3,741 行 |
| E2E のみ到達の行（core production） | 1,343 行 |

E2E のみ到達の core 行はユニットテストが検証していないドメイン到達点であり、
E2E テストを縮小する前に、この行をカバーするユニットテストを移譲先へ追加する。
主な分布: app/file 256、app/member 171、app/key 134、app/registration 125、
app/rewrap 143、app/kv 83、app/trust 75（app 層で約 1,100 行）、
feature 層は inspect 37、context 36、kv 30、key 22、envelope 22 など計約 160 行。

#### E2E テスト分類台帳

対象 8 領域の E2E テスト 153 件を全件分類した。分類の意味は次のとおり。

- 残す: CLI 表現（引数解釈・終了コード・出力文言・プロンプト・配管）の検証として維持する
- 縮小: CLI 表現の assert を残し、ドメイン細部の assert を内部ユニットテストへ移す
- 移譲: テスト全体を内部ユニットテストへ移し、E2E からは削除する

この台帳は Phase 6 の各 PR の削減上限を固定する。台帳にないテストの削除・変更は行わない。


#### tests/cli/rewrap/membership.rs

| テスト関数名 | 分類 | 移譲先（内部ユニットファイル） | 判定理由（1 行） |
|---|---|---|---|
| test_rewrap_adds_new_member | 移譲 | app_rewrap_execution_test.rs | rewrap 前後の KV wrap recipient handle だけを検証しており、CLI 表現の assert がない。 |
| test_rewrap_non_interactive_skips_prompt_for_known_incoming_kid | 移譲 | app_rewrap_promotion_test.rs | 非対話 prompt の有無ではなく BOB が recipient に入る状態だけを検証している。 |
| test_rewrap_non_interactive_skips_online_verify_for_known_incoming_github_binding | 移譲 | app_rewrap_promotion_test.rs | オンライン検証スキップの表示ではなく known incoming GitHub binding の recipient 追加だけを検証している。 |
| test_rewrap_non_interactive_auto_accepts_self_rotation | 移譲 | app_rewrap_promotion_test.rs | self rotation 後の recipient handle が Alice のままという内部状態だけを検証している。 |
| test_rewrap_accept_prompt_accepts_carriage_return_in_pty | 縮小 | app_rewrap_execution_test.rs | PTY prompt と carriage return 表示は CLI 固有だが、BOB 追加 assert は wrap 内部状態である。 |
| test_rewrap_rejects_self_incoming_when_local_identity_mismatches | 縮小 | app_rewrap_promotion_test.rs | 失敗終了と stderr 文言は残すが、self incoming の identity mismatch 判定は promotion 細部である。 |
| test_rewrap_removes_member_kv_enc | 移譲 | feature_rewrap_kv_test.rs | KV wrap と removed_recipients の recipient handle を直接検証しており、CLI 経由である必要が薄い。 |
| test_rewrap_removes_member_file_enc | 移譲 | feature_rewrap_file_test.rs | file-enc JSON の protected.wrap と removed_recipients を直接検証する内部構造テストである。 |
| test_rewrap_requires_recipient_trust_approval | 縮小 | app_rewrap_plan_test.rs | 失敗終了と Unknown recipient kid 表示は CLI 表現だが、trust approval gate は rewrap plan の細部である。 |
| test_rewrap_rejects_duplicate_kid_workspace_before_processing | 縮小 | app_rewrap_plan_test.rs | Duplicate kid の stderr は残すが、active/incoming の duplicate kid 検出は plan 細部である。 |

#### tests/cli/rewrap/operations.rs

| テスト関数名 | 分類 | 移譲先（内部ユニットファイル） | 判定理由（1 行） |
|---|---|---|---|
| test_rewrap_rotate_key | 縮小 | feature_rewrap_kv_test.rs | --rotate-key の CLI 経路は残すが、ファイル内容変化と wrap recipient handle は KV rewrap 内部状態である。 |
| test_rewrap_clear_disclosure_history | 縮小 | feature_rewrap_kv_test.rs | --clear-disclosure-history の CLI 経路は残すが、removed_recipients が空になる assert は内部状態である。 |

#### tests/cli/rewrap/preconditions.rs

| テスト関数名 | 分類 | 移譲先（内部ユニットファイル） | 判定理由（1 行） |
|---|---|---|---|
| test_rewrap_requires_workspace | 残す | なし | workspace 未解決時の失敗終了だけを検証しており、CLI 起動と終了コードを除くと検証内容が残らない。 |
| test_rewrap_with_no_files_fails_gracefully | 残す | なし | secrets に対象ファイルがない場合の失敗終了と No encrypted files の stderr 文言を検証している。 |
| test_rewrap_nonexistent_workspace_fails | 残す | なし | 存在しない --workspace 指定時の failure を検証する CLI 引数経路のテストである。 |
| test_rewrap_quiet_keeps_failed_file_details_on_stderr | 残す | なし | --quiet 時の色付き stderr とエラー文言を検証する CLI 表示テストである。 |
| test_rewrap_surfaces_insecure_trust_store_warning_on_stderr | 残す | なし | 成功終了しつつ Insecure permissions が stderr に出る警告表示を検証している。 |
| test_rewrap_surfaces_recipient_key_expiry_warning_on_stderr | 残す | なし | 成功終了と recipient key expiry warning の stderr 文言を検証している。 |

#### tests/cli/rewrap/roundtrip.rs

| テスト関数名 | 分類 | 移譲先（内部ユニットファイル） | 判定理由（1 行） |
|---|---|---|---|
| test_rewrap_file_enc_roundtrip | 残す | なし | rewrap 後に decrypt --out で復号できる file-enc の happy-path CLI roundtrip である。 |
| test_rewrap_kv_enc_roundtrip | 残す | なし | rewrap 後に get の stdout で値を取得できる KV の happy-path CLI roundtrip である。 |
| test_rewrap_json_output_uses_operation_outcome_shape | 残す | なし | --json stdout の success と summary 形状を検証する CLI JSON 契約である。 |

#### tests/cli/member.rs

| テスト関数名 | 分類 | 移譲先（内部ユニットファイル） | 判定理由（1 行） |
|---|---|---|---|
| test_member_list_shows_initialized_member | 残す | なし | member list の stdout に member handle と display kid が出ることを検証している。 |
| test_member_list_json_output | 残す | なし | member list --json の members.active 配列と protected.kid を検証する CLI JSON 構造テストである。 |
| test_member_list_empty_workspace | 残す | なし | 空 workspace で成功終了し No members found を stdout に出す表示契約を検証している。 |
| test_member_list_json_empty_workspace_outputs_empty_arrays | 残す | なし | 空 workspace の --json stdout が active/incoming 空配列になる CLI JSON 契約を検証している。 |
| test_member_list_json_skips_invalid_member_file | 縮小 | app_member_verification_test.rs | JSON と stderr warning は CLI 表現だが、改ざん member file の除外判定は member verification 細部である。 |
| test_member_show_displays_public_key | 残す | なし | member show の見出し、ラベル、非表示文言を stdout で検証する表示レイアウト依存テストである。 |
| test_member_show_reports_verification_warning | 残す | なし | expired 表示と has expired の stderr warning を検証する CLI 表示テストである。 |
| test_member_show_json_wraps_public_key_document | 残す | なし | member show --json の member.protected.subject_handle と kid を検証する CLI JSON 構造テストである。 |
| test_member_show_unknown_member_fails | 残す | なし | unknown member 指定時の failure を検証する CLI エラー経路である。 |
| test_member_show_invalid_member_fails | 移譲 | feature_member_verification_test.rs | CLI assert は failure のみで、attestation sig 改ざん member の検証失敗が本質である。 |
| test_member_verify_approve_requires_manual_confirmation_non_interactive | 残す | なし | 非対話 approve の failure と interactive confirmation の stderr 文言を検証している。 |
| test_member_verify_approve_debug_logs_candidate_verification | 残す | なし | --debug stdout の candidate verification trace と非対話確認エラーを検証している。 |
| test_member_verify_approve_accepts_member_handle_option_for_trust_store_owner | 残す | なし | --member-handle 有無による stderr 文言差を検証する CLI options 経路である。 |
| test_member_verify_approve_hides_already_known_results | 残す | なし | already known の member handle や Approved を stderr に出さない表示契約を検証している。 |
| test_member_verify_approve_json_skips_already_known_results | 残す | なし | --json stdout の results 空配列と stderr 非表示を検証する CLI JSON 契約である。 |
| test_member_remove_removes_from_workspace | 縮小 | app_member_mutation_test.rs | list/remove/list の CLI smoke は残すが、削除後に active list から消える状態変化は mutation 細部である。 |
| test_member_remove_without_force_in_non_interactive_mode_fails | 残す | なし | 非対話時の --force 要求 stderr と削除されていない list 表示を検証している。 |
| test_member_remove_nonexistent_fails | 残す | なし | nonexistent member の remove が failure になる CLI エラー経路である。 |
| test_member_remove_warns_on_tampered_artifact_but_continues | 縮小 | app_member_mutation_test.rs | 成功終了と stderr warning は残すが、改ざん artifact scan 継続は mutation 細部である。 |
| test_member_remove_debug_logs_artifact_scan | 残す | なし | --debug stdout の artifact scan trace と平文非表示を検証している。 |
| test_member_add_places_in_incoming | 残す | なし | member add の成功終了と Added member の stderr 表示を検証している。 |
| test_member_add_invalid_file_fails | 残す | なし | invalid JSON 入力時の failure を検証する CLI エラー経路である。 |
| test_member_add_duplicate_without_force_fails | 残す | なし | 重複 add without --force の failure を検証する CLI エラー経路である。 |
| test_member_verify_reports_offline_invalid_member | 残す | なし | failure と not found in active/ の stderr 文言を検証している。 |
| test_member_verify_ignores_invalid_incoming_member_when_verifying_all | 縮小 | app_member_verification_test.rs | --json results の外形は残すが、invalid incoming を無視する判定は verification 細部である。 |

#### tests/cli/trust.rs

| テスト関数名 | 分類 | 移譲先（内部ユニットファイル） | 判定理由（1 行） |
|---|---|---|---|
| test_trust_list_succeeds_without_ssh_agent | 残す | なし | ssh-agent なしで成功し stderr に handle と display kid を出す CLI 表示を検証している。 |
| test_trust_list_json_keeps_canonical_kid | 残す | なし | trust keys list --json の known_keys 配列と canonical kid を検証する CLI JSON 契約である。 |
| test_trust_recipients_list_text_shows_sid_hash_and_kids | 残す | なし | recipients list の stderr に SID、hash、display kid が出ることを検証している。 |
| test_trust_recipients_list_json_keeps_canonical_fields | 残す | なし | recipients list --json の recipient_sets、canonical kid、hash field を検証している。 |
| test_trust_recipients_remove_deletes_requested_sid | 縮小 | feature_trust_recipient_sets_test.rs | Removed recipient set 表示は残すが、指定 SID だけ消える状態変化は recipient set 細部である。 |
| test_trust_remove_prints_insecure_permission_warning | 残す | なし | permission warning、removal confirmation、display kid の stderr 表示を検証している。 |
| test_trust_remove_colors_warning_when_forced | 残す | なし | CLICOLOR_FORCE 時の ANSI warning と strip 後文言を検証している。 |
| test_trust_remove_requires_member_handle_when_keystore_is_ambiguous | 残す | なし | ambiguous keystore 時の failure、複数行 stderr、赤色適用範囲を検証している。 |
| test_trust_remove_accepts_member_handle_when_keystore_is_ambiguous | 残す | なし | --member-handle 指定で成功し Removed kid を stderr に出す CLI 経路を検証している。 |
| test_trust_remove_accepts_display_kid | 残す | なし | display kid を CLI 引数として受け、stderr に display kid を出すことを検証している。 |
| test_trust_remove_accepts_unique_prefix_kid | 残す | なし | unique prefix kid を CLI 引数として受け、stderr に display kid を出すことを検証している。 |
| test_trust_list_prints_warning_after_known_key_output | 残す | なし | known key 表示が permission warning より前に出る stderr 順序を検証している。 |
| test_trust_purge_with_force | 縮小 | feature_trust_known_keys_test.rs | purge 件数と empty list 表示は残すが、古い known key の削除状態は trust 細部である。 |
| test_trust_purge_accepts_member_handle_when_keystore_is_ambiguous | 残す | なし | ambiguous keystore で --member-handle 指定時の成功と purge 件数表示を検証している。 |
| test_trust_purge_without_force_in_non_interactive_mode_error | 残す | なし | 非対話 purge without --force の failure と stderr 文言を検証している。 |
| test_trust_recipients_purge_with_force_removes_only_old_records | 縮小 | feature_trust_recipient_sets_test.rs | purge 件数と list 表示は残すが、old record だけ削除される判定は recipient set 細部である。 |
| test_trust_recipients_purge_without_force_in_non_interactive_mode_error | 縮小 | feature_trust_recipient_sets_test.rs | failure と stderr 文言は残すが、失敗後に全 recipient set が残る状態確認は内部細部である。 |

#### tests/cli/key/export.rs

| テスト関数名 | 分類 | 移譲先（内部ユニットファイル） | 判定理由（1 行） |
|---|---|---|---|
| test_key_export_explicit_kid | 縮小 | app_key_export_test.rs（新設） | explicit kid と --out の CLI 経路は残すが、exported PublicKey の kid/subject_handle/format は app 細部である。 |
| test_key_export_active | 縮小 | app_key_export_test.rs（新設） | active key export の CLI smoke は残すが、exported PublicKey format の内部確認は app 細部である。 |
| test_key_export_accepts_display_kid | 縮小 | app_key_export_test.rs（新設） | display kid 引数の CLI 経路は残すが、exported PublicKey の kid 一致は app 細部である。 |
| test_key_export_private_rejects_short_password_by_default | 残す | なし | stdin password、failure、stderr 文言、Warning 非表示、出力ファイル未作成を検証している。 |
| test_key_export_private_colors_short_password_error_when_forced | 残す | なし | CLICOLOR_FORCE 時の ANSI error、strip 後文言、出力ファイル未作成を検証している。 |
| test_key_export_private_warns_for_allowed_weak_password_to_file | 残す | なし | 弱い password を許可した場合の success、stderr warning、出力ファイル作成を検証している。 |
| test_key_export_private_colors_short_password_warning_when_forced | 残す | なし | CLICOLOR_FORCE 時の ANSI warning と strip 後文言を検証している。 |
| test_key_export_private_warns_for_accepted_short_password_only_on_stderr | 残す | なし | --stdout の base64url 出力と warning が stderr のみに出る配管契約を検証している。 |
| test_key_export_private_does_not_warn_for_recommended_password | 残す | なし | 推奨長 password で success し stderr に warning 文言がないことを検証している。 |
| test_key_export_private_writes_password_protected_key_file | 縮小 | feature_key_portable_export_test.rs | --out success は残すが、base64url decode 後の PrivateKey subject_handle/format は portable export 細部である。 |
| test_key_export_private_writes_base64url_to_stdout_with_stdout_flag | 縮小 | feature_key_portable_export_test.rs | --stdout 出力は残すが、decode 後の PrivateKey subject_handle/format は portable export 細部である。 |
| test_key_export_private_requires_member_handle_before_password_input | 残す | なし | member handle 未設定が password mismatch より先に出る stderr 順序を検証している。 |
| test_key_export_private_requires_explicit_output_destination | 残す | なし | stdout 空、failure、requires either --out or --stdout の stderr を検証している。 |
| test_key_export_private_rejects_stdout_and_out_together | 残す | なし | --stdout と --out 同時指定時の failure と cannot be used with の stderr を検証している。 |

#### tests/cli/decrypt.rs

| テスト関数名 | 分類 | 移譲先（内部ユニットファイル） | 判定理由（1 行） |
|---|---|---|---|
| test_decrypt_help_aligns_multiline_usage | 残す | なし | --help stdout の Usage 改行位置を検証する clap 表示契約である。 |
| test_decrypt_missing_input | 残す | なし | 必須 input 欠落時の failure と clap stderr 文言を検証している。 |
| test_decrypt_rejects_kv_enc_format | 残す | なし | kv-enc 入力時の failure と Expected file-enc format の stderr を検証している。 |
| test_decrypt_rejects_unknown_format | 残す | なし | unknown format 入力時の failure と Expected file-enc format の stderr を検証している。 |
| test_decrypt_file_enc_roundtrip_with_out | 縮小 | feature_decrypt_test.rs | debug stdout と Decrypted to 表示は残すが、復号ファイル内容一致は decrypt 細部である。 |
| test_decrypt_rejects_tampered_file_enc_signature | 縮小 | feature_verify_file_operation_test.rs | Signature verification failed の stderr は残すが、改ざん artifact の復号拒否は verify/decrypt 細部である。 |
| test_decrypt_surfaces_private_key_expiry_warning_on_stderr | 残す | なし | decrypt 成功時に local key expiry warning を stderr に出す CLI 表示を検証している。 |
| test_decrypt_nonexistent_file_fails | 残す | なし | nonexistent path 指定時の failure を検証する CLI エラー経路である。 |
| test_decrypt_file_with_stdout_writes_bytes_to_stdout | 残す | なし | --stdout 時の stdout bytes と Decrypted to 非表示を検証する配管テストである。 |
| test_decrypt_stdin_with_out_writes_decrypted_file | 残す | なし | --stdin --out、stdin 入力、出力先 path 表示、出力ファイル bytes を検証している。 |
| test_decrypt_stdin_with_stdout_writes_bytes_to_stdout | 残す | なし | --stdin --stdout、stdin 入力、stdout bytes、stderr 非表示を検証している。 |
| test_decrypt_file_requires_out_or_stdout | 残す | なし | 出力先未指定時の failure と requires either --out or --stdout の stderr を検証している。 |
| test_decrypt_rejects_stdout_and_out_together | 残す | なし | --stdout と --out 同時指定時の failure と stderr 文言を検証している。 |
| test_decrypt_rejects_input_and_stdin_together | 残す | なし | input path と --stdin 同時指定時の failure と stderr 文言を検証している。 |

#### tests/cli/inspect.rs

| テスト関数名 | 分類 | 移譲先（内部ユニットファイル） | 判定理由（1 行） |
|---|---|---|---|
| test_inspect_file_enc_shows_metadata | 残す | なし | file-enc metadata の見出し、各セクション、Attestation 表示を stdout で検証している。 |
| test_inspect_file_enc_json_output_is_structured | 縮小 | feature_inspect_test.rs | --json stdout 構造は残すが、wrap item enc/ct、payload ct、signer_pub、verification status は inspect 細部である。 |
| test_inspect_kv_enc_shows_metadata | 残す | なし | KV metadata の見出し、各セクション、Attestation 表示を stdout で検証している。 |
| test_inspect_kv_enc_json_output_is_structured | 縮小 | feature_inspect_test.rs | --json stdout 構造は残すが、entry nonce/ct/disclosed、summary、verification status は inspect 細部である。 |
| test_inspect_invalid_format_fails | 残す | なし | plain text 入力時の failure を検証する CLI エラー経路である。 |
| test_inspect_nonexistent_file_fails | 残す | なし | nonexistent path 指定時の failure を検証する CLI エラー経路である。 |
| test_inspect_shows_signature_verification | 残す | なし | Signature Verification セクションと Status 表示を stdout で検証している。 |
| test_inspect_kv_shows_entry_count | 残す | なし | Total Entries: 1 の stdout 表示を検証している。 |
| test_inspect_succeeds_without_workspace_or_private_key | 残す | なし | workspace/private key なしで success し signature verification 表示を出す CLI 挙動を検証している。 |
| test_inspect_ignores_trust_store_and_strict_key_checking | 残す | なし | invalid trust store と env 指定下でも success して stdout 表示する CLI 挙動を検証している。 |
| test_inspect_colors_public_key_expiry_warning_when_forced | 残す | なし | CLICOLOR_FORCE 時の ANSI warning と strip 後文言を検証している。 |
| test_inspect_colors_disclosed_rotation_warning_when_forced | 残す | なし | disclosed rotation warning の ANSI 表示と strip 後文言を検証している。 |

#### tests/cli/kv/default_file.rs

| テスト関数名 | 分類 | 移譲先（内部ユニットファイル） | 判定理由（1 行） |
|---|---|---|---|
| test_error_when_workspace_not_found | 残す | なし | workspace 未検出時の failure と stderr 文言候補を検証する CLI エラー経路である。 |

#### tests/cli/kv/get.rs

| テスト関数名 | 分類 | 移譲先（内部ユニットファイル） | 判定理由（1 行） |
|---|---|---|---|
| test_get_existing_key | 残す | なし | get の成功終了と stdout の値表示を検証する happy-path CLI smoke である。 |
| test_get_rejects_tampered_kv_signature | 縮小 | feature_verify_kv_operation_test.rs | Signature verification failed の stderr は残すが、KV signature 改ざん拒否は verify 細部である。 |
| test_get_nonexistent_key | 残す | なし | nonexistent key の failure と not found の stderr を検証している。 |
| test_get_with_json_output | 残す | なし | get --json の values.TEST_KEY 構造を stdout JSON として検証している。 |
| test_get_error_when_file_not_exists | 残す | なし | KV ファイル未存在時の failure と not found の stderr を検証している。 |
| test_get_all | 残す | なし | get --all の成功終了と複数値の stdout 表示を検証している。 |
| test_get_all_debug_logs_public_key_verification_contexts | 残す | なし | --debug stdout の trace 文言と非表示 trace を検証している。 |
| test_get_all_debug_uses_half_kid_for_high_frequency_traces | 残す | なし | debug stdout の KID 表示形式と full KID 非表示を検証している。 |
| test_get_all_verbose_does_not_log_public_key_verification_contexts | 残す | なし | --verbose では debug trace が stdout に出ないことを検証している。 |
| test_get_all_with_key | 残す | なし | --with-key の KEY="value" stdout 表示形式を検証している。 |
| test_get_with_key_format | 残す | なし | 単一 key の --with-key stdout 表示形式を検証している。 |
| test_get_all_with_key_arg_fails | 残す | なし | --all と key 引数の不正な組み合わせが failure になる CLI 引数テストである。 |
| test_get_without_key_and_all_fails | 残す | なし | key も --all もない CLI 呼び出しが failure になる引数テストである。 |
| test_get_all_json | 残す | なし | get --all --json の values 構造と複数値を stdout JSON として検証している。 |

#### tests/cli/kv/import.rs

| テスト関数名 | 分類 | 移譲先（内部ユニットファイル） | 判定理由（1 行） |
|---|---|---|---|
| test_import_dotenv_file | 残す | なし | Imported 3 entries の出力と後続 get stdout を確認する import happy-path CLI smoke である。 |
| test_import_overwrites_existing_keys | 移譲 | app_kv_mutation_test.rs | import 自体は success のみで、主検証は既存 key の上書き結果であり KV mutation の細部である。 |
| test_import_invalid_dotenv_fails | 残す | なし | invalid dotenv の failure と missing '=' separator の stderr を検証している。 |
| test_import_nonexistent_file_fails | 残す | なし | nonexistent input path 指定時の failure を検証する CLI エラー経路である。 |
| test_import_empty_file_fails | 残す | なし | 有効 entry なしの failure と No valid entries found の stderr を検証している。 |
| test_import_with_json_output | 残す | なし | import --json の success と summary を stdout JSON として検証している。 |
| test_import_rejects_symlink_input_file | 縮小 | support_fs_test.rs | symlink の stderr 表示は残すが、symlink 入力拒否はファイル安全性の細部である。 |

#### tests/cli/kv/list.rs

| テスト関数名 | 分類 | 移譲先（内部ユニットファイル） | 判定理由（1 行） |
|---|---|---|---|
| test_list_all_keys | 残す | なし | list の成功終了と key 一覧の stdout 表示を検証している。 |
| test_list_with_json_output | 残す | なし | list --json の keys 配列と順序を stdout JSON として検証している。 |
| test_list_error_when_file_not_exists | 残す | なし | KV ファイル未存在時の failure と not found の stderr を検証している。 |
| test_list_rejects_tampered_kv_signature | 縮小 | feature_verify_kv_operation_test.rs | Signature verification failed の stderr は残すが、KV signature 改ざん拒否は verify 細部である。 |
| test_list_debug_verifies_key_possession_without_printing_values | 残す | なし | --debug stdout の key possession trace と secret 値非表示を検証している。 |

#### tests/cli/kv/name_option.rs

| テスト関数名 | 分類 | 移譲先（内部ユニットファイル） | 判定理由（1 行） |
|---|---|---|---|
| test_set_with_name_option_creates_named_file | 残す | なし | -n による出力先パス解決と default file 非作成を検証している。 |
| test_set_get_with_name_option_roundtrip | 残す | なし | set -n と get -n の成功、stdout 値表示を検証する CLI roundtrip である。 |
| test_list_with_name_option | 残す | なし | list -n の成功と stdout key 表示を検証している。 |
| test_unset_with_name_option | 残す | なし | unset -n --force の成功と後続 get -n failure を検証している。 |
| test_run_with_name_option | 残す | なし | run -n -- の stdout に環境変数値が出ることを検証している。 |
| test_get_with_nonexistent_name_fails | 残す | なし | nonexistent -n 指定時の failure を検証する CLI エラー経路である。 |
| test_named_file_and_default_file_are_independent | 残す | なし | default と -n other の list stdout を比較し、ファイル選択表示を検証している。 |

#### tests/cli/kv/set.rs

| テスト関数名 | 分類 | 移譲先（内部ユニットファイル） | 判定理由（1 行） |
|---|---|---|---|
| test_set_creates_new_file | 縮小 | app_kv_mutation_test.rs | default file 作成は残すが、ファイル内容に key が含まれる assert は保存内容の細部である。 |
| test_set_updates_existing_key | 移譲 | app_kv_mutation_test.rs | set 自体は success のみで、主検証は既存 key 更新結果であり KV mutation の細部である。 |
| test_set_debug_does_not_log_secret_value | 残す | なし | --debug stdout の trace と secret 値非表示を検証している。 |
| test_set_multiple_keys | 移譲 | app_kv_mutation_test.rs | set は success のみで、主検証は複数 key が残る mutation 結果である。 |
| test_set_without_workspace_fails | 残す | なし | workspace なしの failure と stderr 文言候補を検証している。 |
| test_set_stdin_creates_new_file | 残す | なし | --stdin 入力、出力先 path 作成、後続 get の stdout 値表示を検証している。 |
| test_set_stdin_and_value_arg_conflicts | 残す | なし | --stdin と VALUE 引数の CLI 競合が failure になることを検証している。 |
| test_set_without_stdin_and_without_value_fails | 残す | なし | VALUE なし、--stdin なしの CLI 呼び出しが failure になることを検証している。 |
| test_set_existing_file_updates_wrap_to_current_active_members | 移譲 | feature_rewrap_kv_test.rs | parse_kv_wrap で wrap recipient 配列を直接読み、暗号文書内部構造を検証している。 |

#### tests/cli/kv/unset.rs

| テスト関数名 | 分類 | 移譲先（内部ユニットファイル） | 判定理由（1 行） |
|---|---|---|---|
| test_unset_existing_key_with_force | 残す | なし | unset --force 成功と後続 list の stdout 表示/非表示を検証している。 |
| test_unset_nonexistent_key | 残す | なし | nonexistent key の failure と not found の stderr を検証している。 |
| test_unset_non_interactive_without_force_fails | 残す | なし | 非対話 unset without --force の stderr 実文言を検証している。 |
| test_unset_requires_member_handle_before_confirmation | 残す | なし | member handle エラーが force 要求より先に出る stderr 順序を検証している。 |

#### tests/cli/verify.rs

| テスト関数名 | 分類 | 移譲先（内部ユニットファイル） | 判定理由（1 行） |
|---|---|---|---|
| test_verify_file_enc_valid_signature | 残す | なし | inspect の success と Signature Verification / OK の stdout 表示を検証している。 |
| test_verify_kv_enc_valid_signature | 残す | なし | KV inspect の success と Signature Verification / OK の stdout 表示を検証している。 |
| test_verify_file_enc_tampered_fails | 縮小 | feature_verify_file_operation_test.rs | inspect が success のまま FAILED を出す表示は残すが、signature field 改ざん検出は verify 細部である。 |

#### 集計

| ファイル | 残す | 縮小 | 移譲 | 合計 |
|---|---:|---:|---:|---:|
| tests/cli/rewrap/membership.rs | 0 | 4 | 6 | 10 |
| tests/cli/rewrap/operations.rs | 0 | 2 | 0 | 2 |
| tests/cli/rewrap/preconditions.rs | 6 | 0 | 0 | 6 |
| tests/cli/rewrap/roundtrip.rs | 3 | 0 | 0 | 3 |
| tests/cli/member.rs | 20 | 4 | 1 | 25 |
| tests/cli/trust.rs | 13 | 4 | 0 | 17 |
| tests/cli/key/export.rs | 9 | 5 | 0 | 14 |
| tests/cli/decrypt.rs | 12 | 2 | 0 | 14 |
| tests/cli/inspect.rs | 10 | 2 | 0 | 12 |
| tests/cli/kv/default_file.rs | 1 | 0 | 0 | 1 |
| tests/cli/kv/get.rs | 13 | 1 | 0 | 14 |
| tests/cli/kv/import.rs | 5 | 1 | 1 | 7 |
| tests/cli/kv/list.rs | 4 | 1 | 0 | 5 |
| tests/cli/kv/name_option.rs | 7 | 0 | 0 | 7 |
| tests/cli/kv/set.rs | 5 | 1 | 3 | 9 |
| tests/cli/kv/unset.rs | 4 | 0 | 0 | 4 |
| tests/cli/verify.rs | 2 | 1 | 0 | 3 |
| 合計 | 114 | 28 | 11 | 153 |

## 8. フェーズ実績

### Phase 0(PR #116、2026-06-10 完了)

- カバレッジ・規模のベースラインを付録 7 に記録
- `public_api.rs` に 17 テストを追補し、公開 API 148 項目すべてを参照で固定
- `cli_api::app` / `presentation` の allow-list スナップショット照合テストを追加

### Phase 1(PR #117〜#118、2026-06-10 完了)

- dev 専用 crate `crates/kapsaro-test-support` を新設し、重複ヘルパー 6 ペアを
  単一ソースに統合(net -861 行)。core のテストバイナリは型同一性の制約
  (lib テストの `crate::` と外部 crate 経由の型は別物)があるため、共有ソースを
  `#[path]` で直接 include する方式とした。同一内容の重複ファイルは 0
- `tests/cli/common.rs`(748 行)を責務単位の 4 サブモジュールに分割

### Phase 2(PR #119〜#123、2026-06-11 完了)

| 指標 | 前 | 後 |
| --- | --- | --- |
| `test_support.rs` 再エクスポート名 | 429 | 181 |
| `test_support.rs` 行数 | 727 | 380 |
| core 外部ユニットテストファイル | 120 | 7 |
| core 内部ユニットテストファイル | 70 | 179 |
| `tests/unit.rs` の `#[path]` 手動登録 | 118 | 8 |
| テスト総数 | 1,911 | 1,911(維持) |
| カバレッジ(Line) | 88.88% | 88.66% |

- 未参照 6 件を削除、公開境界(`presentation` / `app`)で代替可能な 8 件を書き換え
- 内部実装を検証していた外部テスト 111 ファイルを `tests/unit/internal/` へ移設し、
  対応するブリッジ再エクスポートを削除
- テスト追加手順は「ファイルを置く + 対応 production ファイルに 1 行」となり、
  登録自動化(作業項目 3)は不要と判断
- カバレッジの見かけ -0.22pt は、新設 dev crate のソースが集計に二重計上される
  ことによるもので、production コードの未カバー増は計 16 行(実質維持)
- 残課題: 再エクスポート 181 のうち、共有ヘルパーとルート crate テストが
  構造的に必要とする分(約 130)はブリッジが唯一の経路であり削減不可。
  テスト再設計が必要な延期分(44 件)は Phase 6 のテスト再編で再評価する

### Phase 3(PR #125、2026-06-11 完了)

- 調査の結果、file/kv 統合の中核は実装済みと判明: rewrap オーケストレーションは
  `RewrapExecutor` / `RewrapDocumentAdapter` トレイトで統合済み、受信者・開示
  履歴処理は `feature/recipient` / `feature/disclosure` で完全共有済み、app 層の
  ファイル形式分岐は `EncContent` enum 経由の 1 箇所のみ
- 残っていた同型ボイラープレートである検証済みラッパー 2 型を
  ジェネリック `VerifiedDocument<T>` に統合(ドメイン名は型エイリアスで維持)
- 2 系統のみの分岐に対する広いトレイト抽象の導入は、計画のリスク指針に従い見送り

### Phase 4(PR #126〜#129、2026-06-11 完了)

- `app/file/inspect.rs`(646 行)を収集 / JSON 整形 / オーケストレーションに分割
- doctor 診断の 50〜79 行関数群を分割し、`DoctorCheck` 構築ヘルパー 4 種で
  約 30 箇所のビルダー連鎖を短縮(チェック ID・メッセージは不変)
- trust / kv / member / rewrap / file の 45〜70 行関数群を責務単位に分割
- CLI テキスト出力の重複整形プリミティブを layout に集約
- コマンド前処理は調査の結果 `app/context` に集約済みで、追加の共通化対象なし
- 関数分割によりシグネチャ・登録行が増え、app 層行数は 11,990 → 13,252 行に
  増加(完了条件の「総行数の有意減」よりも関数粒度の改善を優先した)

### Phase 5(PR #130、2026-06-11 完了)

- 調査の結果、エラー変換は全型(CryptoError / SshError / FormatError)で
  `From` 実装に集約済み、手書き変換なし。ErrorKind の KV 系分類差は意図的設計
- 重複エラーメッセージ 6 種を構築ヘルパーに集約(文言・分類は不変)
- 未使用と推定された support 関数 3 件はモジュール内呼び出しが確認され維持

## 9. 全体完了基準の検証(2026-06-11 時点)

| 基準 | 結果 |
| --- | --- |
| 機能・CLI 仕様・ワイヤーフォーマット・公開 API 不変 | 達成(全 PR でスナップショット・E2E・スキーマ適合テスト通過) |
| カバレッジがベースライン以上 | 達成(Line 88.88% → 88.99%、Region 86.82% → 87.04%) |
| テストコード総行数の削減 | 達成(55,774 → 55,063 行) |
| production 総行数の削減 | 未達(47,891 → 49,309 行。テスト登録行 + 関数分割による増) |
| テスト追加・移動時の編集箇所削減 | 達成(ヘルパー一本化、手動登録 118 → 8、ブリッジ 429 → 181) |
| clippy 警告ゼロ・fmt 違反ゼロ | 達成 |

テスト実行時間は core 独立ユニットバイナリが約 46 秒 → 約 3 秒に短縮
(テスト本体は lib バイナリへ移動し並列ビルド・実行効率が向上)。

## 10. 残課題

- Phase 6 本体(三層重複テストのカバレッジ分析と層間統合)は未実施。
  external 7 / internal 179 / E2E 259 という役割分担の再定義は Phase 2 で
  実質完了しており、残るのは E2E がドメイン細部を検証しているケースの
  内部ユニットへの移譲
- `cli_api::test_support` 再エクスポート 181 名(目標 100 以下)。
  構造的下限は約 130 で、テスト再設計が必要な延期分 44 件が削減余地
- production 総行数の削減は未達。重複は解消済みのため、今後の削減は
  機能整理(デッドコード化した DTO の追跡削除など)に依存する
