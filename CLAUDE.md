# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

kapsaro は、オフライン優先（offline-first）の暗号ファイル共有 CLI ツールです。HPKE (RFC9180) と Ed25519 署名を用いて、チーム内で `.env` や証明書などの秘密情報を安全に共有します。Git リポジトリをストレージとして使用し、サーバー不要で動作します。

## Workspace 構成

本リポジトリは cargo workspace で構成されています。

- ルート crate `kapsaro` (bin) — `src/cli/`, `src/main.rs`。CLI バイナリのみ
- `crates/kapsaro-core` (lib) — domain ロジック全て（`app/`, `feature/`, `crypto/`, `format/`, `model/`, `io/`, `config/`, `support/` と公開 API `api/`）
- `crates/kapsaro-test-support` (lib) — workspace 内テストで共有する fixture と環境制御 helper

### kapsaro-core の API 境界

- `kapsaro_core::api` — 外部アプリケーションと first-party CLI が共有する標準公開 API
- `kapsaro_core::Error` / `ErrorKind` / `Result` — crate 共通のエラー API
- `kapsaro_core::cli_api` — first-party CLI 向けの内部 API
  - `cli_api::app` — CLI ユースケースの入口
  - `cli_api::presentation` — CLI 表示の補助
  - `cli_api::test_support` — test harness 専用の補助
- `app` / `feature` / `io` / `format` / `model` / `crypto` / `config` / `support` — crate-private の実装モジュール

### Feature flags

- `cli-internal` — `cli_api` を有効化（CLI バイナリビルド時に必須）
- `cli-test-support` — `cli_api::test_support` を有効化（dev-dependencies で有効）
- `online` — GitHub オンライン検証のネットワーク実装を有効化（core は既定で無効、ルート CLI は既定で有効）

`cli-test-support` は first-party test harness 用であり、外部 API 契約ではない。CLI production code は `cli_api::test_support` を import せず、標準 `api` または `cli_api::app` / `cli_api::presentation` の allow-list を使う。`cli_api::test_support` は下位実装 layer root の broad mirror を提供せず、用途別 helper root だけを公開する。外部 API の facade 境界は `crates/kapsaro-core/tests/public_api.rs` で固定する。

## Build/Test/Lint Commands

```bash
cargo build                    # ルート package `kapsaro` をビルド
cargo build --workspace        # workspace 全体をビルド
cargo build --release          # ルート package `kapsaro` の release build
cargo test --workspace         # Run all tests (workspace 全体。--workspace なしだとルート crate のみ)
cargo test                     # ルート package `kapsaro` の全 test target
cargo test -p kapsaro --bin kapsaro  # ルート crate の CLI 内部テスト（src/ 内 #[cfg(test)]）
cargo test -p kapsaro-core   # kapsaro-core crate のテストのみ
cargo test --test unit -p kapsaro-core  # kapsaro-core の独立ユニットテスト（外部ツリー）
cargo test --test cli_integration  # CLI E2E テスト
cargo test --test public_api -p kapsaro-core  # 公開 API 境界テスト
cargo test <module_path>::     # 特定モジュールのテスト
cargo test <test_name>         # 名前指定で単一テスト実行
cargo clippy --workspace --all-targets  # Lint（workspace 全体）
cargo fmt                      # Format
cargo fmt -- --check           # Format 確認
```

### カバレッジ (cargo-llvm-cov)

```bash
cargo llvm-cov --workspace                     # summary を stdout に表示
cargo llvm-cov --workspace --html              # HTML レポートを target/llvm-cov/html/index.html に生成
cargo llvm-cov --workspace --open              # HTML 生成後にブラウザで開く
cargo llvm-cov --workspace --ignore-filename-regex '^tests/'  # tests/ 配下を集計対象から除外
cargo llvm-cov clean --workspace               # 計測データを掃除（前回結果が混ざる場合に実行）
```

初回利用時は `cargo install cargo-llvm-cov` でツールを導入し、必要に応じて `rustup component add llvm-tools-preview` を実行する。`--test unit` などテスト対象を絞るオプションは通常の `cargo test` と同じ要領で組み合わせ可能。

### Rust toolchain

`rust-toolchain.toml` で `1.95.0` に固定されている。

## Architecture

### レイヤー構造と依存方向

```
cli -> api
cli -> cli_api -> app -> feature
app -> io | format | model | config | api
feature -> crypto | format | model | io | config
format -> crypto | model | support
crypto -> model | support
config -> io | support
```

- `cli` (ルート crate) は標準 `api` または `cli_api` の allow-list を使い、`feature` / `io` に直接依存しない
- `feature` は `cli` / `app` に依存しない
- `app` は `cli` に依存しない
- `io` は `feature` / `app` / `cli` に依存しない
- `format` は `feature` に依存しない
- `crypto` は `app` / `cli` / `feature` / `io` に依存しない
- `model` は `cli` / `app` / `feature` に依存しない
- `config/types.rs` は `io` / `feature` に依存しない

### レイヤー責務

- **`cli/`**（ルート crate） — presentation 層。clap 引数定義、対話入力（dialoguer）、stdout/stderr 出力、標準 `api` と `cli_api` の request/result を CLI 表現に変換。`common/` に共有オプション・出力・コンテキスト構築。`io::*` / `feature::*` への直接アクセス禁止
- **`app/`** — ユースケースオーケストレーション層。コマンド単位の処理順序定義、workspace/config/keystore/member 解決、複数 feature/io 呼び出しの束ね込み、CLI が描画しやすい結果 DTO の返却。`println!` / `dialoguer` 禁止
- **`feature/`** — ドメイン処理本体。CLI の存在を知らず、再利用可能な機能を提供
  - `envelope/` — artifact key schedule、HPKE wrap/unwrap、key-possession proof、エントリ暗号化
  - `kv/` — KV ドキュメント操作（builder, encrypt, decrypt, mutate, rewrite）
  - `decrypt/`, `encrypt/` — ファイル暗号化・復号
  - `verify/` — 署名検証、鍵ローダー
  - `rewrap/` — 鍵ローテーション（ファイル用・KV用）
  - `inspect/` — ドキュメント検査
  - `key/` — 鍵生成・管理（保護付き秘密鍵含む）
  - `member/`, `trust/`, `recipient/`, `disclosure/` — メンバー・信頼・受信者・開示処理
  - `context/` — CryptoContext（鍵ロード）、env key、鍵期限の処理。SSH 署名環境の解決は `app/context/ssh` が担当
- **`config/`** — 設定モデル（`types.rs`）と設定解決ロジック（`resolution/`）。CLI > env > config > default の優先順
- **`model/`** — 共有ドメインモデル（`file_enc`, `kv_enc`, `public_key`, `private_key`, `signature`, `verified`, `trust_store` 等）
- **`crypto/`** — 暗号プリミティブ（AEAD, KDF, KEM, Ed25519 署名）
- **`format/`** — ワイヤーフォーマット（JSON 構造、JCS 正規化、トークンエンコーディング）
- **`io/`** — 外部 I/O
  - `keystore/` — 鍵ストア操作
  - `config/` — 設定ファイル I/O（store, paths, bootstrap）
  - `ssh/` — SSH エージェント・SSHSIG 操作（`SshKeygen`/`SshAdd` trait で抽象化）
  - `workspace/` — ワークスペース検出、メンバー管理
  - `trust/` — トラストストア I/O
  - `verify_online/` — GitHub 経由の公開鍵オンライン検証
  - `github/` — GitHub API クライアント
  - `process.rs` — 子プロセスへ継承する環境変数の分離 helper
  - `document_store.rs` — ドキュメント永続化
- **`support/`** — ユーティリティ（表示、時刻、ファイルシステム操作、secret、limits、path、runtime、kid、validation、tty、warning、shell、post_write）
- **`api/`**（kapsaro-core 公開） — 外部アプリケーション、first-party CLI、および `app` 層が共有する公開型層。`LocalTrustStore` や `TrustPolicyEvaluator` のような実装本体もここに置かれており、`app` 配下の一部モジュールは `feature` / `io` の代わりに `api::{file,kv,key,trust,operation}` を直接参照する
  - `diagnostics.rs` — ローカル状態の警告を呼び出し側が取り出すための入口

### 暗号化フロー

ファイル暗号化: 平文 → MK 生成 → payload key と MAC key を導出 → XChaCha20-Poly1305 暗号化 → HPKE で MK を各受信者に wrap → key-possession MAC → Ed25519 署名 → JSON エンコード

KV 暗号化: KV マップ → MK 生成 → エントリごとの CEK と MAC key を導出 → XChaCha20-Poly1305 暗号化 → HPKE で MK を各受信者に wrap → key-possession MAC → Ed25519 署名 → line-based text 構築

### テスト構成

テストファイルはルート crate、`kapsaro-core`、`kapsaro-test-support` の 3 つの `tests/` ツリーに分かれる。

#### ルート crate (`tests/`)

- `tests/unit/internal/` — `src/` の production module から `#[cfg(test)] #[path = "..."]` で登録する crate-private ユニットテスト
- `tests/cli_integration.rs` — `tests/cli.rs` と `tests/test_utils.rs` を登録する CLI E2E のエントリポイント
- `tests/cli/` — コマンド別の CLI E2E テスト
- `tests/test_utils.rs` / `tests/test_utils/` — CLI E2E と bin 内部テストの共通 helper

#### kapsaro-core crate (`crates/kapsaro-core/tests/`)

- `tests/unit/external/` — `tests/unit.rs` から `#[path]` 登録する独立ユニットテスト。`cli_api::test_support` と公開 API 経由でアクセス
- `tests/unit/internal/` — `crates/kapsaro-core/src/` 内の production module から `#[cfg(test)] #[path = "..."]` で登録する crate-private ユニットテスト
- `tests/unit.rs` — 上記外部テストを登録するエントリポイント。`tests/test_support/mod.rs` を import
- `tests/public_api.rs` — `kapsaro_core::api` の公開 API 境界テスト
- `tests/cli_api_boundary.rs` — `kapsaro_core::cli_api` の境界テスト。`required-features = ["cli-test-support"]` 付きの独立ターゲット

#### kapsaro-test-support crate (`crates/kapsaro-test-support/tests/`)

- `tests/ed25519_backend_test.rs` — 共有する Ed25519 署名 backend の独立テスト
- `tests/guards_test.rs` — cwd と環境変数の guard helper の独立テスト
- `tests/privilege_test.rs` — 権限拒否を再現するテストが共有する特権判定の独立テスト

#### テストを追加する際の手順

- core 外部テスト: `crates/kapsaro-core/tests/unit/external/` にファイルを作成し、`crates/kapsaro-core/tests/unit.rs` に登録
- crate-private テスト: 対象 crate の `tests/unit/internal/` にファイルを作成し、対応する production module から配置深度に合う相対 `#[path]` で登録
- CLI E2E: `tests/cli/` の該当モジュールへ追加し、新規モジュールの場合は親モジュールから登録
- 複数 crate で共有する fixture/helper: `crates/kapsaro-test-support` に追加

#### 登録漏れに注意

`crates/kapsaro-core/tests/unit/external/`、`tests/unit/internal/`、`tests/cli/`、`tests/test_support/`、`tests/test_utils/` のいずれかに `.rs` ファイルを追加したら、その親にあたるエントリポイント（core の `tests/unit.rs`、production module、`tests/cli.rs`、同名ディレクトリの `.rs` など）へ必ず `mod` または `#[path]` を書く。登録漏れのファイルはコンパイルされず、テストが存在しないまま緑になる。

#### レビューで確認する規約

以下は自動検査がない。コードレビューで確認する。

- `#[path]` 登録の書き忘れ
- 実体のないファイルを指す stale な登録と、同じファイルを二か所から取り込む二重登録
- production source 内のインラインテストモジュール（`#[cfg(test)] mod tests`）
- shebang 付きのファイルを書き出して exec するテストの `#[serial]` 指定。理由は当該テストの module doc に記載されている
- 登録の有無を確認するときは `#[path]` 属性そのものを grep する。モジュール名は `mod tests;` のような総称名とファイル名と同名のものが混在しており、名前からは追えない
- cwd を変えるテストは `kapsaro-test-support` の `with_temp_cwd` を使う。生の `set_current_dir` は `CWD_LOCK` を取らないため、`with_temp_cwd` を使う他のテストと並行実行され、panic 時に cwd も復元されない

#### production tree に置くテスト専用コード

`src/` 配下には、`#[cfg(test)]` で本番ビルドから消えるテスト専用コードが3種類ある。

- `crates/kapsaro-core/src/support/fs/test_umask.rs` — マクロが crate-private 項目を `crate::` パスで参照するため `src/` から出せない
- フォールトインジェクション用のフック — 書き込みの途中で失敗させたり、ロックを保持している区間の内側を観測したりするには、本番の制御フローにシームを置くしかない。`support/fs` の作成・書き込み・走査経路と、`io/keystore` および `io/trust` の保存経路にある
- テスト専用の中置コンストラクタ — 本番は検証を経る `try_new` 系だけを使うが、テストではリテラル値から直接組み立てたい箇所がある。`feature/kv/types.rs` の `KvInputEntry::new`、`feature/trust/judgment/identity.rs` の `TrustIdentity::new`、`feature/trust/judgment/self_trust.rs` の `SelfTrustSet::new` が該当し、いずれも `#[cfg(test)]` 付きで対応する `try_new` を呼んで invalid な入力なら panic する

フックを新しく足すときは、既存のフックと同じ形に揃える。thread_local の slot に登録し、実行側は `take()` で自己消費してテスト間に持ち越さない。本番ビルドでは呼び出しが no-op になるようにする。

## Reference Documents

- `crates/kapsaro-core/schemas/kapsaro_public_key_schema.json` — PublicKey JSON Schema
- `crates/kapsaro-core/schemas/kapsaro_private_key_schema.json` — PrivateKey JSON Schema
- `crates/kapsaro-core/schemas/kapsaro_common_schema.json` — 各 schema が共有する定義
- `crates/kapsaro-core/schemas/kapsaro_file_enc_schema.json` — file-enc JSON Schema
- `crates/kapsaro-core/schemas/kapsaro_kv_enc_schema.json` — kv-enc JSON Schema
- `crates/kapsaro-core/schemas/kapsaro_artifact_signature_schema.json` — artifact signature JSON Schema
- `crates/kapsaro-core/schemas/kapsaro_local_trust_schema.json` — local trust store JSON Schema
- `guides/product_brief_en.md` / `guides/product_brief_ja.md` — Product Brief (EN/JA)
- `guides/security_design_en.md` / `guides/security_design_ja.md` — Security Design (EN/JA)
- `guides/user_guide_en.md` / `guides/user_guide_ja.md` — User Guide (EN/JA)

## Conventions

- Copyright ヘッダー: `// Copyright 2026 Satoshi Ebisawa` + `// SPDX-License-Identifier: Apache-2.0`
- 命名規則・モジュール構成・テスト命名は、別途定められた関連ドキュメントの規定に従う
