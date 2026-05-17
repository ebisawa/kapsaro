# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

secretenv は、オフライン優先（offline-first）の暗号ファイル共有 CLI ツールです。HPKE (RFC9180) と Ed25519 署名を用いて、チーム内で `.env` や証明書などの秘密情報を安全に共有します。Git リポジトリをストレージとして使用し、サーバー不要で動作します。

## Workspace 構成

本リポジトリは cargo workspace で構成されています。

- ルート crate `secretenv` (bin) — `src/cli/`, `src/main.rs`, `src/lib.rs`。CLI バイナリのみ
- `crates/secretenv-core` (lib) — domain ロジック全て（`app/`, `feature/`, `crypto/`, `format/`, `model/`, `io/`, `config/`, `support/` と公開 API `api/`）

### secretenv-core の API 境界

- `secretenv_core::api` — 外部埋め込み向けの安定公開 API。`FileEncArtifact`, `KvEncArtifact`, `VerifiedFileEncArtifact`, `VerifiedKvEncArtifact`, `SecretEnvHome`, `LocalKeyStore`, `LocalTrustStore`, `VerifiedLocalTrustStore`, `GitHubOnlineVerifier`, `KeyContext`, `OperationOptions`, `SecretString` など
- `secretenv_core::cli_api` — 本リポジトリ内 CLI 専用の内部境界（`cli-internal` feature でのみ公開）
  - `cli_api::app::*` — ユースケース層への入口。CLI はここを経由する
  - `cli_api::presentation::*` — CLI 出力で使う型・関数の再エクスポート（`SecretString`, `format_kid_display`, `tty`, `validation`, `limits` 等）
  - `cli_api::test_support::*` — 本リポジトリのテスト専用 hidden bridge（`cli-test-support` feature）。production CLI と外部埋め込み用途では使用しない。`settings` / `primitives` / `operations` / `wire` / `storage` / `domain` / `helpers` の用途別 helper root を経由し、core 内部 layer root 名の mirror は作らない
- `secretenv_core::error`, `prelude` — 公開ユーティリティ

default build の `secretenv-core` は保存形式 DTO を public API として再 export しない。外部埋め込み用途では、raw document model ではなく `api` の opaque facade を経由する。

`app` / `feature` / `io` / `format` / `model` / `crypto` / `config` / `support` の実装 module root は crate-private とし、外部向け root surface として扱わない。必要な first-party access は `cli_api` の明示 allow-list だけを経由する。

`prelude` は通常の embedding flow に必要な最小 import set とし、online verification facade や詳細 trust review 型は含めない。これらを使う場合は `secretenv_core::api::online` または `secretenv_core::api::trust` から明示 import する。外部向け `api::secret::SecretString` / `SecretBytes` は `expose_secret()` と所有権消費の boundary conversion を使い、暗黙的な `AsRef<str>` や equality を公開しない。

ルートの `secretenv` crate (CLI) は `secretenv_core::api` と `cli_api::app` / `cli_api::presentation` のみを参照します。`feature/`, `io/`, `crypto/` 等の internal モジュールへの直接アクセスは禁止です。

### Feature flags

- `cli-internal` — `cli_api` を有効化（CLI バイナリビルド時に必須）
- `cli-test-support` — `cli_api::test_support` を有効化（dev-dependencies で有効）
- `online` — GitHub オンライン検証など外部 I/O 経路

`cli-test-support` は first-party test harness 用であり、外部 API 契約ではない。CLI production code は `cli_api::test_support` を import せず、`cli_api::app` / `cli_api::presentation` の allow-list のみを使う。`cli_api::test_support` は下位実装 layer root の broad mirror を提供せず、用途別 helper root だけを公開する。外部 API の facade 境界は `crates/secretenv-core/tests/public_api.rs` で固定する。

## Build/Test/Lint Commands

```bash
cargo build                    # Build (workspace 全体)
cargo build --release          # Release build
cargo test --workspace         # Run all tests (workspace 全体。--workspace なしだとルート crate のみ)
cargo test                     # ルート crate (secretenv bin) のテストのみ
cargo test --lib               # ルート crate の lib テスト（src/ 内 #[cfg(test)]）
cargo test -p secretenv-core   # secretenv-core crate のテストのみ
cargo test --test unit         # tests/unit.rs から登録される独立ユニットテスト
cargo test --test cli_integration  # CLI E2E テスト
cargo test --test public_api -p secretenv-core  # 公開 API 境界テスト
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

## Architecture

### レイヤー構造と依存方向

```
cli -> app -> feature
app -> io | format | model | config
feature -> crypto | format | model | io | config
format -> crypto | model | support
crypto -> model | support
config -> io | support
```

- `cli` (ルート crate) は `feature` / `io` に直接依存しない（`secretenv_core::cli_api::app` 経由）
- `feature` は `cli` / `app` に依存しない
- `app` は `cli` に依存しない
- `io` は `feature` / `app` / `cli` に依存しない
- `format` は `feature` に依存しない
- `crypto` は `app` / `cli` / `feature` / `io` に依存しない
- `model` は `cli` / `app` / `feature` に依存しない
- `config/types.rs` は `io` / `feature` に依存しない

### レイヤー責務

- **`cli/`**（ルート crate） — presentation 層。clap 引数定義、対話入力（dialoguer）、stdout/stderr 出力、`app` の request/result を CLI 表現に変換。`common/` に共有オプション・出力・コンテキスト構築。`io::*` / `feature::*` への直接アクセス禁止（`cli_api::app` / `cli_api::presentation` のみ）
- **`app/`** — ユースケースオーケストレーション層。コマンド単位の処理順序定義、workspace/config/keystore/member 解決、複数 feature/io 呼び出しの束ね込み、CLI が描画しやすい結果 DTO の返却。`println!` / `dialoguer` 禁止
- **`feature/`** — ドメイン処理本体。CLI の存在を知らず、再利用可能な機能を提供
  - `envelope/` — HPKE wrap/unwrap、CEK 生成、エントリ暗号化
  - `kv/` — KV ドキュメント操作（builder, encrypt, decrypt, mutate, rewrite）
  - `decrypt/`, `encrypt/` — ファイル暗号化・復号
  - `verify/` — 署名検証、鍵ローダー
  - `rewrap/` — 鍵ローテーション（ファイル用・KV用）
  - `inspect/` — ドキュメント検査
  - `key/` — 鍵生成・管理（保護付き秘密鍵含む）
  - `member/`, `trust/`, `recipient/`, `disclosure/` — メンバー・信頼・受信者・開示処理
  - `context/` — CryptoContext（鍵ロード）、SshSigningContext（SSH 署名環境解決）
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
  - `process.rs` — 外部プロセス実行ラッパー
  - `document_store.rs` — ドキュメント永続化
- **`support/`** — ユーティリティ（recipients, 時刻, ファイルシステム操作, SecretString, kid フォーマット, validation, tty）
- **`api/`**（secretenv-core 公開） — 外部埋め込み向け安定 API ファサード

### 暗号化フロー

ファイル暗号化: 平文 → CEK 生成 → XChaCha20-Poly1305 暗号化 → HPKE で CEK を各受信者に wrap → Ed25519 署名 → JSON エンコード

KV 暗号化: KV マップ → エントリごとに CEK で暗号化 → トークンエンコード → KvDocumentBuilder で署名付きドキュメント構築

### テスト構成

- `tests/unit/external/` — `tests/unit.rs` から登録する、公開 API・`cli_api::test_support` 経由でアクセスする独立ユニットテスト
- `tests/unit/internal/` — `crates/secretenv-core/src/` 内 `#[cfg(test)] #[path = "../../../../tests/unit/internal/..."]` から登録する private / crate-internal ユニットテスト
- `tests/cli_integration.rs` — CLI の E2E テスト（ルート crate）
- `crates/secretenv-core/tests/public_api.rs` — `secretenv_core::api` の公開 API 境界テスト
- `src/` 内 `#[cfg(test)]` — モジュール内インラインテスト（in-source は原則回避、外部ファイル `#[path]` 登録で記述）

## Reference Documents

- `schemas/secretenv_schema.json` — v3 JSON Schema
- `guides/product_brief_en.md` / `guides/product_brief_ja.md` — Product Brief (EN/JA)
- `guides/security_design_en.md` / `guides/security_design_ja.md` — Security Design (EN/JA)
- `guides/user_guide_en.md` / `guides/user_guide_ja.md` — User Guide (EN/JA)

## Conventions

- Copyright ヘッダー: `// Copyright 2026 Satoshi Ebisawa` + `// SPDX-License-Identifier: Apache-2.0`
- 命名規則・モジュール構成・テスト命名は、別途定められた関連ドキュメントの規定に従う

## Subagent Review Rules

- `crypto/`, `feature/envelope/`, `feature/key/`, `model/private_key.rs` など暗号関連コードを変更した場合は、`security-reviewer` サブエージェントでレビューを実施する
- レイヤーをまたぐ変更（新規モジュール追加、`use crate::` の追加・変更、`cli_api` の公開面拡張）を行った場合は、`architecture-reviewer` サブエージェントでレイヤー依存ルール違反がないことを確認する
