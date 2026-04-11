# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

secretenv は、オフライン優先（offline-first）の暗号ファイル共有 CLI ツールです。HPKE (RFC9180) と Ed25519 署名を用いて、チーム内で `.env` や証明書などの秘密情報を安全に共有します。Git リポジトリをストレージとして使用し、サーバー不要で動作します。

## Build/Test/Lint Commands

```bash
cargo build                    # Build
cargo build --release          # Release build
cargo test                     # Run all tests
cargo test --lib               # Unit tests only (src/ 内 #[cfg(test)])
cargo test --test unit         # Unit tests (tests/unit/ 配下)
cargo test --test cli_integration  # CLI integration tests
cargo test <module_path>::     # Specific module tests (e.g. cargo test crypto::)
cargo test <test_name>         # Run single test by name
cargo clippy                   # Lint
cargo fmt                      # Format
cargo fmt -- --check           # Check formatting
```

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

- `cli` は `feature` / `io` に直接依存しない（`app` 経由で利用）
- `feature` は `cli` / `app` に依存しない
- `app` は `cli` に依存しない
- `io` は `feature` / `app` / `cli` に依存しない
- `format` は `feature` に依存しない
- `crypto` は `app` / `cli` / `feature` / `io` に依存しない
- `model` は `cli` / `app` / `feature` に依存しない
- `config/types.rs` は `io` / `feature` に依存しない

### レイヤー責務

- **`cli/`** — presentation 層。clap 引数定義、対話入力（dialoguer）、stdout/stderr 出力、`app` の request/result を CLI 表現に変換。`common/` に共有オプション・出力・コンテキスト構築。`io::*` / `feature::*` への直接アクセス禁止
- **`app/`** — ユースケースオーケストレーション層。コマンド単位の処理順序定義、workspace/config/keystore/member 解決、複数 feature/io 呼び出しの束ね込み、CLI が描画しやすい結果 DTO の返却。`println!` / `dialoguer` 禁止
- **`feature/`** — ドメイン処理本体。CLI の存在を知らず、再利用可能な機能を提供
  - `envelope/` — HPKE wrap/unwrap、CEK 生成、エントリ暗号化
  - `kv/` — KV ドキュメント操作（builder, encrypt, decrypt, mutate, rewrite）
  - `decrypt/`, `encrypt/` — ファイル暗号化・復号
  - `verify/` — 署名検証、鍵ローダー
  - `rewrap/` — 鍵ローテーション（ファイル用・KV用）
  - `inspect/` — ドキュメント検査
  - `key/` — 鍵生成・管理（保護付き秘密鍵含む）
  - `context/` — CryptoContext（鍵ロード）、SshSigningContext（SSH 署名環境解決）
- **`config/`** — 設定モデル（`types.rs`）と設定解決ロジック（`resolution/`）。CLI > env > config > default の優先順
- **`model/`** — 共有ドメインモデル（`file_enc`, `kv_enc`, `public_key`, `private_key`, `signature`, `verified`）
- **`crypto/`** — 暗号プリミティブ（AEAD, KDF, KEM, Ed25519 署名）
- **`format/`** — ワイヤーフォーマット（JSON 構造、JCS 正規化、トークンエンコーディング）
- **`io/`** — 外部 I/O
  - `keystore/` — 鍵ストア操作
  - `config/` — 設定ファイル I/O（store, paths, bootstrap）
  - `ssh/` — SSH エージェント・SSHSIG 操作（`SshKeygen`/`SshAdd` trait で抽象化）
  - `workspace/` — ワークスペース検出、メンバー管理
  - `verify_online/` — GitHub 経由の公開鍵オンライン検証
  - `schema/` — JSON Schema バリデーション
  - `json.rs` — JCS 正規化など JSON ユーティリティ
  - `process.rs` — 外部プロセス実行ラッパー
- **`support/`** — ユーティリティ（recipients, 時刻, ファイルシステム操作）

### 暗号化フロー

ファイル暗号化: 平文 → CEK 生成 → XChaCha20-Poly1305 暗号化 → HPKE で CEK を各受信者に wrap → Ed25519 署名 → JSON エンコード

KV 暗号化: KV マップ → エントリごとに CEK で暗号化 → トークンエンコード → KvDocumentBuilder で署名付きドキュメント構築

### テスト構成

- `tests/unit/` — `<module_path>_test.rs` 命名規則のユニットテスト（80+ ファイル）
- `tests/cli_integration.rs` — CLI の E2E テスト
- `src/` 内 `#[cfg(test)]` — モジュール内インラインテスト

## Reference Documents

- `schemas/secretenv_schema.json` — v3 JSON Schema
- `guides/product_brief_en.md` / `guides/product_brief_ja.md` — Product Brief (EN/JA)
- `guides/security_design_en.md` / `guides/security_design_ja.md` — Security Design (EN/JA)
- `guides/user_guide_en.md` / `guides/user_guide_ja.md` — User Guide (EN/JA)

## Conventions

- Copyright ヘッダー: `// Copyright 2026 Satoshi Ebisawa` + `// SPDX-License-Identifier: Apache-2.0`
- モジュール構成: Rust 2018 edition スタイル（`mod.rs` 非推奨、`name.rs` + `name/` ペア）
- 検証済み型は `Verified*` プレフィックス、証明型は `*Proof` サフィックス
- テスト関数名: `test_<対象>_<シナリオ>[_fails|_error|_roundtrip]`
- テストファイル名: `<module_path>_test.rs`（例: `feature/encrypt/wrap.rs` → `feature_encrypt_wrap_test.rs`）
- 動詞規則: `build_*`（組み立て）、`load_*`（読み込み）、`save_*`（書き込み）、`resolve_*`（動的解決）、`encrypt_*`/`decrypt_*`、`sign_*`/`verify_*`、`wrap_*`/`unwrap_*`。`create_*`, `prepare_*`, `read_*`, `write_*` は使用禁止
- CLI 専用動詞: `setup_*`（実行前準備）、`run_*`（エントリポイント）、`print_*`（表示）— `cli/` 以外での使用禁止

## Subagent Review Rules

- `crypto/`, `feature/envelope/`, `feature/key/`, `model/private_key.rs` など暗号関連コードを変更した場合は、`security-reviewer` サブエージェントでレビューを実施する
- レイヤーをまたぐ変更（新規モジュール追加、`use crate::` の追加・変更）を行った場合は、`architecture-reviewer` サブエージェントでレイヤー依存ルール違反がないことを確認する
