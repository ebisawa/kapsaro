# CLAUDE.md

This file provides guidance to coding agents working in this repository. `AGENTS.md` is a symlink to this file, so Claude Code, Codex, and any other agent that follows either convention read the same content.

## Project Overview

kapsaro は、オフライン優先（offline-first）の暗号ファイル共有 CLI ツールです。HPKE (RFC9180) と Ed25519 署名を用いて、チーム内で `.env` や証明書などの秘密情報を安全に共有します。Git リポジトリをストレージとして使用し、サーバー不要で動作します。

## Workspace 構成

本リポジトリは cargo workspace で構成されています。

- ルート crate `kapsaro` (bin) — `src/cli/`, `src/main.rs`。CLI バイナリのみ
- `crates/kapsaro-core` (lib) — domain ロジック全て（`service/`, `feature/`, `crypto/`, `format/`, `model/`, `io/`, `config/`, `support/` と公開 API `api/`）
- `crates/kapsaro-test-support` (lib) — workspace 内テストで共有する fixture と環境制御 helper

### kapsaro-core の API 境界

- `kapsaro_core::api` — 外部アプリケーションと first-party CLI が共有する標準公開 API
- `kapsaro_core::Error` / `ErrorKind` / `Result` — crate 共通のエラー API
- `kapsaro_core::test_support` — feature-gated の first-party test harness 専用補助。標準 API ではない
- `service` / `feature` / `io` / `format` / `model` / `crypto` / `config` / `support` — crate-private の実装モジュール

### Feature flags

- `cli-test-support` — hidden root `test_support` を有効化（dev-dependencies で有効）
- `online` — GitHub オンライン検証のネットワーク実装を有効化（core は既定で無効、ルート CLI は既定で有効）

`cli-test-support` は first-party test harness 用であり、外部 API 契約ではない。CLI production code は `test_support` を importせず、標準 `api` だけを使う。`test_support` は下位実装 layer root の broad mirror を提供せず、用途別 helper root だけを公開する。外部 API の facade 境界は `crates/kapsaro-core/tests/public_api.rs` で固定する。

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
cli -> api -> service
service -> feature | io | format | model | config | support
feature -> crypto | format | model | io | config
format -> crypto | model | support
crypto -> model | support
config -> io | support
```

production の依存経路は `cli -> api -> service` の一本とする。

- `cli` (ルート crate) は標準 `api` を使い、`service` / `feature` / `io` に直接依存しない
- `api` は `service` の標準操作と型から外部公開する項目だけを明示的に再公開し、実装本体を持たない
- `service` は `api` / `cli` に依存しない
- `feature` は `cli` に依存しない
- `io` は `feature` / `cli` に依存しない
- `format` は `feature` に依存しない
- `crypto` は `cli` / `feature` / `io` に依存しない
- `model` は `cli` / `feature` に依存しない
- `config/types.rs` は `io` / `feature` に依存しない

### レイヤー責務

- **`cli/`**（ルート crate） — presentation 層。clap 引数定義、CLI・環境変数・設定の優先順位、対話入力（dialoguer）、stdout/stderr 出力、子 process 起動、標準 `api` の request/result 変換を担当する。`io::*` / `feature::*` への直接アクセス禁止
- **`service/`** — 標準公開 API の実装層。caller が明示した入力と検証済み capability を受け取り、artifact、key、KV、trust、online verification、diagnostics の再利用可能な規則を実行する。入力の再解決、環境変数・設定優先順位・workspace 自動検出、TTY、CLI DTO を扱わず、`api` / `cli` に依存しない
- **`feature/`** — ドメイン処理本体。CLI の存在を知らず、再利用可能な機能を提供
  - `envelope/` — artifact key schedule、HPKE wrap/unwrap、key-possession proof、エントリ暗号化
  - `kv/` — KV ドキュメント操作（builder, encrypt, decrypt, mutate, rewrite）
  - `decrypt/`, `encrypt/` — ファイル暗号化・復号
  - `verify/` — 署名検証、鍵ローダー
  - `rewrap/` — 鍵ローテーション（ファイル用・KV用）
  - `inspect/` — ドキュメント検査
  - `key/` — 鍵生成・管理（保護付き秘密鍵含む）
  - `member/`, `trust/`, `recipient/`, `disclosure/` — メンバー・信頼・受信者・開示処理
  - `context/` — CryptoContext（鍵ロード）、env key、鍵期限の処理
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
- **`api/`**（kapsaro-core 公開） — 外部アプリケーションと first-party CLI 向けの allow-list facade。`service` の型と操作から外部公開する項目だけを用途別 module で明示的に再公開し、実装、変換、fallback、CLI 固有処理、glob 再公開を持たない

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

- `tests/unit/external/` — `tests/unit.rs` から `#[path]` 登録する独立ユニットテスト。hidden root `test_support` と公開 API 経由でアクセス
- `tests/unit/internal/` — `crates/kapsaro-core/src/` 内の production module から `#[cfg(test)] #[path = "..."]` で登録する crate-private ユニットテスト
- `tests/unit.rs` — 上記外部テストを登録するエントリポイント。`tests/test_support/mod.rs` を import
- `tests/public_api.rs` — `kapsaro_core::api` の公開 API 境界テスト
- `tests/test_support_boundary.rs` — hidden root `kapsaro_core::test_support` 境界テスト。`required-features = ["cli-test-support"]` 付きの独立ターゲット

#### kapsaro-test-support crate (`crates/kapsaro-test-support/tests/`)

- `tests/ed25519_backend_test.rs` — 共有する Ed25519 署名 backend の独立テスト
- `tests/guards_test.rs` — cwd と環境変数の guard helper の独立テスト
- `tests/privilege_test.rs` — 権限拒否を再現するテストが共有する特権判定の独立テスト

#### テストの層選択と登録

どの層にテストを置くか、どこへ登録するか、テスト名の付け方、書いてはいけないテストは `kapsaro-testing` skill にある。テストを追加・移動するときは先にそれを読む。

登録漏れのファイルはコンパイルされず、テストが存在しないまま緑になる。`.claude/hooks/pre-stop-checks.sh` が未登録を検出するが、登録は書いた本人が行う。

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
- すべてのソースファイルの冒頭に、Copyright ヘッダーに続けて役割を述べる `//!` コメントを置く
- レイヤーの置き場所判断、依存方向、関数名・型名・モジュール名の規則は `kapsaro-conventions` skill にある。実装前に読む
- テストの層選択と登録手順は `kapsaro-testing` skill、レビュー観点は `kapsaro-review` skill にある

### 自動検査

規約検査は `scripts/` のスクリプトにある。エージェントの hook からも、コマンドとしても同じものが動く。

```bash
./scripts/check-source-conventions.sh [file.rs ...]  # 省略時は production ソース全件
./scripts/check-repo-conventions.sh
```

- `check-source-conventions.sh` — Copyright ヘッダー、`//!` コメント、`mod.rs` の新設、インラインテストモジュール
- `check-repo-conventions.sh` — テストファイルの登録漏れ、`guides/` の行末スペース

違反があると標準エラーへ説明を出して終了コード 2 で終わる。Claude Code では `.claude/settings.json` が前者を PostToolUse、後者を Stop の hook として登録している。hook 機構を持たないエージェントは、ソースを追加・変更したあとに自分で実行する。

これらが扱えない規約（stale な登録、`#[serial]` 指定、テスト層の選択、命名）は `kapsaro-review` の観点で確認する。

### skill の所在

規約の詳細はリポジトリ内の `.claude/skills/` にある。実体はここだけで、他の場所にコピーは置かない。

| 読むもの | いつ |
| --- | --- |
| `.claude/skills/kapsaro-conventions/SKILL.md` | コードを実装・変更・移動するとき。レイヤーの置き場所判断と命名 |
| `.claude/skills/kapsaro-conventions/references/layering.md` | 各層の責務の詳細が要るとき |
| `.claude/skills/kapsaro-conventions/references/naming.md` | 動詞・型名・廃止パターンの一覧が要るとき |
| `.claude/skills/kapsaro-testing/SKILL.md` | テストを追加・移動するとき。層の選択と登録手順 |
| `.claude/skills/kapsaro-review/SKILL.md` | 変更をレビューするとき |

上の表のパスは、どのエージェントからもリポジトリ内の相対パスとして読める。作業内容が該当したら、行動する前に対応するファイルを開いて読む。

skill を名前で読み込む機構を持つエージェントは、設定なしでリポジトリから発見できる。

- Claude Code は `.claude/skills/` を読む
- Codex は `.agents/skills/` を読む。中身は `.claude/skills/` への相対 symlink

実体は `.claude/skills/` の 1 つだけで、`.agents/skills/` はそこを指す symlink である。skill を追加したら `.claude/skills/` に置き、`.agents/skills/` へ symlink を張る。

```bash
ln -s ../../.claude/skills/<name> .agents/skills/<name>
```
