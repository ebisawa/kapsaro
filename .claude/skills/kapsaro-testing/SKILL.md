---
name: kapsaro-testing
description: kapsaro にテストを追加・移動・削除するときの規約。どの層に置くか、どこへ登録するか、テスト名の付け方、テストで書いてはいけないもの。テストが落ちたとき、テスト構成を変えるとき、カバレッジを増やすときにも使う。
---

# kapsaro テスト規約

テストツリーの所在は CLAUDE.md にある。ここでは層の選び方、登録手順、禁止事項を扱う。

テスト名とテストファイル名の規則は `kapsaro-conventions` skill の `references/naming.md` にある。ここでは重複して定義しない。

## どの層に置くか

テストの assert から次の要素を取り除いて考える。

- プロセス起動
- stdout / stderr
- 終了コード
- 対話プロンプト
- PTY 挙動
- CLI 固有の表示整形

取り除いたあとに検証内容が残らなければ CLI E2E に置く。残るならその部分をユニット層へ移す。両方を検証したい場合はテストを 2 層に分け、CLI E2E では CLI 表現だけを assert する。

| 検証したいこと | 置き場所 |
| --- | --- |
| `--help` の出力順、フラグ名、終了コード | CLI E2E |
| JSON 出力が CLI 表示用の形に整形されること | CLI E2E |
| `cli_api::app` の request が特定の result DTO を返すこと | 外部ユニット |
| `kapsaro_core::api` の公開面のシグネチャと振る舞い | 外部ユニット |
| 署名検証で同じ `ErrorKind` に到達する複数の改ざんパターン | 内部ユニット |
| JSON ドキュメントの正規化バイト列が仕様どおり組み立てられること | 内部ユニット |

### 各層の担当

CLI E2E は、プロセスとして起動した CLI が利用者から見て期待どおりに振る舞うかを見る。引数解釈、必須引数、排他フラグ、`--help`、終了コード、stdout と stderr の文言と順序と色、対話プロンプトと PTY、non-interactive と `--force`、stdin と stdout の配管、出力先パス解決、CLI 整形後の JSON 構造。各コマンドにつき happy-path roundtrip を 1 本以上置く。

外部ユニットは、crate 外部または first-party テスト用の境界から見た契約を見る。`api` と `cli_api` の public surface を固定したい場合はここ。下位実装の private item へ入らずに検証できるなら、内部ユニットより外部ユニットを選ぶ。

内部ユニットは、ドメインアルゴリズムと実装の細部を見る。エッジケース、改ざん検出のバリエーション、wrap と署名検証の細部、ドキュメントのバイトレベル検証、同一エラーへ到達する入力バリエーション、crate-private item の不変条件。`crate::` 直接アクセスが必要な検証はここ。

同一ドメインエラーの入力バリエーションは内部ユニットで網羅し、CLI E2E には代表 1 件だけ置く。CLI E2E で暗号文書の内部構造、wrap トークン、署名検証の細部を assert しない。

## 登録

ファイルを追加したら必ず登録する。登録漏れのファイルはコンパイルされず、テストが存在しないまま緑になる。

### 内部ユニット

`crates/kapsaro-core/tests/unit/internal/` または root crate の `tests/unit/internal/` にファイルを置き、対応する production ファイルの末尾に登録する。

```rust
#[cfg(test)]
#[path = "../../tests/unit/internal/<file>.rs"]
mod <mod>;
```

相対パスの深さは production ファイルの位置で決まるため、既存の近いファイルの書き方に合わせる。既存ファイルに同じ検証対象のテストがある場合は、新規ファイルを増やす前に追記を検討する。

内部ユニットをさらに分割する場合は、親テストファイルからサブディレクトリ付きの相対パスで登録する。

```rust
#[path = "format_file_enc_test/decrypt.rs"]
mod decrypt;
```

### 外部ユニット

`crates/kapsaro-core/tests/unit/external/` にファイルを置き、`crates/kapsaro-core/tests/unit.rs` へ 1 行追加する。

```rust
#[path = "unit/external/<file>.rs"]
pub mod <mod>;
```

root crate には外部ユニットのツリーがない。root crate 側で契約を固定したい場合は CLI E2E か内部ユニットを使う。

### CLI E2E

`tests/cli/` の対応コマンドのファイルへ追記する。新しいコマンド領域を足す場合は `tests/cli.rs` から辿れる module として登録する。`tests/cli_integration.rs` は入口なので、通常のテスト追加では触らない。

### 登録の確認

`.claude/hooks/pre-stop-checks.sh` が未登録と二重登録を検出する。手で確認するときは、モジュール名ではなく `#[path]` 属性そのものを grep する。モジュール名は `mod tests;` のような総称名とファイル名と同名のものが混在しており、名前からは追えない。

## 書いてはいけないテスト

### ソースコードのテキスト解析

ソースファイルを `fs::read_to_string` で読み、`contains` や正規表現で規約適合、依存方向、公開面の変化を検査するテストは書かない。`src/**/*.rs` を読むテストを追加しようとした時点で設計が誤っている。

行単位のテキスト走査は Rust の構文を解釈できないため、想定していない記法が検査を素通りする。以前あった allow-list スナップショット検査では、別ファイルへ分ける `pub mod x;` 形式と `pub unsafe fn` が収集からも未対応検出からも漏れており、公開面が知らないうちに広がるのを防ぐという目的を果たしていなかった。誤検知も生む。コメントや文字列リテラルに禁止語が現れただけで失敗する一方、別名 import で書き換えれば通過する。

境界や規約を守らせたいときは、次のいずれかで表現する。

- 型と可視性でコンパイラに強制させる。`pub(crate)` で crate 外から到達できなくする、newtype で不正な値を構築できなくする
- `clippy.toml` の `disallowed-methods` / `disallowed-types` に理由つきで登録する。CI は `cargo clippy --workspace --all-targets --locked -- -D warnings` を実行するため、警告レベルでも違反はビルド失敗になる
- 対象を実際に import して使うコンパイル時の境界テストにする。`crates/kapsaro-core/tests/public_api.rs` がこの形で、公開面から項目が消えればコンパイルが通らない

lint 設定を追加したら、意図した違反が実際に検出されることを確認する。パスが解決できない登録は警告も出さずに無効化されるため、設定を書いただけでは検査が効いている根拠にならない。確認は production コードを一時的に壊すのではなく、使い捨ての小さな crate に同じ `clippy.toml` を置いて行う。

### 旧仕様の削除を確認する負のテスト

「〜しないこと」を確認するテストは書かず、最新仕様への適合だけを確認する。

### 環境変数のロックを取らないテスト

`KAPSARO_HOME` や `KAPSARO_PRIVATE_KEY` などを読むコードのテストは、`crates/kapsaro-test-support/src/guards.rs` の `EnvGuard` を必ず取得する。`EnvGuard` はグローバル mutex を保持し、環境変数を書き換えるテストどうしの並行実行を防いだうえで、退出時に元の値へ戻す。

ロックを取らないテストが並行実行されると、他のテストが設定した環境変数を拾って断続的に失敗する。成功や `exit_code() == 0` を主張するテストは、拾った設定でたまたま成功してしまうため特に危険で、失敗が再現しにくい形で紛れ込む。

### cwd を生で変更するテスト

`std::env::set_current_dir` は `clippy.toml` で禁止されている。`kapsaro-test-support` の `with_temp_cwd` を使う。生の呼び出しは `CWD_LOCK` を取らないため、`with_temp_cwd` を使う他のテストと並行実行され、panic 時に cwd も復元されない。

## production tree に置くテスト専用コード

`src/` 配下に置いてよいテスト専用コードは 3 種類だけで、いずれも `#[cfg(test)]` で本番ビルドから消える。

- `crates/kapsaro-core/src/support/fs/test_umask.rs` — マクロが crate-private 項目を `crate::` パスで参照するため `src/` から出せない
- フォールトインジェクション用のフック — 書き込みの途中で失敗させたり、ロックを保持している区間の内側を観測したりするには、本番の制御フローにシームを置くしかない。`support/fs` の作成・書き込み・走査経路と、`io/keystore` および `io/trust` の保存経路にある
- テスト専用の中置コンストラクタ — 本番は検証を経る `try_new` 系だけを使うが、テストではリテラル値から直接組み立てたい箇所がある。`feature/kv/types.rs` の `KvInputEntry::new`、`feature/trust/judgment/identity.rs` の `TrustIdentity::new`、`feature/trust/judgment/self_trust.rs` の `SelfTrustSet::new` が該当し、いずれも `#[cfg(test)]` 付きで対応する `try_new` を呼び、invalid な入力なら panic する

差し込み口を新しく足すときは、既存と同じ形に揃える。thread_local の slot に登録し、実行側は `take()` で自己消費してテスト間に持ち越さない。本番ビルドでは呼び出しが no-op になるようにする。

本番の実行経路に、何もしない closure や、そのためだけの型引数を残さない。何もしない closure を本番から渡す形にすると、テストの都合が production の関数の形を決めてしまう。処理を割り込ませる必要がある場合は、`#[cfg(test)]` で囲んだ thread-local の hook と `#[cfg(not(test))]` の空実装の組を使う。差し込み口が何を再現するためのものかは、宣言箇所のコメントに書く。

インラインテストモジュール（production ファイル内の `#[cfg(test)] mod tests { ... }`）は置かない。テスト本体は必ず `tests/` ツリーに置き、`#[path]` で登録する。

## テスト数を比べるとき

比較と検証は `cargo test --workspace` どうしで行う。`cargo test -p <crate>` の単独実行は feature unification が異なるため、workspace 全体の比較基準にしない。root crate の default feature に `online` が含まれることが差の原因になる。

CLI E2E の代表ケースを増やす前に、同じドメイン分岐が内部ユニットで網羅できるか確認する。外部ユニットと内部ユニットのどちらでも検証できる場合は、公開境界の契約として意味があるかを基準に選ぶ。
