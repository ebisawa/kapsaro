---
name: kapsaro-conventions
description: kapsaro の Rust コードを実装・変更・移動するときの規約。処理をどのレイヤーへ置くかの判断、依存方向の禁止事項、関数名・型名・モジュール名の決め方。新しい関数や型を追加するとき、既存コードを別モジュールへ移すとき、リファクタリングの移動先を決めるとき、命名に迷ったときに使う。
---

# kapsaro 実装規約

レイヤー構成と各層の概要は CLAUDE.md にある。ここでは、そこに書かれていない判断基準と命名規則を扱う。

## 先に知っておくこと

`cli -> cli_api -> app -> service` の経路は廃止予定である。CLI 用の内部 API である `cli_api` と、そのバックエンドの `app` レイヤーは、順次 `api` と `service` へ移管している。到達点は `cli -> api -> service` の一本。

このため新しい責務は `service` に置き、外部へ出す必要があるものだけ `api` から再公開する。`app` と `cli_api` には新しいユースケースを追加しない。既存の `app` の処理に手を入れるときは、それが CLI 固有の入力解決なのか caller 共通の規則なのかを見直し、後者なら `service` へ移す。移行済みの処理を互換 wrapper として `app` や `cli_api` に残さない。

詳細な表が必要になったら次を読む。

- `references/layering.md` — 各層の「やってよいこと / やってはいけないこと」、層間のデータ受け渡し、副作用の担当、逆流検出コマンド
- `references/naming.md` — 動詞の用途表、廃止した命名パターンと代替先、型名サフィックス

## 置き場所の判断

処理の移動先に迷ったら、上から順に問う。最初に Yes になった層へ置く。

| 問い | Yes なら |
| --- | --- |
| ユーザーとの対話や出力が主目的か | `cli` |
| 明示的な入力と capability だけで、CLI 以外からも同じ意味で実行できるか | `service` |
| 複数機能の呼び出し順を組み立てていて、CLI 固有の入力解決と不可分か | `app`（廃止予定。新設は避け、`service` へ寄せられないか先に検討する） |
| 1 つのドメイン機能の正しさを実装しているか | `feature` |
| 外部パス・プロセス・ネットワークに触れているか | `io`（手続きのみ。結果の解釈は上位） |
| バイト列のエンコード・正規化・パースが主目的か | `format` |
| 複数箇所で共有するデータの形だけを定義したいか | `model` |
| 1 回の暗号・署名演算に還元できるか | `crypto` |
| CLI / env / 設定ファイルのどれが勝つかを決めているか | `config` の resolution |
| 特定ドメインに属さない小さな共有ヘルパか | `support`（意味が付いたら上位へ移す） |

迷う場合の原則。

- 表示に近いものは上へ、ドメイン規則に近いものは下へ
- 共通化のために上位レイヤーへ引き上げない
- UI 都合で下位レイヤーへ責務を押し込まない

### app と service の切り分け

同じ処理が両方に見えるときは、入力を誰が選ぶかで決める。

- どの入力を選び、いつ、何を、どの順序で行うかは `app`
- 選択済みの入力と capability に対して、どの caller でも同じ規則を実行するのは `service`
- review 後に何を再ロードして再試行するかは `app`、review candidate と証跡の整合や保存 transaction は `service`

`service` が環境変数、設定の優先順位、workspace 自動検出、TTY、CLI DTO に触れていたら、その部分は `app` にある。

`app` は縮小していく層なので、この切り分けは既存コードを読むときと、移管の粒度を決めるときに使う。迷ったら `service` 側に寄せる。

## よくある逆流

追加した `use` がこれらに当たらないか確認する。全て 0 件であるべきものなので、1 件でも出たら設計を戻す。

```bash
K=crates/kapsaro-core/src
rg -n "use crate::(io|feature)::" src/cli -g '*.rs'
rg -n "println!|eprintln!|dialoguer" $K/app -g '*.rs'
rg -n "crate::api" $K/app -g '*.rs'
rg -n "crate::(app|api|cli_api)" $K/service -g '*.rs'
rg -n "use crate::(feature|app|cli)::" $K/io -g '*.rs'
rg -n "use crate::feature::" $K/format -g '*.rs'
rg -n "use crate::(app|cli|feature|io)::" $K/crypto -g '*.rs'
```

## 命名の要点

関数は `動詞_対象_修飾子`、型は名詞のみ、モジュールは単数形の名詞。関連する操作は対称に名付ける（`wrap_*` と `unwrap_*`、`sign_*` と `verify_*`）。

取り違えやすい組み合わせを挙げる。全ての動詞は `references/naming.md` にある。

| 使い分け | 判断基準 |
| --- | --- |
| `get_*` と `load_*` | I/O があれば `load_*`。`get_*` はパス・設定値の取得に限る |
| `validate_*` と `verify_*` | 構造・形式の制約チェックは `validate_*`、暗号検証は `verify_*` |
| `check_*` と `enforce_*` | 違反時に `Err` を返すなら `enforce_*`。`check_*` は判定結果を返すだけ |
| `generate_*` と `derive_*` | 非決定的な生成は `generate_*`、決定的な導出は `derive_*` |
| `judge_*` と `evaluate_*` | `feature` の純粋判定は `judge_*`、`app` の文脈付き評価は `evaluate_*` |
| `execute_*` と `run_*` | `app` / `io` の副作用処理は `execute_*`、CLI エントリポイントは `run_*` |
| `find_*` と `select_*` | 条件に合う単一要素の探索は `find_*`、優先順位に基づく選択は `select_*` |
| `parse_*` と `deserialize_*` | 外部入力の妥当性検証を含むなら `parse_*` |
| `derive_*` と `compute_*` | 鍵・ID・暗号素材の仕様上の導出は `derive_*`、ハッシュや統計値は `compute_*` |
| `member_handle` と `member_id` | ユーザーが指定する識別子は `member_handle`、永続化・ワイヤ・domain model は `member_id` |

`setup_*` / `run_*` / `print_*` / `prompt_*` / `confirm_*` は `cli/` 専用で、他の層では使わない。

### 使わない動詞

`create_*` / `prepare_*` / `make_*` / `process_*` / `handle_*` / `map_*` / `configure_*` / `diagnose_*` / `reject_*` / `classify_*` / `warn_*` / `read_*` / `write_*` と、`*_flow()` サフィックス。代替先は `references/naming.md` にある。

### 型名

処理済み状態は過去分詞プレフィックスではなく名詞サフィックスで表す。`Loaded*` / `Resolved*` / `Generated*` ではなく `*Resolution` / `*LoadResult` / `*Snapshot` / `*Plan` / `*Report` / `*View` などを使う。

security state を表す opaque capability は、暗号学的検証済みが `Verified*`、現在の信頼状態で読み取り可能なものが `Trusted*`、特定の更新操作を認可済みのものが `Authorized*`。

### モジュール

`mod.rs` は使わず `{module_name}.rs` と `{module_name}/` のペアで構成する。`flow` はモジュール名に使わず、`review` / `execution` / `session` / `approval` / `persistence` など責務を表す具体名にする。

## 処理を移したあと

移動元に残った未使用の関数と import を確認する。

`crates/kapsaro-core/src/lib.rs` の blanket allow は `cli-internal` feature が無効なときだけ効くため、lib 単体ビルドではデッドコードが報告されない。判定は `cargo clippy --workspace --all-targets` で行う。内部テストは production module から `#[cfg(test)] #[path]` で登録されており、lib 単体ビルドではコンパイルされないため、テストからのみ使われる項目が誤ってデッドに見える。

production から使われず内部テストからのみ使われる項目は、削除せず `#[cfg(test)] pub(crate) use ...` にする。`crates/kapsaro-core/src/app/trust.rs` に既存の書き方がある。

## 実装後に確認する

```bash
cargo test --workspace
cargo clippy --workspace --all-targets
cargo fmt -- --check
```
