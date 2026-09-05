---
name: kapsaro-review
description: kapsaro の変更をレビューするときの観点。レイヤー責務違反、依存の逆流、テスト登録漏れ、デッドコードの残骸を確認する。コードレビュー、PR レビュー、実装完了後の自己点検、リファクタリング後の点検で使う。
---

# kapsaro レビュー観点

実装規約そのものは `kapsaro-conventions`、テスト規約は `kapsaro-testing` にある。ここでは変更を見るときに確認する項目を扱う。

## レイヤー責務

1. `cli` から `service` / `feature` / `io` へ直接 import していないか
2. `service` に `println!` / `eprintln!` / `dialoguer` が混入していないか
3. `service` が `api` / `cli` を参照していないか
4. `service` が環境変数、設定優先順位、workspace 自動検出、TTY、CLI DTO を扱っていないか
5. `api` に実装、変換、fallback、glob 再公開が混入していないか
6. `feature` が `cli` を参照していないか
7. `format` から `feature` へ依存が逆流していないか
8. `io` から `feature` / `cli` へ依存が逆流していないか
9. `crypto` が `cli` / `feature` / `io` を参照していないか
10. 表示の都合だけで service / feature の API が歪められていないか
11. `support` にドメイン規則や I/O の本体が溜まっていないか

1 から 9 は grep で確認できる。

```bash
K=crates/kapsaro-core/src
rg -n "use kapsaro_core::(service|feature|io)::" src/cli -g '*.rs'
rg -n "println!|eprintln!|dialoguer" $K/service -g '*.rs'
rg -n "crate::(api|cli)" $K/service -g '*.rs'
rg -n "use crate::(feature|cli)::" $K/io -g '*.rs'
rg -n "use crate::feature::" $K/format -g '*.rs'
rg -n "use crate::(cli|feature|io)::" $K/crypto -g '*.rs'
```

10 と 11 は読んで判断する。`support` に新しく入ったものは、2 つ以上のレイヤから使われているか、ビジネス上の意味が付いていないかを見る。意味が付いていたら `service` / `feature` / `io` への移動を検討する。

## 廃止した層の復活

`app` と `cli_api` は廃止済みで、責務は `api` と `service` へ移った。これらの名前を持つモジュールや、標準 API の互換 wrapper が復活していないかを見る。

## テストの登録と構成

`scripts/` の検査が Copyright ヘッダ、module doc、`mod.rs` の新設、インラインテストモジュール、テストの登録漏れ、実体のないファイルを指す stale な `#[path]` 登録、同じテストバイナリへの二重登録を機械的に検出する。レビューではこれらを再確認せず、検査が扱えない次の項目を見る。

- shebang 付きのファイルを書き出して exec するテストの `#[serial]` 指定。理由は当該テストの module doc にある
- テストが検証している内容が、その層の担当と合っているか
- 旧仕様の削除を確認する負のテストが追加されていないか
- 失敗したテストを、仕様を確認せずに書き換えていないか

## デッドコードの残骸

処理を別レイヤーへ移した変更では、移動元に残った未使用の関数と import を確認する。

判定は `cargo clippy --workspace --all-targets` で行う。CI のゲートもこれ。lib 単体ビルド（`cargo check -p kapsaro-core` など）は内部テストをコンパイルしないため、テストからのみ使われる項目を誤ってデッドと判定する。削除するとテストが壊れる。

production から使われず内部テストからのみ使われる項目は、削除ではなく `#[cfg(test)] pub(crate) use ...` にする。`crates/kapsaro-core/src/service/kv/mutation.rs` と `crates/kapsaro-core/src/io/keystore/access.rs` に既存の書き方がある。

残っている `#[allow]` を貫通して総量を測りたいときは、ファイルを編集せずに次を実行する。

```bash
CARGO_TARGET_DIR=/tmp/kapsaro-deadcode \
  RUSTFLAGS="--force-warn dead_code --force-warn unused_imports" \
  cargo check -p kapsaro-core --features cli-test-support --message-format short \
  | grep '^crates/kapsaro'
```

依存クレートの警告も出るため、自リポジトリ分に絞る。新しく `#[allow(dead_code)]` を足す変更では、対象が絞られているか、英語の理由コメントが添えられているかを見る。

## 命名

新しく追加された `pub fn` と `pub(crate) fn` について、`kapsaro-conventions` の `references/naming.md` の動詞表と照らす。とくに次は取り違えが起きやすい。

- I/O を伴うのに `get_*` になっている
- 違反時に `Err` を返すのに `check_*` になっている
- 暗号検証なのに `validate_*` になっている
- 決定的な導出なのに `generate_*` になっている
- `cli/` 以外に `setup_*` / `run_*` / `print_*` / `prompt_*` / `confirm_*` が現れている
- 廃止した `create_*` / `prepare_*` / `make_*` / `process_*` / `handle_*` / `map_*` / `read_*` / `write_*` が復活している

型名では、`Loaded*` / `Resolved*` / `Generated*` のような過去分詞プレフィックスが使われていないかを見る。

## 誤検出を避ける

指摘を出す前に、その挙動が仕様どおりでないことを確認する。silent failure、TOCTOU、`expect()` による panic の指摘は、実装だけを読むと成立して見えても仕様上は意図された挙動であることがある。過去に受容済み・仕様どおりと判定された指摘は繰り返さない。

## 実装後に通す

```bash
cargo test --workspace
cargo clippy --workspace --all-targets
cargo fmt -- --check
```

失敗したテストは、無条件に書き換えず、仕様に適合しているかを先に確認する。
