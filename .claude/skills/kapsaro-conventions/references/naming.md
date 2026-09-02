# 命名規則の詳細

対象は `pub fn` と `pub(crate) fn`。private 関数も同じ方針で名付ける。

## カテゴリ別の形

| カテゴリ | ルール | 例 |
| --- | --- | --- |
| 型名 | 名詞のみ。動詞・形容詞を含まない | `FileEncDocument`、`WrapItem` |
| 関数名 | `動詞_対象_修飾子` | `load_private_key()`、`encrypt_file_document()` |
| モジュール名 | 単数形の名詞、または動詞の名詞形 | `encrypt/`、`decrypt/`、`model/` |

関連する操作は対称に名付ける。

```
encrypt_file_document()   ↔  decrypt_file_document()
encrypt_kv_document()     ↔  decrypt_kv_document()
wrap_master_key()         ↔  unwrap_master_key()
sign_file_document()      ↔  verify_file_document()
sign_kv_document()        ↔  verify_kv_document()
```

## member_id と member_handle

CLI 引数、環境変数、設定値など、ユーザーが指定するメンバー識別子は `member_handle` と呼ぶ。

永続化形式、ワイヤ形式、JSON schema、domain model、暗号ドキュメント内の識別子は `member_id` / `MemberId` と呼ぶ。

外部入力を解決して domain object や暗号ドキュメントへ渡すところでは、入力側が `member_handle`、解決済みの domain 値が `member_id`。

## 動詞の用途

| 動詞 | 用途 | 禁止事項 |
| --- | --- | --- |
| `get_*` | パス・設定値の取得（I/O なし） | ファイル読み込みに使用不可 |
| `load_*` | ファイル・ストレージからの読み込み | |
| `save_*` | ファイル・ストレージへの書き込み | |
| `parse_*` | バイト列・文字列から構造体への変換 | |
| `encode_*` / `decode_*` | base64、token、SSH blob など明確なエンコード仕様に基づく符号化と復号 | `parse_*` と混用しない |
| `serialize_*` / `deserialize_*` | serde JSON など、内部データ構造と保存・送信用バイト列の相互変換 | 外部入力の妥当性検証や schema validation を含む処理には `parse_*` を使う |
| `format_*` | 表示用文字列・表示行の整形 | データ構造の組み立てには使用しない |
| `normalize_*` | 入力値を canonical form へ正規化 | 表示用整形には使用しない |
| `detect_*` | フォーマット・種別の判定 | |
| `extract_*` | 構造化済みデータから一部を取り出す | 外部 I/O や新規構築には使用しない |
| `build_*` | 複数部品から構造体を組み立て | `create_*` / `prepare_*` / `make_*` を使わない |
| `generate_*` | 乱数、鍵、salt など非決定的な値の生成 | 決定的な派生値には使用しない |
| `derive_*` | 鍵・ID・派生値を入力から決定的に導出 | 乱数生成には使用しない |
| `encrypt_*` / `decrypt_*` | 暗号化と復号 | |
| `sign_*` / `verify_*` | 暗号署名の生成と検証 | |
| `validate_*` | 構造・形式の制約チェック（暗号検証を伴わない） | `verify_*` と混用しない |
| `check_*` | 状態確認と判定結果の返却 | 違反時に必ずエラーにする処理には使用しない |
| `enforce_*` | policy、事前条件、安全条件の強制。違反時は `Err` を返す | 単なる判定には使用しない |
| `wrap_*` / `unwrap_*` | KEM ラップとアンラップ | |
| `resolve_*` | 設定・パスの動的解決 | |
| `require_*` | 必須値・必須コンテキストを取得し、欠落時は `Err` を返す | 動的な候補解決には使用しない |
| `fetch_*` | リモート API など外部サービスからの取得 | ローカルファイル・ストレージ読み込みには使用しない |
| `ensure_*` | 必要な状態を満たす。必要に応じて作成・補正などの副作用を伴ってよい | 純粋な構造体組み立てには使用しない |
| `list_*` | コレクションの列挙 | |
| `collect_*` | 既存データから条件に合う要素を集めて返す | 外部ストレージからの列挙には使用しない |
| `find_*` | 条件に合う単一要素の探索 | 優先順位に基づく選択には使用しない |
| `select_*` | 候補群から規則・優先順位に基づいて 1 つを選ぶ | 単純な探索には使用しない |
| `set_*` / `unset_*` | KV エントリの設定と削除 | |
| `add_*` / `remove_*` | member、recipient、known key など domain collection の追加と削除 | KV エントリには `set_*` / `unset_*` を使う。低レベルなファイル削除名の代替として安易に使わない |
| `append_*` | 既存の文字列・バイト列・ドキュメント末尾へ、SIG 行などの構造化要素を追記 | domain collection への追加は `add_*`、ファイル保存は `save_*` |
| `promote_*` | incoming など一時状態の domain object を正式状態へ昇格 | |
| `export_*` / `import_*` | 内部状態と外部ファイル・portable 表現のあいだの操作 | `save_*` / `load_*` と混用しない |
| `execute_*` | `app` / `io` 層で副作用を含む一連の処理を実行 | CLI エントリポイントには `run_*` を使う |
| `judge_*` | `feature` 層で信頼状態などを純粋に判定し、判定結果を返す | `app` 層の文脈付き評価には使用しない |
| `evaluate_*` | `app` 層で proof、context、policy を組み合わせて評価する | 純粋な domain 判定には使用しない |
| `review_*` | 人間の承認・確認を含む review 処理 | 単なる判定には使用しない |
| `*_with_confirmation` | 確認コールバックを受け取る review・approval 処理 | `*_with_handler` を使わない |
| `rewrite_*` | 既存データやファイル内容を意味を保ちながら書き換える | 単なる保存には使用しない |
| `compute_*` | ハッシュ、fingerprint、統計値など計算結果を導出する | 鍵・ID・暗号素材の仕様上の導出には `derive_*` を使う |
| `rewrap_*` | 既存暗号ドキュメントの recipient wrap や鍵素材の再ラップと再暗号化 | 通常の暗号化は `encrypt_*`、意味を保つ一般的な書き換えは `rewrite_*` |

### 限定例外

中核の動詞表へ追加せず、次の狭い用途に限って使ってよい。

| パターン | 用途 |
| --- | --- |
| `seal_*` / `open_*` / `expand_*` | 暗号仕様で定義された primitive 名をそのまま表す場合 |
| `fill_*` | 呼び出し元が渡したバッファや配列へ値を埋め込む低レベル処理 |
| `activate_*` / `rotate_*` / `clear_*` / `purge_*` / `merge_*` | 仕様または domain model で定義された状態・世代・履歴操作 |

### cli 専用の動詞

`cli/` 以外では使わない。

| 動詞 | 用途 |
| --- | --- |
| `setup_*` | コマンド実行前の準備処理（外部 I/O を伴う初期化）。副作用を持つ点で `build_*` と区別する |
| `run_*` | コマンドのエントリポイント、またはサブコマンドのディスパッチ |
| `print_*` | 標準出力への表示 |
| `prompt_*` | ユーザー入力を求める対話処理 |
| `confirm_*` | yes/no などユーザー確認を求める対話処理 |

### Rust idiom とアクセサ

次は一般的な API idiom または単純アクセサとして使ってよい。複雑な処理、外部 I/O、policy 判定、副作用を含む場合は、上の動詞規則に従って具体的な責務名を付ける。

| パターン | 用途 |
| --- | --- |
| `new` / `try_new` / `default` | 型の標準コンストラクタ |
| `from_*` / `into_*` / `as_*` / `to_*` | Rust の変換・参照取得 idiom |
| `is_*` / `has_*` / `contains_*` / `matches_*` | bool を返す単純判定 |
| `allows_*` / `needs_*` | bool を返す policy・状態の単純判定 |
| `with_*` | builder-style の値追加、または closure で一時的な context を渡す処理 |
| `block_on*` | async runtime や executor の標準的な同期実行 idiom |
| `*_mut` | mutable accessor |
| フィールド名と同じ関数名 | I/O や計算を伴わない単純 accessor |

## 廃止した命名パターン

| 廃止 | 代替 |
| --- | --- |
| `create_*` | 決定的な構造体組み立ては `build_*`、乱数・鍵生成は `generate_*`、I/O 作成は `ensure_*` または `save_*` |
| `prepare_*` | 状態判定は `evaluate_*`、動的解決は `resolve_*`、副作用を伴う状態整備は `ensure_*`、実行は `execute_*` または `run_*` |
| `make_*` | 構造体組み立ては `build_*`、非決定的生成は `generate_*`、決定的導出は `derive_*` |
| `process_*` | 副作用を含む一連の処理は `execute_*`、評価は `evaluate_*`、書き換えは `rewrite_*`、変換は `parse_*` / `format_*` / `build_*` |
| `handle_*` | エラー生成は `build_*_error`、CLI 応答は `run_*` / `print_*`、副作用実行は `execute_*` |
| `map_*` | エラー生成は `build_*_error`、view model 生成は `build_*_view`、値の抽出は `extract_*`、単純変換は `from_*` / `into_*` / `to_*` |
| `trim_*` / `unquote_*` | parser の一部として `parse_*`、canonical form への整形として `normalize_*`、一部抽出として `extract_*` |
| `configure_*` | 既存オブジェクトへの値設定は `set_*`、設定値の解決は `resolve_*`、状態整備は `ensure_*` |
| `diagnose_*` / `probe_*` | 状態確認は `check_*`、制約強制は `enforce_*`、失敗時のエラー生成は `build_*_error` |
| `reject_*` | 禁止条件の強制は肯定形の `enforce_*` |
| `classify_*` / `match_*` | 分類済みデータの構築は `build_*`、判定は `judge_*`、探索は `find_*`、選択は `select_*` |
| `warn_*` | 警告値の生成は `build_*_warning`、CLI 出力は `print_*`。logging macro は helper で隠さず呼び出し側で直接使う |
| `build_*_display()` | 文字列整形は `format_*` |
| `*_with_handler` | 確認コールバックを受けるなら `*_with_confirmation`、それ以外は具体的な責務名 |
| `*_flow()` サフィックス | 全レイヤーで廃止。外して意味が通るならそのまま、不明瞭ならドメイン名詞を補う |
| `verify_and_decrypt_*` | `decrypt_*` に統合 |
| `read_*` | `load_*` に統一（`cli/` を含む全レイヤー） |
| `write_*` | `save_*` に統一（`cli/` を含む全レイヤー） |

## 型名

### 検証済みラッパー型

`Verified*` プレフィックスに統一する。`Decrypted*` は廃止。

security state を表す opaque capability では、暗号学的に検証済みを `Verified*`、現在の信頼状態で読み取り可能な状態を `Trusted*`、特定の更新操作を認可済みの状態を `Authorized*` で表す。対象、状態、鍵、操作の不変条件を型に保持する場合に限って使う。

### Proof 型

`*Proof` サフィックスに統一する。`SignatureVerificationProof`、`BindingVerificationProof`、`AttestationProof`、`DecryptionProof`、`SelfSignatureProof`。

### ドキュメント型

暗号化済みデータを表す型は `{Domain}EncDocument`。

### 状態と結果を表す型

処理済み状態や結果は、動詞の過去分詞プレフィックスではなく名詞サフィックスで表す。

| サフィックス | 用途 | 例 |
| --- | --- | --- |
| `*Resolution` | 設定・パス・候補の解決結果 | `SshKeyResolution` |
| `*LoadResult` | ファイル・ストレージ読み込みの結果 | `TrustStoreLoadResult` |
| `*Draft` | 署名前・確定前の作業中ドキュメント | `KvDocumentDraft` |
| `*Material` | 鍵素材など生成・構築された素材一式 | `KeypairMaterial` |
| `*State` | 現在状態を保持する値 | `TrustStoreState` |
| `*Snapshot` | ある時点の状態を固定した値 | `ActiveMemberSnapshot` |
| `*Candidate` | 選択・承認・検証の候補 | `TrustApprovalCandidate` |
| `*Plan` | 実行前に確定した処理計画 | `RewrapBatchPlan` |
| `*Report` | 検証・診断・実行結果の報告 | `SignatureVerificationReport` |
| `*View` | CLI や表示用の view model | `MemberListView` |

`Loaded*` / `Resolved*` / `Generated*` / `Unsigned*` / `Encrypted*` などの過去分詞・形容詞プレフィックスは使わず、上のサフィックスか具体的なドメイン名詞へ置き換える。

仕様で定義された domain state を表す `Active`、`Incoming`、`Known` は型名の修飾語として使ってよい。`Verified*` は検証済みラッパー型の規則に従う。

## モジュールとファイル名

- モジュール名は単数形の名詞、または動詞の名詞形
- `flow` はモジュール名に使わない。`review` / `execution` / `session` / `approval` / `persistence` など責務を表す具体名を使う
- `mod.rs` は使わず、`{module_name}.rs` と `{module_name}/` のペアで構成する
- ファイル名はそのファイルの主役を表す名詞

## テストの命名

テスト関数名は `test_<対象>_<シナリオ>_<結果サフィックス>`。`test_` プレフィックスは必須。

| サフィックス | 用途 | 例 |
| --- | --- | --- |
| なし | ハッピーパス | `test_encrypt_file_with_workspace` |
| `_fails` | パニック・abort で失敗するケース | `test_decrypt_with_invalid_input_fails` |
| `_error` | `Result::Err` を返すケース | `test_resolve_ssh_key_no_source_error` |
| `_roundtrip` | エンコードとデコード、暗号化と復号の往復検証 | `test_aes_gcm_encrypt_decrypt_roundtrip` |

使わないサフィックスは `_success`、`_returns_error`、`_returns_err`、`_ok`、`_works`。

テストヘルパー名は、`tests/` 配下の fixture や一時環境の初期化に限り `setup_*` を使ってよい。`make_*` / `process_*` / `handle_*` はテストヘルパーでも使わず、構造体組み立ては `build_*`、非決定的生成は `generate_*`、I/O を伴う保存は `save_*`、状態整備は `ensure_*` を使う。

テストファイル名は `<モジュールパス>_test.rs`。対象モジュールのソースパスをアンダースコアで連結する。

| テスト対象ソース | テストファイル名 |
| --- | --- |
| `feature/encrypt/wrap.rs` | `feature_encrypt_wrap_test.rs` |
| `io/keystore/resolver.rs` | `io_keystore_resolver_test.rs` |
| `support/recipients.rs` | `support_recipients_test.rs` |
| `crypto/sign/ed25519.rs` | `crypto_sign_ed25519_test.rs` |

登録時の module 宣言名はファイル名（拡張子を除く）と一致させる。配置と登録の手順は `kapsaro-testing` skill にある。
