# レイヤー責務の詳細

各層で「何を置き、どこからが越境か」を固定する。依存方向の図は CLAUDE.md にある。

`cli_api` と `app` は廃止予定で、責務を `api` と `service` へ移管している最中である。これらの節は既存コードを読み、移管するまでのあいだ手を入れるための記述であり、新しい責務の置き場所としては使わない。

## cli

外部入出力の adapter。ユーザー入力を解釈し、request と result を CLI 表現へ変換することだけを担当する。

やってよいこと。

- Clap 引数の定義と解釈、対話入力と確認プロンプト
- `CommonCommandOptions` や CLI 専用 args struct から request を組み立てる
- `println!` / `eprintln!` による表示、human-readable と JSON の分岐
- 終了コードに相当するエラー伝播、CLI 表示専用の整形
- trusted な秘密値を環境変数へ変換して子プロセスを起動する process boundary

やってはいけないこと。

- 暗号処理、署名検証、再暗号化などの業務ロジック実装
- workspace 解決、keystore 解決、member 解決の本体実装
- `io::*` および `feature::*` への直接アクセス
- 永続化フォーマットやドメイン制約の判断

`cli` の関数が長くなったら、表示分岐が多いのか、本来 `app` にある処理が混ざっているのかを疑う。テストは表示文言・JSON 形状・フラグ分岐に集中させる。

## app（廃止予定）

first-party CLI のユースケースオーケストレーション。CLI 引数、環境変数、設定、既定値から実行対象と方針を一度だけ解決し、1 コマンド単位の処理順序を管理する。

残すのは CLI 固有の入力解決と、review 前後の reload や retry のような進行管理に限る。caller 共通の規則は `service` へ移す。

やってよいこと。

- `service` / `feature` / `io` / `format` / `model` / `config` の呼び出し
- request struct と result struct の定義、エラーへの文脈付与
- workspace 解決ポリシー（optional / required）の統一
- review 前後の reload、retry、recovery、競合時の再提示

やってはいけないこと。

- `println!` / `eprintln!` による直接出力、`dialoguer` などの対話 UI
- 暗号仕様や署名仕様そのものの実装
- 永続化フォーマットの parser / serializer 実装
- CLI の文言テンプレートの保持
- artifact の信頼評価、approval 証跡検証、trust store transaction の再実装
- `api` facade への依存

典型例。encrypt 実行前に workspace と recipient 群を解決して `feature::encrypt` へ渡す。key list のために member id fallback と keystore 解決をまとめる。rewrap の batch 実行で scan、verify、promote、rewrite を順序制御する。trust review 後に artifact、members、trust store を再ロードして同じ操作として再評価する。

返り値は、CLI が追加のドメイン知識なしで表示できる粒度にする。

## service

標準公開 API の実装層。caller が明示した入力と、検証済み・信頼済み・認可済みの capability を受け取り、CLI 以外のアプリケーションからも同じ意味で使える標準操作を実行する。

やってよいこと。

- caller が明示した path、owner、member、operation、options の利用
- `feature` / `io` / `format` / `model` / `config` の型と `support` への依存
- `Verified*` / `Trusted*` / `Authorized*` capability の安全な生成順序
- 選択済み root の descriptor と capability を保持した I/O
- trust store のロック、snapshot 照合、再署名、原子的保存
- 操作結果と構造化された診断の返却

やってはいけないこと。

- CLI 引数、環境変数、設定優先順位、workspace 自動検出による入力の選択
- `app` / `api` / `cli_api` / `cli` への依存
- TTY、表示、確認プロンプト、CLI DTO、子プロセス起動
- caller が選択した path や identity の再解決

## feature

ドメインの処理本体。CLI の存在を知らず、1 つの機能を再利用可能な形で提供する。

やってよいこと。

- `io` / `format` / `model` / `crypto` / `config` への依存
- 純粋関数または限定された副作用を持つドメイン処理
- 暗号化・復号・署名・検証・再暗号化のロジック、member / key / kv / inspect のドメインルール

やってはいけないこと。

- `cli` の引数型や表示形式への依存、`app` の DTO や session 概念への依存
- `println!` / `eprintln!` による UI 出力、対話入力
- 「このコマンドでは次に何をするか」というフロー制御の保持

同じ処理を CLI 以外からも再利用したいなら `feature`。入出力よりも正しい変換・検証・制約に主眼があるなら `feature`。

## io

外部世界との I/O の実装置き場。ファイル、設定ストア、SSH エージェント、workspace 検出とメンバー管理など、環境依存の手続きを担当する。

やってよいこと。

- パスの解決、読み書き、ロック、ブートストラップ
- SSH や keystore など OS・外部プロセスとのやりとり
- `support` を使った安全なファイル操作や表示用パス整形
- バイト列やテキストの入出力（意味付けは上位へ）

やってはいけないこと。

- 暗号仕様に沿った業務判断の本体（誰が復号できるか、再暗号化の可否など）
- `feature` / `app` / `cli` への依存、CLI 表示や対話

パスがどこか、ファイルに何バイトあるかは `io`。その内容が仕様上正しいかは `feature` や `format` / `model`。

## format

ワイヤー表現とシリアライズ。JSON 構造、JCS、トークンエンコード、KV 行形式、入力フォーマット検出など、on-disk と on-wire の形に責任を持つ。

やってよいこと。

- 正規化に基づく署名対象バイト列の組み立て、トークンや KV 行のパースと生成
- `crypto` / `model` / `support`（`wire` と `limits` を含む）への依存

やってはいけないこと。

- `feature` への依存。ドメインのオーケストレーションやユースケース分岐を持ち込まない
- CLI や app 専用の DTO や表示都合への迎合

ファイルを開いて読むのは `io`、読んだ文字列を仕様どおりの構造にするのが `format`。

## model

複数レイヤで共有するドメインデータの形。ファイル暗号ドキュメント、KV、公開鍵と秘密鍵のラッパ、署名、検証済み型など。

フィールドと不変条件の表現、識別子や定数との整合を担う。`format` のパーサ型など表現に直結する軽い依存は持ってよい。I/O や環境解決、ユースケースのフロー制御は持たない。

この構造体が何を表すかは `model`、それをどう使って処理を進めるかは `feature` / `app`。

## config

設定の型と解決。`types.rs` にモデルを置き、`resolution/` で CLI > env > config > default の優先順を実装する。

解決済み設定値やパス（SSH バイナリ、署名手段など）を決定し、`app` / `feature` がそのまま使えるスナップショットを提供する。`io` と `support` との連携はよいが、`cli` / `app` への依存と暗号処理そのものは持たない。

ユーザーが最終的に何を選んだかの決定は `config`、その選択に基づく暗号操作は `feature`。

## crypto

暗号プリミティブとその型安全なラッパ。AEAD、KDF、KEM、Ed25519 署名と検証など、アルゴリズムとバイト列に閉じた処理。

`model` と `support` に依存してよい。オンワイヤ識別子は呼び出し元が引数として渡すため、`crypto` は `model::wire` に依存しない。ファイルパス解決や workspace ポリシー、ユースケース全体の組み立ては持たない。

1 ステップの暗号演算は `crypto`、複数ステップをドメイン言語でつなぐのは `feature`。

## support

横断的なユーティリティ。recipients 整形、時刻、ファイルシステム操作、バリデーション、base64url、JSON 深さ制限、オンワイヤ識別子、DoS 上限など、単一ドメインに属さない補助を置く。

必要なら `crypto` のデータ型のみに触れてよい。ユースケースやドメイン規則の本体をここへ集約しない。2 つ以上のレイヤで同じコードが欲しくなったときの候補だが、ビジネス上の意味が付いたら `feature` や `model` を検討する。

## クレート横断の要素

- `model::wire` — アルゴリズム識別子、フォーマット版定数、AAD と HPKE 用のコンテキスト文字列など、仕様上のオンワイヤ識別子。SSH ワイヤ用定数は `io::ssh::protocol::constants` を直接参照し、`wire` からは再エクスポートしない
- `support::limits` — DoS 対策の長さ・件数・ネスト上限
- `error` — `Error` と `Result` の単一の定義場所。分類はここに集約し、各層はメッセージと文脈を付与する

## 層間のデータ受け渡し

cli から app へ。

- CLI 引数をそのまま feature へ流さず、request に詰め替える
- 表示用のフラグと業務入力を分離する

app から cli へ。

- CLI が `io` や `feature` の内部型に依存せずに済む DTO を返す
- DTO は表示に必要な事実を返し、表示文言そのものは返さない。`message` のような限定的な表示補助は許容する

app から feature へ。

- workspace や key の解決は app で済ませ、feature には必要最小限の依存情報だけを渡す

app から service へ。

- app で一度だけ解決した workspace、home、member、kid、operation、options を明示的に渡す
- service が環境変数、設定、論理 path から入力を再解決しないよう、選択済み capability を渡す
- review や競合が必要な結果は構造化された値で受け取り、次の状態遷移は app が決める

api から service へ。

- 外部公開する service の型と操作だけを用途別 module から明示的に再公開する
- 変換、fallback、CLI 固有の既定値を追加しない

## 副作用の担当

| 種類 | 主担当 | 補足 |
| --- | --- | --- |
| CLI 表示 | `cli` | `println!`、`eprintln!`、JSON 出力 |
| 対話入力 | `cli` | `dialoguer` を含む |
| ユースケース順序制御 | `app` | 複数 feature と io の束ね込み |
| 標準 API 操作 | `service` | 明示入力と capability に対する検証・信頼評価・transaction |
| ドメイン処理 | `feature` | 暗号、検証、再暗号化、制約判定 |
| 永続化と外部システム | `io` | ファイル、設定、HTTP、SSH |
| ワイヤー・ファイル形式 | `format` | パース、シリアライズ、JCS、トークン |
| 共有データ形状 | `model` | ドキュメント、鍵、署名の型 |
| 設定の解決 | `config` | 優先順に従った値の確定 |
| 暗号プリミティブ | `crypto` | 演算とバイト列レベル API |
| 汎用補助 | `support` | FS、時刻、検証ヘルパ。ルール本体は持たない |

## 運用ルール

- 新規 CLI コマンドは、最初に `service` の操作を作り、必要なら `api` から再公開してから CLI を書く。`app` の入口関数を新設しない
- 既存 CLI に `io::*` / `feature::*` の直接依存を追加しない
- `app` と `cli_api` に新しいユースケースを追加しない
- 標準 API へ移行済みの処理を、互換 wrapper として `app` や `cli_api` に残さない
- app に対話 prompt を新設しない
- app に標準 API の信頼規則や永続化 transaction を実装しない
- service に CLI 固有の入力解決や進行管理を実装しない
- api に実装本体や glob 再公開を追加しない
- feature に CLI 出力を新設しない
- 責務違反を見つけたら、機能追加と同時に最小単位で是正する
