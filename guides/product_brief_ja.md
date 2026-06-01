# Kapsaro: `.env` を暗号化して Git で共有する

あなたのチームでは、`.env`、証明書、秘密鍵ファイルをどう共有していますか。

Kapsaro は、Git リポジトリに平文を保存せず、暗号化した秘密情報をチームで共有できる offline-first CLI です。`.env` のようなキーと値の組を扱うファイルにも、証明書や設定ファイルのような任意ファイルにも対応し、メンバー管理と鍵更新を Git のレビュー運用に載せられます。

## 導入判断の要点

Kapsaro は、Git と PR レビューを中心に開発している小規模から中規模チームが、平文の秘密情報の受け渡しを減らすための軽量な暗号共有モデルです。

向いているチーム:

- Git と PR レビューを中心に開発している
- `.env` や証明書を少人数で安全に共有したい
- SaaS や常時接続の秘密情報管理基盤を前提にしたくない
- オフライン、ローカル開発、CI/CD で同じ運用をしたい

期待してよいこと:

- 平文 `.env` や証明書をチャットで配る運用を減らす
- 秘密情報の追加、更新、メンバー変更を Git の差分としてレビューする
- HPKE など標準規格に基づく暗号方式で、共有相手ごとに暗号化する
- メンバー削除後に、今後の暗号ファイルの共有相手を同期する
- 過去に誰へ開示されていたかを見える形にする

向いていない用途:

- 細粒度のアクセス制御を中央で強制したい
- 一度開示した秘密を後から回収できると期待している
- 正当な受信者が復号後に平文を持ち出すことを防ぎたい
- 実行時の秘密情報注入をクラウド基盤全体で統制したい

## よくある課題

### チャットや手作業で `.env` を配っている

- 平文がメッセージ履歴やローカル端末に残る
- 誰が最新版を持っているか分からない
- 退職者や異動者が古い値を保持し続ける
- いつ誰が何を変えたかを追いにくい

### `.env.example` + 手作業で値を配る

- オンボーディングのたびに秘密情報の受け渡し作業が発生する
- 環境差分が増え、staging や CI だけ壊れる
- キー追加や更新の漏れが起きやすい

### 専用の秘密情報管理サービスは重い

- サーバー運用や権限制御の設計コストが高い
- ネットワーク前提の運用になりやすい
- 小中規模チームには導入コストが見合わないことがある
- Git の PR レビューに秘密情報の変更フローを載せにくい

### 暗号化できてもチーム運用が残る

- 鍵や受信者の変更を誰がレビューしたかを追いにくい
- 削除済みメンバーが読めた可能性のある値を判断しにくい
- CI 用アクセスを通常メンバーと同じ運用で扱いにくい

## Kapsaro が提供するもの

Kapsaro の目的は、秘密情報を平文で配り回さず、Git のレビューと履歴の中で扱えるようにすることです。暗号方式の詳細を理解していなくても、日常運用では次のことができます。

### 1. 平文を置かずに `.env` を Git 管理できる

```bash
# 初期セットアップ
kapsaro init --member-handle alice@example.com

# .env を一括取り込み
kapsaro import .env

# 以後はキー単位で更新
kapsaro set DATABASE_URL "postgres://..."
kapsaro set API_KEY "sk-..."
```

`.env` の各キーを個別の暗号化エントリとして保存します。値を1つ更新したときも差分が必要以上に膨らまず、Git diff で「どの項目を触ったか」を追いやすくなります。

### 2. 証明書やバイナリも同じ仕組みで共有できる

```bash
kapsaro encrypt certs/ca.pem
kapsaro decrypt ca.pem.encrypted --out certs/ca.pem
```

Kapsaro は `.env` 専用ではありません。証明書、設定ファイル、任意バイナリも同じ暗号化・署名パイプラインを通り、同じワークスペースで一元的に扱えます。

### 3. 平文 `.env` を配らずにコマンドを起動できる

```bash
kapsaro run -- docker compose up
kapsaro run -- npm start
kapsaro run -- rails server

kapsaro get DATABASE_URL
```

`run` は暗号化された `.env` の内容をその場で復号し、環境変数として注入してプロセスを起動します。普段のコマンド実行を変えずに、平文 `.env` を配布しない運用へ移行できます。

子プロセスは既定で親プロセスの環境変数を継承します。シェルで設定した `PATH` や `RUST_LOG` などの値はそのままアプリへ届きます。ただし `KAPSARO_` で始まる環境変数だけは起動前に取り除かれます。

`-n` オプションで環境を分けて管理できます。

```bash
kapsaro set -n staging DATABASE_URL "postgres://staging/..."
kapsaro run -n prod -- ./deploy.sh
```

### 4. メンバー追加と承認を Git のレビューに載せられる

```bash
# 新メンバー
kapsaro join --member-handle bob@example.com
# -> 承認待ちの参加申請を作る

# 既存メンバー
kapsaro rewrap
# -> 参加申請を承認し、全ての暗号ファイルの共有相手を同期する
```

新メンバーはまず「承認待ち」として登録され、既存メンバーが `rewrap` を実行して承認・反映します。メンバー変更がリポジトリ上の差分になるため、誰がいつ参加したかを PR レビューで追えます。

### 5. 退職者対応と鍵更新を機械的に実行できる

```bash
kapsaro member remove old-member@example.com
kapsaro rewrap
```

メンバー削除後、`rewrap` により暗号ファイルの共有相手を同期します。さらに目的に応じて、次の3つのフラグで動作を絞り込めます。

- `kapsaro rewrap --rotate-key` — 暗号化に使う鍵自体を作り直して再暗号化する
- `kapsaro rewrap --clear-disclosure-history` — 値更新後に開示履歴をクリアする
- `kapsaro rewrap --target <path>` — 一部のファイルだけを再暗号化したいときに、対象アーティファクトを限定する

### 6. 開示履歴を残し、更新が必要な秘密を見落としにくい

Kapsaro は、共有相手から外したメンバーの履歴を記録します。さらに `.env` 用の暗号ファイルでは、削除時に各項目の状態も追えるため、「どの値を更新すべきか」を見落としにくくなります。

重要なのは、メンバーを削除しても過去に開示された内容は回収できないという前提を隠さないことです。Kapsaro はこの残余リスクを可視化し、値更新とローテーションの判断をしやすくします。

### 7. CI/CD で SSH 鍵やエージェントなしに動作する

Kapsaro はポータブルな秘密鍵エクスポートを通じて CI/CD 環境をサポートします。

```bash
# 開発マシンで: CI メンバーの鍵をエクスポート
kapsaro key export --private --member-handle ci@example.com --out ci-key.txt
```

`KAPSARO_PRIVATE_KEY` と `KAPSARO_KEY_PASSWORD` を CI のシークレット変数に登録すれば、SSH 鍵、SSH エージェント、ローカルキーストアなしで `kapsaro run` や `kapsaro get` を使えます。CI メンバーも現メンバー一覧の1エントリにすぎないため、`member remove` + `rewrap` の同じフローで権限剥奪できます。

### 8. メンバーの鍵が本人のものか確認できる

```bash
# active メンバーを GitHub と照合し承認
kapsaro member verify --approve

# ローカル信頼ストアの管理
kapsaro trust keys list
kapsaro trust keys remove <kid>
kapsaro trust recipients list
```

Kapsaro は「この暗号ファイルがある鍵で作られたこと」を確認できますが、その鍵が実際に名乗っているメンバーのものかは別途確認が必要です。`member verify --approve` はメンバーの公開鍵を GitHub アカウントと照合し、承認した鍵の記録をローカル信頼ストアに保存します。鍵のすり替えに気づきやすくするための追加確認として使えます。

## 典型的な導入フロー

### 必要なもの

- SSH Ed25519 鍵
- Git リポジトリ
- GitHub アカウント
  任意。公開鍵とアカウントの照合を行う場合に利用。
- PR レビューや保護ブランチなど、メンバー変更を確認するための Git 運用
- CI/CD で使う場合は、CI の秘密情報用の変数を安全に管理できる環境

### 既存プロジェクトへの導入

Git リポジトリのディレクトリで以下を実行します。Kapsaro は Git リポジトリ内で workspace を自動検出します。

```bash
# インストール
brew tap ebisawa/kapsaro
brew install kapsaro

# workspace を作成
kapsaro init --member-handle alice@example.com

# 既存 .env を取り込む
kapsaro import .env

# 日常利用
kapsaro set API_KEY "sk-..."
kapsaro get API_KEY
kapsaro run -- npm start

# メンバー変更
kapsaro join --member-handle bob@example.com
kapsaro rewrap
kapsaro member remove old-member@example.com
kapsaro rewrap
```

以後は `.kapsaro/` を Git 管理し、秘密情報は `set` / `get` / `run` / `encrypt` / `decrypt` / `rewrap` で扱います。

## 他の選択肢との見方

Kapsaro は中央集権的なアクセス制御を提供するツールではありません。提供するのは、チームで共有する秘密情報を Git と相性よく安全に扱うための、軽量で実務的な暗号共有モデルです。

比較検討では、どのツールが優れているかではなく、どの運用に合うかを見るのが重要です。

| 欲しいもの | 向きやすい選択肢 |
| --- | --- |
| `.env` の暗号化と実行時注入を手早く始めたい | Kapsaro、または `.env` 暗号化と実行時注入に特化したツール |
| 既存の鍵管理や外部鍵管理とファイル暗号化を組み合わせたい | ファイル暗号化と外部鍵管理に特化したツール |
| 全体ポリシー管理、SSO、SCIM、細粒度 ACL が必要 | 中央集権型の秘密情報管理基盤 |
| Git と PR レビューに秘密情報の変更やメンバー変更を載せたい | Kapsaro |
| 小中規模チームで `.env`、証明書、CI 読み取り、rewrap、開示履歴を同じ流れにしたい | Kapsaro |

Kapsaro を検討する価値が高いのは、Git レビューを中心にした開発運用を保ちながら、平文の秘密情報の受け渡しを減らしたい場合です。全体ポリシー管理や組織全体の実行時の秘密情報注入を統制したい場合は、Kapsaro だけで要件を満たそうとせず、中央集権型の秘密情報管理基盤を検討してください。

## 関連ドキュメント

- [ユーザーガイド](user_guide_ja.md) — インストール、日常利用、CI/CD セットアップ
- [セキュリティ設計](security_design_ja.md) — 脅威モデル、暗号プロトコル、信頼アーキテクチャ
