# SecretEnv: `.env` を暗号化して Git で共有する

あなたのチームでは、`.env`、証明書、秘密鍵ファイルをどう共有していますか。

SecretEnv は、秘密情報を暗号化したまま Git リポジトリで共有するための offline-first CLI です。`.env` のようなキーと値の組を扱うファイルにも、証明書や設定ファイルのような任意ファイルにも対応し、メンバー管理と鍵更新を Git のレビュー運用に載せられます。

## よくある課題

### Slack や DM で `.env` を送っている

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
- Git の PR レビューに秘密情報の変更フローを乗せにくい

### 既存の暗号化ツールでは運用が噛み合わない

- GPG や PGP の鍵配布と更新が煩雑
- `.env` の差分更新に弱い
- メンバー削除後の「過去に誰へ開示されていたか」を追いにくい

## SecretEnv が提供するもの

SecretEnv の目的は、秘密情報を平文で配り回さず、Git のレビューと履歴の中で扱えるようにすることです。暗号方式の詳細を理解していなくても、日常運用では次のことができます。

### 1. `.env` を暗号化したまま Git 管理できる

```bash
# 初期セットアップ
secretenv init --member-handle alice@example.com

# .env を一括取り込み
secretenv import .env

# 以後はキー単位で更新
secretenv set DATABASE_URL "postgres://..."
secretenv set API_KEY "sk-..."
```

`.env` の各キーを個別の暗号化エントリとして保存します。値を1つ更新したときも差分が必要以上に膨らまず、Git diff で「どの項目を触ったか」を追いやすくなります。

### 2. 証明書やバイナリも同じ仕組みで共有できる

```bash
secretenv encrypt certs/ca.pem
secretenv decrypt ca.pem.encrypted --out certs/ca.pem
```

SecretEnv は `.env` 専用ではありません。証明書、設定ファイル、任意バイナリも同じ暗号化・署名パイプラインを通り、同じワークスペースで一元的に扱えます。

### 3. 平文 `.env` を配らずにコマンドを起動できる

```bash
secretenv run -- docker compose up
secretenv run -- npm start
secretenv run -- rails server

secretenv get DATABASE_URL
```

`run` は暗号化された `.env` の内容をその場で復号し、環境変数として注入してプロセスを起動します。普段のコマンド実行を変えずに、平文 `.env` を配布しない運用へ移行できます。

子プロセスは既定で親プロセスの環境変数を継承します。シェルで設定した `PATH` や `RUST_LOG` などの値はそのままアプリへ届きます。ただし `SECRETENV_` で始まる環境変数だけは起動前に取り除かれます。

`-n` オプションで環境を分けて管理できます。

```bash
secretenv set -n staging DATABASE_URL "postgres://staging/..."
secretenv run -n prod -- ./deploy.sh
```

### 4. メンバー追加と承認を Git のレビューに載せられる

```bash
# 新メンバー
secretenv join --member-handle bob@example.com
# -> 承認待ちの参加申請を作る

# 既存メンバー
secretenv rewrap
# -> 参加申請を承認し、全ての暗号ファイルの共有相手を同期する
```

新メンバーはまず「承認待ち」として登録され、既存メンバーが `rewrap` を実行して承認・反映します。メンバー変更がリポジトリ上の差分になるため、誰がいつ参加したかを PR レビューで追えます。

### 5. 退職者対応と鍵更新を機械的に実行できる

```bash
secretenv member remove alice@example.com
secretenv rewrap
```

メンバー削除後、`rewrap` により暗号ファイルの共有相手を同期します。さらに目的に応じて、次の3つのフラグで動作を絞り込めます。

- `secretenv rewrap --rotate-key` — 暗号化に使う鍵自体を作り直して再暗号化する
- `secretenv rewrap --clear-disclosure-history` — 値更新後に開示履歴をクリアする
- `secretenv rewrap --target <path>` — 一部のファイルだけを再暗号化したいときに、対象アーティファクトを限定する

### 6. 開示履歴を残し、更新が必要な秘密を見落としにくい

SecretEnv は、共有相手から外したメンバーの履歴を記録します。さらに `.env` 用の暗号ファイルでは、削除時に各項目の状態も追えるため、「どの値を更新すべきか」を見落としにくくなります。

重要なのは、メンバーを削除しても過去に開示された内容は回収できないという前提を隠さないことです。SecretEnv はこの残余リスクを可視化し、値更新とローテーションの判断をしやすくします。

### 7. CI/CD で SSH 鍵やエージェントなしに動作する

SecretEnv はポータブルな秘密鍵エクスポートを通じて CI/CD 環境をサポートします。

```bash
# 開発マシンで: CI メンバーの鍵をエクスポート
secretenv key export --private --member-handle ci@example.com --out ci-key.txt
```

`SECRETENV_PRIVATE_KEY` と `SECRETENV_KEY_PASSWORD` を CI のシークレット変数に登録すれば、SSH 鍵、SSH エージェント、ローカルキーストアなしで `secretenv run` や `secretenv get` を使えます。CI メンバーも現メンバー一覧の1エントリにすぎないため、`member remove` + `rewrap` の同じフローで権限剥奪できます。

### 8. メンバーの鍵が本人のものか確認できる

```bash
# active メンバーを GitHub と照合し承認
secretenv member verify --approve

# ローカル信頼ストアの管理
secretenv trust keys list
secretenv trust keys remove <kid>
secretenv trust recipients list
```

SecretEnv は「この暗号ファイルがある鍵で作られたこと」を確認できますが、その鍵が実際に名乗っているメンバーのものかは別途確認が必要です。`member verify --approve` はメンバーの公開鍵を GitHub アカウントと照合し、承認した鍵の記録をローカル信頼ストアに保存します。鍵のすり替えに気づきやすくするための追加確認として使えます。

## 安心材料と前提条件

SecretEnv は「Git に置くなら平文を置かない」「変更はレビューできる形にする」「外したメンバーには今後の共有を止める」という運用を支えます。一方で、端末、秘密鍵、PR レビュー、CI の secret 管理まで含めて安全に扱うことが前提です。

| 気になること | SecretEnv がすること | チーム側で見ること |
| --- | --- | --- |
| リポジトリ、クローン、バックアップから `.env` の中身が読まれる | 秘密情報を暗号化して保存し、共有相手だけが復号できる形にする | 復号できるメンバーを適切に管理する |
| 暗号ファイルやメタデータが書き換えられる | 復号前に署名と形式を検証し、壊れた内容や想定外の内容なら止める | PR レビューや保護ブランチで不審な変更を止める |
| 新しいメンバーの鍵が本人のものか不安 | `member verify --approve` で GitHub アカウントとの照合結果を確認し、承認した鍵をローカル信頼ストアに保存する | 初回承認時は本人確認を慎重に行う |
| 退職者や異動者が今後の秘密を読めてしまう | `member remove` と `rewrap` で今後の共有相手から外す | すでに開示された値は必要に応じて外部サービス側で更新する |
| CI で SSH 鍵やエージェントを用意しにくい | エクスポートした SecretEnv 秘密鍵を CI の secret 変数から使える | 信頼できる workflow、runner、ref に限定して使う |

コア機能は offline-first です。暗号化、復号、検証、`rewrap` はローカル中心で完結し、GitHub 連携は公開鍵とアカウントの照合を追加したい場合の補助機能として使えます。暗号方式や脅威モデルの詳細は Security Design ドキュメントで説明しています。

## 典型的な導入フロー

### 必要なもの

- SSH Ed25519 鍵
- Git リポジトリ
- GitHub アカウント
  任意。公開鍵とアカウントの照合を行う場合に利用。
- PR レビューや保護ブランチなど、メンバー変更を確認するための Git 運用
- CI/CD で使う場合は、CI の secret 変数を安全に管理できる環境

### インストール

```bash
brew tap ebisawa/secretenv
brew install secretenv
```

### 既存プロジェクトへの導入

Git リポジトリのディレクトリで以下を実行します。SecretEnv は Git リポジトリ内で workspace を自動検出します。

```bash
# Git リポジトリのディレクトリに移動
cd /path/to/your-repo

# 1. workspace を作成
secretenv init --member-handle alice@example.com

# 2. 既存 .env を取り込む
secretenv import .env
```

以後は `.secretenv/` を Git 管理し、秘密情報は `set` / `get` / `run` / `encrypt` / `decrypt` / `rewrap` で扱います。

## SecretEnv の立ち位置

SecretEnv は中央集権的なアクセス制御を提供するツールではありません。提供するのは、チームで共有する秘密情報を Git と相性よく安全に扱うための、軽量で実務的な暗号共有モデルです。

期待してよいこと:

- 平文 `.env` や証明書をチャットで配る運用を減らす
- 秘密情報の追加、更新、メンバー変更を Git の差分としてレビューする
- メンバー削除後に、今後の暗号ファイルの共有相手を同期する
- 過去に誰へ開示されていたかを見える形にする

向いているチーム:

- Git と PR レビューを中心に開発している
- `.env` や証明書を少人数で安全に共有したい
- SaaS や常時接続の secret 基盤を前提にしたくない
- オフライン、ローカル開発、CI/CD で同じ運用をしたい

向いていない用途:

- 細粒度のアクセス制御を中央で強制したい
- 一度開示した秘密を後から回収できると期待している
- 正当な受信者が復号後に平文を持ち出すことを防ぎたい
- 実行時 secret injection をクラウド基盤全体で統制したい

## 関連ドキュメント

- [ユーザーガイド](user_guide_ja.md) — インストール、日常利用、CI/CD セットアップ
- [セキュリティ設計](security_design_ja.md) — 脅威モデル、暗号プロトコル、信頼アーキテクチャ
