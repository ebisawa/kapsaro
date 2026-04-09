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

SecretEnv は、秘密情報の共有を「暗号化」と「Git 運用」の両面から整理します。

### 1. `.env` を暗号化したまま Git 管理できる

```bash
# 初期セットアップ
secretenv init --member-id alice@example.com

# .env を一括取り込み
secretenv import .env

# 以後はキー単位で更新
secretenv set DATABASE_URL "postgres://..."
secretenv set API_KEY "sk-..."
```

`.env` の各キーを個別に暗号化して保存するため、値を 1 つ更新したときも差分が必要以上に膨らみません。Git diff で「どの項目を触ったか」を追いやすくなります。

### 2. 証明書やバイナリも同じ仕組みで共有できる

```bash
secretenv encrypt certs/ca.pem
secretenv decrypt ca.pem.encrypted --out certs/ca.pem
```

`.env` だけでなく、証明書、設定ファイル、任意バイナリも同じワークスペースで扱えます。

### 3. 既存の開発フローを崩さない

```bash
secretenv run -- docker compose up
secretenv run -- npm start
secretenv run -- rails server

secretenv get DATABASE_URL
```

`run` は暗号化された `.env` の内容をその場で復号して環境変数として注入し、そのままプロセスを起動します。普段のコマンド実行を変えずに、平文 `.env` を配布しない運用へ移行できます。

`-n` オプションで環境を分けて管理できます:

```bash
secretenv set -n staging DATABASE_URL "postgres://staging/..."
secretenv run -n prod -- ./deploy.sh
```

### 4. メンバー追加と承認を Git のレビューに載せられる

```bash
# 新メンバー
secretenv join --member-id bob@example.com
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

メンバー削除後、`rewrap` により暗号ファイルの共有相手を同期します。さらに必要なら、次の 2 つを使い分けられます。

- `secretenv rewrap --rotate-key`
  暗号化に使う鍵自体を作り直して再暗号化する
- `secretenv rewrap --clear-disclosure-history`
  値更新後に開示履歴をクリアする

### 6. 開示履歴を残し、更新が必要な秘密を見落としにくい

SecretEnv は、共有相手から外したメンバーの履歴を記録します。さらに `.env` 用の暗号ファイルでは、削除時に各項目の状態も追えるため、「どの値を更新すべきか」を見落としにくくなります。

重要なのは、**メンバーを削除しても過去に開示された内容は回収できない** という前提を隠さないことです。SecretEnv はこの事実を可視化し、値更新とローテーションの判断をしやすくします。

### 7. CI/CD で SSH 鍵やエージェントなしに動作する

SecretEnv はポータブルな秘密鍵エクスポートを通じて CI/CD 環境をサポートします:

```bash
# 開発マシンで: CI メンバーの鍵をエクスポート
secretenv key export --private --member-id ci@example.com --out ci-key.txt
```

`SECRETENV_PRIVATE_KEY` と `SECRETENV_KEY_PASSWORD` を CI のシークレット変数に登録すれば、SSH 鍵、SSH エージェント、ローカルキーストアなしで `secretenv run` や `secretenv get` を使えます。

### 8. 鍵の本人性検証でサプライチェーンリスクを低減

```bash
# active メンバーを GitHub と照合し承認
secretenv member verify --approve

# ローカル信頼ストアの管理
secretenv trust list
secretenv trust remove <kid>
```

SecretEnv は現在のメンバーシップと承認履歴を分離しています。`member verify --approve` はメンバーの公開鍵を GitHub アカウントと照合し、結果をローカル信頼ストアに保存します。PKI を必要とせず、公開鍵すり替えに対する保護層を追加します。

## どう安全なのか

SecretEnv は以下の性質を重視しています。

| 保護対象 | 手段 | 効果 |
| --- | --- | --- |
| 機密性 | HPKE + AEAD | 現在の共有相手だけが復号できる |
| 改ざん検知 | Ed25519 署名 | 暗号ファイルやメタデータの改ざんを検知できる |
| 文脈の固定 | ファイルや項目名を暗号化データに結びつける設計 | 別の秘密や別項目との入れ替えを防ぐ |
| 鍵更新時の整合性 | 暗号化データを特定の鍵ステートメントに束縛する設計 | 鍵ローテーションや鍵差し替え時の取り違えを防ぐ |
| 信頼の判断 | `members/active` を認可の基準情報、ローカル信頼ストアを TOFU 承認キャッシュとして分離 | 現在のメンバーシップと承認履歴を分離する |
| 鍵の本人性補強 | SSH 鍵とのひも付けと GitHub 照合 | 公開鍵のすり替えリスクを下げる |

コア機能は offline-first です。暗号化、復号、署名検証、`rewrap` はローカル中心で完結し、GitHub 連携は公開鍵とアカウントの照合を追加したい場合の補助機能として使えます。

## 典型的な導入フロー

### 必要なもの

- SSH Ed25519 鍵
- Git リポジトリ
- GitHub アカウント
  任意。公開鍵とアカウントの照合を行う場合に利用

### インストール

```bash
brew tap ebisawa/secretenv
brew install secretenv
```

### 既存プロジェクトへの導入

Git リポジトリのディレクトリで以下を実行します。secretenv は Git リポジトリ内で workspace を自動検出します。

```bash
# Git リポジトリのディレクトリに移動
cd /path/to/your-repo

# 1. workspace を作成
secretenv init --member-id alice@example.com

# 2. 既存 .env を取り込む
secretenv import .env
```

以後は `.secretenv/` を Git 管理し、秘密情報は `set` / `get` / `run` / `encrypt` / `decrypt` / `rewrap` で扱います。

## SecretEnv の立ち位置

SecretEnv は、専用の秘密情報管理サービスのように中央集権的なアクセス制御を提供するツールではありません。提供するのは、チームで共有する秘密情報を Git と相性よく安全に扱うための、軽量で実務的な暗号共有モデルです。

向いているチーム:

- Git と PR レビューを中心に開発している
- `.env` や証明書を少人数で安全に共有したい
- SaaS や常時接続の secret 基盤を前提にしたくない
- オフライン、ローカル開発、CI/CD で同じ運用をしたい

向いていない用途:

- 細粒度のアクセス制御を中央で強制したい
- 一度開示した秘密を後から回収できると期待している
- 実行時 secret injection をクラウド基盤全体で統制したい

## 関連ドキュメント

- [ユーザーガイド](user_guide_ja.md) — インストール、日常利用、CI/CD セットアップ
- [セキュリティ設計](security_design_ja.md) — 脅威モデル、暗号プロトコル、信頼アーキテクチャ

---

**SecretEnv** — Slack で `.env` を送るのはもうやめましょう。暗号化して Git で共有すれば、チームの既存のレビュー運用がそのままセキュリティゲートになります。
