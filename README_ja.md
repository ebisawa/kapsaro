# secretenv

[English README](README.md)

`.env` を Slack や DM で送るのをやめたい。  
でも、専用サーバーや常時接続の秘密情報管理サービスを前提にしたくない。

`secretenv` は、そうしたチームのための offline-first な暗号ファイル共有 CLI です。  
`.env`、証明書、鍵ファイルなどを暗号化したまま Git リポジトリで扱い、メンバー追加や削除、鍵更新も Git のレビュー運用に載せられます。

向いているケース:

- チームで `.env` を安全に共有したい
- 証明書や設定ファイルも同じ仕組みで管理したい
- ローカル開発でも CI でも同じ secret 運用をしたい
- SaaS や専用基盤に依存せずに運用したい

このプロジェクトの狙いは、「秘密を平文で配らない」だけではありません。  
誰に共有されているか、改ざんされていないか、鍵更新やメンバー変更をどう反映するかまで、Git と相性のよい形で整理することを目指しています。

## セキュリティ上の特徴

`secretenv` は、アクセストークン、API キー、証明書など、本来公開してはいけない秘密情報を暗号化します。暗号化された結果を Git に置くことで、多くのメンバーが共有するリポジトリでも、平文の `.env` や鍵ファイルをコミットせずに秘密情報を扱えます。

設計の中心は次の4点です。

- 秘密情報をリポジトリへ置く前に暗号化し、共有リポジトリでも扱える状態にします
- 公開鍵暗号を使い、各メンバーが自分の公開鍵・秘密鍵を持つことで、チーム共通の暗号鍵を配布・保護する運用を避けます
- 専用サーバーや SaaS を必要とせず、暗号化、復号、検証、共有先の更新をオフラインで完結できます
- 秘密情報の追加・変更と共有先メンバーの追加・変更を Git 上のファイル更新として扱い、既存の PR レビューに載せられます

## インストール

### Homebrew (macOS / Linux)

```bash
brew tap ebisawa/secretenv
brew install secretenv
```

### シェルスクリプト

```bash
curl -fsSL https://raw.githubusercontent.com/ebisawa/secretenv/main/install.sh | sh
```

### ソースからビルド

```bash
git clone <secretenv-repo>
cd secretenv
cargo install --path .
```

## クイックスタート

### 1. ワークスペースの初期化

```bash
cd /path/to/your-git-repo
secretenv init --member-handle alice@example.com
```

`.secretenv/` ディレクトリが作成され、鍵ペアの生成と最初のメンバー登録が行われます。
既に workspace がある場合、`init` は何もしません。既存 workspace への参加や鍵の staging には `secretenv join` を使ってください。

### 2. シークレットの追加

```bash
# 個別に追加
secretenv set DATABASE_URL "postgres://user:pass@localhost/mydb"
secretenv set API_KEY "sk-your-api-key"

# 既存の .env ファイルを一括インポート
secretenv import .env
```

### 3. Git にコミット

```bash
git add .secretenv/
git commit -m "Initialize secretenv workspace"
```

### 4. シークレットを使う

```bash
# 値を個別に取得
secretenv get DATABASE_URL

# すべてのシークレットを環境変数として注入してコマンドを実行
secretenv run -- ./my-app
```

メンバー追加、CI 設定、リリース準備の前に workspace の状態を確認します。

```bash
secretenv doctor
```

詳しい導入・運用手順は [User Guide](guides/user_guide_ja.md) を参照してください。

## 関連ドキュメント

まず全体像を知りたい場合:

- [Product Brief (English)](guides/product_brief_en.md)
- [Product Brief (Japanese)](guides/product_brief_ja.md)

実際の導入や運用手順を知りたい場合:

- [User Guide (English)](guides/user_guide_en.md)
- [User Guide (Japanese)](guides/user_guide_ja.md)

暗号設計やセキュリティモデルを詳しく確認したい場合:

- [Security Design (English)](guides/security_design_en.md)
- [Security Design (Japanese)](guides/security_design_ja.md)

## ステータス

現在はアルファ段階です。仕様策定と実装を並行して進めています。

## ライセンス

Apache-2.0. See [LICENSE](LICENSE).
