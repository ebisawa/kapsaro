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

## Install

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

## Getting Started

### 1. ワークスペースの初期化

```bash
cd /path/to/your-git-repo
secretenv init --member-id alice@example.com
```

`.secretenv/` ディレクトリが作成され、鍵ペアの生成と最初のメンバー登録が行われます。

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

詳しい導入・運用手順は [User Guide](guides/user_guide_ja.md) を参照してください。

## Read More

まず全体像を知りたい場合:

- [Product Brief (English)](guides/product_brief_en.md)
- [Product Brief (Japanese)](guides/product_brief_ja.md)

実際の導入や運用手順を知りたい場合:

- [User Guide (English)](guides/user_guide_en.md)
- [User Guide (Japanese)](guides/user_guide_ja.md)

暗号設計やセキュリティモデルを詳しく確認したい場合:

- [Security Design (English)](guides/security_design_en.md)
- [Security Design (Japanese)](guides/security_design_ja.md)

Local Trust Store について知りたい場合:

- [Local Trust Store Update (English)](guides/trust_store_update_en.md)
- [Local Trust Store Update (Japanese)](guides/trust_store_update_ja.md)

## Status

現在はアルファ段階です。仕様策定と実装を並行して進めています。

## License

Apache-2.0. See [LICENSE](LICENSE).