# Kapsaro

[English README](README.md)

> [!NOTE]
> 本プロダクトは SecretEnv から Kapsaro に名称変更しました。

`kapsaro` は、API トークン、DB パスワード、証明書、`.env` の値などの開発用秘密情報を、平文で配り回さずにチームで共有するための offline-first CLI です。

Git と PR レビューを日常的に使っている開発チームに向いています。秘密情報、メンバー変更、削除、鍵更新を暗号化されたリポジトリ上の変更として扱えるため、秘密情報の共有判断を既存のレビュー運用に載せられます。

専用のクラウドサービス、SaaS 型の秘密情報管理基盤、常時稼働するサーバーは不要です。暗号化、復号、検証、共有先の更新はローカルかつオフラインで動作し、Git を共有とレビューのためのレイヤとして利用します。

現在はベータ段階です。正式採用前の試用、設計レビュー、実運用に近い feedback を歓迎しています。

## まず何ができるか

Kapsaro を使うと、次の流れを Git のレビュー運用に載せられます。

- 既存の `.env` を暗号化し、平文をコミットせずに共有する
- 暗号化された秘密情報を復号して、普段の開発コマンドを起動する
- メンバー削除後に、今後の共有メンバーを更新する

```bash
# 既存 .env を暗号化して Git 管理へ移す
kapsaro init --member-handle alice@example.com
kapsaro import .env

# 平文 .env を配らずにアプリを起動する
kapsaro run -- npm start

# メンバー削除後の共有メンバーを更新する
kapsaro member remove old-member@example.com
kapsaro rewrap
```

## 暗号化だけでは残る運用課題

秘密情報を暗号化していても、チームで共有するには次の確認が必要です。

- 新しいメンバーへ、どの秘密情報をいつ共有したか
- 削除したメンバーが、今後の秘密情報を読めない状態になっているか
- 削除したメンバーが過去に見られた値を、必要に応じて更新できるか

Kapsaro は、削除済みメンバーの履歴を残し、`.env` の項目ごとに更新が必要か判断しやすい情報を表示します。秘密情報の更新や共有メンバーの変更はファイル変更として残るため、通常の PR で確認できます。詳しい位置づけは [Product Brief](guides/product_brief_ja.md) を参照してください。

## セキュリティ上の特徴

`kapsaro` は、アクセストークン、API キー、証明書など、本来公開してはいけない秘密情報を、各メンバーが自分の鍵で復号できる形に暗号化します。チーム共通の暗号鍵を配らず、共有相手に含まれるメンバーだけが読める形で扱えます。

主な特徴は次の5点です。

- 秘密情報をリポジトリへ置く前に暗号化し、共有リポジトリでも扱える状態にします
- 公開鍵暗号の仕組みにより、共有相手ごとに復号に必要な情報を安全に共有します
- HPKE、Ed25519 署名、XChaCha20-Poly1305、HKDF-SHA256 など、標準規格に基づく実績ある暗号方式を採用しています
- 専用サーバーや SaaS を必要とせず、暗号化、復号、検証、共有先の更新をオフラインで完結できます
- 復号や暗号ファイルの更新前に、署名と受信者情報を検証します

## インストール

### Homebrew (macOS / Linux)

```bash
brew tap ebisawa/kapsaro
brew install kapsaro
```

### シェルスクリプト

```bash
curl -fsSL https://raw.githubusercontent.com/ebisawa/kapsaro/main/install.sh | sh
```

インストーラは、各リリースアーカイブのビルド来歴を GitHub Artifact Attestations で検証します。検証には GitHub CLI (`gh`) を使い、既定で検証が必須です。`gh` が未インストールの場合、または意図的に検証を省略する場合は、`KAPSARO_INSECURE=1` を設定すると検証なしでインストールします。

### ソースからビルド

```bash
git clone <kapsaro-repo>
cd kapsaro
cargo install --path .
```

## クイックスタート

### 1. ワークスペースの初期化

```bash
cd /path/to/your-git-repo
kapsaro init --member-handle alice@example.com
```

`.kapsaro/` ディレクトリが作成され、鍵ペアの生成と最初のメンバー登録が行われます。
既に workspace がある場合、`init` は何もしません。既存 workspace への参加や鍵の staging には `kapsaro join` を使ってください。

### 2. シークレットの追加

```bash
# 個別に追加
kapsaro set DATABASE_URL "postgres://user:pass@localhost/mydb"
kapsaro set API_KEY "sk-your-api-key"

# 既存の .env ファイルを一括インポート
kapsaro import .env
```

### 3. Git にコミット

```bash
git add .kapsaro/
git commit -m "Initialize kapsaro workspace"
```

### 4. シークレットを使う

```bash
# 値を個別に取得
kapsaro get DATABASE_URL

# すべてのシークレットを環境変数として注入してコマンドを実行
kapsaro run -- ./my-app
```

メンバー追加、CI 設定、リリース準備の前に workspace の状態を確認します。

```bash
kapsaro doctor
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

現在はベータ段階です。ベータ段階では、大きな問題がない限りファイルフォーマットなどの外部仕様を固定し、正式リリースに向けてバグ修正と UI の調整を進めます。

## ライセンス

Apache-2.0. See [LICENSE](LICENSE).
