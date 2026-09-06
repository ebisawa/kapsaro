# Kapsaro

[English README](README.md)

> [!NOTE]
> 本プロダクトは SecretEnv から Kapsaro に名称変更しました。

`kapsaro` は、API トークン、データベースパスワード、証明書、`.env` の値といった開発用シークレットを、平文で共有することなく安全にチーム内で受け渡すためのオフライン優先（offline-first）CLI ツールです。

日常的な開発フローとして Git と Pull Request（PR）レビューを活用しているチームに適しています。シークレットの値だけでなく、メンバーの追加・削除や鍵のローテーションもすべて暗号化されたリポジトリ上の変更として扱えるため、シークレットの共有判断を普段のコードレビュー運用とまったく同じプロセスに統合できます。

専用のクラウドサービスや SaaS 型のシークレット管理ツール、常時稼働するサーバーは一切不要です。暗号化、復号、署名検証、受信者情報の更新はすべてローカルかつオフラインで動作し、Git を共有とレビューのための基盤（トランスポート層）としてそのまま利用します。

本プロジェクトは現在ベータ段階です。本番導入前の試用や設計レビュー、実際のチーム開発シナリオに基づくフィードバックを歓迎しています。

## まず何ができるか

Kapsaro を使うと、次のようなワークフローを Git のレビュー運用にそのまま統合できます。

- 既存の `.env` を暗号化し、平文をコミットすることなく安全に共有する
- 暗号化されたシークレットを実行時に復号し、普段の開発コマンドをそのまま実行する
- メンバー離脱時に、今後の共有対象（受信者）を更新して同期する

```bash
# 既存の .env を暗号化して Git 管理に移行する
kapsaro init --member-handle alice@example.com
kapsaro import .env

# 平文の .env を配布することなくアプリを起動する
kapsaro run -- npm start

# 離脱したメンバーを今後の共有対象から除外する
kapsaro member remove old-member@example.com
kapsaro rewrap
```

`rewrap` の既定の対象はワークスペース内の `secrets/` ディレクトリです。別の場所にある暗号化ファイルは `--target` で指定します。メンバー変更の手順は、メンバー情報と暗号化ファイルの両方の変更内容を確認して共有（コミット）し、共有後のコミットから正しく復号できることを確認するまでを含みます。詳細は[メンバー変更の完了確認](guides/user_guide_ja.md#membership-completion)を参照してください。

## 暗号化だけでは残る運用課題

シークレットを暗号化するだけでは、チーム運用において次のような判断や確認の課題が残ります。

- 新しいメンバーに、どのシークレットをいつ共有したか
- 離脱したメンバーが、今後のシークレットを閲覧できない状態になっているか
- 離脱したメンバーが過去に閲覧できた値のうち、どれを更新（ローテーション）すべきか

Kapsaro は削除済みメンバーの履歴を保持し、`.env` の項目ごとに更新が必要かどうかを判断するためのシグナルを表示します。シークレットの更新や共有メンバーの変更はすべてリポジトリ内のファイル変更として記録されるため、通常の PR 上で確認できます。プロダクトの位置づけについての詳細は [Product Brief](guides/product_brief_ja.md) を参照してください。

## セキュリティ上の特徴

`kapsaro` は、アクセストークン、API キー、証明書などの機密データを、各メンバーが各自の鍵で復号できる形に暗号化します。チーム共通の暗号鍵を配布する必要はなく、明示的に受信者として指定されたメンバーだけが内容を復号できます。

設計上の 5 つの柱:

- **リポジトリ保存前の事前暗号化**: シークレットをリポジトリへ保存する前に暗号化するため、チーム共有の Git リポジトリでも安全に管理できます。
- **受信者ごとの公開鍵暗号化**: 公開鍵暗号の仕組みにより、復号に必要な鍵情報を共有相手ごとに個別に暗号化して安全に配分します。
- **標準規格に準拠した実績ある暗号方式**: HPKE (RFC 9180)、Ed25519 署名、XChaCha20-Poly1305、HKDF-SHA256 など、実績のある最新の暗号標準を採用しています。
- **サーバー不要のオフライン完結**: 専用サーバーや外部 SaaS を必要とせず、暗号化、復号、検証、受信者更新のすべてがオフラインで完結します。
- **厳格な署名・受信者検証**: 復号や暗号化ファイルの更新を行う前に、電子署名と受信者メタデータの正当性を必ず検証します。

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

インストーラは、GitHub CLI (`gh`) を通じて GitHub Artifact Attestations を利用し、各リリースアーカイブのビルド来歴を検証します。この検証は既定で必須となっています。`gh` が未インストールの場合や、意図的に検証を省略する場合は、`KAPSARO_INSECURE=1` を設定すると検証なしでインストールできます。

### ソースからビルド

```bash
git clone https://github.com/ebisawa/kapsaro.git
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
すでにワークスペースが存在する場合、`init` は何もしません。既存のワークスペースへの参加や鍵の登録（staging）には `kapsaro join` を使用してください。

### 2. シークレットの追加

```bash
# 個別に追加
kapsaro set DATABASE_URL "postgres://user:pass@localhost/mydb"
kapsaro set API_KEY "sk-your-api-key"

# または既存の .env ファイルを一括インポート
kapsaro import .env
```

### 3. Git にコミット

```bash
git add .kapsaro/
git commit -m "Initialize kapsaro workspace"
```

### 4. シークレットの利用

```bash
# 値を個別に取得
kapsaro get DATABASE_URL

# すべてのシークレットを環境変数として注入してコマンドを実行
kapsaro run -- ./my-app
```

メンバー追加、CI 設定、リリース準備の前には、ワークスペースの状態を診断コマンドで確認できます。

```bash
kapsaro doctor
```

詳しい導入・運用手順については [User Guide](guides/user_guide_ja.md) を参照してください。

チーム運用における [Git 競合の解消手順](guides/user_guide_ja.md#git-conflict-resolution) や、[バージョン固定と来歴検証を伴う CI セットアップ](guides/user_guide_ja.md#ci-setup) もあわせて参照してください。なお、ストア名は同一ワークスペース内で値を整理するための名前です。CI を含め共有先のグループを分ける場合は、ワークスペース自体を分けて運用します。

## 関連ドキュメント

プロダクトの全体像を知りたい場合:

- [Product Brief (English)](guides/product_brief_en.md)
- [Product Brief (Japanese)](guides/product_brief_ja.md)

実際の導入や運用手順を知りたい場合:

- [User Guide (English)](guides/user_guide_en.md)
- [User Guide (Japanese)](guides/user_guide_ja.md)
- [Windows / WSL2 補足ガイド (English)](guides/wsl_user_guide_en.md)
- [Windows / WSL2 補足ガイド (Japanese)](guides/wsl_user_guide_ja.md)

暗号設計やセキュリティモデルを詳しく確認したい場合:

- [Security Design (English)](guides/security_design_en.md)
- [Security Design (Japanese)](guides/security_design_ja.md)

## ステータス

本プロジェクトは現在ベータ段階です。ベータ段階では、重大な問題がない限りファイルフォーマットなどの外部仕様を固定とし、正式リリースに向けてバグ修正と UI の調整を進めます。

## ライセンス

Apache-2.0. See [LICENSE](LICENSE).
