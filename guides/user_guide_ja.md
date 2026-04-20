# secretenv ユーザーガイド

## 目次

1. [はじめに](#1-はじめに)
2. [使い始める前に知っておくこと](#2-使い始める前に知っておくこと)
3. [よく使う用語](#3-よく使う用語)
4. [安全に使うための前提](#4-安全に使うための前提)
5. [インストール](#5-インストール)
6. [クイックスタート（チームリーダー向け）](#6-クイックスタートチームリーダー向け)
7. [新メンバーとして参加する](#7-新メンバーとして参加する)
8. [日常的な使い方（KV ストア）](#8-日常的な使い方kv-ストア)
9. [ファイルの暗号化・復号](#9-ファイルの暗号化復号)
10. [メンバー管理](#10-メンバー管理)
11. [鍵の管理とローテーション](#11-鍵の管理とローテーション)
12. [CI/CD 連携](#12-cicd-連携)
13. [よくある質問（FAQ）](#13-よくある質問faq)
14. [コマンドリファレンス（早見表）](#14-コマンドリファレンス早見表)
15. [設定リファレンス](#15-設定リファレンス)

---

## 1. はじめに

### secretenv とは

チーム開発では、データベースのパスワード、API キー、証明書などの「秘密情報（secrets）」を複数のメンバーで共有する必要があります。しかし、その共有方法は往々にして問題をはらんでいます。

- Slack や Teams のチャットに平文でパスワードを貼り付けている
- `.env.example` に実際の値をコメントで残している
- 退職したメンバーが以前共有されたパスワードを知ったまま

secretenv はこうした問題を解決するための CLI ツールです。**暗号化された秘密情報を Git リポジトリで管理**することで、チームは安全かつ追跡可能な方法で secrets を共有できます。

### 何を解決するか

- `.env` や証明書ファイルを暗号化してリポジトリに格納し、チームで安全に共有できる
- メンバーの追加・削除に合わせて、暗号ファイルへのアクセス権を更新できる
- 誰がいつアクセスできたかの履歴を暗号ファイル自身が記録する
- サーバー不要・ネットワーク不要でオフラインでも動作する

### 何を解決しないか

secretenv は万能ではありません。復号後の情報の扱い、過去に見られた値の回収、端末や鍵そのものの漏洩対策までは自動では解決しません。これらの前提は [4章](#4-安全に使うための前提) でまとめて確認してください。

---

## 2. 使い始める前に知っておくこと

### まず全体像

secretenv での secret 共有は、次の流れで考えると理解しやすくなります。

1. チームは Git リポジトリ内の workspace で、暗号化された secret とメンバー情報を共有する
2. 各ユーザーが、自分専用の公開鍵と秘密鍵を持つ
3. 新しいメンバーや新しい鍵はレビューされ、承認後に secret の受信者として有効になる

以降では、この順に必要な考え方を説明します。

### Workspace を Git で共有する

workspace は、Git リポジトリ内の `.secretenv/` ディレクトリです。チームはここで secret とメンバー情報を共有します。

```
.secretenv/
├── members/
│   ├── active/
│   └── incoming/
├── secrets/
└── config.toml
```

- `members/active/`: 利用中のメンバーの公開鍵
- `members/incoming/`: 参加申請中、またはローテーション中の公開鍵
- `secrets/`: 暗号化された secret

`.secretenv/` は運用の中心なので、`.gitignore` に入れず Git で管理します。

### まず鍵の役割を理解する

secretenv では、各ユーザーが自分の鍵ペアを持ちます。

- **公開鍵** はチームで共有してよい鍵です
- **秘密鍵** は自分だけが持つ鍵です

公開鍵暗号の基本はシンプルです。**公開鍵で暗号化し、対応する秘密鍵で復号する**という役割分担になっています。secretenv でも、secret は受信者の公開鍵に向けて暗号化されるため、対応する秘密鍵を持つ人だけが復号できます。つまり、共有鍵暗号方式のように、チーム全体で共通の秘密鍵を安全に配る前提にはなっていません。

共有鍵暗号方式では、同じ秘密鍵を使う相手全員にその鍵を安全に渡す必要があり、**秘密鍵をどう共有するか**自体が運用上の悩みになりがちです。公開鍵暗号方式では、相手に渡すのは公開鍵だけでよいため、**共有すべき秘密そのものを配布しなくてよい**というメリットがあります。

ここで重要なのは、**秘密鍵は絶対に他人と共有してはいけない**ことです。秘密鍵を渡すということは、その人に「自分として secret を読める権限」を渡すのと同じです。Git へのコミット、チャットへの貼り付け、バックアップの無造作な共有も避けてください。

逆に、**公開鍵は「鍵」という名前でも積極的に共有してよい情報**です。公開鍵だけでは通常、secret を復号できません。`members/active/` や `members/incoming/` に公開鍵ファイルをコミットするのもこのためです。

ただし、難しいのは **「その公開鍵が本当は誰のものか」** という確認です。公開鍵そのものは共有してよくても、攻撃者が「これは alice の公開鍵です」と偽って提出することはありえます。だから secretenv では、公開鍵を配ること自体よりも、**その公開鍵を誰の鍵として信頼するかを慎重に判断すること**が重要になります。

### メンバーが使えるようになるまで

新しいメンバーや新しい鍵は、まず `members/incoming/` に入ります。その後、既存メンバーが PR を確認し、`secretenv rewrap` を実行してはじめて受信者として有効になります。

つまり、**PR レビューがメンバー承認の一部**です。レビュー時には「公開鍵を追加している」だけでなく、「その公開鍵をその人のものとして信頼してよいか」を確認しています。見覚えのない公開鍵を安易にマージしないでください。

### ふだん使う形式は 2 種類

- **kv-enc**: `.env` のような key-value を管理する形式です。日常の設定値管理はこちらを推奨します
- **file-enc**: 証明書やバイナリなど、ファイルを丸ごと暗号化する形式です

詳しい操作は [8章](#8-日常的な使い方kv-ストア) と [9章](#9-ファイルの暗号化復号) を参照してください。

---

## 3. よく使う用語

### Workspace

workspace は Git リポジトリ内の `.secretenv/` ディレクトリです。secretenv は通常、Git リポジトリ内で実行すると workspace を自動検出します。Git リポジトリ外で使う場合は `-w` / `--workspace` で明示してください。

### `active` / `incoming`

- **incoming**: まだ承認されていない公開鍵
- **active**: 承認済みで、secret の受信者になれる公開鍵

### `rewrap`

メンバー追加・削除・鍵ローテーションのあとに、暗号ファイルの受信者情報を更新する操作です。`incoming` の鍵を有効化するのも `rewrap` の役目です。

### `member handle`

ユーザーが複数の SecretEnv workspace で継続的に使う、ユーザーが自称するハンドルです。メールアドレス風の値を使うことが多いですが、実際のメールアドレスや外部サービスで検証済みの識別子である必要はありません。

### `kid`

鍵を識別する ID です。1 人のメンバーが複数の鍵を持つことがあるため、どの鍵かを区別するために使います。普段は `key list` や `rewrap` の出力で目にします。

### ローカル信頼ストア

`~/.config/secretenv/trust/` にある、承認済み鍵のローカル記録です。`member verify --approve` などで登録され、以後の確認プロンプトを減らすために使われます。

---

## 4. 安全に使うための前提

### secretenv が守るもの

Git に保存された secret は暗号化され、署名検証も行われます。リポジトリが共有されていても、秘密鍵がなければ内容は読めません。

### secretenv が自動では守らないもの

- 正当なメンバーが復号した後の取り扱い
- 既に見られた secret の「記憶」やコピーの回収
- 端末や秘密鍵そのものの漏洩

メンバーを削除しただけで、過去に見られた値まで消えるわけではありません。必要に応じて secret 自体を更新してください。

### 何が平文メタデータとして見えるか

secretenv が暗号的に守る対象は、secret の値や file-enc のファイル内容です。一方で、運用や監査に必要な一部メタデータは平文のまま残ります。

- kv-enc のキー名
- 受信者一覧（recipient の `member_id` / `kid`）
- 署名者の `kid`
- 作成日時・更新日時
- 開示履歴

`list` が復号せずにキー名を表示でき、`inspect` が復号せずに受信者や時刻や開示履歴を表示できるのはこのためです。したがって、環境変数名、受信者関係、時刻、開示履歴そのものを秘匿したい用途には追加の運用対策が必要です。必要に応じて、リポジトリのアクセス制御や workspace の分離を検討してください。

### SSH 鍵の役割

SSH Ed25519 鍵は、workspace の secret を直接復号する鍵ではありません。ローカルに保存された secretenv の秘密鍵を保護し、その鍵がどの SSH 鍵に紐づくかを示すために使われます。

GitHub と連携して online verify を使う運用では、`attestation.pub` がその GitHub account の**現在の** SSH 公開鍵一覧に含まれているかも確認します。つまり GitHub から SSH 公開鍵を削除すると、その鍵に依存する今後の online verify を止められます。これは既存の attestation を消すものではありませんが、将来の承認や trust 更新を止めるための実務上の停止手段として使えます。

### 迷ったときの運用原則

- 見覚えのない公開鍵を PR でマージしない
- 秘密鍵や SSH 鍵を他人と共有しない
- 漏洩や紛失が疑われたら、`key new` → `join` → `rewrap` でローテーションする
- GitHub 連携を使っているなら、不要になった古い SSH 公開鍵は移行完了後に GitHub から削除する

詳しい設計背景が必要な場合は [Security Design](security_design_ja.md) を参照してください。

---

## 5. インストール

### 前提条件

- Ed25519 形式の SSH 鍵（`~/.ssh/id_ed25519`）
- SSH エージェント（推奨）または ssh-keygen

### Homebrew でインストール（推奨）

```bash
brew tap ebisawa/secretenv
brew install secretenv
```

### ソースからインストール（代替）

ソースからビルドする場合は Rust ツールチェーン（`cargo`）が必要です。

```bash
# リポジトリをクローンしてインストール
git clone <secretenv-repo>
cd secretenv
cargo install --path .
```

インストール後、`secretenv --help` でコマンド一覧を確認できます。

### SSH エージェントの確認

secretenv は秘密鍵の保護に SSH 鍵を使用します。SSH エージェントが動作しているか確認してください。

```bash
# SSH エージェントの確認
ssh-add -l

# 鍵が表示されない場合は追加する
ssh-add ~/.ssh/id_ed25519
```

**注意**: SSH 鍵は必ず Ed25519 形式を使用してください（RSA 等は非対応）。

```bash
# Ed25519 鍵の生成（まだない場合）
ssh-keygen -t ed25519 -C "your@email.com"
```

---

## 6. クイックスタート（チームリーダー向け）

チームで secretenv を初めて導入するときの手順です。

### ステップ 1: リポジトリを用意する

secretenv の workspace 自動検出は Git リポジトリ内で機能します。まず Git リポジトリのディレクトリに移動してください。

```bash
# 既存のリポジトリで始める場合
cd /path/to/your-repo

# または新規リポジトリを作成する場合
git init my-project
cd my-project
```

### ステップ 2: Workspace を初期化する

```bash
secretenv init --member-handle alice@example.com
```

実行結果:

```
Creating workspace .secretenv/
  Created members/active/
  Created members/incoming/
  Created secrets/
Using SSH key: SHA256:xxxxx... (from ~/.ssh/id_ed25519)
SSH signature determinism: OK
Generated and activated key for 'alice@example.com':
  Key ID:   7M2Q-9D4R-1H8V-W6PK-T3XN-C5JY-2F9A-R8GD
  Expires:  2027-03-19T00:00:00Z
Added 'alice@example.com' to members/active/
```

`init` は以下を自動で行います。

- `.secretenv/` ディレクトリ構造を作成
- ローカルのキーストアに自分用の鍵を生成
- 自分の公開鍵を `members/active/alice@example.com.json` に登録

既に active member を持つ workspace がある場合、`init` は変更せず終了します。既存 workspace への参加や鍵の staging には `join` を使います。

### ステップ 3: 最初の secrets を追加する

```bash
# KV 形式で secrets を追加
secretenv set DATABASE_URL "postgres://user:pass@localhost/mydb"
secretenv set API_KEY "sk-your-api-key"

# または既存の .env ファイルを一括インポート
secretenv import .env
```

### ステップ 4: Git にコミットする

```bash
git add .secretenv/
git commit -m "Initialize secretenv workspace"
```

### ステップ 5: チームメンバーに参加してもらう

Workspace の準備が完了したら、他のメンバーに [7章](#7-新メンバーとして参加する) の手順を案内します。

メンバーから PR が届いたら [10章のメンバー追加](#メンバー追加の-git-ワークフロー) に従って承認してください。

---

## 7. 新メンバーとして参加する

既存の Workspace に参加するときの手順です。

### ステップ 1: リポジトリをクローンする

リポジトリをクローンし、そのディレクトリに移動します。これにより secretenv が workspace を自動検出できるようになります。

```bash
git clone <repo-url>
cd my-project
```

### ステップ 2: 参加申請する

```bash
secretenv join --member-handle bob@example.com
```

実行結果:

```
Using SSH key: SHA256:xxxxx... (from ~/.ssh/id_ed25519)
Generated and activated key for 'bob@example.com':
  Key ID:   9N4R-1H8V-W6PK-T3XN-C5JY-2F9A-R8GD-7M2Q
  Expires:  2027-03-19T00:00:00Z
Added 'bob@example.com' to members/incoming/

Ready! Create a PR to share your public key with the team.
An active member needs to run 'secretenv rewrap' so you can start reading secrets.
```

`join` は `init` と異なり、Workspace を作成しません。自分の公開鍵を `members/incoming/` に置くだけです。既に active なメンバーも、`key new` の後に `join` を使って新世代鍵を `members/incoming/` に staging できます。

### ステップ 3: PR を作成する

```bash
git checkout -b join/bob
git add .secretenv/members/incoming/bob@example.com.json
git commit -m "Add bob to secretenv (incoming)"
git push origin join/bob
```

GitHub（または使用している Git ホスティング）で PR を作成し、既存メンバーにレビューをリクエストします。

### ステップ 4: 既存メンバーに rewrap を依頼する

PR がマージされた後、既存メンバーが `secretenv rewrap` を実行して承認します。rewrap が完了してコミットされると、あなたが secrets を取得できるようになります。

### ステップ 5: secrets を確認し、既存メンバーを信頼登録する

```bash
# 最新を取得
git pull

# 動作確認
secretenv get DATABASE_URL
secretenv run -- env | grep MY_APP

# 既存メンバーの鍵をローカル信頼ストアに登録
secretenv member verify --approve
```

最後のコマンドでチームの既存鍵をローカル信頼ストアに登録し、以降の操作で承認プロンプトが表示されないようにします。

---

## 8. 日常的な使い方（KV ストア）

### エントリの追加・更新

```bash
# 基本的な使い方
secretenv set DATABASE_URL "postgres://user:pass@localhost/db"

# 別のストア（-n オプション）に保存
secretenv set -n staging DATABASE_URL "postgres://user:pass@staging/db"
secretenv set -n prod DATABASE_URL "postgres://user:pass@prod/db"
```

ストアを指定しない場合は `default`（`.secretenv/secrets/default.kvenc`）に保存されます。

**シェル履歴に残さないために**: パスワード等は `--stdin` を使用します。

```bash
# パイプで渡す
echo "super-secret-token" | secretenv set SECRET_TOKEN --stdin

# 対話入力（パスワード等）
secretenv set SECRET_TOKEN --stdin
# → 入力待ち状態になる。入力後 Ctrl+D で確定
```

### エントリの削除

```bash
secretenv unset OLD_KEY
secretenv unset -n staging OLD_KEY
```

### エントリの取得

```bash
# 特定キーの値を取得
secretenv get DATABASE_URL

# KEY="VALUE" 形式で出力
secretenv get --with-key DATABASE_URL

# 全エントリを取得
secretenv get --all

# 全エントリを KEY="VALUE" 形式で出力
secretenv get --all --with-key

# 別のストアから取得
secretenv get -n staging DATABASE_URL
```

### キー一覧の表示

```bash
# キー名の一覧（値は表示しない）
secretenv list

# 別のストアのキー一覧
secretenv list -n staging
```

`list` は暗号を復号せずにキー名だけを表示します。値を確認するには `get` を使います。

### 環境変数として注入してコマンドを実行

```bash
# デフォルトストアの全 secrets を環境変数として注入
secretenv run -- ./my-app

# 別のストアを使う
secretenv run -n staging -- ./my-app

# 複数の引数を渡す
secretenv run -- python manage.py runserver
```

`run` は親プロセスの環境変数をそのまま引き継ぎません。子プロセスには `PATH` や `HOME` などの標準的な環境変数だけを残し、secret の値をその上に注入します。

### .env ファイルの一括インポート

```bash
# .env を default ストアにインポート
secretenv import .env

# 別のストアにインポート
secretenv import -n staging staging.env
```

既存のキーは上書きされます。

---

## 9. ファイルの暗号化・復号

証明書やバイナリファイルなど、KV 形式に合わない secrets は `encrypt` / `decrypt` を使います。

### 暗号化

```bash
# ファイルを暗号化（カレントディレクトリに <filename>.encrypted を生成）
secretenv encrypt certs/ca.pem
# → ./ca.pem.encrypted

# 出力先を指定
secretenv encrypt certs/ca.pem --out .secretenv/secrets/ca.pem.encrypted

# stdin から暗号化してファイルへ保存
cat certs/ca.pem | secretenv encrypt --stdin --out .secretenv/secrets/ca.pem.encrypted

# stdin から暗号化して file-enc JSON を stdout に出力
cat certs/ca.pem | secretenv encrypt --stdin --stdout > ca.pem.encrypted
```

暗号化と同時に署名が付与されます。

batch の `rewrap` は、`--target` を指定しない場合に workspace の `.secretenv/secrets/` 配下を自動的に対象にします。特定の file-enc だけを rewrap したい場合は、`secretenv rewrap --target <path>` を使うと、その指定ファイルだけが対象になります。

### 復号

```bash
# 署名検証 → 復号の順で実行される
secretenv decrypt ca.pem.encrypted --out certs/ca.pem
```

復号して取り出した平文ファイルは Git で管理しないようにしてください。`.secretenv/` は Git 管理対象ですが、復号後の `.env` や証明書ファイルは `.gitignore` に入れておくのが安全です。

### メタデータの確認

暗号ファイルを復号せずに内容を確認できます。

```bash
secretenv inspect .secretenv/secrets/default.kvenc
secretenv inspect ca.pem.encrypted
```

表示される情報:

- 受信者一覧
- 署名者と署名の kid
- 暗号アルゴリズム
- 作成日時・更新日時
- 開示履歴（削除されたメンバーへの開示記録）

`inspect` は日常的な確認だけでなく、定期監査にも使えます。受信者に不要なメンバーが含まれていないか、開示履歴に見直すべきエントリがないか、署名者が想定どおりか、期限切れが近い鍵が使われていないかを確認してください。

### 使用すべき場面とすべきでない場面

| 場面 | 推奨 | 理由 |
|------|------|------|
| `.env` の key-value | kv-enc（`set`, `import`） | diff が最小、エントリ単位の操作が可能 |
| 証明書ファイル（PEM） | file-enc（`encrypt`） | バイナリ対応 |
| SSH 秘密鍵 | file-enc（`encrypt`） | バイナリ対応 |
| 数十 MB 以上のファイル | 外部ストレージを検討 | base64 エンコードでサイズが約 4/3 倍になる |
| 数百 MB 以上のファイル | 非推奨 | Git リポジトリに大容量ファイルを入れることになる |

---

## 10. メンバー管理

### メンバー追加の Git ワークフロー

新メンバーが `secretenv join` で PR を作成したら、以下のフローで承認します。

**なぜ PR レビューが重要か**: PR をレビューしてマージする行為は「この人物の公開鍵を信頼する」という意思決定です。見知らぬ人からの PR を確認もせずにマージすることは、その人を secrets の受信者として追加することを意味します。

```bash
# 1. 新メンバーの PR をマージした後、最新を取得
git pull

# 2. rewrap を実行し、表示された鍵情報を確認して承認する
secretenv rewrap

# 表示例:
# Member bob@example.com
#   GitHub account id: 12345678 (bob-gh)
#   SSH key fingerprint: SHA256:xxxxx...
# Approve? [y/N]: y    ← 本当にこの人の鍵か確認してから y を押す

# 3. 変更をコミット・プッシュ
git add .secretenv/
git commit -m "Approve bob and rewrap secrets"
git push
```

`rewrap` が完了すると:
- `members/incoming/bob@example.com.json` が `members/active/` に移動する
- 全ての暗号ファイルで bob が受信者として追加される

**推奨**: rewrap 後に新メンバーの鍵をローカル信頼ストアに登録しておくと、以降の操作で承認プロンプトが表示されなくなります:

```bash
secretenv member verify --approve
```

incoming メンバーが存在する場合、`rewrap` は対話的に承認を求めます。表示された鍵情報を見て「この公開鍵は本当にこの人のものか」を確認してから承認してください。incoming メンバーがいない場合は、受信者情報の同期だけが行われるため通常は非対話的に動作します。

なお、CI/CD で使う環境変数経由の鍵読み込みでは `rewrap` はサポートされていません。`rewrap` は開発者の手元で実行してください。

### メンバー一覧の確認

```bash
# 全メンバー（active + incoming）を表示
secretenv member list

# 特定メンバーの詳細を確認
secretenv member show bob@example.com
```

### メンバー検証

```bash
# active メンバーの公開鍵を検証（online 検証あり）
secretenv member verify

# 特定の active メンバーのみ検証
secretenv member verify alice@example.com bob@example.com

# active メンバーを検証し、その場で local trust store に承認を保存
secretenv member verify --approve

# 特定の active メンバーのみ承認対象にする
secretenv member verify --approve alice@example.com bob@example.com
```

`member verify --approve` は、現在 active なメンバーの鍵を確認し、その結果を自分の端末に保存するためのコマンドです。画面には、どの鍵を確認しているかを判断するための情報が表示されるので、「この公開鍵は本当にこの人のものか」を確認して承認してください。承認した鍵はローカル trust store に保存され、以後の操作で同じ確認を求められなくなります。

### ローカル trust store の管理

ローカル trust store は、**自分が確認済みの公開鍵を自分の端末に記録しておく場所**です。ここに承認済みの鍵が入っていると、復号や検証のたびに同じ鍵を毎回確認し直さずに済みます。

`trust list` を実行すると、現在自分の端末に保存されている承認済み鍵を確認できます。`trust remove` や `trust purge` は、そのローカル記録を削除するコマンドです。local trust store は基本的に承認が蓄積されていく仕組みなので、記録が増えすぎたときや、もう使われていない鍵、あらためて確認し直したい鍵を整理したいときに使います。

通常は `member verify --approve` や interactive な承認で自動的に記録されるため、日常的に手で操作する必要はありません。誤って承認した鍵を見直したいとき、古い承認を整理したいとき、確認を最初からやり直したいときに使ってください。

```bash
# 承認済み鍵を一覧表示
secretenv trust list

# 特定の kid の承認記録を local trust store から削除
secretenv trust remove <kid>

# 古い承認をまとめて削除
secretenv trust purge --older-than 180d --force
```

`trust remove` と `trust purge` が変更するのは **自分の端末上の記録だけ**です。workspace の `members/active` や暗号ファイルの recipients は変更されません。つまり、これらのコマンドは「チームのメンバー構成を変える」のではなく、「自分が次回どこまで再確認を求められるか」を変える操作です。

### メンバー削除

この操作は、退職、異動、端末紛失、権限見直しなどの理由で、**そのメンバーに今後の secret を読ませたくない**ときに行います。流れは 2 段階です。まず `member remove` で workspace 上のメンバー一覧から外し、そのあと `rewrap` で暗号ファイル側の受信者情報を更新します。ここまで完了すると、そのメンバーは **更新後の secret** を復号できなくなります。

**重要な注意事項**: メンバーを削除して rewrap しても、そのメンバーが**過去に取得した secrets の値は無効になりません**。暗号学的に「過去の開示を回収」することは不可能です。

```bash
# 1. workspace のメンバー一覧から削除する
secretenv member remove alice@example.com

# 2. 暗号ファイル側の受信者情報を更新する
secretenv rewrap

# 3. 変更を Git に反映する
git add .secretenv/
git commit -m "Remove alice from secretenv"
```

この時点で変わるのは **今後のアクセス権** です。すでに相手が知っている値そのものは変わらないため、次の手順で secret の値も見直す必要があります。

### 削除後に必ず行うべきこと

削除と `rewrap` だけでは十分ではありません。削除されたメンバーが知っていた可能性のある値は、必要に応じて新しい値へ更新してください。

```bash
secretenv set API_KEY "new-api-key"
secretenv set DATABASE_PASSWORD "new-password"
```

そのうえで、`secretenv inspect` を使って「どのファイルにそのメンバーへの開示履歴が残っているか」を確認すると、どの secret を更新すべきか判断しやすくなります。

値の更新が終わったあとで、必要なら開示履歴をクリアします。

```bash
secretenv rewrap --clear-disclosure-history
```

つまり、メンバー削除後の実務は「メンバー一覧から外す」だけではなく、**相手が知っていた値を新しい値に変える**ところまで含めて完了です。あわせて、GitHub、AWS、データベース、SaaS など、secret の外側にある実サービスの権限も同時に見直してください。

---

## 11. 鍵の管理とローテーション

この章は、自分の鍵を安全に使い続けるための手順です。主に「期限切れが近い」「鍵の漏洩が疑われる」「古い鍵を整理したい」ときに参照してください。

### 鍵管理の原則

secretenv では、鍵管理の責任はユーザーごとに分かれています。最低限、次の原則を守ってください。

- **公開鍵は共有してよいが、秘密鍵は共有しない**: PR に載せるのは公開鍵だけです。秘密鍵はローカルの `~/.config/secretenv/keys/` に保持し、Git やチャットに載せてはいけません
- **秘密鍵を保護する SSH 鍵も自分で管理する**: secretenv の秘密鍵は SSH Ed25519 鍵で保護されます。SSH 鍵が不用意にコピーされたり、無防備な端末で使われたりしないようにしてください
- **端末の保護も鍵管理の一部**: 画面ロック、ディスク暗号化、OS アカウントの保護、バックアップの管理が不十分だと、秘密鍵が間接的に漏洩します
- **漏洩や紛失が疑われたら即時にローテーションする**: 秘密鍵や SSH 鍵、端末の安全性に疑義が出たら、`key new` → `join` → `rewrap` を実施し、必要に応じて secret 自体の値も更新してください

### 鍵の状態

| 状態 | 説明 |
|------|------|
| active | 暗号化・署名に使用される鍵。member_id につき 1 つ |
| available | 復号可能だが暗号化・署名には使用しない |
| expired | 有効期限切れ。復号は可能（警告あり） |

普段の運用で新しく暗号化や署名に使われるのは `active` の鍵だけです。`available` や `expired` の鍵が残るのは、過去にその鍵で暗号化された secret を後から読めるようにするためです。

### 鍵の一覧

```bash
secretenv key list
```

`key list` は、どの鍵が現在 `active` なのか、古い鍵がまだ残っているのか、期限切れが近い鍵がないかを確認したいときに使います。ローテーション前後や、古い鍵を削除してよいか判断するときにまず確認すると安全です。

CLI では kid がハイフン入りで表示されることがありますが、`key activate`、`key remove`、`key export` などではハイフンあり・なしのどちらでも入力できます。

### 定期ローテーション

ローテーションは、期限切れが近いときだけでなく、秘密鍵や SSH 鍵の漏洩が疑われるときにも実施します。流れとしては、「新しい鍵を作る」→「その公開鍵をチームに共有する」→「secret の受信者を新しい鍵に切り替える」と考えると分かりやすいです。

鍵はデフォルトで生成から 1 年後に期限切れになります。期限切れ 30 日前から警告が表示されます。

**手順概要**: (1) `key new` → (2) `join` → (3) PR 作成・マージ → (4) `rewrap` → (5) コミット → (6) 移行期間後に旧鍵を削除。

```bash
# 1. 新しい鍵をローカルに生成する（自動で active になる）
secretenv key new

# 有効期限を指定する場合
secretenv key new --expires-at 2028-01-01T00:00:00Z
secretenv key new --valid-for 2y    # 2年
secretenv key new --valid-for 180d  # 180日

# 2. 新しい公開鍵を workspace に提出する
secretenv join

# 3. PR を作成してレビュー・マージしてもらう
git add .secretenv/members/incoming/alice@example.com.json
git commit -m "Rotate alice's key"
git push

# 4. マージ後、secret 側の受信者情報を新しい鍵へ切り替える
secretenv rewrap

# 5. その変更をコミットする
git add .secretenv/secrets/
git commit -m "Rewrap secrets for alice's new key"
git push

# 6. 旧鍵はしばらく残し、問題がなければ後で削除する
secretenv key remove <old_kid>
```

ポイントは、`key new` だけではチーム側の secret は新しい鍵をまだ使わないということです。`join` で公開鍵を共有し、`rewrap` で受信者情報を更新してはじめて、workspace 全体が新しい鍵へ切り替わります。

GitHub を使った online verify を前提にしている場合は、移行完了後に**旧 SSH 公開鍵を GitHub から削除する**運用が有効です。online verify は「いま GitHub に登録されている鍵か」を見ているため、古い SSH 公開鍵を削除すると、その鍵に紐づく古い attestation は今後の新規承認や trust 更新で通しにくくなります。これは旧鍵の attestation 自体を無効化するわけではないので、必要なら `members/active` の見直しや `known_keys` の削除も別途行ってください。

### 秘密鍵の漏洩が疑われるとき

秘密鍵、SSH 鍵、端末のいずれかに漏洩や不正アクセスの疑いがある場合は、定期ローテーションと同じく `key new` → `join` → `rewrap` の順で新しい鍵へ切り替えます。ただし、**漏洩疑いのあるケースでは通常の定期ローテーションのように旧鍵をしばらく保持しない**ことが重要です。

まず新しい鍵を作成して共有し、PR マージ後に `rewrap` を実行して受信者情報を新しい鍵へ切り替えます。あわせて、漏洩後の被害をこれ以上広げないために、必要なら `rewrap --rotate-key` で暗号ファイルのコンテンツ鍵も再生成してください。そのうえで、API キーやパスワードなど、漏洩した鍵で読まれた可能性のある secret の値自体も更新します。

最後に、漏洩が疑われる旧鍵はローカルから削除します。

```bash
secretenv key remove <compromised_old_kid>
```

こうしておくと、漏洩した旧鍵が手元で「自分の過去の鍵」として残り続ける状態を避けられます。通常の定期ローテーションでは旧鍵をしばらく保持することがありますが、漏洩疑い時はその扱いを分けてください。

漏洩が疑われるのが SSH attestor 鍵である場合は、ローカルから消すだけでは不十分です。GitHub 連携を使っているなら、**その SSH 公開鍵を GitHub からも早急に削除**してください。これにより、その鍵に依存する以後の online verify を失敗させ、将来の承認フローに乗り続けることを防ぎやすくなります。

### コンテンツ鍵のローテーション

メンバー鍵のローテーションとは別に、暗号ファイルのコンテンツ鍵（MK/DEK）自体をローテーションできます。これは、メンバー削除後や漏洩が疑われるときに「ファイル自体を新しい鍵材料で作り直したい」場合に使います。

```bash
secretenv rewrap --rotate-key
```

これにより全ファイルの MK/DEK が再生成され、以前取得されていた古いコンテンツ鍵は新しいファイルには使えなくなります。ただし、すでに相手が復号して知っている平文そのものを消せるわけではありません。

### 特定の鍵をアクティブ化

複数の鍵をローカルに持っていて、「この鍵を今後の暗号化・署名に使いたい」というときに使います。切り替わるのは **自分のローカル環境だけ** で、workspace 側の受信者情報は変わりません。

```bash
secretenv key activate <kid>
```

### 旧鍵の保持期間の目安

旧鍵をすぐ削除しないのは、過去にその鍵で暗号化された secret や、まだ全員が取り込んでいない変更を読めなくなる可能性があるためです。削除前に、以下を確認してください。

- チーム全員が新しい鍵で rewrap された暗号ファイルを取得済みであること
- 旧鍵で暗号化された secrets の復号が必要な運用がなくなったこと

目安として、rewrap 完了から 1〜3 ヶ月は旧鍵を保持することを推奨します。

---

## 12. CI/CD 連携

secretenv は、ポータブルな秘密鍵エクスポートと環境変数ベースの鍵読み込みにより、**信頼できる CI 文脈に限って** CI/CD 環境をサポートします。CI ランナーに SSH 鍵、`ssh-agent`、ローカルキーストアは不要です。

### 概要

この章は、CI で秘密情報を **読む必要がある場合だけ** 参照してください。人間の開発者と同じように CI から鍵管理や `rewrap` まで行うことは想定していません。基本的には、開発者マシンで作成した CI 専用鍵を CI に渡し、CI では `get` / `run` / `decrypt` などの読み取り系コマンドだけを実行します。

CI 環境では、secretenv はローカルキーストアではなく環境変数から秘密鍵とパスワードを読み取ります。環境変数による鍵読み込みで保証されるのは読み取り系コマンドであり、`run` / `decrypt` / `get` / `list` が利用できます。

CI ランナーは通常一時的な環境であり、ローカル信頼ストア（`~/.config/secretenv/trust/`）を持ちません。そのため、他メンバーの署名が付いた秘密情報を読む信頼できる CI ジョブでは、`SECRETENV_STRICT_KEY_CHECKING=no` を明示設定する必要があります。これは「自分の端末に保存した承認履歴がない」ことによる確認だけを省略する設定であり、現在のメンバー確認や署名検証そのものは引き続き行われます。

それでも、CI がチェックアウトしたワークスペースを無条件に信用してよいわけではありません。環境変数による鍵読み込みは、信頼できるワークフロー、信頼できる参照先、信頼できるランナーで実行されるジョブに限定してください。

### 使ってよい CI コンテキスト

- 保護されたブランチへのマージ後に実行されるワークフロー
- 保護されたタグ上のリリース / デプロイ用ワークフロー
- 信頼できるメンテナが起動し、信頼できる参照先を取得する手動実行

### 使ってはいけない CI コンテキスト

- fork からの PR
- 信頼できない PR
- `pull_request_target`
- シークレット注入後に攻撃者が制御する参照先をチェックアウトするジョブ
- 信頼できないランナー上のジョブ

### CI に必要な最小構成

信頼できる CI 文脈で必要なものは 3 つだけです。逆に言えば、これ以外のローカル設定や SSH 環境を CI に持ち込む必要はありません。

1. `SECRETENV_PRIVATE_KEY` 環境変数 -- エクスポートされた秘密鍵（Base64url エンコード済み）
2. `SECRETENV_KEY_PASSWORD` 環境変数 -- エクスポート時に使用したパスワード
3. ワークスペース（`.secretenv/` ディレクトリを含む Git リポジトリ）

`SECRETENV_HOME`、ローカルキーストア、SSH 鍵、設定ファイルは不要です。

ローカル信頼ストアを持たない信頼できる CI で、他メンバー署名の読み取りコマンドを実行する場合は `SECRETENV_STRICT_KEY_CHECKING=no` をそのジョブにだけ明示設定してください。これはローカル承認履歴の確認だけを省略する設定であり、現在のメンバー確認や署名検証は省略しません。また承認履歴を自動更新することもありません。

### セットアップ手順

#### ステップ 1: CI 専用メンバーを作成する

CI 用の専用メンバーを作成します（人間のメンバーの鍵を流用しないでください）。

```bash
# SSH 鍵にアクセスできる開発者のマシンで実行
secretenv key new --member-handle ci@example.com
secretenv join --member-handle ci@example.com
```

#### ステップ 2: CI メンバーを受信者に追加する

```bash
git add .secretenv/members/incoming/ci@example.com.json
git commit -m "Add CI member"
git push

# マージ後: incoming 鍵を昇格し、CI メンバーを全暗号ファイルに追加
secretenv rewrap
git add .secretenv/secrets/
git commit -m "Rewrap secrets for CI member"
git push
```

#### ステップ 3: 秘密鍵をエクスポートする

```bash
# SSH 署名鍵とローカルキーストアにアクセスできる開発者マシンで実行
secretenv key export --private --member-handle ci@example.com --out ci-key.txt
# パスワードの入力と確認を求められます（最低 8 文字）
```

> **パスワードの強度について:** 8 文字は実装上の下限値であり、推奨値ではありません。オフラインブルートフォースへの耐性を考慮すると、20 文字以上のランダム文字列（または同等のエントロピーを持つパスフレーズ）を強く推奨します。パスワードマネージャーで生成した CI シークレット変数を使用するのが理想的です。

出力ファイルには Base64url エンコードされたテキストが 1 行含まれます。標準出力に出したい場合は、`--stdout` を明示的に指定してください。

#### ステップ 4: CI シークレット変数に登録する

CI プラットフォームに 2 つのシークレット変数を登録します。

| 変数 | 値 |
|------|-----|
| `SECRETENV_PRIVATE_KEY` | `ci-key.txt` の内容 |
| `SECRETENV_KEY_PASSWORD` | エクスポート時に入力したパスワード |

登録後、`ci-key.txt` ファイルは安全に削除してください。CI ジョブのログ、標準出力、一時的なアーティファクトに秘密鍵を流して受け渡してはいけません。

#### ステップ 5: CI ジョブで使用する

CI ジョブでは、環境変数経由での鍵ロードに対応した秘密情報の読み取りコマンドのみ使用できます。`member_id` は秘密鍵から自動的に決定されます。

### 例: GitHub Actions

```yaml
name: Deploy
on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install secretenv
        run: cargo install --path .

      - name: Run with secrets
        env:
          SECRETENV_PRIVATE_KEY: ${{ secrets.SECRETENV_PRIVATE_KEY }}
          SECRETENV_KEY_PASSWORD: ${{ secrets.SECRETENV_KEY_PASSWORD }}
          SECRETENV_STRICT_KEY_CHECKING: no
        run: secretenv run -- ./deploy.sh
```

### 例: 汎用 CI 設定

```bash
# 任意の CI プラットフォーム
export SECRETENV_PRIVATE_KEY="<登録済みシークレット>"
export SECRETENV_KEY_PASSWORD="<登録済みシークレット>"
export SECRETENV_STRICT_KEY_CHECKING=no

# 環境変数経由での鍵ロードに対応したコマンドのみ動作
secretenv get DATABASE_URL
secretenv run -- ./my-app
secretenv decrypt ca.pem.encrypted --out ca.pem
```

### サポートされる操作

環境変数経由での鍵ロード時に利用できるのは、現在のところ次の読み取り系コマンドです。

- **復号**（`run`, `decrypt`, `get`）
- **一覧表示**（`list`）

それ以外のコマンドは、CI での環境変数経由の鍵ロードではサポートされません。

- **秘密情報の更新/再署名**（`encrypt`, `set`, `unset`, `import`, `rewrap`）
- **鍵ライフサイクル**（`key new`, `key list`, `key activate`, `key remove`, `key export`, `key export --private`）
- **セットアップ**（`init`, `join`）
- **その他の補助コマンド**（`inspect`, `member`, `config` など）

### セキュリティに関する注意事項

- **パスワードの露出**: `SECRETENV_KEY_PASSWORD` はプロセスメモリに残存し、Linux では `/proc/*/environ` を通じて可視になる場合があります。これは CI プラットフォームがシークレットを取り扱う方法と整合的です。
- **信頼できる CI に限定**: 環境変数による鍵読み込みは、前述の「使ってよい CI コンテキスト」および「使ってはいけない CI コンテキスト」の範囲に従ってください。攻撃者が制御するチェックアウトを署名検証の入力として扱ってはいけません。
- **`SECRETENV_STRICT_KEY_CHECKING=no` の範囲**: 本章前半で説明したとおり、これはローカル信頼ストアを持てない CI のための例外です。書き込み系コマンドには効かず、ローカル承認履歴を自動更新することもありません。
- **CI 専用メンバー**: セットアップ手順で作成した CI 専用メンバーを使い、人間のメンバーの鍵は流用しないでください。これにより独立したローテーションと失効が可能になります。
- **鍵のローテーション**: 再エクスポートとシークレットストア更新は、セットアップ時と同様に SSH 署名鍵とローカルキーストアを使える開発者マシンで行ってください。CI ジョブ内では実施しません。
- **最小権限**: CI メンバーは実際にアクセスが必要な秘密情報のみに追加してください。

---

## 13. よくある質問（FAQ）

### 全般

### Q: サーバーは必要ですか？

不要です。secretenv はサーバーレスで動作します。暗号化、復号、署名検証などのすべての基本操作はローカルで完結します。GitHub API を使ったオンライン検証はオプションの追加チェックです。

### Q: GPG は必要ですか？

不要です。secretenv は SSH 鍵（Ed25519）のみで動作します。GPG や PGP の鍵管理は不要です。

### Q: クラウド Secrets Manager は必要ですか？

不要です。暗号化、復号、鍵管理はすべてローカルで行われます。KMS やクラウドサービスへの依存はありません。

### Q: チーム共通の秘密鍵を管理する必要がありますか？

不要です。secretenv は公開鍵暗号を使うため、チーム全体で共有する秘密鍵はありません。各メンバーの公開鍵に向けて個別に暗号化するため、共通パスワードや共有鍵の配布・管理・ローテーションは不要です。

### Q: GitHub に公開鍵ファイルをコミットしても安全ですか？

安全です。`members/active/*.json` には公開鍵（暗号化用の公開鍵と SSH 公開鍵のフィンガープリント）が含まれますが、秘密鍵は一切含まれません。公開鍵は名前の通り公開しても問題ない情報です。

実際に secrets を復号するためには、ローカルの `~/.config/secretenv/keys/` にある秘密鍵が必要です。この秘密鍵は Git に含まれません。

### Q: リポジトリを公開しても安全ですか？

暗号ファイルは強力な暗号方式で保護されており、秘密鍵なしでの復号は極めて困難です。ただし、リポジトリの公開には暗号強度以外の運用リスクもあります。機密性の高いデータについては、リポジトリを非公開にすることを推奨します。

### SSH 鍵

### Q: 新しい SSH 鍵を作る必要がありますか？

Ed25519 鍵を既にお持ちであれば（例: GitHub 用に作成済み）、そのまま再利用できます。なければ `ssh-keygen -t ed25519` で生成してください。RSA その他の鍵タイプには対応していません。

### Q: SSH エージェントが必要な理由は？

secretenv の秘密鍵は、パスフレーズの代わりに SSH Ed25519 鍵で保護されています。secretenv を操作するたびに SSH 鍵を使った復号が必要になるため、毎回の入力を減らすには SSH エージェントを使うと便利です。

SSH エージェントが使えない環境では `--ssh-keygen` オプションで `ssh-keygen` コマンドによる署名に切り替えることもできます。

SSH エージェントに複数の鍵がロードされている場合、`-i` オプションまたは `ssh_identity` 設定で使用する鍵を明示的に指定できます：

```bash
secretenv encrypt -i ~/.ssh/id_ed25519_work secret.env
```

### Q: 1Password の SSH agent に対応していますか？

はい。secretenv は ssh-agent 経由の署名に対応しており、1Password の SSH agent を含みます。Windows/WSL2 固有の設定については [WSL ユーザーガイド](wsl_user_guide_ja.md) を参照してください。

### 日常利用

### Q: 既存の .env ファイルから移行できますか？

はい。`secretenv import .env` で一括インポートできます。以降は `secretenv run` でコマンドを実行すれば、復号された secrets が環境変数として注入されます。

### Q: .env 以外のファイルも暗号化できますか？

はい。証明書、設定ファイル、バイナリファイルなどは `secretenv encrypt` / `secretenv decrypt` で扱えます。[9章](#9-ファイル暗号化と復号) を参照してください。

### Q: 複数環境（dev / staging / prod）を管理できますか？

はい。`-n` オプションで環境ごとに別のストアを作成できます：

```bash
secretenv set -n staging DATABASE_URL "postgres://..."
secretenv set -n prod DATABASE_URL "postgres://..."
secretenv run -n staging -- ./my-app
```

### Q: `secretenv run` と `.env` ファイルを手動で読み込む方法、どちらがよいですか？

`secretenv run` の使用を推奨します。理由は以下の通りです。

- 平文の `.env` ファイルがディスクに残らない
- 実行のたびに最新の secrets を復号するため、値の更新が即座に反映される
- 署名検証が自動で実行され、改ざんされた secrets でのコマンド実行を防げる
- 親シェルの任意環境変数を子プロセスへ漏らしにくい

### Q: 複数のプロジェクトで別々の secrets を管理したいのですが？

各 Git リポジトリに独立した `.secretenv/` を持てます。プロジェクトごとに `secretenv init` を実行し、それぞれ独立した Workspace として管理します。

同じメンバーが複数のプロジェクトに参加する場合でも、その人の公開鍵は各 Workspace で独立して受信者として登録されます。

### Q: 暗号ファイルごとに共有先を細かく分けられますか？

通常の運用ではできません。secretenv は、その Workspace の `members/active` にいるメンバー全員を受信者として暗号ファイルを共有します。

ただし、共有先グループを分けたい場合は、**複数の Workspace を使い分ける**という方法があります。`-w` / `--workspace` で対象 Workspace を切り替えられるため、たとえば「開発チーム全体向け」「本番運用担当のみ」「特定案件メンバーのみ」のように、Workspace 自体を共有先グループとして分けて運用できます。

これは少し例外的な使い方なので、まずは 1 つの Workspace をチーム共有用として使う前提で考えるのが分かりやすいです。暗号ファイルごとに共有範囲を変えたい要件が明確にある場合だけ、Workspace を分ける運用を検討してください。

### Q: Git で暗号ファイルがコンフリクトしたらどうなりますか？

secretenv は各 `.env` キーを個別に暗号化するため、異なるキーの変更がコンフリクトすることはまれです。同じキーが同時に変更された場合は、通常の Git コンフリクトと同様にどちらか一方を選択して解消してください。

### メンバーシップと鍵

### Q: メンバーを削除すれば過去の secrets は消えますか？

消えません。メンバーを削除して rewrap しても、そのメンバーが過去に復号した値は依然としてそのメンバーの手元に存在する可能性があります。

「削除後に secrets が漏洩するリスクをゼロにしたい」場合は、そのメンバーが知っていた可能性のある secrets の値（API キー、パスワード等）を必ず新しい値に更新してください。

### Q: 鍵ローテーションに対応していますか？

はい。`secretenv rewrap --rotate-key` で暗号鍵を再生成し全体を再暗号化できます。メンバー変更時と定期的なローテーションの両方に対応しています。[11章](#11-鍵管理とローテーション) を参照してください。

### Q: CI/CD 環境で使えますか？

はい。`secretenv run` と `secretenv get` は環境変数経由の鍵ロードにより非対話的に動作し、CI パイプラインへの統合が容易です。セットアップの詳細、許可されるコンテキスト、セキュリティ上の注意点は [12章](#12-cicd-連携) を参照してください。

### トラブルシューティング

### Q: SSH エージェントのエラー — "no keys" や "agent not running"

`ssh-add -l` で確認してください。空の場合は `ssh-add ~/.ssh/id_ed25519` で鍵を追加します。エージェントが起動していない場合は `eval "$(ssh-agent -s)"` で起動してください。

### Q: 鍵の有効期限切れの警告やエラー

鍵はデフォルトで生成から1年後に期限切れになります。[11章](#11-鍵管理とローテーション) のローテーション手順に従ってください。`secretenv key new` で新しい鍵を生成し、`secretenv join` で staging し、PR マージ後に `secretenv rewrap` を実行します。

### Q: 復号時に予期しない承認プロンプトが表示される

署名者の `kid` がローカル信頼ストアに登録されていない場合に発生します。`secretenv member verify --approve` を実行して、現在の active メンバーを確認・承認してください。詳細は [10章](#10-メンバー管理) を参照してください。

### Q: 「非決定的 SSH 署名」エラー

SSH 鍵が同じ入力に対して2回連続で異なる署名を生成したことを意味します。これは FIDO2/ハードウェアトークン（Ed25519-SK）で発生し得ます。secretenv は決定的な Ed25519 署名を必要とします。標準的なソフトウェア Ed25519 鍵を使用してください。

---

## 14. コマンドリファレンス（早見表）

### 共通オプション（全コマンドで使用可能）

| オプション | 説明 |
|-----------|------|
| `--home <path>` | ベースディレクトリを指定（デフォルト: `~/.config/secretenv/`） |
| `-w` / `--workspace <path>` | Workspace Root を指定 |
| `-i` / `--ssh-identity <path>` | SSH 鍵ファイルパスを指定（ssh-agent での鍵選択にも使用） |
| `--ssh-agent` | SSH エージェントを使用 |
| `--ssh-keygen` | ssh-keygen コマンドを使用 |
| `--json` | JSON 形式で出力 |
| `-q` / `--quiet` | 最小限の出力 |
| `-v` / `--verbose` | 詳細ログを出力 |

### 初期化・参加

| コマンド | 説明 |
|---------|------|
| `secretenv init [--member-handle <id>]` | 新しい Workspace を bootstrap し、最初のメンバーを active に登録 |
| `secretenv join [--member-handle <id>] [--force]` | 既存 Workspace に参加申請、または鍵ローテーション用の公開鍵を staging（incoming に登録） |

### KV 操作

| コマンド | 説明 |
|---------|------|
| `secretenv set [-n <name>] <KEY> <VALUE>` | エントリを追加・更新 |
| `secretenv set [-n <name>] <KEY> --stdin` | stdin から値を読み込んでセット |
| `secretenv get [-n <name>] <KEY>` | 特定キーの値を取得・表示 |
| `secretenv get [-n <name>] --all` | 全エントリを取得・表示 |
| `secretenv get [-n <name>] [--all] --with-key` | `KEY="VALUE"` 形式で出力 |
| `secretenv unset [-n <name>] <KEY>` | エントリを削除 |
| `secretenv list [-n <name>]` | キー名の一覧を表示（値は表示しない） |
| `secretenv import [-n <name>] <file>` | `.env` ファイルを一括インポート |
| `secretenv run [-n <name>] -- <command>` | secrets を環境変数として注入してコマンドを実行 |

### ファイル操作

| コマンド | 説明 |
|---------|------|
| `secretenv encrypt <file> [--out <path> \| --stdout]` | ファイルを暗号化（file-enc） |
| `secretenv encrypt --stdin (--out <path> \| --stdout)` | stdin 入力を file-enc として暗号化 |
| `secretenv decrypt <file> --out <path>` | ファイルを復号 |
| `secretenv inspect <file>` | 暗号ファイルのメタデータを表示（復号不要） |

### メンバー管理

| コマンド | 説明 |
|---------|------|
| `secretenv member list` | 全メンバーを一覧表示 |
| `secretenv member show <member_handle>` | 特定メンバーの詳細を表示 |
| `secretenv member verify [<member_handle>...]` | active メンバーの公開鍵を検証（online 検証あり） |
| `secretenv member verify --approve [<member_handle>...]` | active メンバーの鍵を確認し、承認結果を local trust store に保存 |
| `secretenv member add <file>` | メンバーの公開鍵ファイルを incoming に追加 |
| `secretenv member remove <member_handle>` | メンバーを Workspace から削除 |
| `secretenv rewrap [--rotate-key] [--clear-disclosure-history] [--target <path>...]` | 承認待ちメンバーを有効化し、`--target` 未指定時は workspace の全暗号ファイル、指定時はその対象ファイルだけの受信者情報を更新 |

### ローカル trust store

| コマンド | 説明 |
|---------|------|
| `secretenv trust list` | local trust store に保存されている承認済み鍵を一覧表示 |
| `secretenv trust remove <kid>` | local trust store から特定の鍵の承認記録を削除 |
| `secretenv trust purge --older-than <duration> [-f, --force]` | 指定期間より古い承認記録を local trust store から削除 |

### 鍵管理

| コマンド | 説明 |
|---------|------|
| `secretenv key new [--expires-at <datetime>] [--valid-for <duration>]` | 新しい鍵を生成（自動で activate） |
| `secretenv key list` | 鍵一覧を表示 |
| `secretenv key activate <kid>` | 特定の鍵を active にする |
| `secretenv key remove <kid>` | 鍵を削除 |
| `secretenv key export [<kid>] [--member-handle <id>] --out <path>` | 公開鍵をエクスポート |
| `secretenv key export --private [<kid>] [--member-handle <id>] (--stdout \| --out <path>)` | 秘密鍵をエクスポート（パスワード保護、CI/CD 用） |

### 設定

| コマンド | 説明 |
|---------|------|
| `secretenv config set <key> <value>` | 設定値をセット |
| `secretenv config get <key>` | 設定値を取得 |
| `secretenv config list` | 設定一覧を表示 |
| `secretenv config unset <key>` | 設定値を削除 |

設定キー: `member_handle`, `ssh_signing_method`（`auto` / `ssh-agent` / `ssh-keygen`）, `ssh_identity`, `github_user`

---

## 15. 設定リファレンス

### よく使う設定（オプション）

ここで紹介する設定は、毎回同じオプションを入力したくない場合にだけ使えば十分です。初期セットアップ時に必ず実行する必要はありません。

```bash
# デフォルトの member handle を設定（以降 --member-handle を省略可能）
secretenv config set member_handle alice@example.com

# GitHub アカウントを設定（online 検証を使う場合）
secretenv config set github_user alice-gh

# SSH 署名方式の設定（通常はデフォルトの auto で問題なし）
# auto: ssh-agent → ssh-keygen の順で自動選択
# ssh-agent: SSH エージェントを使用
# ssh-keygen: ssh-keygen コマンドを使用
secretenv config set ssh_signing_method auto

# SSH 鍵の指定（ssh-agent で複数鍵がある場合に特定の鍵を選択）
secretenv config set ssh_identity ~/.ssh/id_ed25519_work
```

設定ファイルの場所は `~/.config/secretenv/config.toml` です。

secretenv は設定値を複数のソースから以下の優先順位で解決します:

1. **CLI オプション**（最優先）
2. **環境変数**
3. **設定ファイル**（`<SECRETENV_HOME>/config.toml`）
4. **デフォルト値**（最低優先）

上位のソースで値が見つかった場合、下位のソースは無視されます。

### 設定ファイル

グローバル設定ファイルは `<SECRETENV_HOME>/config.toml`（デフォルト: `~/.config/secretenv/config.toml`）に配置します。フラット TOML キーバリュー形式です。

| キー | 説明 | デフォルト | CLI オプション | 環境変数 |
|------|------|------------|--------------|----------|
| `member_handle` | デフォルトの member handle（パターン: `^[A-Za-z0-9][A-Za-z0-9._@+-]{0,253}$`） | （なし） | `-m` / `--member-handle` | `SECRETENV_MEMBER_HANDLE` |
| `ssh_identity` | SSH 秘密鍵ファイル（Ed25519）のパス。チルダ展開（`~/...`）対応 | `~/.ssh/id_ed25519` | `-i` / `--ssh-identity` | `SECRETENV_SSH_IDENTITY` |
| `ssh_signing_method` | SSH 署名方式: `auto`, `ssh-agent`, `ssh-keygen` | `auto` | `--ssh-agent` / `--ssh-keygen` | `SECRETENV_SSH_SIGNING_METHOD` |
| `ssh_keygen_command` | `ssh-keygen` コマンドのパス | `ssh-keygen` | — | — |
| `ssh_add_command` | `ssh-add` コマンドのパス | `ssh-add` | — | — |
| `github_user` | `key new` 実行時のデフォルト GitHub ログイン名 | （なし） | `--github-user` | `SECRETENV_GITHUB_USER` |

設定例:

```toml
member_handle = "alice@example.com"
ssh_identity = "~/.ssh/id_ed25519"
ssh_signing_method = "auto"
github_user = "alice-gh"
```

設定ファイルが存在しない場合、エラーにならず環境変数やデフォルト値にフォールバックします。ファイルが存在するが構文エラーの場合はエラーになります。

### 環境変数

| 変数名 | 説明 | デフォルト |
|--------|------|------------|
| `SECRETENV_HOME` | secretenv の設定と鍵のベースディレクトリ | `~/.config/secretenv/` |
| `SECRETENV_MEMBER_HANDLE` | デフォルトの member handle | （なし） |
| `SECRETENV_SSH_IDENTITY` | SSH 秘密鍵ファイル（Ed25519）のパス | `~/.ssh/id_ed25519` |
| `SECRETENV_SSH_SIGNING_METHOD` | SSH 署名方式: `auto`, `ssh-agent`, `ssh-keygen` | `auto` |
| `SECRETENV_GITHUB_USER` | `key new` 実行時のデフォルト GitHub ログイン名 | （なし） |
| `SECRETENV_WORKSPACE` | ワークスペースディレクトリのパス（自動検出をオーバーライド） | （git ルートから自動検出） |
| `SECRETENV_STRICT_KEY_CHECKING` | 読み取り時にローカル承認履歴の確認を行うか: `yes`, `no` | `yes` |
| `SECRETENV_PRIVATE_KEY` | Base64url エンコードされたポータブル秘密鍵ドキュメント（CI/CD 用） | （なし） |
| `SECRETENV_KEY_PASSWORD` | `SECRETENV_PRIVATE_KEY` の復号パスワード（CI/CD 用） | （なし） |

**補足:**

- `SECRETENV_PRIVATE_KEY` と `SECRETENV_KEY_PASSWORD` は、ローカル keystore が利用できない CI/CD 環境で使用します。`SECRETENV_PRIVATE_KEY` を設定する場合、`SECRETENV_KEY_PASSWORD` も必須です。詳細は [12章](#12-cicd-連携) を参照してください。
- `SECRETENV_STRICT_KEY_CHECKING=no` は、読み取り時のローカル承認履歴の確認だけを省略します。読み取り操作（decrypt, get, run, list）に限り許可され、書き込み操作では常に厳格チェックが適用されます。
- `SECRETENV_WORKSPACE` は git リポジトリルートからのワークスペース自動検出をオーバーライドします。リポジトリツリー外からコマンドを実行する場合に便利です。

---

*このガイドは secretenv の日常利用に必要な情報をまとめたものです。より詳しい設計背景が必要な場合は、関連する設計ドキュメントを参照してください。*
