# Kapsaro ユーザーガイド

## 目次

1. [導入と安全上の前提](#1-導入と安全上の前提)
2. [インストール](#2-インストール)
3. [ワークスペースの作成と参加](#3-ワークスペースの作成と参加)
4. [KV 操作](#4-kv-操作)
5. [ファイルの暗号化と復号](#5-ファイルの暗号化と復号)
6. [メンバー管理](#6-メンバー管理)
7. [鍵の管理と更新](#7-鍵の管理と更新)
8. [CI/CD 連携](#8-cicd-連携)
9. [診断](#9-診断)
10. [問題解決とよくある質問](#10-問題解決とよくある質問)
11. [コマンド・設定リファレンス](#11-コマンド設定リファレンス)
12. [用語集](#12-用語集)

---

<a id="1-はじめに"></a>

## 1. 導入と安全上の前提

### Kapsaro とは

Kapsaro は、データベースの接続情報、API トークン、証明書などを暗号化して Git で共有する、オフライン優先の CLI ツールです。次のような共有方法を見直したいチームで利用できます。

- Slack や Teams などのチャットツールに平文でパスワードを貼り付けて共有している
- `.env.example` に実際のシークレットをコメントアウトした状態で残している
- 異動や退職をしたメンバーが、過去に共有されたパスワードを保持し続けている

Kapsaro は Git へ保存する前に秘密情報を暗号化し、署名と開示履歴を付けて変更を記録します。発行元サービスでの資格情報の失効は、別途運用で行います。

### Kapsaro が解決すること

- `.env` の値やファイルを暗号化して Git で共有する
- メンバー変更後に `rewrap` を実行して、暗号化ファイルの受信者を更新する
- 除外された受信者を記録し、値の再発行が必要かを判断する材料にする
- 暗号化・復号・署名検証をローカルで行う（任意の GitHub 本人確認にはネットワーク接続を使用）

### Kapsaro が自動では解決しないこと

受信者は復号した値をコピーできます。コピーの回収、発行元サービスでの資格情報の失効、侵害された端末上の秘密情報の保護は Kapsaro だけでは行えません。チームで担う対策は、[後述の安全上の前提](#4-安全に使うための前提) を確認してください。

---

<a id="2-使い始める前に知っておくこと"></a>

### 全体像の把握

共有の流れは次のとおりです。

1. チームはリポジトリ内の `.kapsaro/` ワークスペースで暗号化ファイルとメンバーの公開鍵を共有します。
2. 各メンバーは自分専用の公開鍵と秘密鍵のペアを管理します。
3. 既存メンバーが新メンバーや更新鍵を PR でレビューし、承認した変更を `rewrap` で反映します。

### ワークスペースを Git で共有する

既定のワークスペースは、Git リポジトリのルート直下にある `.kapsaro/` ディレクトリです。

```
.kapsaro/
├── members/
│   ├── active/
│   └── incoming/
├── secrets/
└── config.toml
```

- `members/active/`: 現在有効なメンバーの公開鍵ドキュメント
- `members/incoming/`: 参加申請中、または鍵ローテーション中の未承認公開鍵
- `secrets/`: 暗号化されたシークレットストアおよびファイル

> [!IMPORTANT]
> `.kapsaro/` はプロジェクトと一緒にコミットします。`.gitignore` の対象から外してください。

### 鍵の役割を正しく理解する

各メンバーは公開鍵を共有し、対応する秘密鍵を手元で保護します。Kapsaro は内容を共通鍵で暗号化し、その鍵を各受信者の公開鍵で個別に保護します。このため、秘密鍵を配布したりチーム共通のマスターパスワードを管理したりせずに、暗号化データを共有できます。

秘密鍵は他者と共有しないでください。秘密鍵を得た人物は、その鍵宛てのファイルを復号し、所有者になりすまして署名できる可能性があります。Git、チャット、暗号化されていないバックアップには保存しないでください。

`members/active/` と `members/incoming/` の公開鍵は、秘密鍵を公開せずに共有できます。ただし、公開鍵ファイルにはメンバーの識別情報も含まれるため、リポジトリを公開する前にその内容を確認してください。

鍵を承認する前に、意図したチームメイトの鍵であることを確認します。公開鍵だけでは所有者の本人確認も、秘密情報を受け取る権限の確認もできません。

### メンバーが有効化されるまでの流れ

新しいメンバーやローテーション後の新鍵は、まず `members/incoming/` に配置されます。その後、既存メンバーが Pull Request をレビューしてマージし、`kapsaro rewrap` を実行することで初めて正式な受信者として有効化されます。

PR では本人確認とアクセスの必要性をレビューします。承認したメンバー構成は `rewrap` で反映し、各端末の鍵承認には本人確認の結果を記録します。署名が有効であることだけでは、本人確認やアクセス許可の判断はできません。

### 主な 2 つの保存形式

- kv-enc は `.env` のようなキーと値の組を保存し、エントリごとに更新できる形式です。
- file-enc は証明書やバイナリデータを含む、ファイル全体を暗号化する形式です。

コマンドは [KV 操作](#4-kv-操作) と [ファイル操作](#5-ファイルの暗号化と復号) を参照してください。

---

<a id="4-安全に使うための前提"></a>

### Kapsaro が保証すること

Kapsaro で作成したファイルには、認証付き暗号と電子署名を使用します。[セキュリティ設計](security_design_ja.md) に示す暗号学的な仮定のもとで、必要な鍵や別経路の平文を持たない第三者から内容を保護します。

### Kapsaro が自動では防げないこと

- 正規メンバーが復号した後の平文データの取り扱い（端末外への持ち出しや漏洩）
- メンバーが過去に復号して閲覧したシークレットの「記憶」や手元コピーの抹消
- 端末の紛失・盗難やマルウェアによる秘密鍵の直接奪取

メンバーを除外しても、その人物が保持する過去の暗号文や平文へのアクセスは残ります。離脱対応では、アクセスできた資格情報を発行元サービスで失効・再発行してください。

### 平文のまま残るメタデータ

Kapsaro が暗号化によって保護するのはシークレットの値そのもの、および file-enc のファイル本文です。一方で、運用と監査に必要な以下のメタデータは平文のまま記録されます。

- kv-enc 内のキー名（環境変数名）
- 受信者一覧（メンバーハンドルおよび `kid`）
- 署名者の `kid`
- 作成日時および更新日時のタイムスタンプ
- 過去の開示履歴（除外されたメンバーの記録）

`kapsaro list` はキー名を、`kapsaro inspect` はメタデータと署名検証結果を、値を復号せずに表示します。開示履歴が示すのは過去の受信者であり、実際に値を読んだ記録ではありません。キー名、日時、メンバーの識別情報を秘匿する場合は、リポジトリへのアクセスを制限するかワークスペースを分けてください。

### SSH 鍵の役割

Ed25519 SSH 鍵は、手元の Kapsaro 秘密鍵を保護し、Kapsaro 公開鍵と SSH 鍵を結び付ける証明情報に署名します。ワークスペースのデータを復号するのは Kapsaro 秘密鍵です。

GitHub を使ったオンライン検証では、証明情報内の SSH 公開鍵である `attestation.pub` が、現在も対象の GitHub アカウントに登録されているかを確認します。GitHub から削除した鍵は、その後のオンライン照合で失敗します。ただし、ワークスペースの既存のアクセス権や手元の承認記録は残ります。

### 迷ったときの運用原則

- 見知らぬ公開鍵を含む PR は絶対にマージしない
- 秘密鍵や SSH 秘密鍵を他者と共有しない
- 端末や鍵の侵害が疑われたら、安全な端末から SSH 鍵・Kapsaro 鍵の交換、漏洩鍵の除外、内容鍵の更新、資格情報の失効を行う（[鍵の管理](#7-鍵の管理と更新) を参照）
- GitHub 連携を利用している場合、退役した古い SSH 公開鍵は移行完了後に GitHub から削除する

暗号プロトコルの詳細については [セキュリティ設計](security_design_ja.md) を参照してください。

---

<a id="5-インストール"></a>

## 2. インストール

### 前提条件

- Ed25519 SSH 鍵（`~/.ssh/id_ed25519`）
- 稼働中の SSH エージェント（推奨）、または `ssh-keygen` コマンド

### Homebrew によるインストール（推奨）

```bash
brew tap ebisawa/kapsaro
brew install kapsaro
```

### ソースコードからのビルド

```bash
git clone https://github.com/ebisawa/kapsaro.git
cd kapsaro
cargo install --path .
```

インストール後、`kapsaro --help` を実行してコマンド一覧が表示されることを確認します。

### SSH エージェントの確認

Kapsaro はローカル秘密鍵の保護に SSH 鍵を使用します。SSH エージェントが起動し、鍵が登録されていることを確認してください。

```bash
# エージェントに登録されている鍵の一覧を確認
ssh-add -l

# 鍵が登録されていない場合は追加
ssh-add ~/.ssh/id_ed25519
```

> [!NOTE]
> Kapsaro は Ed25519 形式の鍵のみをサポートしています（RSA 等は非対応です）。

```bash
# Ed25519 鍵をお持ちでない場合は生成してください
ssh-keygen -t ed25519 -C "your@email.com"
```

SSH エージェントの代わりに `ssh-keygen` で署名する設定は、[SSH エージェントに関する FAQ](#q-why-is-the-ssh-agent-needed) を参照してください。

---

<a id="6-クイックスタートチームリーダー向け"></a>

## 3. ワークスペースの作成と参加

### ワークスペースを作成する

チームに初めて Kapsaro を導入する際の手順です。

#### ステップ 1: リポジトリの準備

プロジェクトの Git リポジトリへ移動します。

```bash
# 既存のリポジトリへ移動
cd /path/to/your-repo

# または新しいリポジトリを作成
git init my-project
cd my-project
```

#### ステップ 2: ワークスペースの初期化

```bash
kapsaro init --member-handle alice@example.com
```

出力例:

```
Creating workspace .kapsaro/
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

`kapsaro init` は以下の処理を自動で実行します。

- `.kapsaro/` ディレクトリ構造の作成
- 手元の鍵ペアの利用、または必要に応じた `~/.config/kapsaro/keys/` 内での生成
- `.kapsaro/members/active/alice@example.com.json` への初期公開鍵の登録

すでにワークスペースに有効なメンバーが存在する場合、`init` は変更を行わずに終了します。既存ワークスペースへの鍵登録には `kapsaro join` を使用してください。

#### ステップ 3: 最初のシークレットを追加

以下の値は例です。実際の資格情報は、シェル履歴やプロセス引数に残さないよう、[画面に表示しない標準入力](#secret-input) から登録してください。

```bash
# 個別にシークレットを追加
kapsaro set DATABASE_URL "postgres://user:pass@localhost/mydb"
kapsaro set API_KEY "sk-your-api-key"

# または既存の .env ファイルを一括インポート
kapsaro import .env
```

#### ステップ 4: 登録内容の確認

```bash
kapsaro list
kapsaro run -- true
```

`kapsaro list` でキー名の一覧を確認し、`kapsaro run -- true` でシークレットの復号が正常に行えることを検証します（画面にシークレットを出力せずに動作確認できます）。

#### ステップ 5: Git にコミット

```bash
git add .kapsaro/
git commit -m "Initialize kapsaro workspace"
```

#### ステップ 6: チームメンバーの参加

他のメンバーに [ワークスペースへの参加手順](#ワークスペースに参加する) を案内してください。参加 PR をレビューし、[メンバー追加手順](#member-addition-git-workflow) に従って反映します。

---

<a id="7-新しいメンバーとして参加する"></a>

### ワークスペースに参加する

既存のチームワークスペースに参加する手順です。

#### ステップ 1: リポジトリをクローン

```bash
git clone <repo-url>
cd my-project
```

#### ステップ 2: 参加申請（join）を実行

```bash
kapsaro join --member-handle bob@example.com
```

出力例:

```
Using SSH key: SHA256:xxxxx... (from ~/.ssh/id_ed25519)
Generated and activated key for 'bob@example.com':
  Key ID:   9N4R-1H8V-W6PK-T3XN-C5JY-2F9A-R8GD-7M2Q
  Expires:  2027-03-19T00:00:00Z
Added 'bob@example.com' to members/incoming/

Ready! Create a PR to share your public key with the team.
```

`join` は既存ワークスペースへの参加申請です。利用できる自分の鍵があればその公開鍵を使い、なければ鍵ペアを生成して、公開鍵を `members/incoming/` に配置します。既存メンバーの鍵更新にも使います。

#### ステップ 3: PR を作成して提出

```bash
git checkout -b join/bob
git add .kapsaro/members/incoming/bob@example.com.json
git commit -m "Add bob to kapsaro (incoming)"
git push origin join/bob
```

GitHub 等で Pull Request を作成し、既存メンバーにレビューを依頼します。

#### ステップ 4: 既存メンバーによる rewrap の実行を待つ

PR がマージされた後、既存メンバーが [共通完了手順](#membership-completion) に従って `rewrap` を実行し、暗号化ファイルを更新してコミット・プッシュします。この共有が完了するまでお待ちください。

#### ステップ 5: 復号確認とメンバーの信頼承認

```bash
# 最新の変更を取得
git status --short
git pull --ff-only

# 既存メンバーの公開鍵を検証・承認
kapsaro member verify --approve

# シークレットを表示せずに復号動作を確認
kapsaro run -- true
```

表示されたハンドルと指紋から鍵の所有者を確認して承認します。`kapsaro run -- true` の成功が確認するのは既定ストアへのアクセスです。参加完了とする前に、名前付きストアは `-n` で、単体ファイルは `decrypt` でそれぞれ確認してください。

---

<a id="8-日常的な使い方kv-ストア"></a>

## 4. KV 操作

### エントリの追加と更新

```bash
# デフォルトストアへの保存
kapsaro set DATABASE_URL "postgres://user:pass@localhost/db"

# 環境別の名前付きストアへの保存 (-n オプション)
kapsaro set -n staging DATABASE_URL "postgres://user:pass@staging/db"
kapsaro set -n prod DATABASE_URL "postgres://user:pass@prod/db"
```

ストア名を省略した場合は `default` ストア（`.kapsaro/secrets/default.kvenc`）に保存されます。

<a id="workspace-sharing"></a>

名前付きストア（`dev`、`staging`、`prod` など）は、同じワークスペースのメンバー向けに秘密情報を整理します。受信者には `members/active/` のメンバーを使うため、メンバー変更後は `rewrap` で既存ファイルを同期してください。アクセスできる人を分ける場合は、別のメンバー構成を持つワークスペースを作成し、明示的に指定します。

```bash
kapsaro set --workspace .kapsaro-prod -n prod DATABASE_URL --stdin
kapsaro run --workspace .kapsaro-prod -n prod -- ./my-app
```

<a id="secret-input"></a>

機密性の高いトークンやパスワードは、コマンド引数とシェル履歴に残さないよう必ず `--stdin` から入力してください。Bash で入力した文字を画面に表示しないようにするには、次を実行します。

```bash
(
  set -eu
  terminal_state=$(stty -g)
  trap 'stty "$terminal_state"' EXIT
  stty -echo
  kapsaro set SECRET_TOKEN --stdin
)
```

値を入力して Enter を押し、Ctrl+D を押すことで入力を完了できます。

### エントリの削除

```bash
kapsaro unset OLD_KEY
kapsaro unset -n staging OLD_KEY
```

### エントリの取得

```bash
# 特定のキーの値を取得
kapsaro get DATABASE_URL

# KEY="VALUE" 形式で出力
kapsaro get --with-key DATABASE_URL

# すべてのエントリを取得
kapsaro get --all
kapsaro get --all --with-key

# 名前付きストアから取得
kapsaro get -n staging DATABASE_URL
```

### キー名の一覧表示

```bash
# キー名一覧を表示（値は復号されません）
kapsaro list

# 名前付きストアのキー名一覧を表示
kapsaro list -n staging
```

`kapsaro list` は、値を復号せずに署名と信頼状態を検証します。

### シークレットを環境変数として注入してコマンドを実行

```bash
# デフォルトストアのシークレットを注入して実行
kapsaro run -- ./my-app

# 名前付きストアのシークレットを注入して実行
kapsaro run -n staging -- ./my-app

# 複数の引数を伴うコマンドを実行
kapsaro run -- python manage.py runserver
```

`kapsaro run` は親シェルの環境変数を継承し、そこから `KAPSARO_` で始まる変数を除去します。最後に復号した値を設定するため、親シェルの同名変数は上書きされます。

### `.env` ファイルの一括インポート

```bash
# デフォルトストアへインポート
kapsaro import .env

# 名前付きストアへインポート
kapsaro import -n staging staging.env
```

既存のキーが存在する場合は上書きされます。

---

<a id="9-ファイルの暗号化と復号"></a>

## 5. ファイルの暗号化と復号

証明書や秘密鍵ファイル、バイナリデータなど、KV 形式に適さないファイルの保護には `encrypt` / `decrypt` を使用します。

### ファイルの暗号化

```bash
# ファイルを暗号化（カレントディレクトリに <ファイル名>.encrypted を生成）
kapsaro encrypt certs/ca.pem

# 出力先パスを明示して暗号化
kapsaro encrypt certs/ca.pem --out .kapsaro/secrets/ca.pem.encrypted

# 標準入力から暗号化してファイルへ保存
cat certs/ca.pem | kapsaro encrypt --stdin --out .kapsaro/secrets/ca.pem.encrypted

# 標準入力から暗号化して JSON を標準出力へ送出
cat certs/ca.pem | kapsaro encrypt --stdin --stdout > ca.pem.encrypted
```

暗号化時に電子署名が自動的に付与されます。

### ファイルの復号

```bash
# 署名を検証してファイルへ復号
kapsaro decrypt ca.pem.encrypted --out certs/ca.pem

# 復号結果を標準出力へ送出
kapsaro decrypt ca.pem.encrypted --stdout > certs/ca.pem

# 標準入力から暗号化 JSON を読み込んで復号
cat ca.pem.encrypted | kapsaro decrypt --stdin --stdout > certs/ca.pem
```

> [!WARNING]
> 復号した平文ファイルを Git にコミットしてはなりません。復号先ファイルは必ず `.gitignore` に指定してください。

### メタデータの確認（inspect）

ファイルを復号することなく、メタデータや署名状態を検査できます。

```bash
kapsaro inspect .kapsaro/secrets/default.kvenc
kapsaro inspect ca.pem.encrypted
```

表示される情報:

- 受信者一覧（メンバーハンドルおよび `kid`）
- 署名者および署名キーの `kid`
- 暗号化アルゴリズム
- 作成日時および更新日時
- 開示履歴（除外された受信者の記録）

Signature Verification が `OK`、または JSON 出力の `signature_verification.verified` が `true` であることを確認してください。終了ステータスだけでは署名の有効性を判断できません。アクセスの確認には、KV ストアなら `run -- true`、ファイルなら `decrypt --stdout > /dev/null` も実行します。

### 形式の使い分け

| 対象データ | 推奨形式 | 理由 |
| :--- | :--- | :--- |
| アプリケーション設定値（`.env`） | kv-enc (`set`, `import`) | Git 差分の最小化、キー単位の更新管理 |
| 証明書（PEM） | file-enc (`encrypt`) | バイナリ・複数行データに対応 |
| SSH 秘密鍵 | file-enc (`encrypt`) | 改行・書式を保持 |
| 数十 MB 以上の大容量ファイル | 外部ストレージを推奨 | Base64 エンコードによりデータサイズが約 33% 増加するため |
| 数百 MB 以上の極大ファイル | Git 管理非推奨 | Git リポジトリ自体の肥大化を避けるため |

---

<a id="11-メンバー管理"></a>

## 6. メンバー管理

<a id="メンバー追加の-git-ワークフロー"></a>
<a id="member-addition-git-workflow"></a>

<a id="membership-completion"></a>

### メンバー変更の共通完了手順

`join` の PR をレビューした後は、メンバーの追加・鍵の交換・除外・CI メンバーの登録を、次の手順で完了させます。メンバー情報と、チームで共有するすべての暗号化ファイルを確認してください。

1. レビュー済みの変更を取得します。
   未コミットの変更がないことを確認し、マージされた最新コミットを取得します。
   ```bash
   git status --short
   git pull --ff-only
   ```

2. `rewrap` で受信者を同期します。
   既定では `secrets/` 配下の全ファイルが処理されます。参加メンバーの情報を確認して承認します。
   ```bash
   kapsaro member list
   kapsaro rewrap
   ```
   `secrets/` 外にある暗号化ファイルは `--target` を指定して同期します。
   ```bash
   kapsaro rewrap --target certs/ca.pem.encrypted
   ```

3. 署名と復号を検証します。
   すべての対象ファイルについて、受信者が意図した構成であり、署名が有効で、復号できることを確認します。
   ```bash
   kapsaro member list
   kapsaro inspect .kapsaro/secrets/default.kvenc
   kapsaro member verify --approve
   kapsaro run -- true
   git diff --stat
   git diff -- .kapsaro/members/ .kapsaro/secrets/
   ```
   単体ファイルの場合:
   ```bash
   kapsaro inspect certs/ca.pem.encrypted
   kapsaro decrypt certs/ca.pem.encrypted --stdout > /dev/null
   ```
   各 `inspect` の Signature Verification が `OK`（JSON では `signature_verification.verified` が `true`）であることを確認します。名前付きストアは `-n` を付けてすべて確認してください。鍵の交換・除外を含め、`active` と `incoming` の両方を確認します。

4. 変更をコミットして共有します。
   メンバー昇格、incoming ファイルの削除、暗号化ファイルの更新をまとめてコミットします。
   ```bash
   git add -A -- .kapsaro/members/ .kapsaro/secrets/
   git diff --cached --name-status
   git commit -m "Apply approved member changes and rewrap secrets"
   git push
   ```
   `secrets/` 外の暗号化ファイルも、差分確認とコミット対象への追加に含めます。

5. 利用するメンバーまたは CI ジョブで確認します。
   メンバーは共有したコミットを取得し、復号を確認します。
   ```bash
   git pull --ff-only
   kapsaro member verify --approve
   kapsaro run -- true
   ```
   利用するすべてのストアと単体ファイルを確認します。鍵交換時は [新鍵だけでの検証](#new-key-verification) を、CI では実際のランナーから共有コミットの検証を行います。

<a id="rewrap-recovery"></a>

### rewrap が途中で失敗した場合の復旧手順

`rewrap` の処理が中断したり一部失敗したりした場合:

1. `git status` や `git diff` を確認し、成功したファイルと失敗したファイルを切り分けます。
2. 失敗原因（パーミッション、ロックの競合、マージ競合など）を解消します。
3. 失敗したファイルのみを対象に `--target` を指定して `rewrap` を再実行します。
   ```bash
   kapsaro rewrap --target .kapsaro/secrets/staging.kvenc
   ```
4. 全対象の検証を終えたら、共通完了手順に従ってコミット・共有します。

### 公開鍵ファイルを直接追加する

```bash
# 公開鍵ファイルを incoming へ登録
kapsaro member add bob.public.json

# レビュー用にコミットしてプッシュ
git add .kapsaro/members/incoming/bob@example.com.json
git commit -m "Add bob to kapsaro (incoming)"
git push
```

### メンバーの一覧と検証

```bash
# メンバー一覧を表示（active + incoming）
kapsaro member list

# 特定メンバーの詳細情報を表示
kapsaro member show bob@example.com

# active メンバーを GitHub と照合して承認
kapsaro member verify --approve
```

### ローカル信頼ストアの管理

```bash
# 承認済みキーの一覧を表示
kapsaro trust keys list

# 特定の承認キーを削除
kapsaro trust keys remove <kid>

# レビュー済み受信者セットの一覧を表示
kapsaro trust recipients list

# 180 日以上前の古い承認履歴を一括パージ
kapsaro trust keys purge --older-than 180d --force
kapsaro trust recipients purge --older-than 180d --force

# 信頼ストアの署名を現在の active 鍵へ移行
kapsaro trust resign
```

### メンバーの除外（離脱）

```bash
# 最新状態を取得
git status --short
git pull --ff-only

# メンバーを除外して暗号化ファイルを再ラップ
kapsaro member remove alice@example.com
kapsaro rewrap
```

[共通完了手順](#membership-completion) に従って変更内容をコミット・共有します。

### 除外後のシークレット再発行（ローテーション）

メンバーを除外し、関係するすべてのファイルで `rewrap` を実行すると、そのメンバーが新しい受信者一覧から外れ、内容鍵も更新されます。過去の暗号文や開示済みの値は引き続き利用できるため、次の手順で資格情報自体を再発行します。

1. 離脱メンバーが閲覧できた資格情報を特定します。
2. 発行元でトークン、パスワード、証明書を失効・再発行します。
3. 新しい値を `--stdin` 経由で Kapsaro に反映します。
   ```bash
   kapsaro set API_KEY --stdin
   kapsaro set DATABASE_PASSWORD --stdin
   ```
4. 対象の値をすべて更新し、利用者が共有後の更新を確認したら、必要に応じて開示履歴を消去します。
   ```bash
   kapsaro rewrap --clear-disclosure-history
   ```

開示履歴の消去は、運用上の判断を反映する操作です。資格情報の失効や Git の過去の履歴の削除は行いません。

---

<a id="12-鍵の管理とローテーション"></a>

## 7. 鍵の管理と更新

### 運用の基本原則

- 公開鍵は `.kapsaro/members/` にコミットし、秘密鍵は保護したローカルキーストアに保管する
- Kapsaro 秘密鍵の保護に使う Ed25519 SSH 鍵を、強いパスフレーズなどで保護する
- 侵害が疑われる場合は安全な端末から対応し、該当する SSH 鍵と Kapsaro 鍵を交換する。古い SSH 鍵は登録先で失効させ、各端末の `kapsaro trust keys remove <kid>` で漏洩鍵の承認を削除する

以下の通常の手順は、メンバーの鍵を交換するものです。漏洩が疑われる場合は、漏洩鍵が `active` と `incoming` の両方から外れたことを確認し、関係するすべてのファイルに `rewrap --rotate-key` を実行して、発行元で資格情報を失効させます。同じハンドルの鍵を交換するだけでは、既存のマスター鍵が保持される場合があります。漏洩鍵には、通常の移行用の保管期間を適用しないでください。

### 鍵のステータス

| 状態 | 説明 |
| :--- | :--- |
| active | 新しい操作や署名に使う手元の選択中の鍵。ハンドルごとに 1 つ |
| available | その鍵宛てのファイルを復号できる旧世代の有効鍵 |
| expired | 有効期限を過ぎた鍵。緊急復旧には明示的な許可が必要 |

### 定期的な鍵ローテーション手順

鍵の有効期間は既定で生成から 1 年間です。期限の 30 日前から警告が表示されます。

```bash
# 新しいローカル鍵を生成（自動的に active に設定されます）
kapsaro key new

# 新しい公開鍵をワークスペースの incoming へ申請
kapsaro join

# レビュー用にコミットしてプッシュ
git add .kapsaro/members/incoming/alice@example.com.json
git commit -m "Rotate alice's key"
git push
```

マージ後、[共通完了手順](#membership-completion) に従って `rewrap` を実行し、完了コミットを共有します。

<a id="new-key-verification"></a>

### 新しい鍵単体での復号検証

新鍵が正しく機能しているかを、手元の旧鍵に頼らず独立して検証するには、一時ディレクトリを用いて隔離テストを行います。

```bash
(
  set -eu
  umask 077
  unset KAPSARO_PRIVATE_KEY KAPSARO_KEY_PASSWORD
  source_home="$HOME/.config/kapsaro"
  new_kid='<new_kid_without_hyphens>'
  rotation_check=$(mktemp -d)
  trap 'rm -rf "$rotation_check"' EXIT
  rotation_home="$rotation_check/home"
  mkdir -p "$rotation_home/keys/alice@example.com"
  cp -R "$source_home/keys/alice@example.com/$new_kid" \
    "$rotation_home/keys/alice@example.com/"
  kapsaro key activate "$new_kid" --home "$rotation_home" \
    --member-handle alice@example.com
  kapsaro key list --home "$rotation_home" --member-handle alice@example.com
  git clone <repo-url> "$rotation_check/repo"
  kapsaro member verify --approve --home "$rotation_home" \
    --workspace "$rotation_check/repo/.kapsaro" --member-handle alice@example.com
  kapsaro run --home "$rotation_home" --workspace "$rotation_check/repo/.kapsaro" \
    --member-handle alice@example.com -- true
)
```

通常の鍵更新では、検証後も 1〜3 か月程度は旧鍵を保持し、チームが更新を取得する時間を確保してから削除します。漏洩した鍵は、前述の侵害時の手順で対応してください。

```bash
kapsaro key remove <old_kid>
```

### コンテンツ暗号化鍵のローテーション

内容のマスター鍵（MK）から、ファイルや KV エントリを暗号化する鍵（CEK）を導出します。`secrets/` 配下のファイルで MK を生成し直し、内容を再暗号化するには、次を実行します。

```bash
kapsaro rewrap --rotate-key
```

別の場所の暗号化ファイルは `--target` で指定し、[共通の検証・コミット手順](#membership-completion) を完了させます。受信者の削除時にも MK は自動で更新されます。鍵更新では平文の値を維持するため、発行元サービスのパスワードやトークンは別途再発行します。

---

<a id="ci-setup"></a>

<a id="13-cicd-連携"></a>

## 8. CI/CD 連携

CI ジョブでは、パスワードで保護した秘密鍵を環境変数から読み込めます。ランナーにはワークスペースのチェックアウトが必要ですが、SSH エージェントや事前に用意したローカルキーストアは不要です。

### 運用モデル

環境変数鍵モードで使えるのは `run`、`get`、`decrypt`、`list` と、読み取り専用の診断コマンド `doctor` です。鍵生成、`rewrap`、メンバー管理は開発者の端末で行います。これは CLI コマンドの制限であり、エクスポートした鍵自体には署名能力もあります。

承認記録を保持しない信頼済みジョブでは、`KAPSARO_STRICT_KEY_CHECKING=no` を設定します。読み取り時に手元の鍵承認記録との照合を省略しますが、署名、復号時の鍵所持証明、公開鍵、有効メンバーとしての認可、受信者の整合性は引き続き検証します。既存のローカル状態に安全上の問題がある場合や、信頼ストアが不正な場合はエラーになります。

CI の秘密情報を渡してよいのは、保守担当者がワークフローを管理し、保護されたブランチ・タグまたは信頼済みのマージ後コミットを取得し、ランナーを信頼できて未承認の処理と分離している場合です。フォークや未承認 PR のジョブ、`pull_request_target`、攻撃者が変更できるコードを取得するジョブ、信頼できないランナーには渡さないでください。秘密情報を渡した後も、取得するコードは信頼済みの版に限定します。

### セットアップ手順

#### ステップ 1: CI 専用メンバーの作成

```bash
git status --short
git pull --ff-only
kapsaro key new --member-handle ci@example.com
kapsaro join --member-handle ci@example.com
```

#### ステップ 2: CI メンバーの追加と rewrap

```bash
git add .kapsaro/members/incoming/ci@example.com.json
git commit -m "Add CI member"
git push

# PR マージ後:
git pull --ff-only
kapsaro rewrap
git add -A -- .kapsaro/members/ .kapsaro/secrets/
git commit -m "Rewrap secrets for CI member"
git push
```

[共通完了手順](#membership-completion) に従って受信者と署名を確認し、復号を検証します。`secrets/` 外の暗号化ファイルも共有コミットに含めてください。

#### ステップ 3: CI 用秘密鍵のエクスポート

```bash
kapsaro key export --private --member-handle ci@example.com --out ci-key.txt
```

強力なパスフレーズ（UTF-8 で 20 バイト以上）を設定します。

#### ステップ 4: CI プラットフォームへのシークレット登録

以下の 2 つの環境変数を CI プラットフォームのシークレット設定に登録します。

- `KAPSARO_PRIVATE_KEY`: `ci-key.txt` の内容
- `KAPSARO_KEY_PASSWORD`: エクスポート時に設定したパスフレーズ

登録後は端末上の `ci-key.txt` を削除し、Git、ログ、バックアップにも残さないでください。エクスポートした鍵とパスワードを同じ CI の保管先に保存できますが、その保管先が侵害されると両方が漏洩します。パスワード保護が主に防ぐのは、鍵ファイルだけが漏洩した場合の被害です。

ランナーで共有コミットを使った `kapsaro run -- true` が成功してから、デプロイを実行します。必要な名前付きストアと単体ファイルもすべて確認してください。CI 鍵を交換する場合は、両方の環境変数を更新して新鍵で確認し、古い受信者鍵を除外した暗号化ファイルを共有します。

### GitHub Actions の設定例

この例は Kapsaro を `v0.99.2-beta` に固定し、ダウンロードしたアーカイブの GitHub 証明を検証してから展開・実行します。`main` とランナーは、上記の条件を満たすように設定してください。

```yaml
name: Deploy
on:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4

      - name: Install kapsaro
        shell: bash
        run: |
          set -euo pipefail
          command -v curl
          command -v tar
          command -v gh

          kapsaro_tag=v0.99.2-beta
          kapsaro_archive="kapsaro-${kapsaro_tag}-x86_64-unknown-linux-gnu.tar.gz"
          kapsaro_bundle="kapsaro-${kapsaro_tag}.sigstore.jsonl"
          kapsaro_url="https://github.com/ebisawa/kapsaro/releases/download/${kapsaro_tag}"
          kapsaro_download="$(mktemp -d "${RUNNER_TEMP}/kapsaro-download.XXXXXX")"
          kapsaro_install="$(mktemp -d "${RUNNER_TEMP}/kapsaro-bin.XXXXXX")"
          trap 'rm -rf "${kapsaro_download}"' EXIT

          curl -fsSL "${kapsaro_url}/${kapsaro_archive}" \
            -o "${kapsaro_download}/${kapsaro_archive}"
          curl -fsSL "${kapsaro_url}/${kapsaro_bundle}" \
            -o "${kapsaro_download}/${kapsaro_bundle}"
          gh attestation verify "${kapsaro_download}/${kapsaro_archive}" \
            --bundle "${kapsaro_download}/${kapsaro_bundle}" \
            --repo ebisawa/kapsaro \
            --signer-workflow ebisawa/kapsaro/.github/workflows/release.yml

          tar -xzf "${kapsaro_download}/${kapsaro_archive}" -C "${kapsaro_install}"
          kapsaro_version="$("${kapsaro_install}/kapsaro" --version)"
          printf '%s\n' "${kapsaro_version}"
          if [[ "${kapsaro_version}" != "kapsaro ${kapsaro_tag#v}" ]]; then
            echo "::error::Unexpected kapsaro version"
            exit 1
          fi
          printf '%s\n' "${kapsaro_install}" >> "${GITHUB_PATH}"

      - name: Run with secrets
        env:
          KAPSARO_PRIVATE_KEY: ${{ secrets.KAPSARO_PRIVATE_KEY }}
          KAPSARO_KEY_PASSWORD: ${{ secrets.KAPSARO_KEY_PASSWORD }}
          KAPSARO_STRICT_KEY_CHECKING: "no"
        shell: bash
        run: |
          set -euo pipefail
          kapsaro run -- true
          kapsaro run -- ./deploy.sh
```

---

<a id="10-ワークスペースの健全性確認doctor"></a>

## 9. 診断

`kapsaro doctor` は、ワークスペースの構成、手元の鍵、信頼ストア、アクセス権限を読み取り専用で診断します。

```bash
kapsaro doctor
kapsaro doctor --verbose
kapsaro doctor --workspace .kapsaro --home ~/.config/kapsaro
```

参加 PR のレビュー時、`rewrap` や鍵更新の前後、CI 用の `KAPSARO_PRIVATE_KEY` 設定時に実行してください。リリース前の確認、定期監査、端末の移行、ローカル状態の復旧にも使えます。

診断項目は次のとおりです。

- ワークスペース構造と Git との対応
- active と incoming のメンバー情報、鍵の有効期限、重複する `kid`、GitHub 検証状態
- ローカルキーストアの利用可否と有効な秘密鍵の読み取り
- ローカル信頼ストアの承認状態
- `<KAPSARO_HOME>` 配下の権限と所有者
- 中断された書き込みで残った一時ファイル
- `.kapsaro/secrets/` 配下の暗号化ファイルの完全性と署名
- `KAPSARO_PRIVATE_KEY` に設定した環境変数鍵

### 診断ステータスの見方

| ステータス | 意味 | 対応 |
| :--- | :--- | :--- |
| OK | 検査に合格 | この検査については対応不要 |
| WARN | 確認・承認・鍵更新が必要な可能性あり | 指摘内容と推奨対応を確認 |
| FAIL | 解消が必要な問題あり | 続行前に `Next` の手順で解消 |
| SKIP | 前提条件の不足 | ネットワーク接続などの条件を満たして再実行 |

診断結果に FAIL が含まれると、`doctor` は終了ステータス `1` を返します。検査の成功が示すのは、その検査で確認した範囲です。

### ローカル状態のパーミッション設定

`<KAPSARO_HOME>` は本人だけがアクセスできるようにし、ディレクトリを `0700`、ファイルを `0600` にします。

```bash
chmod -R go-rwx ~/.config/kapsaro
kapsaro doctor
```

---

<a id="14-よくある質問faq"></a>

## 10. 問題解決とよくある質問

### 全般

#### Q: 専用サーバーやクラウド基盤は必要ですか？
専用サービスは不要です。暗号化・復号・署名検証はローカルで行います。任意の GitHub 本人確認にはネットワーク接続が必要です。

#### Q: GPG や PGP の設定は必要ですか？
不要です。手元の鍵保護には Ed25519 SSH 鍵を使い、暗号化用・署名用の鍵は Kapsaro が管理します。

#### Q: チーム共通のマスターパスワードを管理する必要がありますか？
不要です。Kapsaro は内容のマスター鍵を、各受信者の公開鍵を使って HPKE で個別に保護します。

#### Q: `.kapsaro/members/` を GitHub で公開しても安全ですか？
ファイルに含まれるのは公開鍵と識別情報で、秘密鍵は含まれません。チーム共有のためにコミットできますが、リポジトリを公開する前にメンバーの識別情報などの公開範囲を確認してください。

<a id="q-why-is-the-ssh-agent-needed"></a>

#### Q: SSH エージェントはなぜ必要ですか？

SSH エージェントは、SSH 秘密鍵ファイルを Kapsaro に渡さずに署名するために使います。その署名から手元の Kapsaro 鍵を保護・復号します。直接署名する場合は `--ssh-keygen --ssh-identity ~/.ssh/id_ed25519` を指定するか、グローバル設定に `ssh_signing_method = "ssh-keygen"` を保存してください。Windows 側の SSH エージェントを使う場合は [WSL ガイド](wsl_user_guide_ja.md) を参照してください。

<a id="git-conflict-resolution"></a>

### 暗号化ファイルの Git コンフリクト解消手順

#### Q: Git マージ時に暗号化ファイルが競合した場合はどうすればよいですか？

KV ストアはキーごとに値を暗号化しますが、電子署名はファイル全体を対象としています。そのため、並行ブランチで異なるキーを変更した場合でも、署名メタデータ行の変更によって競合が発生します。暗号化されたテキスト行を手作業で結合してはなりません。両方のコミットを一時ブランチに保持した上で、正常なドキュメントを起点に変更操作を再適用します。

通常のマージで競合が発生した場合の解消手順:

1. 両方のコミットを一時ブランチに退避します。
   ```bash
   git status --short
   git branch recovery/local HEAD
   git branch recovery/other MERGE_HEAD
   ```

2. 採用する変更内容に合意します。
   キーの追加・更新・削除についてチーム内で確認・合意します。

3. 起点となる正常なコミットからファイルを復元します。
   ```bash
   base_commit=$(git rev-parse recovery/other)
   git restore --source="$base_commit" --worktree -- .kapsaro/secrets/default.kvenc
   kapsaro inspect .kapsaro/secrets/default.kvenc
   ```
   Signature Verification が `OK` であることを確認します。メンバー構成が異なる場合は先に `rewrap` を実行します。
   ```bash
   kapsaro rewrap --target .kapsaro/secrets/default.kvenc
   ```

4. 他方の変更を `set` と `unset` で再適用します。
   ```bash
   kapsaro set DATABASE_URL --stdin
   kapsaro set API_TOKEN --stdin
   kapsaro unset OLD_KEY
   ```

5. 検証してマージを完了します。
   ```bash
   kapsaro inspect .kapsaro/secrets/default.kvenc
   kapsaro list
   kapsaro run -- true
   git add -A -- .kapsaro/members/ .kapsaro/secrets/
   git commit -m "Merge approved secret changes"
   git push
   ```

---

<a id="15-コマンドリファレンス"></a>

## 11. コマンド・設定リファレンス

### 共通オプション

| オプション | 説明 |
| :--- | :--- |
| `--home <path>` | ローカル状態ディレクトリを指定（既定: `~/.config/kapsaro/`） |
| `-w` / `--workspace <path>` | ワークスペースのルートパスを指定 |
| `-m` / `--member-handle <handle>` | 使用するメンバーハンドルを指定 |
| `-i` / `--ssh-identity <path>` | Ed25519 SSH 秘密鍵、またはエージェント署名で使う公開鍵ファイルのパス |
| `--ssh-agent` | `ssh-agent` による署名を強制 |
| `--ssh-keygen` | `ssh-keygen` コマンドによる署名を強制 |
| `--json` | 構造化 JSON 形式で出力 |
| `-q` / `--quiet` | 成功メッセージ等の出力を抑制 |
| `-v` / `--verbose` | 詳細な診断・実行情報を表示 |
| `--debug` | 内部デバッグトレースログを出力 |
| `-n` / `--name <name>` | 名前付き KV ストアを選択（既定: `default`） |
| `-f` / `--force` | 対応するコマンドの確認プロンプトを省略 |
| `--allow-expired-key` | 期限切れ鍵による緊急復号・検証を許可 |

### カテゴリ別コマンド一覧

| カテゴリ | コマンド | 説明 |
| :--- | :--- | :--- |
| 初期設定 | `kapsaro init` | ワークスペースを初期化し、初期メンバーを登録 |
| | `kapsaro join` | 既存ワークスペースへの参加申請を作成 |
| KV 操作 | `kapsaro set <KEY> <VALUE>` | シークレットを追加または更新 |
| | `kapsaro set <KEY> --stdin` | 標準入力からシークレットを入力 |
| | `kapsaro get <KEY>` | 特定のシークレットを復号して表示 |
| | `kapsaro get --all` | すべてのシークレットを復号して表示 |
| | `kapsaro unset <KEY>` | キーをストアから削除 |
| | `kapsaro list` | シークレットを復号せずにキー名一覧を表示 |
| | `kapsaro import <file>` | 既存の `.env` ファイルを一括インポート |
| | `kapsaro run -- <cmd>` | シークレットを環境変数として注入してコマンドを実行 |
| ファイル操作 | `kapsaro encrypt <file>` | 任意ファイルを暗号化（file-enc 形式） |
| | `kapsaro decrypt <file>` | 暗号化ファイルを復号 |
| | `kapsaro inspect <file>` | 暗号化ファイルのメタデータ・署名・受信者を検査 |
| 診断 | `kapsaro doctor` | ワークスペース、鍵、信頼ストアの健全性を診断 |
| メンバー管理 | `kapsaro member list` | 全メンバーと各キー ID を一覧表示 |
| | `kapsaro member show <handle>` | 特定メンバーの詳細情報を表示 |
| | `kapsaro member verify --approve` | メンバー公開鍵を GitHub と照合して承認 |
| | `kapsaro member add <file>` | 公開鍵ファイルを `members/incoming/` に追加 |
| | `kapsaro member remove <handle>` | メンバーをワークスペースから除外 |
| | `kapsaro rewrap` | 受信者情報を同期し、未承認メンバーを昇格 |
| 信頼ストア | `kapsaro trust keys list` | ローカル信頼ストア内の承認済み鍵を表示 |
| | `kapsaro trust keys remove <kid>` | 特定の承認記録を削除 |
| | `kapsaro trust recipients list` | レビュー済み受信者セットを表示 |
| | `kapsaro trust resign` | 信頼ストアの署名を現在の有効鍵で再署名 |
| 鍵管理 | `kapsaro key new` | 新しいローカル鍵ペアを生成 |
| | `kapsaro key list` | 手元の鍵一覧とステータスを表示 |
| | `kapsaro key activate <kid>` | 現在の有効鍵を切り替え |
| | `kapsaro key remove <kid>` | ローカル鍵を削除 |
| | `kapsaro key export` | 公開鍵ドキュメントをエクスポート |
| | `kapsaro key export --private` | CI/CD 用に暗号化秘密鍵をエクスポート |
| 設定管理 | `kapsaro config set <k> <v>` | グローバル設定値を設定 |
| | `kapsaro config get <k>` | グローバル設定値を取得 |
| | `kapsaro config list` | すべてのグローバル設定値を一覧表示 |

---

<a id="16-設定リファレンス"></a>

### 設定の優先順位

Kapsaro は以下の優先順位に従って設定値を解決します。

1. CLI オプション（最優先）
2. 環境変数
3. 設定ファイル（`~/.config/kapsaro/config.toml`）
4. 組み込みの既定値（最低優先）

### 設定ファイル（`config.toml`）

```toml
member_handle = "alice@example.com"
workspace = "~/src/project/.kapsaro"
ssh_identity = "~/.ssh/id_ed25519"
ssh_signing_method = "auto"
github_user = "alice-gh"
allow_expired_key = "no"
allow_non_member = "no"
```

### 環境変数一覧

| 環境変数 | 説明 | 既定値 |
| :--- | :--- | :--- |
| `KAPSARO_HOME` | 設定・キーストア・信頼ストアの保存先ディレクトリ | `~/.config/kapsaro/` |
| `KAPSARO_MEMBER_HANDLE` | 既定のメンバーハンドル | （未設定） |
| `KAPSARO_SSH_IDENTITY` | Ed25519 SSH 秘密鍵、またはエージェント署名で使う公開鍵ファイルのパス | `~/.ssh/id_ed25519` |
| `KAPSARO_SSH_SIGNING_METHOD` | SSH 署名方式（`auto`, `ssh-agent`, `ssh-keygen`） | `auto` |
| `KAPSARO_GITHUB_USER` | 新しく生成する公開鍵に関連付ける GitHub ログイン名の既定値 | （未設定） |
| `KAPSARO_WORKSPACE` | ワークスペースの明示的ルートパス | （自動検出） |
| `KAPSARO_STRICT_KEY_CHECKING` | 読み取り時のローカル信頼ストア照合を強制（`yes`, `no`） | `yes` |
| `KAPSARO_ALLOW_EXPIRED_KEY` | 期限切れ鍵による緊急復号を許可（`yes`, `no`） | `no` |
| `KAPSARO_ALLOW_NON_MEMBER` | 対応する読み取りコマンドで非メンバー署名の一時承認を許可。`run` は常に拒否 | `no` |
| `KAPSARO_PRIVATE_KEY` | CI/CD 環境用の可搬秘密鍵ドキュメント | （未設定） |
| `KAPSARO_KEY_PASSWORD` | `KAPSARO_PRIVATE_KEY` の復号パスフレーズ | （未設定） |

---

<a id="3-よく使う用語"></a>

## 12. 用語集

### ワークスペース

メンバーの公開鍵と暗号化ファイルを置くディレクトリで、通常は `.kapsaro/` です。Git 管理下ではリポジトリのルートにあるワークスペースを、Git 管理外ではカレントディレクトリ直下の `.kapsaro/` を自動検出します。別の場所は `-w` / `--workspace` で指定します。

### `active` と `incoming`

ワークスペースの `incoming` にはレビュー待ちの鍵を、`active` には承認済み受信者の公開鍵を置きます。ローカルキーストアでも、そのメンバーが現在選択している鍵を active と呼びます。

### `rewrap`

メンバーや鍵の変更に合わせて暗号化ファイルの受信者を同期し、承認した incoming の鍵を active に昇格する操作です。受信者の削除時、または `--rotate-key` 指定時には、内容の暗号化に使うマスター鍵も生成し直して全内容を再暗号化します。

### メンバーハンドル

`alice@example.com` のように、メンバーを識別するために付ける名前です。メールアドレス形式でも実在するアドレスである必要はなく、外部で確認された本人情報を意味しません。

### `kid`（キー ID）

公開鍵から導出する識別子です。鍵更新中に複数世代の鍵を保持するとき、どの鍵かを区別します。

### ローカル信頼ストア

`~/.config/kapsaro/trust/` に保存する署名付きの記録です。`known_keys` は確認・承認した鍵の所有者を、`recipient_sets` はレビューした受信者の組み合わせを記録します。`member verify --approve` などで承認を保存し、同じ確認を繰り返す手間を減らします。現在のワークスペースでのアクセス許可は `members/active/` が定めます。
