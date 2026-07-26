# Windows / WSL2 ユーザー向け補足ガイド

kapsaro は、Windows 環境において WSL2 (Windows Subsystem for Linux) を利用することで、通常の Linux と同様にインストールおよび利用が可能です。

本ドキュメントは、主に `guides/user_guide_ja.md` / `guides/user_guide_en.md` を補足する目的で、Windows / WSL2 特有の注意点と推奨設定の例をまとめたものです。

## WSL2 で 1Password の SSH agent を利用する

WSL2 環境において 1Password の SSH agent を利用する場合、kapsaro の設定で以下のように指定します。

```toml
ssh_identity = "/home/<username>/.ssh/<your-ssh-public-key>.pub"
ssh_keygen_command = "ssh-keygen.exe"
ssh_signing_method = "ssh-keygen"
```

*(※ `username` やファイル名は実際の環境に合わせて変更してください。)*

### `kapsaro config set` で推奨設定を投入する例

以下は、上記の推奨設定を CLI から投入する例です。

```bash
kapsaro config set ssh_identity ~/.ssh/<your-ssh-public-key>.pub
kapsaro config set ssh_keygen_command ssh-keygen.exe
kapsaro config set ssh_signing_method ssh-keygen
```

### 設定のポイント

#### `ssh-keygen` コマンドで署名する

署名の生成自体は `ssh-keygen` コマンドが行うため、署名方式として `ssh-keygen` を指定します。

#### `ssh_keygen_command` には `.exe` をつける

WSL2 から Windows 側の `ssh-keygen.exe` を呼び出すことで、Windows 側で動作している 1Password SSH agent と連携して署名を行います。`.exe` がないと Linux 側のバイナリが実行され、エージェントに到達できません。

#### `ssh_identity` には公開鍵ファイルを指定する

署名に使いたい SSH 鍵、すなわち 1Password 内にある鍵の公開鍵を、あらかじめ WSL 内のファイルとして保存し、そのファイルパスを `ssh_identity` に指定します。秘密鍵は 1Password 内に留まります。

## ワークスペースの配置場所

ワークスペースと `KAPSARO_HOME` は `/mnt/c` 配下ではなく、Linux 側のホームディレクトリ、すなわち WSL2 のファイルシステム上に置きます。

`/mnt/c` 配下のパスは、変換層を介して見えている Windows ボリュームです。この層が報告するパーミッションは実際の POSIX モードに対応しないため、kapsaro がキーストアとローカル信頼ストアに対して行う所有者限定の検査では、保護されたファイルと誰でも読めるファイルを区別できません。セキュリティ設計はこのパーミッションを運用上の責任として扱いますが、`/mnt/c` 上には依拠すべき実体がありません。

ワークスペースを移動したら `kapsaro doctor` を実行してください。検証可能なパーミッション連鎖が報告されます。

## 参考資料

WSL2 と 1Password SSH agent の連携に関する詳細なセットアップ手順については、1Password の公式ドキュメントをご参照ください。

- [Use the 1Password SSH agent with WSL | 1Password Developer](https://developer.1password.com/docs/ssh/integrations/wsl/)
