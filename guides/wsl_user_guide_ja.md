# Windows / WSL2 ユーザー向け補足ガイド

kapsaro は、Windows 環境において **WSL2 (Windows Subsystem for Linux)** を利用することで、通常の Linux と同様にインストールおよび利用が可能です。

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

1. **`ssh-keygen` コマンドを使って SSH 署名を行う**
   署名の生成自体は `ssh-keygen` コマンドを使って行うため、署名方式として `ssh-keygen` を指定します。

2. **`ssh_keygen_command` に `.exe` をつける**
   WSL2 から Windows 側の `ssh-keygen.exe` を呼び出すことで、Windows 側で動作している 1Password SSH agent と連携して署名を行います。そのため、コマンド名として `.exe` をつけた `ssh-keygen.exe` を指定します。

3. **`ssh_identity` として、署名に使いたい SSH 鍵（1Password 内の SSH 鍵）をファイルに保存し、そのファイル名を指定する**
   署名に使いたい SSH 鍵（1Password 内の SSH 鍵）の **公開鍵** をあらかじめ WSL 内のファイルとして保存しておき、そのファイルパスを `ssh_identity` に指定します。

## 参考資料

WSL2 と 1Password SSH agent の連携に関する詳細なセットアップ手順については、1Password の公式ドキュメントをご参照ください。

- [Use the 1Password SSH agent with WSL | 1Password Developer](https://developer.1password.com/docs/ssh/integrations/wsl/)
