# Windows / WSL2 ユーザー向け補足ガイド

Windows では、WSL2（Windows Subsystem for Linux）内で Kapsaro を利用します。この補足ガイドは[ユーザーガイド](user_guide_ja.md)に加え、保存場所の要件と、Windows 側の 1Password SSH エージェントを使うための設定を説明します。

## ワークスペースの配置場所

ワークスペースと、ローカルの鍵や設定を保存する `KAPSARO_HOME` は、WSL2 の Linux ファイルシステム上に置いてください。たとえば Linux 側のホームディレクトリ（`~` 配下）を使います。

Kapsaro は、ローカルの鍵や状態を OS のファイルアクセス権限で保護します。`/mnt/c` などにマウントした Windows ボリュームは変換層を介しており、[既定のアクセス権限の扱いが Linux と異なります](https://learn.microsoft.com/en-us/windows/wsl/file-permissions)。Windows ファイルシステム上でのワークスペース運用はサポート対象外です。

<a id="ssh_identity-には公開鍵ファイルのパスを指定する"></a>
## 公開鍵を準備する

Windows 側で 1Password SSH エージェントを有効にし、Ed25519 SSH 鍵を利用できる状態にします。公開鍵を WSL 内のファイルに保存し、そのパスを `ssh_identity` に指定してください。秘密鍵は 1Password 内に保持します。

Windows 側の署名プログラムを WSL から実行でき、そのプログラムが渡された公開鍵のパスを読み取れる必要があります。Kapsaro はパスを Windows 形式に変換せずに渡すため、設定を使う前に、その環境でパスにアクセスできることを確認してください。

<a id="wsl2-で-1password-の-ssh-エージェントを利用する"></a>
## Kapsaro を設定する

次の設定は、Windows 側の `ssh-keygen.exe` と公開鍵ファイルを指定する例です。`<username>` とファイル名は、自分の環境に合わせて置き換えてください。

```toml
ssh_identity = "/home/<username>/.ssh/<your-ssh-public-key>.pub"
ssh_keygen_command = "ssh-keygen.exe"
ssh_signing_method = "ssh-keygen"
```

<a id="kapsaro-config-set-で推奨設定を適用する例"></a>
### CLI で設定する

同じ値を `kapsaro config set` で設定することもできます。実行前にファイル名を置き換えてください。

```bash
kapsaro config set ssh_identity ~/.ssh/<your-ssh-public-key>.pub
kapsaro config set ssh_keygen_command ssh-keygen.exe
kapsaro config set ssh_signing_method ssh-keygen
```

<a id="設定のポイント"></a>
## 署名方式の説明

<a id="ssh-keygen-コマンドで署名する"></a>
### `ssh-keygen` で署名を依頼する

`ssh_signing_method = "ssh-keygen"` を指定すると、Kapsaro は `ssh-keygen -Y sign` を呼び出します。`ssh_identity` が公開鍵ファイルを指す場合、コマンドは対応する秘密鍵を持つエージェントに署名を依頼します。公開鍵は鍵を特定するためのもので、公開鍵だけでは署名できません。

<a id="ssh_keygen_command-には必ず-exe-を付与する"></a>
### Windows 側の実行ファイルを選ぶ

`ssh_keygen_command` には `.exe` を付け、Windows 側の実行ファイルを選びます。WSL の相互運用機能を使って Windows 側のプログラムを実行します。Linux 版の `ssh-keygen` は Linux 側のエージェント設定を使うため、Windows 側のエージェントに接続するには別途中継の設定が必要です。

Windows 側の実行ファイルが `-Y sign` に対応し、指定した公開鍵ファイルを読み取り、1Password に署名を依頼できることを確認してください。設定値を保存するだけでは、これらの環境要件を満たすかは確認できません。

## 参考資料

Windows 側のエージェント設定と WSL の相互運用機能は、1Password 公式ガイドを参照してください。同ガイドの Git コミット署名設定は 1Password 専用の署名プログラムを使っており、上記の Kapsaro 設定がすべての環境で動作することを示すものではありません。

- [Use the 1Password SSH agent with WSL | 1Password Developer](https://developer.1password.com/docs/ssh/integrations/wsl/)
