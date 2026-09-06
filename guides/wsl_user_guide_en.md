# Windows / WSL2 Supplemental Guide

On Windows, run Kapsaro inside WSL2 (Windows Subsystem for Linux). This supplement to the [User Guide](user_guide_en.md) covers storage requirements and using the 1Password SSH agent on the Windows host.

## Workspace Storage Location

Place workspaces and `KAPSARO_HOME`, the directory for local keys and settings, on the WSL2 Linux filesystem, for example under your Linux home directory (`~`).

Kapsaro relies on operating system file permissions to protect local keys and state. Windows volumes mounted under paths such as `/mnt/c` use a filesystem translation layer, whose [default permission behavior differs from Linux](https://learn.microsoft.com/en-us/windows/wsl/file-permissions). Workspaces on the Windows host filesystem are unsupported.

<a id="point-ssh_identity-to-the-public-key-file"></a>
## Prepare the Public Key

Enable the 1Password SSH agent on the Windows host and make an Ed25519 SSH key available to it. Export the public key to a file inside WSL, and set `ssh_identity` to that file. The private key stays in 1Password.

The Windows signing executable must be available from WSL and able to read the public key path supplied to it. Kapsaro passes that path to the executable without converting it to a Windows path; check path access in your environment before using this configuration.

<a id="using-the-1password-ssh-agent-on-wsl2"></a>
## Configure Kapsaro

The following settings select the Windows `ssh-keygen.exe` executable and the public key file. Replace `<username>` and the filename with values for your environment.

```toml
ssh_identity = "/home/<username>/.ssh/<your-ssh-public-key>.pub"
ssh_keygen_command = "ssh-keygen.exe"
ssh_signing_method = "ssh-keygen"
```

<a id="applying-recommended-settings-via-kapsaro-config-set"></a>
### Apply Settings with the CLI

Alternatively, set the same values with `kapsaro config set`. Replace the filename before running these commands.

```bash
kapsaro config set ssh_identity ~/.ssh/<your-ssh-public-key>.pub
kapsaro config set ssh_keygen_command ssh-keygen.exe
kapsaro config set ssh_signing_method ssh-keygen
```

<a id="key-configuration-points"></a>
## How Signing Works

<a id="sign-via-ssh-keygen"></a>
### Sign Through `ssh-keygen`

With `ssh_signing_method = "ssh-keygen"`, Kapsaro calls `ssh-keygen -Y sign`. When `ssh_identity` points to a public key file, the command asks the agent holding the corresponding private key to sign. The public key identifies the key; it cannot produce a signature by itself.

<a id="retain-the-exe-suffix-for-ssh_keygen_command"></a>
### Select the Windows Executable

Keep the `.exe` suffix in `ssh_keygen_command` to select the Windows executable. This uses WSL interoperability to reach a program on the Windows host. The Linux `ssh-keygen` executable uses the Linux agent setup and needs a separate forwarding arrangement to reach a Windows agent.

Check that your Windows executable supports `-Y sign`, can read the selected public key file, and can request a signature from 1Password. The settings alone do not verify these environment requirements.

## References

The official 1Password guide explains Windows agent setup and WSL interoperability. Its Git commit-signing configuration uses a separate 1Password signing program; it does not establish that the Kapsaro configuration above works in every environment.

- [Use the 1Password SSH agent with WSL | 1Password Developer](https://developer.1password.com/docs/ssh/integrations/wsl/)
