# Windows / WSL2 Supplemental Guide

On Windows, you can install and use kapsaro in a **WSL2 (Windows Subsystem for Linux)** environment just like on a normal Linux system.

This document is intended as a **supplement** to `guides/user_guide_en.md` / `guides/user_guide_ja.md`, and summarizes Windows/WSL2-specific notes and recommended configuration examples.

## Using the 1Password SSH agent on WSL2

If you want to use the 1Password SSH agent from WSL2, configure kapsaro as follows:

```toml
ssh_identity = "/home/<username>/.ssh/<your-ssh-public-key>.pub"
ssh_keygen_command = "ssh-keygen.exe"
ssh_signing_method = "ssh-keygen"
```

*(Replace `username` and the file name to match your environment.)*

### Example: applying the recommended settings via `kapsaro config set`

Below is an example of setting the recommended values via the CLI.

```bash
kapsaro config set ssh_identity ~/.ssh/<your-ssh-public-key>.pub
kapsaro config set ssh_keygen_command ssh-keygen.exe
kapsaro config set ssh_signing_method ssh-keygen
```

### Key points

1. **Use `ssh-keygen` to perform SSH signing**
   Signing is performed via the `ssh-keygen` command, so set the signing method to `ssh-keygen`.

2. **Set `ssh_keygen_command` to `ssh-keygen.exe` (with `.exe`)**
   From WSL2, calling `ssh-keygen.exe` runs the Windows binary, which can integrate with the 1Password SSH agent running on the Windows host.

3. **Set `ssh_identity` to the public key file you want to use for signing**
   Save the **public key** of the SSH key you want to use for signing (stored in 1Password) as a file inside WSL, and point `ssh_identity` to that file path.

## References

For detailed setup steps for integrating WSL2 with the 1Password SSH agent, refer to the official 1Password documentation.

- [Use the 1Password SSH agent with WSL | 1Password Developer](https://developer.1password.com/docs/ssh/integrations/wsl/)
