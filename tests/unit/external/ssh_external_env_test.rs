// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use secretenv::io::ssh::external::add::DefaultSshAdd;
use secretenv::io::ssh::external::keygen::DefaultSshKeygen;
use secretenv::io::ssh::external::traits::SshAdd;
use secretenv::io::ssh::external::traits::SshKeygen;
use secretenv::io::ssh::protocol::constants::KEY_PROTECTION_NAMESPACE;
use secretenv::io::ssh::protocol::parse::decode_ssh_public_key_blob;
use secretenv::io::ssh::protocol::wire::encode_ssh_string;
use secretenv::support::codec::base64_public::encode_base64_standard;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;

use crate::test_utils::{generate_temp_ssh_keypair_in_dir, EnvGuard};

fn setup_env_dump_script() -> (TempDir, String) {
    let temp_dir = TempDir::new().unwrap();
    let script_path = temp_dir.path().join("dump-env.sh");
    fs::write(&script_path, "#!/bin/sh\nenv\n").unwrap();
    let mut perms = fs::metadata(&script_path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&script_path, perms).unwrap();
    (temp_dir, script_path.to_string_lossy().into_owned())
}

fn setup_ssh_wrapper_script(name: &str, body: &str) -> (TempDir, String) {
    let temp_dir = TempDir::new().unwrap();
    let script_path = temp_dir.path().join(name);
    fs::write(&script_path, body).unwrap();
    let mut perms = fs::metadata(&script_path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&script_path, perms).unwrap();
    (temp_dir, script_path.to_string_lossy().into_owned())
}

fn build_test_sshsig_armored(raw_sig: [u8; 64], ssh_pubkey: &str) -> String {
    let mut sshsig_blob = Vec::new();
    sshsig_blob.extend_from_slice(b"SSHSIG");
    sshsig_blob.extend_from_slice(&1u32.to_be_bytes());
    let publickey = decode_ssh_public_key_blob(ssh_pubkey).unwrap();
    sshsig_blob.extend_from_slice(&encode_ssh_string(&publickey));
    sshsig_blob.extend_from_slice(&encode_ssh_string(KEY_PROTECTION_NAMESPACE.as_bytes()));
    sshsig_blob.extend_from_slice(&encode_ssh_string(b""));
    sshsig_blob.extend_from_slice(&encode_ssh_string(b"sha256"));

    let mut signature_blob = Vec::new();
    signature_blob.extend_from_slice(&encode_ssh_string(b"ssh-ed25519"));
    signature_blob.extend_from_slice(&encode_ssh_string(&raw_sig));
    sshsig_blob.extend_from_slice(&encode_ssh_string(&signature_blob));

    format!(
        "-----BEGIN SSH SIGNATURE-----\n{}\n-----END SSH SIGNATURE-----\n",
        encode_base64_standard(&sshsig_blob)
    )
}

#[test]
fn test_load_ssh_public_key_from_keygen_uses_sanitized_env_with_optional_socket() {
    let _guard = EnvGuard::new(&[
        "HOME",
        "PATH",
        "SSH_AUTH_SOCK",
        "SECRETENV_PRIVATE_KEY",
        "CUSTOM_PARENT_ENV",
    ]);
    let fake_home = TempDir::new().unwrap();
    std::env::set_var("HOME", fake_home.path());
    std::env::set_var("PATH", "/usr/bin");
    std::env::set_var("SSH_AUTH_SOCK", "/tmp/agent.sock");
    std::env::set_var("SECRETENV_PRIVATE_KEY", "sensitive");
    std::env::set_var("CUSTOM_PARENT_ENV", "parent-value");

    let (_script_dir, script_path) = setup_env_dump_script();
    let output = DefaultSshKeygen::new(&script_path)
        .derive_public_key(std::path::Path::new("/tmp/test-key"))
        .unwrap();

    assert!(output.contains("PATH=/usr/bin"));
    assert!(output.contains("SSH_AUTH_SOCK=/tmp/agent.sock"));
    assert!(output.contains("CUSTOM_PARENT_ENV=parent-value"));
    assert!(!output.contains("SECRETENV_PRIVATE_KEY=sensitive"));
}

#[test]
fn test_default_ssh_add_sets_resolved_socket_without_inheriting_secret_env() {
    let _guard = EnvGuard::new(&[
        "HOME",
        "PATH",
        "SSH_AUTH_SOCK",
        "SECRETENV_PRIVATE_KEY",
        "CUSTOM_PARENT_ENV",
    ]);
    let fake_home = TempDir::new().unwrap();
    std::env::set_var("HOME", fake_home.path());
    std::env::set_var("PATH", "/usr/bin");
    std::env::set_var("SSH_AUTH_SOCK", "/tmp/agent.sock");
    std::env::set_var("SECRETENV_PRIVATE_KEY", "sensitive");
    std::env::set_var("CUSTOM_PARENT_ENV", "parent-value");

    let (_script_dir, script_path) = setup_env_dump_script();
    let ssh_add = DefaultSshAdd::new(script_path);
    let output = ssh_add.list_keys().unwrap();

    assert!(output.contains("PATH=/usr/bin"));
    assert!(output.contains("SSH_AUTH_SOCK=/tmp/agent.sock"));
    assert!(output.contains("CUSTOM_PARENT_ENV=parent-value"));
    assert!(!output.contains("SECRETENV_PRIVATE_KEY=sensitive"));
}

#[test]
fn test_default_ssh_add_reports_nonzero_stderr() {
    let _guard = EnvGuard::new(&["HOME", "PATH", "SSH_AUTH_SOCK"]);
    let fake_home = TempDir::new().unwrap();
    std::env::set_var("HOME", fake_home.path());
    std::env::set_var("PATH", "/usr/bin");
    std::env::set_var("SSH_AUTH_SOCK", "/tmp/agent.sock");

    let (_script_dir, script_path) = setup_ssh_wrapper_script(
        "ssh-add-wrapper.sh",
        "#!/bin/sh\n\
echo 'agent down sentinel' >&2\n\
exit 42\n",
    );

    let err = DefaultSshAdd::new(script_path)
        .list_keys()
        .unwrap_err()
        .to_string();

    assert!(err.contains("ssh-add -L failed"));
    assert!(err.contains("agent down sentinel"));
}

#[test]
fn test_default_ssh_add_reports_invalid_utf8_stdout() {
    let _guard = EnvGuard::new(&["HOME", "PATH", "SSH_AUTH_SOCK"]);
    let fake_home = TempDir::new().unwrap();
    std::env::set_var("HOME", fake_home.path());
    std::env::set_var("PATH", "/usr/bin");
    std::env::set_var("SSH_AUTH_SOCK", "/tmp/agent.sock");

    let (_script_dir, script_path) = setup_ssh_wrapper_script(
        "ssh-add-wrapper.sh",
        "#!/bin/sh\n\
printf '\\377'\n",
    );

    let err = DefaultSshAdd::new(script_path)
        .list_keys()
        .unwrap_err()
        .to_string();

    assert!(err.contains("Invalid UTF-8 in ssh-add output"));
}

#[test]
fn test_default_ssh_add_requires_resolved_agent_socket() {
    let _guard = EnvGuard::new(&["HOME", "PATH", "SSH_AUTH_SOCK"]);
    let fake_home = TempDir::new().unwrap();
    std::env::set_var("HOME", fake_home.path());
    std::env::set_var("PATH", "/usr/bin");
    std::env::remove_var("SSH_AUTH_SOCK");

    let err = DefaultSshAdd::new("/should/not/run")
        .list_keys()
        .unwrap_err()
        .to_string();

    assert!(err.contains("SSH_AUTH_SOCK") || err.contains("IdentityAgent"));
}

#[test]
fn test_default_ssh_keygen_sign_uses_stdin_stdout_without_sig_file() {
    let temp_dir = TempDir::new().unwrap();
    let ssh_dir = TempDir::new().unwrap();
    let (ssh_priv, _ssh_pub, ssh_pub_content) = generate_temp_ssh_keypair_in_dir(&ssh_dir);

    let script_path = temp_dir.path().join("ssh-keygen-wrapper.sh");
    fs::write(
        &script_path,
        "#!/bin/sh\n\
if [ \"$#\" -ne 8 ]; then\n\
  echo \"unexpected arg count: $#\" >&2\n\
  exit 9\n\
fi\n\
if [ \"$1\" != \"-Y\" ] || [ \"$2\" != \"sign\" ] || [ \"$3\" != \"-f\" ] || [ \"$5\" != \"-n\" ] || [ \"$7\" != \"-O\" ]; then\n\
  echo \"unexpected args\" >&2\n\
  exit 10\n\
fi\n\
input=$(/bin/cat)\n\
if [ \"$input\" != \"stdin-signature-test\" ]; then\n\
  echo \"stdin mismatch\" >&2\n\
  exit 11\n\
fi\n\
exec /usr/bin/ssh-keygen \"$@\"\n",
    )
    .unwrap();
    let mut perms = fs::metadata(&script_path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&script_path, perms).unwrap();

    let signature = DefaultSshKeygen::new(script_path.to_string_lossy().into_owned())
        .sign(
            &ssh_priv,
            KEY_PROTECTION_NAMESPACE,
            &ssh_pub_content,
            b"stdin-signature-test",
        )
        .unwrap();

    assert_eq!(signature.as_bytes().len(), 64);
}

#[test]
fn test_default_ssh_keygen_sign_with_public_key_uses_agent_stdin_stdout() {
    let _guard = EnvGuard::new(&["HOME", "PATH", "SSH_AUTH_SOCK", "SECRETENV_PRIVATE_KEY"]);
    let fake_home = TempDir::new().unwrap();
    std::env::set_var("HOME", fake_home.path());
    std::env::set_var("PATH", "/usr/bin");
    std::env::set_var("SSH_AUTH_SOCK", "/tmp/agent.sock");
    std::env::set_var("SECRETENV_PRIVATE_KEY", "sensitive");

    let temp_dir = TempDir::new().unwrap();
    let ssh_dir = TempDir::new().unwrap();
    let (_ssh_priv, ssh_pub, ssh_pub_content) = generate_temp_ssh_keypair_in_dir(&ssh_dir);

    let mut expected_raw_sig = [0u8; 64];
    for (index, byte) in expected_raw_sig.iter_mut().enumerate() {
        *byte = index as u8;
    }
    let armored = build_test_sshsig_armored(expected_raw_sig, &ssh_pub_content);

    let script_path = temp_dir.path().join("ssh-keygen-wrapper.sh");
    let script = format!(
        "#!/bin/sh\n\
if [ \"$#\" -ne 8 ]; then\n\
  echo \"unexpected arg count: $#\" >&2\n\
  exit 20\n\
fi\n\
if [ \"$1\" != \"-Y\" ] || [ \"$2\" != \"sign\" ] || [ \"$3\" != \"-f\" ] || [ \"$5\" != \"-n\" ] || [ \"$6\" != \"{namespace}\" ] || [ \"$7\" != \"-O\" ] || [ \"$8\" != \"hashalg=sha256\" ]; then\n\
  echo \"unexpected args\" >&2\n\
  exit 21\n\
fi\n\
if [ \"$4\" != \"{pub_path}\" ]; then\n\
  echo \"unexpected pubkey path: $4\" >&2\n\
  exit 22\n\
fi\n\
if [ \"${{SSH_AUTH_SOCK:-}}\" != \"/tmp/agent.sock\" ]; then\n\
  echo \"missing SSH_AUTH_SOCK\" >&2\n\
  exit 23\n\
fi\n\
if [ \"${{SECRETENV_PRIVATE_KEY:-}}\" = \"sensitive\" ]; then\n\
  echo \"secret env leaked\" >&2\n\
  exit 24\n\
fi\n\
input=$(/bin/cat)\n\
if [ \"$input\" != \"public-key-agent-signature-test\" ]; then\n\
  echo \"stdin mismatch\" >&2\n\
  exit 25\n\
fi\n\
/bin/cat <<'EOF'\n\
{armored}EOF\n",
        namespace = KEY_PROTECTION_NAMESPACE,
        pub_path = ssh_pub.display(),
        armored = armored,
    );
    fs::write(&script_path, script).unwrap();
    let mut perms = fs::metadata(&script_path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&script_path, perms).unwrap();

    let signature = DefaultSshKeygen::new(script_path.to_string_lossy().into_owned())
        .sign(
            &ssh_pub,
            KEY_PROTECTION_NAMESPACE,
            &ssh_pub_content,
            b"public-key-agent-signature-test",
        )
        .unwrap();

    assert_eq!(signature.as_bytes(), &expected_raw_sig);
}

#[test]
fn test_default_ssh_keygen_verify_uses_sanitized_env_and_stdin() {
    let _guard = EnvGuard::new(&["HOME", "PATH", "SSH_AUTH_SOCK", "SECRETENV_PRIVATE_KEY"]);
    let fake_home = TempDir::new().unwrap();
    std::env::set_var("HOME", fake_home.path());
    std::env::set_var("PATH", "/usr/bin");
    std::env::set_var("SSH_AUTH_SOCK", "/tmp/agent.sock");
    std::env::set_var("SECRETENV_PRIVATE_KEY", "sensitive");

    let temp_dir = TempDir::new().unwrap();
    let script_path = temp_dir.path().join("ssh-keygen-verify-wrapper.sh");
    fs::write(
        &script_path,
        "#!/bin/sh\n\
if [ \"$#\" -ne 10 ]; then\n\
  echo \"unexpected arg count: $#\" >&2\n\
  exit 30\n\
fi\n\
if [ \"$1\" != \"-Y\" ] || [ \"$2\" != \"verify\" ] || [ \"$3\" != \"-f\" ] || [ \"$5\" != \"-I\" ] || [ \"$7\" != \"-n\" ] || [ \"$9\" != \"-s\" ]; then\n\
  echo \"unexpected args\" >&2\n\
  exit 31\n\
fi\n\
if [ \"$6\" != \"secretenv-key-protection\" ] || [ \"$8\" != \"secretenv-key-protection\" ]; then\n\
  echo \"unexpected namespace\" >&2\n\
  exit 32\n\
fi\n\
if [ ! -s \"$4\" ] || [ ! -s \"${10}\" ]; then\n\
  echo \"missing temp files\" >&2\n\
  exit 33\n\
fi\n\
if [ \"${SSH_AUTH_SOCK:-}\" != \"/tmp/agent.sock\" ]; then\n\
  echo \"missing SSH_AUTH_SOCK\" >&2\n\
  exit 34\n\
fi\n\
if [ \"${SECRETENV_PRIVATE_KEY:-}\" = \"sensitive\" ]; then\n\
  echo \"secret env leaked\" >&2\n\
  exit 35\n\
fi\n\
input=$(/bin/cat)\n\
if [ \"$input\" != \"verify-stdin-test\" ]; then\n\
  echo \"stdin mismatch\" >&2\n\
  exit 36\n\
fi\n",
    )
    .unwrap();
    let mut perms = fs::metadata(&script_path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&script_path, perms).unwrap();

    DefaultSshKeygen::new(script_path.to_string_lossy().into_owned())
        .verify(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl user@example.com",
            KEY_PROTECTION_NAMESPACE,
            b"verify-stdin-test",
            "-----BEGIN SSH SIGNATURE-----\ndGVzdA==\n-----END SSH SIGNATURE-----\n",
        )
        .unwrap();
}
