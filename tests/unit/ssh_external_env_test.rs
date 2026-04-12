// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use secretenv::io::ssh::external::add::DefaultSshAdd;
use secretenv::io::ssh::external::keygen::DefaultSshKeygen;
use secretenv::io::ssh::external::traits::SshAdd;
use secretenv::io::ssh::external::traits::SshKeygen;
use secretenv::io::ssh::protocol::sshsig::SSHSIG_NAMESPACE;
use secretenv::io::ssh::protocol::wire::ssh_string_encode;
use secretenv::support::codec::base64_public::encode_base64_standard;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;

use crate::test_utils::{create_temp_ssh_keypair_in_dir, EnvGuard};

fn make_env_dump_script() -> (TempDir, String) {
    let temp_dir = TempDir::new().unwrap();
    let script_path = temp_dir.path().join("dump-env.sh");
    fs::write(&script_path, "#!/bin/sh\nenv\n").unwrap();
    let mut perms = fs::metadata(&script_path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&script_path, perms).unwrap();
    (temp_dir, script_path.to_string_lossy().into_owned())
}

fn build_test_sshsig_armored(raw_sig: [u8; 64]) -> String {
    let mut sshsig_blob = Vec::new();
    sshsig_blob.extend_from_slice(b"SSHSIG");
    sshsig_blob.extend_from_slice(&1u32.to_be_bytes());
    sshsig_blob.extend_from_slice(&ssh_string_encode(b"ssh-ed25519 AAAA..."));
    sshsig_blob.extend_from_slice(&ssh_string_encode(SSHSIG_NAMESPACE.as_bytes()));
    sshsig_blob.extend_from_slice(&ssh_string_encode(b""));
    sshsig_blob.extend_from_slice(&ssh_string_encode(b"sha256"));

    let mut signature_blob = Vec::new();
    signature_blob.extend_from_slice(&ssh_string_encode(b"ssh-ed25519"));
    signature_blob.extend_from_slice(&ssh_string_encode(&raw_sig));
    sshsig_blob.extend_from_slice(&ssh_string_encode(&signature_blob));

    format!(
        "-----BEGIN SSH SIGNATURE-----\n{}\n-----END SSH SIGNATURE-----\n",
        encode_base64_standard(&sshsig_blob)
    )
}

#[test]
fn test_load_ssh_public_key_from_keygen_uses_sanitized_env_with_optional_socket() {
    let _guard = EnvGuard::new(&["HOME", "PATH", "SSH_AUTH_SOCK", "SECRETENV_PRIVATE_KEY"]);
    let fake_home = TempDir::new().unwrap();
    std::env::set_var("HOME", fake_home.path());
    std::env::set_var("PATH", "/usr/bin");
    std::env::set_var("SSH_AUTH_SOCK", "/tmp/agent.sock");
    std::env::set_var("SECRETENV_PRIVATE_KEY", "sensitive");

    let (_script_dir, script_path) = make_env_dump_script();
    let output = DefaultSshKeygen::new(&script_path)
        .derive_public_key(std::path::Path::new("/tmp/test-key"))
        .unwrap();

    assert!(output.contains("PATH=/usr/bin"));
    assert!(output.contains("SSH_AUTH_SOCK=/tmp/agent.sock"));
    assert!(!output.contains("SECRETENV_PRIVATE_KEY=sensitive"));
}

#[test]
fn test_default_ssh_add_sets_resolved_socket_without_inheriting_secret_env() {
    let _guard = EnvGuard::new(&["HOME", "PATH", "SSH_AUTH_SOCK", "SECRETENV_PRIVATE_KEY"]);
    let fake_home = TempDir::new().unwrap();
    std::env::set_var("HOME", fake_home.path());
    std::env::set_var("PATH", "/usr/bin");
    std::env::set_var("SSH_AUTH_SOCK", "/tmp/agent.sock");
    std::env::set_var("SECRETENV_PRIVATE_KEY", "sensitive");

    let (_script_dir, script_path) = make_env_dump_script();
    let ssh_add = DefaultSshAdd::new(script_path);
    let output = ssh_add.list_keys().unwrap();

    assert!(output.contains("PATH=/usr/bin"));
    assert!(output.contains("SSH_AUTH_SOCK=/tmp/agent.sock"));
    assert!(!output.contains("SECRETENV_PRIVATE_KEY=sensitive"));
}

#[test]
fn test_default_ssh_keygen_sign_uses_stdin_stdout_without_sig_file() {
    let temp_dir = TempDir::new().unwrap();
    let ssh_dir = TempDir::new().unwrap();
    let (ssh_priv, _ssh_pub, _ssh_pub_content) = create_temp_ssh_keypair_in_dir(&ssh_dir);

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
        .sign(&ssh_priv, SSHSIG_NAMESPACE, b"stdin-signature-test")
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
    let (_ssh_priv, ssh_pub, _ssh_pub_content) = create_temp_ssh_keypair_in_dir(&ssh_dir);

    let mut expected_raw_sig = [0u8; 64];
    for (index, byte) in expected_raw_sig.iter_mut().enumerate() {
        *byte = index as u8;
    }
    let armored = build_test_sshsig_armored(expected_raw_sig);

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
        namespace = SSHSIG_NAMESPACE,
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
            SSHSIG_NAMESPACE,
            b"public-key-agent-signature-test",
        )
        .unwrap();

    assert_eq!(signature.as_bytes(), &expected_raw_sig);
}
