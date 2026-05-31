// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for install.sh.

use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

const ARCHIVE: &str = "kapsaro-v1.2.3-x86_64-unknown-linux-gnu.tar.gz";

#[test]
fn test_install_script_installs_archive_after_sha256_verification() {
    let fixture = InstallFixture::new();
    fixture.save_archive(b"release archive bytes");
    fixture.save_checksums(&format!("{}  {}\n", fixture.archive_hash(), ARCHIVE));
    fixture.save_fake_commands(true);

    let output = fixture.run_installer();

    assert!(
        output.status.success(),
        "installer failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read_to_string(fixture.install_dir.path().join("kapsaro")).unwrap(),
        "installed binary\n"
    );
}

#[test]
fn test_install_script_rejects_archive_with_sha256_mismatch() {
    let fixture = InstallFixture::new();
    fixture.save_archive(b"tampered archive bytes");
    fixture.save_checksums(&format!("{}  {}\n", "0".repeat(64), ARCHIVE));
    fixture.save_fake_commands(true);

    let output = fixture.run_installer();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("SHA256 mismatch"));
    assert!(!fixture.install_dir.path().join("kapsaro").exists());
}

#[test]
fn test_install_script_rejects_checksums_without_target_archive() {
    let fixture = InstallFixture::new();
    fixture.save_archive(b"release archive bytes");
    fixture.save_checksums(&format!(
        "{}  kapsaro-v1.2.3-aarch64-unknown-linux-gnu.tar.gz\n",
        fixture.archive_hash()
    ));
    fixture.save_fake_commands(true);

    let output = fixture.run_installer();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Checksum not found"));
    assert!(!fixture.install_dir.path().join("kapsaro").exists());
}

#[test]
fn test_install_script_rejects_environment_without_sha256_command() {
    let fixture = InstallFixture::new();
    fixture.save_archive(b"release archive bytes");
    fixture.save_checksums(&format!("{}  {}\n", fixture.archive_hash(), ARCHIVE));
    fixture.save_fake_commands(false);

    let output = fixture.run_installer();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("No SHA256 command found"));
    assert!(!fixture.install_dir.path().join("kapsaro").exists());
}

struct InstallFixture {
    root: TempDir,
    install_dir: TempDir,
    bin_dir: PathBuf,
}

impl InstallFixture {
    fn new() -> Self {
        let root = TempDir::new().unwrap();
        let install_dir = TempDir::new().unwrap();
        let bin_dir = root.path().join("bin");
        fs::create_dir(&bin_dir).unwrap();
        fs::write(root.path().join("kapsaro"), "installed binary\n").unwrap();

        Self {
            root,
            install_dir,
            bin_dir,
        }
    }

    fn save_archive(&self, content: &[u8]) {
        fs::write(self.root.path().join("archive.tar.gz"), content).unwrap();
    }

    fn archive_hash(&self) -> String {
        let archive = fs::read(self.root.path().join("archive.tar.gz")).unwrap();
        let digest = Sha256::digest(archive);
        hex::encode(digest)
    }

    fn save_checksums(&self, content: &str) {
        fs::write(self.root.path().join("SHA256SUMS"), content).unwrap();
    }

    fn save_fake_commands(&self, include_checksum: bool) {
        self.save_uname();
        self.save_curl();
        self.save_tar();
        self.save_mktemp();
        self.save_passthrough("cp", "/bin/cp");
        self.save_passthrough("rm", "/bin/rm");
        self.save_passthrough("chmod", "/bin/chmod");
        self.link_system_command("grep");
        self.link_system_command("sed");
        self.link_system_command("awk");
        if include_checksum {
            self.link_first_existing_command(&["sha256sum", "shasum", "openssl"]);
        }
    }

    fn save_uname(&self) {
        self.save_executable(
            "uname",
            r#"#!/bin/sh
if [ "$1" = "-s" ]; then
  printf '%s\n' 'Linux'
else
  printf '%s\n' 'x86_64'
fi
"#,
        );
    }

    fn save_curl(&self) {
        self.save_executable(
            "curl",
            r#"#!/bin/sh
out=''
url=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o)
      out="$2"
      shift 2
      ;;
    -*)
      shift
      ;;
    *)
      url="$1"
      shift
      ;;
  esac
done

case "$url" in
  *api.github.com*)
    printf '{"tag_name":"v1.2.3"}\n'
    ;;
  *SHA256SUMS)
    /bin/cp "${FIXTURE_DIR}/SHA256SUMS" "$out"
    ;;
  *kapsaro-v1.2.3-x86_64-unknown-linux-gnu.tar.gz)
    /bin/cp "${FIXTURE_DIR}/archive.tar.gz" "$out"
    ;;
  *)
    printf 'unexpected URL: %s\n' "$url" >&2
    exit 44
    ;;
esac
"#,
        );
    }

    fn save_tar(&self) {
        self.save_executable(
            "tar",
            r#"#!/bin/sh
out=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    -C)
      out="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
/bin/cp "${FIXTURE_DIR}/kapsaro" "${out}/kapsaro"
"#,
        );
    }

    fn save_mktemp(&self) {
        self.save_executable(
            "mktemp",
            r#"#!/bin/sh
dir="${FIXTURE_DIR}/tmp.$$"
/bin/mkdir -p "$dir"
printf '%s\n' "$dir"
"#,
        );
    }

    fn save_passthrough(&self, name: &str, target: &str) {
        self.save_executable(name, &format!("#!/bin/sh\nexec {target} \"$@\"\n"));
    }

    fn save_executable(&self, name: &str, content: &str) {
        let path = self.bin_dir.join(name);
        fs::write(&path, content).unwrap();
        set_executable_permissions(&path);
    }

    fn link_system_command(&self, name: &str) {
        let target = find_command(name).unwrap_or_else(|| panic!("{name} must be available"));
        link_command(&target, &self.bin_dir.join(name));
    }

    fn link_first_existing_command(&self, candidates: &[&str]) {
        let (name, target) = candidates
            .iter()
            .find_map(|candidate| find_command(candidate).map(|target| (*candidate, target)))
            .unwrap_or_else(|| panic!("one SHA256 command must be available"));
        link_command(&target, &self.bin_dir.join(name));
    }

    fn run_installer(&self) -> std::process::Output {
        Command::new("/bin/sh")
            .arg("install.sh")
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .env("PATH", &self.bin_dir)
            .env("FIXTURE_DIR", self.root.path())
            .env("INSTALL_DIR", self.install_dir.path())
            .output()
            .unwrap()
    }
}

fn find_command(name: &str) -> Option<PathBuf> {
    env::var_os("PATH").and_then(|paths| {
        env::split_paths(&paths)
            .map(|dir| dir.join(name))
            .find(|path| path.exists())
    })
}

#[cfg(unix)]
fn set_executable_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}

#[cfg(unix)]
fn link_command(target: &Path, link: &Path) {
    std::os::unix::fs::symlink(target, link).unwrap();
}
