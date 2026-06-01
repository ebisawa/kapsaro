// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for install.sh.
//! Exercises installer download, provenance verification, and install paths.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

const ARCHIVE: &str = "kapsaro-v1.2.3-x86_64-unknown-linux-gnu.tar.gz";
const BUNDLE: &str = "kapsaro-v1.2.3.sigstore.jsonl";

#[test]
fn test_install_script_installs_archive_after_provenance_verification() {
    let fixture = InstallFixture::new();
    fixture.save_archive(b"release archive bytes");
    fixture.save_attestation_bundle();
    fixture.save_fake_commands(GhCommand::Available {
        verify_success: true,
    });

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
    let invocation = fixture.gh_invocation();
    assert!(invocation.contains("attestation verify"));
    assert!(invocation.contains(ARCHIVE));
    assert!(invocation.contains(BUNDLE));
    assert!(invocation.contains("--repo ebisawa/kapsaro"));
}

#[test]
fn test_install_script_rejects_archive_when_provenance_verification_fails() {
    let fixture = InstallFixture::new();
    fixture.save_archive(b"release archive bytes");
    fixture.save_attestation_bundle();
    fixture.save_fake_commands(GhCommand::Available {
        verify_success: false,
    });

    let output = fixture.run_installer();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Provenance verification failed"));
    assert!(!fixture.install_dir.path().join("kapsaro").exists());
}

#[test]
fn test_install_script_rejects_environment_without_gh_command() {
    let fixture = InstallFixture::new();
    fixture.save_archive(b"release archive bytes");
    fixture.save_attestation_bundle();
    fixture.save_fake_commands(GhCommand::Missing);

    let output = fixture.run_installer();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("GitHub CLI (gh) is required"));
    assert!(!fixture.install_dir.path().join("kapsaro").exists());
}

#[test]
fn test_install_script_installs_archive_without_provenance_when_insecure() {
    let fixture = InstallFixture::new();
    fixture.save_archive(b"release archive bytes");
    fixture.save_fake_commands(GhCommand::Missing);

    let output = fixture.run_installer_with_env(&[("KAPSARO_INSECURE", "1")]);

    assert!(
        output.status.success(),
        "installer failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("KAPSARO_INSECURE=1"));
    assert_eq!(
        fs::read_to_string(fixture.install_dir.path().join("kapsaro")).unwrap(),
        "installed binary\n"
    );
    assert!(!fixture.root.path().join("gh-invocation").exists());
}

enum GhCommand {
    Available { verify_success: bool },
    Missing,
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

    fn save_attestation_bundle(&self) {
        fs::write(self.root.path().join(BUNDLE), "sigstore bundle\n").unwrap();
    }

    fn save_fake_commands(&self, gh_command: GhCommand) {
        self.save_uname();
        self.save_curl();
        self.save_tar();
        self.save_mktemp();
        self.save_passthrough("cp", "/bin/cp");
        self.save_passthrough("rm", "/bin/rm");
        self.save_passthrough("chmod", "/bin/chmod");
        self.link_system_command("grep");
        self.link_system_command("sed");
        if let GhCommand::Available { verify_success } = gh_command {
            self.save_gh(verify_success);
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
  *kapsaro-v1.2.3.sigstore.jsonl)
    /bin/cp "${FIXTURE_DIR}/kapsaro-v1.2.3.sigstore.jsonl" "$out"
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

    fn save_gh(&self, verify_success: bool) {
        let exit_code = if verify_success { "0" } else { "46" };
        let script = r#"#!/bin/sh
printf '%s\n' "$*" > "${FIXTURE_DIR}/gh-invocation"
if [ "$1" != "attestation" ] || [ "$2" != "verify" ]; then
  printf 'unexpected gh command: %s\n' "$*" >&2
  exit 45
fi

archive="$3"
shift 3
bundle=''
repo=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --bundle)
      bundle="$2"
      shift 2
      ;;
    --repo)
      repo="$2"
      shift 2
      ;;
    *)
      printf 'unexpected gh argument: %s\n' "$1" >&2
      exit 45
      ;;
  esac
done

if [ ! -f "$archive" ] || [ ! -f "$bundle" ]; then
  printf 'missing attestation input\n' >&2
  exit 45
fi
if [ "$repo" != "ebisawa/kapsaro" ]; then
  printf 'unexpected repo: %s\n' "$repo" >&2
  exit 45
fi
if [ "__VERIFY_EXIT__" = "0" ]; then
  exit 0
fi
printf 'attestation failed\n' >&2
exit __VERIFY_EXIT__
"#
        .replace("__VERIFY_EXIT__", exit_code);
        self.save_executable("gh", &script);
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

    fn run_installer(&self) -> std::process::Output {
        self.run_installer_with_env(&[])
    }

    fn run_installer_with_env(&self, envs: &[(&str, &str)]) -> std::process::Output {
        let mut command = Command::new("/bin/sh");
        command
            .arg("install.sh")
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .env("PATH", &self.bin_dir)
            .env("FIXTURE_DIR", self.root.path())
            .env("INSTALL_DIR", self.install_dir.path());
        for (key, value) in envs {
            command.env(key, value);
        }
        command.output().unwrap()
    }

    fn gh_invocation(&self) -> String {
        fs::read_to_string(self.root.path().join("gh-invocation")).unwrap()
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
