// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Test helpers for process umask-sensitive filesystem assertions.
//! Runs umask mutations in isolated test child processes.

// libc::umask has no safe wrapper. Confined to a child process spawned for a
// single test, so the process-global mutation cannot affect other tests.
#![allow(unsafe_code)]

/// Carries the child's instructions from the parent that spawned it.
#[cfg(unix)]
const MARKER_ENV: &str = "KAPSARO_UMASK_CHILD_MARKER";

/// Opens a value this helper wrote, telling it apart from any other variable
/// of the same name the surrounding environment happens to carry.
#[cfg(unix)]
const MARKER_MAGIC: &str = "kapsaro-umask-child";

/// Separates the fields of the marker value. A unit separator cannot appear in
/// a path or a test name, so no field can run into the next.
#[cfg(unix)]
const MARKER_FIELD_SEPARATOR: char = '\u{1f}';

/// What one spawned child was told to do.
#[cfg(unix)]
pub(crate) struct UmaskChildInstruction {
    test_name: String,
    marker: std::path::PathBuf,
}

#[cfg(unix)]
impl UmaskChildInstruction {
    pub(crate) fn test_name(&self) -> &str {
        &self.test_name
    }

    pub(crate) fn marker(&self) -> &std::path::Path {
        &self.marker
    }

    pub(crate) fn encode(
        nonce: &str,
        test_name: &str,
        marker: &std::path::Path,
    ) -> std::ffi::OsString {
        use std::os::unix::ffi::OsStrExt;

        let mut value = std::ffi::OsString::from(format!(
            "{MARKER_MAGIC}{MARKER_FIELD_SEPARATOR}{nonce}{MARKER_FIELD_SEPARATOR}\
             {test_name}{MARKER_FIELD_SEPARATOR}"
        ));
        value.push(std::ffi::OsStr::from_bytes(marker.as_os_str().as_bytes()));
        value
    }

    /// Read the instruction back, accepting only a value this helper wrote.
    ///
    /// The magic prefix, the test name and the nonce are all checked, and the
    /// nonce is checked against the one the parent left beside the marker
    /// rather than against the shape of a UUID. A variable of the same name
    /// from outside would otherwise turn an ordinary parallel test process into
    /// a "child" and let it change the umask of the whole process, which
    /// decides the mode of every file the other tests running beside it create.
    pub(crate) fn decode(value: &std::ffi::OsStr) -> Option<Self> {
        use std::os::unix::ffi::OsStrExt;

        let text = value.to_str()?;
        let mut fields = text.splitn(4, MARKER_FIELD_SEPARATOR);
        if fields.next()? != MARKER_MAGIC {
            return None;
        }
        let nonce = fields.next()?;
        let test_name = fields.next()?.to_string();
        let marker =
            std::path::PathBuf::from(std::ffi::OsStr::from_bytes(fields.next()?.as_bytes()));
        if !parent_issued_nonce(&marker, nonce) {
            return None;
        }
        Some(Self { test_name, marker })
    }
}

/// Whether the nonce is the one the parent generated for this very run.
///
/// The parent writes it beside the marker before it spawns anything, so a value
/// somebody else put in the environment names a file that either does not exist
/// or holds a different nonce, and the process goes on to spawn a child of its
/// own instead of mutating its umask.
#[cfg(unix)]
fn parent_issued_nonce(marker: &std::path::Path, nonce: &str) -> bool {
    let Some(path) = nonce_file_path(marker) else {
        return false;
    };
    std::fs::read_to_string(path).is_ok_and(|issued| issued == nonce)
}

/// Where the parent leaves the nonce it generated: beside the marker it names,
/// in a directory only it created.
#[cfg(unix)]
fn nonce_file_path(marker: &std::path::Path) -> Option<std::path::PathBuf> {
    Some(marker.parent()?.join("nonce"))
}

/// Run `body` under a umask isolated in a dedicated child process.
///
/// In the parent this spawns the test binary filtered to `qualified_test_name`
/// and requires the child to leave a completion marker behind. A libtest filter
/// that matches nothing still exits 0, so the marker rather than the exit code
/// is what proves the body ran.
///
/// The child branch is taken only for a marker this helper wrote naming this
/// very test, so a process that inherited an unrelated variable spawns a child
/// as any parent would instead of mutating its own umask.
#[cfg(unix)]
pub(crate) fn run_test_in_isolated_umask_process(qualified_test_name: &str, body: impl FnOnce()) {
    let instruction = std::env::var_os(MARKER_ENV)
        .as_deref()
        .and_then(UmaskChildInstruction::decode)
        .filter(|instruction| instruction_names_this_test(instruction, qualified_test_name));
    let Some(instruction) = instruction else {
        return spawn_isolated_umask_child(qualified_test_name);
    };
    body();
    std::fs::write(&instruction.marker, "completed")
        .unwrap_or_else(|error| panic!("cannot write {}: {error}", instruction.marker.display()));
}

/// Whether a decoded instruction names the very test that is running.
///
/// The child branch must be taken only by the test the parent spawned it for,
/// so an instruction meant for a different test falls through to spawning a
/// child of its own instead of running under a umask meant for someone else.
#[cfg(unix)]
pub(crate) fn instruction_names_this_test(
    instruction: &UmaskChildInstruction,
    qualified_test_name: &str,
) -> bool {
    instruction.test_name == qualified_test_name
}

#[cfg(unix)]
fn spawn_isolated_umask_child(qualified_test_name: &str) {
    let marker_dir = tempfile::TempDir::new().unwrap();
    let marker = marker_dir.path().join("completed");
    let nonce = uuid::Uuid::new_v4().to_string();
    std::fs::write(nonce_file_path(&marker).unwrap(), &nonce).unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg(qualified_test_name)
        .arg("--nocapture")
        .arg("--test-threads=1")
        .env(
            MARKER_ENV,
            UmaskChildInstruction::encode(&nonce, qualified_test_name, &marker),
        )
        .status()
        .unwrap();

    assert!(status.success(), "umask child test failed: {status}");
    assert!(
        marker.exists(),
        "umask child did not run '{qualified_test_name}': the filter matched no test"
    );
}

/// Drop the crate name that `module_path!` prefixes, leaving the path a
/// libtest `--exact` filter accepts.
#[cfg(unix)]
pub(crate) fn qualified_test_name(module_path: &str, test_name: &str) -> String {
    match module_path.split_once("::") {
        Some((_, module)) => format!("{module}::{test_name}"),
        None => test_name.to_string(),
    }
}

/// Declare a test whose body runs under a umask isolated in a child process.
///
/// The child's `--exact` filter is built from the enclosing module and the
/// declared name, so the filter cannot drift away from the test it names.
///
/// A test declared with this macro needs no `#[serial]` of its own. The
/// isolation is a real process boundary rather than a lock: the umask this
/// test mutates lives in a child spawned to run only this one test, so it
/// cannot race the umask of any other test running in the shared test
/// binary. Nothing at the call site shows that, since the spawn happens
/// inside `run_test_in_isolated_umask_process`.
#[cfg(unix)]
macro_rules! isolated_umask_test {
    ($(#[$attribute:meta])* fn $test_fn:ident() $body:block) => {
        $(#[$attribute])*
        #[test]
        fn $test_fn() {
            crate::support::fs::test_umask::run_test_in_isolated_umask_process(
                &crate::support::fs::test_umask::qualified_test_name(
                    module_path!(),
                    stringify!($test_fn),
                ),
                || $body,
            );
        }
    };
}

#[cfg(unix)]
pub(crate) use isolated_umask_test;

#[cfg(unix)]
pub(crate) fn with_restrictive_umask(run: impl FnOnce()) {
    with_umask(0o777, run);
}

#[cfg(unix)]
pub(crate) fn with_umask(mode: libc::mode_t, run: impl FnOnce()) {
    let previous = unsafe { libc::umask(mode) };
    let guard = UmaskGuard(previous);
    run();
    drop(guard);
}

#[cfg(unix)]
struct UmaskGuard(libc::mode_t);

#[cfg(unix)]
impl Drop for UmaskGuard {
    fn drop(&mut self) {
        unsafe {
            libc::umask(self.0);
        }
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/support_fs_test_umask_test.rs"]
mod support_fs_test_umask_test;
