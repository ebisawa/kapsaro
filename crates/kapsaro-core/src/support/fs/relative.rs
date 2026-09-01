// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Directory-fd-relative filesystem operations.
//! Keeps workspace I/O bound to a verified directory inode.

use crate::support::display::format_path_for_message;
#[cfg(unix)]
use crate::support::fs::permission::report_scoped_open_permission;
use crate::support::fs::read::{decode_loaded_text, load_capped_bytes};
use crate::support::limits::MAX_ATOMIC_WRITE_TARGET_NAME_LENGTH;
use crate::support::path::{format_finding_path, format_path_relative_to_cwd};
use crate::support::post_write::{format_post_change_failure, CompletedChange};
use crate::{Error, Result};
use std::ffi::{CString, OsStr};
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "redox",
    target_vendor = "apple",
))]
use rustix::fs::RenameFlags;
#[cfg(unix)]
use rustix::fs::{self as rfs, AtFlags, FileType, Mode, OFlags};

pub(crate) trait DirectoryFd {
    fn file(&self) -> &File;
    fn path(&self) -> &Path;

    fn scope(&self) -> DirectoryScope {
        DirectoryScope::Generic
    }
}

#[derive(Debug)]
pub(crate) struct OpenDir {
    file: File,
    path: PathBuf,
    scope: DirectoryScope,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectoryScope {
    Generic,
    LocalState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChildType {
    Directory,
    RegularFile,
    Symlink,
    Other,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChildDirectoryCreationStep {
    Permission,
    ChildSync,
    Publish,
    ParentSync,
}

impl DirectoryFd for OpenDir {
    fn file(&self) -> &File {
        &self.file
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn scope(&self) -> DirectoryScope {
        self.scope
    }
}

/// Open a directory named by path, resolving a final symlink.
///
/// Placing a root behind a symlink is a deliberate and supported setup, so the
/// link is followed. What the directory identity rests on is the descriptor
/// returned here, not the path that reached it: once opened, later operations
/// stay on this inode even if the link is repointed.
#[cfg(unix)]
pub(crate) fn open_dir_following(path: &Path, scope: DirectoryScope) -> Result<OpenDir> {
    validate_directory_path(path, scope)?;
    let fd = rfs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| open_directory_error(path, error))?;
    Ok(OpenDir {
        file: fd.into(),
        path: path.to_path_buf(),
        scope,
    })
}

/// Open a directory named by path, refusing a final symlink.
///
/// A write addressed by path has to land where the caller named it. A link in
/// the final position sends the whole operation somewhere else, and the entry
/// standing there is not something kapsaro wrote, so it is refused rather than
/// followed.
#[cfg(unix)]
pub(crate) fn open_dir_nofollow(path: &Path, scope: DirectoryScope) -> Result<OpenDir> {
    validate_directory_path_nofollow(path, scope)?;
    let fd = rfs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| open_directory_error(path, error))?;
    Ok(OpenDir {
        file: fd.into(),
        path: path.to_path_buf(),
        scope,
    })
}

/// Confirm the entry a path names is a directory and not a link to one.
///
/// The type is settled before the open so the refusal names what actually
/// stands there rather than an errno that differs between platforms.
#[cfg(unix)]
fn validate_directory_path_nofollow(path: &Path, scope: DirectoryScope) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| inspect_directory_path_error(path, error))?;
    match mismatched_dir_kind(child_type_from_file_type(&metadata.file_type())) {
        None => Ok(()),
        Some(kind) => Err(invalid_directory_type(path, kind, scope)),
    }
}

#[cfg(unix)]
pub(crate) fn open_child_dir<D>(parent: &D, name: &str) -> Result<OpenDir>
where
    D: DirectoryFd,
{
    open_optional_child_dir(parent, name)?.ok_or_else(|| {
        Error::build_not_found_error(format!("Directory not found: {}", child_path(parent, name)))
    })
}

#[cfg(unix)]
pub(crate) fn open_optional_child_dir<D>(parent: &D, name: &str) -> Result<Option<OpenDir>>
where
    D: DirectoryFd,
{
    let child = checked_child_name(name)?;
    let fd = match rfs::openat(
        parent.file(),
        child.as_c_str(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(error) if is_not_found(error) => return Ok(None),
        Err(error) => return Err(open_child_dir_error(parent, name, child.as_c_str(), error)),
    };
    Ok(Some(OpenDir {
        file: fd.into(),
        path: parent.path().join(name),
        scope: parent.scope(),
    }))
}

/// Open a child directory by a single-component name, resolving a symlink.
///
/// The one-component restriction still binds the open to `parent`, and the
/// descriptor it returns is what every later operation runs against, so the
/// identity is fixed at the inode the link pointed to when it was opened.
///
/// The name arrives as the bytes the caller's path holds rather than as text.
/// This is how a root the operator chose is reached, and a root is named by the
/// operator and the OS: a Unix path component is a byte string, and a directory
/// whose name does not decode as UTF-8 is an ordinary directory on the machine
/// it lives on. The names kapsaro chooses itself go through the `&str` API,
/// where the specification fixes what the name may be.
///
/// `path` keeps the logical name — the link itself — rather than what it
/// resolved to. Messages and permission repair hints are built from it, so a
/// resolved path would name a location the operator never typed, and reading
/// one back would mean re-resolving a path that is only ever displayed.
/// `chmod` follows symlinks, so a repair hint stays correct on the link.
#[cfg(unix)]
pub(crate) fn open_child_dir_following<D>(parent: &D, name: &OsStr) -> Result<OpenDir>
where
    D: DirectoryFd,
{
    let child = checked_os_child_name(name)?;
    let path = parent.path().join(name);
    validate_child_dir_type(parent, child.as_c_str(), &path)?;
    let fd = rfs::openat(
        parent.file(),
        child.as_c_str(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| open_directory_error(&path, error))?;
    Ok(OpenDir {
        file: fd.into(),
        path,
        scope: parent.scope(),
    })
}

/// Confirm the resolved child is a directory before it is opened.
///
/// A name whose target is gone is reported as a dangling link rather than as
/// an absence, because the entry is there and only its target is missing.
#[cfg(unix)]
fn validate_child_dir_type<D>(parent: &D, child: &std::ffi::CStr, path: &Path) -> Result<()>
where
    D: DirectoryFd,
{
    let stat = match rfs::statat(parent.file(), child, AtFlags::empty()) {
        Ok(stat) => stat,
        Err(error) if is_not_found(error) => {
            return Err(missing_child_dir_error(parent, child, path))
        }
        Err(error) => {
            return Err(io_error(
                format!("Failed to inspect directory: {}", format_finding_path(path)),
                error,
            ))
        }
    };
    match mismatched_dir_kind(child_type_from_raw(FileType::from_raw_mode(stat.st_mode))) {
        None => Ok(()),
        Some(kind) => Err(invalid_directory_type(path, kind, parent.scope())),
    }
}

/// Name what a directory open found when following the entry led nowhere.
///
/// The entry itself is stat'ed again without following it. A second inspection
/// that fails for its own reason is reported as that failure: collapsing it into
/// an absence would turn a directory kapsaro is not allowed to look at, or a
/// link chain too deep to resolve, into "nothing is there".
#[cfg(unix)]
fn missing_child_dir_error<D>(parent: &D, child: &std::ffi::CStr, path: &Path) -> Error
where
    D: DirectoryFd,
{
    classify_missing_child_dir(
        rfs::statat(parent.file(), child, AtFlags::SYMLINK_NOFOLLOW).map(|_| ()),
        parent.scope(),
        path,
    )
}

#[cfg(unix)]
fn classify_missing_child_dir(
    entry: std::result::Result<(), rustix::io::Errno>,
    scope: DirectoryScope,
    path: &Path,
) -> Error {
    let display = format_finding_path(path);
    match entry {
        Ok(()) => scoped_invalid_operation_error(
            scope,
            format!("refusing to open a symlink whose target is missing: {display}"),
        ),
        Err(error) if is_not_found(error) => {
            Error::build_not_found_error(format!("Directory not found: {display}"))
        }
        Err(error) => io_error(format!("Failed to inspect directory: {display}"), error),
    }
}

/// Create a child directory only this account can reach, refusing a taken name.
#[cfg(unix)]
pub(crate) fn create_child_dir_restricted_at<D>(parent: &D, name: &str) -> Result<OpenDir>
where
    D: DirectoryFd,
{
    publish_new_child_dir(parent, name, Some(Mode::from(0o700)))?.ok_or_else(|| {
        invalid_operation_error(
            parent,
            format!(
                "refusing to replace existing entry: {}",
                child_path(parent, name)
            ),
        )
    })
}

/// Create a child directory and put it under `name` only once it is finished.
///
/// The directory is made under a name of this call's own, its mode is settled
/// there, and a no-replace rename publishes it. This is the shape every file
/// write here already has, and it is what keeps an unfinished entry out of the
/// name space: what appears under the name the caller asked for is a directory
/// that is already complete.
///
/// Two things follow. The name whose mode is settled is one nothing else knows,
/// so it cannot be swapped for a link between the create and the settling. And a
/// failure has only the staged entry to give up: no other caller can have picked
/// that entry up, so there is no identity to compare before removing it and no
/// way to remove somebody else's directory.
///
/// Nothing is published when the name is already taken, which the rename reports
/// rather than the create. The caller opens what stands there.
#[cfg(unix)]
fn publish_new_child_dir<D>(
    parent: &D,
    name: &str,
    restricted: Option<Mode>,
) -> Result<Option<OpenDir>>
where
    D: DirectoryFd,
{
    let target = checked_child_name(name)?;
    let staging = unique_staging_dir_name();
    let staging_child = checked_child_name(&staging)?;
    let create_mode = restricted.unwrap_or(Mode::from(0o777));
    make_child_dir(parent, &staging, staging_child.as_c_str(), create_mode)?;
    let outcome = stage_child_dir(parent, &staging, staging_child.as_c_str(), restricted).and_then(
        |staged| {
            publish_staged_child_dir(parent, staged, staging_child.as_c_str(), (&target, name))
        },
    );
    if !matches!(outcome, Ok(Some(_))) {
        discard_staged_child_dir(parent, &staging);
    }
    outcome
}

/// Settle the mode of the directory a publish just staged, and open it.
///
/// The mode `mkdirat` was given is filtered by the process umask, so it is
/// settled afterwards rather than trusted. It is settled on the descriptor
/// wherever one can be had, which is a mode set on an inode and cannot land
/// anywhere else. A umask that drops the owner bits leaves a directory nothing
/// can open and so no descriptor to settle: only there is the mode set by name,
/// and the name it is set on is this call's staging name.
///
/// The staged directory is synced only when this call is the one that chose its
/// mode; a directory left at whatever the umask allowed carries the mode of the
/// checkout it belongs to and nothing here changed it.
#[cfg(unix)]
fn stage_child_dir<D>(
    parent: &D,
    staging: &str,
    staging_child: &std::ffi::CStr,
    restricted: Option<Mode>,
) -> Result<OpenDir>
where
    D: DirectoryFd,
{
    let staged = open_staged_child_dir(parent, staging, staging_child, restricted)?;
    check_injected_creation_failure(ChildDirectoryCreationStep::Permission)?;
    if let Some(mode) = restricted {
        set_open_child_dir_mode(parent, staged.file(), staging, mode)?;
    }
    check_injected_creation_failure(ChildDirectoryCreationStep::ChildSync)?;
    if restricted.is_some() {
        sync_directory_at(&staged)?;
    }
    Ok(staged)
}

/// Open the directory just staged, chmod'ing it first only when nothing else
/// can open it.
///
/// `EACCES` on a directory this call created a moment ago is the umask having
/// dropped the owner bits. That is the one case with no descriptor to settle a
/// mode on, so the mode is set by name and the open retried.
#[cfg(unix)]
fn open_staged_child_dir<D>(
    parent: &D,
    staging: &str,
    staging_child: &std::ffi::CStr,
    restricted: Option<Mode>,
) -> Result<OpenDir>
where
    D: DirectoryFd,
{
    let file = match (openat_child_dir(parent, staging_child), restricted) {
        (Ok(file), _) => file,
        (Err(error), Some(mode)) if error == rustix::io::Errno::ACCESS => {
            set_child_mode(parent, staging, mode)?;
            openat_child_dir(parent, staging_child)
                .map_err(|error| open_child_dir_error(parent, staging, staging_child, error))?
        }
        (Err(error), _) => return Err(open_child_dir_error(parent, staging, staging_child, error)),
    };
    Ok(OpenDir {
        file: file.into(),
        path: parent.path().join(staging),
        scope: parent.scope(),
    })
}

#[cfg(unix)]
fn openat_child_dir<D>(
    parent: &D,
    child: &std::ffi::CStr,
) -> std::result::Result<rustix::fd::OwnedFd, rustix::io::Errno>
where
    D: DirectoryFd,
{
    rfs::openat(
        parent.file(),
        child,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
}

/// Move the finished directory onto the name the caller asked for.
///
/// The descriptor the staged directory was opened on is what the caller is
/// handed, so what it holds is the inode this call made whatever becomes of the
/// name afterwards. Nothing is handed back when the name turns out to be taken.
///
/// The rename is the point the directory becomes reachable under its name, so a
/// failure after it leaves the directory published rather than rolling it back:
/// a second caller may already have opened it, and the mode was settled before
/// the rename, so what stands there is complete.
#[cfg(unix)]
fn publish_staged_child_dir<D>(
    parent: &D,
    staged: OpenDir,
    staging_child: &std::ffi::CStr,
    target: (&CString, &str),
) -> Result<Option<OpenDir>>
where
    D: DirectoryFd,
{
    let (target_child, name) = target;
    check_injected_creation_failure(ChildDirectoryCreationStep::Publish)?;
    if !rename_staged_child_dir(parent, staging_child, target_child.as_c_str(), name)? {
        return Ok(None);
    }
    let published = OpenDir {
        file: staged.file,
        path: parent.path().join(name),
        scope: staged.scope,
    };
    sync_published_child_dir(parent)
        .map_err(|error| unsynced_published_dir_error(parent, name, &error))?;
    Ok(Some(published))
}

/// Persist the directory entry the rename created.
///
/// The injected failure stands in for the sync itself, so it is raised inside
/// this call rather than before it. Raised outside, it would bypass the wrapping
/// the caller applies and reach that caller reading as a directory that was
/// never made.
#[cfg(unix)]
fn sync_published_child_dir<D>(parent: &D) -> Result<()>
where
    D: DirectoryFd,
{
    check_injected_creation_failure(ChildDirectoryCreationStep::ParentSync)?;
    sync_directory_at(parent)
}

/// Publish the staged directory, reporting a name that was taken as `false`.
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "redox",
    target_vendor = "apple",
))]
fn rename_staged_child_dir<D>(
    parent: &D,
    staging_child: &std::ffi::CStr,
    target_child: &std::ffi::CStr,
    name: &str,
) -> Result<bool>
where
    D: DirectoryFd,
{
    match rfs::renameat_with(
        parent.file(),
        staging_child,
        parent.file(),
        target_child,
        RenameFlags::NOREPLACE,
    ) {
        Ok(()) => Ok(true),
        Err(error) if std::io::Error::from(error).kind() == std::io::ErrorKind::AlreadyExists => {
            Ok(false)
        }
        Err(error) => Err(io_error(
            format!("Failed to create directory: {}", child_path(parent, name)),
            error,
        )),
    }
}

/// Report a directory the rename published but whose entry was not persisted.
///
/// The rename is the point the directory becomes reachable under its name, and
/// it already happened. A bare sync failure reads as "the directory was never
/// made" and sends the caller to create one that is already there.
#[cfg(unix)]
fn unsynced_published_dir_error<D>(parent: &D, name: &str, error: &Error) -> Error
where
    D: DirectoryFd,
{
    Error::build_io_error(format_post_change_failure(
        "Directory",
        &parent.path().join(name),
        CompletedChange::Written,
        "its directory entry was not persisted, so a crash before the next sync could lose it",
        error.format_user_message(),
    ))
}

/// Remove the directory this call staged and never published.
///
/// The staging name is this call's own, so the entry it names is the one this
/// call made or nothing at all: there is no other caller's directory to take
/// away and no identity to compare first. A rename that already succeeded leaves
/// the staging name free, so the same call covers a failure that struck after
/// the directory was published without touching what was published.
///
/// The cleanup runs while the failure that triggered it is being reported, so a
/// leftover is logged rather than replacing that failure.
#[cfg(unix)]
fn discard_staged_child_dir<D>(parent: &D, staging: &str)
where
    D: DirectoryFd,
{
    if remove_empty_child_dir_if_exists_at(parent, staging).is_err() {
        tracing::warn!(
            "Left a staged directory behind: {}",
            child_path(parent, staging)
        );
    }
}

// Test-only seam: fails one step of directory creation so a test can check what
// each side of the publishing rename leaves behind — a staged directory removed
// before the rename, and a published one kept after it. Compiled out of
// production builds.
#[cfg(all(test, unix))]
thread_local! {
    static INJECTED_CREATION_FAILURE: std::cell::Cell<Option<ChildDirectoryCreationStep>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(all(test, unix))]
fn fail_next_child_dir_creation_at(step: ChildDirectoryCreationStep) {
    INJECTED_CREATION_FAILURE.with(|slot| slot.set(Some(step)));
}

#[cfg(all(test, unix))]
fn check_injected_creation_failure(step: ChildDirectoryCreationStep) -> Result<()> {
    let injected = INJECTED_CREATION_FAILURE.with(std::cell::Cell::get);
    if injected != Some(step) {
        return Ok(());
    }
    INJECTED_CREATION_FAILURE.with(|slot| slot.set(None));
    Err(Error::build_io_error(step.injected_failure_message()))
}

#[cfg(all(not(test), unix))]
fn check_injected_creation_failure(_step: ChildDirectoryCreationStep) -> Result<()> {
    Ok(())
}

#[cfg(all(test, unix))]
impl ChildDirectoryCreationStep {
    fn injected_failure_message(self) -> &'static str {
        match self {
            Self::Permission => "Injected child directory permission failure",
            Self::ChildSync => "Injected child directory sync failure",
            Self::Publish => "Injected child directory publish failure",
            Self::ParentSync => "Injected parent directory sync failure",
        }
    }
}

/// Ensure a child directory exists and is reachable only by its owner.
#[cfg(unix)]
pub(crate) fn ensure_child_dir_restricted_at<D>(parent: &D, name: &str) -> Result<OpenDir>
where
    D: DirectoryFd,
{
    ensure_child_dir_with_mode(parent, name, Some(Mode::from(0o700)))
}

/// Ensure a child directory exists with the mode the process umask allows.
///
/// A workspace directory is shared through git and its modes come from the
/// checkout, so pinning it to 0700 would hand the operator a tree only they can
/// read and a repository that changes mode on every machine.
#[cfg(unix)]
pub(crate) fn ensure_child_dir_at<D>(parent: &D, name: &str) -> Result<OpenDir>
where
    D: DirectoryFd,
{
    ensure_child_dir_with_mode(parent, name, None)
}

/// Ensure a child directory exists, restricting it only where the scope asks.
#[cfg(unix)]
pub(crate) fn ensure_scoped_child_dir_at<D>(parent: &D, name: &str) -> Result<OpenDir>
where
    D: DirectoryFd,
{
    match parent.scope() {
        DirectoryScope::LocalState => ensure_child_dir_restricted_at(parent, name),
        DirectoryScope::Generic => ensure_child_dir_at(parent, name),
    }
}

/// Open a child directory, publishing a new one when the name is free.
///
/// A directory that was already there is opened and its mode left alone: it is
/// one the operator may have set up on purpose, so it is reported rather than
/// changed.
///
/// The name is looked up before anything is staged, because a name already taken
/// is the ordinary case and staging a directory for it would create and remove
/// one for nothing. A name taken between that look-up and the publish is
/// answered by the publish itself, so the look-up is an economy rather than the
/// decision.
#[cfg(unix)]
fn ensure_child_dir_with_mode<D>(
    parent: &D,
    name: &str,
    restricted: Option<Mode>,
) -> Result<OpenDir>
where
    D: DirectoryFd,
{
    if !file_exists_at(parent, name)? {
        if let Some(published) = publish_new_child_dir(parent, name, restricted)? {
            return Ok(published);
        }
    }
    let opened = open_child_dir(parent, name)?;
    report_scoped_open_permission(&opened, opened.file(), opened.path());
    Ok(opened)
}

/// Whether a mode set by name refuses to follow a link in the final position.
///
/// Linux implements no `AT_SYMLINK_NOFOLLOW` for this operation and answers
/// that it is unsupported, so the flag is only asked for where it exists.
///
/// Where it does not, what protects the operation is the name it is used on. A
/// mode is only ever set by name here on the staging name of a directory this
/// call has just made: it holds a fresh UUID, nothing else has ever seen it, and
/// the entry never carries the name the caller asked for. There is no name for
/// somebody else to aim a link at. Even if one were aimed there, the link would
/// be followed with this account's own privileges and the mode landing on it
/// only removes access.
///
/// It is also the fallback rather than the path: a mode reaches this call only
/// when the process umask dropped the owner bits, which leaves a directory no
/// descriptor can be had for. Under any ordinary umask the mode is settled on
/// the descriptor instead, where no name is involved at all.
#[cfg(any(target_os = "linux", target_os = "android"))]
const SET_CHILD_MODE_FLAGS: AtFlags = AtFlags::empty();

#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
const SET_CHILD_MODE_FLAGS: AtFlags = AtFlags::SYMLINK_NOFOLLOW;

/// Set the mode of one child by name, from the descriptor of its parent.
///
/// Addressing the entry by name is what reaches a directory whose mode the
/// umask left unopenable: every other way of setting a mode here needs a
/// descriptor, and there is none to be had for an entry that cannot be opened.
#[cfg(unix)]
fn set_child_mode<D>(parent: &D, name: &str, mode: Mode) -> Result<()>
where
    D: DirectoryFd,
{
    let child = checked_child_name(name)?;
    rfs::chmodat(parent.file(), child.as_c_str(), mode, SET_CHILD_MODE_FLAGS).map_err(|error| {
        io_error(
            format!(
                "Failed to set directory permissions: {}",
                child_path(parent, name)
            ),
            error,
        )
    })
}

/// Settle the mode of a directory on the descriptor that holds it.
///
/// The mode lands on the inode the descriptor was opened on, so nothing that
/// happens to the name in the meantime can send it anywhere else.
#[cfg(unix)]
fn set_open_child_dir_mode<D>(parent: &D, file: &File, name: &str, mode: Mode) -> Result<()>
where
    D: DirectoryFd,
{
    rfs::fchmod(file, mode).map_err(|error| {
        io_error(
            format!(
                "Failed to set directory permissions: {}",
                child_path(parent, name)
            ),
            error,
        )
    })
}

/// Make the directory a publish stages, under a name of that call's own.
#[cfg(unix)]
fn make_child_dir<D>(parent: &D, name: &str, child: &std::ffi::CStr, mode: Mode) -> Result<()>
where
    D: DirectoryFd,
{
    rfs::mkdirat(parent.file(), child, mode).map_err(|error| {
        io_error(
            format!("Failed to create directory: {}", child_path(parent, name)),
            error,
        )
    })
}

#[cfg(unix)]
pub(crate) fn load_text_with_limit_at<D>(
    dir: &D,
    name: &str,
    max_bytes: usize,
    subject: &str,
) -> Result<String>
where
    D: DirectoryFd,
{
    let mut file = open_regular_file_at(dir, name)?;
    let display_path = dir.path().join(name);
    report_scoped_open_permission(dir, &file, display_path.as_path());
    let path = format_finding_path(&display_path);
    let bytes = load_capped_bytes(&mut file, max_bytes, subject, &path)?;
    decode_loaded_text(bytes, &path)
}

#[cfg(unix)]
pub(crate) fn file_exists_at<D>(dir: &D, name: &str) -> Result<bool>
where
    D: DirectoryFd,
{
    let child = checked_child_name(name)?;
    match rfs::statat(dir.file(), child.as_c_str(), AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Ok(true),
        Err(e) if std::io::Error::from(e).kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(io_error(
            format!("Failed to inspect file: {}", child_path(dir, name)),
            e,
        )),
    }
}

/// A directory entry name exactly as `readdir` returned it.
///
/// The bytes are kept rather than a decoded string, so an entry kapsaro cannot
/// decode can still be opened and still names the path it actually occupies.
#[cfg(unix)]
#[derive(Clone, Debug)]
pub(crate) struct ChildName {
    raw: CString,
}

#[cfg(unix)]
impl ChildName {
    fn new(raw: CString) -> Self {
        Self { raw }
    }

    /// The name as UTF-8, absent when the bytes do not decode.
    pub(crate) fn decoded(&self) -> Option<&str> {
        self.raw.to_str().ok()
    }

    /// The path this entry occupies below `dir`.
    pub(crate) fn path_under<D>(&self, dir: &D) -> PathBuf
    where
        D: DirectoryFd,
    {
        use std::os::unix::ffi::OsStrExt;
        dir.path()
            .join(std::ffi::OsStr::from_bytes(self.raw.as_bytes()))
    }

    /// Build a name from the bytes `readdir` would have returned.
    ///
    /// A filesystem may refuse to create an entry whose name is not UTF-8, so a
    /// test that has to judge one builds the name instead of the entry.
    #[cfg(all(test, unix))]
    pub(crate) fn from_raw_bytes(raw: &[u8]) -> Self {
        Self::new(CString::new(raw).expect("a directory entry name holds no NUL"))
    }
}

/// What one directory entry looked like when the scan read it.
///
/// A scan that stops at the first entry it cannot read leaves the rest of the
/// directory uninspected, and the entries it never reached are exactly the ones
/// somebody else may have placed there. Each entry therefore carries its own
/// outcome instead of ending the walk.
#[cfg(unix)]
pub(crate) enum ScannedChild {
    Inspected {
        name: ChildName,
        child_type: ChildType,
        mode: u32,
        owner: u32,
        identity: EntryIdentity,
    },
    Unreadable {
        name: ChildName,
        error: Error,
    },
}

/// Which inode one entry was, as the call that inspected it saw it.
///
/// A name is only a name: the entry a scan recorded and the one a later open
/// reaches can be different inodes. Carrying the identity lets the caller say
/// so instead of attributing the first entry's mode to the second.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct EntryIdentity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
impl EntryIdentity {
    /// Widen the raw stat fields to one width.
    ///
    /// `dev_t` is signed on some targets and unsigned on others, and the
    /// standard library widens it exactly this way, so both sides of a
    /// comparison agree however the platform spells it.
    #[allow(clippy::unnecessary_cast)]
    fn from_stat(stat: &rfs::Stat) -> Self {
        Self {
            device: stat.st_dev as u64,
            inode: stat.st_ino as u64,
        }
    }

    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;

        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }

    /// Build an identity for a scan result a test hands over directly.
    #[cfg(all(test, unix))]
    pub(crate) fn from_parts(device: u64, inode: u64) -> Self {
        Self { device, inode }
    }
}

/// The identity the descriptor of an opened directory actually holds.
#[cfg(unix)]
pub(crate) fn open_dir_identity<D>(dir: &D) -> Result<EntryIdentity>
where
    D: DirectoryFd,
{
    file_identity(dir.file(), dir.path())
}

/// The identity an open descriptor holds, whatever name was used to reach it.
///
/// `display_path` names the descriptor for a failure only; the answer comes
/// from the open file, so a name repointed since the open cannot change it. A
/// permission walk asks this about a directory it reached from a listing, so the
/// name it carries is one the directory's owner chose and is spelled out.
#[cfg(unix)]
pub(crate) fn file_identity(file: &File, display_path: &Path) -> Result<EntryIdentity> {
    let metadata = file.metadata().map_err(|error| {
        Error::build_io_error_with_source(
            format!(
                "Failed to inspect directory: {}",
                format_finding_path(display_path)
            ),
            error,
        )
    })?;
    Ok(EntryIdentity::from_metadata(&metadata))
}

#[cfg(unix)]
impl ScannedChild {
    pub(crate) fn name(&self) -> &ChildName {
        match self {
            Self::Inspected { name, .. } | Self::Unreadable { name, .. } => name,
        }
    }
}

/// How many entries one scan may inspect before it stops reading a directory.
///
/// A caller that judges what it gets back has a bound on that work, and the
/// bound is worth nothing if the listing behind it is unbounded: a directory
/// holding a million entries costs a million `statat` calls and a million
/// allocations before the first one is ever judged.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScanBudget {
    Unlimited,
    AtMost(usize),
}

#[cfg(unix)]
impl ScanBudget {
    /// Whether an entry beyond `inspected` may still be inspected.
    fn allows(self, inspected: usize) -> bool {
        match self {
            Self::Unlimited => true,
            Self::AtMost(limit) => inspected < limit,
        }
    }
}

/// The entries one scan inspected, and whether the directory held more.
#[cfg(unix)]
pub(crate) struct ScannedChildren {
    pub(crate) entries: Vec<ScannedChild>,
    pub(crate) truncated: bool,
}

/// List children together with the metadata one `statat` already returned.
///
/// Reading the mode here rather than opening each entry later keeps a file the
/// owner cannot open from being reported as unreadable when its mode is exactly
/// what makes it dangerous.
///
/// Reading stops as soon as the budget is spent and one further entry has been
/// seen, so the caller learns the listing was cut short without paying for the
/// rest of it. The entries kept are whichever ones `readdir` returned first;
/// the sort that follows only makes the result stable, not complete.
///
/// The budget is charged for every entry inspected rather than for every entry
/// handed back. An entry that disappeared between the listing and its `statat`
/// is left out of the result but was still paid for, and counting the result
/// instead would let a directory whose entries keep vanishing draw as many
/// `statat` calls as it likes out of a caller that asked for a bounded scan.
#[cfg(unix)]
pub(crate) fn scan_child_entries_at<D>(dir: &D, budget: ScanBudget) -> Result<ScannedChildren>
where
    D: DirectoryFd,
{
    let stream = rfs::Dir::read_from(dir.file()).map_err(|error| {
        io_error(
            format!(
                "Failed to read directory: {}",
                format_finding_path(dir.path())
            ),
            error,
        )
    })?;
    let mut entries = Vec::new();
    let mut inspected = 0;
    let mut truncated = false;
    for entry in stream {
        let entry = entry.map_err(|error| read_directory_entry_error(dir, error))?;
        let raw = entry.file_name();
        if raw.to_bytes() == b"." || raw.to_bytes() == b".." {
            continue;
        }
        if !budget.allows(inspected) {
            truncated = true;
            break;
        }
        inspected += 1;
        entries.extend(scan_one_child(dir, ChildName::new(raw.to_owned())));
    }
    entries.sort_by(|left, right| left.name().raw.cmp(&right.name().raw));
    Ok(ScannedChildren { entries, truncated })
}

/// Inspect one entry the listing returned, or report that it is no longer there.
///
/// An entry that vanished between the listing and this inspection is left out
/// rather than reported as unreadable. Another command removing what it wrote
/// is ordinary, and treating the gap it leaves as a failure would end an
/// unrelated listing over a directory that is perfectly fine.
#[cfg(unix)]
fn scan_one_child<D>(dir: &D, name: ChildName) -> Option<ScannedChild>
where
    D: DirectoryFd,
{
    if scanned_child_vanished() {
        return None;
    }
    match rfs::statat(dir.file(), name.raw.as_c_str(), AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => Some(ScannedChild::Inspected {
            child_type: child_type_from_raw(FileType::from_raw_mode(stat.st_mode)),
            mode: permission_bits(stat.st_mode),
            owner: stat.st_uid,
            identity: EntryIdentity::from_stat(&stat),
            name,
        }),
        Err(error) if is_not_found(error) => None,
        Err(error) => {
            let error = io_error(
                format!(
                    "Failed to inspect entry: {}",
                    format_finding_path(&name.path_under(dir))
                ),
                error,
            );
            Some(ScannedChild::Unreadable { name, error })
        }
    }
}

// Test-only seam: makes one entry answer as if it had been removed between the
// listing and its own inspection, which is the case a scan pays for and cannot
// hand back. Reproducing it needs another process removing an entry inside a
// window this call opens, so the window is opened here instead. Compiled out of
// production builds.
#[cfg(all(test, unix))]
thread_local! {
    static VANISH_NEXT_SCANNED_CHILD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(all(test, unix))]
fn vanish_next_scanned_child() {
    VANISH_NEXT_SCANNED_CHILD.with(|slot| slot.set(true));
}

#[cfg(all(test, unix))]
fn scanned_child_vanished() -> bool {
    VANISH_NEXT_SCANNED_CHILD.with(|slot| slot.replace(false))
}

#[cfg(all(not(test), unix))]
fn scanned_child_vanished() -> bool {
    false
}

/// Widen a raw mode to the one width the rest of the code uses.
///
/// `RawMode` is `u16` on some targets and `u32` on others, so the conversion is
/// written out here once instead of at each use, where one spelling or the
/// other would be a lint failure depending on the platform.
#[cfg(unix)]
#[allow(clippy::useless_conversion)]
fn permission_bits(mode: rfs::RawMode) -> u32 {
    u32::from(mode)
}

/// Open a scanned child directory, addressing it by the bytes `readdir` gave.
///
/// A name that does not decode still names a directory, and its contents are
/// exactly what a caller inspecting the tree must not be made to skip.
#[cfg(unix)]
pub(crate) fn open_scanned_child_dir<D>(dir: &D, name: &ChildName) -> Result<Option<OpenDir>>
where
    D: DirectoryFd,
{
    let fd = match rfs::openat(
        dir.file(),
        name.raw.as_c_str(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(error) if is_not_found(error) => return Ok(None),
        Err(error) => {
            return Err(io_error(
                format!(
                    "Failed to open directory: {}",
                    format_finding_path(&name.path_under(dir))
                ),
                error,
            ))
        }
    };
    Ok(Some(OpenDir {
        file: fd.into(),
        path: name.path_under(dir),
        scope: dir.scope(),
    }))
}

/// List every child by decoded name, refusing a directory holding a name that
/// does not decode. Callers that must inspect such a directory anyway use
/// `scan_child_entries_at`, which reports each entry on its own.
#[cfg(unix)]
pub(crate) fn list_child_entries_at<D>(dir: &D) -> Result<Vec<(String, ChildType)>>
where
    D: DirectoryFd,
{
    scan_child_entries_at(dir, ScanBudget::Unlimited)?
        .entries
        .into_iter()
        .map(|child| match child {
            ScannedChild::Inspected {
                name, child_type, ..
            } => match name.decoded() {
                Some(decoded) => Ok((decoded.to_string(), child_type)),
                None => Err(invalid_utf8_child_name(dir, &name)),
            },
            ScannedChild::Unreadable { error, .. } => Err(error),
        })
        .collect()
}

/// Whether a regular file of that name is present.
///
/// An entry of any other type is an error rather than an absence: callers treat
/// `false` as "the document was never written", and reporting an occupied name
/// that way would make them act on state they cannot actually read.
#[cfg(unix)]
pub(crate) fn regular_file_exists_at<D>(dir: &D, name: &str) -> Result<bool>
where
    D: DirectoryFd,
{
    let child = checked_child_name(name)?;
    let stat = match rfs::statat(dir.file(), child.as_c_str(), AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(error) if is_not_found(error) => return Ok(false),
        Err(error) => {
            return Err(io_error(
                format!("Failed to inspect file: {}", child_path(dir, name)),
                error,
            ))
        }
    };
    match child_type_from_raw(FileType::from_raw_mode(stat.st_mode)) {
        ChildType::RegularFile => Ok(true),
        _ => Err(invalid_regular_file_type(dir, name, "non-regular file")),
    }
}

/// The refusal for an entry a caller required to be a regular file.
///
/// A caller that took the entry type from a directory scan reports it in the
/// same words as a caller that looked the single name up, so an occupied name
/// reads the same however it was found.
pub(crate) fn non_regular_file_error<D>(dir: &D, name: &str) -> Error
where
    D: DirectoryFd,
{
    invalid_regular_file_type(dir, name, "non-regular file")
}

/// Name the entry standing where a write expected a file of its own, or `None`
/// for a regular file, which a publishing rename may replace.
///
/// Every caller that refuses to take over an occupied name reports it in these
/// words, so the same entry reads the same whichever document was being written.
pub(crate) fn describe_unreplaceable_child_type(child_type: ChildType) -> Option<&'static str> {
    match child_type {
        ChildType::RegularFile => None,
        ChildType::Symlink => Some("symlink"),
        ChildType::Directory => Some("directory"),
        ChildType::Other => Some("non-regular file"),
    }
}

/// Compare what stands under `name` with the text a reviewer read.
///
/// Only the bytes are compared. The name is opened again, so the entry this
/// reads and the one the reviewer read are two lookups and may be two inodes;
/// a caller that needs the entry itself to be the reviewed one checks the
/// descriptor it kept instead of relying on this.
#[cfg(unix)]
pub(crate) fn ensure_text_file_content_matches_at<D>(
    dir: &D,
    name: &str,
    reviewed_content: Option<&str>,
    subject_display: &str,
    max_bytes: usize,
) -> Result<()>
where
    D: DirectoryFd,
{
    match reviewed_content {
        Some(reviewed_content) => {
            let current = load_text_with_limit_at(dir, name, max_bytes, subject_display).map_err(
                |error| classify_review_comparison_failure(dir, name, subject_display, error),
            )?;
            if current == reviewed_content {
                return Ok(());
            }
        }
        None => {
            if !file_exists_at(dir, name)? {
                return Ok(());
            }
        }
    }

    Err(review_changed_error(subject_display))
}

/// Say whether the file changed or whether it could not be compared at all.
///
/// A file the reviewer saw that is gone now, or that some other entry type
/// stands at now, has changed. A read that failed for its own reason — denied
/// permission, an I/O fault, content past the size cap — leaves the question
/// open, and answering it with "changed since review" sends the operator back
/// to review a file when what they have to fix is the read.
#[cfg(unix)]
fn classify_review_comparison_failure<D>(
    dir: &D,
    name: &str,
    subject_display: &str,
    error: Error,
) -> Error
where
    D: DirectoryFd,
{
    let vanished = matches!(file_exists_at(dir, name), Ok(false));
    let replaced = matches!(
        error.kind(),
        crate::ErrorKind::NotFound | crate::ErrorKind::InvalidOperation
    );
    if vanished || replaced {
        return review_changed_error(subject_display);
    }
    Error::build_io_error(format!(
        "{} could not be compared with the state that was reviewed: {}",
        subject_display,
        error.format_user_message()
    ))
}

#[cfg(unix)]
fn review_changed_error(subject_display: &str) -> Error {
    Error::build_invalid_operation_error(format!(
        "{} changed since review and must be reviewed again.",
        subject_display
    ))
}

#[cfg(unix)]
pub(crate) fn save_text_at<D>(dir: &D, name: &str, content: &str) -> Result<()>
where
    D: DirectoryFd,
{
    save_bytes_at_with_mode(dir, name, content.as_bytes(), None)
}

#[cfg(unix)]
pub(crate) fn save_bytes_at<D>(dir: &D, name: &str, data: &[u8]) -> Result<()>
where
    D: DirectoryFd,
{
    save_bytes_at_with_mode(dir, name, data, None)
}

#[cfg(unix)]
pub(crate) fn save_text_restricted_at<D>(dir: &D, name: &str, content: &str) -> Result<()>
where
    D: DirectoryFd,
{
    save_bytes_restricted_at(dir, name, content.as_bytes())
}

#[cfg(unix)]
pub(crate) fn save_bytes_restricted_at<D>(dir: &D, name: &str, data: &[u8]) -> Result<()>
where
    D: DirectoryFd,
{
    save_bytes_at_with_mode(dir, name, data, Some(Mode::from(0o600)))
}

/// Publish content under a name nothing may already hold.
///
/// The content is staged beside its target and moved onto the final name with a
/// no-replace rename, so an entry that appeared since the caller last looked is
/// reported rather than overwritten.
///
/// The staging name is formed here for the same reason every other write forms
/// it here: a caller that stages under a name of its own and then saves that
/// name is staged a second time, and the two suffixes together outgrow what a
/// directory entry holds. Bounding the caller's name once is what keeps the
/// refusal about the name they chose.
#[cfg(unix)]
pub(crate) fn create_text_noreplace_at<D>(dir: &D, name: &str, content: &str) -> Result<()>
where
    D: DirectoryFd,
{
    let target = checked_atomic_write_target_name(name)?;
    let temp_name = unique_write_staging_name(name);
    let temp = checked_child_name(&temp_name)?;
    write_staged_file(dir, &temp_name, temp.as_c_str(), content.as_bytes(), None)?;
    if let Err(error) =
        rename_child_noreplace(dir, temp.as_c_str(), &temp_name, target.as_c_str(), name)
    {
        discard_staged_file(dir, &temp_name);
        return Err(error);
    }
    sync_changed_entry(dir).map_err(|error| unsynced_entry_error(dir, name, &error))
}

#[cfg(unix)]
fn save_bytes_at_with_mode<D>(dir: &D, name: &str, data: &[u8], mode: Option<Mode>) -> Result<()>
where
    D: DirectoryFd,
{
    let target = checked_atomic_write_target_name(name)?;
    let temp_name = unique_write_staging_name(name);
    let temp = checked_child_name(&temp_name)?;
    write_staged_file(dir, &temp_name, temp.as_c_str(), data, mode)?;
    publish_staged_file(dir, name, &temp_name, temp.as_c_str(), target.as_c_str())
}

/// Fill the file a write stages beside its target, leaving nothing on failure.
///
/// The descriptor is closed before the cleanup so the entry is unlinked with no
/// writer still holding it, and a staged file is removed rather than left for
/// the next caller to find standing in the directory.
#[cfg(unix)]
fn write_staged_file<D>(
    dir: &D,
    temp_name: &str,
    temp: &std::ffi::CStr,
    data: &[u8],
    mode: Option<Mode>,
) -> Result<()>
where
    D: DirectoryFd,
{
    let create_mode = mode.unwrap_or(Mode::from(0o666));
    let mut temp_file = create_temp_file(dir, temp, temp_name, create_mode)?;
    let result = apply_saved_file_mode(dir, &temp_file, temp_name, mode)
        .and_then(|()| write_and_sync(&mut temp_file, data));
    drop(temp_file);
    if let Err(error) = result {
        discard_staged_file(dir, temp_name);
        return Err(error);
    }
    Ok(())
}

/// Give the staged file the mode its finished entry has to carry.
///
/// A restricted write pins 0600 whatever the umask allows. An ordinary write
/// keeps the umask-derived mode the create produced and adds the owner bits
/// back: a umask that masks them would otherwise leave behind an entry its own
/// owner cannot read.
#[cfg(unix)]
fn apply_saved_file_mode<D>(dir: &D, file: &File, name: &str, mode: Option<Mode>) -> Result<()>
where
    D: DirectoryFd,
{
    let mode = match mode {
        Some(mode) => mode,
        None => owner_readable_umask_mode(dir, file, name)?,
    };
    set_open_file_mode(dir, file, name, mode)
}

#[cfg(unix)]
fn owner_readable_umask_mode<D>(dir: &D, file: &File, name: &str) -> Result<Mode>
where
    D: DirectoryFd,
{
    let stat = rfs::fstat(file).map_err(|error| {
        io_error(
            format!("Failed to inspect file: {}", child_path(dir, name)),
            error,
        )
    })?;
    Ok((Mode::from_raw_mode(stat.st_mode) & Mode::from(0o777)) | Mode::from(0o600))
}

/// Rename the staged file onto its final name and persist the directory entry.
#[cfg(unix)]
fn publish_staged_file<D>(
    dir: &D,
    name: &str,
    temp_name: &str,
    temp: &std::ffi::CStr,
    target: &std::ffi::CStr,
) -> Result<()>
where
    D: DirectoryFd,
{
    rfs::renameat(dir.file(), temp, dir.file(), target).map_err(|error| {
        discard_staged_file(dir, temp_name);
        io_error(
            format!("Persist to {} failed", child_path(dir, name)),
            error,
        )
    })?;
    sync_changed_entry(dir).map_err(|error| unsynced_entry_error(dir, name, &error))
}

/// Persist the directory entry a publish or a removal just changed.
///
/// A test can make this fail once to check that a change already on disk is
/// reported as the change it is rather than as one that never happened.
#[cfg(all(test, unix))]
fn sync_changed_entry<D>(dir: &D) -> Result<()>
where
    D: DirectoryFd,
{
    if FAIL_NEXT_PARENT_SYNC.with(|flag| flag.replace(false)) {
        return Err(Error::build_io_error("Injected parent sync failure"));
    }
    sync_directory_at(dir)
}

#[cfg(all(not(test), unix))]
fn sync_changed_entry<D>(dir: &D) -> Result<()>
where
    D: DirectoryFd,
{
    sync_directory_at(dir)
}

#[cfg(all(test, unix))]
thread_local! {
    static FAIL_NEXT_PARENT_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(all(test, unix))]
fn fail_next_parent_sync() {
    FAIL_NEXT_PARENT_SYNC.with(|flag| flag.set(true));
}

/// Report a file the rename published but whose entry was not persisted.
///
/// The rename is the point the content becomes readable, and it already
/// happened. A bare sync failure reads as "nothing was saved" and sends the
/// operator to write again over content that is already on disk.
#[cfg(unix)]
fn unsynced_entry_error<D>(dir: &D, name: &str, error: &Error) -> Error
where
    D: DirectoryFd,
{
    Error::build_io_error(format_post_change_failure(
        "File",
        &dir.path().join(name),
        CompletedChange::Written,
        "its directory entry was not persisted, so a crash before the next sync could lose it",
        error.format_user_message(),
    ))
}

/// Remove the temporary a failed write left behind.
///
/// Cleanup runs while an earlier failure is being reported, so a leftover is
/// logged rather than replacing that failure.
#[cfg(unix)]
fn discard_staged_file<D>(dir: &D, temp_name: &str)
where
    D: DirectoryFd,
{
    if unlink_child(dir, temp_name).is_err() {
        tracing::warn!("Left a staged file behind: {}", child_path(dir, temp_name));
    }
}

/// Persist the directory entry created by the rename.
#[cfg(unix)]
pub(crate) fn sync_directory_at<D>(dir: &D) -> Result<()>
where
    D: DirectoryFd,
{
    rfs::fsync(dir.file()).map_err(|e| {
        io_error(
            format!("Directory sync failed: {}", format_finding_path(dir.path())),
            e,
        )
    })
}

/// What one removal left behind.
///
/// The unlink is the point the name stops resolving, and it can succeed with the
/// directory entry still unpersisted. The two outcomes are told apart here
/// rather than by each caller looking the entry up again: a caller told only
/// that the removal failed reports a document as still there when the name it
/// stood under is already free.
#[cfg(unix)]
#[must_use]
#[derive(Debug)]
pub(crate) enum RemovedEntry {
    /// The entry is gone and the directory entry naming it is on storage.
    Persisted,
    /// The entry is gone; persisting the directory entry failed for this reason.
    Unpersisted(Error),
}

/// Unlink one entry and say whether the directory entry was persisted.
///
/// A failure is only ever the unlink's own: the entry is still there and the
/// name still resolves to it.
#[cfg(unix)]
pub(crate) fn remove_file_at<D>(dir: &D, name: &str) -> Result<RemovedEntry>
where
    D: DirectoryFd,
{
    unlink_child(dir, name)?;
    match sync_changed_entry(dir) {
        Ok(()) => Ok(RemovedEntry::Persisted),
        Err(error) => Ok(RemovedEntry::Unpersisted(error)),
    }
}

#[cfg(unix)]
pub(crate) fn remove_file_if_exists_at<D>(dir: &D, name: &str) -> Result<()>
where
    D: DirectoryFd,
{
    if unlink_child_if_exists(dir, name, AtFlags::empty(), "file")? {
        sync_directory_at(dir)?;
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn remove_empty_child_dir_if_exists_at<D>(dir: &D, name: &str) -> Result<()>
where
    D: DirectoryFd,
{
    if unlink_child_if_exists(dir, name, AtFlags::REMOVEDIR, "directory")? {
        sync_directory_at(dir)?;
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn rename_child_noreplace_unsynced_at<D>(
    dir: &D,
    source: &str,
    destination: &str,
) -> Result<()>
where
    D: DirectoryFd,
{
    let source_child = checked_child_name(source)?;
    let destination_child = checked_child_name(destination)?;
    rename_child_noreplace(
        dir,
        source_child.as_c_str(),
        source,
        destination_child.as_c_str(),
        destination,
    )
}

#[cfg(unix)]
fn validate_directory_path(path: &Path, scope: DirectoryScope) -> Result<()> {
    let metadata =
        std::fs::metadata(path).map_err(|error| inspect_directory_path_error(path, error))?;
    if metadata.is_dir() {
        return Ok(());
    }
    Err(invalid_directory_type(path, "non-directory", scope))
}

/// Report a path-addressed directory open that could not inspect what it named.
///
/// Only a path the caller spelled out reaches here — a workspace root, a local
/// state root, or one assembled from fixed component names — so the name is
/// shortened against the working directory the way the rest of that path is,
/// rather than spelled out the way a name read off a directory is.
fn inspect_directory_path_error(path: &Path, error: std::io::Error) -> Error {
    let display = format_path_relative_to_cwd(path);
    if error.kind() == std::io::ErrorKind::NotFound {
        return Error::build_not_found_error(format!("Directory not found: {display}"));
    }
    Error::build_io_error_with_source(format!("Failed to inspect directory: {display}"), error)
}

fn invalid_directory_type(path: &Path, kind: &str, scope: DirectoryScope) -> Error {
    scoped_invalid_operation_error(
        scope,
        format!(
            "refusing to open {kind} as directory: {}",
            format_finding_path(path)
        ),
    )
}

/// Name the entry type that stands where a directory was expected.
#[cfg(unix)]
fn mismatched_dir_kind(child_type: ChildType) -> Option<&'static str> {
    match child_type {
        ChildType::Directory => None,
        ChildType::Symlink => Some("symlink"),
        ChildType::RegularFile | ChildType::Other => Some("non-directory"),
    }
}

/// Turn a failed child directory open into the error that names the entry type.
///
/// `openat` with `O_DIRECTORY | O_NOFOLLOW` reports a symlink through an errno
/// that differs between platforms, so the entry is stat'ed back and the message
/// follows the type it actually has rather than the failure it produced.
#[cfg(unix)]
fn open_child_dir_error<D>(
    parent: &D,
    name: &str,
    child: &std::ffi::CStr,
    error: rustix::io::Errno,
) -> Error
where
    D: DirectoryFd,
{
    let path = parent.path().join(name);
    if let Some(kind) = child_type_at(parent, name, child)
        .ok()
        .and_then(mismatched_dir_kind)
    {
        return invalid_directory_type(&path, kind, parent.scope());
    }
    open_directory_error(&path, error)
}

/// Turn a failed directory open named by path into a not-found or I/O error.
///
/// A type mismatch is settled before the open by the caller, which stats the
/// path and names the type it found, so no type is inferred from the errno here.
#[cfg(unix)]
fn open_directory_error(path: &Path, error: rustix::io::Errno) -> Error {
    if is_not_found(error) {
        return Error::build_not_found_error(format!(
            "Directory not found: {}",
            format_finding_path(path)
        ));
    }
    io_error(
        format!("Failed to open directory: {}", format_finding_path(path)),
        error,
    )
}

#[cfg(unix)]
fn read_directory_entry_error<D>(dir: &D, error: rustix::io::Errno) -> Error
where
    D: DirectoryFd,
{
    io_error(
        format!(
            "Failed to read directory entry in {}",
            format_finding_path(dir.path())
        ),
        error,
    )
}

fn invalid_utf8_child_name<D>(dir: &D, name: &ChildName) -> Error
where
    D: DirectoryFd,
{
    invalid_operation_error(
        dir,
        format!(
            "Directory {} contains an entry whose name is not UTF-8: {}",
            format_finding_path(dir.path()),
            format_path_for_message(&String::from_utf8_lossy(name.raw.as_bytes())),
        ),
    )
}

/// What stands under `name`, or nothing when the name is free.
#[cfg(unix)]
pub(crate) fn optional_child_type_at<D>(dir: &D, name: &str) -> Result<Option<ChildType>>
where
    D: DirectoryFd,
{
    let child = checked_child_name(name)?;
    match rfs::statat(dir.file(), child.as_c_str(), AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => Ok(Some(child_type_from_raw(FileType::from_raw_mode(
            stat.st_mode,
        )))),
        Err(error) if is_not_found(error) => Ok(None),
        Err(error) => Err(io_error(
            format!("Failed to inspect entry: {}", child_path(dir, name)),
            error,
        )),
    }
}

#[cfg(unix)]
fn child_type_at<D>(dir: &D, name: &str, child: &std::ffi::CStr) -> Result<ChildType>
where
    D: DirectoryFd,
{
    let stat = rfs::statat(dir.file(), child, AtFlags::SYMLINK_NOFOLLOW).map_err(|error| {
        io_error(
            format!("Failed to inspect entry: {}", child_path(dir, name)),
            error,
        )
    })?;
    Ok(child_type_from_raw(FileType::from_raw_mode(stat.st_mode)))
}

#[cfg(unix)]
fn child_type_from_file_type(file_type: &std::fs::FileType) -> ChildType {
    if file_type.is_symlink() {
        return ChildType::Symlink;
    }
    if file_type.is_dir() {
        return ChildType::Directory;
    }
    if file_type.is_file() {
        return ChildType::RegularFile;
    }
    ChildType::Other
}

#[cfg(unix)]
fn child_type_from_raw(file_type: FileType) -> ChildType {
    match file_type {
        FileType::Directory => ChildType::Directory,
        FileType::RegularFile => ChildType::RegularFile,
        FileType::Symlink => ChildType::Symlink,
        _ => ChildType::Other,
    }
}

fn invalid_regular_file_type<D>(dir: &D, name: &str, kind: &str) -> Error
where
    D: DirectoryFd,
{
    invalid_operation_error(
        dir,
        format!("refusing to use {kind}: {}", child_path(dir, name)),
    )
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "redox",
    target_vendor = "apple",
))]
fn rename_child_noreplace<D>(
    dir: &D,
    source_child: &std::ffi::CStr,
    source: &str,
    destination_child: &std::ffi::CStr,
    destination: &str,
) -> Result<()>
where
    D: DirectoryFd,
{
    rfs::renameat_with(
        dir.file(),
        source_child,
        dir.file(),
        destination_child,
        RenameFlags::NOREPLACE,
    )
    .map_err(|error| {
        if std::io::Error::from(error).kind() == std::io::ErrorKind::AlreadyExists {
            return invalid_operation_error(
                dir,
                format!(
                    "refusing to replace existing entry: {}",
                    child_path(dir, destination)
                ),
            );
        }
        io_error(
            format!(
                "Failed to rename {} to {}",
                child_path(dir, source),
                child_path(dir, destination)
            ),
            error,
        )
    })
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "redox",
    target_vendor = "apple",
)))]
compile_error!(
    "kapsaro requires atomic no-replace rename (renameat2 / renameatx_np); \
     supported targets are Linux, Android, Redox and Apple platforms"
);

#[cfg(unix)]
pub(crate) fn open_regular_file_at<D>(dir: &D, name: &str) -> Result<File>
where
    D: DirectoryFd,
{
    let child = checked_child_name(name)?;
    validate_pre_open_file_type(dir, name, child.as_c_str())?;
    let fd = rfs::openat(
        dir.file(),
        child.as_c_str(),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| {
        io_error(
            format!("Failed to read file {}: {}", child_path(dir, name), e),
            e,
        )
    })?;
    let file: File = fd.into();
    validate_regular_file(&file, &child_path(dir, name), dir.scope())?;
    Ok(file)
}

#[cfg(unix)]
fn validate_pre_open_file_type<D>(dir: &D, name: &str, child: &std::ffi::CStr) -> Result<()>
where
    D: DirectoryFd,
{
    let path = child_path(dir, name);
    let stat = rfs::statat(dir.file(), child, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|e| io_error(format!("Failed to read file {}: {}", path, e), e))?;
    validate_raw_file_type(FileType::from_raw_mode(stat.st_mode), &path, dir.scope())
}

#[cfg(unix)]
fn validate_regular_file(file: &File, path: &str, scope: DirectoryScope) -> Result<()> {
    let metadata = file.metadata().map_err(|e| {
        Error::build_io_error_with_source(format!("Failed to read file {path}: {e}"), e)
    })?;
    if metadata.file_type().is_file() {
        return Ok(());
    }
    Err(scoped_invalid_operation_error(
        scope,
        format!("refusing to read non-regular file: {path}"),
    ))
}

#[cfg(unix)]
fn validate_raw_file_type(file_type: FileType, path: &str, scope: DirectoryScope) -> Result<()> {
    if file_type == FileType::RegularFile {
        return Ok(());
    }
    Err(scoped_invalid_operation_error(
        scope,
        format!("refusing to read non-regular file: {path}"),
    ))
}

/// Create the file a write stages beside its target.
///
/// `mode` is what the create asks for; the umask still narrows it, and the
/// caller settles the final mode on the descriptor afterwards.
#[cfg(unix)]
fn create_temp_file<D>(dir: &D, temp: &std::ffi::CStr, temp_name: &str, mode: Mode) -> Result<File>
where
    D: DirectoryFd,
{
    let fd = rfs::openat(
        dir.file(),
        temp,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        mode,
    )
    .map_err(|e| {
        io_error(
            format!("Failed to create temp file: {}", child_path(dir, temp_name)),
            e,
        )
    })?;
    Ok(fd.into())
}

#[cfg(unix)]
fn set_open_file_mode<D>(dir: &D, file: &File, name: &str, mode: Mode) -> Result<()>
where
    D: DirectoryFd,
{
    rfs::fchmod(file, mode).map_err(|e| {
        io_error(
            format!("Failed to set file permissions: {}", child_path(dir, name)),
            e,
        )
    })
}

/// Write and persist the contents to storage.
///
/// `flush` only hands the bytes to the kernel. Without the sync the rename can
/// reach disk while the contents have not, leaving an empty or truncated file
/// after a crash.
fn write_and_sync(file: &mut File, data: &[u8]) -> Result<()> {
    file.write_all(data)
        .map_err(|e| Error::build_io_error_with_source(format!("Write failed: {}", e), e))?;
    file.sync_all()
        .map_err(|e| Error::build_io_error_with_source(format!("Sync failed: {}", e), e))
}

#[cfg(unix)]
fn unlink_child<D>(dir: &D, name: &str) -> Result<()>
where
    D: DirectoryFd,
{
    let child = checked_child_name(name)?;
    rfs::unlinkat(dir.file(), child.as_c_str(), AtFlags::empty()).map_err(|e| {
        Error::build_io_error_with_source(
            format!("Failed to remove file {}: {}", child_path(dir, name), e),
            std::io::Error::from(e),
        )
    })
}

#[cfg(unix)]
fn unlink_child_if_exists<D>(dir: &D, name: &str, flags: AtFlags, kind: &str) -> Result<bool>
where
    D: DirectoryFd,
{
    let child = checked_child_name(name)?;
    match rfs::unlinkat(dir.file(), child.as_c_str(), flags) {
        Ok(()) => Ok(true),
        Err(error) if is_not_found(error) => Ok(false),
        Err(error) => Err(io_error(
            format!("Failed to remove {kind} {}", child_path(dir, name)),
            error,
        )),
    }
}

/// Bind a name kapsaro chose itself to one usable in a syscall.
///
/// A backslash is refused on top of what a path component cannot hold, because
/// every name reaching here is one the specification fixes and none of them
/// carry one; a name that does is a caller passing something it assembled.
fn checked_child_name(name: &str) -> Result<CString> {
    if name.as_bytes().contains(&b'\\') {
        return Err(invalid_child_name(name));
    }
    checked_os_child_name(OsStr::new(name)).map_err(|_| invalid_child_name(name))
}

/// Bind one path component the caller's own path holds to a name usable in a
/// syscall.
///
/// The bytes are taken as they stand: only what cannot name a child of a
/// directory at all is refused. A component of a path the operator typed is
/// chosen by them and by the OS, and on Unix it is a byte string rather than
/// text, so nothing here judges whether it decodes.
fn checked_os_child_name(name: &OsStr) -> Result<CString> {
    use std::os::unix::ffi::OsStrExt;

    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes == b"." || bytes == b".." {
        return Err(invalid_os_child_name(name));
    }
    if bytes.contains(&b'/') {
        return Err(invalid_os_child_name(name));
    }
    CString::new(bytes).map_err(|_| invalid_os_child_name(name))
}

fn invalid_child_name(name: &str) -> Error {
    Error::build_invalid_argument_error(format!(
        "invalid relative file name '{}': only a single path component is allowed",
        name
    ))
}

/// Report a path component that cannot name a child, spelling out its bytes.
///
/// The name comes from a path the operator typed and may hold anything a
/// filesystem accepts, so it is spelled out rather than passed through: a
/// newline in one would forge a second line of its own on standard error.
fn invalid_os_child_name(name: &OsStr) -> Error {
    Error::build_invalid_argument_error(format!(
        "invalid relative file name {}: only a single path component is allowed",
        format_path_for_message(&name.to_string_lossy())
    ))
}

fn invalid_operation_error<D>(dir: &D, message: impl Into<String>) -> Error
where
    D: DirectoryFd,
{
    scoped_invalid_operation_error(dir.scope(), message)
}

fn scoped_invalid_operation_error(scope: DirectoryScope, message: impl Into<String>) -> Error {
    match scope {
        DirectoryScope::Generic => Error::build_invalid_operation_error(message),
        DirectoryScope::LocalState => Error::build_local_state_path_unsafe_error(message),
    }
}

/// Name for an entry staged beside the target it will become, or that the
/// target was moved to while an operation on it finishes.
///
/// The shape is what [`is_write_staging_name`] recognises, so an entry left
/// under it is reported by the directory checks with a repair naming the file
/// rather than passing as ordinary content. `checked_atomic_write_target_name`
/// bounds the target so that this longer name still fits `NAME_MAX`.
#[cfg(unix)]
pub(crate) fn unique_write_staging_name(target: &str) -> String {
    format!(".{target}.tmp.{}", uuid::Uuid::new_v4())
}

/// Name for a directory staged beside its final name until a rename publishes it.
pub(crate) fn unique_staging_dir_name() -> String {
    format!(".tmp-{}", uuid::Uuid::new_v4())
}

/// Whether a name has the shape of an entry staged by an unfinished write.
///
/// Both shapes are recognised: `.{target}.tmp.{uuid}` from an atomic file write
/// and `.tmp-{uuid}` from a staged directory. Only the name is examined, so a
/// caller reports the leftover rather than deleting what it found.
pub(crate) fn is_write_staging_name(name: &str) -> bool {
    if let Some(suffix) = name.strip_prefix(".tmp-") {
        return is_hyphenated_uuid(suffix);
    }
    let Some((prefix, suffix)) = name.rsplit_once(".tmp.") else {
        return false;
    };
    prefix.len() > 1 && prefix.starts_with('.') && is_hyphenated_uuid(suffix)
}

fn is_hyphenated_uuid(value: &str) -> bool {
    value.len() == 36 && uuid::Uuid::parse_str(value).is_ok()
}

/// Validate a name an atomic write will stage under `.{name}.tmp.{uuid}`.
///
/// The staging name is longer than the target, so a target that fits `NAME_MAX`
/// on its own can still be unwritable. Rejecting it here reports the target the
/// caller chose rather than an opaque name-too-long failure on the temporary.
fn checked_atomic_write_target_name(name: &str) -> Result<CString> {
    if name.len() > MAX_ATOMIC_WRITE_TARGET_NAME_LENGTH {
        return Err(Error::build_invalid_argument_error(format!(
            "file name too long for an atomic write: {} bytes (max {})",
            name.len(),
            MAX_ATOMIC_WRITE_TARGET_NAME_LENGTH
        )));
    }
    checked_child_name(name)
}

/// Name one child of a directory inside a message an operator reads.
///
/// A child's name is chosen by whoever can write the directory, so it is spelled
/// out rather than passed through: a newline in one would let it forge a second
/// line of its own on standard error.
fn child_path<D>(dir: &D, name: &str) -> String
where
    D: DirectoryFd,
{
    format_finding_path(&dir.path().join(name))
}

#[cfg(unix)]
fn io_error(message: String, error: rustix::io::Errno) -> Error {
    Error::build_io_error_with_source(message, std::io::Error::from(error))
}

#[cfg(unix)]
fn is_not_found(error: rustix::io::Errno) -> bool {
    std::io::Error::from(error).kind() == std::io::ErrorKind::NotFound
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/support_fs_relative_test.rs"]
mod support_fs_relative_test;
