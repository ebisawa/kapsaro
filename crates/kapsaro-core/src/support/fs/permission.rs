// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Filesystem permission inspection for local state files and directories.
//! Collects findings as warnings instead of stopping the operation that made them.

use std::fs;
use std::fs::File;
use std::path::{Path, PathBuf};

use crate::support::display::format_path_for_message;
// Every finding in this module names a path an entry's owner may have chosen,
// so each one goes through `DisplayBase::finding`; a raw display would let a
// name carry control characters or quotes straight into the operator's terminal.
use crate::support::path::{path_or_current_dir, DisplayBase};
use crate::support::shell::{append_repair_command, format_repair_command};
#[cfg(unix)]
use crate::support::warning::{
    record_local_state_warning, LocalStateWarning, LocalStateWarningCode,
};
use crate::Result;

use super::policy::{ensure_real_directory_tree, DirectoryKind};
#[cfg(unix)]
use super::relative::{
    open_dir_identity, open_scanned_child_dir, scan_child_entries_at, ChildName, ChildType,
    DirectoryFd, DirectoryScope, EntryIdentity, OpenDir, ScanBudget, ScannedChild,
};

pub fn ensure_dir(path: &Path) -> Result<()> {
    ensure_real_directory_tree(path, DirectoryKind::General)
}

/// What makes one local state entry unsafe for its owner.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum PermissionViolationKind {
    InsecureMode,
    ForeignOwner,
    Unreadable,
    UndecodableName,
    UnexpectedEntryType,
    ReplacedEntry,
    InsecureAncestor,
    UnreadableAncestor,
    UnresolvableAncestry,
    IncompleteScan,
}

/// One local state entry that group or other can reach, described for the operator.
#[cfg(unix)]
#[derive(Debug, Clone)]
pub(crate) struct PermissionViolation {
    path: PathBuf,
    kind: PermissionViolationKind,
    message: String,
}

#[cfg(unix)]
impl PermissionViolation {
    fn new(path: &Path, kind: PermissionViolationKind, message: String) -> Self {
        Self {
            path: path.to_path_buf(),
            kind,
            message,
        }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn kind(&self) -> PermissionViolationKind {
        self.kind
    }

    pub(crate) fn message(&self) -> &str {
        &self.message
    }
}

/// Owner-only mode a local state entry must carry.
#[cfg(unix)]
fn expected_mode(is_dir: bool) -> &'static str {
    if is_dir {
        "0700"
    } else {
        "0600"
    }
}

#[cfg(unix)]
fn describe_violation(
    base: &DisplayBase,
    mode: u32,
    is_dir: bool,
    display_path: &Path,
) -> PermissionViolation {
    let expected = expected_mode(is_dir);
    let explanation = format!(
        "Insecure permissions {:04o} on {} (expected {})",
        mode & 0o7777,
        base.finding(display_path),
        expected,
    );
    PermissionViolation::new(
        display_path,
        PermissionViolationKind::InsecureMode,
        append_repair_command(&explanation, &format!("chmod {expected}"), display_path),
    )
}

/// Report an entry a different user owns.
///
/// Owner-only permissions say nothing when the owner is somebody else: they can
/// change the mode back whenever they like, so the entry is theirs to rewrite.
#[cfg(unix)]
fn describe_foreign_owner(
    base: &DisplayBase,
    owner: u32,
    is_dir: bool,
    display_path: &Path,
) -> PermissionViolation {
    let subject = if is_dir { "directory" } else { "file" };
    PermissionViolation::new(
        display_path,
        PermissionViolationKind::ForeignOwner,
        format!(
            "Local state {} {} is owned by uid {}, not by the current user; \
             move local state somewhere you own, or select another local state root \
             with --home or KAPSARO_HOME",
            subject,
            base.finding(display_path),
            owner,
        ),
    )
}

/// Report an entry whose mode could not be read at all.
/// Treated as a violation so an unreadable entry never passes as safe.
#[cfg(unix)]
fn describe_unreadable(
    base: &DisplayBase,
    display_path: &Path,
    error: &dyn std::fmt::Display,
) -> PermissionViolation {
    PermissionViolation::new(
        display_path,
        PermissionViolationKind::Unreadable,
        format!(
            "Cannot check permissions on {}: {}",
            base.finding(display_path),
            escape_detail(error)
        ),
    )
}

/// Render a nested failure so it cannot break out of the line it belongs to.
///
/// The detail carries a path of its own, and an entry name is chosen by whoever
/// can write the directory. A newline in one would let it forge a second
/// warning line on standard error, so the whole rendering is escaped rather
/// than only the path this finding names.
#[cfg(unix)]
fn escape_detail(error: &dyn std::fmt::Display) -> String {
    format_path_for_message(&error.to_string())
}

/// Report a walk that stopped before it had seen the whole tree.
///
/// The entries left unread may be the ones another user can reach, so the walk
/// says what it did not cover instead of letting the inspected part stand for
/// the tree.
#[cfg(unix)]
fn describe_incomplete_scan(
    base: &DisplayBase,
    root_path: &Path,
    limit: ScanLimit,
) -> PermissionViolation {
    PermissionViolation::new(
        root_path,
        PermissionViolationKind::IncompleteScan,
        format!(
            "Local state tree below {} holds {}, so the permission scan stopped before it \
             reached every entry; remove what kapsaro did not write below the local state root, \
             or select another local state root with --home or KAPSARO_HOME",
            base.finding(root_path),
            limit.describe_excess(),
        ),
    )
}

/// Which bound of the local state tree walk was reached.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ScanLimit {
    Entries,
    Depth,
}

#[cfg(unix)]
impl ScanLimit {
    fn describe_excess(self) -> String {
        match self {
            Self::Entries => format!("more than {MAX_LOCAL_STATE_TREE_ENTRIES} entries"),
            Self::Depth => format!("more than {MAX_LOCAL_STATE_TREE_DEPTH} levels"),
        }
    }
}

/// The owner and mode of one entry, whichever call read them.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct EntryFacts {
    owner: u32,
    mode: u32,
    is_dir: bool,
}

#[cfg(unix)]
impl EntryFacts {
    pub(crate) fn new(owner: u32, mode: u32, is_dir: bool) -> Self {
        Self {
            owner,
            mode,
            is_dir,
        }
    }

    fn from_metadata(metadata: &fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;

        Self::new(
            metadata.uid(),
            metadata.permissions().mode(),
            metadata.is_dir(),
        )
    }
}

/// Decide what an entry's owner and mode make it.
///
/// Pure so that both branches can be exercised: the owner comparison needs two
/// distinct uids, which no test can arrange with real files.
///
/// The owner is judged first. Owner-only permissions say nothing when the owner
/// is somebody else, because they can put the mode back however they like.
///
/// The mode is judged on `0o077` alone, which is what group and other can do
/// with the entry. Setuid and setgid are left out because neither reaches
/// anybody the `0o077` test does not already catch: they take effect on an
/// executable, and local state holds none, or through a group or other bit that
/// is itself the finding. A setgid directory hands its group to what is created
/// below it, and every write here fixes the mode at 0600 or 0700 regardless.
/// Sticky only takes deletion away from a non-owner, which is the safe
/// direction. The mode is *displayed* as `0o7777` all the same, because the
/// repair the finding offers is `chmod 0700`, which drops the special bits with
/// everything else.
#[cfg(unix)]
pub(crate) fn inspect_entry_facts(
    base: &DisplayBase,
    facts: EntryFacts,
    effective_uid: u32,
    display_path: &Path,
) -> Option<PermissionViolation> {
    if facts.owner != effective_uid {
        return Some(describe_foreign_owner(
            base,
            facts.owner,
            facts.is_dir,
            display_path,
        ));
    }
    if facts.mode & 0o077 == 0 {
        return None;
    }
    Some(describe_violation(
        base,
        facts.mode,
        facts.is_dir,
        display_path,
    ))
}

#[cfg(unix)]
fn effective_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

#[cfg(unix)]
fn inspect_metadata(
    base: &DisplayBase,
    metadata: &fs::Metadata,
    display_path: &Path,
) -> Option<PermissionViolation> {
    inspect_entry_facts(
        base,
        EntryFacts::from_metadata(metadata),
        effective_uid(),
        display_path,
    )
}

/// Report an entry whose name kapsaro cannot decode.
///
/// Every name kapsaro writes is ASCII, so one that does not decode came from
/// somewhere else. The entry is named rather than skipped, and the walk goes on
/// so the entries beside it are still inspected.
#[cfg(unix)]
fn describe_undecodable_name(base: &DisplayBase, display_path: &Path) -> PermissionViolation {
    PermissionViolation::new(
        display_path,
        PermissionViolationKind::UndecodableName,
        format!(
            "Local state holds an entry whose name is not UTF-8, so kapsaro did not write it: {}",
            base.finding(display_path)
        ),
    )
}

/// Report an entry of a type kapsaro never writes into local state.
///
/// A symlink carries no permissions of its own and a device, socket or FIFO
/// carries nothing kapsaro can use, so neither is judged on its mode. Passing
/// over it in silence would be the one case where an entry somebody else placed
/// in local state produces no finding at all, while every read that reaches it
/// is already refused.
#[cfg(unix)]
fn describe_unexpected_entry_type(
    base: &DisplayBase,
    display_path: &Path,
    child_type: ChildType,
) -> PermissionViolation {
    PermissionViolation::new(
        display_path,
        PermissionViolationKind::UnexpectedEntryType,
        format!(
            "Local state holds a {}, which kapsaro does not write and cannot read: {}",
            name_entry_type(child_type),
            base.finding(display_path)
        ),
    )
}

#[cfg(unix)]
fn name_entry_type(child_type: ChildType) -> &'static str {
    match child_type {
        ChildType::Symlink => "symlink",
        ChildType::Directory => "directory",
        ChildType::RegularFile => "regular file",
        ChildType::Other => "special file",
    }
}

/// Report a directory that stopped being the entry the walk had just inspected.
///
/// The mode was read from one inode and the descriptor reached another, so the
/// verdict recorded a moment ago belongs to neither with any certainty.
#[cfg(unix)]
fn describe_replaced_entry(base: &DisplayBase, display_path: &Path) -> PermissionViolation {
    PermissionViolation::new(
        display_path,
        PermissionViolationKind::ReplacedEntry,
        format!(
            "Local state entry {} was replaced while its permissions were being checked, \
             so the result does not describe what is there now; run the check again",
            base.finding(display_path)
        ),
    )
}

/// Write bits that let a different user create or replace entries.
#[cfg(unix)]
const GROUP_OTHER_WRITE_BITS: u32 = 0o022;

/// Bit that stops a non-owner from renaming or deleting entries it does not own.
#[cfg(unix)]
const STICKY_BIT: u32 = 0o1000;

/// Report every directory above `path` that a different user can write.
///
/// The local state entries themselves are owner-only, but that says nothing
/// about the directories leading to them. A directory another user can write
/// lets them move the whole tree aside and put their own in its place, so the
/// keys and pinned trust read afterwards would be theirs.
///
/// This is a configuration audit rather than a race-free capability. The
/// exposure belongs to whoever administers the machine, so it is named for the
/// operator and the command carries on. The directory that is finally opened is
/// pinned by descriptor separately.
#[cfg(unix)]
pub(crate) fn report_local_state_ancestor_safety(path: &Path) {
    report_violations(collect_local_state_ancestor_violations(path));
}

/// Report every directory another user can write on the way to the root.
///
/// A root that is a symlink has two chains leading to it, and both let another
/// user take the tree over: writing the directory that holds the link repoints
/// it, and writing the parent of what it resolves to swaps the target. The
/// chain holding the entry is walked first and the chain it resolves to second,
/// each of them outermost first, and a directory the two share is named once by
/// whichever chain reached it first.
///
/// One view of [`walk_local_state_ancestry`], for a caller that wants only the
/// exposed directories. A caller that wants the owners as well takes both from
/// one scan instead of calling this and its companion, which walks twice.
#[cfg(unix)]
pub(crate) fn collect_local_state_ancestor_violations(path: &Path) -> Vec<PermissionViolation> {
    match walk_local_state_ancestry(path) {
        Ok(scan) => scan.violations,
        Err(reason) => vec![PermissionViolation::new(
            path,
            PermissionViolationKind::UnresolvableAncestry,
            reason,
        )],
    }
}

/// Visit each directory above `path` once, walking both chains outermost first.
///
/// A root that is a symlink has two chains leading to it, and a finding on
/// either is a finding about the path as a whole. The chain holding the entry
/// comes first and the chain it resolves to second, and a directory the two
/// share is named once, by whichever chain reached it first. Every caller wants
/// the same walk, so the merge and the de-duplication live here rather than in
/// each.
#[cfg(unix)]
fn for_each_ancestor<F>(path: &Path, mut visit: F) -> std::io::Result<()>
where
    F: FnMut(&Path),
{
    let bases = resolve_existing_ancestor_bases(path)?;
    let mut seen: Vec<PathBuf> = Vec::new();
    for base in bases {
        // `ancestors` climbs towards the root, so the chain is turned around
        // to reach the operator in the order they repair it.
        let chain: Vec<&Path> = base.ancestors().collect();
        for ancestor in chain.into_iter().rev() {
            if seen.iter().any(|visited| visited == ancestor) {
                continue;
            }
            seen.push(ancestor.to_path_buf());
            visit(ancestor);
        }
    }
    Ok(())
}

/// An ancestor directory a third account owns, named by the diagnostic only.
///
/// Nothing above the local state root is judged on its owner during an ordinary
/// command: the path is administered by whoever runs the machine, and the
/// exposure is the same one a stock home directory carries under root. The type
/// is kept apart from `PermissionViolation` so this finding cannot reach the
/// warning sink every command drains.
#[cfg(unix)]
#[derive(Debug, Clone)]
pub(crate) struct AncestorOwnerFinding {
    path: PathBuf,
    owner: u32,
}

#[cfg(unix)]
impl AncestorOwnerFinding {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn owner(&self) -> u32 {
        self.owner
    }
}

/// Everything one walk over the local state ancestry read from it.
///
/// The mode and the owner of an ancestor answer two different questions, and
/// both come out of the same `stat`, so one walk reads them together and a
/// caller that wants both pays for one pass rather than two.
#[cfg(unix)]
#[derive(Debug, Default)]
pub(crate) struct LocalStateAncestryScan {
    /// Every ancestor that is exposed, or that could not be read at all.
    pub(crate) violations: Vec<PermissionViolation>,
    /// Every ancestor a third account owns.
    pub(crate) owners: Vec<AncestorOwnerFinding>,
    /// Why the first ancestor that could not be read was unreadable.
    ///
    /// An ancestor the walk could not stat is exactly the one that may belong
    /// to somebody else, so a caller judging owners reports the whole walk as
    /// one that did not run rather than answering from the part it did reach.
    pub(crate) unreadable: Option<String>,
}

/// Walk the chains leading to `path` and read each directory once.
///
/// This is the one entry point for the ancestry: a caller wanting the exposed
/// directories, the ones a third account owns, or both, takes them from the
/// same scan.
///
/// A chain that cannot be resolved at all is a failure of the walk rather than
/// a finding about one directory, so it comes back as the reason instead.
#[cfg(unix)]
pub(crate) fn walk_local_state_ancestry(
    path: &Path,
) -> std::result::Result<LocalStateAncestryScan, String> {
    let effective_uid = effective_uid();
    // The working directory is read once for the whole walk, as the tree walk
    // reads it once for its own: every finding of one walk then names its path
    // against the same directory, however long the walk takes.
    let base = DisplayBase::resolve();
    let mut scan = LocalStateAncestryScan::default();
    for_each_ancestor(path, |ancestor| scan.read(&base, ancestor, effective_uid))
        .map_err(|error| format_unresolvable_ancestry(&base, path, &error))?;
    Ok(scan)
}

#[cfg(unix)]
impl LocalStateAncestryScan {
    /// Read one ancestor, taking its mode and its owner from the same call.
    fn read(&mut self, base: &DisplayBase, path: &Path, effective_uid: u32) {
        let metadata = match fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(error) => return self.record_unreadable(base, path, &error),
        };
        self.violations
            .extend(inspect_ancestor_mode(base, &metadata, path));
        self.owners
            .extend(inspect_ancestor_owner(&metadata, path, effective_uid));
    }

    /// Record an ancestor that could not be read, for both questions at once.
    ///
    /// The mode check names it as a finding of its own, because a directory
    /// nobody could inspect is exactly the one that may be open to somebody
    /// else. The owner check reports the whole walk as one that did not run,
    /// because a part of the ancestry it never saw cannot stand for the rest.
    fn record_unreadable(
        &mut self,
        base: &DisplayBase,
        path: &Path,
        error: &dyn std::fmt::Display,
    ) {
        let reason = format_unreadable_ancestor(base, path, error);
        self.violations.push(PermissionViolation::new(
            path,
            PermissionViolationKind::UnreadableAncestor,
            reason.clone(),
        ));
        self.unreadable.get_or_insert(reason);
    }
}

/// Name an ancestor a third account owns, or nothing when its owner is expected.
#[cfg(unix)]
fn inspect_ancestor_owner(
    metadata: &fs::Metadata,
    path: &Path,
    effective_uid: u32,
) -> Option<AncestorOwnerFinding> {
    use std::os::unix::fs::MetadataExt;

    let owner = metadata.uid();
    if is_administrative_owner(owner, effective_uid) {
        return None;
    }
    Some(AncestorOwnerFinding {
        path: path.to_path_buf(),
        owner,
    })
}

/// Whether an ancestor's owner is one the machine is administered with.
///
/// Everything from `/` down is normally owned by root, and the decision that
/// put it there belongs to whoever administers the machine — the same trust a
/// stock home directory already rests on. What is worth naming is a third
/// account on the way to local state: neither the operator nor the
/// administrator.
#[cfg(unix)]
fn is_administrative_owner(owner: u32, effective_uid: u32) -> bool {
    owner == 0 || owner == effective_uid
}

/// Resolve the directories the ancestor walk starts from.
///
/// The chain holding the root comes first, and the parent of what the root
/// resolves to is added when a symlink makes the two differ. The root itself is
/// left out of both because the owner-only rule covers it.
///
/// A local state root is often created on first use, so a root that does not
/// resolve contributes only the walk up from the deepest existing parent.
#[cfg(unix)]
fn resolve_existing_ancestor_bases(path: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut bases = Vec::new();
    if let Some(holding) = resolve_existing_parent(path)? {
        bases.push(holding);
    }
    if let Some(resolved) = resolve_root_parent(path)? {
        if !bases.contains(&resolved) {
            bases.push(resolved);
        }
    }
    Ok(bases)
}

/// Walk up from the parent of `path` to the deepest directory that exists.
///
/// The chain to climb comes from the components of the path itself, so the walk
/// is over once they run out. Asking `Path::parent` for the next step instead
/// would not end: it answers a relative path's last component with an empty
/// path, the directory an empty path stands for is the working directory, and
/// `parent` answers that with an empty path again. A process whose working
/// directory has been removed resolves neither, so the two would be asked about
/// forever.
#[cfg(unix)]
fn resolve_existing_parent(path: &Path) -> std::io::Result<Option<PathBuf>> {
    let Some(parent) = path.parent() else {
        return Ok(None);
    };
    for ancestor in parent.ancestors() {
        match fs::canonicalize(path_or_current_dir(ancestor)) {
            Ok(resolved) => return Ok(Some(resolved)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(None)
}

/// Resolve the parent of the real directory the root path names.
///
/// A root that is absent, or a link whose target is gone, resolves to nothing
/// and leaves the caller with the chain that holds it.
#[cfg(unix)]
fn resolve_root_parent(path: &Path) -> std::io::Result<Option<PathBuf>> {
    match fs::canonicalize(path) {
        Ok(resolved) => Ok(resolved.parent().map(Path::to_path_buf)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Say that one ancestor could not be inspected.
///
/// Kept apart from an entry of local state itself: a shared directory on the
/// way there is not expected to be owner-only, so the repair that fits an entry
/// would be wrong advice here.
#[cfg(unix)]
fn format_unreadable_ancestor(
    base: &DisplayBase,
    real_path: &Path,
    error: &dyn std::fmt::Display,
) -> String {
    format!(
        "Cannot check the permissions of the local state ancestor {}: {}",
        base.finding(real_path),
        escape_detail(error)
    )
}

/// Report an ancestor whose mode lets another user replace the path below it.
#[cfg(unix)]
fn inspect_ancestor_mode(
    base: &DisplayBase,
    metadata: &fs::Metadata,
    real_path: &Path,
) -> Option<PermissionViolation> {
    use std::os::unix::fs::PermissionsExt;

    let mode = metadata.permissions().mode();
    if mode & GROUP_OTHER_WRITE_BITS == 0 {
        return None;
    }
    if mode & STICKY_BIT != 0 {
        return None;
    }
    Some(describe_ancestor_violation(base, mode, real_path))
}

/// Name the ancestor and the smallest repair that removes the exposure.
///
/// `chmod 0700` is the wrong advice here: a shared parent such as `/home` has
/// to stay readable and traversable, and only the write bits matter. The
/// resolved directory is named rather than a symlink pointing at it, because
/// that is what the mode belongs to.
#[cfg(unix)]
fn describe_ancestor_violation(
    base: &DisplayBase,
    mode: u32,
    real_path: &Path,
) -> PermissionViolation {
    PermissionViolation::new(
        real_path,
        PermissionViolationKind::InsecureAncestor,
        format!(
            "Insecure ancestor permissions {:04o} on {} (group or other can write and the sticky \
             bit is not set, so another user can replace the local state path); {}",
            mode & 0o7777,
            base.finding(real_path),
            describe_ancestor_repair(real_path),
        ),
    )
}

/// Say how to close the exposure, or why only the second way is offered.
#[cfg(unix)]
fn describe_ancestor_repair(real_path: &Path) -> String {
    match format_repair_command("chmod go-w", real_path) {
        Some(command) => format!(
            "run: {command}, or select another local state root with --home or KAPSARO_HOME"
        ),
        None => "select another local state root with --home or KAPSARO_HOME, because the path \
                 holds bytes that are not valid UTF-8 and no repair command can name it"
            .to_string(),
    }
}

/// Say that the chain to the root could not be walked at all.
#[cfg(unix)]
fn format_unresolvable_ancestry(
    base: &DisplayBase,
    path: &Path,
    error: &dyn std::fmt::Display,
) -> String {
    format!(
        "Cannot resolve the local state ancestry of {}: {}",
        base.finding(path),
        escape_detail(error)
    )
}

/// Inspect an open local state file or directory without deciding severity.
#[cfg(unix)]
pub(crate) fn inspect_open_permission(
    file: &File,
    display_path: &Path,
) -> Option<PermissionViolation> {
    inspect_open_permission_against(&DisplayBase::resolve(), file, display_path)
}

/// Inspect one open entry, naming it against a working directory already read.
#[cfg(unix)]
fn inspect_open_permission_against(
    base: &DisplayBase,
    file: &File,
    display_path: &Path,
) -> Option<PermissionViolation> {
    match file.metadata() {
        Ok(metadata) => inspect_metadata(base, &metadata, display_path),
        Err(error) => Some(describe_unreadable(base, display_path, &error)),
    }
}

/// Inspect an open entry only when it belongs to local state.
/// Workspace entries are shared through git and keep the checkout's modes.
#[cfg(unix)]
pub(crate) fn inspect_scoped_open_permission<D>(
    dir: &D,
    file: &File,
    display_path: &Path,
) -> Option<PermissionViolation>
where
    D: DirectoryFd + ?Sized,
{
    match dir.scope() {
        DirectoryScope::Generic => None,
        DirectoryScope::LocalState => inspect_open_permission(file, display_path),
    }
}

/// Collect violations across an opened directory chain, outermost entry first.
#[cfg(unix)]
pub(crate) fn collect_open_permission_violations(
    entries: &[&dyn DirectoryFd],
) -> Vec<PermissionViolation> {
    entries
        .iter()
        .filter_map(|entry| inspect_scoped_open_permission(*entry, entry.file(), entry.path()))
        .collect()
}

/// Deepest level below the local state root the walk descends into.
///
/// Local state nests at most `<root>/keys/<member>/<kid>/<file>`, so six levels
/// reach every entry kapsaro writes and leave room for one unexpected level.
#[cfg(unix)]
const MAX_LOCAL_STATE_TREE_DEPTH: usize = 6;

/// Upper bound on the entries one walk inspects.
///
/// A local state tree holds a handful of entries per member key, so a tree far
/// past this bound holds something kapsaro did not put there and is reported
/// from what was already inspected, together with a finding that names the part
/// the walk never reached.
#[cfg(unix)]
const MAX_LOCAL_STATE_TREE_ENTRIES: usize = 1024;

/// Collect violations across the whole local state tree below `root`.
///
/// Walking from the opened root keeps every entry kapsaro owns in scope, the
/// configuration and the trust store included, without naming them one by one.
#[cfg(unix)]
pub(crate) fn collect_local_state_tree_violations<D>(root: &D) -> Vec<PermissionViolation>
where
    D: DirectoryFd,
{
    let mut walk = LocalStateTreeWalk::new();
    walk.inspect_root(root);
    walk.finish(root.path())
}

/// Findings, the remaining entry budget and the bound one local state tree walk
/// reached.
///
/// The effective user and the working directory are read once when the walk
/// starts rather than for each entry: neither has to change while the walk runs,
/// and reading them once is what makes every entry judged against the same
/// account and every finding phrased against the same directory.
#[cfg(unix)]
struct LocalStateTreeWalk {
    violations: Vec<PermissionViolation>,
    remaining_entries: usize,
    reached_limit: Option<ScanLimit>,
    effective_uid: u32,
    base: DisplayBase,
}

#[cfg(unix)]
impl LocalStateTreeWalk {
    fn new() -> Self {
        Self {
            violations: Vec::new(),
            remaining_entries: MAX_LOCAL_STATE_TREE_ENTRIES,
            reached_limit: None,
            effective_uid: effective_uid(),
            base: DisplayBase::resolve(),
        }
    }

    fn record(&mut self, violation: Option<PermissionViolation>) {
        self.violations.extend(violation);
    }

    /// Note the bound that ended the walk early, keeping the one reached first.
    fn mark_limit(&mut self, limit: ScanLimit) {
        self.reached_limit.get_or_insert(limit);
    }

    /// Judge the root the walk starts from, then everything it holds.
    fn inspect_root<D>(&mut self, root: &D)
    where
        D: DirectoryFd,
    {
        let violation = inspect_open_permission_against(&self.base, root.file(), root.path());
        self.record(violation);
        self.inspect_subtree(root, 1);
    }

    /// Hand back the findings, naming the part of the tree left uninspected.
    fn finish(mut self, root_path: &Path) -> Vec<PermissionViolation> {
        if let Some(limit) = self.reached_limit {
            let finding = describe_incomplete_scan(&self.base, root_path, limit);
            self.violations.push(finding);
        }
        self.violations
    }

    fn has_budget(&self) -> bool {
        self.remaining_entries > 0
    }

    /// Charge one inspected entry to the walk's budget.
    ///
    /// The listing was handed the budget that was left, so it never returns more
    /// entries than there is budget to spend on them; a directory holding more
    /// says so through `truncated` instead.
    fn spend_entry(&mut self) {
        self.remaining_entries = self.remaining_entries.saturating_sub(1);
    }

    /// Inspect everything `dir` holds, then walk into the directories among it.
    ///
    /// `depth` is the level of those children below the root. The two passes
    /// are what keeps one level from being displaced by a deep subtree: every
    /// entry of a directory is judged before the walk goes below it, so an
    /// entry budget that runs out further down never leaves `keys/`, `trust/`
    /// or `config.toml` uninspected.
    ///
    /// A descriptor is held only for the directory the walk currently stands
    /// in, so the open files never exceed the depth bound however wide the tree
    /// is. Only a directory that cannot be listed at all ends the pass over it;
    /// one entry that cannot be read is a finding of its own, because the
    /// entries a scan never reaches are exactly the ones somebody else may have
    /// placed there.
    ///
    /// The budget is handed to the listing rather than applied to what it
    /// returns: a directory holding far more entries than the walk will ever
    /// judge must not be inspected in full first.
    fn inspect_subtree<D>(&mut self, dir: &D, depth: usize)
    where
        D: DirectoryFd,
    {
        let scanned = match scan_child_entries_at(dir, ScanBudget::AtMost(self.remaining_entries)) {
            Ok(scanned) => scanned,
            Err(error) => {
                let finding =
                    describe_unreadable(&self.base, dir.path(), &error.format_user_message());
                self.record(Some(finding));
                return;
            }
        };
        if scanned.truncated {
            self.mark_limit(ScanLimit::Entries);
        }
        let mut descendable = Vec::new();
        for child in scanned.entries {
            self.spend_entry();
            descendable.extend(self.inspect_child(dir, child));
        }
        self.descend_into_all(dir, descendable, depth);
    }

    /// Walk into each directory this level holds, or note the bound that stops it.
    fn descend_into_all<D>(&mut self, dir: &D, descendable: Vec<PendingDir>, depth: usize)
    where
        D: DirectoryFd,
    {
        if descendable.is_empty() {
            return;
        }
        if depth >= MAX_LOCAL_STATE_TREE_DEPTH {
            self.mark_limit(ScanLimit::Depth);
            return;
        }
        for pending in descendable {
            // Once the cap is reached the remaining directories would each be
            // cut short at their first entry, so they are not read at all.
            if !self.has_budget() {
                self.mark_limit(ScanLimit::Entries);
                return;
            }
            self.descend(dir, &pending, depth + 1);
        }
    }

    /// Judge one entry, naming it as a directory the walk may go below.
    fn inspect_child<D>(&mut self, dir: &D, child: ScannedChild) -> Option<PendingDir>
    where
        D: DirectoryFd,
    {
        let path = child.name().path_under(dir);
        let scanned = match InspectedChild::from_scanned(child) {
            Ok(scanned) => scanned,
            Err(error) => {
                let finding = describe_unreadable(&self.base, &path, &error.format_user_message());
                self.record(Some(finding));
                return None;
            }
        };
        if scanned.name.decoded().is_none() {
            let finding = describe_undecodable_name(&self.base, &path);
            self.record(Some(finding));
        }
        self.judge_child(scanned, &path)
    }

    /// Record what one readable entry's own facts make it.
    fn judge_child(&mut self, scanned: InspectedChild, path: &Path) -> Option<PendingDir> {
        if matches!(scanned.child_type, ChildType::Symlink | ChildType::Other) {
            self.record_unexpected_entry(&scanned, path);
            return None;
        }
        let finding = inspect_entry_facts(&self.base, scanned.facts, self.effective_uid, path);
        self.record(finding);
        if scanned.child_type != ChildType::Directory {
            return None;
        }
        Some(PendingDir {
            name: scanned.name,
            identity: scanned.identity,
        })
    }

    /// Record an entry of a type kapsaro never writes, and who owns it.
    ///
    /// Neither a symlink nor a device, socket or FIFO is something kapsaro
    /// writes into local state, and a read that reaches one refuses it, so the
    /// operator is told it is there. The mode is left unjudged, because a
    /// symlink carries 0777 whoever created it and a `chmod` on one repairs
    /// nothing. The owner is judged all the same: an entry a third account
    /// placed in local state is theirs to repoint at any moment, which is the
    /// gravest thing the walk can find and not something the operator can
    /// repair from their own session.
    fn record_unexpected_entry(&mut self, scanned: &InspectedChild, path: &Path) {
        let finding = describe_unexpected_entry_type(&self.base, path, scanned.child_type);
        self.record(Some(finding));
        if scanned.facts.owner == self.effective_uid {
            return;
        }
        let finding =
            describe_foreign_owner(&self.base, scanned.facts.owner, scanned.facts.is_dir, path);
        self.record(Some(finding));
    }

    /// Open one scanned child directory and walk it, holding the descriptor
    /// only for as long as the walk stands inside it.
    ///
    /// The directory the scan recorded and the one this open reaches are two
    /// lookups of the same name, so the descriptor is checked against the
    /// identity the scan saw. A mismatch means the entry whose mode was just
    /// judged is not the one about to be walked, and reporting it is the only
    /// way the operator learns the tree moved underneath the command.
    fn descend<D>(&mut self, dir: &D, pending: &PendingDir, depth: usize)
    where
        D: DirectoryFd,
    {
        run_before_child_dir_open();
        match open_scanned_child_dir(dir, &pending.name) {
            Ok(Some(child)) => self.walk_verified_child(child, pending.identity, depth),
            // The directory was removed between the listing and the open, so
            // there is nothing left to report about its permissions.
            Ok(None) => {}
            Err(error) => {
                let finding = describe_unreadable(
                    &self.base,
                    &pending.name.path_under(dir),
                    &error.format_user_message(),
                );
                self.record(Some(finding));
            }
        }
    }

    /// Walk into the opened directory only while it is the entry that was scanned.
    fn walk_verified_child(
        &mut self,
        child: OpenDir,
        scanned_identity: EntryIdentity,
        depth: usize,
    ) {
        match open_dir_identity(&child) {
            Ok(opened) if opened == scanned_identity => self.inspect_subtree(&child, depth),
            Ok(_) => {
                let finding = describe_replaced_entry(&self.base, child.path());
                self.record(Some(finding));
            }
            Err(error) => {
                let finding =
                    describe_unreadable(&self.base, child.path(), &error.format_user_message());
                self.record(Some(finding));
            }
        }
    }
}

/// One readable entry, with the facts the scan's single `statat` returned.
#[cfg(unix)]
struct InspectedChild {
    name: ChildName,
    child_type: ChildType,
    facts: EntryFacts,
    identity: EntryIdentity,
}

#[cfg(unix)]
impl InspectedChild {
    /// Split a scan result into the readable case and the error it carried.
    fn from_scanned(child: ScannedChild) -> std::result::Result<Self, crate::Error> {
        match child {
            ScannedChild::Unreadable { error, .. } => Err(error),
            ScannedChild::Inspected {
                name,
                child_type,
                mode,
                owner,
                identity,
            } => Ok(Self {
                facts: EntryFacts::new(owner, mode, child_type == ChildType::Directory),
                name,
                child_type,
                identity,
            }),
        }
    }
}

/// A child directory the walk will go into, named rather than held open.
///
/// Keeping the name and the identity the scan saw, instead of a descriptor,
/// means a directory holding a thousand subdirectories costs a thousand names
/// and not a thousand open files. The identity is what the open is checked
/// against when the walk finally reaches this entry.
#[cfg(unix)]
struct PendingDir {
    name: ChildName,
    identity: EntryIdentity,
}

/// Judge entries handed over directly rather than read off a filesystem.
///
/// A name that is not UTF-8 and an entry whose metadata could not be read are
/// both cases some filesystems refuse to create, so a test that builds them on
/// disk runs on one platform and quietly passes on another. Test-only entry
/// point; compiled out of production builds.
#[cfg(all(test, unix))]
pub(crate) fn judge_scanned_children<D>(
    dir: &D,
    children: Vec<ScannedChild>,
) -> (Vec<PermissionViolation>, Vec<ChildName>)
where
    D: DirectoryFd,
{
    let mut walk = LocalStateTreeWalk::new();
    let mut descendable = Vec::new();
    for child in children {
        descendable.extend(walk.inspect_child(dir, child).map(|pending| pending.name));
    }
    (walk.finish(dir.path()), descendable)
}

// Test-only seam: runs once between the scan that recorded a child directory
// and the open that walks into it, so a test can replace the entry in between.
// Compiled out of production builds.
#[cfg(all(test, unix))]
thread_local! {
    static BEFORE_CHILD_DIR_OPEN: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(all(test, unix))]
pub(crate) fn run_before_next_child_dir_open(action: impl FnOnce() + 'static) {
    BEFORE_CHILD_DIR_OPEN.with(|slot| *slot.borrow_mut() = Some(Box::new(action)));
}

#[cfg(all(test, unix))]
fn run_before_child_dir_open() {
    if let Some(action) = BEFORE_CHILD_DIR_OPEN.with(|slot| slot.borrow_mut().take()) {
        action();
    }
}

#[cfg(all(not(test), unix))]
fn run_before_child_dir_open() {}

/// Record every collected violation for the operator, one warning per entry.
///
/// Reporting only the first would make the operator repair and re-run once per
/// level of the tree, so every entry that must change is named at once. The
/// path travels beside the sentence rather than only inside it, so a caller
/// that is not a terminal can act on the entry itself.
#[cfg(unix)]
pub(crate) fn report_violations(violations: Vec<PermissionViolation>) {
    for violation in violations {
        record_local_state_warning(LocalStateWarning::new(
            LocalStateWarningCode::Permissions,
            &violation.path,
            violation.message,
        ));
    }
}

/// Report an open entry that belongs to local state and is not owner-only.
#[cfg(unix)]
pub(crate) fn report_scoped_open_permission<D>(dir: &D, file: &File, display_path: &Path)
where
    D: DirectoryFd + ?Sized,
{
    report_violations(
        inspect_scoped_open_permission(dir, file, display_path)
            .into_iter()
            .collect(),
    );
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/support_fs_permission_test.rs"]
mod support_fs_permission_test;
