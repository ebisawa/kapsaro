// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Storage locality of the mount an open directory lives on.
//! Answers whether another host can reach the same bytes, or that it is unknown.

use std::fs::File;

/// Where the storage under one directory lives.
///
/// `Unknown` is a verdict of its own rather than an optimistic `Local`: a mount
/// this platform cannot describe may well be shared, and reporting it as local
/// would hide exactly the setup worth telling an operator about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StorageLocality {
    /// The storage is attached to this machine, so this host is the only writer.
    Local,
    /// The storage is served from elsewhere and another host may write it too.
    Remote,
    /// Nothing here can tell the two apart on this platform.
    Unknown,
}

/// Filesystems that carry no device and are still local to this machine.
///
/// Some of these hold their bytes in memory and some stack on storage already
/// attached here, but no host other than this one can reach either.
///
/// `overlay` and `ecryptfs` are stacking filesystems: this classification does
/// not look at what they are layered on. If their lower layer is itself a
/// remote share, the stacked mount is still reported as `Local`. Reporting
/// `Unknown` instead would put every container CI run that stacks on overlay
/// under a constant lock-safety warning, so the accepted trade-off is to treat
/// the stack as local rather than as unjudged.
#[cfg(any(target_os = "linux", target_os = "android", test))]
const DEVICELESS_LOCAL_FILESYSTEMS: [&str; 5] = ["tmpfs", "overlay", "ramfs", "zfs", "ecryptfs"];

/// Filesystems that carry no device because another host serves their bytes.
///
/// `fuse` stands for every mount a userspace daemon serves: the daemon speaks to
/// whatever it likes, so nothing here can promise the bytes stay on this machine.
#[cfg(any(target_os = "linux", target_os = "android", test))]
const REMOTE_FILESYSTEMS: [&str; 11] = [
    "nfs",
    "nfs4",
    "cifs",
    "smbfs",
    "smb3",
    "ceph",
    "glusterfs",
    "9p",
    "afs",
    "lustre",
    "fuse",
];

/// Filesystems that carry a backing device and are still mounted by several
/// hosts at once.
///
/// A backing device says the bytes are reached over a block layer, not that the
/// block layer ends at this machine: a LUN on a SAN, an iSCSI target or an
/// NVMe-oF namespace is a block device every host that can see it may mount.
/// These filesystems exist for exactly that arrangement, so a lock taken on one
/// holds only between the processes on this host however local the device looks.
#[cfg(any(target_os = "linux", target_os = "android", test))]
const SHARED_CLUSTER_FILESYSTEMS: [&str; 6] = ["ocfs2", "gfs", "gfs2", "gpfs", "vmfs", "cvfs"];

/// Judge the storage the mount holding the open directory is served from.
///
/// Apple platforms carry the answer as a mount flag the kernel sets, so it is
/// read rather than derived from the filesystem's name. It is read from the
/// descriptor, so the answer is about the directory the caller holds rather than
/// about whatever a name resolves to at the moment of asking.
#[cfg(target_vendor = "apple")]
pub(crate) fn classify_storage_locality(file: &File) -> StorageLocality {
    let Ok(stat) = rustix::fs::fstatfs(file) else {
        return StorageLocality::Unknown;
    };
    if stat.f_flags & (libc::MNT_LOCAL as u32) != 0 {
        return StorageLocality::Local;
    }
    StorageLocality::Remote
}

/// Judge the storage the mount holding the open directory is served from.
///
/// The kernel numbers every mount and gives each one a line in `mountinfo` under
/// that number, so the mount the descriptor belongs to is named without a path
/// being resolved a second time. `filesystems` marks the types that carry no
/// backing device. A backing device settles the answer unless the filesystem is
/// one built to be mounted by several hosts at once, and a mount without one may
/// be either a share or a filesystem that simply keeps no block device of its
/// own, so the name decides. A name in none of the lists stays `Unknown` rather
/// than being called a share: local filesystems keep appearing that carry no
/// device, and telling an operator their own disk is reachable from elsewhere is
/// a claim that never goes away.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) fn classify_storage_locality(file: &File) -> StorageLocality {
    let Ok(filesystems) = std::fs::read_to_string("/proc/filesystems") else {
        return StorageLocality::Unknown;
    };
    match mount_id(file) {
        Some(mount_id) => classify_mount(mount_id, &filesystems),
        None => classify_filesystem_magic(file, &filesystems),
    }
}

/// Nothing portable describes the mount here, so the storage stays unjudged.
#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "android", target_vendor = "apple"))
))]
pub(crate) fn classify_storage_locality(_file: &File) -> StorageLocality {
    StorageLocality::Unknown
}

/// The mount the open directory belongs to, as the kernel numbers it.
///
/// `statx` answers about the descriptor rather than about a name, which is what
/// keeps the measurement on the directory the caller holds. Kernels before 5.8
/// do not report the number, and one without `statx` at all reports nothing;
/// both say so by leaving the field out of the mask they return, so the mask is
/// what is read rather than the field.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn mount_id(file: &File) -> Option<u64> {
    use rustix::fs::{AtFlags, StatxFlags};

    let stat = rustix::fs::statx(file, "", AtFlags::EMPTY_PATH, StatxFlags::MNT_ID).ok()?;
    if !StatxFlags::from_bits_truncate(stat.stx_mask).contains(StatxFlags::MNT_ID) {
        return None;
    }
    Some(stat.stx_mnt_id)
}

/// Judge the mount the kernel gave that number.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn classify_mount(mount_id: u64, filesystems: &str) -> StorageLocality {
    let Ok(mountinfo) = std::fs::read_to_string("/proc/self/mountinfo") else {
        return StorageLocality::Unknown;
    };
    let Some(filesystem) = find_mount_filesystem(&mountinfo, mount_id) else {
        return StorageLocality::Unknown;
    };
    classify_filesystem(
        filesystem,
        is_deviceless_filesystem(filesystems, filesystem),
    )
}

/// Judge the mount from the magic its filesystem answers with.
///
/// This is what a kernel too old to number its mounts leaves: `fstatfs` names
/// the filesystem as a number rather than as text, and only the filesystems the
/// classification has something to say about are recognised. One that is not
/// reaches no verdict, which is where an unrecognised name lands too.
#[cfg(any(target_os = "linux", target_os = "android"))]
// The kernel spells the magic in a type whose width and signedness differ
// between targets, so the widening is written out rather than inferred.
#[allow(clippy::unnecessary_cast)]
fn classify_filesystem_magic(file: &File, filesystems: &str) -> StorageLocality {
    let Ok(stat) = rustix::fs::fstatfs(file) else {
        return StorageLocality::Unknown;
    };
    let Some(filesystem) = filesystem_name_from_magic(stat.f_type as u32) else {
        return StorageLocality::Unknown;
    };
    classify_filesystem(
        filesystem,
        is_deviceless_filesystem(filesystems, filesystem),
    )
}

/// The name the kernel registers for one filesystem magic.
///
/// Only the filesystems the lists above name are here, plus the device-backed
/// ones common enough that leaving them out would put an ordinary disk under a
/// standing warning on an old kernel.
#[cfg(any(target_os = "linux", target_os = "android", test))]
const FILESYSTEM_MAGICS: [(u32, &str); 16] = [
    (0x0000_EF53, "ext4"),
    (0x5846_5342, "xfs"),
    (0x9123_683E, "btrfs"),
    (0xF2F5_2010, "f2fs"),
    (0x0102_1994, "tmpfs"),
    (0x794C_7630, "overlay"),
    (0x8584_58F6, "ramfs"),
    (0x0000_F15F, "ecryptfs"),
    (0x0000_6969, "nfs"),
    (0xFF53_4D42, "cifs"),
    (0xFE53_4D42, "smb3"),
    (0x00C3_6400, "ceph"),
    (0x0102_1997, "9p"),
    (0x0BD0_0BD0, "lustre"),
    (0x7461_636F, "ocfs2"),
    (0x0116_1970, "gfs2"),
];

/// Name the filesystem one `statfs` magic stands for.
#[cfg(any(target_os = "linux", target_os = "android", test))]
fn filesystem_name_from_magic(magic: u32) -> Option<&'static str> {
    FILESYSTEM_MAGICS
        .iter()
        .find(|(known, _)| *known == magic)
        .map(|(_, name)| *name)
}

/// Name the filesystem of the mount the kernel gave that number.
///
/// A line that cannot be read ends the lookup with no answer, because it may be
/// the line describing that mount. Passing over it would leave the question
/// answered by a mount nothing here knows anything about.
#[cfg(any(target_os = "linux", target_os = "android", test))]
fn find_mount_filesystem(mountinfo: &str, mount_id: u64) -> Option<&str> {
    for line in mountinfo.lines() {
        let (id, filesystem) = parse_mountinfo_line(line)?;
        if id == mount_id {
            return Some(filesystem);
        }
    }
    None
}

/// Read the mount number and filesystem type out of one `mountinfo` line.
///
/// The optional fields between the root and the separator vary in number, so
/// the type is read from after the separator rather than from a fixed column.
/// The mount point is passed over: it is escaped, and nothing here compares it
/// against a path any more.
#[cfg(any(target_os = "linux", target_os = "android", test))]
fn parse_mountinfo_line(line: &str) -> Option<(u64, &str)> {
    let mut fields = line.split(' ');
    let id = fields.next()?.parse().ok()?;
    let mut after_separator = fields.skip_while(|field| *field != "-");
    after_separator.next()?;
    let filesystem = after_separator.next()?;
    Some((id, filesystem))
}

/// Whether the kernel lists the filesystem as carrying no backing device.
#[cfg(any(target_os = "linux", target_os = "android", test))]
fn is_deviceless_filesystem(filesystems: &str, filesystem: &str) -> bool {
    let registered = registered_filesystem_name(filesystem);
    filesystems.lines().any(|line| {
        let mut fields = line.split_whitespace();
        matches!(
            (fields.next(), fields.next()),
            (Some("nodev"), Some(name)) if name == registered
        )
    })
}

/// The type the kernel registers for every mount a userspace daemon serves.
#[cfg(any(target_os = "linux", target_os = "android", test))]
const USERSPACE_FILESYSTEM: &str = "fuse";

/// The name the kernel registered the mount's filesystem under.
///
/// A mount a userspace daemon serves is recorded as that type followed by the
/// subtype the daemon chose, and the subtype is not a filesystem the kernel ever
/// registered, so neither the kernel's list nor the ones kept here hold it. Every
/// lookup goes through the registered name so a daemon that names itself anything
/// still reaches the same answer.
#[cfg(any(target_os = "linux", target_os = "android", test))]
fn registered_filesystem_name(filesystem: &str) -> &str {
    match filesystem.split_once('.') {
        Some((prefix, _)) if prefix == USERSPACE_FILESYSTEM => USERSPACE_FILESYSTEM,
        _ => filesystem,
    }
}

/// Turn what the kernel said about one filesystem into a verdict.
///
/// The name is asked first, because it is the only thing that can say a mount is
/// shared in spite of its backing device. A device settles the rest: whatever
/// else a filesystem with one is, it is not a share this classification knows how
/// to name.
#[cfg(any(target_os = "linux", target_os = "android", test))]
fn classify_filesystem(filesystem: &str, deviceless: bool) -> StorageLocality {
    let registered = registered_filesystem_name(filesystem);
    if REMOTE_FILESYSTEMS.contains(&registered) || SHARED_CLUSTER_FILESYSTEMS.contains(&registered)
    {
        return StorageLocality::Remote;
    }
    if !deviceless {
        return StorageLocality::Local;
    }
    if DEVICELESS_LOCAL_FILESYSTEMS.contains(&registered) {
        return StorageLocality::Local;
    }
    StorageLocality::Unknown
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/support_fs_mount_test.rs"]
mod support_fs_mount_test;
