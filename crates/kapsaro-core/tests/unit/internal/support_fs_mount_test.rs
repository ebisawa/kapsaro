// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for the storage locality of a mount.
//! Covers the verdict on real storage and the reading of the kernel's mount tables.

use super::{
    classify_filesystem, classify_storage_locality, filesystem_name_from_magic,
    find_mount_filesystem, is_deviceless_filesystem, StorageLocality,
};

const MOUNTINFO: &str = "\
21 1 0:20 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
24 21 0:22 / /run rw,nosuid shared:5 - tmpfs tmpfs rw,size=1g
31 21 0:29 / /mnt/team rw,relatime shared:9 - nfs4 fileserver:/team rw
33 31 0:30 / /mnt/team/nested rw,relatime shared:11 - ext4 /dev/sdb1 rw
";

const FILESYSTEMS: &str = "\
nodev\tsysfs
nodev\ttmpfs
nodev\tnfs4
nodev\tfuse
\text4
\tocfs2
";

/// A FUSE mount is named after the daemon serving it, while the kernel lists
/// only the `fuse` it registered.
const FUSE_MOUNTINFO: &str = "\
21 1 0:20 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
42 21 0:44 / /home/alice/remote rw,nosuid,relatime - fuse.sshfs alice@fileserver:/srv rw,user_id=1000
";

/// A temporary directory is served by the storage the test machine runs on, so a
/// platform that reads its own mounts has to name it as storage attached here.
/// The platforms with no reading of their own can only answer `Unknown`, which
/// says nothing about the verdict, so they are left out.
#[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
#[test]
fn test_storage_locality_answers_for_real_storage() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let opened = std::fs::File::open(temp_dir.path()).unwrap();

    let locality = classify_storage_locality(&opened);

    assert_eq!(locality, StorageLocality::Local, "{locality:?}");
}

/// The mount a line describes is found by the number the kernel gave it, which
/// is what `statx` answers for an open descriptor.
#[test]
fn test_mount_lookup_names_the_filesystem_of_the_numbered_mount() {
    assert_eq!(find_mount_filesystem(MOUNTINFO, 31), Some("nfs4"));
    assert_eq!(find_mount_filesystem(MOUNTINFO, 33), Some("ext4"));
}

/// A number no line carries names no filesystem, so nothing is claimed about it.
#[test]
fn test_mount_lookup_of_an_unlisted_mount_names_no_filesystem() {
    assert_eq!(find_mount_filesystem(MOUNTINFO, 99), None);
}

/// The optional fields before the separator vary in number, so a line carrying
/// none of them still has its filesystem read from after the separator.
#[test]
fn test_mount_lookup_reads_a_line_without_optional_fields() {
    let mountinfo = "21 1 0:20 / /srv rw,relatime - xfs /dev/sdc1 rw\n";

    assert_eq!(find_mount_filesystem(mountinfo, 21), Some("xfs"));
}

/// The verdict the two kernel files reach for the mount holding that number,
/// read the way the platform implementation reads them.
fn verdict(mountinfo: &str, mount_id: u64) -> StorageLocality {
    let Some(filesystem) = find_mount_filesystem(mountinfo, mount_id) else {
        return StorageLocality::Unknown;
    };
    classify_filesystem(
        filesystem,
        is_deviceless_filesystem(FILESYSTEMS, filesystem),
    )
}

/// A line that cannot be read may be the one describing the mount, so the lookup
/// answers that it names no filesystem rather than passing over it and taking
/// another line for the one that serves it.
#[test]
fn test_an_unreadable_mountinfo_line_names_no_filesystem() {
    let mountinfo = "\
not-a-mount-id 1 0:20 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
31 21 0:29 / /mnt/team rw,relatime shared:9 - nfs4 fileserver:/team rw
";

    assert_eq!(find_mount_filesystem(mountinfo, 31), None);
}

/// A FUSE mount carries the name of the daemon serving it, and the kernel lists
/// the type it registered, so the list is read under the registered name.
#[test]
fn test_a_fuse_subtype_is_read_under_its_registered_type() {
    assert!(is_deviceless_filesystem(FILESYSTEMS, "fuse.sshfs"));
    assert!(is_deviceless_filesystem(FILESYSTEMS, "fuse.rclone"));
}

/// A userspace daemon answers to whatever it likes, so the type the kernel
/// registered for it is read as a share.
#[test]
fn test_a_fuse_mount_is_remote() {
    assert_eq!(verdict(FUSE_MOUNTINFO, 42), StorageLocality::Remote);
}

/// A mount the kernel lists as deviceless under a name neither list holds
/// reaches no verdict, rather than being reported as a share.
#[test]
fn test_an_unrecognized_deviceless_mount_is_unknown() {
    let mountinfo = "\
21 1 0:20 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
28 21 0:21 / /sys rw,nosuid shared:3 - sysfs sysfs rw
";

    assert_eq!(verdict(mountinfo, 28), StorageLocality::Unknown);
}

/// A kernel too old to number its mounts leaves the magic `statfs` answers with,
/// and only the filesystems the classification has something to say about are
/// recognised there.
#[test]
fn test_a_filesystem_magic_names_the_filesystem_it_stands_for() {
    assert_eq!(filesystem_name_from_magic(0x0000_EF53), Some("ext4"));
    assert_eq!(filesystem_name_from_magic(0x0000_6969), Some("nfs"));
    assert_eq!(filesystem_name_from_magic(0x7461_636F), Some("ocfs2"));
    assert_eq!(filesystem_name_from_magic(0x0000_0001), None);
}

/// A shared cluster filesystem read from its magic reaches the same verdict as
/// one read from its name, so an old kernel does not silently call a SAN local.
#[test]
fn test_a_filesystem_magic_reaches_the_verdict_of_its_name() {
    let filesystem = filesystem_name_from_magic(0x7461_636F).unwrap();

    assert_eq!(
        classify_filesystem(
            filesystem,
            is_deviceless_filesystem(FILESYSTEMS, filesystem)
        ),
        StorageLocality::Remote
    );
}

#[test]
fn test_deviceless_filesystems_are_read_from_the_kernel_list() {
    assert!(is_deviceless_filesystem(FILESYSTEMS, "nfs4"));
    assert!(!is_deviceless_filesystem(FILESYSTEMS, "ext4"));
}

/// A filesystem backed by a device that is not one of the shared cluster
/// filesystems is attached to this machine, whatever it is called, so no list of
/// known names decides that verdict.
#[test]
fn test_a_device_backed_filesystem_that_is_not_a_cluster_filesystem_is_local() {
    assert_eq!(
        classify_filesystem("something-unheard-of", false),
        StorageLocality::Local
    );
    assert_eq!(classify_filesystem("ext4", false), StorageLocality::Local);
}

/// A backing device says the bytes are reached over a block layer, not that the
/// block layer ends here: a filesystem built to be mounted by several hosts at
/// once is a share whatever device carries it.
#[test]
fn test_a_shared_cluster_filesystem_is_remote_despite_its_device() {
    assert_eq!(classify_filesystem("ocfs2", false), StorageLocality::Remote);
    assert_eq!(classify_filesystem("gfs2", false), StorageLocality::Remote);
    assert_eq!(classify_filesystem("vmfs", false), StorageLocality::Remote);
}

/// A filesystem another host serves is named as one, so its mount is a share
/// even though nothing about the missing device says so on its own.
#[test]
fn test_a_known_network_filesystem_is_remote() {
    assert_eq!(classify_filesystem("nfs4", true), StorageLocality::Remote);
    assert_eq!(classify_filesystem("cifs", true), StorageLocality::Remote);
    assert_eq!(classify_filesystem("9p", true), StorageLocality::Remote);
}

/// The kernel's own in-memory filesystems carry no device and are still reachable
/// by this host alone.
#[test]
fn test_in_memory_filesystems_stay_local() {
    assert_eq!(classify_filesystem("tmpfs", true), StorageLocality::Local);
    assert_eq!(classify_filesystem("overlay", true), StorageLocality::Local);
    assert_eq!(classify_filesystem("ramfs", true), StorageLocality::Local);
}

/// A pool or a stacking layer keeps no block device of its own and still holds
/// bytes no other host can reach, so it is named as storage attached here.
#[test]
fn test_deviceless_local_filesystems_stay_local() {
    assert_eq!(classify_filesystem("zfs", true), StorageLocality::Local);
    assert_eq!(
        classify_filesystem("ecryptfs", true),
        StorageLocality::Local
    );
}

/// A filesystem in neither list is left unjudged: calling it a share would tell
/// an operator their own disk is reachable from elsewhere.
#[test]
fn test_an_unrecognized_deviceless_filesystem_is_unknown() {
    assert_eq!(classify_filesystem("sysfs", true), StorageLocality::Unknown);
    assert_eq!(
        classify_filesystem("something-unheard-of", true),
        StorageLocality::Unknown
    );
}
