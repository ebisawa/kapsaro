// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Permission tests for the anchored keystore capability.
//! Covers the warnings key reads and writes raise and the private key refusal.

#[cfg(unix)]
mod unix_tests {
    use crate::io::keystore::access::KeystoreAccess;
    use crate::model::identity::{Kid, MemberHandle};
    use crate::support::warning::LocalStateWarningGuard;
    use crate::test_support::storage::keystore::storage::{load_private_key, load_public_key};
    use crate::test_utils::{
        local_state_temp_dir, setup_test_keystore_from_fixtures, ALICE_MEMBER_HANDLE,
    };
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;

    /// A fixture keystore reduced to the paths these tests change.
    struct KeystoreFixture {
        home: TempDir,
        member: MemberHandle,
        kid: Kid,
    }

    impl KeystoreFixture {
        fn build() -> Self {
            let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
            let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
            let kid = KeystoreAccess::open(home.path().join("keys"))
                .unwrap()
                .load_active_kid(&member)
                .unwrap()
                .unwrap();
            Self { home, member, kid }
        }

        fn root(&self) -> PathBuf {
            self.home.path().join("keys")
        }

        fn member_dir(&self) -> PathBuf {
            self.root().join(self.member.as_str())
        }

        fn key_dir(&self) -> PathBuf {
            self.member_dir().join(self.kid.as_str())
        }
    }

    /// A private key another account can already read is handed to nobody:
    /// the warning every other local state entry gets would arrive after the
    /// key material had left the keystore.
    #[test]
    fn test_load_private_key_refuses_insecure_permissions() {
        let fixture = KeystoreFixture::build();
        set_mode(&fixture.key_dir().join("private.json"), 0o644);

        let _guard = LocalStateWarningGuard::new();
        let error = load_private_key(
            &fixture.root(),
            fixture.member.as_str(),
            fixture.kid.as_str(),
        )
        .expect_err("a private key others can read must not be loaded");

        assert_eq!(error.recovery(), Some("E_LOCAL_STATE_PRIVATE_KEY_EXPOSED"));
        let message = error.format_user_message();
        assert!(message.contains("Insecure permissions 0644"), "{message}");
        assert!(message.contains("expected 0600"), "{message}");
        assert!(message.contains("chmod 0600"), "{message}");
    }

    /// Reading both halves goes through the same refusal, so a command that
    /// asks for the key pair never sees an exposed private half either. The
    /// rule names the exposure rather than an unsafe path, which is what lets
    /// the diagnostic offer a `chmod` instead of asking about the entry itself.
    #[test]
    fn test_load_key_pair_refuses_insecure_private_key_permissions() {
        let fixture = KeystoreFixture::build();
        set_mode(&fixture.key_dir().join("private.json"), 0o640);

        let _guard = LocalStateWarningGuard::new();
        let error = KeystoreAccess::open(fixture.root())
            .unwrap()
            .load_key_pair(&fixture.member, &fixture.kid)
            .expect_err("a private key others can read must not be loaded");

        assert_eq!(error.recovery(), Some("E_LOCAL_STATE_PRIVATE_KEY_EXPOSED"));
        assert!(
            error.format_user_message().contains("Insecure permissions"),
            "{}",
            error.format_user_message()
        );
    }

    #[test]
    fn test_load_private_key_warns_about_insecure_parent_directory_permissions() {
        let fixture = KeystoreFixture::build();
        set_mode(&fixture.member_dir(), 0o755);

        let guard = LocalStateWarningGuard::new();
        load_private_key(
            &fixture.root(),
            fixture.member.as_str(),
            fixture.kid.as_str(),
        )
        .unwrap();

        let warning = guard.take_single_reason_under(fixture.home.path());
        assert!(warning.contains("Insecure permissions 0755"), "{warning}");
        assert!(warning.contains("expected 0700"), "{warning}");
    }

    /// The directory enclosing the keystore root is local state too, so it is
    /// named even though the keystore itself is owner-only.
    #[test]
    fn test_load_private_key_warns_about_insecure_secret_home_permissions() {
        let fixture = KeystoreFixture::build();
        set_mode(fixture.home.path(), 0o755);

        let guard = LocalStateWarningGuard::new();
        KeystoreAccess::open_from_home(fixture.home.path())
            .unwrap()
            .load_private_key(&fixture.member, &fixture.kid)
            .unwrap();

        let warning = guard.take_single_reason_under(fixture.home.path());
        assert!(warning.contains("Insecure permissions 0755"), "{warning}");
        assert!(warning.contains("expected 0700"), "{warning}");
    }

    #[test]
    fn test_load_private_key_accepts_secure_permissions_records_no_warning() {
        let fixture = KeystoreFixture::build();

        let guard = LocalStateWarningGuard::new();
        load_private_key(
            &fixture.root(),
            fixture.member.as_str(),
            fixture.kid.as_str(),
        )
        .unwrap();
        let warnings = guard.take_reasons_under(fixture.home.path());

        assert!(warnings.is_empty(), "{warnings:?}");
    }

    /// A public key file inside local state is reported just like a private one:
    /// the keystore is owner-only state, so a reachable entry is named.
    #[test]
    fn test_load_public_key_warns_about_insecure_permissions() {
        let fixture = KeystoreFixture::build();
        set_mode(&fixture.key_dir().join("public.json"), 0o644);

        let guard = LocalStateWarningGuard::new();
        load_public_key(
            &fixture.root(),
            fixture.member.as_str(),
            fixture.kid.as_str(),
        )
        .unwrap();

        let warning = guard.take_single_reason_under(fixture.home.path());
        assert!(warning.contains("Insecure permissions 0644"), "{warning}");
        assert!(warning.contains("expected 0600"), "{warning}");
        assert!(warning.contains("chmod 0600"), "{warning}");
    }

    /// The whole ancestry of a public key is local state, so a reachable member
    /// directory is named even when the key file itself is owner-only.
    #[test]
    fn test_load_public_key_warns_about_insecure_parent_directory_permissions() {
        let fixture = KeystoreFixture::build();
        set_mode(&fixture.member_dir(), 0o755);

        let guard = LocalStateWarningGuard::new();
        load_public_key(
            &fixture.root(),
            fixture.member.as_str(),
            fixture.kid.as_str(),
        )
        .unwrap();

        let warning = guard.take_single_reason_under(fixture.home.path());
        assert!(warning.contains("Insecure permissions 0755"), "{warning}");
        assert!(warning.contains("expected 0700"), "{warning}");
        assert!(warning.contains("chmod 0700"), "{warning}");
    }

    /// A keystore root others can reach still opens and still reads, and the
    /// exposure is named on the read that depends on it.
    #[test]
    fn test_keystore_access_warns_about_insecure_root_permissions() {
        let fixture = KeystoreFixture::build();
        set_mode(&fixture.root(), 0o755);
        let access = KeystoreAccess::open(fixture.root()).unwrap();

        let guard = LocalStateWarningGuard::new();
        access.load_active_kid(&fixture.member).unwrap().unwrap();

        let warning = guard.take_single_reason_under(fixture.home.path());
        assert!(warning.contains("Insecure permissions 0755"), "{warning}");
        assert!(warning.contains("expected 0700"), "{warning}");
    }

    /// The key still lands in a member directory others can reach, so the
    /// operator keeps the key they asked for and is told what to repair.
    #[test]
    fn test_save_key_pair_warns_about_insecure_member_directory_permissions() {
        let fixture = KeystoreFixture::build();
        let source = KeystoreAccess::open(fixture.root()).unwrap();
        let private_key = source
            .load_private_key(&fixture.member, &fixture.kid)
            .unwrap();
        let public_key = source
            .load_public_key(&fixture.member, &fixture.kid)
            .unwrap();

        let target = local_state_temp_dir();
        let root = target.path().join("keys");
        let access = KeystoreAccess::create(&root).unwrap();
        let member_dir = root.join(fixture.member.as_str());
        fs::create_dir(&member_dir).unwrap();
        set_mode(&member_dir, 0o755);

        let guard = LocalStateWarningGuard::new();
        access
            .save_key_pair_atomic(&fixture.member, &fixture.kid, &private_key, &public_key)
            .unwrap();

        let warning = guard.take_single_reason_under(target.path());
        assert!(warning.contains("Insecure permissions 0755"), "{warning}");
        assert!(member_dir.join(fixture.kid.as_str()).is_dir());
    }

    fn set_mode(path: &Path, mode: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }
}
