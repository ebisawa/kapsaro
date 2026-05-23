// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Permission validation tests for keystore storage

#[cfg(unix)]
mod unix_tests {
    use secretenv_core::cli_api::test_support::storage::keystore::storage::{
        load_private_key, load_public_key,
    };
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    #[test]
    fn test_load_private_key_rejects_insecure_permissions() {
        let temp_dir = TempDir::new().unwrap();
        let member_handle = "test@example.com";
        let kid = "01ABCDEFGHIJKLMNOPQRSTUVWX";
        let key_dir = temp_dir.path().join(member_handle).join(kid);
        fs::create_dir_all(&key_dir).unwrap();
        fs::set_permissions(temp_dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(
            temp_dir.path().join(member_handle),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        fs::set_permissions(&key_dir, fs::Permissions::from_mode(0o700)).unwrap();

        let private_path = key_dir.join("private.json");
        fs::write(&private_path, r#"{"dummy": true}"#).unwrap();
        fs::set_permissions(&private_path, fs::Permissions::from_mode(0o644)).unwrap();

        let err = load_private_key(temp_dir.path(), member_handle, kid).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("Insecure permissions"));
        assert!(msg.contains("0644"));
    }

    #[test]
    fn test_load_private_key_rejects_insecure_parent_directory_permissions() {
        let temp_dir = TempDir::new().unwrap();
        let member_handle = "test@example.com";
        let kid = "01ABCDEFGHIJKLMNOPQRSTUVWX";
        let key_dir = temp_dir.path().join(member_handle).join(kid);
        fs::create_dir_all(&key_dir).unwrap();
        fs::set_permissions(temp_dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&key_dir, fs::Permissions::from_mode(0o700)).unwrap();

        let private_path = key_dir.join("private.json");
        fs::write(&private_path, r#"{"dummy": true}"#).unwrap();
        fs::set_permissions(&private_path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(
            temp_dir.path().join(member_handle),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();

        let err = load_private_key(temp_dir.path(), member_handle, kid).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("Insecure permissions"));
        assert!(msg.contains("expected 0700"));
    }

    #[test]
    fn test_load_private_key_rejects_insecure_secret_home_permissions() {
        let temp_dir = TempDir::new().unwrap();
        let keystore_root = temp_dir.path().join("keys");
        let member_handle = "test@example.com";
        let kid = "01ABCDEFGHIJKLMNOPQRSTUVWX";
        let key_dir = keystore_root.join(member_handle).join(kid);
        fs::create_dir_all(&key_dir).unwrap();
        fs::set_permissions(temp_dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&keystore_root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(
            keystore_root.join(member_handle),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        fs::set_permissions(&key_dir, fs::Permissions::from_mode(0o700)).unwrap();

        let private_path = key_dir.join("private.json");
        fs::write(&private_path, r#"{"dummy": true}"#).unwrap();
        fs::set_permissions(&private_path, fs::Permissions::from_mode(0o600)).unwrap();

        let err = load_private_key(&keystore_root, member_handle, kid).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("Insecure permissions"));
        assert!(msg.contains("expected 0700"));
    }

    #[test]
    fn test_load_private_key_accepts_secure_permissions() {
        let temp_dir = TempDir::new().unwrap();
        let member_handle = "test@example.com";
        let kid = "01ABCDEFGHIJKLMNOPQRSTUVWX";
        let key_dir = temp_dir.path().join(member_handle).join(kid);
        fs::create_dir_all(&key_dir).unwrap();
        fs::set_permissions(temp_dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(
            temp_dir.path().join(member_handle),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        fs::set_permissions(&key_dir, fs::Permissions::from_mode(0o700)).unwrap();

        let private_path = key_dir.join("private.json");
        fs::write(&private_path, r#"{"dummy": true}"#).unwrap();
        fs::set_permissions(&private_path, fs::Permissions::from_mode(0o600)).unwrap();

        // Should fail with parse error, NOT permission error
        let err = load_private_key(temp_dir.path(), member_handle, kid).unwrap_err();
        let msg = err.to_string();
        assert!(!msg.contains("Insecure permissions"));
    }

    #[test]
    fn test_load_public_key_warns_on_insecure_permissions() {
        let temp_dir = TempDir::new().unwrap();
        let member_handle = "test@example.com";
        let kid = "01ABCDEFGHIJKLMNOPQRSTUVWX";
        let key_dir = temp_dir.path().join(member_handle).join(kid);
        fs::create_dir_all(&key_dir).unwrap();
        fs::set_permissions(temp_dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(
            temp_dir.path().join(member_handle),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        fs::set_permissions(&key_dir, fs::Permissions::from_mode(0o700)).unwrap();

        let public_path = key_dir.join("public.json");
        fs::write(&public_path, r#"{"dummy": true}"#).unwrap();
        fs::set_permissions(&public_path, fs::Permissions::from_mode(0o644)).unwrap();

        // Should NOT return a permission error -- warnings are non-fatal.
        // The function will fail with a parse error (invalid JSON structure),
        // confirming that the permission check did not abort.
        let err = load_public_key(temp_dir.path(), member_handle, kid).unwrap_err();
        let msg = err.to_string();
        assert!(
            !msg.contains("Insecure permissions"),
            "public.json permission issue should be a warning, not an error"
        );
    }

    #[test]
    fn test_load_public_key_warns_on_insecure_parent_directory_permissions() {
        let temp_dir = TempDir::new().unwrap();
        let member_handle = "test@example.com";
        let kid = "01ABCDEFGHIJKLMNOPQRSTUVWX";
        let key_dir = temp_dir.path().join(member_handle).join(kid);
        fs::create_dir_all(&key_dir).unwrap();
        fs::set_permissions(temp_dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&key_dir, fs::Permissions::from_mode(0o700)).unwrap();

        let public_path = key_dir.join("public.json");
        fs::write(&public_path, r#"{"dummy": true}"#).unwrap();
        fs::set_permissions(&public_path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(
            temp_dir.path().join(member_handle),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();

        let err = load_public_key(temp_dir.path(), member_handle, kid).unwrap_err();
        let msg = err.to_string();
        assert!(
            !msg.contains("Insecure permissions"),
            "public.json permission issue should be a warning, not an error"
        );
    }
}
