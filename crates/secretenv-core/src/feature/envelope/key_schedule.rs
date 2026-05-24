// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Artifact key schedules for file-enc and kv-enc.
//!
//! Derives purpose-separated encryption and MAC keys from an artifact MK.

use crate::crypto::kdf;
use crate::crypto::types::data::Ikm;
use crate::crypto::types::keys::{Cek, MacKey, MasterKey, XChaChaKey};
use crate::feature::envelope::binding::{
    build_file_content_key_info, build_file_key_schedule_salt, build_file_mac_key_info,
    build_kv_cek_info, build_kv_key_schedule_salt, build_kv_mac_key_info,
};
use crate::Result;
use uuid::Uuid;

pub struct FileKeySchedule {
    prk: kdf::HkdfSha256Prk,
    sid: Uuid,
}

impl FileKeySchedule {
    pub fn extract(master_key: &MasterKey, sid: &Uuid) -> Result<Self> {
        let salt = build_file_key_schedule_salt(sid)?;
        let ikm = Ikm::from(master_key.as_bytes().to_vec());
        Ok(Self {
            prk: kdf::derive_hkdf_sha256_prk(&ikm, &salt),
            sid: *sid,
        })
    }

    pub fn derive_content_key(&self) -> Result<XChaChaKey> {
        let info = build_file_content_key_info(&self.sid)?;
        kdf::derive_hkdf_sha256_array_from_prk(&self.prk, &info).map(XChaChaKey::from_zeroizing)
    }

    pub fn derive_mac_key(&self) -> Result<MacKey> {
        let info = build_file_mac_key_info(&self.sid)?;
        kdf::derive_hkdf_sha256_array_from_prk(&self.prk, &info).map(MacKey::from_zeroizing)
    }
}

pub struct KvKeySchedule {
    prk: kdf::HkdfSha256Prk,
    sid: Uuid,
}

impl KvKeySchedule {
    pub fn extract(master_key: &MasterKey, sid: &Uuid) -> Result<Self> {
        let salt = build_kv_key_schedule_salt(sid)?;
        let ikm = Ikm::from(master_key.as_bytes().to_vec());
        Ok(Self {
            prk: kdf::derive_hkdf_sha256_prk(&ikm, &salt),
            sid: *sid,
        })
    }

    pub fn derive_cek(&self, key: &str, nonce: &str) -> Result<Cek> {
        let info = build_kv_cek_info(&self.sid, key, nonce)?;
        kdf::derive_hkdf_sha256_array_from_prk(&self.prk, &info).map(Cek::from_zeroizing)
    }

    pub fn derive_mac_key(&self) -> Result<MacKey> {
        let info = build_kv_mac_key_info(&self.sid)?;
        kdf::derive_hkdf_sha256_array_from_prk(&self.prk, &info).map(MacKey::from_zeroizing)
    }
}
