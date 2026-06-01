// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Keystore module for multi-generation key management
//!
//! Key storage structure:
//! ```text
//! ~/.config/kapsaro/keys/
//! └── <member_handle>/
//!     ├── <kid>/
//!     │   ├── private.json  (PrivateKey)
//!     │   └── public.json   (PublicKey)
//!     ├── <kid>/
//!     │   ├── private.json
//!     │   └── public.json
//!     └── active           (plaintext file containing active kid)
//! ```

pub mod active;
pub mod helpers;
pub mod member;
pub mod paths;
pub mod public_key_source;
pub mod public_keys;
pub mod resolver;
pub mod signer;
pub mod storage;
