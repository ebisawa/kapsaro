// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Core library APIs for Kapsaro encrypted artifacts and local state.
//!
//! The implementation roots below stay crate-private so that every caller
//! reaches the domain through the `api` facade. Widening one of them to `pub`
//! would let the CLI, or an external application, bypass the facade and bind
//! itself to an internal module path. Each root is held shut by a doctest that
//! stops compiling the moment the root becomes reachable from outside.
//!
//! ```compile_fail
//! use kapsaro_core::config;
//! ```
//!
//! ```compile_fail
//! use kapsaro_core::crypto;
//! ```
//!
//! ```compile_fail
//! use kapsaro_core::feature;
//! ```
//!
//! ```compile_fail
//! use kapsaro_core::format;
//! ```
//!
//! ```compile_fail
//! use kapsaro_core::io;
//! ```
//!
//! ```compile_fail
//! use kapsaro_core::model;
//! ```
//!
//! ```compile_fail
//! use kapsaro_core::support;
//! ```
//!
//! ```compile_fail
//! use kapsaro_core::service;
//! ```

#[cfg(not(unix))]
compile_error!("kapsaro-core currently supports Unix targets only.");

pub mod api;
mod error;

#[cfg(any(feature = "cli-test-support", test))]
#[doc(hidden)]
pub mod test_support;

pub(crate) mod config;
pub(crate) mod crypto;
pub(crate) mod feature;
pub(crate) mod format;
pub(crate) mod io;
pub(crate) mod model;
mod service;
pub(crate) mod support;

pub use error::{Error, ErrorKind, Result};

// Test sources are shared with the workspace test-support crate and with the
// external test trees, which spell paths as `kapsaro::` or `kapsaro_core::`.
// Aliasing the crate to both names keeps those paths resolving to this crate
// so the shared sources compile unchanged inside the lib test binary.
#[cfg(test)]
extern crate self as kapsaro;

#[cfg(test)]
extern crate self as kapsaro_core;

#[cfg(test)]
#[allow(dead_code, unused_imports)]
#[path = "../tests/test_support/mod.rs"]
pub(crate) mod test_utils;

#[cfg(test)]
#[allow(dead_code, unused_imports)]
#[path = "../tests/test_support/service_context.rs"]
pub(crate) mod service_test_utils;
