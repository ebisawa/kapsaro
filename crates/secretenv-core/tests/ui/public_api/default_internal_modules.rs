use secretenv_core::config;
use secretenv_core::crypto;
use secretenv_core::feature;
use secretenv_core::format;
use secretenv_core::io;
use secretenv_core::model;
use secretenv_core::support;

fn main() {
    let _ = config::types;
    let _ = crypto::types;
    let _ = feature::verify;
    let _ = format::content;
    let _ = io::keystore;
    let _ = model::wire;
    let _ = support::limits;
}
