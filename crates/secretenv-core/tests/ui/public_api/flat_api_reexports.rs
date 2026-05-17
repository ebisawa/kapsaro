use secretenv_core::api::{FileEncArtifact, SecretEnvHome};

fn main() {
    let _ = std::any::type_name::<FileEncArtifact>();
    let _ = std::any::type_name::<SecretEnvHome>();
}
