use std::path::Path;

use super::*;
use crate::utility::*;

pub(super) const STAGE: Stage = Stage {
    name: "certs",
    enabled: None,
    always_recreate: false,
    explain_init_permissions: None,
    explain_fini_permissions: None,
    init: Some(step),
    fini: Some(undo),
    check,
};

fn step(config: &mut Config) {
    let scratch = &config.scratch_directory;

    std::fs::create_dir_all(scratch).unwrap();
    repermission(scratch, config.uid, config.uid, 0o700);
    run!(
        cwd = scratch,
        "openssl req -x509 -newkey ed25519 -days 365 -nodes -keyout key.pem -out cert.pem -subj \
         /CN=localhost -addext subjectAltName=DNS:localhost,IP:127.0.0.1 -extensions v3_req"
    );
    repermission(format!("{scratch}/key.pem"), config.uid, config.uid, 0o600);
    repermission(format!("{scratch}/cert.pem"), config.uid, config.uid, 0o664);
}

fn undo(config: &Config) {
    let scratch = &config.scratch_directory;
    remove_file_not_found_ok(format!("{scratch}/key.pem")).unwrap();
    remove_file_not_found_ok(format!("{scratch}/cert.pem")).unwrap();
}

fn check(config: &Config) -> CheckResult {
    let scratch = &config.scratch_directory;
    let key_path = format!("{scratch}/key.pem");
    let cert_path = format!("{scratch}/cert.pem");

    let found_key = match Path::new(&key_path).try_exists() {
        Ok(exists) => exists,
        result => return partially_configured!("error reading path {key_path} {result:?}"),
    };
    let found_cert = match Path::new(&cert_path).try_exists() {
        Ok(exists) => exists,
        result => return partially_configured!("error reading path {cert_path} {result:?}"),
    };

    if !found_key && !found_cert {
        return not_configured!("no certs at {scratch}/{{key,cert}}.pem");
    }

    check_file(&key_path, config.uid, config.uid, 0o100600)?;
    check_file(&cert_path, config.uid, config.uid, 0o100664)?;
    check_directory(&config.scratch_directory, config.uid, config.uid, 0o40700)?;
    CheckResult::Ok(())
}
