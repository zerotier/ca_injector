use std::{path::PathBuf, str::FromStr};

use anyhow::anyhow;

#[derive(Debug, Clone)]
struct TrustStoreMetadata {
    dir: &'static str,
    bin: &'static str,
    args: Vec<&'static str>,
}

fn get_trust_store_command() -> Result<TrustStoreMetadata, anyhow::Error> {
    if let Ok(md) = std::fs::metadata("/etc/pki/ca-trust/source/anchors") {
        if md.is_dir() {
            return Ok(TrustStoreMetadata {
                dir: "/etc/pki/ca-trust/source/anchors",
                bin: "update-ca-trust",
                args: vec!["extract"],
            });
        }
    }

    if let Ok(md) = std::fs::metadata("/usr/local/share/ca-certificates") {
        if md.is_dir() {
            return Ok(TrustStoreMetadata {
                dir: "/usr/local/share/ca-certificates",
                bin: "update-ca-certificates",
                args: vec![],
            });
        }
    }

    if let Ok(md) = std::fs::metadata("/etc/ca-certificates/trust-source/anchors") {
        if md.is_dir() {
            return Ok(TrustStoreMetadata {
                dir: "/etc/ca-certificates/trust-source/anchors",
                bin: "trust",
                args: vec!["extract-compat"],
            });
        }
    }

    if let Ok(md) = std::fs::metadata("/usr/share/pki/trust/anchors") {
        if md.is_dir() {
            return Ok(TrustStoreMetadata {
                dir: "/usr/share/pki/trust/anchors",
                bin: "update-ca-certificates",
                args: vec![],
            });
        }
    }

    Err(anyhow!("CA location could not be determined"))
}

fn template_filename(filename: &str, tsc: &TrustStoreMetadata) -> Result<PathBuf, anyhow::Error> {
    let pb = PathBuf::from_str(tsc.dir)?;
    Ok(pb.join(filename.replace(" ", "_").replace(".crt", ".pem")))
}

fn update(tsc: &TrustStoreMetadata) -> Result<std::process::ExitStatus, anyhow::Error> {
    Ok(std::process::Command::new(tsc.bin)
        .args(tsc.args.clone())
        .env_clear()
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?)
}

pub fn install_ca(filename: &str) -> Result<(), anyhow::Error> {
    let tsc = get_trust_store_command()?;
    std::fs::copy(filename, template_filename(filename, &tsc)?)?;

    let res = update(&tsc)?;

    if !res.success() {
        return Err(anyhow!("Unable to install CA certificate"));
    }

    Ok(())
}

pub fn uninstall_ca(filename: &str) -> Result<(), anyhow::Error> {
    let tsc = get_trust_store_command()?;
    std::fs::remove_file(template_filename(filename, &tsc)?)?;

    let res = update(&tsc)?;

    if !res.success() {
        return Err(anyhow!("Unable to uninstall CA certificate"));
    }

    Ok(())
}
