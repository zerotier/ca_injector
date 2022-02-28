use std::{
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::anyhow;
use glob::glob;
use which::which;

fn certutil() -> Result<PathBuf, anyhow::Error> {
    Ok(which("certutil")?)
}

fn nssdbs() -> Result<Vec<PathBuf>, anyhow::Error> {
    let home_var = std::env::var("HOME").unwrap_or("/".to_string());
    let home = Path::new(home_var.as_str());

    // append all firefox profiles on the machine for the given user
    // FIXME might want to enumerate all firefox profiles on the whole machine later
    let mut paths = glob(home.join(".mozilla/firefox/*").to_str().unwrap())?
        .map(|p| p.unwrap())
        .collect::<Vec<PathBuf>>();

    let mut other_paths = vec![
        home.join(".pki/nssdb"),
        home.join("snap/chromium/current/.pki/nssdb"),
        PathBuf::from_str("/etc/pki/nssdb")?,
    ];

    paths.append(&mut other_paths);

    Ok(paths)
}

fn install_nss(filename: &str) -> Result<(), anyhow::Error> {
    let certutil = certutil()?;

    for db in nssdbs()? {
        match db.metadata() {
            Ok(meta) => {
                if meta.is_dir() {
                    log::debug!(
                        "Running certutil for {} against {} to install the cert",
                        db.display(),
                        filename
                    );
                    std::process::Command::new(certutil.clone())
                        .args(vec![
                            "-A",
                            "-d",
                            db.to_str().unwrap(),
                            "-t",
                            "C,,",
                            "-n",
                            filename,
                            "-i",
                            filename,
                        ])
                        .env_clear()
                        .stdin(std::process::Stdio::null())
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status()?;
                }
            }
            _ => {}
        }
    }

    Ok(())
}

fn uninstall_nss(filename: &str) -> Result<(), anyhow::Error> {
    let certutil = certutil()?;

    for db in nssdbs()? {
        match db.metadata() {
            Ok(meta) => {
                if meta.is_dir() {
                    log::debug!(
                        "Running certutil for {} against {} to install the cert",
                        db.display(),
                        filename
                    );
                    std::process::Command::new(certutil.clone())
                        .args(vec!["-D", "-d", db.to_str().unwrap(), "-n", filename])
                        .env_clear()
                        .stdin(std::process::Stdio::null())
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status()?;
                }
            }
            _ => {}
        }
    }

    Ok(())
}

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
                bin: "/usr/sbin/update-ca-certificates",
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
    Ok(pb.join(
        Path::new(filename)
            .file_name()
            .unwrap()
            .to_string_lossy()
            .replace(" ", "_")
            .replace(".pem", ".crt"),
    ))
}

fn update_ca(tsc: &TrustStoreMetadata) -> Result<std::process::ExitStatus, anyhow::Error> {
    log::debug!("Executing {} {:?}", tsc.bin, tsc.args);

    Ok(std::process::Command::new(tsc.bin)
        .args(tsc.args.clone())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?)
}

pub fn install_ca(filename: &str) -> Result<(), anyhow::Error> {
    let tsc = get_trust_store_command()?;
    let new_filename = template_filename(filename, &tsc)?;

    log::debug!(
        "copying cert from {} to {}",
        filename.to_string(),
        new_filename.display()
    );

    std::fs::copy(filename, new_filename)?;

    let res = update_ca(&tsc)?;

    if !res.success() {
        return Err(anyhow!("Unable to install CA certificate"));
    }

    Ok(install_nss(filename)?)
}

pub fn uninstall_ca(filename: &str) -> Result<(), anyhow::Error> {
    let tsc = get_trust_store_command()?;
    std::fs::remove_file(template_filename(filename, &tsc)?)?;

    let res = update_ca(&tsc)?;

    if !res.success() {
        return Err(anyhow!("Unable to uninstall CA certificate"));
    }

    Ok(uninstall_nss(filename)?)
}

#[cfg(test)]
mod tests {
    use tempdir::TempDir;

    #[test]
    fn test_install() {
        env_logger::builder()
            .filter_level(log::LevelFilter::Debug)
            .init();

        use coyote::acme::ca::CA;

        for filename in vec![
            "test.pem",
            "file with spaces.pem",
            "certificate.crt",
            "this_other_thing.crt",
        ] {
            let ca = CA::new_test_ca().unwrap();
            let dir = TempDir::new("").unwrap();

            let test_pem = dir.path().join(filename);

            std::fs::write(test_pem.clone(), ca.certificate().to_pem().unwrap()).unwrap();
            super::install_ca(test_pem.to_str().unwrap()).unwrap();
            super::uninstall_ca(test_pem.to_str().unwrap()).unwrap();
        }
    }
}
