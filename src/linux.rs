use std::{
    io::Write,
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::anyhow;
use glob::glob;
use tempfile::NamedTempFile;
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
    append_path: Option<&'static str>,
    args: Vec<&'static str>,
}

fn get_trust_store_command() -> Result<TrustStoreMetadata, anyhow::Error> {
    if let Ok(md) = std::fs::metadata("/etc/pki/ca-trust/source/anchors") {
        if md.is_dir() {
            return Ok(TrustStoreMetadata {
                dir: "/etc/pki/ca-trust/source/anchors",
                bin: "update-ca-trust",
                append_path: None,
                args: vec!["extract"],
            });
        }
    }

    if let Ok(md) = std::fs::metadata("/usr/share/ca-certificates") {
        if md.is_dir() {
            return Ok(TrustStoreMetadata {
                dir: "/usr/share/ca-certificates",
                bin: "/usr/sbin/update-ca-certificates",
                append_path: Some("/etc/ca-certificates.conf"),
                args: vec![],
            });
        }
    }

    if let Ok(md) = std::fs::metadata("/usr/local/share/ca-certificates") {
        if md.is_dir() {
            return Ok(TrustStoreMetadata {
                dir: "/usr/local/share/ca-certificates",
                bin: "/usr/sbin/update-ca-certificates",
                append_path: Some("/etc/ca-certificates.conf"),
                args: vec![],
            });
        }
    }

    if let Ok(md) = std::fs::metadata("/etc/ca-certificates/trust-source/anchors") {
        if md.is_dir() {
            return Ok(TrustStoreMetadata {
                dir: "/etc/ca-certificates/trust-source/anchors",
                bin: "trust",
                append_path: None,
                args: vec!["extract-compat"],
            });
        }
    }

    if let Ok(md) = std::fs::metadata("/usr/share/pki/trust/anchors") {
        if md.is_dir() {
            return Ok(TrustStoreMetadata {
                dir: "/usr/share/pki/trust/anchors",
                bin: "update-ca-certificates",
                append_path: None,
                args: vec![],
            });
        }
    }

    Err(anyhow!("CA location could not be determined"))
}

fn tr_filename(filename: &str) -> String {
    Path::new(filename)
        .file_name()
        .unwrap()
        .to_string_lossy()
        .replace(" ", "_")
        .replace(".pem", ".crt")
}

fn template_filename(filename: &str, tsc: &TrustStoreMetadata) -> Result<PathBuf, anyhow::Error> {
    let pb = PathBuf::from_str(tsc.dir)?;
    Ok(pb.join(tr_filename(filename)))
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

pub fn append_path(registry: &str, filename: PathBuf) -> Result<(), anyhow::Error> {
    let mut registry_lines = std::fs::read_to_string(registry)?;
    let basename = filename.file_name().unwrap();

    for line in registry_lines.split("\n") {
        if line == basename {
            return Ok(());
        }
    }

    let mut f = NamedTempFile::new()?;

    log::debug!(
        "Appending {} with CA {} added",
        registry,
        basename.to_str().unwrap()
    );

    registry_lines += &format!("{}\n", basename.to_str().unwrap());
    f.write(registry_lines.as_bytes())?;
    f.flush()?;
    let path = f.into_temp_path();

    std::fs::rename(path, registry)?;

    Ok(())
}

pub fn redact_path(registry: &str, filename: PathBuf) -> Result<(), anyhow::Error> {
    let registry_lines = std::fs::read_to_string(registry)?;
    let basename = filename.file_name().unwrap();
    let mut new_registry = Vec::new();

    log::debug!(
        "Redacting from {} for CA {} (removed)",
        registry,
        basename.to_str().unwrap()
    );

    for line in registry_lines.split("\n") {
        if line != basename {
            new_registry.push(line);
        }
    }

    let mut f = NamedTempFile::new()?;
    f.write(new_registry.join("\n").as_bytes())?;
    f.flush()?;
    let path = f.into_temp_path();

    std::fs::rename(path, registry)?;

    Ok(())
}

pub fn install_ca(filename: &str) -> Result<(), anyhow::Error> {
    let tsc = get_trust_store_command()?;
    let new_filename = template_filename(filename, &tsc)?;

    log::debug!(
        "copying cert from {} to {}",
        filename.to_string(),
        new_filename.display()
    );

    std::fs::copy(filename, new_filename.clone())?;

    if let Some(path) = tsc.append_path {
        append_path(path, new_filename)?;
    }

    let res = update_ca(&tsc)?;

    if !res.success() {
        return Err(anyhow!("Unable to install CA certificate"));
    }

    Ok(install_nss(filename)?)
}

pub fn uninstall_ca(filename: &str) -> Result<(), anyhow::Error> {
    let tsc = get_trust_store_command()?;
    let new_filename = template_filename(filename, &tsc)?;
    std::fs::remove_file(new_filename.clone())?;

    if let Some(path) = tsc.append_path {
        redact_path(path, new_filename)?;
    }

    let res = update_ca(&tsc)?;

    if !res.success() {
        return Err(anyhow!("Unable to uninstall CA certificate"));
    }

    Ok(uninstall_nss(filename)?)
}

#[cfg(test)]
mod tests {
    use std::sync::Once;

    use tempdir::TempDir;

    use crate::linux::tr_filename;

    static LOGGER: Once = Once::new();

    fn init_logger() {
        LOGGER.call_once(|| {
            env_logger::builder()
                .filter_level(log::LevelFilter::Debug)
                .init();
        })
    }

    #[test]
    fn test_install() {
        use coyote::acme::ca::CA;

        init_logger();

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

            let s = std::fs::read_to_string("/etc/ca-certificates.conf").unwrap();
            assert!(s.contains(&tr_filename(filename)));
            super::uninstall_ca(test_pem.to_str().unwrap()).unwrap();

            let s = std::fs::read_to_string("/etc/ca-certificates.conf").unwrap();
            assert!(!s.contains(&tr_filename(filename)));
        }
    }
}
