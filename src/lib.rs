#[cfg(target_os = "linux")]
mod linux;

pub fn install_ca(filename: &str) -> Result<(), anyhow::Error> {
    #[cfg(target_os = "linux")]
    return crate::linux::install_ca(filename);

    #[cfg(not(target_os = "linux"))]
    Err(anyhow::anyhow!(
        "Unable to install CA certificate '{}' on this platform",
        filename
    ))
}

pub fn uninstall_ca(filename: &str) -> Result<(), anyhow::Error> {
    #[cfg(target_os = "linux")]
    return crate::linux::uninstall_ca(filename);

    #[cfg(not(target_os = "linux"))]
    Err(anyhow::anyhow!(
        "Unable to uninstall CA certificate '{}' on this platform",
        filename
    ))
}

#[cfg(test)]
mod tests {}
