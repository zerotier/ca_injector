//! ca_injector: inject CAs into a variety of trust stores
//!
//! This code is adapted from [mkcert](https://github.com/FiloSottile/mkcert) and presented as a
//! library. The general idea is to support a variety of needs for installation of third party CA
//! certificates into trust stores.
//!
//! Please see the (arguably simple) API below to meet your needs. This library only supports linux
//! as of this writing, but OS X and Windows support are planned in the near future.
#[cfg(target_os = "linux")]
mod linux;

/// This function installs a file by name into the system and NSS trust stores. For NSS, the CA
/// name will also be the filename. For system trust stores, this is highly dependent on platform
/// and "platform flavor", such as Ubuntu or Debian for Linux.
pub fn install_ca(filename: &str) -> Result<(), anyhow::Error> {
    #[cfg(target_os = "linux")]
    return crate::linux::install_ca(filename);

    #[cfg(not(target_os = "linux"))]
    Err(anyhow::anyhow!(
        "Unable to install CA certificate '{}' on this platform",
        filename
    ))
}

/// The inverse of [install_ca]. Must be presented with the same base filename as [install_ca] to
/// remove. Errors will occur if the file is not found.
pub fn uninstall_ca(filename: &str) -> Result<(), anyhow::Error> {
    #[cfg(target_os = "linux")]
    return crate::linux::uninstall_ca(filename);

    #[cfg(not(target_os = "linux"))]
    Err(anyhow::anyhow!(
        "Unable to uninstall CA certificate '{}' on this platform",
        filename
    ))
}
