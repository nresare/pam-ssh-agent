use anyhow::{Context, Result};
use std::path::Path;
use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;

pub fn set_file_permissions(filename: &Path, mode: u32, uid: u32, gid: u32) -> Result<()> {
    // authorized_keys file should be owned by root:root and have 0600 permissions
    let _ = std::os::unix::fs::chown(filename, Some(uid), Some(gid)).with_context(|| format!("Tests tried to set file {:?} ownership to root:root but failed", filename));
    let perms = Permissions::from_mode(mode);
    let _ = std::fs::set_permissions(filename, perms).with_context(|| format!("Tests tried to set permissions of file {:?} to 0o600 but failed", filename));
    Ok(())
}