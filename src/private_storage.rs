//! Permissions for managed host state. Never traverse guest filesystems.
use std::fs;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::config::CoopConfig;
use crate::fs_util::private_dir;

/// Repair existing managed state before a command reads it. Only known host
/// state directories are scanned; mounted rootfs trees and workspace data
/// must not be recursively chmodded.
pub fn prepare(cfg: &CoopConfig) -> Result<()> {
    private_dir(&cfg.data_dir)?;
    repair_files(&cfg.data_dir)?;
    for name in ["images", "instances", "state"] {
        let directory = cfg.data_dir.join(name);
        private_dir(&directory)?;
        repair_files(&directory)?;
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            let metadata = entry.path().symlink_metadata()?;
            if metadata.is_dir() {
                private_dir(&entry.path())?;
                repair_files(&entry.path())?;
            } else if metadata.is_symlink() {
                bail!(
                    "Managed storage cannot contain a symlink: {}",
                    entry.path().display()
                );
            }
        }
    }
    #[cfg(target_os = "macos")]
    crate::lima::prepare_private_storage()?;
    Ok(())
}

fn repair_files(directory: &Path) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if (name.ends_with(".json") || name.ends_with(".txt") || name == "vm_key" || is_disk(&name))
            && !entry.path().symlink_metadata()?.is_dir()
        {
            private_file(&entry.path())?;
        }
    }
    Ok(())
}

#[expect(
    clippy::case_sensitive_file_extension_comparisons,
    reason = "managed disk names use exact lowercase suffixes"
)]
fn is_disk(name: &str) -> bool {
    name.ends_with(".ext4")
        || name.ends_with(".ext4.new")
        || name.ends_with(".img")
        || name.ends_with(".img.new")
        || matches!(name, "disk" | "diffdisk")
}

/// Seal an existing sensitive file. Root-owned Firecracker disks are repaired
/// with sudo only when necessary, after sealing their user-owned parent.
pub fn private_file(path: &Path) -> Result<()> {
    private_dir(path.parent().context("Private file has no parent")?)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        bail!(
            "Private storage requires a regular file with one link: {}",
            path.display()
        );
    }
    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { libc::geteuid() };
    if metadata.uid() != uid {
        if metadata.uid() != 0
            || !is_disk(
                &path
                    .file_name()
                    .context("Private file has no name")?
                    .to_string_lossy(),
            )
        {
            bail!(
                "Private storage file is not owned by this user: {}",
                path.display()
            );
        }
        if metadata.mode() & 0o777 != 0o600 {
            tracing::warn!("Restricting existing disk permissions: {}", path.display());
            crate::cmd::Cmd::new("chmod")
                .arg("0600")
                .arg("--")
                .arg(path)
                .sudo()
                .run()?;
        }
        return Ok(());
    }
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let opened = file.metadata()?;
    if opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
        bail!(
            "Private storage file changed while opening: {}",
            path.display()
        );
    }
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    crate::fs_util::clear_private_acl(&file)?;
    Ok(())
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test assertions")]
mod tests {
    use std::os::unix::fs::symlink;
    use std::process::Command;

    use super::*;
    use crate::config::ConfigPath;
    use crate::fs_util::atomic_write_json;

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().mode() & 0o777
    }

    #[test]
    fn private_storage_under_permissive_umask() {
        const CHILD: &str = "COOP_PRIVATE_STORAGE_TEST_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let status = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "private_storage::tests::private_storage_under_permissive_umask",
                ])
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }
        // Only this test runs in the child, so changing umask cannot race tests.
        unsafe {
            libc::umask(0);
        }
        let root = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let cfg = CoopConfig {
            data_dir: ConfigPath::new(root.path().join("data")),
            ..CoopConfig::default()
        };
        prepare(&cfg).unwrap();
        let instance = cfg.instances_dir().join("test");
        atomic_write_json(&instance.join("guest_env.json"), "{\"canary\":\"test\"}").unwrap();
        let directories: [&Path; 4] = [
            cfg.data_dir.as_ref(),
            &cfg.images_dir(),
            &cfg.instances_dir(),
            &instance,
        ];
        for directory in directories {
            assert_eq!(mode(directory), 0o700);
        }
        assert_eq!(mode(&instance.join("guest_env.json")), 0o600);
        atomic_write_json(&instance.join("guest_env.json"), "{}").unwrap();
        assert_eq!(mode(&instance.join("guest_env.json")), 0o600);
    }

    #[test]
    fn private_directories_override_restrictive_umask() {
        const CHILD: &str = "COOP_PRIVATE_STORAGE_RESTRICTIVE_CHILD";
        if std::env::var_os(CHILD).is_none() {
            assert!(
                Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "private_storage::tests::private_directories_override_restrictive_umask"
                    ])
                    .env(CHILD, "1")
                    .status()
                    .unwrap()
                    .success()
            );
            return;
        }
        let root = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        // SAFETY: this test runs in an isolated child process.
        unsafe {
            libc::umask(0o777);
        }
        let directory = root.path().join("a/b");
        let result = private_dir(&directory);
        if result.is_err() {
            let _ = fs::set_permissions(root.path().join("a"), fs::Permissions::from_mode(0o700));
            let _ = fs::set_permissions(&directory, fs::Permissions::from_mode(0o700));
        }
        result.unwrap();
        assert_eq!(mode(&root.path().join("a")), 0o700);
        assert_eq!(mode(&directory), 0o700);
    }

    #[test]
    fn migration_repairs_state_and_disks_without_entering_guest_trees() {
        let root = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let cfg = CoopConfig {
            data_dir: ConfigPath::new(root.path().join("data")),
            ..CoopConfig::default()
        };
        let instance = cfg.instances_dir().join("test");
        let image = cfg.images_dir().join("test");
        for directory in [&instance, &image, &cfg.data_dir.join("state/github-pat")] {
            fs::create_dir_all(directory).unwrap();
            fs::set_permissions(directory, fs::Permissions::from_mode(0o777)).unwrap();
        }
        let files = [
            instance.join("guest_env.json"),
            instance.join("rootfs.ext4"),
            image.join("rootfs-template.ext4"),
            cfg.data_dir.join("vm_key"),
            cfg.data_dir.join("state/github-pat/test.txt"),
        ];
        for path in &files {
            fs::write(path, "canary").unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap();
        }
        let guest = instance.join("rootfs-mount/etc");
        fs::create_dir_all(&guest).unwrap();
        let guest_file = guest.join("guest.json");
        fs::write(&guest_file, "guest").unwrap();
        fs::set_permissions(&guest_file, fs::Permissions::from_mode(0o644)).unwrap();
        prepare(&cfg).unwrap();
        prepare(&cfg).unwrap();
        for path in &files {
            assert_eq!(mode(path), 0o600);
            assert_eq!(fs::read_to_string(path).unwrap(), "canary");
        }
        assert_eq!(mode(&instance), 0o700);
        assert_eq!(mode(&image), 0o700);
        assert_eq!(mode(&guest_file), 0o644);
    }

    #[test]
    fn rejects_symlinks_hardlinks_and_writable_ancestors() {
        let root = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let target = root.path().join("target");
        fs::write(&target, "untouched").unwrap();
        let owned_directory = root.path().join("owned");
        private_dir(&owned_directory.join("child")).unwrap();
        let ancestor_alias = root.path().join("ancestor-alias");
        symlink(&owned_directory, &ancestor_alias).unwrap();
        assert!(private_dir(&ancestor_alias.join("child")).is_err());
        let before = mode(&target);
        assert!(private_dir(&target).is_err());
        assert_eq!(mode(&target), before);
        let link = root.path().join("link");
        symlink(&target, &link).unwrap();
        assert!(private_file(&link).is_err());
        assert!(atomic_write_json(&link, "changed").is_err());
        fs::remove_file(&link).unwrap();
        fs::hard_link(&target, &link).unwrap();
        assert!(private_file(&link).is_err());
        assert!(atomic_write_json(&link, "changed").is_err());
        assert_eq!(fs::read_to_string(&target).unwrap(), "untouched");
        let shared = root.path().join("shared");
        fs::create_dir(&shared).unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(private_dir(&shared.join("data")).is_err());
        let alias = root.path().join("alias");
        symlink(&shared, &alias).unwrap();
        assert!(private_dir(&alias).is_err());
        assert!(private_dir(Path::new("/")).is_err());
    }

    #[test]
    fn atomic_replacement_tightens_modes_and_rejects_directory_targets() {
        let root = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let path = root.path().join("state.json");
        fs::write(&path, "old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        atomic_write_json(&path, "new").unwrap();
        assert_eq!(mode(&path), 0o600);
        assert_eq!(fs::read_to_string(&path).unwrap(), "new");
        let directory = root.path().join("directory.json");
        fs::create_dir(&directory).unwrap();
        assert!(atomic_write_json(&directory, "{}").is_err());
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 2);
    }

    #[test]
    fn image_names_that_look_like_files_remain_directories() {
        let root = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let cfg = CoopConfig {
            data_dir: ConfigPath::new(root.path().join("data")),
            ..CoopConfig::default()
        };
        prepare(&cfg).unwrap();
        for name in ["my.json", "my.txt", "my.img", "disk"] {
            let image = cfg.image_dir(&crate::config::ImageName::new(name).unwrap());
            fs::create_dir(&image).unwrap();
            prepare(&cfg).unwrap();
            assert_eq!(mode(&image), 0o700);
        }
    }

    #[test]
    fn identifies_managed_disk_names() {
        for name in [
            "rootfs.ext4",
            "rootfs-template.ext4.new",
            "lima-base.img",
            "lima-base.img.new",
            "disk",
            "diffdisk",
        ] {
            assert!(is_disk(name));
        }
        for name in ["state.json", "file", "disk.log", "rootfs.EXT4", "image.IMG"] {
            assert!(!is_disk(name));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn removes_access_and_inherited_acls() {
        use std::os::unix::io::AsRawFd as _;
        let root = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let mut acl = 2_u32.to_le_bytes().to_vec();
        for (tag, permissions, id) in [
            (1_u16, 7_u16, u32::MAX),
            (2, 7, 65534),
            (4, 0, u32::MAX),
            (16, 7, u32::MAX),
            (32, 0, u32::MAX),
        ] {
            acl.extend(tag.to_le_bytes());
            acl.extend(permissions.to_le_bytes());
            acl.extend(id.to_le_bytes());
        }
        let directory = fs::File::open(root.path()).unwrap();
        // Linux POSIX ACL xattr layout from linux/posix_acl_xattr.h.
        assert_eq!(
            unsafe {
                libc::fsetxattr(
                    directory.as_raw_fd(),
                    c"system.posix_acl_default".as_ptr(),
                    acl.as_ptr().cast(),
                    acl.len(),
                    0,
                )
            },
            0
        );
        let path = root.path().join("secret.json");
        fs::write(&path, "canary").unwrap();
        let file = fs::File::open(&path).unwrap();
        assert!(
            unsafe {
                libc::fgetxattr(
                    file.as_raw_fd(),
                    c"system.posix_acl_access".as_ptr(),
                    std::ptr::null_mut(),
                    0,
                )
            } > 0
        );
        private_file(&path).unwrap();
        for (file, name) in [
            (&directory, c"system.posix_acl_default"),
            (&file, c"system.posix_acl_access"),
        ] {
            assert_eq!(
                unsafe {
                    libc::fgetxattr(file.as_raw_fd(), name.as_ptr(), std::ptr::null_mut(), 0)
                },
                -1
            );
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ENODATA)
            );
        }
        assert_eq!(mode(&path), 0o600);
        assert_eq!(fs::read_to_string(path).unwrap(), "canary");
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires passwordless sudo to create foreign-owned fixtures"]
    fn rejects_files_and_directories_owned_by_another_user() {
        struct RestoreOwnership(std::path::PathBuf);
        impl Drop for RestoreOwnership {
            fn drop(&mut self) {
                // SAFETY: geteuid has no preconditions.
                let uid = unsafe { libc::geteuid() }.to_string();
                let _ = Command::new("sudo")
                    .args(["-n", "chown", "-R", &uid])
                    .arg(&self.0)
                    .status();
            }
        }
        let root = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let directory = root.path().join("other");
        // Restore ownership before tempfile cleanup even when an assertion fails.
        let _restore = RestoreOwnership(directory.clone());
        fs::create_dir(&directory).unwrap();
        let path = directory.join("state.json");
        fs::write(&path, "canary").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let child = directory.join("private");
        private_dir(&child).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
        let status = Command::new("sudo")
            .args(["-n", "chown", "65534"])
            .arg(&path)
            .status()
            .unwrap();
        assert!(status.success());
        assert!(private_file(&path).is_err());
        assert!(atomic_write_json(&path, "changed").is_err());
        // Keep the parent traversable so ownership, rather than access, rejects it.
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
        let status = Command::new("sudo")
            .args(["-n", "chown", "65534"])
            .arg(&directory)
            .status()
            .unwrap();
        assert!(status.success());
        assert!(private_dir(&directory).is_err());
        assert!(private_dir(&child).is_err());
        // Restore ownership so tempfile can clean up without privilege.
        let uid = unsafe { libc::geteuid() }.to_string();
        assert!(
            Command::new("sudo")
                .args(["-n", "chown", "-R", &uid])
                .arg(&directory)
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("sudo")
                .args(["-n", "chown", "0"])
                .arg(&directory)
                .status()
                .unwrap()
                .success()
        );
        assert!(private_dir(&directory).is_err());
        private_dir(&child).unwrap();
        let alias = root.path().join("root-alias");
        symlink(&directory, &alias).unwrap();
        assert!(
            Command::new("sudo")
                .args(["-n", "chown", "-h", "0"])
                .arg(&alias)
                .status()
                .unwrap()
                .success()
        );
        assert!(private_dir(&alias).is_err());
        private_dir(&alias.join("private")).unwrap();
        assert_eq!(mode(&child), 0o700);
    }
}
