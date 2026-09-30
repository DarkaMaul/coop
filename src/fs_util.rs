use std::ffi::CStr;
use std::fs::{self, File};
use std::io::Write as _;
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::io::{AsRawFd as _, FromRawFd as _};
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

/// Create and seal a private directory without following path symlinks.
/// Ancestors must be owned by this user or root; writable shared ancestors
/// must have the sticky bit (for example /tmp). Existing private directories
/// are tightened through their open descriptor before being used.
pub fn private_dir(path: &Path) -> Result<()> {
    seal_private_dir(path, MissingDirectory::Create)
}

/// Seal existing private storage without recreating a concurrently removed path.
pub fn private_existing_dir(path: &Path) -> Result<()> {
    seal_private_dir(path, MissingDirectory::Reject)
}

#[derive(Clone, Copy)]
enum MissingDirectory {
    Create,
    Reject,
}

fn seal_private_dir(path: &Path, missing: MissingDirectory) -> Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;
    use std::path::Component;

    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    if absolute == Path::new("/") {
        bail!("The filesystem root cannot be private storage");
    }
    let mut directory = File::open("/")?;
    check_ancestor(&directory)?;
    let components: Vec<_> = absolute.components().collect();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(name) = component else {
            if matches!(component, Component::ParentDir) {
                bail!(
                    "Private storage path cannot contain '..': {}",
                    path.display()
                );
            }
            continue;
        };
        let name = CString::new(name.as_bytes())?;
        let final_component = index + 1 == components.len();
        let mut opened = open_directory_at(&directory, &name, SymlinkPolicy::Reject);
        if opened.is_err() && !final_component && root_owned_symlink_at(&directory, &name) {
            opened = open_directory_at(&directory, &name, SymlinkPolicy::TrustedAncestor);
        }
        let (next, creation) = match opened {
            Ok(next) => (next, DirectoryCreation::Existing),
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    && matches!(missing, MissingDirectory::Create) =>
            {
                let creation = create_private_directory_at(&directory, &name)?;
                (
                    open_directory_at(&directory, &name, SymlinkPolicy::Reject)?,
                    creation,
                )
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("Cannot open private directory {}", path.display()));
            }
        };
        directory = next;
        let metadata = directory.metadata()?;
        // SAFETY: geteuid has no preconditions.
        let uid = unsafe { libc::geteuid() };
        if metadata.uid() != uid && (final_component || metadata.uid() != 0) {
            bail!(
                "Private storage requires an owned directory: {}",
                path.display()
            );
        }
        if final_component || matches!(creation, DirectoryCreation::Created) {
            directory.set_permissions(fs::Permissions::from_mode(0o700))?;
            clear_private_acl(&directory)?;
        } else {
            check_ancestor(&directory)?;
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum SymlinkPolicy {
    Reject,
    TrustedAncestor,
}

#[derive(Debug, PartialEq, Eq)]
enum DirectoryCreation {
    Created,
    Existing,
}

fn open_directory_at(parent: &File, name: &CStr, policy: SymlinkPolicy) -> std::io::Result<File> {
    const DIRECTORY_OPEN_FLAGS: libc::c_int = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC;
    const PRIVATE_DIRECTORY_OPEN_FLAGS: libc::c_int = DIRECTORY_OPEN_FLAGS | libc::O_NOFOLLOW;
    let flags = match policy {
        SymlinkPolicy::Reject => PRIVATE_DIRECTORY_OPEN_FLAGS,
        SymlinkPolicy::TrustedAncestor => DIRECTORY_OPEN_FLAGS,
    };
    // SAFETY: parent owns a live descriptor and name is NUL-terminated.
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: openat returned a new owned descriptor, including a valid fd 0.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn root_owned_symlink_at(parent: &File, name: &CStr) -> bool {
    // SAFETY: all-zero is a valid initial value for the C stat output structure.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: parent and name are valid; stat is writable.
    (unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            &raw mut stat,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    }) == 0
        && trusted_ancestor_alias(stat.st_mode, stat.st_uid)
}

fn trusted_ancestor_alias(mode: libc::mode_t, uid: libc::uid_t) -> bool {
    mode & libc::S_IFMT == libc::S_IFLNK && uid == 0
}

fn directory_creation(result: libc::c_int, error: std::io::Error) -> Result<DirectoryCreation> {
    if result == 0 {
        Ok(DirectoryCreation::Created)
    } else if error.kind() == std::io::ErrorKind::AlreadyExists {
        Ok(DirectoryCreation::Existing)
    } else {
        Err(error.into())
    }
}

fn create_private_directory_at(parent: &File, name: &CStr) -> Result<DirectoryCreation> {
    // SAFETY: parent owns a live descriptor and name is NUL-terminated.
    let result = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
    let creation = directory_creation(result, std::io::Error::last_os_error())?;
    if matches!(creation, DirectoryCreation::Created) {
        // Restore owner permissions removed by umask before opening the directory.
        // The new entry is owned by this user in the pinned, checked parent.
        // SAFETY: valid parent/name; no other user can replace our new entry.
        if unsafe { libc::fchmodat(parent.as_raw_fd(), name.as_ptr(), 0o700, 0) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    Ok(creation)
}

fn check_ancestor(file: &File) -> Result<()> {
    #[cfg(target_os = "macos")]
    mac_acl::check_ancestor(file)?;
    if writable_ancestor(file.metadata()?.mode()) {
        bail!("Private storage has a writable ancestor");
    }
    Ok(())
}

fn writable_ancestor(mode: u32) -> bool {
    mode & 0o022 != 0 && mode & 0o1000 == 0
}

/// Remove ACL grants and directory inheritance from private storage.
/// chmod alone does not remove macOS extended ACL grants.
pub fn clear_private_acl(file: &File) -> Result<()> {
    #[cfg(target_os = "linux")]
    for name in [c"system.posix_acl_access", c"system.posix_acl_default"] {
        // SAFETY: file owns a live descriptor and name is NUL-terminated.
        if unsafe { libc::fremovexattr(file.as_raw_fd(), name.as_ptr()) } != 0 {
            acl_removal_error(std::io::Error::last_os_error())?;
        }
    }
    #[cfg(target_os = "macos")]
    mac_acl::clear(file)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn acl_removal_error(error: std::io::Error) -> Result<()> {
    if matches!(error.raw_os_error(), Some(libc::ENODATA | libc::ENOTSUP)) {
        Ok(())
    } else {
        Err(error.into())
    }
}

#[cfg(target_os = "macos")]
mod mac_acl {
    use std::fs::File;
    use std::os::unix::io::AsRawFd as _;

    use anyhow::{Result, bail};

    // Darwin sys/acl.h; libc does not expose these functions.
    unsafe extern "C" {
        fn acl_init(count: libc::c_int) -> *mut libc::c_void;
        fn acl_get_fd(fd: libc::c_int) -> *mut libc::c_void;
        fn acl_set_fd(fd: libc::c_int, acl: *mut libc::c_void) -> libc::c_int;
        fn acl_free(acl: *mut libc::c_void) -> libc::c_int;
        fn acl_get_entry(
            acl: *mut libc::c_void,
            id: libc::c_int,
            entry: *mut *mut libc::c_void,
        ) -> libc::c_int;
        fn acl_get_tag_type(entry: *mut libc::c_void, tag: *mut libc::c_int) -> libc::c_int;
        fn acl_get_permset_mask_np(entry: *mut libc::c_void, mask: *mut u64) -> libc::c_int;
        fn acl_get_flagset_np(
            entry: *mut libc::c_void,
            flags: *mut *mut libc::c_void,
        ) -> libc::c_int;
        fn acl_get_flag_np(flags: *mut libc::c_void, flag: libc::c_int) -> libc::c_int;
    }

    struct Acl(*mut libc::c_void);
    impl Drop for Acl {
        fn drop(&mut self) {
            // SAFETY: this owns the allocation from acl_init or acl_get_fd.
            unsafe {
                acl_free(self.0);
            }
        }
    }

    pub(super) fn clear(file: &File) -> Result<()> {
        // SAFETY: acl_init allocates an empty extended ACL.
        let acl = Acl(unsafe { acl_init(0) });
        if acl.0.is_null() {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: valid descriptor and allocated ACL.
        if unsafe { acl_set_fd(file.as_raw_fd(), acl.0) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ENOTSUP) {
                return Err(error.into());
            }
        }
        Ok(())
    }

    pub(super) fn check_ancestor(file: &File) -> Result<()> {
        // SAFETY: file owns a valid descriptor.
        let pointer = unsafe { acl_get_fd(file.as_raw_fd()) };
        if pointer.is_null() {
            let error = std::io::Error::last_os_error();
            if matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ENOTSUP)) {
                return Ok(());
            }
            return Err(error.into());
        }
        let acl = Acl(pointer);
        let mut id = 0; // ACL_FIRST_ENTRY; ACL_NEXT_ENTRY is -1.
        loop {
            let mut entry = std::ptr::null_mut();
            // SAFETY: acl is allocated; entry is a writable output pointer.
            if unsafe { acl_get_entry(acl.0, id, &raw mut entry) } != 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINVAL) {
                    return Ok(());
                }
                return Err(error.into());
            }
            id = -1;
            let mut tag = 0;
            let mut mask = 0;
            let mut flags = std::ptr::null_mut();
            // SAFETY: entry belongs to the live ACL; outputs are writable.
            if unsafe { acl_get_tag_type(entry, &raw mut tag) } != 0
                || unsafe { acl_get_permset_mask_np(entry, &raw mut mask) } != 0
                || unsafe { acl_get_flagset_np(entry, &raw mut flags) } != 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            // ACL_ENTRY_ONLY_INHERIT does not authorize writes to this parent.
            // SAFETY: flags belongs to the live entry.
            let inherit_only = unsafe { acl_get_flag_np(flags, 1 << 8) };
            if inherit_only < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            // ADD_FILE, DELETE, ADD_SUBDIRECTORY, DELETE_CHILD, WRITE_SECURITY, CHANGE_OWNER.
            const WRITE_CONTROL: u64 =
                (1 << 2) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 12) | (1 << 13);
            if tag == 1 && inherit_only == 0 && mask & WRITE_CONTROL != 0 {
                bail!("Private storage ancestor has an ACL granting write access");
            }
        }
    }
}

/// Write private JSON state atomically, tightening existing permissions.
pub fn atomic_write_json(path: &Path, json: &str) -> Result<()> {
    private_dir(path.parent().context("Private state has no parent")?)?;
    atomic_write_with_mode(path, json, 0o600)
}

/// RAII file lock acquired via `flock(LOCK_EX)`. Releases on drop.
///
/// Use [`lock_sibling`] for an indefinite wait or [`lock_sibling_bounded`]
/// when a lifecycle operation must time out.
pub struct FileLock {
    _file: File,
}

/// Acquire an exclusive flock on a sibling `.lock` file next to `target`.
///
/// The lock file is created if necessary and lives across calls — its
/// purpose is purely to serialize access to `target`. Releases on drop.
/// Returns an error if the parent directory cannot be created or the
/// lock cannot be acquired.
#[mutants::skip] // low-payoff: flock helper; callers always target existing dirs, so the parent-dir guard is never exercised
pub fn lock_sibling(target: &Path) -> Result<FileLock> {
    let parent = target.parent().unwrap_or_else(|| Path::new("."));
    if !parent.as_os_str().is_empty() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory {}", parent.display()))?;
    }
    let stem = target
        .file_name()
        .map_or_else(|| "coop".to_string(), |n| n.to_string_lossy().into_owned());
    let lock_path = parent.join(format!(".{stem}.lock"));
    let file = File::create(&lock_path)
        .with_context(|| format!("Failed to create lock file {}", lock_path.display()))?;
    // SAFETY: flock is safe on a valid fd. The File owns the fd and
    // outlives this call.
    let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if ret != 0 {
        bail!(
            "Failed to acquire lock on {}: {}",
            lock_path.display(),
            std::io::Error::last_os_error()
        );
    }
    Ok(FileLock { _file: file })
}

/// Acquire a sibling lock with a bounded wait. The lock file stays outside
/// an instance directory, so destroying that directory cannot replace the
/// inode used by concurrent lifecycle operations.
pub fn lock_sibling_bounded(target: &Path, timeout: Duration) -> Result<FileLock> {
    let parent = target.parent().context("Lock target has no parent")?;
    fs::create_dir_all(parent)?;
    let stem = target.file_name().context("Lock target has no name")?;
    let path = parent.join(format!(".{}.operation.lock", stem.to_string_lossy()));
    let file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .with_context(|| format!("Failed to open operation lock {}", path.display()))?;
    let start = Instant::now();
    loop {
        // SAFETY: file owns a valid descriptor throughout the flock call.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(FileLock { _file: file });
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::WouldBlock {
            return Err(error).with_context(|| format!("Failed to lock {}", path.display()));
        }
        if start.elapsed() >= timeout {
            bail!("Timed out waiting for operation lock {}", path.display());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Write `content` to `path` atomically with permissions `mode`.
///
/// If the target file already exists with stricter permissions (any
/// bit in `mode` not also set on the existing file), the existing
/// permissions are preserved — we never relax a file's mode.
pub fn atomic_write_with_mode(path: &Path, content: &str, mode: u32) -> Result<()> {
    let parent = path
        .parent()
        .context("Cannot determine parent directory for atomic write")?;
    if !parent.as_os_str().is_empty() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory {}", parent.display()))?;
    }
    let perms = match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_file()
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.nlink() != 1
            {
                bail!(
                    "Atomic write requires an owned regular file: {}",
                    path.display()
                );
            }
            let existing = metadata.permissions().mode() & 0o777;
            // Pick the more restrictive of (existing, requested).
            let combined = existing & mode;
            fs::Permissions::from_mode(combined)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::Permissions::from_mode(mode)
        }
        Err(error) => return Err(error.into()),
    };
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    clear_private_acl(temporary.as_file())?;
    temporary.write_all(content.as_bytes())?;
    temporary.as_file().set_permissions(perms)?;
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("Failed to replace {}", path.display()))?;
    Ok(())
}

/// Write content to a file atomically, preserving SSH-appropriate
/// permissions (0o600 default).
pub fn atomic_write_ssh(path: &Path, content: &str) -> Result<()> {
    atomic_write_with_mode(path, content, 0o600)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code — panics are assertions")]
mod tests {
    use super::*;

    #[test]
    fn directory_creation_preserves_existing_and_failed_results() {
        assert_eq!(
            directory_creation(0, std::io::Error::from_raw_os_error(libc::EACCES)).unwrap(),
            DirectoryCreation::Created
        );
        assert_eq!(
            directory_creation(-1, std::io::Error::from_raw_os_error(libc::EEXIST)).unwrap(),
            DirectoryCreation::Existing
        );
        assert!(directory_creation(-1, std::io::Error::from_raw_os_error(libc::EACCES)).is_err());
    }

    #[test]
    fn trusted_ancestor_alias_requires_root_owned_symlink() {
        assert!(trusted_ancestor_alias(libc::S_IFLNK | 0o777, 0));
        assert!(!trusted_ancestor_alias(libc::S_IFLNK | 0o777, 65534));
        assert!(!trusted_ancestor_alias(libc::S_IFDIR | 0o755, 0));
        assert!(!trusted_ancestor_alias(libc::S_IFREG | 0o644, 0));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn acl_error_policy_accepts_absence_and_unsupported_but_preserves_other_errors() {
        for errno in [libc::ENODATA, libc::ENOTSUP] {
            assert!(acl_removal_error(std::io::Error::from_raw_os_error(errno)).is_ok());
        }
        for errno in [libc::EACCES, libc::EIO] {
            let error = acl_removal_error(std::io::Error::from_raw_os_error(errno)).unwrap_err();
            assert_eq!(
                error
                    .downcast_ref::<std::io::Error>()
                    .unwrap()
                    .raw_os_error(),
                Some(errno)
            );
        }
    }

    #[test]
    fn existing_directory_repair_preserves_absence() {
        let root = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let path = root.path().join("missing/child");
        let error = private_existing_dir(&path).unwrap_err();
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::NotFound
        );
        assert!(!root.path().join("missing").exists());
        private_dir(&path).unwrap();
        private_existing_dir(&path).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[test]
    fn private_directory_creation_accepts_concurrent_callers() {
        let root = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let barrier = std::sync::Barrier::new(4);
        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    let mut results = Vec::new();
                    for index in 0..32 {
                        barrier.wait();
                        results.push(private_dir(&root.path().join(format!("dir-{index}"))));
                    }
                    // All callers reach every barrier even when creation fails.
                    for result in results {
                        result.unwrap();
                    }
                });
            }
        });
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 32);
    }

    #[test]
    fn private_directory_descriptors_are_closed_with_stdin_initially_closed() {
        const CHILD: &str = "COOP_PRIVATE_DIRECTORY_FD_TEST";
        if std::env::var_os(CHILD).is_none() {
            assert!(std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "fs_util::tests::private_directory_descriptors_are_closed_with_stdin_initially_closed"])
                .env(CHILD, "1").status().unwrap().success());
            return;
        }
        let root = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        // The child runs only this test; fd 0 is deliberately available to openat.
        unsafe {
            libc::close(0);
        }
        assert!(fs::metadata(root.path().join("missing")).is_err());
        let directory = root.path().join("a/b");
        private_dir(&directory).unwrap();
        assert_eq!(
            fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(unsafe { libc::fcntl(0, libc::F_GETFD) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EBADF)
        );
    }

    #[test]
    fn writable_ancestor_requires_sticky_bit_for_each_write_class() {
        for mode in [0o700, 0o755, 0o1755, 0o1777, 0o1702, 0o1720] {
            assert!(!writable_ancestor(mode));
        }
        for mode in [0o702, 0o720, 0o722, 0o777] {
            assert!(writable_ancestor(mode));
        }
    }

    #[test]
    fn generic_config_writes_and_locks_preserve_parent_permissions() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let path = root.path().join("config.toml");
        atomic_write_with_mode(&path, "key = 1", 0o644).unwrap();
        let _lock = lock_sibling(&path).unwrap();
        assert_eq!(
            fs::metadata(root.path()).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(fs::read_to_string(path).unwrap(), "key = 1");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_ancestor_acl_write_grants_are_rejected_and_deny_entries_are_allowed() {
        use std::process::Command;
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            Command::new("chmod")
                .args(["+a", "everyone allow add_file"])
                .arg(root.path())
                .status()
                .unwrap()
                .success()
        );
        assert!(private_dir(&root.path().join("private")).is_err());
        assert!(
            Command::new("chmod")
                .arg("-N")
                .arg(root.path())
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("chmod")
                .args(["+a", "everyone deny delete"])
                .arg(root.path())
                .status()
                .unwrap()
                .success()
        );
        private_dir(&root.path().join("private")).unwrap();
        let file = root.path().join("private/state.json");
        fs::write(&file, "canary").unwrap();
        assert!(
            Command::new("chmod")
                .args(["+a", "everyone allow read"])
                .arg(&file)
                .status()
                .unwrap()
                .success()
        );
        crate::private_storage::private_file(&file).unwrap();
        let listing = Command::new("ls").arg("-le").arg(&file).output().unwrap();
        assert!(listing.status.success());
        assert!(!String::from_utf8_lossy(&listing.stdout).contains("allow read"));
        assert_eq!(fs::read_to_string(&file).unwrap(), "canary");
    }

    #[test]
    fn bounded_sibling_lock_times_out_and_can_be_reacquired() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("instance");
        let first = lock_sibling_bounded(&target, Duration::from_millis(100)).unwrap();
        let error = lock_sibling_bounded(&target, Duration::from_millis(100))
            .err()
            .unwrap();
        assert!(error.to_string().contains("Timed out"));
        drop(first);
        assert!(lock_sibling_bounded(&target, Duration::from_millis(100)).is_ok());
    }

    #[test]
    fn atomic_write_json_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.json");
        atomic_write_json(&path, r#"{"key": "value"}"#).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), r#"{"key": "value"}"#);
        // No sibling .tmp files left behind
        let siblings: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(siblings.is_empty(), "stray tmp file remains");
    }

    #[test]
    fn atomic_write_json_preserves_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.json");
        fs::write(&path, "old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        atomic_write_json(&path, "new").unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn atomic_write_json_creates_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("dir").join("test.json");
        atomic_write_json(&path, "{}").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "{}");
    }

    #[test]
    fn atomic_write_json_overwrites_completely() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.json");

        // Write long content first
        atomic_write_json(&path, &"x".repeat(1000)).unwrap();
        // Overwrite with short content
        atomic_write_json(&path, "{}").unwrap();

        // Must be exactly the short content, not a partial mix
        assert_eq!(fs::read_to_string(&path).unwrap(), "{}");
    }

    #[test]
    fn atomic_write_json_default_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("new.json");
        atomic_write_json(&path, "{}").unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn atomic_write_ssh_default_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config");
        atomic_write_ssh(&path, "Host *\n").unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn atomic_write_ssh_preserves_existing_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config");
        fs::write(&path, "old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        atomic_write_ssh(&path, "new").unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn atomic_write_with_mode_never_relaxes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        fs::write(&path, "old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        // Requesting a more permissive mode must not widen the file.
        atomic_write_with_mode(&path, "new", 0o644).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "existing 0o600 must not be relaxed to 0o644");
        assert_eq!(fs::read_to_string(&path).unwrap(), "new");
    }

    #[test]
    fn atomic_write_with_mode_default_for_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("new");
        atomic_write_with_mode(&path, "content", 0o640).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640, "new file must use the requested mode verbatim");
        assert_eq!(fs::read_to_string(&path).unwrap(), "content");
    }

    #[test]
    fn atomic_write_with_mode_creates_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("dir").join("file");
        atomic_write_with_mode(&path, "content", 0o600).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "content");
    }

    #[test]
    fn atomic_write_no_temp_file_on_success() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.json");
        atomic_write_json(&path, "{}").unwrap();

        // Verify no stale .tmp sibling
        let entries: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].file_name(), "test.json");
    }
}
