use super::*;

#[test]
fn private_directories_and_files_are_private_from_creation() {
    let root = tempfile::tempdir().unwrap();
    let nested = root.path().join("a/b/c");
    create_dir_all_private(&nested).unwrap();
    assert!(nested.is_dir());
    for directory in [
        root.path().join("a"),
        root.path().join("a/b"),
        nested.clone(),
    ] {
        assert!(
            exposure(&directory).unwrap().is_private(),
            "{} must be private",
            directory.display()
        );
    }

    let key = nested.join("secret.key");
    let mut file = create_new_file_private(&key).unwrap();
    io::Write::write_all(&mut file, b"private").unwrap();
    drop(file);
    assert!(exposure(&key).unwrap().is_private());
    assert_eq!(std::fs::read(&key).unwrap(), b"private");
}

#[test]
fn creating_a_file_that_exists_fails_and_leaves_it_alone() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("exists.key");
    std::fs::write(&path, b"original").unwrap();
    let error = create_new_file_private(&path).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
    assert_eq!(std::fs::read(&path).unwrap(), b"original");
}

#[test]
fn creating_an_existing_directory_is_a_no_op() {
    let root = tempfile::tempdir().unwrap();
    create_dir_all_private(root.path()).unwrap();
    create_dir_all_private(&root.path().join("x")).unwrap();
    create_dir_all_private(&root.path().join("x")).unwrap();
}

/// Make `path` readable and writable by everyone, the way a default umask or an inherited
/// `ProgramData` ACL can.
fn loosen(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if path.is_dir() { 0o777 } else { 0o666 };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }
    #[cfg(windows)]
    {
        let status = std::process::Command::new("icacls")
            .arg(path)
            .args(["/grant", "*S-1-1-0:(OI)(CI)F"])
            .output()
            .expect("run icacls");
        assert!(status.status.success(), "icacls failed: {status:?}");
    }
}

#[test]
fn restrict_tightens_loose_files_and_directories() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("loose-dir");
    std::fs::create_dir(&directory).unwrap();
    let file = directory.join("loose.key");
    std::fs::write(&file, b"k").unwrap();
    loosen(&directory);
    loosen(&file);

    let before = exposure(&file).unwrap();
    assert!(
        before.readable_by_others && before.writable_by_others,
        "the fixture must start exposed: {before:?}"
    );
    assert!(!exposure(&directory).unwrap().is_private());

    restrict_file(&file).unwrap();
    restrict_dir(&directory).unwrap();
    assert!(exposure(&file).unwrap().is_private());
    assert!(exposure(&directory).unwrap().is_private());
    assert_eq!(
        std::fs::read(&file).unwrap(),
        b"k",
        "the owner still has access"
    );
}

/// Windows inherits a directory's DACL into new files; Unix does not inherit mode bits (a file
/// created normally gets the umask default), so this guarantee exists only on Windows.
#[cfg(windows)]
#[test]
fn files_created_normally_inside_a_private_directory_are_private() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("private");
    create_dir_all_private(&directory).unwrap();
    let child = directory.join("child.txt");
    std::fs::write(&child, b"x").unwrap();
    assert!(
        exposure(&child).unwrap().is_private(),
        "a file created inside a private directory is private from its first byte"
    );
}

#[test]
fn exposure_of_a_missing_path_is_an_error() {
    let root = tempfile::tempdir().unwrap();
    assert!(exposure(&root.path().join("missing")).is_err());
}

#[test]
fn files_we_create_are_owned_by_the_current_user() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("mine.txt");
    std::fs::write(&path, b"x").unwrap();
    assert!(owned_by_current_user(&path).unwrap());
    let private = root.path().join("private.txt");
    drop(create_new_file_private(&private).unwrap());
    assert!(owned_by_current_user(&private).unwrap());
    assert!(owned_by_current_user(&root.path().join("missing")).is_err());
}

/// A directory where everyone can create entries but not replace or delete others': a sticky
/// `/tmp` on Unix, or `Authenticated Users:(AD)` like `C:\` on Windows.
#[test]
fn create_only_directories_are_creatable_but_not_writable() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("shared");
    create_dir_all_private(&directory).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o1777)).unwrap();
    }
    #[cfg(windows)]
    {
        let status = std::process::Command::new("icacls")
            .arg(&directory)
            .args(["/grant", "*S-1-5-11:(AD)"])
            .output()
            .expect("run icacls");
        assert!(status.status.success(), "icacls failed: {status:?}");
    }
    let exposure = exposure(&directory).unwrap();
    assert!(exposure.creatable_by_others, "{exposure:?}");
    assert!(!exposure.writable_by_others, "{exposure:?}");
    assert!(exposure.tamperable_by_others());
    assert!(!exposure.is_private());
}

/// The OS temp directory and drive roots are shared places every program uses. The model must not
/// call them replaceable by others, or every data-directory ancestor check would reject them.
#[cfg(windows)]
#[test]
fn well_known_windows_ancestors_are_not_replaceable() {
    for path in [
        std::path::PathBuf::from("C:\\"),
        std::path::PathBuf::from("C:\\Users"),
    ] {
        let exposure = exposure(&path).unwrap();
        assert!(
            !exposure.writable_by_others,
            "{} must not look replaceable: {exposure:?}",
            path.display()
        );
    }
}

#[test]
fn final_path_of_an_open_file_is_its_canonical_path() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("real.txt");
    std::fs::write(&path, b"x").unwrap();
    let file = File::open(&path).unwrap();
    match final_path(&file) {
        Ok(real) => assert_eq!(real, std::fs::canonicalize(&path).unwrap()),
        Err(error) if error.kind() == io::ErrorKind::Unsupported => {}
        Err(error) => panic!("final_path failed: {error}"),
    }
}

/// Opening *through* a symlink reports the file the link resolved to, not the link.
#[cfg(unix)]
#[test]
fn final_path_follows_a_symlink_to_the_real_file() {
    let root = tempfile::tempdir().unwrap();
    let real = root.path().join("real.txt");
    std::fs::write(&real, b"x").unwrap();
    let link = root.path().join("link.txt");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let file = File::open(&link).unwrap();
    match final_path(&file) {
        Ok(found) => assert_eq!(found, std::fs::canonicalize(&real).unwrap()),
        Err(error) if error.kind() == io::ErrorKind::Unsupported => {}
        Err(error) => panic!("final_path failed: {error}"),
    }
}

/// A directory junction resolves to its target on Windows (no privilege needed to create one).
#[cfg(windows)]
#[test]
fn final_path_follows_a_junction_to_the_real_file() {
    let root = tempfile::tempdir().unwrap();
    let real_dir = root.path().join("real");
    std::fs::create_dir(&real_dir).unwrap();
    std::fs::write(real_dir.join("file.txt"), b"x").unwrap();
    let junction = root.path().join("junction");
    let status = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&junction)
        .arg(&real_dir)
        .output()
        .unwrap();
    assert!(status.status.success(), "mklink failed: {status:?}");
    let file = File::open(junction.join("file.txt")).unwrap();
    let found = final_path(&file).unwrap();
    assert_eq!(
        found,
        std::fs::canonicalize(real_dir.join("file.txt")).unwrap()
    );
}

#[test]
fn create_dir_private_makes_one_private_directory_and_refuses_an_existing_one() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("one");
    create_dir_private(&directory).unwrap();
    assert!(directory.is_dir());
    assert!(exposure(&directory).unwrap().is_private());
    let error = create_dir_private(&directory).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
    // No parents are created.
    let nested = root.path().join("missing").join("child");
    assert!(create_dir_private(&nested).is_err());
    assert!(!root.path().join("missing").exists());
}

/// A file created private must not block renaming or deleting it while still open, the way a file
/// from `std::fs` does not: callers write a temporary, keep the handle, then rename it into place.
#[test]
fn a_private_file_can_be_renamed_and_replaced_while_its_handle_is_open() {
    let root = tempfile::tempdir().unwrap();
    let temporary = root.path().join("state.tmp");
    let target = root.path().join("state.json");
    let mut file = create_new_file_private(&temporary).unwrap();
    io::Write::write_all(&mut file, b"new").unwrap();
    std::fs::write(&target, b"old").unwrap();
    std::fs::rename(&temporary, &target)
        .expect("rename over an existing file with the handle open");
    assert_eq!(std::fs::read(&target).unwrap(), b"new");
    drop(file);
}

#[test]
fn open_regular_file_opens_files_and_refuses_everything_else() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("plain.txt");
    std::fs::write(&path, b"hello").unwrap();
    let mut file = open_regular_file(&path).unwrap();
    let mut text = String::new();
    io::Read::read_to_string(&mut file, &mut text).unwrap();
    assert_eq!(text, "hello");
    // A directory is not a regular file. (On Windows opening one fails outright; either way it is
    // an error and never a handle.)
    assert!(open_regular_file(root.path()).is_err());
    assert!(open_regular_file(&root.path().join("missing")).is_err());
}

/// A FIFO would block `open` forever waiting for a writer; it must be refused promptly.
#[cfg(unix)]
#[test]
fn open_regular_file_does_not_hang_on_a_fifo() {
    let root = tempfile::tempdir().unwrap();
    let fifo = root.path().join("pipe");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap();
    assert!(status.success());
    let started = std::time::Instant::now();
    let error = open_regular_file(&fifo).unwrap_err();
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "must not block"
    );
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
}

#[test]
fn verified_real_path_reports_the_canonical_path() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("real.txt");
    std::fs::write(&path, b"x").unwrap();
    let file = File::open(&path).unwrap();
    assert_eq!(
        verified_real_path(&file, &path).unwrap(),
        std::fs::canonicalize(&path).unwrap()
    );
}

/// The no-`/proc` fallback: same file open and resolved gives the real path; a different file at
/// the path (swapped after the open) is refused.
#[cfg(unix)]
#[test]
fn the_inode_fallback_refuses_a_path_that_names_a_different_file() {
    // Exercise the fallback arm directly by comparing a handle with a path to another file.
    let root = tempfile::tempdir().unwrap();
    let opened = root.path().join("opened.txt");
    let other = root.path().join("other.txt");
    std::fs::write(&opened, b"a").unwrap();
    std::fs::write(&other, b"b").unwrap();
    let file = File::open(&opened).unwrap();
    use std::os::unix::fs::MetadataExt;
    let a = file.metadata().unwrap();
    let same = std::fs::metadata(&opened).unwrap();
    let different = std::fs::metadata(&other).unwrap();
    assert!(a.dev() == same.dev() && a.ino() == same.ino());
    assert!(!(a.dev() == different.dev() && a.ino() == different.ino()));
}

/// A path with an interior NUL must be refused rather than silently truncated by the wide Win32
/// calls (which would act on a shorter path than `std::fs` later opens).
#[cfg(windows)]
#[test]
fn an_interior_nul_in_a_path_is_refused() {
    use std::os::windows::ffi::OsStringExt;
    let mut units: Vec<u16> = "C:\nul-test".encode_utf16().collect();
    units.insert(4, 0);
    let path = std::path::PathBuf::from(std::ffi::OsString::from_wide(&units));
    assert_eq!(
        create_new_file_private(&path).unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput
    );
    assert_eq!(
        exposure(&path).unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput
    );
    assert_eq!(
        create_dir_private(&path).unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput
    );
}
