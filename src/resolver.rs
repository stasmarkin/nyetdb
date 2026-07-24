//! Directory scoping: is a connection reachable from cwd? Pure logic;
//! path canonicalization (IO) is injected by the caller.

use std::path::{Path, PathBuf};

/// `cwd` must already be canonicalized by the caller. `canon` is realpath
/// (symlinks resolved); an allowed_dir that cannot be canonicalized (e.g.
/// does not exist) grants nothing — fail closed. Empty `allowed_dirs` =
/// denied everywhere.
pub fn is_allowed(
    cwd: &Path,
    allowed_dirs: &[String],
    home: Option<&Path>,
    canon: &dyn Fn(&Path) -> Option<PathBuf>,
) -> bool {
    allowed_dirs.iter().any(|dir| {
        match canon(&expand_home(dir, home)) {
            // Path::starts_with compares whole components: /a/bc does NOT match /a/b.
            Some(allowed) => cwd.starts_with(&allowed),
            None => false,
        }
    })
}

fn expand_home(dir: &str, home: Option<&Path>) -> PathBuf {
    if dir == "~" {
        // No home -> empty path, which never canonicalizes -> denied.
        return home.map(Path::to_path_buf).unwrap_or_default();
    }
    if let Some(rest) = dir.strip_prefix("~/") {
        return match home {
            // Defense in depth (config validation already rejects these):
            // a rooted remainder ("~//...") or a Windows drive prefix ("C:.")
            // makes join() ignore home; ".." escapes home. All would widen
            // the scope — fail closed instead.
            Some(h) if safe_remainder(rest) => h.join(rest),
            _ => PathBuf::new(),
        };
    }
    PathBuf::from(dir)
}

fn safe_remainder(rest: &str) -> bool {
    use std::path::Component;
    let path = Path::new(rest);
    !path.has_root()
        && !path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::Prefix(_)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn canon(p: &Path) -> Option<PathBuf> {
        fs::canonicalize(p).ok()
    }

    #[test]
    fn tilde_expands_to_home() {
        let home = tempfile::tempdir().unwrap();
        let proj = home.path().join("proj/sub");
        fs::create_dir_all(&proj).unwrap();
        let cwd = fs::canonicalize(&proj).unwrap();
        assert!(is_allowed(
            &cwd,
            &["~/proj".into()],
            Some(home.path()),
            &canon
        ));
        assert!(is_allowed(&cwd, &["~".into()], Some(home.path()), &canon));
        // No home dir -> tilde cannot resolve -> denied.
        assert!(!is_allowed(&cwd, &["~/proj".into()], None, &canon));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_allowed_dir_resolves() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real");
        fs::create_dir(&real).unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let cwd = fs::canonicalize(&real).unwrap();
        // allowed_dirs points at the symlink; cwd is the real dir.
        assert!(is_allowed(
            &cwd,
            &[link.to_string_lossy().into_owned()],
            None,
            &canon
        ));
    }

    #[test]
    fn rooted_remainder_after_tilde_is_denied() {
        let home = tempfile::tempdir().unwrap();
        // Old bug: "~//" expanded to the filesystem root -> allowed everywhere.
        assert_eq!(expand_home("~//", Some(home.path())), PathBuf::new());
        assert_eq!(expand_home("~//etc", Some(home.path())), PathBuf::new());
        let cwd = fs::canonicalize(".").unwrap();
        assert!(!is_allowed(
            &cwd,
            &["~//".into()],
            Some(home.path()),
            &canon
        ));
        assert!(!is_allowed(
            &cwd,
            &["~//etc".into()],
            Some(home.path()),
            &canon
        ));
    }

    #[test]
    fn parent_dir_remainder_after_tilde_is_denied() {
        let home = tempfile::tempdir().unwrap();
        // "~/.." would canonicalize outside home -> widened scope.
        assert_eq!(expand_home("~/..", Some(home.path())), PathBuf::new());
        assert_eq!(expand_home("~/../etc", Some(home.path())), PathBuf::new());
        let cwd = fs::canonicalize(".").unwrap();
        assert!(!is_allowed(
            &cwd,
            &["~/..".into()],
            Some(home.path()),
            &canon
        ));
    }

    #[cfg(windows)]
    #[test]
    fn drive_prefix_remainder_is_unsafe() {
        // "C:." is Component::Prefix only on Windows; join() would ignore home.
        assert!(!safe_remainder("C:."));
        assert!(!safe_remainder(r"C:\x"));
    }

    #[test]
    fn nested_path_is_allowed() {
        let tmp = tempfile::tempdir().unwrap();
        let deep = tmp.path().join("a/b/c");
        fs::create_dir_all(&deep).unwrap();
        let cwd = fs::canonicalize(&deep).unwrap();
        let allowed = tmp.path().join("a").to_string_lossy().into_owned();
        assert!(is_allowed(&cwd, &[allowed], None, &canon));
    }

    #[test]
    fn sibling_with_common_string_prefix_is_denied() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join("b")).unwrap();
        fs::create_dir(tmp.path().join("bc")).unwrap();
        let cwd = fs::canonicalize(tmp.path().join("bc")).unwrap();
        let allowed = tmp.path().join("b").to_string_lossy().into_owned();
        assert!(!is_allowed(&cwd, &[allowed], None, &canon));
    }

    #[test]
    fn empty_allowed_dirs_denies_everywhere() {
        let cwd = fs::canonicalize(".").unwrap();
        assert!(!is_allowed(&cwd, &[], None, &canon));
    }

    #[test]
    fn nonexistent_allowed_dir_grants_nothing() {
        let cwd = fs::canonicalize(".").unwrap();
        assert!(!is_allowed(
            &cwd,
            &["/no/such/dir/hopefully".into()],
            None,
            &canon
        ));
    }
}
