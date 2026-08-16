//! Every relative markdown link in the repository resolves.
//!
//! The guide is nine files that cross-reference each other, so a rename turns a
//! link into a 404 that nothing else here catches: no other test reads the
//! docs, and the CI linters check spelling, not links. This is the check that
//! would have caught `[docs/DESIGN.md]` surviving the move into `docs/dev/` —
//! in `SECURITY.md`, the file GitHub links from the Security tab.
//!
//! **Only relative targets are checked.** External URLs are deliberately left
//! alone: verifying them would put the network and somebody else's uptime on
//! the critical path of `cargo test`.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Root `.md` files plus everything under `docs/`, recursively.
fn markdown_files(root: &Path) -> Vec<PathBuf> {
    fn is_md(p: &Path) -> bool {
        p.extension().is_some_and(|e| e.eq_ignore_ascii_case("md"))
    }
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let entries = fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {dir:?}: {e}"));
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if is_md(&path) {
                out.push(path);
            }
        }
    }

    let mut out = Vec::new();
    for entry in fs::read_dir(root).expect("read_dir repo root").flatten() {
        let path = entry.path();
        if path.is_file() && is_md(&path) {
            out.push(path);
        }
    }
    walk(&root.join("docs"), &mut out);
    out.sort();
    out
}

/// The lines outside fenced code blocks. A fence line opens or closes a block;
/// what is inside it is a sample, not a link — the annotated config example
/// alone would otherwise contribute a dozen `#`-comment "headings".
fn prose_lines(text: &str) -> impl Iterator<Item = &str> {
    let mut fenced = false;
    text.lines().filter(move |line| {
        if line.trim_start().starts_with("```") {
            fenced = !fenced;
            return false;
        }
        !fenced
    })
}

/// GitHub's heading anchor: lowercase, drop everything that is not a letter,
/// digit, `_` or `-`, and turn each remaining space into a hyphen. Runs of
/// spaces become runs of hyphens, which is why `## MySQL / MariaDB` anchors as
/// `mysql--mariadb` — the slash is dropped but both spaces survive.
fn slug(heading: &str) -> String {
    let mut out = String::new();
    for c in heading.trim().chars() {
        if c.is_alphanumeric() || c == '_' || c == '-' {
            out.extend(c.to_lowercase());
        } else if c.is_whitespace() {
            out.push('-');
        }
    }
    out
}

fn anchors(text: &str) -> BTreeSet<String> {
    prose_lines(text)
        .filter_map(|line| {
            let rest = line.trim_start_matches('#');
            let hashes = line.len() - rest.len();
            // A heading is one to six hashes and then a space: `#nyet` is a
            // word, not an `<h1>`, and GitHub agrees.
            if !(1..=6).contains(&hashes) || !rest.starts_with(' ') {
                return None;
            }
            Some(slug(rest))
        })
        .collect()
}

/// The targets of every `[text](target)` in `text`. Reference-style links and
/// image targets are not used in this repository, so a scan for `](` is the
/// whole parser — and one that cannot silently skip a link the way a partial
/// regex would.
fn link_targets(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in prose_lines(text) {
        let bytes = line.as_bytes();
        let mut i = 0;
        while let Some(open) = line[i..].find("](") {
            let start = i + open + 2;
            match bytes[start..].iter().position(|&b| b == b')') {
                Some(len) => {
                    out.push(line[start..start + len].to_string());
                    i = start + len;
                }
                // An unclosed `](` is not a link; stop scanning this line.
                None => break,
            }
        }
    }
    out
}

#[test]
fn every_relative_markdown_link_resolves() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let files = markdown_files(root);
    assert!(
        files.len() > 5,
        "found only {} markdown files — the walk is wrong",
        files.len()
    );

    let mut broken = Vec::new();
    let mut checked = 0usize;

    for file in &files {
        let text = fs::read_to_string(file).unwrap_or_else(|e| panic!("read {file:?}: {e}"));
        let here = file
            .strip_prefix(root)
            .unwrap_or(file)
            .display()
            .to_string();

        for target in link_targets(&text) {
            if target.starts_with("http://")
                || target.starts_with("https://")
                || target.starts_with("mailto:")
            {
                continue;
            }
            checked += 1;

            let (path_part, fragment) = match target.split_once('#') {
                Some((p, f)) => (p, Some(f)),
                None => (target.as_str(), None),
            };

            // An empty path is a link into the file's own headings.
            let resolved = if path_part.is_empty() {
                file.clone()
            } else {
                let joined = file.parent().expect("a file has a parent").join(path_part);
                if !joined.exists() {
                    broken.push(format!("{here} -> {target} (no such file)"));
                    continue;
                }
                joined
            };

            let Some(fragment) = fragment.filter(|f| !f.is_empty()) else {
                continue;
            };
            // Only markdown carries headings; a fragment on anything else
            // (a directory, an image) is not ours to judge.
            if resolved.extension().is_none_or(|e| e != "md") {
                continue;
            }
            let target_text =
                fs::read_to_string(&resolved).unwrap_or_else(|e| panic!("read {resolved:?}: {e}"));
            if !anchors(&target_text).contains(fragment) {
                broken.push(format!("{here} -> {target} (no such heading)"));
            }
        }
    }

    assert!(
        broken.is_empty(),
        "{} broken link(s) out of {checked} relative ones:\n  {}",
        broken.len(),
        broken.join("\n  ")
    );
}
