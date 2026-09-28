//! Releases: `release VERSION` prepares one (the version everywhere, the changelog's
//! `Unreleased` section under the version and today's date), and `release-notes VERSION`
//! prints its notes, failing unless the version and the notes are in place. The release
//! workflow runs `release-notes` for the tag it builds.

use std::{
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

const UNRELEASED: &str = "## Unreleased";

/// `cargo xtask release VERSION`.
pub fn prepare(root: &Path, version: &str) -> Result<(), String> {
    check_version(version)?;
    let manifest_path = root.join("Cargo.toml");
    let manifest = read(&manifest_path)?;
    write(&manifest_path, &set_version(&manifest, version)?)?;

    let changelog_path = root.join("CHANGELOG.md");
    let changelog = read(&changelog_path)?;
    write(
        &changelog_path,
        &date_unreleased(&changelog, version, &today())?,
    )?;

    // The lock file records the workspace's own versions too.
    super::cargo(root, &["update", "--workspace", "--offline"])?;
    println!(
        "release: {version} is ready. Review, run `cargo xtask verify`, commit \
         (`chore: release {version}`), then tag v{version} and push the tag."
    );
    Ok(())
}

/// `cargo xtask release-notes VERSION`: the changelog section for `VERSION` on stdout.
pub fn notes(root: &Path, version: &str) -> Result<(), String> {
    let version = version.strip_prefix('v').unwrap_or(version);
    check_version(version)?;
    let manifest = read(&root.join("Cargo.toml"))?;
    let current = workspace_version(&manifest)?;
    if current != version {
        return Err(format!(
            "Cargo.toml says {current}, not {version}: run `cargo xtask release {version}`"
        ));
    }
    let changelog = read(&root.join("CHANGELOG.md"))?;
    let section = section(&changelog, version)
        .ok_or_else(|| format!("CHANGELOG.md has no notes under `## {version} - …`"))?;
    print!("{section}");
    Ok(())
}

fn read(path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|e| format!("can't read {}: {e}", path.display()))
}

fn write(path: &Path, text: &str) -> Result<(), String> {
    fs::write(path, text).map_err(|e| format!("can't write {}: {e}", path.display()))
}

/// `MAJOR.MINOR.PATCH`, with an optional `-pre.release` part.
fn check_version(version: &str) -> Result<(), String> {
    let (core, pre) = match version.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (version, None),
    };
    let numbers: Vec<&str> = core.split('.').collect();
    let number = |n: &&str| {
        !n.is_empty()
            && n.bytes().all(|b| b.is_ascii_digit())
            && (n.len() == 1 || !n.starts_with('0'))
    };
    let identifier =
        |p: &str| !p.is_empty() && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
    let pre_ok = pre.is_none_or(|pre| pre.split('.').all(identifier));
    if numbers.len() == 3 && numbers.iter().all(number) && pre_ok {
        Ok(())
    } else {
        Err(format!(
            "`{version}` isn't a version like 0.1.0 or 0.2.0-beta.1"
        ))
    }
}

/// The `version` under `[workspace.package]`.
fn workspace_version(manifest: &str) -> Result<&str, String> {
    let (_, line) = version_line(manifest)?;
    line.split('"')
        .nth(1)
        .ok_or_else(|| "Cargo.toml's workspace version isn't a string".to_owned())
}

/// The byte offset and text of the `version = "…"` line in `[workspace.package]`.
fn version_line(manifest: &str) -> Result<(usize, &str), String> {
    let mut in_package = false;
    let mut offset = 0;
    for line in manifest.split_inclusive('\n') {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_package = trimmed == "[workspace.package]";
        } else if in_package && trimmed.starts_with("version") && trimmed.contains('=') {
            return Ok((offset, line.trim_end_matches(['\n', '\r'])));
        }
        offset += line.len();
    }
    Err("Cargo.toml has no version under [workspace.package]".into())
}

fn set_version(manifest: &str, version: &str) -> Result<String, String> {
    let (offset, line) = version_line(manifest)?;
    Ok(format!(
        "{}version = \"{version}\"{}",
        &manifest[..offset],
        &manifest[offset + line.len()..]
    ))
}

/// Puts the `Unreleased` notes under `## VERSION - DATE`, with a new, empty
/// `Unreleased` section above for what comes next.
fn date_unreleased(changelog: &str, version: &str, date: &str) -> Result<String, String> {
    if section(changelog, version).is_some() {
        return Err(format!("CHANGELOG.md already has notes for {version}"));
    }
    if section(changelog, "Unreleased").is_none() {
        return Err("CHANGELOG.md's `## Unreleased` section is missing or empty".into());
    }
    Ok(changelog.replacen(
        &format!("{UNRELEASED}\n"),
        &format!("{UNRELEASED}\n\n## {version} - {date}\n"),
        1,
    ))
}

/// The text under `## NAME` (a version, or `Unreleased`) up to the next `## `, trimmed
/// of blank lines at either end, with a final line break.
fn section<'a>(changelog: &'a str, name: &str) -> Option<String> {
    let mut lines = changelog.lines();
    lines.find(|line| {
        line.strip_prefix("## ")
            .is_some_and(|heading| heading == name || heading.starts_with(&format!("{name} - ")))
    })?;
    let body: Vec<&'a str> = lines.take_while(|line| !line.starts_with("## ")).collect();
    let text = body.join("\n");
    let text = text.trim_matches('\n');
    (!text.trim().is_empty()).then(|| format!("{text}\n"))
}

/// Today's date in UTC, `YYYY-MM-DD`.
fn today() -> String {
    let days = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() / 86_400);
    let (y, m, d) = civil_from_days(i64::try_from(days).unwrap_or(0));
    format!("{y:04}-{m:02}-{d:02}")
}

/// Days since 1970-01-01 to a calendar date (Howard Hinnant's algorithm).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = u32::try_from(doy - (153 * mp + 2) / 5 + 1).unwrap_or(1);
    let m = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).unwrap_or(1);
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHANGELOG: &str = "# Changelog\n\nIntro.\n\n## Unreleased\n\n- New thing.\n- Fix.\n\n## 0.1.0 - 2026-10-01\n\n- First.\n";

    #[test]
    fn versions_are_semver() {
        for good in ["0.1.0", "1.20.3", "0.2.0-beta.1", "1.0.0-rc.2"] {
            assert!(check_version(good).is_ok(), "{good}");
        }
        for bad in [
            "",
            "1",
            "1.0",
            "01.0.0",
            "1.0.0-",
            "1.0.0-a..b",
            "v1.0.0",
            "1.0.0 ",
        ] {
            assert!(check_version(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn only_the_workspace_version_changes() {
        let manifest = "[workspace]\nmembers = []\n\n[workspace.package]\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[workspace.dependencies]\nclap = { version = \"4.6\" }\n";
        assert_eq!(workspace_version(manifest).unwrap(), "0.1.0");
        let bumped = set_version(manifest, "0.2.0").unwrap();
        assert_eq!(workspace_version(&bumped).unwrap(), "0.2.0");
        assert!(bumped.contains("clap = { version = \"4.6\" }"));
        assert_eq!(bumped.len(), manifest.len());
    }

    #[test]
    fn unreleased_notes_become_the_version() {
        assert_eq!(
            section(CHANGELOG, "0.1.0").unwrap(),
            "- First.\n",
            "a dated heading is found by its version"
        );
        let dated = date_unreleased(CHANGELOG, "0.2.0", "2026-11-02").unwrap();
        assert!(dated.contains("## Unreleased\n\n## 0.2.0 - 2026-11-02\n\n- New thing.\n- Fix.\n"));
        assert_eq!(section(&dated, "0.2.0").unwrap(), "- New thing.\n- Fix.\n");
        assert!(section(&dated, "Unreleased").is_none(), "nothing new yet");
        // Twice, or with nothing to release, is refused.
        assert!(date_unreleased(&dated, "0.2.0", "2026-11-02").is_err());
        assert!(date_unreleased(&dated, "0.3.0", "2026-11-02").is_err());
    }

    #[test]
    fn dates_are_utc_calendar_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(20_725), (2026, 9, 29));
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
    }
}
