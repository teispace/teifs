//! What an integrity check finds: a stored version's verdict, and what a pass over the
//! drive has found so far.

use std::fmt;

use serde::{Deserialize, Serialize};

/// What a check found wrong with a stored version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "problem", rename_all = "camelCase")]
pub enum Damage {
    /// Its data file is gone.
    Missing,
    /// Fewer bytes are stored than it has.
    Truncated,
    /// Its encrypted bytes, or its sealed record, don't authenticate.
    Tampered,
    /// Its bytes don't match its ETag.
    Etag,
    /// Its bytes don't match a checksum kept with it (of a part, when `part` is set: its
    /// position in the object, from 1).
    #[serde(rename_all = "camelCase")]
    Checksum {
        /// The algorithm.
        algorithm: String,
        /// The part.
        #[serde(skip_serializing_if = "Option::is_none")]
        part: Option<u32>,
    },
}

/// Why a version couldn't be checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Unverifiable {
    /// It's encrypted with a customer-provided key (SSE-C), which TeiFS doesn't keep.
    CustomerKey,
    /// It's encrypted under a KMS key, and no KMS was at hand to open it.
    NoKms,
    /// Nothing was recorded to compare with (a folder bucket's file changed outside
    /// TeiFS, not yet indexed again).
    NothingToCompare,
    /// It changed while it was being read (a folder bucket's file being edited).
    ChangedMeanwhile,
}

impl fmt::Display for Damage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => f.write_str("its data is missing"),
            Self::Truncated => f.write_str("its data is cut short"),
            Self::Tampered => f.write_str("its encrypted data doesn't authenticate"),
            Self::Etag => f.write_str("its bytes don't match its ETag"),
            Self::Checksum {
                algorithm,
                part: None,
            } => write!(f, "its bytes don't match its {algorithm} checksum"),
            Self::Checksum {
                algorithm,
                part: Some(part),
            } => write!(
                f,
                "part {part}'s bytes don't match its {algorithm} checksum"
            ),
        }
    }
}

impl fmt::Display for Unverifiable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::CustomerKey => "it's encrypted with a key its client keeps (SSE-C)",
            Self::NoKms => "it's encrypted, and the keyring isn't here (--kms-keyring)",
            Self::NothingToCompare => "it changed outside TeiFS, so nothing records its bytes",
            Self::ChangedMeanwhile => "it changed while it was being read",
        })
    }
}

/// The outcome of checking one version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "camelCase")]
pub enum Verdict {
    /// Its bytes are the ones written.
    Intact,
    /// Its bytes aren't.
    Damaged {
        /// What's wrong.
        #[serde(flatten)]
        damage: Damage,
    },
    /// It couldn't be checked.
    Unverifiable {
        /// Why.
        reason: Unverifiable,
    },
}

impl From<Damage> for Verdict {
    fn from(damage: Damage) -> Self {
        Self::Damaged { damage }
    }
}

impl From<Unverifiable> for Verdict {
    fn from(reason: Unverifiable) -> Self {
        Self::Unverifiable { reason }
    }
}

/// One version checked by a pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Checked {
    /// Its bucket.
    pub bucket: String,
    /// Its key.
    pub key: String,
    /// Its version id.
    pub version_id: String,
    /// Its size in bytes.
    pub size: u64,
    /// What the check found.
    #[serde(flatten)]
    pub verdict: Verdict,
}

/// The most damaged versions a scrub pass lists (it counts them all).
pub const MAX_FINDINGS: usize = 100;

/// A background integrity pass over the drive (a scrub): how far it got and what it found.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScrubPass {
    /// When it started, in milliseconds since the Unix epoch.
    pub started_ms: i64,
    /// When it finished; `None` while it's under way.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_ms: Option<i64>,
    /// Versions checked.
    pub versions: u64,
    /// Bytes read.
    pub bytes: u64,
    /// Versions found damaged.
    pub damaged: u64,
    /// Versions that couldn't be checked.
    pub unverifiable: u64,
    /// The damaged versions, the first [`MAX_FINDINGS`] found.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<Checked>,
}

impl ScrubPass {
    /// Counts `checked` in, and lists it if it's damaged.
    pub fn record(&mut self, checked: Checked) {
        self.versions += 1;
        self.bytes += checked.size;
        match checked.verdict {
            Verdict::Intact => {}
            Verdict::Unverifiable { .. } => self.unverifiable += 1,
            Verdict::Damaged { .. } => {
                self.damaged += 1;
                if self.findings.len() < MAX_FINDINGS {
                    self.findings.push(checked);
                }
            }
        }
    }
}

/// What the drive's scrubs have found.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScrubReport {
    /// The pass under way, if one is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<ScrubPass>,
    /// The last pass that finished.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last: Option<ScrubPass>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checked(size: u64, verdict: Verdict) -> Checked {
        Checked {
            bucket: "b".into(),
            key: "k".into(),
            version_id: "null".into(),
            size,
            verdict,
        }
    }

    #[test]
    fn a_pass_counts_everything_and_lists_the_first_damage() {
        let mut pass = ScrubPass::default();
        pass.record(checked(10, Verdict::Intact));
        pass.record(checked(20, Unverifiable::CustomerKey.into()));
        for _ in 0..=MAX_FINDINGS {
            pass.record(checked(1, Damage::Etag.into()));
        }
        assert_eq!(
            (pass.versions, pass.bytes, pass.damaged, pass.unverifiable),
            (103, 131, 101, 1)
        );
        assert_eq!(pass.findings.len(), MAX_FINDINGS);
        let json = serde_json::to_value(&pass.findings[0]).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"bucket": "b", "key": "k", "versionId": "null", "size": 1,
                "verdict": "damaged", "problem": "etag"})
        );
        let back: Checked = serde_json::from_value(json).unwrap();
        assert_eq!(back, pass.findings[0]);
    }
}
