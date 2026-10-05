//! Reviewed, pinned artifact manifest for app-managed provider downloads.
//!
//! Every managed install resolves to exactly one entry in [`artifact`], keyed by
//! `(provider_id, host architecture)`. The version, download URL, SHA-256 digest,
//! archive format, and expected executable member are all **hardcoded and reviewed
//! here** — nothing a caller supplies influences them. A new upstream version
//! requires editing this file (a reviewable supply-chain change), never a runtime
//! metadata lookup. Any unknown provider, unsupported architecture, or provider
//! without a safe managed artifact (e.g. Nmap) returns `None` and fails closed.
//!
//! Digests were taken from the upstream projects' signed release `checksums.txt`
//! for the pinned versions below.

/// macOS CPU architecture of a managed artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    /// Apple Silicon (`aarch64` / `arm64`).
    Arm64,
    /// Intel (`x86_64` / `amd64`).
    X86_64,
}

impl Arch {
    /// The architecture MACSPLOIT is currently running as, or `None` for an
    /// architecture we do not ship managed artifacts for (fail closed — never
    /// guess an asset for an unknown architecture).
    pub fn host() -> Option<Self> {
        match std::env::consts::ARCH {
            "aarch64" => Some(Arch::Arm64),
            "x86_64" => Some(Arch::X86_64),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Arch::Arm64 => "arm64",
            Arch::X86_64 => "x86_64",
        }
    }
}

/// On-disk archive format of a managed artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveFormat {
    /// A `.zip` archive (ProjectDiscovery tools).
    Zip,
    /// A gzip-compressed tar (`.tar.gz`) archive (ffuf).
    TarGz,
}

/// One reviewed, pinned, verifiable upstream artifact.
#[derive(Debug, Clone)]
pub struct ManagedArtifact {
    pub provider_id: String,
    pub version: String,
    pub arch: Arch,
    /// Full HTTPS URL of the reviewed release asset (initial request).
    pub url: String,
    /// Expected lowercase hex SHA-256 of the downloaded archive.
    pub sha256: String,
    pub archive: ArchiveFormat,
    /// The exact top-level executable member expected inside the archive. Only a
    /// top-level regular file with this name is extracted; anything else fails.
    pub member: String,
    /// Filename the executable is installed as in the managed directory.
    pub installed_name: String,
    /// Hard ceiling on the compressed download size (reject larger).
    pub max_download_bytes: u64,
    /// Hard ceiling on the decompressed member size (zip-bomb guard).
    pub max_extracted_bytes: u64,
}

/// Official GitHub release-asset hosts a managed download is allowed to touch.
/// The initial request goes to `github.com`, which redirects to GitHub's
/// release-asset CDN. No other host is ever contacted, and every hop must be
/// HTTPS. This is the minimal set observed for the pinned assets.
pub const ALLOWED_HOSTS: &[&str] = &[
    "github.com",
    "release-assets.githubusercontent.com",
    "objects.githubusercontent.com",
];

/// Maximum number of redirects a managed download will follow.
pub const MAX_REDIRECTS: u32 = 5;

const MAX_DOWNLOAD_BYTES: u64 = 64 * 1024 * 1024; // generous headroom over ~10-20 MiB assets
const MAX_EXTRACTED_BYTES: u64 = 128 * 1024 * 1024;

fn pd_zip(provider: &str, version: &str, arch: Arch, sha256: &str) -> ManagedArtifact {
    // ProjectDiscovery naming: <tool>_<ver>_macOS_<amd64|arm64>.zip, binary at root.
    let asset_arch = match arch {
        Arch::Arm64 => "arm64",
        Arch::X86_64 => "amd64",
    };
    ManagedArtifact {
        provider_id: provider.to_owned(),
        version: version.to_owned(),
        arch,
        url: format!(
            "https://github.com/projectdiscovery/{provider}/releases/download/v{version}/{provider}_{version}_macOS_{asset_arch}.zip"
        ),
        sha256: sha256.to_owned(),
        archive: ArchiveFormat::Zip,
        member: provider.to_owned(),
        installed_name: provider.to_owned(),
        max_download_bytes: MAX_DOWNLOAD_BYTES,
        max_extracted_bytes: MAX_EXTRACTED_BYTES,
    }
}

/// Resolve the reviewed artifact for a provider on a given architecture. Returns
/// `None` for anything outside the pinned, reviewed set (fail closed).
pub fn artifact(provider_id: &str, arch: Arch) -> Option<ManagedArtifact> {
    Some(match (provider_id, arch) {
        // --- ProjectDiscovery Subfinder v2.16.0 ---
        ("subfinder", Arch::Arm64) => pd_zip(
            "subfinder",
            "2.16.0",
            arch,
            "af55827c9e6cdc530cca377ad459214ead16daf1b79d90e3dcefa387f644e057",
        ),
        ("subfinder", Arch::X86_64) => pd_zip(
            "subfinder",
            "2.16.0",
            arch,
            "8300c4d98f75596b7e8460ba6f3322dfeda4674bc2bcbde14d61d098db260b50",
        ),
        // --- ProjectDiscovery HTTPX v1.12.0 ---
        ("httpx", Arch::Arm64) => pd_zip(
            "httpx",
            "1.12.0",
            arch,
            "21d60328b383dba8a9fe249ac76b12edda4ec2e52a9cb21876c0a79123675569",
        ),
        ("httpx", Arch::X86_64) => pd_zip(
            "httpx",
            "1.12.0",
            arch,
            "16760b5e2122b66f57b9fbdb59f564b1181507c093d6a36066f40e5de38e8fa9",
        ),
        // --- ProjectDiscovery Katana v1.8.0 ---
        ("katana", Arch::Arm64) => pd_zip(
            "katana",
            "1.8.0",
            arch,
            "52e9802e9f83012a089fe57fb1ac476b936f181ac033c71bfa55f913c07cede6",
        ),
        ("katana", Arch::X86_64) => pd_zip(
            "katana",
            "1.8.0",
            arch,
            "806256316dd45e0fe0e3985fd7283ddffc376c95cbaa3dcfd14cde6e1de61aaf",
        ),
        // --- ffuf v2.3.0 (tar.gz, binary at root) ---
        ("ffuf", Arch::Arm64) => ManagedArtifact {
            provider_id: "ffuf".into(),
            version: "2.3.0".into(),
            arch,
            url: "https://github.com/ffuf/ffuf/releases/download/v2.3.0/ffuf_2.3.0_macOS_arm64.tar.gz".into(),
            sha256: "891e6358f7c72c951ce6fcef82a3736e91b34034e95edbd305505c9d31cfff13".into(),
            archive: ArchiveFormat::TarGz,
            member: "ffuf".into(),
            installed_name: "ffuf".into(),
            max_download_bytes: MAX_DOWNLOAD_BYTES,
            max_extracted_bytes: MAX_EXTRACTED_BYTES,
        },
        ("ffuf", Arch::X86_64) => ManagedArtifact {
            provider_id: "ffuf".into(),
            version: "2.3.0".into(),
            arch,
            url: "https://github.com/ffuf/ffuf/releases/download/v2.3.0/ffuf_2.3.0_macOS_amd64.tar.gz".into(),
            sha256: "c1d1a0320b299d2c7f3a62163b336fe861954ea865bab13b9e80f128eb985997".into(),
            archive: ArchiveFormat::TarGz,
            member: "ffuf".into(),
            installed_name: "ffuf".into(),
            max_download_bytes: MAX_DOWNLOAD_BYTES,
            max_extracted_bytes: MAX_EXTRACTED_BYTES,
        },
        // Nmap and everything else: no reviewed managed artifact — fail closed.
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_supported_provider_resolves_for_both_arches() {
        for id in ["subfinder", "httpx", "katana", "ffuf"] {
            for arch in [Arch::Arm64, Arch::X86_64] {
                let a = artifact(id, arch).unwrap_or_else(|| panic!("{id}/{arch:?}"));
                assert_eq!(a.provider_id, id);
                assert!(a.url.starts_with("https://"));
                assert_eq!(a.sha256.len(), 64);
                assert!(a.sha256.chars().all(|c| c.is_ascii_hexdigit()));
                assert_eq!(a.member, id);
            }
        }
    }

    #[test]
    fn nmap_and_unknown_have_no_managed_artifact() {
        assert!(artifact("nmap", Arch::Arm64).is_none());
        assert!(artifact("nmap", Arch::X86_64).is_none());
        assert!(artifact("totally-unknown", Arch::Arm64).is_none());
    }

    #[test]
    fn projectdiscovery_urls_match_pinned_version_and_arch() {
        let a = artifact("subfinder", Arch::Arm64).unwrap();
        assert_eq!(
            a.url,
            "https://github.com/projectdiscovery/subfinder/releases/download/v2.16.0/subfinder_2.16.0_macOS_arm64.zip"
        );
        assert_eq!(a.archive, ArchiveFormat::Zip);
        let f = artifact("ffuf", Arch::X86_64).unwrap();
        assert_eq!(f.archive, ArchiveFormat::TarGz);
        assert!(f.url.ends_with("ffuf_2.3.0_macOS_amd64.tar.gz"));
    }
}
