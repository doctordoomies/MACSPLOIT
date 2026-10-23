import Foundation

// Integrated Linux terminal foundation (Issue #90, parent #27).
//
// MACSPLOIT's structured, scope-aware provider workflows remain the preferred path. This
// is a deliberate power-user *escape hatch*: an optional, explicitly started managed Linux
// (Kali ARM64) environment whose shell the user drives directly. It is a separate trust
// boundary — commands typed here are NOT core-authorized provider actions, are never
// scope-checked, and their output is never auto-imported into Assets/Evidence/Findings.
//
// Everything here is the durable foundation: a typed lifecycle, a verified-image manifest,
// a security-preserving downloader interface, persistent storage separate from workspace
// data, and a virtualization backend behind a protocol (a real Virtualization.framework
// adapter plus an offline fake for tests). Nothing starts a VM until the user explicitly
// does so, and nothing is downloaded until the user approves a setup plan.

/// The typed lifecycle of the managed Linux environment. State is never inferred from ad
/// hoc UI booleans; transient states (setting up / starting / running / stopping) are not
/// persisted — only a configured environment's on-disk metadata is, so a relaunch always
/// resolves to a non-running state.
public enum LinuxEnvironmentState: String, Codable, Sendable, Equatable {
    /// The host cannot run the managed VM (not Apple Silicon, or macOS < 13). Fail-closed:
    /// no setup, no fake VM.
    case unsupported = "UNSUPPORTED"
    case notConfigured = "NOT_CONFIGURED"
    case settingUp = "SETTING_UP"
    case installReady = "INSTALL_READY"
    case installing = "INSTALLING"
    case stopped = "STOPPED"
    case starting = "STARTING"
    case running = "RUNNING"
    case stopping = "STOPPING"
    case failed = "FAILED"

    /// A VM may only be started from a fully configured, stopped environment.
    public var canStart: Bool { self == .stopped }
    /// Stop is offered only while the VM is live.
    public var canStop: Bool { self == .running || self == .installing || self == .starting }
    /// The environment exists on disk (configured), regardless of run state.
    public var isConfigured: Bool {
        switch self {
        case .unsupported, .notConfigured, .settingUp: return false
        case .installReady, .installing, .stopped, .starting, .running, .stopping, .failed: return true
        }
    }
}

/// Downloaded media is an installer, never the writable installed root disk.
public enum LinuxImageFormat: String, Codable, Sendable, Equatable {
    case installerISO = "INSTALLER_ISO"
}

public enum LinuxBootMode: String, Sendable, Equatable { case installation, installed }
public enum LinuxInstallationStatus: String, Codable, Sendable { case awaitingOwnerConfirmation, installed }

public enum LinuxImageError: Error, Equatable {
    case insecureURL(String)
    case badChecksum
    case oversized
    case missingArtifact(String)
    case unsupportedSchema(Int)
}

/// A reviewed, pinned description of the guest image MACSPLOIT will download and verify.
/// Mirrors the core installer's manifest discipline (HTTPS-only, pinned SHA-256, bounded
/// size) rather than trusting an ad hoc URL. The production catalog pins official versioned Kali installer media; tests use offline fixtures.
public struct LinuxImageManifest: Codable, Sendable, Equatable {
    public static let supportedSchema = 2
    /// Largest guest artifact MACSPLOIT will download (defense in depth over a real ~2-8 GiB image).
    public static let maxArtifactBytes: UInt64 = 12 * 1024 * 1024 * 1024

    public var schemaVersion: Int
    public var identifier: String
    public var displayName: String
    public var release: String
    public var architecture: String
    public var provenanceURL: String
    public var format: LinuxImageFormat
    /// The installer ISO, its exact pinned SHA-256, and expected byte count.
    /// The writable sparse root disk is always created locally.
    public var installerURL: String
    public var sha256: String
    public var downloadByteCount: UInt64
    /// Hosts a redirect may land on, in addition to the installer URL's own host. Redirects to
    /// any other host are refused — redirect targets are not an open set.
    public var redirectAllowedHosts: [String]

    public init(schemaVersion: Int = LinuxImageManifest.supportedSchema, identifier: String,
                displayName: String, release: String = "fixture", architecture: String = "arm64",
                provenanceURL: String = "", format: LinuxImageFormat = .installerISO, installerURL: String,
                sha256: String, downloadByteCount: UInt64, redirectAllowedHosts: [String] = []) {
        self.schemaVersion = schemaVersion; self.identifier = identifier; self.displayName = displayName
        self.release = release; self.architecture = architecture; self.provenanceURL = provenanceURL
        self.format = format; self.installerURL = installerURL; self.sha256 = sha256
        self.downloadByteCount = downloadByteCount; self.redirectAllowedHosts = redirectAllowedHosts
    }

    /// The reviewed set of hosts a redirect may reach: the installer URL's host plus any
    /// explicitly allow-listed hosts.
    public var allowedRedirectHosts: Set<String> {
        var hosts = Set(redirectAllowedHosts)
        if let host = URLComponents(string: installerURL)?.host { hosts.insert(host) }
        return hosts
    }

    /// A syntactically valid, policy-conforming manifest. A valid manifest does not prove
    /// the artifact is present or trustworthy — it only enforces the security envelope
    /// (HTTPS, a pinned 64-hex SHA-256, and a positive, bounded size).
    public func validate() throws {
        guard schemaVersion == Self.supportedSchema else { throw LinuxImageError.unsupportedSchema(schemaVersion) }
        guard let parsed = URLComponents(string: installerURL), parsed.scheme?.lowercased() == "https",
              !(parsed.host ?? "").isEmpty, parsed.user == nil, parsed.password == nil else {
            throw LinuxImageError.insecureURL(installerURL)
        }
        guard architecture == "arm64", !release.isEmpty, format == .installerISO else {
            throw LinuxImageError.missingArtifact("Expected ARM64 installer ISO metadata.")
        }
        guard redirectAllowedHosts.allSatisfy({ host in
            !host.isEmpty && host == host.lowercased() && !host.contains("*") &&
            URLComponents(string: "https://" + host)?.host == host && !host.contains(":") && !host.contains("/")
        }) else { throw LinuxImageError.insecureURL("Invalid redirect allow-list.") }
        let digest = sha256.lowercased()
        guard digest.count == 64, digest.allSatisfy({ $0.isHexDigit }) else { throw LinuxImageError.badChecksum }
        guard downloadByteCount > 0, downloadByteCount <= Self.maxArtifactBytes else { throw LinuxImageError.oversized }
    }
}

/// Persisted metadata for a configured environment. Only this is written to disk; the run
/// state is always recomputed on launch so MACSPLOIT never auto-starts a VM.
public struct LinuxEnvironmentConfig: Codable, Sendable, Equatable {
    public static let supportedSchema = 2
    public var schemaVersion: Int
    public var image: LinuxImageManifest
    public var cpuCount: Int
    public var memoryBytes: UInt64
    public var diskSizeBytes: UInt64
    public var createdAt: String
    public var installationStatus: LinuxInstallationStatus = .awaitingOwnerConfirmation
    public var machineIdentifierSHA256: String = ""
    public var efiStoreByteCount: UInt64 = 0

    public init(image: LinuxImageManifest, resources: LinuxResources, createdAt: String = LinuxEnvironment.now()) {
        self.schemaVersion = Self.supportedSchema
        self.image = image
        self.cpuCount = resources.cpuCount
        self.memoryBytes = resources.memoryBytes
        self.diskSizeBytes = resources.diskSizeBytes
        self.createdAt = createdAt
    }

    public var resources: LinuxResources {
        LinuxResources(cpuCount: cpuCount, memoryBytes: memoryBytes, diskSizeBytes: diskSizeBytes)
    }
}

/// Host-resource allocation for the guest, always clamped to sane bounds so the VM can
/// never be configured to starve the host.
public struct LinuxResources: Codable, Sendable, Equatable {
    public var cpuCount: Int
    public var memoryBytes: UInt64
    public var diskSizeBytes: UInt64

    public init(cpuCount: Int, memoryBytes: UInt64, diskSizeBytes: UInt64) {
        self.cpuCount = cpuCount
        self.memoryBytes = memoryBytes
        self.diskSizeBytes = diskSizeBytes
    }

    /// Clamp each field into the supported range for `host` resources.
    public func clamped(to host: LinuxHostResources = .current) -> LinuxResources {
        LinuxResources(
            cpuCount: min(max(cpuCount, 1), host.maxCPU),
            memoryBytes: min(max(memoryBytes, LinuxEnvironmentLimits.minMemoryBytes), host.maxMemoryBytes),
            diskSizeBytes: min(max(diskSizeBytes, LinuxEnvironmentLimits.minDiskBytes), LinuxEnvironmentLimits.maxDiskBytes)
        )
    }

    /// Safe defaults for `host`: about half the cores (capped) and a quarter of RAM (capped),
    /// leaving the host responsive.
    public static func defaults(for host: LinuxHostResources = .current) -> LinuxResources {
        let cpu = min(max(host.cpuCount / 2, 1), host.maxCPU)
        let memory = min(max(host.memoryBytes / 4, LinuxEnvironmentLimits.minMemoryBytes), host.maxMemoryBytes)
        return LinuxResources(cpuCount: cpu, memoryBytes: memory, diskSizeBytes: LinuxEnvironmentLimits.defaultDiskBytes)
    }
}

/// A snapshot of host resources, injectable so bounds/defaults are deterministic in tests.
public struct LinuxHostResources: Sendable, Equatable {
    public var cpuCount: Int
    public var memoryBytes: UInt64
    public init(cpuCount: Int, memoryBytes: UInt64) { self.cpuCount = cpuCount; self.memoryBytes = memoryBytes }

    /// Never hand the guest every core/byte: cap CPUs and leave the host several GiB of RAM.
    public var maxCPU: Int { max(1, cpuCount - 1) }
    public var maxMemoryBytes: UInt64 {
        let reserve: UInt64 = 4 * 1024 * 1024 * 1024
        return memoryBytes > reserve + LinuxEnvironmentLimits.minMemoryBytes ? memoryBytes - reserve : LinuxEnvironmentLimits.minMemoryBytes
    }

    public static let current = LinuxHostResources(
        cpuCount: ProcessInfo.processInfo.activeProcessorCount,
        memoryBytes: ProcessInfo.processInfo.physicalMemory
    )
}

public enum LinuxEnvironmentLimits {
    public static let minMemoryBytes: UInt64 = 2 * 1024 * 1024 * 1024
    public static let minDiskBytes: UInt64 = 8 * 1024 * 1024 * 1024
    public static let defaultDiskBytes: UInt64 = 32 * 1024 * 1024 * 1024
    public static let maxDiskBytes: UInt64 = 128 * 1024 * 1024 * 1024
    /// At most this many interactive terminal tabs share the single running VM.
    public static let maxSessions = 8
}

/// Filesystem layout for the managed environment, rooted OUTSIDE workspace storage and the
/// `Providers/` directory so removing the terminal never touches workspaces, Assets,
/// Evidence, Findings, provider installs, or unrelated settings, and the environment
/// survives replacing MACSPLOIT.app.
public struct LinuxEnvironmentPaths: Sendable {
    public let root: URL
    public init(root: URL) { self.root = root }

    /// `<Application Support>/MACSPLOIT/Virtual Machines/Linux/`.
    public static func standard(applicationSupport: URL) -> LinuxEnvironmentPaths {
        LinuxEnvironmentPaths(root: applicationSupport
            .appendingPathComponent("Virtual Machines", isDirectory: true)
            .appendingPathComponent("Linux", isDirectory: true))
    }

    public var configFile: URL { root.appendingPathComponent("environment.json") }
    public var diskImage: URL { root.appendingPathComponent("root.img") }
    public var installerISO: URL { root.appendingPathComponent("installer.iso") }
    public var machineIdentifier: URL { root.appendingPathComponent("machine-identifier") }
    public var auxStorage: URL { root.appendingPathComponent("efi-vars.img") }
    /// Download staging, finalized atomically only after prepare+persist succeed; safe to
    /// wipe on cancel/failure without touching an existing finalized disk.
    public var staging: URL { root.appendingPathComponent("staging", isDirectory: true) }
    /// Verified installer media waits here until setup commits it to `installerISO`.
    public var stagedInstaller: URL { staging.appendingPathComponent("installer.iso") }
}

public enum LinuxEnvironment {
    public static func now() -> String {
        let formatter = ISO8601DateFormatter()
        return formatter.string(from: Date())
    }
}

/// Reviewed official versioned installer. No mutable `current` URL and no custom root image.
/// SHA256SUMS.gpg was checked against Kali's 2025 archive signing key:
/// 827C8569F2518CC677FECA1AED65462EC8D5E4C5. Runtime uses the pinned SHA-256, not GPG.
public enum LinuxImageCatalog {
    public static var availableManifest: LinuxImageManifest? {
        LinuxImageManifest(
            identifier: "kali-2026.3-installer-arm64", displayName: "Kali Linux 2026.3 ARM64 Installer",
            release: "2026.3", provenanceURL: "https://cdimage.kali.org/kali-2026.3/SHA256SUMS",
            installerURL: "https://cdimage.kali.org/kali-2026.3/kali-linux-2026.3-installer-arm64.iso",
            sha256: "c4a7f9bf3a0ff07c8263fe9e9b0edba0cc3d9b408f1d8f06c066df0afce23072",
            downloadByteCount: 4_051_513_344,
            // Reviewed official destinations advertised by cdimage's release redirector.
            // Other mirrors fail closed until separately reviewed; no wildcard domains.
            redirectAllowedHosts: ["kali.download", "us.mirror.ionos.com", "volico.mm.fcix.net",
                                   "mirror.xenyth.net", "ohioix.mm.fcix.net", "nocix.mm.fcix.net",
                                   "mirror.us.cdn-perfprod.com", "mirror.quantum5.ca", "southfront.mm.fcix.net"])
    }
}
