import Foundation

/// The dedicated OSINT workflows. Each maps to a typed core chain and capability; the
/// core re-validates the subject, provider compatibility, and risk class.
public enum OSINTMode: String, CaseIterable, Identifiable, Sendable {
    case username = "Username OSINT"
    case email = "Email OSINT"

    public var id: String { rawValue }
    /// The `start_chain` chain kind.
    public var chainKind: String { self == .username ? "username_osint" : "email_osint" }
    /// The provider capability this workflow requires.
    public var capability: String { self == .username ? "USERNAME_OSINT" : "EMAIL_OSINT" }
    /// The only target type this workflow accepts.
    public var targetType: String { self == .username ? "Username" : "EmailAddress" }
    public var icon: String { self == .username ? "person.text.rectangle" : "envelope.badge" }
    public var purpose: String {
        switch self {
        case .username: return "Check public platforms for one explicitly selected @username."
        case .email: return "Check public platforms for registrations of one explicitly selected email address."
        }
    }
    public var targetHint: String {
        switch self {
        case .username: return "Add a username target such as @handle using the target bar above."
        case .email: return "Add an email target such as name@example.test using the target bar above."
        }
    }

    /// The workflow that accepts a target type, if any.
    public static func mode(forTargetType type: String) -> OSINTMode? {
        allCases.first { $0.targetType == type }
    }

    /// Workspace targets this workflow can run on.
    public func compatibleTargets(_ targets: [Target]) -> [Target] {
        targets.filter { $0.targetType == targetType }
    }

    /// Registered providers that advertise this workflow's capability and target type.
    /// Availability is reported separately so a missing provider stays visible.
    public func compatibleProviders(_ providers: [ProviderStatus]) -> [ProviderStatus] {
        providers.filter { $0.capabilities.contains(capability) && $0.supportedTargetTypes.contains(targetType) }
    }

    /// The chain names the core gives OSINT runs (used to list OSINT history).
    public static let chainNames: Set<String> = Set(allCases.map(\.rawValue))
}

/// Provider-neutral status of one platform check.
public enum OSINTCheckStatus: String, Sendable {
    case positive = "POSITIVE", negative = "NEGATIVE", blocked = "BLOCKED", error = "ERROR", unknown = "UNKNOWN"
}

/// A platform check listed in a run summary (errors, policy-blocked, unknown).
public struct OSINTCheckNote: Identifiable, Equatable, Sendable {
    public let id: Int
    public let platform: String, category: String?, upstreamStatus: String, reason: String?
}

/// Per-run summary recorded by the core on the subject's observation.
public struct OSINTRunSummary: Equatable, Sendable {
    public let provider: String, subject: String, subjectKind: String
    public let checked: Int, positive: Int, negative: Int, blocked: Int, error: Int, unknown: Int
    public let accounts: Int, duplicates: Int, urlsRejected: Int, dropped: Int, malformed: Int, mismatched: Int
    public let positiveOverLimit: Int
    public let partial: Bool
    public let errors: [OSINTCheckNote], blockedChecks: [OSINTCheckNote], unknownChecks: [OSINTCheckNote]
    public let identityNote: String

    public init?(_ value: JSONValue) {
        guard value["kind"].string == "osint_run_summary" else { return nil }
        func count(_ key: String) -> Int { value[key].int ?? 0 }
        func notes(_ key: String) -> [OSINTCheckNote] {
            value[key].array.enumerated().map { index, item in
                OSINTCheckNote(id: index, platform: item["platform"].string ?? "Unknown platform",
                               category: item["category"].string, upstreamStatus: item["upstream_status"].string ?? "",
                               reason: item["reason"].string)
            }
        }
        let counts = value["counts"]
        provider = value["provider"].string ?? ""
        subject = value["subject"].string ?? ""
        subjectKind = value["subject_kind"].string ?? ""
        checked = count("checked")
        positive = counts["positive"].int ?? 0
        negative = counts["negative"].int ?? 0
        blocked = counts["blocked"].int ?? 0
        error = counts["error"].int ?? 0
        unknown = counts["unknown"].int ?? 0
        accounts = count("accounts")
        duplicates = count("duplicates")
        urlsRejected = count("urls_rejected")
        dropped = count("records_dropped_over_limit")
        malformed = count("records_malformed")
        mismatched = count("records_mismatched_subject")
        positiveOverLimit = count("positive_over_limit")
        partial = value["partial"].bool ?? false
        errors = notes("errors")
        blockedChecks = notes("blocked")
        unknownChecks = notes("unknown")
        identityNote = value["identity_note"].string ?? ""
    }
}

/// One bounded public profile field reported by a provider.
public struct OSINTProfileField: Identifiable, Equatable, Sendable {
    public let key: String, value: String
    public var id: String { key }
}

/// One reported account from one run. URLs are untrusted provider output: they are
/// displayed and copyable, never opened or acted on automatically.
public struct OSINTAccountResult: Identifiable, Equatable, Sendable {
    public let id: String
    public let assetId: String, platform: String, category: String?
    public let upstreamStatus: String, confidence: String, upstreamConfidence: String?
    public let profileURL: String?
    public let profile: [OSINTProfileField]
    public let evidenceId: String?, providerRunId: String?, timestamp: String

    init?(_ observation: Observation) {
        guard let meta = observation.metadata, meta["kind"].string == "osint_account" else { return nil }
        id = observation.id
        assetId = observation.assetId
        platform = meta["platform"].string ?? observation.observedValue
        category = meta["category"].string
        upstreamStatus = meta["upstream_status"].string ?? ""
        confidence = observation.confidence
        upstreamConfidence = meta["upstream_confidence"].string
        profileURL = meta["url"].string
        profile = meta["profile"].object
            .map { entry -> OSINTProfileField in
                let text: String
                switch entry.value {
                case .string(let v): text = v
                case .number(let v): text = (v.rounded() == v && abs(v) < 1e15) ? String(Int(v)) : String(v)
                case .bool(let v): text = v ? "true" : "false"
                default: text = ""
                }
                return OSINTProfileField(key: entry.key, value: text)
            }
            .filter { !$0.value.isEmpty }
            .sorted { $0.key < $1.key }
        evidenceId = observation.evidenceId
        providerRunId = observation.providerRunId
        timestamp = observation.timestamp
    }
}

/// User-facing state of one OSINT run, derived only from durable core state.
public enum OSINTRunState: Equatable, Sendable {
    case running, completed, partial, failed(String?), cancelled

    public init(chain: ChainRun) {
        switch chain.status {
        case "PENDING", "RUNNING": self = .running
        case "COMPLETED": self = .completed
        case "PARTIAL": self = .partial
        case "CANCELLED": self = .cancelled
        default: self = .failed(chain.errorCode)
        }
    }

    public var title: String {
        switch self {
        case .running: return "Running"
        case .completed: return "Completed"
        case .partial: return "Completed with partial results"
        case .failed(let code): return code.map { "Failed · \($0)" } ?? "Failed"
        case .cancelled: return "Cancelled"
        }
    }

    public var detail: String {
        switch self {
        case .running:
            return "The provider writes its structured report when the scan finishes. Cancel stops the scan; captured output is kept as evidence."
        case .completed: return "Every platform check returned a result."
        case .partial:
            return "Some platform checks errored, returned an unrecognized status, or were dropped by a safety bound. Discoveries that were reported are saved."
        case .failed:
            return "No discoveries were saved from this run. Its captured output and any report are preserved as evidence."
        case .cancelled:
            return "The scan was stopped. The provider only writes structured results at the end, so none were saved; captured output is preserved as evidence."
        }
    }
}

/// Everything the OSINT view shows for one run.
public struct OSINTRunResults: Equatable, Sendable {
    public let chain: ChainRun
    public let state: OSINTRunState
    public let providerRun: ProviderRun?
    public let stages: [ChainStage]
    public let summary: OSINTRunSummary?
    public let accounts: [OSINTAccountResult]
    public let evidence: [Evidence]

    public init?(snapshot: Snapshot, chainId: String) {
        guard let chain = snapshot.chains.first(where: { $0.id == chainId }) else { return nil }
        self.chain = chain
        state = OSINTRunState(chain: chain)
        let runs = snapshot.providerRuns.filter { $0.chainId == chainId }
        providerRun = runs.last
        stages = snapshot.stages.filter { $0.chainId == chainId }.sorted { $0.position < $1.position }
        let runIds = Set(runs.map(\.id))
        let observations = snapshot.observations.filter { $0.providerRunId.map { runIds.contains($0) } ?? false }
        summary = observations.lazy.compactMap { $0.metadata.flatMap(OSINTRunSummary.init) }.first
        accounts = observations.compactMap(OSINTAccountResult.init).sorted {
            ($0.platform.lowercased(), $0.id) < ($1.platform.lowercased(), $1.id)
        }
        evidence = snapshot.evidence.filter { runIds.contains($0.providerRunId) }
    }

    /// Results for a chain, or nil when it is not an OSINT run in this snapshot.
    public static func make(snapshot: Snapshot, chainId: String?) -> OSINTRunResults? {
        guard let chainId, let chain = snapshot.chains.first(where: { $0.id == chainId }),
              OSINTMode.chainNames.contains(chain.name) else { return nil }
        return OSINTRunResults(snapshot: snapshot, chainId: chain.id)
    }
}

public extension Snapshot {
    /// OSINT runs, newest first.
    var osintChains: [ChainRun] { chains.filter { OSINTMode.chainNames.contains($0.name) }.reversed() }
}
