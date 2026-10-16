import Foundation

/// The dedicated OSINT workflows. Each maps to a typed core chain and capability; the
/// core re-validates the subject, provider compatibility, and risk class.
public enum OSINTMode: String, CaseIterable, Identifiable, Sendable {
    case username = "Username OSINT"
    case email = "Email OSINT"
    case phone = "Phone OSINT"
    case domain = "Domain OSINT"

    public var id: String { rawValue }
    /// The `start_chain` chain kind.
    public var chainKind: String {
        switch self {
        case .username: return "username_osint"
        case .email: return "email_osint"
        case .phone: return "phone_osint"
        case .domain: return "domain_osint"
        }
    }
    /// The provider capability this workflow requires.
    public var capability: String {
        switch self {
        case .username: return "USERNAME_OSINT"
        case .email: return "EMAIL_OSINT"
        case .phone: return "PHONE_OSINT"
        case .domain: return "DOMAIN_OSINT"
        }
    }
    /// The only target type this workflow accepts.
    public var targetType: String {
        switch self {
        case .username: return "Username"
        case .email: return "EmailAddress"
        case .phone: return "PhoneNumber"
        case .domain: return "Domain"
        }
    }
    public var icon: String {
        switch self {
        case .username: return "person.text.rectangle"
        case .email: return "envelope.badge"
        case .phone: return "phone"
        case .domain: return "globe"
        }
    }
    /// Risk label shown for the workflow (the core enforces the provider's class).
    public var riskLabel: String {
        switch self {
        case .username, .email: return "ACTIVE · LOW"
        case .phone, .domain: return "PASSIVE"
        }
    }
    /// Whether results are platform accounts (username/email) rather than facts.
    public var reportsAccounts: Bool { self == .username || self == .email }
    public var purpose: String {
        switch self {
        case .username: return "Check public platforms for one explicitly selected @username."
        case .email: return "Check public platforms for registrations of one explicitly selected email address."
        case .phone: return "Public numbering metadata (format, country, carrier, number range) for one explicitly selected international number."
        case .domain: return "Passive public records for one explicitly selected in-scope domain: registration (RDAP), certificate transparency, and public passive sources."
        }
    }
    public var targetHint: String {
        switch self {
        case .username: return "Add a username target such as @handle using the target bar above."
        case .email: return "Add an email target such as name@example.test using the target bar above."
        case .phone: return "Add a phone target in international format such as +1 202 555 0143 (MACSPLOIT never guesses the country)."
        case .domain: return "Add an in-scope domain target such as example.test using the target bar above."
        }
    }
    /// What the workflow contacts and what it never does.
    public var activityNote: String {
        switch self {
        case .username, .email:
            return "Sends ordinary requests to third-party public platforms — never to the subject's own systems — so workspace host scope does not apply to an identifier. Modules that can notify the subject, recursive cross-scanning, breach/infostealer lookups, and proxies are disabled. Runs are bounded (concurrency, request timeout, 15-minute limit) and cancellable."
        case .phone:
            return "Uses offline numbering data plus OVH's public number-range lookup. No calls, SMS, OTP, account recovery, API-key services, or search-engine dorks; one number, one bounded run, no pivots."
        case .domain:
            return "Queries public registries (RDAP), certificate-transparency logs, and key-less public passive sources — never the domain or the hosts found. The domain must be in workspace scope. Names found are passive or historical claims; MACSPLOIT never resolves, probes, or brute-forces them."
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

/// Typed `subject_kind` of an OSINT run summary. The core writes SCREAMING_SNAKE_CASE
/// (`USERNAME`, `EMAIL`, `PHONE`, `DOMAIN`); parsing is case-insensitive so the
/// presentation contract cannot silently break on casing.
public enum OSINTSubjectKind: String, Sendable {
    case username = "USERNAME", email = "EMAIL", phone = "PHONE", domain = "DOMAIN"

    public init?(wire: String) { self.init(rawValue: wire.uppercased()) }

    /// The workflow that produces this subject kind.
    public var mode: OSINTMode {
        switch self {
        case .username: return .username
        case .email: return .email
        case .phone: return .phone
        case .domain: return .domain
        }
    }
}

/// Which results surface a run uses. Decided from durable state only (the summary's
/// typed subject kind, else the chain name) — never from live-console text.
public enum OSINTResultsPresentation: Equatable, Sendable {
    case accounts, phoneFacts, domain

    init(mode: OSINTMode) {
        switch mode {
        case .username, .email: self = .accounts
        case .phone: self = .phoneFacts
        case .domain: self = .domain
        }
    }
}

/// Facts one source reported for a phone number (e.g. PhoneInfoga's `local` or `ovh`).
public struct OSINTSourceFacts: Identifiable, Equatable, Sendable {
    public let source: String
    public let facts: [OSINTProfileField]
    public var id: String { source }
}

/// Human label for a snake_case fact key (`country_code` → `Country code`).
public func osintFactLabel(_ key: String) -> String {
    let words = key.split(separator: "_").map(String.init)
    guard let first = words.first else { return key }
    let acronyms: Set<String> = ["e164", "ip", "url", "dns", "asn", "iana"]
    return words.enumerated().map { index, word in
        if acronyms.contains(word.lowercased()) { return word.uppercased() }
        return index == 0 ? first.prefix(1).uppercased() + first.dropFirst() : word
    }.joined(separator: " ")
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
    /// Domain OSINT counts (zero for other workflows).
    public let hosts: Int, emails: Int, ips: Int, nameservers: Int
    public let droppedOutOfDomain: Int, droppedInvalid: Int, droppedOverLimit: Int
    /// True when every claim in the run is historical (certificate transparency).
    public let historical: Bool
    /// Bounded run-level facts: phone numbering facts per source, or domain
    /// registration facts (RDAP). Contact details are never present.
    public let details: [OSINTProfileField]
    /// Typed subject kind (nil only for a value this client does not know).
    public let kind: OSINTSubjectKind?
    /// Phone: facts grouped by the source that reported them (empty values omitted).
    public let sourceFacts: [OSINTSourceFacts]

    public init?(_ value: JSONValue) {
        guard value["kind"].string == "osint_run_summary" else { return nil }
        func count(_ key: String) -> Int { value[key].int ?? 0 }
        func notes(_ key: String) -> [OSINTCheckNote] {
            value[key].array.enumerated().map { index, item in
                OSINTCheckNote(id: index, platform: item["platform"].string ?? item["source"].string ?? "Unknown platform",
                               category: item["category"].string, upstreamStatus: item["upstream_status"].string ?? "",
                               reason: item["reason"].string)
            }
        }
        let counts = value["counts"]
        provider = value["provider"].string ?? ""
        subject = value["subject"].string ?? ""
        subjectKind = value["subject_kind"].string ?? ""
        kind = OSINTSubjectKind(wire: subjectKind)
        sourceFacts = value["sources"].object.sorted(by: { $0.key < $1.key }).compactMap { source, facts in
            let fields = facts.object.sorted(by: { $0.key < $1.key }).compactMap { key, value in
                OSINTProfileField.text(value).map { OSINTProfileField(key: key, value: $0) }
            }
            return fields.isEmpty ? nil : OSINTSourceFacts(source: source, facts: Array(fields.prefix(24)))
        }
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
        identityNote = value["identity_note"].string ?? value["note"].string ?? ""
        hosts = counts["hosts"].int ?? 0
        emails = counts["emails"].int ?? 0
        ips = counts["ips"].int ?? 0
        nameservers = counts["nameservers"].int ?? 0
        droppedOutOfDomain = counts["dropped_out_of_domain"].int ?? 0
        droppedInvalid = counts["dropped_invalid"].int ?? 0
        droppedOverLimit = counts["dropped_over_limit"].int ?? 0
        historical = value["historical"].bool ?? false
        var details: [OSINTProfileField] = []
        for (source, facts) in value["sources"].object.sorted(by: { $0.key < $1.key }) {
            details += OSINTProfileField.flatten(source, facts)
        }
        details += OSINTProfileField.flatten("registration", value["registration"])
        self.details = Array(details.prefix(80))
    }
}

/// One bounded public profile field reported by a provider.
public struct OSINTProfileField: Identifiable, Equatable, Sendable {
    public let key: String, value: String
    public var id: String { key }

    /// Display text for a scalar (or a list of scalars); nil for nested objects.
    static func text(_ value: JSONValue) -> String? {
        switch value {
        case .string(let v): return v.isEmpty ? nil : v
        case .number(let v): return (v.rounded() == v && abs(v) < 1e15) ? String(Int(v)) : String(v)
        case .bool(let v): return v ? "true" : "false"
        case .array(let items):
            let parts = items.compactMap(text)
            return parts.isEmpty ? nil : parts.joined(separator: ", ")
        default: return nil
        }
    }

    /// Flatten one level of nested facts into `prefix.key` fields (objects one level
    /// deeper become `prefix.key.sub`). Bounded by the caller.
    static func flatten(_ prefix: String, _ value: JSONValue) -> [OSINTProfileField] {
        if let scalar = text(value) { return [OSINTProfileField(key: prefix, value: scalar)] }
        var fields: [OSINTProfileField] = []
        for (key, item) in value.object.sorted(by: { $0.key < $1.key }) {
            if let scalar = text(item) {
                fields.append(OSINTProfileField(key: "\(prefix).\(key)", value: scalar))
            } else {
                for (sub, inner) in item.object.sorted(by: { $0.key < $1.key }) {
                    if let scalar = text(inner) {
                        fields.append(OSINTProfileField(key: "\(prefix).\(key).\(sub)", value: scalar))
                    }
                }
                for (index, entry) in item.array.enumerated() {
                    let parts = entry.object.sorted(by: { $0.key < $1.key }).compactMap { text($0.value) }
                    if !parts.isEmpty {
                        fields.append(OSINTProfileField(key: "\(prefix).\(key)[\(index)]", value: parts.joined(separator: " · ")))
                    }
                }
            }
        }
        return fields
    }
}

/// One passive Domain-OSINT observation (host, email, IP, or nameserver) from one
/// run. A public-source claim: never resolved, probed, or contacted by MACSPLOIT.
public struct OSINTDomainResult: Identifiable, Equatable, Sendable {
    public let id: String
    public let assetId: String, assetType: String, value: String
    public let provider: String, confidence: String
    public let historical: Bool
    public let inScope: Bool?
    public let facts: [OSINTProfileField]
    /// Other providers (outside this run) that observed the same canonical asset —
    /// e.g. a Subfinder recon run — shown so existing data is reused, not re-collected.
    public let alsoObservedBy: [String]
    public let evidenceId: String?, providerRunId: String?

    init?(_ observation: Observation, asset: Asset?, others: [Observation]) {
        guard let meta = observation.metadata, meta["kind"].string == "osint_domain_observation" else { return nil }
        id = observation.id
        assetId = observation.assetId
        assetType = asset?.assetType ?? ""
        value = asset?.canonicalIdentity ?? observation.observedValue
        provider = meta["provider"].string ?? observation.discoveredBy
        confidence = observation.confidence
        historical = meta["historical"].bool ?? false
        inScope = asset?.metadata["in_scope"].bool
        facts = Array(OSINTProfileField.flatten("facts", meta["facts"]).map {
            OSINTProfileField(key: String($0.key.dropFirst("facts.".count)), value: $0.value)
        }.prefix(16))
        alsoObservedBy = Array(Set(others.map(\.discoveredBy))).sorted()
        evidenceId = observation.evidenceId
        providerRunId = observation.providerRunId
    }
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

    /// Completion copy appropriate to the workflow (platform-check wording is only
    /// used for Username/Email).
    public func detail(for mode: OSINTMode?) -> String {
        switch (mode, self) {
        case (.phone?, .completed): return "The phone intelligence lookup completed. Reported numbering facts are shown below."
        case (.phone?, .partial):
            return "The phone intelligence lookup completed, but a source errored or returned lines MACSPLOIT could not parse. Facts that were reported are shown below."
        case (.domain?, .completed): return "The passive domain intelligence lookup completed. Observations are shown below."
        case (.domain?, .partial):
            return "The passive domain intelligence lookup completed, but some records were malformed, outside the domain, or over a safety bound. Observations that were kept are shown below."
        case (.phone?, .running), (.domain?, .running):
            return "The lookup is running. Cancel stops it; anything already captured is kept as evidence."
        case (.phone?, .cancelled), (.domain?, .cancelled):
            return "The lookup was stopped before results were parsed; captured output is preserved as evidence."
        default: return detail
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
    /// Domain-OSINT hosts, emails, IPs, and nameservers (empty for other workflows).
    public let domainResults: [OSINTDomainResult]
    /// The workflow this run belongs to (typed summary first, then the chain name).
    public var mode: OSINTMode? { summary?.kind?.mode ?? OSINTMode(rawValue: chain.name) }
    /// Which results surface to render.
    public var presentation: OSINTResultsPresentation { mode.map(OSINTResultsPresentation.init) ?? .accounts }
    /// Workflow-aware state copy.
    public var stateDetail: String { state.detail(for: mode) }
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
        let assets = Dictionary(snapshot.assets.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        let outside = Dictionary(grouping: snapshot.observations.filter { observation in
            !(observation.providerRunId.map { runIds.contains($0) } ?? false)
        }, by: \.assetId)
        domainResults = observations.compactMap {
            OSINTDomainResult($0, asset: assets[$0.assetId], others: outside[$0.assetId] ?? [])
        }.sorted { ($0.assetType, $0.value, $0.id) < ($1.assetType, $1.value, $1.id) }
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
