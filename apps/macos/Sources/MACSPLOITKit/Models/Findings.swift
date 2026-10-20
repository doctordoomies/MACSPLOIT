import Foundation
import Combine

/// Impact dimension — independent of confidence and status.
public enum FindingSeverity: String, Codable, Sendable, CaseIterable, Identifiable, Comparable {
    case informational = "INFORMATIONAL", low = "LOW", medium = "MEDIUM", high = "HIGH", critical = "CRITICAL"
    public var id: String { rawValue }
    public var label: String { rawValue.capitalized }
    private var rank: Int { Self.allCases.firstIndex(of: self) ?? 0 }
    public static func < (a: Self, b: Self) -> Bool { a.rank < b.rank }
}

/// Analyst confidence the finding is real — independent of severity and status.
public enum FindingConfidence: String, Codable, Sendable, CaseIterable, Identifiable {
    case low = "LOW", medium = "MEDIUM", high = "HIGH", confirmed = "CONFIRMED"
    public var id: String { rawValue }
    public var label: String { rawValue.capitalized }
}

/// Security-testing lifecycle — independent of severity and confidence. Transitions are
/// validated by the Rust core; the UI only offers the ones the core will accept.
public enum FindingStatus: String, Codable, Sendable, CaseIterable, Identifiable {
    case draft = "DRAFT", open = "OPEN", confirmed = "CONFIRMED", informational = "INFORMATIONAL"
    case falsePositive = "FALSE_POSITIVE", resolved = "RESOLVED", retestPassed = "RETEST_PASSED"
    public var id: String { rawValue }
    public var label: String {
        switch self {
        case .draft: return "Draft"
        case .open: return "Open"
        case .confirmed: return "Confirmed"
        case .informational: return "Informational"
        case .falsePositive: return "False positive"
        case .resolved: return "Resolved"
        case .retestPassed: return "Retest passed"
        }
    }
    /// Statuses a finding may be created in (mirrors the core).
    public static let initialChoices: [FindingStatus] = [.draft, .open, .confirmed, .informational]
    /// Lifecycle transitions the core allows (kept in sync with `FindingStatus` in Rust).
    public var allowedTransitions: [FindingStatus] {
        switch self {
        case .draft: return [.open, .informational, .falsePositive]
        case .open: return [.confirmed, .informational, .falsePositive, .resolved]
        case .confirmed: return [.resolved, .falsePositive]
        case .informational: return [.open, .falsePositive]
        case .falsePositive: return [.open]
        case .resolved: return [.retestPassed, .open]
        case .retestPassed: return [.open]
        }
    }
}

/// One affected canonical asset link (at most one primary per finding).
public struct AffectedAsset: Codable, Sendable, Equatable, Identifiable {
    public let assetId: String
    public let isPrimary: Bool
    public var id: String { assetId }
}

/// One append-only history entry.
public struct FindingHistoryEntry: Codable, Sendable, Equatable, Identifiable {
    public let id: String
    public let kind: String
    public let fromValue: String?
    public let toValue: String?
    public let note: String
    public let actor: String
    public let timestamp: String
}

/// A durable analyst Finding: a reviewable security conclusion referencing durable
/// records. Severity/confidence/status are three independent dimensions.
public struct Finding: Codable, Sendable, Equatable, Identifiable {
    public let id: String
    public let workspaceId: String
    public let title: String
    public let severity: FindingSeverity
    public let confidence: FindingConfidence
    public let status: FindingStatus
    public let description: String
    public let reproduction: String
    public let remediation: String
    public let sourceProvider: String?
    public let sourceRunId: String?
    public let tags: [String]
    public let cweIds: [String]
    public let cveIds: [String]
    public let affectedAssets: [AffectedAsset]
    public let evidenceIds: [String]
    public let createdBy: String
    public let createdAt: String
    public let updatedAt: String
    public let history: [FindingHistoryEntry]

    public var primaryAssetId: String? {
        affectedAssets.first(where: \.isPrimary)?.assetId ?? affectedAssets.first?.assetId
    }
}

/// Analyst input to create a finding. Only factual references (asset/evidence/source) are
/// ever prefilled by "Create Finding from a result"; the analyst writes the conclusion.
public struct NewFinding: Codable, Sendable, Equatable {
    public var title: String = ""
    public var severity: FindingSeverity = .informational
    public var confidence: FindingConfidence = .low
    public var status: FindingStatus? = .open
    public var description: String = ""
    public var reproduction: String = ""
    public var remediation: String = ""
    public var tags: [String] = []
    public var cweIds: [String] = []
    public var cveIds: [String] = []
    public var primaryAssetId: String? = nil
    public var additionalAssetIds: [String] = []
    public var evidenceIds: [String] = []
    public var sourceProvider: String? = nil
    public var sourceRunId: String? = nil
    public init() {}
}

/// Analyst edits to a finding's own fields (never status or source attribution).
public struct FindingEdit: Codable, Sendable, Equatable {
    public var title: String? = nil
    public var severity: FindingSeverity? = nil
    public var confidence: FindingConfidence? = nil
    public var description: String? = nil
    public var reproduction: String? = nil
    public var remediation: String? = nil
    public var tags: [String]? = nil
    public var cweIds: [String]? = nil
    public var cveIds: [String]? = nil
    public init() {}
}

/// One normalized, provenance-carrying result item (the shared results contract).
public struct ResultItem: Codable, Sendable, Equatable, Identifiable {
    public let kind: String
    public let observationId: String
    public let assetId: String
    public let assetType: String
    public let assetIdentity: String
    public let sourceAssetId: String?
    public let runId: String?
    public let providerId: String?
    public let discoveredBy: String
    public let evidenceId: String?
    public let observedValue: String
    public let confidence: String
    public let timestamp: String
    public var metadata: JSONValue? = nil
    public var metadataOmitted: Bool? = nil
    public var id: String { observationId }
}

/// A chain's normalized results — a read model derived from durable records.
public struct ResultProjection: Codable, Sendable, Equatable {
    public let workspaceId: String
    public let chainId: String
    public let chainName: String
    public let items: [ResultItem]
}

// MARK: Deterministic Finding drafts (#79 + Level 1 of #81)

/// One affected asset in a draft, carrying its identity for display without a round trip.
public struct DraftAsset: Codable, Sendable, Equatable, Identifiable {
    public let assetId: String
    public let assetType: String
    public let assetIdentity: String
    public var isPrimary: Bool
    public var id: String { assetId }
    public init(assetId: String, assetType: String, assetIdentity: String, isPrimary: Bool) {
        self.assetId = assetId; self.assetType = assetType
        self.assetIdentity = assetIdentity; self.isPrimary = isPrimary
    }
}

/// One evidence reference in a draft, with a bounded display label (never the body).
public struct DraftEvidence: Codable, Sendable, Equatable, Identifiable {
    public let evidenceId: String
    public let label: String
    public var id: String { evidenceId }
    public init(evidenceId: String, label: String) {
        self.evidenceId = evidenceId; self.label = label
    }
}

/// A typed, non-persisted Finding draft the core builds deterministically from durable
/// context. The structured editor opens already populated from it; nothing is created
/// until the analyst presses Create.
public struct FindingDraft: Codable, Sendable, Equatable {
    public let kind: String
    public let title: String
    public let severity: FindingSeverity
    public let confidence: FindingConfidence
    public let suggestedStatus: FindingStatus
    public let description: String
    public let reproduction: String
    public let remediation: String
    public let tags: [String]
    public let cweIds: [String]
    public let cveIds: [String]
    public let primaryAssetId: String?
    public let affectedAssets: [DraftAsset]
    public let evidence: [DraftEvidence]
    public let sourceProvider: String?
    public let sourceRunId: String?
    public let provenance: [String]
}

public extension FindingDraft {
    /// The `NewFinding` an *unedited* draft creates — the canonical "Create from this
    /// draft" mapping, mirroring the core's `FindingDraft::to_new_finding`. The editor
    /// seeds its fields from the same draft, so an untouched draft produces exactly this.
    func newFinding() -> NewFinding {
        var new = NewFinding()
        new.title = title
        new.severity = severity
        new.confidence = confidence
        new.status = suggestedStatus
        new.description = description
        new.reproduction = reproduction
        new.remediation = remediation
        new.tags = tags
        new.cweIds = cweIds
        new.cveIds = cveIds
        let primary = affectedAssets.first(where: \.isPrimary)?.assetId ?? affectedAssets.first?.assetId
        new.primaryAssetId = primary
        new.additionalAssetIds = affectedAssets.filter { $0.assetId != primary }.map(\.assetId)
        new.evidenceIds = evidence.map(\.evidenceId)
        new.sourceProvider = sourceProvider
        new.sourceRunId = sourceRunId
        return new
    }
}

/// A typed selection of durable context to draft a finding from. The core validates every
/// id against the workspace (and the run); Swift never enforces isolation itself.
public struct FindingDraftContext: Codable, Sendable, Equatable {
    public var runId: String?
    public var observationIds: [String]
    public var assetIds: [String]
    public var evidenceIds: [String]
    public var primaryAssetId: String?
    public init(runId: String? = nil, observationIds: [String] = [], assetIds: [String] = [],
                evidenceIds: [String] = [], primaryAssetId: String? = nil) {
        self.runId = runId; self.observationIds = observationIds; self.assetIds = assetIds
        self.evidenceIds = evidenceIds; self.primaryAssetId = primaryAssetId
    }
}

public extension Snapshot {
    /// Findings newest first.
    var findingsNewestFirst: [Finding] { (findings ?? []).sorted { $0.createdAt > $1.createdAt } }
}

public extension JSONValue {
    /// Encode an `Encodable` into a `JSONValue` using the core's snake_case convention,
    /// so typed request bodies (e.g. `NewFinding`, `FindingEdit`) serialize to the exact
    /// shape the Rust core expects.
    static func encoding<T: Encodable>(_ value: T) throws -> JSONValue {
        let data = try CoreCoding.encoder().encode(value)
        return try CoreCoding.decoder().decode(JSONValue.self, from: data)
    }
}

/// Bounds for local result/draft reconstruction (a read-only SQLite/core RPC, not a
/// network provider). If the core does not answer within this, the loader stops waiting
/// and shows a retryable error instead of spinning forever. Scanners are never bounded by
/// this value.
public enum FindingLoad {
    public static let defaultTimeout: TimeInterval = 8
    static let timeoutCode = "LoaderTimeout"
}

/// Ensures a one-shot outcome is delivered exactly once (timeout vs. completion race).
private actor FindingLoadLatch {
    private var claimed = false
    func claim() -> Bool { if claimed { return false }; claimed = true; return true }
}

/// Run `operation`, returning its result, or throwing a `LoaderTimeout` `CoreFailure` after
/// `seconds`. The operation runs in a detached task so that if the underlying IPC read is
/// not promptly cancellable (PipeTransport blocks on a serial queue), the timeout still
/// returns control immediately; the orphaned work is abandoned and can never resume this
/// continuation twice. Callers additionally gate on a request token, so an abandoned op's
/// late result is ignored.
func withFindingLoadTimeout<T: Sendable>(
    _ seconds: TimeInterval,
    _ operation: @Sendable @escaping () async throws -> T
) async throws -> T {
    let latch = FindingLoadLatch()
    return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<T, Error>) in
        let work = Task {
            do {
                let value = try await operation()
                if await latch.claim() { continuation.resume(returning: value) }
            } catch {
                if await latch.claim() { continuation.resume(throwing: error) }
            }
        }
        Task {
            try? await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
            if await latch.claim() {
                work.cancel()
                continuation.resume(throwing: CoreFailure(code: FindingLoad.timeoutCode, message: "timed out"))
            }
        }
    }
}

/// Loading state shared by the result picker and offline race tests. A request token
/// distinguishes repeated A→B→A selections: only the current token may mutate visible
/// state, so a stale/abandoned response can neither overwrite a newer selection nor clear
/// its loading state. A bounded timeout guarantees the current request always reaches a
/// terminal state (success, failure, or a retryable timeout) rather than spinning forever.
@MainActor public final class FindingResultLoader: ObservableObject {
    @Published public private(set) var projection: ResultProjection?
    @Published public private(set) var isLoading = false
    @Published public private(set) var errorMessage: String?
    private var request = UUID()
    public init() {}
    public func clear() {
        request = UUID(); projection = nil; errorMessage = nil; isLoading = false
    }
    public func load(client: any CoreAPI, workspace: String, chain: String,
                     timeout: TimeInterval = FindingLoad.defaultTimeout) async {
        let token = UUID(); request = token
        projection = nil; errorMessage = nil; isLoading = true
        do {
            let result = try await withFindingLoadTimeout(timeout) {
                try await client.resultProjection(workspace: workspace, chain: chain)
            }
            // Only the current request may mutate state; a superseded one returns silently
            // (a newer request already owns the loading state).
            guard token == request else { return }
            guard result.workspaceId == workspace, result.chainId == chain else {
                throw CoreFailure(code: "InvalidResponse", message: "Results do not match the selected workspace and run.")
            }
            projection = result; isLoading = false
        } catch {
            guard token == request else { return }
            errorMessage = Self.message(for: error); isLoading = false
        }
    }
    private static func message(for error: Error) -> String {
        if (error as? CoreFailure)?.code == FindingLoad.timeoutCode {
            return "MACSPLOIT took too long to reconstruct this run's results. Try again."
        }
        return error.localizedDescription
    }
}

/// Loads a deterministic `FindingDraft` for a typed context and rejects stale responses.
/// Only the current request token may mutate visible state, so a slower draft for a
/// superseded selection can never populate the editor for the user's newer action nor
/// clear its loading state; a failure or timeout surfaces as an error, never a blank draft.
@MainActor public final class FindingDraftLoader: ObservableObject {
    @Published public private(set) var draft: FindingDraft?
    @Published public private(set) var isLoading = false
    @Published public private(set) var errorMessage: String?
    private var request = UUID()
    public init() {}
    public func clear() {
        request = UUID(); draft = nil; errorMessage = nil; isLoading = false
    }
    public func load(client: any CoreAPI, workspace: String?, context: FindingDraftContext,
                     timeout: TimeInterval = FindingLoad.defaultTimeout) async {
        let token = UUID(); request = token
        draft = nil; errorMessage = nil; isLoading = true
        guard let workspace else {
            errorMessage = "Select a workspace before drafting a finding."; isLoading = false; return
        }
        do {
            let result = try await withFindingLoadTimeout(timeout) {
                try await client.draftFinding(workspace: workspace, context: context)
            }
            guard token == request else { return }
            draft = result; isLoading = false
        } catch {
            guard token == request else { return }
            errorMessage = Self.message(for: error); isLoading = false
        }
    }
    private static func message(for error: Error) -> String {
        if (error as? CoreFailure)?.code == FindingLoad.timeoutCode {
            return "MACSPLOIT took too long to build this finding draft. Try again."
        }
        return error.localizedDescription
    }
}

/// Reference labels are display-only; canonical IDs/URLs remain unchanged for links.
public func findingReferenceLabel(_ value: String) -> String {
    let clean = String(value.unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) && !CharacterSet(charactersIn: "\u{202a}\u{202b}\u{202c}\u{202d}\u{202e}\u{2066}\u{2067}\u{2068}\u{2069}").contains($0) })
    if var url = URLComponents(string: clean), ["http", "https"].contains(url.scheme?.lowercased() ?? "") {
        let query = url.percentEncodedQuery != nil
        url.user = nil; url.password = nil; url.query = nil; url.fragment = nil
        return String(((url.string ?? "[URL]") + (query ? "?[redacted]" : "")).prefix(1024))
    }
    return String(clean.prefix(1024))
}
