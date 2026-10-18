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

/// Loading state shared by the result picker and offline race tests. A request token
/// distinguishes repeated A→B→A selections; cancellation and scope are checked as well.
@MainActor public final class FindingResultLoader: ObservableObject {
    @Published public private(set) var projection: ResultProjection?
    @Published public private(set) var isLoading = false
    @Published public private(set) var errorMessage: String?
    private var request = UUID()
    public init() {}
    public func clear() {
        request = UUID(); projection = nil; errorMessage = nil; isLoading = false
    }
    public func load(client: any CoreAPI, workspace: String, chain: String) async {
        let token = UUID(); request = token
        projection = nil; errorMessage = nil; isLoading = true
        do {
            let result = try await client.resultProjection(workspace: workspace, chain: chain)
            guard token == request, !Task.isCancelled else { return }
            guard result.workspaceId == workspace, result.chainId == chain else {
                throw CoreFailure(code: "InvalidResponse", message: "Results do not match the selected workspace and run.")
            }
            projection = result; isLoading = false
        } catch {
            guard token == request, !Task.isCancelled else { return }
            errorMessage = error.localizedDescription; isLoading = false
        }
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
