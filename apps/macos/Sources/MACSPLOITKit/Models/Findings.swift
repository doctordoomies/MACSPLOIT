import Foundation

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
    public var id: String { observationId }
}

/// A chain's normalized results — a read model derived from durable records.
public struct ResultProjection: Codable, Sendable, Equatable {
    public let chainId: String
    public let chainName: String
    public let items: [ResultItem]
}

public extension Snapshot {
    /// Findings newest first.
    var findingsNewestFirst: [Finding] { (findings ?? []).sorted { $0.createdAt > $1.createdAt } }
}

public extension JSONValue {
    /// Encode an `Encodable` into a `JSONValue` using the core's snake_case convention,
    /// so typed request bodies (e.g. `NewFinding`, `FindingEdit`) serialize to the exact
    /// shape the Rust core expects.
    static func encoding<T: Encodable>(_ value: T) -> JSONValue {
        guard let data = try? CoreCoding.encoder().encode(value),
              let json = try? CoreCoding.decoder().decode(JSONValue.self, from: data)
        else { return .null }
        return json
    }
}
