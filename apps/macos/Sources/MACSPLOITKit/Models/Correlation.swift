import Foundation

/// One review-log entry (the proposal is the first entry). Append-only in the core.
public struct CorrelationReview: Codable, Identifiable, Sendable, Equatable {
    public let id: String
    public let fromStatus: String?
    public let toStatus: String
    public let note: String, actor: String, timestamp: String
}

/// An analyst's explicit, evidence-backed claim that two different canonical assets
/// may refer to one real-world subject. Separate from canonical deduplication: the
/// core never merges, rewrites, or deletes assets because of a correlation, and it
/// never creates one automatically.
public struct Correlation: Codable, Identifiable, Sendable, Equatable {
    public let id: String, workspaceId: String
    public let leftAssetId: String, rightAssetId: String
    /// `analyst_review`, `shared_identifier` (capped at LOW), `shared_public_record`.
    public let basis: String
    /// `LOW`, `MEDIUM`, `HIGH`.
    public let confidence: String
    /// `PROPOSED`, `CONFIRMED`, `REJECTED`, `RETRACTED`.
    public let status: String
    public let rationale: String
    public let observationIds: [String], evidenceIds: [String]
    public let createdBy: String, createdAt: String, updatedAt: String
    public let reviews: [CorrelationReview]

    /// Review decisions the core accepts from the current status.
    public var availableDecisions: [CorrelationDecision] {
        switch status {
        case "PROPOSED": return [.confirm, .reject]
        case "CONFIRMED": return [.retract]
        case "REJECTED", "RETRACTED": return [.reopen]
        default: return []
        }
    }
}

public enum CorrelationDecision: String, CaseIterable, Identifiable, Sendable {
    case confirm, reject, retract, reopen
    public var id: String { rawValue }
    public var title: String { rawValue.capitalized }
}

public enum CorrelationBasisOption: String, CaseIterable, Identifiable, Sendable {
    case analystReview = "analyst_review", sharedPublicRecord = "shared_public_record", sharedIdentifier = "shared_identifier"
    public var id: String { rawValue }
    public var title: String {
        switch self {
        case .analystReview: return "Analyst review of evidence"
        case .sharedPublicRecord: return "Public record names both"
        case .sharedIdentifier: return "Shared identifier (weak · LOW only)"
        }
    }
}

public extension Snapshot {
    /// Assets an analyst may correlate: OSINT subjects and accounts that have at
    /// least one evidence-backed observation (analyst-entered targets alone cannot
    /// back a correlation).
    var correlatableAssets: [Asset] {
        let types: Set<String> = ["Username", "EmailAddress", "PhoneNumber", "Domain", "Account"]
        let evidenced = Set(observations.filter { $0.evidenceId != nil }.map(\.assetId))
        return assets.filter { types.contains($0.assetType) && evidenced.contains($0.id) }
            .sorted { ($0.assetType, $0.canonicalIdentity) < ($1.assetType, $1.canonicalIdentity) }
    }

    /// Evidence-backed observations to cite for an asset (most recent first, bounded).
    func citableObservations(for asset: String, limit: Int = 5) -> [String] {
        Array(observations.filter { $0.assetId == asset && $0.evidenceId != nil }.reversed().prefix(limit).map(\.id))
    }
}
