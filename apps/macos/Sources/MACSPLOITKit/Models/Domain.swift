import Foundation

public enum JSONValue: Codable, Sendable, Equatable {
    case string(String), number(Double), bool(Bool), object([String: JSONValue]), array([JSONValue]), null

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() { self = .null }
        else if let value = try? container.decode(Bool.self) { self = .bool(value) }
        else if let value = try? container.decode(String.self) { self = .string(value) }
        else if let value = try? container.decode(Double.self) { self = .number(value) }
        else if let value = try? container.decode([String: JSONValue].self) { self = .object(value) }
        else { self = .array(try container.decode([JSONValue].self)) }
    }
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .string(let value): try container.encode(value)
        case .number(let value): try container.encode(value)
        case .bool(let value): try container.encode(value)
        case .object(let value): try container.encode(value)
        case .array(let value): try container.encode(value)
        case .null: try container.encodeNil()
        }
    }
    public subscript(_ key: String) -> JSONValue {
        if case .object(let fields) = self { return fields[key] ?? .null }
        return .null
    }
    public var string: String? { if case .string(let value) = self { return value }; return nil }
    public var isFalse: Bool { self == .bool(false) }
    public var pretty: String {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        return (try? String(data: encoder.encode(self), encoding: .utf8)) ?? "{}"
    }
}

public struct Workspace: Codable, Identifiable, Sendable, Equatable {
    public let id: String, name: String, createdAt: String, updatedAt: String
    public let scope: [String]
}
public struct Target: Codable, Identifiable, Sendable, Equatable {
    public let id: String, workspaceId: String, originalValue: String, normalizedValue: String, targetType: String, createdAt: String
    public let assetId: String?
}
public struct Asset: Codable, Identifiable, Sendable, Equatable {
    public let id: String, workspaceId: String, assetType: String, canonicalIdentity: String, displayValue: String, firstSeen: String, lastSeen: String
    public let metadata: JSONValue
}
public struct Relationship: Codable, Identifiable, Sendable, Equatable {
    public let id: String, workspaceId: String, sourceAssetId: String, destinationAssetId: String, relationshipType: String, createdAt: String
}
public struct Observation: Codable, Identifiable, Sendable, Equatable {
    public let id: String, workspaceId: String, assetId: String, discoveredBy: String, observedValue: String, timestamp: String, confidence: String
    public let sourceAssetId: String?, providerRunId: String?, evidenceId: String?
}
public struct ChainRun: Codable, Identifiable, Sendable, Equatable {
    public let id: String, workspaceId: String, targetId: String, name: String, status: String, createdAt: String, updatedAt: String
    public let errorCode: String?
    public var isRunning: Bool { ["PENDING", "RUNNING"].contains(status) }
}
public struct ChainStage: Codable, Identifiable, Sendable, Equatable {
    public let id: String, workspaceId: String, chainId: String, name: String, status: String
    public let position: Int
    public let capability: String?, startedAt: String?, endedAt: String?
}
public struct TaskRecord: Codable, Identifiable, Sendable, Equatable {
    public let id: String, workspaceId: String, chainId: String, stageId: String, status: String, updatedAt: String
}
public struct ProviderRun: Codable, Identifiable, Sendable, Equatable {
    public let id: String, workspaceId: String, chainId: String, stageId: String, providerId: String, providerVersion: String, target: String, startTime: String, status: String
    public let endTime: String?, rawOutputReference: String?
    public let exitStatus: Int?
}
public struct Evidence: Codable, Identifiable, Sendable, Equatable {
    public let id: String, workspaceId: String, providerRunId: String, provider: String, target: String, timestamp: String, sha256: String, mediaType: String, relativePath: String
    public let byteCount: Int
}
public struct CoreEvent: Codable, Identifiable, Sendable, Equatable {
    public let id: String, workspaceId: String, timestamp: String, eventType: String
    public let sequence: Int64
    public let payload: JSONValue
    public var summary: String {
        switch eventType {
        case "WorkspaceCreated": return "Workspace created: \(payload["name"].string ?? "")"
        case "TargetAdded": return "Target added: \(payload["value"].string ?? "")"
        case "AssetDiscovered": return "Discovered \(payload["value"].string ?? "asset")"
        case "ProviderStarted": return "Provider started: \(payload["provider"].string ?? "")"
        case "ProviderCompleted": return "Provider \(payload["status"].string?.lowercased() ?? "completed")"
        case "ChainStarted": return "Synthetic Recon started"
        case "ChainCompleted": return "Recon \(payload["status"].string?.lowercased() ?? "completed")"
        case "ReconCancelled": return "Recon cancelled"
        case "RecoveryCompleted": return "Interrupted run recovered without restarting"
        default: return eventType.replacingOccurrences(of: "([a-z])([A-Z])", with: "$1 $2", options: .regularExpression)
        }
    }
}
public struct Snapshot: Codable, Sendable, Equatable {
    public let workspace: Workspace
    public let targets: [Target], assets: [Asset], relationships: [Relationship], observations: [Observation]
    public let chains: [ChainRun], stages: [ChainStage], tasks: [TaskRecord], providerRuns: [ProviderRun]
    public let evidence: [Evidence], events: [CoreEvent]
    public let lastSequence: Int64
}
public struct EvidenceContent: Codable, Sendable {
    public let evidenceId: String, rawJson: String
}
public struct CoreHello: Codable, Sendable {
    public let coreVersion: String, protocolVersion: Int, offlineOnly: Bool
}
public struct CoreFailure: Error, Codable, Sendable, LocalizedError, Equatable {
    public let code: String, message: String
    public init(code: String, message: String) { self.code = code; self.message = message }
    public var errorDescription: String? { "\(code): \(message)" }
}

public enum CoreCoding {
    public static func decoder() -> JSONDecoder {
        let decoder = JSONDecoder(); decoder.keyDecodingStrategy = .convertFromSnakeCase; return decoder
    }
    public static func encoder() -> JSONEncoder {
        let encoder = JSONEncoder(); encoder.keyEncodingStrategy = .convertToSnakeCase; return encoder
    }
}

public func displayTime(_ timestamp: String) -> String {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    let date = formatter.date(from: timestamp) ?? ISO8601DateFormatter().date(from: timestamp)
    return date?.formatted(date: .abbreviated, time: .standard) ?? timestamp
}
