import Foundation
import Network

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

    /// The scope-relevant host for this target: the URL host (brackets stripped) for a
    /// URL, or the normalized value for an IP/hostname/domain. `nil` for other types.
    public var scopeHost: String? {
        switch targetType {
        case "URL":
            guard let url = URL(string: normalizedValue), let host = url.host else { return nil }
            return host.trimmingCharacters(in: CharacterSet(charactersIn: "[]")).lowercased()
        case "IPAddress", "Hostname", "Domain":
            return normalizedValue.lowercased()
        default:
            return nil
        }
    }

    /// Whether this target's host is local/private *by classification only*. This is
    /// informational for the UI; it never implies the target is authorized, safe, or
    /// offline. Authorization is always the explicit workspace scope enforced by the core.
    public var isLocalOrPrivateHost: Bool {
        scopeHost.map(Target.isLocalOrPrivateHost) ?? false
    }

    public static func isLocalOrPrivateHost(_ host: String) -> Bool {
        let host = host.lowercased()
        if host == "localhost" || host.hasSuffix(".localhost") { return true }

        // IP-range checks apply only to strings that actually parse as IP literals, so an
        // ordinary hostname (e.g. "fdexample.com", "fe80example.test") is never matched by
        // a string prefix. Parsing is via Foundation's Network framework (no dependency).
        if let v4 = IPv4Address(host) {
            let b = [UInt8](v4.rawValue) // 4 bytes
            switch (b[0], b[1]) {
            case (127, _), (10, _), (192, 168), (169, 254): return true // loopback/private/link-local
            case (172, 16...31): return true                            // 172.16.0.0/12
            default: return false
            }
        }
        if let v6 = IPv6Address(host) {
            let b = [UInt8](v6.rawValue) // 16 bytes
            if b[0...14].allSatisfy({ $0 == 0 }) && b[15] == 1 { return true } // ::1 loopback
            if b[0] == 0xfe && (b[1] & 0xc0) == 0x80 { return true }           // fe80::/10 link-local
            if (b[0] & 0xfe) == 0xfc { return true }                           // fc00::/7 unique-local
            return false
        }
        return false
    }
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
    public let metadata: JSONValue

    private enum CodingKeys: String, CodingKey {
        case id, workspaceId, assetId, discoveredBy, observedValue, timestamp, confidence
        case sourceAssetId, providerRunId, evidenceId, metadata
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        id = try values.decode(String.self, forKey: .id)
        workspaceId = try values.decode(String.self, forKey: .workspaceId)
        assetId = try values.decode(String.self, forKey: .assetId)
        discoveredBy = try values.decode(String.self, forKey: .discoveredBy)
        observedValue = try values.decode(String.self, forKey: .observedValue)
        timestamp = try values.decode(String.self, forKey: .timestamp)
        confidence = try values.decode(String.self, forKey: .confidence)
        sourceAssetId = try values.decodeIfPresent(String.self, forKey: .sourceAssetId)
        providerRunId = try values.decodeIfPresent(String.self, forKey: .providerRunId)
        evidenceId = try values.decodeIfPresent(String.self, forKey: .evidenceId)
        metadata = try values.decodeIfPresent(JSONValue.self, forKey: .metadata) ?? .object([:])
    }
}
public struct ChainRun: Codable, Identifiable, Sendable, Equatable {
    public let id: String, workspaceId: String, targetId: String, name: String, status: String, createdAt: String, updatedAt: String
    public let errorCode: String?, errorMessage: String?

    public init(id: String, workspaceId: String, targetId: String, name: String, status: String,
                createdAt: String, updatedAt: String, errorCode: String?, errorMessage: String? = nil) {
        self.id = id; self.workspaceId = workspaceId; self.targetId = targetId; self.name = name
        self.status = status; self.createdAt = createdAt; self.updatedAt = updatedAt
        self.errorCode = errorCode; self.errorMessage = errorMessage
    }

    public var isRunning: Bool { ["PENDING", "RUNNING"].contains(status) }
}
public struct ChainStage: Codable, Identifiable, Sendable, Equatable {
    public let id: String, workspaceId: String, chainId: String, name: String, status: String
    public let position: Int
    public let capability: String?, startedAt: String?, endedAt: String?
    /// The provider pinned to this stage, when the preset specifies one.
    public let providerId: String?
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
public struct RelationshipObservation: Codable, Identifiable, Sendable, Equatable {
    public let id: String, workspaceId: String, relationshipId: String, providerRunId: String, evidenceId: String, timestamp: String
}
public struct ChainResults: Codable, Sendable, Equatable {
    public let chain: ChainRun
    public let target: Target
    public let stages: [ChainStage]
    public let providerRuns: [ProviderRun]
    public let assets: [Asset]
    public let observations: [Observation]
    public let relationships: [Relationship]
    public let relationshipObservations: [RelationshipObservation]
    public let evidence: [Evidence]
}
public struct CoreEvent: Codable, Identifiable, Sendable, Equatable {
    public let id: String, workspaceId: String, timestamp: String, eventType: String
    public let sequence: Int64
    public let payload: JSONValue
    public var summary: String {
        switch eventType {
        case "WorkspaceCreated": return "Workspace created: \(payload["name"].string ?? "")"
        case "WorkspaceScopeUpdated": return "Workspace scope updated"
        case "TargetAdded": return "Target added: \(payload["value"].string ?? "")"
        case "AssetDiscovered": return "Discovered \(payload["value"].string ?? "asset")"
        case "ProviderStarted": return "Provider started: \(payload["provider"].string ?? "")"
        case "ProviderCompleted": return "Provider \(payload["status"].string?.lowercased() ?? "completed")"
        case "ChainStarted": return "Recon chain started"
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
/// Core-authoritative scope coverage for a target (read-only; no network activity).
public struct ScopeStatus: Codable, Sendable, Equatable {
    public let authorized: Bool
    public let requiredScopeEntry: String?
}
/// Result of authorizing a target from the Recon flow.
public struct AuthorizeResult: Codable, Sendable, Equatable {
    public let workspace: Workspace
    public let authorized: Bool
    public let addedEntry: String?
}
/// Outcome of a provider installation attempt.
public struct InstallOutcome: Codable, Sendable, Equatable {
    public let providerId: String, method: String, status: String, message: String
    public let detail: String?
}
/// Current provider-install state (running + last outcome). Install is global, not
/// workspace data.
public struct InstallState: Codable, Sendable, Equatable {
    public struct Running: Codable, Sendable, Equatable { public let providerId: String, method: String }
    public let running: Running?
    public let last: InstallOutcome?
}
public struct ProviderInstallation: Codable, Sendable, Equatable {
    public let state: String
    public let path: String?
    public let version: String?
    public let message: String?
    /// Available to run: an external tool that is installed, or a built-in provider.
    public var isAvailable: Bool { state == "INSTALLED" || state == "BUILT_IN" }
    /// Kept for source compatibility; true when the provider can run.
    public var isInstalled: Bool { isAvailable }
    public var summary: String {
        switch state {
        case "BUILT_IN": return "Built in"
        case "INSTALLED": return "Installed \(version.map { "(\($0))" } ?? "")"
        case "MISSING": return "Not installed"
        case "UNSUPPORTED_VERSION": return "Unsupported version \(version ?? "")"
        default: return message ?? "Execution error"
        }
    }
}
/// Reviewed install-method availability for a provider, from the core matrix. The
/// UI uses this only to decide which install buttons to show; the Rust core always
/// chooses the formula/URL/artifact and performs (and enforces) the install.
public struct ProviderInstallInfo: Codable, Sendable, Equatable {
    public let homebrew: Bool
    public let managedDownload: Bool
    public let officialInstallerUrl: String?
}
public struct ProviderStatus: Codable, Identifiable, Sendable, Equatable {
    public let id: String, name: String, description: String, version: String
    public let capabilities: [String], supportedTargetTypes: [String], riskClass: String
    /// Explicit network behavior from current protocol-v1 cores.
    public let networkActivity: String?
    /// Legacy compatibility alias retained by protocol v1.
    public let offline: Bool
    public let installation: ProviderInstallation
    public let setup: ProviderSetup?
    public let install: ProviderInstallInfo?
    public var performsNetworkActivity: Bool {
        switch networkActivity {
        case "NETWORK": return true
        case "NONE": return false
        default: return !offline
        }
    }
    /// Whether a verified app-managed direct download is offered (false for Nmap).
    public var managedDownloadSupported: Bool { install?.managedDownload ?? false }
    /// Whether a Homebrew install method is offered.
    public var homebrewSupported: Bool { install?.homebrew ?? false }
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
