import Foundation

/// One line in the Recon live console. Derived entirely from durable snapshot data
/// (chain, provider runs, and events) — never fabricated.
public struct ConsoleLine: Identifiable, Equatable, Sendable {
    public let id: String
    public let timestamp: String
    public let clock: String
    public let label: String
    public let detail: String
    public init(id: String, timestamp: String, label: String, detail: String) {
        self.id = id
        self.timestamp = timestamp
        self.clock = ConsoleLine.clockString(from: timestamp)
        self.label = label
        self.detail = detail
    }
    /// Extract HH:MM:SS from an RFC3339 timestamp, falling back to the raw string.
    public static func clockString(from timestamp: String) -> String {
        if let t = timestamp.split(separator: "T").dropFirst().first {
            return String(t.prefix(8))
        }
        return timestamp
    }
}

/// Build the live-console lines for one chain from a snapshot. Faithful to real state:
/// chain lifecycle, each provider run's start/command/finish, using existing durable
/// events (`ProviderCommand` carries the sanitized display command). No fake output.
public func reconConsoleLines(snapshot: Snapshot, chainId: String) -> [ConsoleLine] {
    guard let chain = snapshot.chains.first(where: { $0.id == chainId }) else { return [] }
    var lines: [ConsoleLine] = []

    lines.append(ConsoleLine(id: "chain-start-\(chain.id)", timestamp: chain.createdAt,
                             label: "CHAIN", detail: "\(chain.name) started"))

    // Display commands keyed by provider_run_id (from ProviderCommand events).
    var commands: [String: String] = [:]
    for event in snapshot.events where event.eventType == "ProviderCommand" {
        guard let runId = event.payload["provider_run_id"].string else { continue }
        if case let .array(parts) = event.payload["command"] {
            let joined = parts.compactMap { $0.string }.joined(separator: " ")
            if !joined.isEmpty { commands[runId] = joined }
        }
    }

    for run in snapshot.providerRuns.filter({ $0.chainId == chainId }).sorted(by: { $0.startTime < $1.startTime }) {
        let label = run.providerId.uppercased()
        lines.append(ConsoleLine(id: "run-start-\(run.id)", timestamp: run.startTime,
                                 label: label, detail: "provider started · \(run.target)"))
        if let command = commands[run.id] {
            lines.append(ConsoleLine(id: "run-cmd-\(run.id)", timestamp: run.startTime,
                                     label: "$", detail: command))
        }
        if let end = run.endTime {
            let exit = run.exitStatus.map { " · exit \($0)" } ?? ""
            lines.append(ConsoleLine(id: "run-end-\(run.id)", timestamp: end,
                                     label: label, detail: "\(run.status.lowercased())\(exit)"))
        }
    }

    if ["COMPLETED", "FAILED", "PARTIAL", "CANCELLED"].contains(chain.status) {
        lines.append(ConsoleLine(id: "chain-end-\(chain.id)", timestamp: chain.updatedAt,
                                 label: "CHAIN", detail: chain.status.lowercased()))
    }

    return lines.sorted { ($0.timestamp, $0.id) < ($1.timestamp, $1.id) }
}
