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

    // Bounded result summaries keyed by provider_run_id (from ProviderResults events).
    var results: [String: CoreEvent] = [:]
    for event in snapshot.events where event.eventType == "ProviderResults" {
        if let runId = event.payload["provider_run_id"].string { results[runId] = event }
    }

    for run in snapshot.providerRuns.filter({ $0.chainId == chainId }).sorted(by: { $0.startTime < $1.startTime }) {
        let label = resultLabel(run.providerId)
        lines.append(ConsoleLine(id: "run-start-\(run.id)", timestamp: run.startTime,
                                 label: label, detail: "provider started · \(run.target)"))
        if let command = commands[run.id] {
            lines.append(ConsoleLine(id: "run-cmd-\(run.id)", timestamp: run.startTime,
                                     label: "$", detail: command))
        }
        let end = run.endTime ?? run.startTime
        // Result preview + count lines (ids sort after run-end at the same timestamp).
        if let event = results[run.id] {
            lines.append(contentsOf: resultLines(event: event, runId: run.id, label: label, timestamp: end))
        }
        if let endTime = run.endTime {
            let exit = run.exitStatus.map { " · exit \($0)" } ?? ""
            lines.append(ConsoleLine(id: "run-end-\(run.id)", timestamp: endTime,
                                     label: label, detail: "\(run.status.lowercased())\(exit)"))
        }
    }

    if ["COMPLETED", "FAILED", "PARTIAL", "CANCELLED"].contains(chain.status) {
        lines.append(ConsoleLine(id: "chain-end-\(chain.id)", timestamp: chain.updatedAt,
                                 label: "CHAIN", detail: chain.status.lowercased()))
    }

    return lines.sorted { ($0.timestamp, $0.id) < ($1.timestamp, $1.id) }
}

/// Short console label for a provider id (drops the `native_` prefix).
private func resultLabel(_ providerId: String) -> String {
    providerId.replacingOccurrences(of: "native_", with: "").uppercased()
}

/// Render bounded result lines from a ProviderResults event: one line per preview item
/// ("ids sort after run-end"), then a count line. Never dumps raw output.
private func resultLines(event: CoreEvent, runId: String, label: String, timestamp: String) -> [ConsoleLine] {
    var out: [ConsoleLine] = []
    var count = 0
    if case let .number(n) = event.payload["count"] { count = Int(n) }
    var shown = 0
    if case let .array(preview) = event.payload["preview"] {
        for (index, item) in preview.enumerated() {
            guard let value = item["value"].string else { continue }
            let source = item["source"].string
            let relationship = item["relationship"].string
            var detail: String
            if let source, !source.isEmpty {
                detail = "\(source) → \(value)"
            } else {
                detail = value
            }
            if let relationship, !relationship.isEmpty {
                detail += " (\(relationship.replacingOccurrences(of: "_", with: " ")))"
            }
            out.append(ConsoleLine(id: "run-result-\(runId)-\(index)", timestamp: timestamp,
                                   label: label, detail: detail))
            shown += 1
        }
    }
    // Count line, with a "+N more" hint when the preview was truncated.
    if count > 0 {
        let more = count - shown
        let suffix = more > 0 ? " · + \(more) more — View Assets" : ""
        out.append(ConsoleLine(id: "run-resultcount-\(runId)", timestamp: timestamp,
                               label: label, detail: "discovered \(count)\(suffix)"))
    } else {
        out.append(ConsoleLine(id: "run-resultcount-\(runId)", timestamp: timestamp,
                               label: label, detail: "no new discoveries"))
    }
    return out
}
