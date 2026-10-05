import Foundation
import Testing
@testable import MACSPLOITKit

@Suite struct ConsoleModelTests {
    private func snapshot() -> Snapshot {
        let ws = Workspace(id: "w", name: "W", createdAt: "now", updatedAt: "now", scope: ["example.test"])
        let chain = ChainRun(id: "c", workspaceId: "w", targetId: "t", name: "Domain Recon",
                             status: "COMPLETED", createdAt: "2026-10-03T19:41:02Z",
                             updatedAt: "2026-10-03T19:41:12Z", errorCode: nil)
        let run = ProviderRun(id: "r1", workspaceId: "w", chainId: "c", stageId: "s", providerId: "nmap",
                              providerVersion: "7.99", target: "192.0.2.10",
                              startTime: "2026-10-03T19:41:05Z", status: "COMPLETED",
                              endTime: "2026-10-03T19:41:12Z", rawOutputReference: "e", exitStatus: 0)
        let cmd = CoreEvent(id: "ev", workspaceId: "w", timestamp: "2026-10-03T19:41:05Z",
                            eventType: "ProviderCommand", sequence: 5,
                            payload: .object(["provider_run_id": .string("r1"),
                                              "command": .array([.string("nmap"), .string("-sT"), .string("192.0.2.10")])]))
        return Snapshot(workspace: ws, targets: [], assets: [], relationships: [], observations: [],
                        chains: [chain], stages: [], tasks: [], providerRuns: [run], evidence: [],
                        events: [cmd], lastSequence: 5)
    }

    @Test func consoleLinesDeriveFromDurableState() {
        let lines = reconConsoleLines(snapshot: snapshot(), chainId: "c")
        let details = lines.map { "\($0.label)|\($0.detail)" }
        #expect(details.contains("CHAIN|Domain Recon started"))
        #expect(details.contains("NMAP|provider started · 192.0.2.10"))
        #expect(details.contains("$|nmap -sT 192.0.2.10"))
        #expect(details.contains("NMAP|completed · exit 0"))
        #expect(details.contains("CHAIN|completed"))
        // Ordered by timestamp: chain start precedes provider start precedes chain end.
        let startIndex = lines.firstIndex { $0.detail == "Domain Recon started" }!
        let endIndex = lines.firstIndex { $0.label == "CHAIN" && $0.detail == "completed" }!
        #expect(startIndex < endIndex)
    }

    @Test func consoleLinesEmptyForUnknownChainAndNeverFabricated() {
        #expect(reconConsoleLines(snapshot: snapshot(), chainId: "missing").isEmpty)
    }

    @Test func clockStringExtractsTimeComponent() {
        #expect(ConsoleLine.clockString(from: "2026-10-03T19:41:05Z") == "19:41:05")
        #expect(ConsoleLine.clockString(from: "garbage") == "garbage")
    }

    private func snapshotWithResults() -> Snapshot {
        let ws = Workspace(id: "w", name: "W", createdAt: "now", updatedAt: "now", scope: ["example.test"])
        let chain = ChainRun(id: "c", workspaceId: "w", targetId: "t", name: "Web Recon",
                             status: "COMPLETED", createdAt: "2026-10-03T19:41:02Z",
                             updatedAt: "2026-10-03T19:41:12Z", errorCode: nil)
        let run = ProviderRun(id: "r1", workspaceId: "w", chainId: "c", stageId: "s", providerId: "native_dns",
                              providerVersion: "core", target: "127.0.0.1",
                              startTime: "2026-10-03T19:41:05Z", status: "COMPLETED",
                              endTime: "2026-10-03T19:41:12Z", rawOutputReference: "e", exitStatus: 0)
        // Preview already sanitized by the core; 2 shown out of a larger count.
        let results = CoreEvent(id: "evr", workspaceId: "w", timestamp: "2026-10-03T19:41:12Z",
                                eventType: "ProviderResults", sequence: 7,
                                payload: .object([
                                    "provider_run_id": .string("r1"),
                                    "provider": .string("native_dns"),
                                    "count": .number(3),
                                    "preview": .array([
                                        .object(["type": .string("Hostname"), "value": .string("localhost"),
                                                 "source": .string("127.0.0.1"), "relationship": .string("ptr_record")]),
                                        .object(["type": .string("IPAddress"), "value": .string("127.0.0.1")])
                                    ])
                                ]))
        return Snapshot(workspace: ws, targets: [], assets: [], relationships: [], observations: [],
                        chains: [chain], stages: [], tasks: [], providerRuns: [run], evidence: [],
                        events: [results], lastSequence: 7)
    }

    @Test func providerResultsRenderBoundedSummaryLines() {
        let lines = reconConsoleLines(snapshot: snapshotWithResults(), chainId: "c")
        let details = lines.map { "\($0.label)|\($0.detail)" }
        // A preview line with source → value and the relationship, label without native_ prefix.
        #expect(details.contains("DNS|127.0.0.1 → localhost (ptr record)"))
        #expect(details.contains("DNS|127.0.0.1"))
        // Count line with a "+N more" hint (3 total, 2 previewed).
        #expect(details.contains { $0.hasPrefix("DNS|discovered 3") && $0.contains("+ 1 more") })
        // No raw stdout is ever dumped (we only rendered what the bounded event carried).
        #expect(!details.contains { $0.lowercased().contains("stdout") })
    }
}
