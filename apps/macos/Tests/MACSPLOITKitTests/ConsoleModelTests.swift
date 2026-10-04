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
}
