import Foundation
import Testing
@testable import MACSPLOITKit

@Suite struct BridgeIntegrationTests {
    @Test(.enabled(if: ProcessInfo.processInfo.environment["MACSPLOIT_CORE_BINARY"] != nil))
    func testSwiftRustSQLiteProviderEventsAndRestart() async throws {
        let binary = try #require(ProcessInfo.processInfo.environment["MACSPLOIT_CORE_BINARY"])
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("macsploit-swift-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let transport = PipeTransport(executable: URL(fileURLWithPath: binary), dataDirectory: directory)
        let client = CoreClient(transport: transport)
        defer { transport.shutdown() }
        let hello = try await client.hello()
        #expect(hello.offlineOnly)
        let workspace = try await client.createWorkspace(name: "Swift bridge test", scope: ["example.test", "*.example.test", "192.0.2.0/24"])
        let target = try await client.addTarget(workspace: workspace.id, value: "example.test")
        #expect(target.targetType == "Domain")
        let before = try await client.snapshot(workspace: workspace.id)
        let run = try await client.startChain(workspace: workspace.id, target: target.id)
        let deadline = Date().addingTimeInterval(15)
        var completed = false, sawRunning = false
        while Date() < deadline {
            let snapshot = try await client.snapshot(workspace: workspace.id)
            let chain = snapshot.chains.first { $0.id == run.id }
            if chain?.status == "RUNNING" { sawRunning = true }
            if chain?.status == "COMPLETED" { completed = true; break }
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        #expect(completed); #expect(sawRunning)
        let result = try await client.snapshot(workspace: workspace.id)
        #expect(result.assets.count == 11); #expect(result.relationships.count == 10)
        #expect(result.evidence.count == 3); #expect(result.providerRuns.count == 3)
        let replay = try await client.events(workspace: workspace.id, after: before.lastSequence)
        #expect(replay.allSatisfy { $0.sequence > before.lastSequence })
        #expect(replay.contains { $0.eventType == "ChainCompleted" })
        for evidence in result.evidence {
            let raw = try await client.readEvidence(workspace: workspace.id, evidence: evidence.id)
            #expect(raw.rawJson.contains("\"synthetic\": true"))
        }
        transport.shutdown()
        let reopenedTransport = PipeTransport(executable: URL(fileURLWithPath: binary), dataDirectory: directory)
        defer { reopenedTransport.shutdown() }
        let reopened = CoreClient(transport: reopenedTransport)
        let persisted = try await reopened.snapshot(workspace: workspace.id)
        #expect(persisted == result)
    }
}
