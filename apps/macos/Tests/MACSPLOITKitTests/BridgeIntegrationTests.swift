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
            // Evidence is now a provider envelope; the synthetic output is nested
            // inside its stdout field.
            #expect(raw.rawJson.contains("\"provider\": \"synthetic\""))
            #expect(raw.rawJson.contains("\"offline\": true"))
        }
        transport.shutdown()
        let reopenedTransport = PipeTransport(executable: URL(fileURLWithPath: binary), dataDirectory: directory)
        defer { reopenedTransport.shutdown() }
        let reopened = CoreClient(transport: reopenedTransport)
        let persisted = try await reopened.snapshot(workspace: workspace.id)
        #expect(persisted == result)
    }

    @Test(.enabled(if: ProcessInfo.processInfo.environment["MACSPLOIT_CORE_BINARY"] != nil
        && ProcessInfo.processInfo.environment["MACSPLOIT_SUBFINDER"] != nil
        && ProcessInfo.processInfo.environment["MACSPLOIT_DNS_FAKE"] != nil))
    func testDomainReconRunsSubfinderThroughBridgeOffline() async throws {
        let binary = try #require(ProcessInfo.processInfo.environment["MACSPLOIT_CORE_BINARY"])
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("macsploit-domain-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let transport = PipeTransport(executable: URL(fileURLWithPath: binary), dataDirectory: directory)
        let client = CoreClient(transport: transport)
        defer { transport.shutdown() }
        _ = try await client.hello()

        // Subfinder is installed (fake, v9.9.9); native DNS is built in.
        let providers = try await client.listProviders()
        let subfinder = try #require(providers.first { $0.id == "subfinder" })
        #expect(subfinder.installation.isInstalled)
        let dns = try #require(providers.first { $0.id == "native_dns" })
        #expect(dns.installation.state == "BUILT_IN")
        #expect(dns.installation.isAvailable)

        let workspace = try await client.createWorkspace(name: "Domain bridge test", scope: ["example.test", "*.example.test", "192.0.2.0/24"])
        let target = try await client.addTarget(workspace: workspace.id, value: "example.test")
        let run = try await client.startChain(workspace: workspace.id, target: target.id, chain: "domain_recon")
        let deadline = Date().addingTimeInterval(15)
        var completed = false
        while Date() < deadline {
            let snapshot = try await client.snapshot(workspace: workspace.id)
            if snapshot.chains.first(where: { $0.id == run.id })?.status == "COMPLETED" { completed = true; break }
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        #expect(completed)
        let result = try await client.snapshot(workspace: workspace.id)
        #expect(result.chains.first?.name == "Domain Recon")
        let subdomains = result.assets.filter { $0.assetType == "Subdomain" }
        let ips = result.assets.filter { $0.assetType == "IPAddress" }
        #expect(subdomains.count == 3)
        #expect(ips.count == 3)
        // 3 has_subdomain + 3 resolves_to.
        #expect(result.relationships.count == 6)
        #expect(result.relationships.filter { $0.relationshipType == "resolves_to" }.count == 3)
        // Two provider runs: subfinder and native_dns.
        #expect(result.providerRuns.count == 2)
        #expect(result.providerRuns.contains { $0.providerId == "subfinder" })
        #expect(result.providerRuns.contains { $0.providerId == "native_dns" })
        #expect(result.evidence.count == 2)

        transport.shutdown()
        let reopenedTransport = PipeTransport(executable: URL(fileURLWithPath: binary), dataDirectory: directory)
        defer { reopenedTransport.shutdown() }
        let reopened = try await CoreClient(transport: reopenedTransport).snapshot(workspace: workspace.id)
        #expect(reopened.assets.count == result.assets.count)
        #expect(reopened.providerRuns.count == 2)
        #expect(reopened.evidence.count == 2)
    }
}
