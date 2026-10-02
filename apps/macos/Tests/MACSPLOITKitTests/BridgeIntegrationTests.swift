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
        #expect(!hello.offlineOnly)
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
        && ProcessInfo.processInfo.environment["MACSPLOIT_DNS_FAKE"] != nil))
    func testEditableScopeAndNativeDnsReconThroughBridge() async throws {
        let binary = try #require(ProcessInfo.processInfo.environment["MACSPLOIT_CORE_BINARY"])
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("macsploit-dns-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }

        let transport = PipeTransport(executable: URL(fileURLWithPath: binary), dataDirectory: directory)
        let client = CoreClient(transport: transport)
        defer { transport.shutdown() }

        let workspace = try await client.createWorkspace(name: "DNS bridge test", scope: [])
        #expect(workspace.scope.isEmpty)

        let scoped = try await client.updateWorkspaceScope(
            workspace: workspace.id,
            scope: ["api.example.test", "192.0.2.0/24"]
        )
        #expect(scoped.scope.contains("api.example.test"))
        #expect(scoped.scope.contains("192.0.2.0/24"))

        let target = try await client.addTarget(workspace: workspace.id, value: "api.example.test")
        let run = try await client.startChain(workspace: workspace.id, target: target.id, chain: "dns_recon")

        let deadline = Date().addingTimeInterval(15)
        var completed = false
        while Date() < deadline {
            let snapshot = try await client.snapshot(workspace: workspace.id)
            if snapshot.chains.first(where: { $0.id == run.id })?.status == "COMPLETED" {
                completed = true
                break
            }
            try await Task.sleep(nanoseconds: 50_000_000)
        }

        #expect(completed)
        let result = try await client.snapshot(workspace: workspace.id)
        #expect(result.chains.first(where: { $0.id == run.id })?.name == "DNS Recon")
        #expect(result.assets.contains {
            $0.assetType == "IPAddress" && $0.canonicalIdentity == "192.0.2.10"
        })
        #expect(result.providerRuns.contains { $0.providerId == "native_dns" })
        #expect(result.evidence.contains { $0.target == "api.example.test" })
    }

    @Test(.enabled(if: ProcessInfo.processInfo.environment["MACSPLOIT_CORE_BINARY"] != nil
        && ProcessInfo.processInfo.environment["MACSPLOIT_SUBFINDER"] != nil
        && ProcessInfo.processInfo.environment["MACSPLOIT_DNS_FAKE"] != nil
        && ProcessInfo.processInfo.environment["MACSPLOIT_NMAP"] != nil
        && ProcessInfo.processInfo.environment["MACSPLOIT_HTTPX"] != nil))
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
        let nmap = try #require(providers.first { $0.id == "nmap" })
        #expect(nmap.installation.isInstalled)
        #expect(nmap.riskClass == "ACTIVE")
        let httpx = try #require(providers.first { $0.id == "httpx" })
        #expect(httpx.installation.isInstalled)
        #expect(httpx.riskClass == "ACTIVE_LOW_IMPACT")

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
        let ports = result.assets.filter { $0.assetType == "Port" }
        let services = result.assets.filter { $0.assetType == "Service" }
        let websites = result.assets.filter { $0.assetType == "Website" }
        let tech = result.assets.filter { $0.assetType == "Technology" }
        #expect(subdomains.count == 3)
        #expect(ips.count == 3)
        #expect(ports.count == 6)     // 22/tcp + 443/tcp per IP
        #expect(services.count == 6)
        #expect(websites.count == 3)  // https service per IP
        #expect(tech.count == 1)      // nginx, shared
        // 3 has_subdomain + 3 resolves_to + 6 exposes + 6 serves + 3 has_endpoint + 3 uses_technology.
        #expect(result.relationships.count == 24)
        #expect(result.relationships.filter { $0.relationshipType == "has_endpoint" }.count == 3)
        #expect(result.relationships.filter { $0.relationshipType == "uses_technology" }.count == 3)
        // Four provider runs: subfinder, native_dns, nmap, httpx.
        #expect(result.providerRuns.count == 4)
        #expect(result.providerRuns.contains { $0.providerId == "httpx" })
        #expect(result.evidence.count == 4)

        transport.shutdown()
        let reopenedTransport = PipeTransport(executable: URL(fileURLWithPath: binary), dataDirectory: directory)
        defer { reopenedTransport.shutdown() }
        let reopened = try await CoreClient(transport: reopenedTransport).snapshot(workspace: workspace.id)
        #expect(reopened.assets.count == result.assets.count)
        #expect(reopened.providerRuns.count == 4)
        #expect(reopened.evidence.count == 4)
    }

    @Test(.enabled(if: ProcessInfo.processInfo.environment["MACSPLOIT_CORE_BINARY"] != nil
        && ProcessInfo.processInfo.environment["MACSPLOIT_WEB_FIXTURE"] != nil))
    func testWebAnalysisRunsNativelyThroughBridgeOffline() async throws {
        let binary = try #require(ProcessInfo.processInfo.environment["MACSPLOIT_CORE_BINARY"])
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("macsploit-webanalysis-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let transport = PipeTransport(executable: URL(fileURLWithPath: binary), dataDirectory: directory)
        let client = CoreClient(transport: transport)
        defer { transport.shutdown() }
        _ = try await client.hello()

        // Native HTTP analysis is built-in.
        let providers = try await client.listProviders()
        let nativeHttp = try #require(providers.first { $0.id == "native_http" })
        #expect(nativeHttp.installation.state == "BUILT_IN")
        #expect(nativeHttp.riskClass == "ACTIVE_LOW_IMPACT")

        let workspace = try await client.createWorkspace(name: "Web analysis bridge test", scope: ["example.test", "*.example.test"])
        let target = try await client.addTarget(workspace: workspace.id, value: "https://example.test/")
        let run = try await client.startChain(workspace: workspace.id, target: target.id, chain: "web_analysis")
        let deadline = Date().addingTimeInterval(15)
        var completed = false
        while Date() < deadline {
            let snapshot = try await client.snapshot(workspace: workspace.id)
            if snapshot.chains.first(where: { $0.id == run.id })?.status == "COMPLETED" { completed = true; break }
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        #expect(completed)
        let result = try await client.snapshot(workspace: workspace.id)
        #expect(result.chains.first?.name == "Web Analysis")
        #expect(result.assets.contains { $0.assetType == "Website" && $0.canonicalIdentity == "https://example.test/" })
        #expect(result.providerRuns.count == 1)
        #expect(result.providerRuns.first?.providerId == "native_http")
        #expect(result.evidence.count == 1)
        let evidence = try await client.readEvidence(workspace: workspace.id, evidence: result.evidence[0].id)
        #expect(evidence.rawJson.contains("strict-transport-security"))
        #expect(!evidence.rawJson.contains("TOPSECRET")) // cookie value never persisted
    }
}
