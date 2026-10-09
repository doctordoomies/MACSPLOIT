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

    @Test(.enabled(if: ProcessInfo.processInfo.environment["MACSPLOIT_CORE_BINARY"] != nil
        && ProcessInfo.processInfo.environment["MACSPLOIT_DOWNLOAD_FAKE"] != nil))
    func testProviderInstallManagedThroughBridgeOffline() async throws {
        // Exercises the async start_install/install_status path over the pipe with the
        // real core and the offline download transport (MACSPLOIT_DOWNLOAD_FAKE):
        //  - Nmap has no managed artifact → UNSUPPORTED (routes to the official page).
        //  - ffuf is supported but the offline transport cannot serve it → FAILED, and
        //    crucially no binary is installed and no network is touched.
        let binary = try #require(ProcessInfo.processInfo.environment["MACSPLOIT_CORE_BINARY"])
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("macsploit-install-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let transport = PipeTransport(executable: URL(fileURLWithPath: binary), dataDirectory: directory)
        let client = CoreClient(transport: transport)
        defer { transport.shutdown() }
        _ = try await client.hello()

        func runInstall(_ provider: String) async throws -> InstallOutcome? {
            try await client.startInstall(provider: provider, method: "managed_download")
            let deadline = Date().addingTimeInterval(10)
            while Date() < deadline {
                if let outcome = try await client.installStatus().last, outcome.providerId == provider {
                    return outcome
                }
                try await Task.sleep(nanoseconds: 50_000_000)
            }
            return nil
        }

        let nmap = try await runInstall("nmap")
        #expect(nmap?.status == "UNSUPPORTED")
        #expect(nmap?.detail == "https://nmap.org/download.html")

        let ffuf = try await runInstall("ffuf")
        #expect(ffuf?.status == "FAILED")
        // Fail closed: nothing was installed into the managed providers directory.
        let installed = directory.appendingPathComponent("Providers/ffuf")
        #expect(!FileManager.default.fileExists(atPath: installed.path))
    }

    @Test(.enabled(if: ProcessInfo.processInfo.environment["MACSPLOIT_CORE_BINARY"] != nil
        && ProcessInfo.processInfo.environment["MACSPLOIT_NMAP"] != nil
        && ProcessInfo.processInfo.environment["MACSPLOIT_HTTPX"] != nil))
    func testIpReconRunsNmapAndHttpxThroughBridgeOffline() async throws {
        // Direct IP Recon from an explicitly scoped IP target, with no domain/DNS step.
        let binary = try #require(ProcessInfo.processInfo.environment["MACSPLOIT_CORE_BINARY"])
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("macsploit-iprecon-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let transport = PipeTransport(executable: URL(fileURLWithPath: binary), dataDirectory: directory)
        let client = CoreClient(transport: transport)
        defer { transport.shutdown() }
        _ = try await client.hello()

        let workspace = try await client.createWorkspace(name: "IP recon bridge test", scope: ["192.0.2.10"])
        let target = try await client.addTarget(workspace: workspace.id, value: "192.0.2.10")
        #expect(target.targetType == "IPAddress")
        let run = try await client.startChain(workspace: workspace.id, target: target.id, chain: "ip_recon")
        let deadline = Date().addingTimeInterval(20)
        var completed = false
        while Date() < deadline {
            let snapshot = try await client.snapshot(workspace: workspace.id)
            if snapshot.chains.first(where: { $0.id == run.id })?.status == "COMPLETED" { completed = true; break }
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        #expect(completed)
        let result = try await client.snapshot(workspace: workspace.id)
        #expect(result.chains.first?.name == "IP Recon")
        #expect(result.assets.contains { $0.assetType == "Website" && $0.canonicalIdentity == "https://192.0.2.10/" })
        #expect(result.providerRuns.contains { $0.providerId == "nmap" })
        #expect(result.providerRuns.contains { $0.providerId == "httpx" })
        #expect(result.evidence.count == 2)
        // No subdomain/DNS work occurred (this is not Domain Recon).
        #expect(!result.assets.contains { $0.assetType == "Subdomain" })
    }

    @Test(.enabled(if: ProcessInfo.processInfo.environment["MACSPLOIT_CORE_BINARY"] != nil
        && ProcessInfo.processInfo.environment["MACSPLOIT_WEB_FIXTURE"] != nil))
    func testWebAnalysisRunsAgainstLocalhostThroughBridgeOffline() async throws {
        // An explicitly scoped localhost URL target runs Web Analysis with no public DNS
        // and no Domain target; the custom port is preserved end to end.
        let binary = try #require(ProcessInfo.processInfo.environment["MACSPLOIT_CORE_BINARY"])
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("macsploit-localweb-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let transport = PipeTransport(executable: URL(fileURLWithPath: binary), dataDirectory: directory)
        let client = CoreClient(transport: transport)
        defer { transport.shutdown() }
        _ = try await client.hello()

        let workspace = try await client.createWorkspace(name: "Local web bridge test", scope: ["localhost"])
        let target = try await client.addTarget(workspace: workspace.id, value: "http://localhost:3000/")
        #expect(target.targetType == "URL")
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
        #expect(result.assets.contains { $0.assetType == "Website" && $0.canonicalIdentity == "http://localhost:3000/" })
        #expect(result.providerRuns.first?.providerId == "native_http")
        let evidence = try await client.readEvidence(workspace: workspace.id, evidence: result.evidence[0].id)
        #expect(evidence.rawJson.contains("localhost:3000"))
        #expect(!evidence.rawJson.contains("LOCALSECRET")) // cookie value never persisted
    }

    @Test(.enabled(if: ProcessInfo.processInfo.environment["MACSPLOIT_CORE_BINARY"] != nil
        && ProcessInfo.processInfo.environment["MACSPLOIT_FFUF"] != nil
        && ProcessInfo.processInfo.environment["MACSPLOIT_FFUF_WORDLIST"] != nil))
    func testContentDiscoveryRunsFfufThroughBridgeOffline() async throws {
        let binary = try #require(ProcessInfo.processInfo.environment["MACSPLOIT_CORE_BINARY"])
        let wordlist = try #require(ProcessInfo.processInfo.environment["MACSPLOIT_FFUF_WORDLIST"])
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("macsploit-contentdisc-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let transport = PipeTransport(executable: URL(fileURLWithPath: binary), dataDirectory: directory)
        let client = CoreClient(transport: transport)
        defer { transport.shutdown() }
        _ = try await client.hello()

        let providers = try await client.listProviders()
        let ffuf = try #require(providers.first { $0.id == "ffuf" })
        #expect(ffuf.installation.isInstalled)
        #expect(ffuf.riskClass == "ACTIVE")

        let workspace = try await client.createWorkspace(name: "Content discovery bridge test", scope: ["example.test", "*.example.test"])
        let target = try await client.addTarget(workspace: workspace.id, value: "https://example.test/")
        let run = try await client.startChain(
            workspace: workspace.id, target: target.id, chain: "content_discovery",
            options: .object(["wordlist_path": .string(wordlist)])
        )
        let deadline = Date().addingTimeInterval(15)
        var completed = false
        while Date() < deadline {
            let snapshot = try await client.snapshot(workspace: workspace.id)
            if snapshot.chains.first(where: { $0.id == run.id })?.status == "COMPLETED" { completed = true; break }
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        #expect(completed)
        let result = try await client.snapshot(workspace: workspace.id)
        #expect(result.chains.first?.name == "Content Discovery")
        let discovered = result.assets.filter { $0.assetType == "URL" && $0.canonicalIdentity != "https://example.test/" }
        #expect(discovered.count == 4) // admin/login/api/secret; 404 excluded
        #expect(result.relationships.filter { $0.relationshipType == "has_endpoint" }.count == 4)
        #expect(result.providerRuns.first?.providerId == "ffuf")
        #expect(result.evidence.count == 1)
        let evidence = try await client.readEvidence(workspace: workspace.id, evidence: result.evidence[0].id)
        #expect(!evidence.rawJson.contains(wordlist)) // full local wordlist path redacted
    }

    @Test(.enabled(if: ProcessInfo.processInfo.environment["MACSPLOIT_CORE_BINARY"] != nil
        && ProcessInfo.processInfo.environment["MACSPLOIT_USER_SCANNER"] != nil))
    func testUsernameOSINTRunCancelEvidenceAndRestartThroughBridgeOffline() async throws {
        let binary = try #require(ProcessInfo.processInfo.environment["MACSPLOIT_CORE_BINARY"])
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("macsploit-osint-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let transport = PipeTransport(executable: URL(fileURLWithPath: binary), dataDirectory: directory)
        let client = CoreClient(transport: transport)
        defer { transport.shutdown() }
        _ = try await client.hello()

        // Fake user-scanner (offline) reports the verified upstream version.
        let providers = try await client.listProviders()
        let scanner = try #require(providers.first { $0.id == "user_scanner" })
        #expect(scanner.installation.isInstalled)
        #expect(scanner.installation.version == "1.5.2.1")
        #expect(scanner.capabilities == ["USERNAME_OSINT", "EMAIL_OSINT"])
        #expect(scanner.setup?.installCommand == "pipx install user-scanner")
        #expect(OSINTMode.username.compatibleProviders(providers).map(\.id) == ["user_scanner"])

        // Host scope does not cover any platform; OSINT runs on the identifier subject.
        let workspace = try await client.createWorkspace(name: "OSINT bridge test", scope: ["example.test"])
        let target = try await client.addTarget(workspace: workspace.id, value: "@octo-synthetic")
        #expect(target.targetType == "Username")
        let idle = try await client.snapshot(workspace: workspace.id)
        #expect(idle.chains.isEmpty) // adding a target never launches OSINT

        let run = try await client.startChain(workspace: workspace.id, target: target.id, chain: "username_osint",
                                              options: .object(["provider_id": .string("user_scanner")]))
        let deadline = Date().addingTimeInterval(20)
        var finished: Snapshot?
        while Date() < deadline {
            let snapshot = try await client.snapshot(workspace: workspace.id)
            if let chain = snapshot.chains.first(where: { $0.id == run.id }), !chain.isRunning { finished = snapshot; break }
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        let result = try #require(finished)
        let results = try #require(OSINTRunResults.make(snapshot: result, chainId: run.id))
        #expect(results.state == .partial)
        #expect(Set(results.accounts.map(\.platform)) == ["Github", "X (Twitter)", "Evilsite"])
        #expect(results.accounts.allSatisfy { $0.confidence == "REPORTED" })
        #expect(results.summary?.error == 1)
        #expect(results.summary?.blocked == 1)
        #expect(result.assets.contains { $0.assetType == "Account" && $0.canonicalIdentity == "github:octo-synthetic" })
        #expect(result.relationships.contains { $0.relationshipType == "has_account" })
        #expect(results.evidence.count == 2)
        for evidence in results.evidence {
            let raw = try await client.readEvidence(workspace: workspace.id, evidence: evidence.id)
            #expect(!raw.rawJson.isEmpty)
        }

        // A second subject that hangs: cancel stops it and keeps captured evidence.
        let slow = try await client.addTarget(workspace: workspace.id, value: "@slow-synthetic")
        let slowRun = try await client.startChain(workspace: workspace.id, target: slow.id, chain: "username_osint", options: .object([:]))
        var running = false
        let runDeadline = Date().addingTimeInterval(10)
        while Date() < runDeadline {
            let snapshot = try await client.snapshot(workspace: workspace.id)
            if snapshot.providerRuns.contains(where: { $0.chainId == slowRun.id && $0.status == "RUNNING" }) { running = true; break }
            try await Task.sleep(nanoseconds: 20_000_000)
        }
        #expect(running)
        try await client.cancelChain(workspace: workspace.id, chain: slowRun.id)
        var cancelled: Snapshot?
        let cancelDeadline = Date().addingTimeInterval(10)
        while Date() < cancelDeadline {
            let snapshot = try await client.snapshot(workspace: workspace.id)
            if snapshot.chains.first(where: { $0.id == slowRun.id })?.status == "CANCELLED" { cancelled = snapshot; break }
            try await Task.sleep(nanoseconds: 20_000_000)
        }
        let afterCancel = try #require(cancelled)
        let cancelledRun = try #require(afterCancel.providerRuns.first { $0.chainId == slowRun.id })
        #expect(cancelledRun.status == "CANCELLED")
        let envelope = try await client.readEvidence(workspace: workspace.id, evidence: try #require(cancelledRun.rawOutputReference))
        #expect(envelope.rawJson.contains("\"cancelled\": true"))

        // Restart: results and provenance survive a new helper process.
        transport.shutdown()
        let reopenedTransport = PipeTransport(executable: URL(fileURLWithPath: binary), dataDirectory: directory)
        defer { reopenedTransport.shutdown() }
        let reopened = CoreClient(transport: reopenedTransport)
        let persisted = try await reopened.snapshot(workspace: workspace.id)
        let restored = try #require(OSINTRunResults.make(snapshot: persisted, chainId: run.id))
        #expect(restored.accounts == results.accounts)
        #expect(restored.summary == results.summary)
    }
}
