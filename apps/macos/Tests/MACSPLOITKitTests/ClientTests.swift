import Foundation
import Testing
@testable import MACSPLOITKit

actor ReplyTransport: CoreTransport {
    let payload: String
    let version: Int
    let mismatchedId: Bool
    private(set) var requests: [Data] = []
    init(_ payload: String, version: Int = 1, mismatchedId: Bool = false) {
        self.payload = payload; self.version = version; self.mismatchedId = mismatchedId
    }
    func exchange(_ request: Data) async throws -> Data {
        requests.append(request)
        let object = try JSONSerialization.jsonObject(with: request) as! [String: Any]
        let id = mismatchedId ? "wrong-request" : object["request_id"] as! String
        var response = try JSONSerialization.jsonObject(with: Data(payload.utf8)) as! [String: Any]
        response["protocol_version"] = version; response["request_id"] = id
        return try JSONSerialization.data(withJSONObject: response)
    }
}

@Suite struct ClientTests {
    @Test func testClientEncodesTargetRequestAndDecodesRustFields() async throws {
        let reply = ReplyTransport(#"{"result":{"id":"target","workspace_id":"workspace","original_value":"EXAMPLE.TEST","normalized_value":"example.test","target_type":"Domain","created_at":"2026-09-27T12:00:00Z","asset_id":"asset"}}"#)
        let result = try await CoreClient(transport: reply).addTarget(workspace: "workspace", value: "EXAMPLE.TEST")
        #expect(result.workspaceId == "workspace")
        #expect(result.normalizedValue == "example.test")
        #expect(result.assetId == "asset")
        let data = await reply.requests[0]
        let object = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        #expect(object["protocol_version"] as? Int == 1)
        #expect(object["method"] as? String == "add_target")
        #expect((object["params"] as? [String: String])?["workspace_id"] == "workspace")
    }

    @Test func testStructuredRustFailureIsThrown() async throws {
        let reply = ReplyTransport(#"{"error":{"code":"InvalidTarget","message":"Enter a valid target."}}"#)
        do { _ = try await CoreClient(transport: reply).hello(); Issue.record("Expected a structured failure") }
        catch let error as CoreFailure { #expect(error.code == "InvalidTarget") }
    }

    @Test func testProtocolAndRequestIdentityMismatchAreRejected() async throws {
        let payload = #"{"result":{"core_version":"0.1.0","protocol_version":1,"offline_only":false}}"#
        for transport in [ReplyTransport(payload, version: 99), ReplyTransport(payload, mismatchedId: true)] {
            do { _ = try await CoreClient(transport: transport).hello(); Issue.record("Expected protocol rejection") }
            catch let error as CoreFailure { #expect(error.code == "ProtocolMismatch") }
        }
    }

    @Test func testSnapshotAndEventPayloadDecodeWithoutUIInterpretation() throws {
        let data = Data(#"{"workspace":{"id":"w","name":"Test","created_at":"now","updated_at":"now","scope":["example.test"]},"targets":[],"assets":[],"relationships":[],"observations":[],"chains":[],"stages":[],"tasks":[],"provider_runs":[],"evidence":[],"events":[{"id":"e","workspace_id":"w","sequence":13,"timestamp":"now","event_type":"AssetDiscovered","payload":{"asset_id":"a","value":"api.example.test","synthetic":true}}],"last_sequence":13}"#.utf8)
        let snapshot = try CoreCoding.decoder().decode(Snapshot.self, from: data)
        #expect(snapshot.lastSequence == 13)
        #expect(snapshot.events[0].summary == "Discovered api.example.test")
        #expect(snapshot.events[0].payload["synthetic"] == .bool(true))
    }

    @Test func testChainResultsEncodesIdsAndDecodesRunMetadataAndFailureDetail() async throws {
        let reply = ReplyTransport(#"{"result":{"chain":{"id":"c","workspace_id":"w","target_id":"t","name":"Domain Recon","status":"PARTIAL","created_at":"now","updated_at":"now","error_code":"ProviderFailure","error_message":"Later provider failed."},"target":{"id":"t","workspace_id":"w","original_value":"example.test","normalized_value":"example.test","target_type":"Domain","created_at":"now","asset_id":"a"},"stages":[],"provider_runs":[],"assets":[],"observations":[{"id":"o","workspace_id":"w","asset_id":"a","source_asset_id":null,"provider_run_id":"p","evidence_id":"e","discovered_by":"ffuf","observed_value":"https://example.test/admin","metadata":{"status":403,"content_length":7},"timestamp":"now","confidence":"CONFIRMED"}],"relationships":[],"relationship_observations":[],"evidence":[]}}"#)
        let result = try await CoreClient(transport: reply).chainResults(workspace: "w", chain: "c")
        #expect(result.chain.status == "PARTIAL")
        #expect(result.chain.errorMessage == "Later provider failed.")
        #expect(result.observations[0].metadata["status"] == .number(403))
        #expect(result.observations[0].metadata["content_length"] == .number(7))

        let object = try JSONSerialization.jsonObject(with: await reply.requests[0]) as! [String: Any]
        #expect(object["method"] as? String == "chain_results")
        let params = object["params"] as! [String: String]
        #expect(params["workspace_id"] == "w")
        #expect(params["chain_id"] == "c")
    }

    @Test func testProviderStatusDecodesFlattenedMetadataAndInstallation() async throws {
        let reply = ReplyTransport(#"{"result":[{"id":"subfinder","name":"Subfinder","description":"Passive subdomain enumeration.","version":"external","capabilities":["SUBDOMAIN_DISCOVERY"],"supported_target_types":["Domain"],"risk_class":"PASSIVE","network_activity":"NETWORK","offline":false,"installation":{"state":"MISSING"}}]}"#)
        let providers = try await CoreClient(transport: reply).listProviders()
        #expect(providers.count == 1)
        #expect(providers[0].id == "subfinder")
        #expect(providers[0].capabilities == ["SUBDOMAIN_DISCOVERY"])
        #expect(providers[0].supportedTargetTypes == ["Domain"])
        #expect(providers[0].networkActivity == "NETWORK")
        #expect(providers[0].performsNetworkActivity)
        #expect(providers[0].installation.isInstalled == false)
        #expect(providers[0].installation.summary == "Not installed")
    }

    @Test func testBuiltInProviderInstallationDecodes() async throws {
        let reply = ReplyTransport(#"{"result":[{"id":"native_dns","name":"Native DNS Resolver","description":"Built-in resolver.","version":"built-in","capabilities":["DNS_RESOLUTION"],"supported_target_types":["Domain","Hostname"],"risk_class":"ACTIVE_LOW_IMPACT","network_activity":"NETWORK","offline":false,"installation":{"state":"BUILT_IN"}}]}"#)
        let providers = try await CoreClient(transport: reply).listProviders()
        #expect(providers[0].id == "native_dns")
        #expect(providers[0].riskClass == "ACTIVE_LOW_IMPACT")
        #expect(providers[0].installation.state == "BUILT_IN")
        #expect(providers[0].networkActivity == "NETWORK")
        #expect(providers[0].performsNetworkActivity)
        #expect(providers[0].installation.isAvailable)
        #expect(providers[0].installation.summary == "Built in")
    }

    @Test func testProviderNetworkActivitySeparatesBuiltInFromNetworkBehavior() async throws {
        let reply = ReplyTransport(#"{"result":[{"id":"synthetic","name":"Synthetic","description":"d","version":"built-in","capabilities":["SUBDOMAIN_DISCOVERY"],"supported_target_types":["Domain"],"risk_class":"PASSIVE","network_activity":"NONE","offline":true,"installation":{"state":"BUILT_IN"}},{"id":"native_http","name":"Native HTTP","description":"d","version":"built-in","capabilities":["WEB_ANALYSIS"],"supported_target_types":["URL"],"risk_class":"ACTIVE_LOW_IMPACT","network_activity":"NETWORK","offline":false,"installation":{"state":"BUILT_IN"}}]}"#)
        let providers = try await CoreClient(transport: reply).listProviders()
        #expect(providers[0].installation.isBuiltIn)
        #expect(providers[0].performsNetworkActivity == false)
        #expect(providers[1].installation.isBuiltIn)
        #expect(providers[1].performsNetworkActivity)
    }

    @Test func testLegacyOfflineFieldIsOnlyAFallback() async throws {
        let reply = ReplyTransport(#"{"result":[{"id":"legacy","name":"Legacy","description":"d","version":"external","capabilities":[],"supported_target_types":[],"risk_class":"PASSIVE","offline":false,"installation":{"state":"MISSING"}}]}"#)
        let providers = try await CoreClient(transport: reply).listProviders()
        #expect(providers[0].networkActivity == nil)
        #expect(providers[0].performsNetworkActivity)
    }

    @Test func testStartChainEncodesChainAndOptions() async throws {
        let reply = ReplyTransport(#"{"result":{"id":"c","workspace_id":"w","target_id":"t","name":"Content Discovery","status":"PENDING","created_at":"now","updated_at":"now","error_code":null}}"#)
        _ = try await CoreClient(transport: reply).startChain(
            workspace: "w", target: "t", chain: "content_discovery",
            options: .object(["wordlist_path": .string("/tmp/list.txt")])
        )
        let data = await reply.requests[0]
        let object = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        #expect(object["method"] as? String == "start_chain")
        let params = object["params"] as! [String: Any]
        #expect(params["chain"] as? String == "content_discovery")
        let options = params["options"] as! [String: Any]
        #expect(options["wordlist_path"] as? String == "/tmp/list.txt")
    }

    @Test func testTargetScopeStatusDecodesAndEncodes() async throws {
        let reply = ReplyTransport(#"{"result":{"authorized":false,"required_scope_entry":"app.example.test"}}"#)
        let status = try await CoreClient(transport: reply).targetScopeStatus(workspace: "w", target: "t")
        #expect(status.authorized == false)
        #expect(status.requiredScopeEntry == "app.example.test")
        let object = try JSONSerialization.jsonObject(with: await reply.requests[0]) as! [String: Any]
        #expect(object["method"] as? String == "target_scope_status")
        let params = object["params"] as! [String: String]
        #expect(params["workspace_id"] == "w")
        #expect(params["target_id"] == "t")
    }

    @Test func testAuthorizeTargetDecodesAddedEntry() async throws {
        let reply = ReplyTransport(#"{"result":{"authorized":true,"added_entry":"192.0.2.25","workspace":{"id":"w","name":"W","created_at":"now","updated_at":"now","scope":["192.0.2.25"]}}}"#)
        let result = try await CoreClient(transport: reply).authorizeTarget(workspace: "w", target: "t")
        #expect(result.authorized)
        #expect(result.addedEntry == "192.0.2.25")
        #expect(result.workspace.scope == ["192.0.2.25"])
        let object = try JSONSerialization.jsonObject(with: await reply.requests[0]) as! [String: Any]
        #expect(object["method"] as? String == "authorize_target")
    }

    @Test func testProviderStatusDecodesInstallInfo() async throws {
        let reply = ReplyTransport(#"{"result":[{"id":"subfinder","name":"Subfinder","description":"d","version":"external","capabilities":["SUBDOMAIN_DISCOVERY"],"supported_target_types":["Domain"],"risk_class":"PASSIVE","offline":false,"installation":{"state":"MISSING"},"install":{"homebrew":true,"managed_download":true,"official_installer_url":"https://github.com/projectdiscovery/subfinder/releases"}}]}"#)
        let providers = try await CoreClient(transport: reply).listProviders()
        #expect(providers[0].homebrewSupported)
        #expect(providers[0].managedDownloadSupported)
        #expect(providers[0].install?.officialInstallerUrl?.hasPrefix("https://") == true)
    }

    @Test func testNmapManagedDownloadUnsupportedInInstallInfo() async throws {
        let reply = ReplyTransport(#"{"result":[{"id":"nmap","name":"Nmap","description":"d","version":"external","capabilities":["PORT_SCAN"],"supported_target_types":["IPAddress"],"risk_class":"ACTIVE","offline":false,"installation":{"state":"MISSING"},"install":{"homebrew":true,"managed_download":false,"official_installer_url":"https://nmap.org/download.html"}}]}"#)
        let providers = try await CoreClient(transport: reply).listProviders()
        #expect(providers[0].homebrewSupported)
        #expect(providers[0].managedDownloadSupported == false)
        #expect(providers[0].install?.officialInstallerUrl == "https://nmap.org/download.html")
    }

    @Test func testProviderStatusWithoutInstallInfoDefaultsUnsupported() async throws {
        // Older/missing `install` field must decode to a safe "no methods" default.
        let reply = ReplyTransport(#"{"result":[{"id":"native_dns","name":"Native DNS","description":"d","version":"built-in","capabilities":["DNS_RESOLUTION"],"supported_target_types":["Domain"],"risk_class":"ACTIVE_LOW_IMPACT","offline":true,"installation":{"state":"BUILT_IN"}}]}"#)
        let providers = try await CoreClient(transport: reply).listProviders()
        #expect(providers[0].install == nil)
        #expect(providers[0].homebrewSupported == false)
        #expect(providers[0].managedDownloadSupported == false)
    }

    @Test func testStartInstallEncodesManagedDownloadMethod() async throws {
        let reply = ReplyTransport(#"{"result":{"started":true,"provider_id":"subfinder"}}"#)
        try await CoreClient(transport: reply).startInstall(provider: "subfinder", method: "managed_download")
        let object = try JSONSerialization.jsonObject(with: await reply.requests[0]) as! [String: Any]
        let params = object["params"] as! [String: Any]
        #expect(params["provider_id"] as? String == "subfinder")
        #expect(params["method"] as? String == "managed_download")
    }

    @Test func testInstallStatusDecodesManagedSuccess() async throws {
        let reply = ReplyTransport(#"{"result":{"running":null,"last":{"provider_id":"subfinder","method":"managed_download","status":"SUCCEEDED","message":"Installed subfinder 2.16.0 (arm64).","detail":"/Users/x/Library/Application Support/MACSPLOIT/Providers/subfinder"}}}"#)
        let state = try await CoreClient(transport: reply).installStatus()
        #expect(state.last?.status == "SUCCEEDED")
        #expect(state.last?.method == "managed_download")
        #expect(state.last?.detail?.hasSuffix("/Providers/subfinder") == true)
    }

    @Test func testStartInstallEncodesProviderAndMethod() async throws {
        let reply = ReplyTransport(#"{"result":{"started":true,"provider_id":"httpx"}}"#)
        try await CoreClient(transport: reply).startInstall(provider: "httpx", method: "homebrew")
        let object = try JSONSerialization.jsonObject(with: await reply.requests[0]) as! [String: Any]
        #expect(object["method"] as? String == "start_install")
        let params = object["params"] as! [String: Any]
        #expect(params["provider_id"] as? String == "httpx")
        #expect(params["method"] as? String == "homebrew")
    }

    @Test func testInstallStatusDecodes() async throws {
        let reply = ReplyTransport(#"{"result":{"running":null,"last":{"provider_id":"ffuf","method":"managed_download","status":"UNSUPPORTED","message":"use Homebrew","detail":"https://example.test"}}}"#)
        let state = try await CoreClient(transport: reply).installStatus()
        #expect(state.running == nil)
        #expect(state.last?.providerId == "ffuf")
        #expect(state.last?.status == "UNSUPPORTED")
        #expect(state.last?.detail == "https://example.test")
    }

    @Test func testStartChainEncodesIpReconChain() async throws {
        let reply = ReplyTransport(#"{"result":{"id":"c","workspace_id":"w","target_id":"t","name":"IP Recon","status":"PENDING","created_at":"now","updated_at":"now","error_code":null}}"#)
        _ = try await CoreClient(transport: reply).startChain(workspace: "w", target: "t", chain: "ip_recon")
        let data = await reply.requests[0]
        let object = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        #expect(object["method"] as? String == "start_chain")
        let params = object["params"] as! [String: Any]
        #expect(params["chain"] as? String == "ip_recon")
    }
}
