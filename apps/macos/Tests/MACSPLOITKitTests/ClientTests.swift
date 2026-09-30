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
        let payload = #"{"result":{"core_version":"0.1.0","protocol_version":1,"offline_only":true}}"#
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

    @Test func testProviderStatusDecodesFlattenedMetadataAndInstallation() async throws {
        let reply = ReplyTransport(#"{"result":[{"id":"subfinder","name":"Subfinder","description":"Passive subdomain enumeration.","version":"external","capabilities":["SUBDOMAIN_DISCOVERY"],"supported_target_types":["Domain"],"risk_class":"PASSIVE","offline":false,"installation":{"state":"MISSING"}}]}"#)
        let providers = try await CoreClient(transport: reply).listProviders()
        #expect(providers.count == 1)
        #expect(providers[0].id == "subfinder")
        #expect(providers[0].capabilities == ["SUBDOMAIN_DISCOVERY"])
        #expect(providers[0].supportedTargetTypes == ["Domain"])
        #expect(providers[0].offline == false)
        #expect(providers[0].installation.isInstalled == false)
        #expect(providers[0].installation.summary == "Not installed")
    }

    @Test func testBuiltInProviderInstallationDecodes() async throws {
        let reply = ReplyTransport(#"{"result":[{"id":"native_dns","name":"Native DNS Resolver","description":"Built-in resolver.","version":"built-in","capabilities":["DNS_RESOLUTION"],"supported_target_types":["Domain","Hostname"],"risk_class":"ACTIVE_LOW_IMPACT","offline":true,"installation":{"state":"BUILT_IN"}}]}"#)
        let providers = try await CoreClient(transport: reply).listProviders()
        #expect(providers[0].id == "native_dns")
        #expect(providers[0].riskClass == "ACTIVE_LOW_IMPACT")
        #expect(providers[0].installation.state == "BUILT_IN")
        #expect(providers[0].installation.isAvailable)
        #expect(providers[0].installation.summary == "Built in")
    }
}
