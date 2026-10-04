import Foundation
import Testing
@testable import MACSPLOITKit

private actor ProviderAPI: CoreAPI {
    private var current: Snapshot
    private var subsequent: Snapshot?
    private(set) var requestedCursor: Int64?
    init() {
        let workspace = Workspace(id: "workspace", name: "Persisted", createdAt: "now", updatedAt: "now", scope: ["example.test"])
        current = Snapshot(workspace: workspace, targets: [], assets: [], relationships: [], observations: [], chains: [], stages: [], tasks: [], providerRuns: [], evidence: [], events: [], lastSequence: 12)
    }
    func prepareEvent() {
        let event = CoreEvent(id: "new", workspaceId: "workspace", timestamp: "now", eventType: "TargetAdded", sequence: 13, payload: .object(["value": .string("example.test")]))
        subsequent = Snapshot(workspace: current.workspace, targets: [], assets: [], relationships: [], observations: [], chains: [], stages: [], tasks: [], providerRuns: [], evidence: [], events: [event], lastSequence: 13)
    }
    func hello() async throws -> CoreHello { CoreHello(coreVersion: "0.1.0", protocolVersion: 1, offlineOnly: false) }
    func listWorkspaces() async throws -> [Workspace] { [] }
    func createWorkspace(name: String, scope: [String]) async throws -> Workspace { current.workspace }
    func updateWorkspaceScope(workspace: String, scope: [String]) async throws -> Workspace { current.workspace }
    func addTarget(workspace: String, value: String) async throws -> Target {
        throw CoreFailure(code: "InvalidTarget", message: "Synthetic test rejection.")
    }
    func snapshot(workspace: String) async throws -> Snapshot { current }
    func events(workspace: String, after: Int64) async throws -> [CoreEvent] {
        requestedCursor = after
        if let subsequent { current = subsequent; self.subsequent = nil; return current.events }
        return []
    }
    func startChain(workspace: String, target: String, chain: String, options: JSONValue) async throws -> ChainRun { throw CoreFailure(code: "TestOnly", message: "Unused test operation.") }
    func cancelChain(workspace: String, chain: String) async throws {}
    func readEvidence(workspace: String, evidence: String) async throws -> EvidenceContent { EvidenceContent(evidenceId: evidence, rawJson: "{}") }
    private(set) var calls = 0
    private var fail = false
    private var held = false
    private var continuation: CheckedContinuation<Void, Never>?
    private var entered: CheckedContinuation<Void, Never>?
    func configureFailure(_ value: Bool) { fail = value }
    func holdNext() { held = true }
    func waitForProbe() async {
        if continuation != nil { return }
        await withCheckedContinuation { entered = $0 }
    }
    func releaseProbe() { held = false; continuation?.resume(); continuation = nil }
    func listProviders() async throws -> [ProviderStatus] {
        calls += 1
        if held {
            await withCheckedContinuation { continuation = $0; entered?.resume(); entered = nil }
        }
        if fail { throw CoreFailure(code: "ProbeFailure", message: "Synthetic status failure") }
        return [try providerFixture(state: "INSTALLED")]
    }
    func targetScopeStatus(workspace: String, target: String) async throws -> ScopeStatus { ScopeStatus(authorized: true, requiredScopeEntry: nil) }
    func authorizeTarget(workspace: String, target: String) async throws -> AuthorizeResult {
        AuthorizeResult(workspace: Workspace(id: "w", name: "W", createdAt: "now", updatedAt: "now", scope: []), authorized: true, addedEntry: nil)
    }
}


private func providerFixture(state: String, expanded: Bool = true) throws -> ProviderStatus {
    var installation: [String: Any] = ["state": state, "version": "unknown", "message": "Fixture diagnostics"]
    if expanded { installation["path"] = "/synthetic/tools/future" }
    var value: [String: Any] = ["id": "future_provider", "name": "Future Provider", "description": "Synthetic provider fixture",
        "version": "1", "capabilities": ["FUTURE_CAPABILITY"], "supported_target_types": ["DOMAIN"],
        "risk_class": "ACTIVE_LOW_IMPACT", "offline": false, "installation": installation]
    if expanded { value["setup"] = ["install_command": "brew install future-fixture", "homepage": "https://example.test", "documentation": "file:///synthetic/blocked"] }
    return try CoreCoding.decoder().decode(ProviderStatus.self, from: JSONSerialization.data(withJSONObject: value))
}

@Suite struct ProviderPresentationTests {
    @Test func allStatesAndGenericFutureProvider() throws {
        for (state, title, filter) in [("BUILT_IN", "Built In", ProviderFilter.builtIn),
            ("INSTALLED", "Installed", .installed), ("MISSING", "Missing", .missing),
            ("UNSUPPORTED_VERSION", "Unsupported", .issues), ("EXECUTION_ERROR", "Error", .issues),
            ("FUTURE_STATE", "Unknown status", .issues)] {
            let provider = try providerFixture(state: state)
            #expect(provider.installation.statusTitle == title)
            #expect(provider.installation.isBuiltIn == (state == "BUILT_IN"))
            #expect(filter.includes(provider, search: "future capability"))
            #expect(ProviderFilter.all.includes(provider, search: "FUTURE_PROVIDER"))
            #expect(!ProviderFilter.all.includes(provider, search: "unrelated"))
            #expect(provider.installation.versionLabel == "Version unknown")
        }
        #expect(providerLabel("SUBDOMAIN_DISCOVERY") == "Subdomain Discovery")
        #expect(providerLabel("IPAddress") == "IP Address")
        #expect(providerLabel("DNS_RESOLUTION") == "DNS Resolution")
    }
    @Test func expandedAndLegacyDecodingAndCopyOnlyHelp() throws {
        let provider = try providerFixture(state: "INSTALLED")
        #expect(provider.installation.path == "/synthetic/tools/future")
        #expect(provider.setup?.installCommand == "brew install future-fixture")
        #expect(provider.setup?.homepageURL?.scheme == "https")
        #expect(provider.setup?.documentationURL == nil)
        let legacy = try providerFixture(state: "INSTALLED", expanded: false)
        #expect(legacy.setup == nil)
        #expect(legacy.installation.path == nil)
        let installed = try CoreCoding.decoder().decode(ProviderInstallation.self, from: Data(#"{"state":"INSTALLED","version":"2.6.6"}"#.utf8))
        #expect(installed.versionLabel == "Version 2.6.6")
        #expect(try CoreCoding.decoder().decode(ProviderStatus.self, from: CoreCoding.encoder().encode(provider)) == provider)
    }
}

@MainActor @Suite struct ProviderRefreshTests {
    @Test func refreshWithoutWorkspaceRetainsResultsOnFailureAndRecovers() async {
        let api = ProviderAPI()
        let model = WorkspaceModel(client: api)
        await model.refreshProviders()
        #expect(await api.calls == 0)
        await model.boot()
        #expect(model.isConnected && model.selectedWorkspaceId == nil)
        #expect(model.providerStatuses.count == 1)
        let previous = model.providerStatuses
        await api.configureFailure(true)
        await model.refreshProviders()
        #expect(model.providerStatuses == previous)
        #expect(model.providerRefreshError?.contains("Synthetic status failure") == true)
        #expect(!model.isRefreshingProviders && model.isConnected)
        await api.configureFailure(false)
        await model.refreshProviders()
        #expect(model.providerRefreshError == nil)
        #expect(await api.calls == 3)
    }
    @Test func duplicateRefreshIsSuppressedWhileProbeIsPending() async {
        let api = ProviderAPI()
        let model = WorkspaceModel(client: api)
        await model.boot()
        await api.holdNext()
        let refresh = Task { await model.refreshProviders() }
        await api.waitForProbe()
        #expect(model.isRefreshingProviders)
        #expect(model.providerStatuses.count == 1)
        await model.refreshProviders()
        #expect(await api.calls == 2)
        await api.releaseProbe()
        await refresh.value
        #expect(!model.isRefreshingProviders)
    }
}
