import Foundation
import Testing
@testable import MACSPLOITKit

/// Records authorize/startChain ordering and lets scope coverage be configured, to test
/// the Authorize & Run sequencing without a real core.
actor AuthzAPI: CoreAPI {
    var authorized: Bool
    var failAuthorize: Bool
    private(set) var calls: [String] = []
    private let ws = Workspace(id: "w", name: "W", createdAt: "now", updatedAt: "now", scope: [])
    private let target = Target(id: "t", workspaceId: "w", originalValue: "example.test",
                                normalizedValue: "example.test", targetType: "Domain",
                                createdAt: "now", assetId: "a")

    init(authorized: Bool, failAuthorize: Bool = false) {
        self.authorized = authorized; self.failAuthorize = failAuthorize
    }

    func hello() async throws -> CoreHello { CoreHello(coreVersion: "0", protocolVersion: 1, offlineOnly: false) }
    func listWorkspaces() async throws -> [Workspace] { [ws] }
    func createWorkspace(name: String, scope: [String]) async throws -> Workspace { ws }
    func updateWorkspaceScope(workspace: String, scope: [String]) async throws -> Workspace { ws }
    func addTarget(workspace: String, value: String) async throws -> Target { target }
    func snapshot(workspace: String) async throws -> Snapshot {
        Snapshot(workspace: ws, targets: [target], assets: [], relationships: [], observations: [],
                 chains: [], stages: [], tasks: [], providerRuns: [], evidence: [], events: [], lastSequence: 1)
    }
    func events(workspace: String, after: Int64) async throws -> [CoreEvent] { [] }
    func startChain(workspace: String, target: String, chain: String, options: JSONValue) async throws -> ChainRun {
        calls.append("start:\(chain)")
        return ChainRun(id: "c", workspaceId: "w", targetId: "t", name: chain, status: "PENDING",
                        createdAt: "now", updatedAt: "now", errorCode: nil)
    }
    func cancelChain(workspace: String, chain: String) async throws {}
    func readEvidence(workspace: String, evidence: String) async throws -> EvidenceContent { EvidenceContent(evidenceId: evidence, rawJson: "{}") }
    func listProviders() async throws -> [ProviderStatus] { [] }
    func targetScopeStatus(workspace: String, target: String) async throws -> ScopeStatus {
        ScopeStatus(authorized: authorized, requiredScopeEntry: authorized ? nil : "example.test")
    }
    func authorizeTarget(workspace: String, target: String) async throws -> AuthorizeResult {
        calls.append("authorize")
        if failAuthorize { throw CoreFailure(code: "ScopeViolation", message: "nope") }
        authorized = true
        return AuthorizeResult(workspace: ws, authorized: true, addedEntry: "example.test")
    }
    func recordedCalls() -> [String] { calls }
}

@MainActor
@Suite struct AuthorizationFlowTests {
    private func booted(_ api: AuthzAPI) async -> WorkspaceModel {
        let model = WorkspaceModel(client: api)
        await model.boot()
        await model.refreshScopeStatus()
        return model
    }

    @Test func outOfScopeTargetAuthorizesBeforeRunning() async {
        let api = AuthzAPI(authorized: false)
        let model = await booted(api)
        #expect(model.scopeStatus?.authorized == false)
        await model.authorizeAndRun(kind: "domain_recon")
        let calls = await api.recordedCalls()
        #expect(calls == ["authorize", "start:domain_recon"]) // authorize strictly before start
    }

    @Test func inScopeTargetRunsWithoutAuthorizing() async {
        let api = AuthzAPI(authorized: true)
        let model = await booted(api)
        #expect(model.scopeStatus?.authorized == true)
        await model.authorizeAndRun(kind: "domain_recon")
        let calls = await api.recordedCalls()
        #expect(calls == ["start:domain_recon"]) // no authorize call
    }

    @Test func failedAuthorizationNeverStartsAChain() async {
        let api = AuthzAPI(authorized: false, failAuthorize: true)
        let model = await booted(api)
        await model.authorizeAndRun(kind: "ip_recon")
        let calls = await api.recordedCalls()
        #expect(calls == ["authorize"]) // start is never reached
        #expect(model.errorMessage != nil)
    }
}
