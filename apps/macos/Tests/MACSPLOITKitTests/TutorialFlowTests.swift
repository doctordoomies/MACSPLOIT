import Foundation
import Testing
@testable import MACSPLOITKit

/// Records workspace/target/chain calls so the tutorial's "prepare demo" and explicit
/// "run synthetic" actions can be verified to use the normal path and launch nothing on
/// their own.
actor TutorialAPI: CoreAPI {
    private(set) var calls: [String] = []
    private var created: [Workspace] = []
    private let demoName = WorkspaceModel.tutorialWorkspaceName
    private var currentWorkspaceId = "w-demo"

    func hello() async throws -> CoreHello { CoreHello(coreVersion: "0", protocolVersion: 1, offlineOnly: false) }
    func listWorkspaces() async throws -> [Workspace] { created }
    func createWorkspace(name: String, scope: [String]) async throws -> Workspace {
        calls.append("create:\(name)")
        let ws = Workspace(id: "w-demo", name: name, createdAt: "now", updatedAt: "now", scope: scope)
        created = [ws]
        return ws
    }
    func updateWorkspaceScope(workspace: String, scope: [String]) async throws -> Workspace {
        created.first ?? Workspace(id: workspace, name: demoName, createdAt: "now", updatedAt: "now", scope: scope)
    }
    func addTarget(workspace: String, value: String) async throws -> Target {
        calls.append("target:\(value)")
        return Target(id: "t", workspaceId: workspace, originalValue: value, normalizedValue: value,
                      targetType: "Domain", createdAt: "now", assetId: "a")
    }
    func snapshot(workspace: String) async throws -> Snapshot {
        let ws = created.first ?? Workspace(id: workspace, name: demoName, createdAt: "now", updatedAt: "now", scope: ["example.test"])
        let target = Target(id: "t", workspaceId: workspace, originalValue: "example.test",
                            normalizedValue: "example.test", targetType: "Domain", createdAt: "now", assetId: "a")
        return Snapshot(workspace: ws, targets: [target], assets: [], relationships: [], observations: [],
                        chains: [], stages: [], tasks: [], providerRuns: [], evidence: [], events: [], lastSequence: 1)
    }
    func events(workspace: String, after: Int64) async throws -> [CoreEvent] { [] }
    func startChain(workspace: String, target: String, chain: String, options: JSONValue) async throws -> ChainRun {
        calls.append("start:\(chain)")
        return ChainRun(id: "c", workspaceId: workspace, targetId: target, name: chain, status: "PENDING",
                        createdAt: "now", updatedAt: "now", errorCode: nil)
    }
    func cancelChain(workspace: String, chain: String) async throws {}
    func readEvidence(workspace: String, evidence: String) async throws -> EvidenceContent { EvidenceContent(evidenceId: evidence, rawJson: "{}") }
    func listProviders() async throws -> [ProviderStatus] { [] }
    func targetScopeStatus(workspace: String, target: String) async throws -> ScopeStatus { ScopeStatus(authorized: true, requiredScopeEntry: nil) }
    func authorizeTarget(workspace: String, target: String) async throws -> AuthorizeResult {
        AuthorizeResult(workspace: created.first!, authorized: true, addedEntry: nil)
    }
    func recordedCalls() -> [String] { calls }
}

@MainActor
@Suite struct TutorialFlowTests {
    @Test func prepareDemoCreatesLabelledWorkspaceAndTargetButLaunchesNothing() async {
        let api = TutorialAPI()
        let model = WorkspaceModel(client: api)
        await model.boot()
        await model.prepareTutorialDemo()
        let calls = await api.recordedCalls()
        #expect(calls.contains("create:\(WorkspaceModel.tutorialWorkspaceName)"))
        #expect(calls.contains("target:example.test"))
        // Preparing the demo must not start any chain.
        #expect(!calls.contains { $0.hasPrefix("start:") })
        #expect(model.isTutorialWorkspace)
    }

    @Test func explicitRunUsesTheSyntheticWorkflowPath() async {
        let api = TutorialAPI()
        let model = WorkspaceModel(client: api)
        await model.boot()
        await model.prepareTutorialDemo()
        await model.runRecon(kind: "synthetic")
        let calls = await api.recordedCalls()
        #expect(calls.contains("start:synthetic"), "explicit run uses the normal synthetic path")
        #expect(!calls.contains { $0.hasPrefix("start:") && !$0.contains("synthetic") }, "no live provider workflow is launched")
    }

    @Test func tutorialArmingAndFinishTogglePersistedFlag() {
        let suite = "macsploit.test.\(UUID().uuidString)"
        let d = UserDefaults(suiteName: suite)!
        d.removePersistentDomain(forName: suite)
        let setup = SetupModel(store: SetupStore(defaults: d))
        setup.startTutorial()
        #expect(setup.tutorialActive)
        #expect(!SetupStore(defaults: d).tutorialCompleted)
        setup.finishTutorial()
        #expect(!setup.tutorialActive)
        #expect(SetupStore(defaults: d).tutorialCompleted)
    }
}
