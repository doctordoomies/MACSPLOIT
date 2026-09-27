import Foundation
import Testing
@testable import MACSPLOITKit

actor ModelAPI: CoreAPI {
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
    func hello() async throws -> CoreHello { CoreHello(coreVersion: "0.1.0", protocolVersion: 1, offlineOnly: true) }
    func listWorkspaces() async throws -> [Workspace] { [current.workspace] }
    func createWorkspace(name: String, scope: [String]) async throws -> Workspace { current.workspace }
    func addTarget(workspace: String, value: String) async throws -> Target {
        throw CoreFailure(code: "InvalidTarget", message: "Synthetic test rejection.")
    }
    func snapshot(workspace: String) async throws -> Snapshot { current }
    func events(workspace: String, after: Int64) async throws -> [CoreEvent] {
        requestedCursor = after
        if let subsequent { current = subsequent; self.subsequent = nil; return current.events }
        return []
    }
    func startChain(workspace: String, target: String) async throws -> ChainRun { throw CoreFailure(code: "TestOnly", message: "Unused test operation.") }
    func cancelChain(workspace: String, chain: String) async throws {}
    func readEvidence(workspace: String, evidence: String) async throws -> EvidenceContent { EvidenceContent(evidenceId: evidence, rawJson: "{}") }
}

@MainActor
@Suite struct WorkspaceModelTests {
    @Test func testBootRestoresWorkspaceAndSnapshotFromCore() async {
        let model = WorkspaceModel(client: ModelAPI())
        await model.boot()
        #expect(model.isConnected)
        #expect(model.selectedWorkspaceId == "workspace")
        #expect(model.snapshot?.workspace.name == "Persisted")
        #expect(model.snapshot?.lastSequence == 12)
    }

    @Test func testPollingUsesDurableCursorAndRefreshesState() async {
        let api = ModelAPI()
        let observed = WorkspaceModel(client: api)
        await observed.boot(); await api.prepareEvent(); await observed.pollOnce()
        let cursor = await api.requestedCursor
        #expect(cursor == 12)
        #expect(observed.snapshot?.lastSequence == 13)
        #expect(observed.snapshot?.events.first?.id == "new")
    }

    @Test func testActionErrorPreservesInputAndClearsBusyState() async {
        let model = WorkspaceModel(client: ModelAPI())
        await model.boot(); model.targetInput = "invalid input"; await model.addTarget()
        #expect(!(model.isBusy))
        #expect(model.targetInput == "invalid input")
        #expect(model.errorMessage?.contains("InvalidTarget") == true)
        #expect(model.snapshot?.lastSequence == 12)
    }
}
