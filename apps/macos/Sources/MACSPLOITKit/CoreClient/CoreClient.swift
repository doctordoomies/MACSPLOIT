import Foundation

public protocol CoreTransport: Sendable {
    func exchange(_ request: Data) async throws -> Data
}
public protocol CoreAPI: Sendable {
    func hello() async throws -> CoreHello
    func listWorkspaces() async throws -> [Workspace]
    func createWorkspace(name: String, scope: [String]) async throws -> Workspace
    func updateWorkspaceScope(workspace: String, scope: [String]) async throws -> Workspace
    func addTarget(workspace: String, value: String) async throws -> Target
    func snapshot(workspace: String) async throws -> Snapshot
    func chainResults(workspace: String, chain: String) async throws -> ChainResults
    func events(workspace: String, after: Int64) async throws -> [CoreEvent]
    func startChain(workspace: String, target: String, chain: String, options: JSONValue) async throws -> ChainRun
    func cancelChain(workspace: String, chain: String) async throws
    func readEvidence(workspace: String, evidence: String) async throws -> EvidenceContent
    func listProviders() async throws -> [ProviderStatus]
    func targetScopeStatus(workspace: String, target: String) async throws -> ScopeStatus
    func authorizeTarget(workspace: String, target: String) async throws -> AuthorizeResult
    func startInstall(provider: String, method: String) async throws
    func cancelInstall() async throws
    func installStatus() async throws -> InstallState
    func proposeCorrelation(workspace: String, left: String, right: String, basis: String, confidence: String,
                            rationale: String, observations: [String]) async throws -> Correlation
    func reviewCorrelation(workspace: String, correlation: String, decision: String, note: String) async throws -> Correlation
    func createFinding(workspace: String, finding: NewFinding) async throws -> Finding
    func updateFinding(workspace: String, finding: String, edit: FindingEdit) async throws -> Finding
    func setFindingStatus(workspace: String, finding: String, status: String, note: String) async throws -> Finding
    func linkFindingEvidence(workspace: String, finding: String, evidence: String) async throws -> Finding
    func unlinkFindingEvidence(workspace: String, finding: String, evidence: String) async throws -> Finding
    func resultProjection(workspace: String, chain: String) async throws -> ResultProjection
}

public extension CoreAPI {
    // Default implementations keep older test doubles source-compatible while new
    // read/install surfaces are introduced. CoreClient overrides these with protocol calls.
    func chainResults(workspace: String, chain: String) async throws -> ChainResults {
        throw CoreFailure(code: "Unsupported", message: "Chain Results are not available in this client.")
    }
    func startInstall(provider: String, method: String) async throws {
        throw CoreFailure(code: "Unsupported", message: "Install not available in this client.")
    }
    func cancelInstall() async throws {}
    func installStatus() async throws -> InstallState { InstallState(running: nil, last: nil, events: nil) }
    func proposeCorrelation(workspace: String, left: String, right: String, basis: String, confidence: String,
                            rationale: String, observations: [String]) async throws -> Correlation {
        throw CoreFailure(code: "Unsupported", message: "Correlation is not available in this client.")
    }
    func createFinding(workspace: String, finding: NewFinding) async throws -> Finding {
        throw CoreFailure(code: "Unsupported", message: "Findings are not available in this client.")
    }
    func updateFinding(workspace: String, finding: String, edit: FindingEdit) async throws -> Finding {
        throw CoreFailure(code: "Unsupported", message: "Findings are not available in this client.")
    }
    func setFindingStatus(workspace: String, finding: String, status: String, note: String) async throws -> Finding {
        throw CoreFailure(code: "Unsupported", message: "Findings are not available in this client.")
    }
    func linkFindingEvidence(workspace: String, finding: String, evidence: String) async throws -> Finding {
        throw CoreFailure(code: "Unsupported", message: "Findings are not available in this client.")
    }
    func unlinkFindingEvidence(workspace: String, finding: String, evidence: String) async throws -> Finding {
        throw CoreFailure(code: "Unsupported", message: "Findings are not available in this client.")
    }
    func resultProjection(workspace: String, chain: String) async throws -> ResultProjection {
        throw CoreFailure(code: "Unsupported", message: "Result projection is not available in this client.")
    }
    func reviewCorrelation(workspace: String, correlation: String, decision: String, note: String) async throws -> Correlation {
        throw CoreFailure(code: "Unsupported", message: "Correlation is not available in this client.")
    }
}

public extension CoreAPI {
    /// Convenience: start a chain with no options.
    func startChain(workspace: String, target: String, chain: String) async throws -> ChainRun {
        try await startChain(workspace: workspace, target: target, chain: chain, options: .object([:]))
    }
    /// Convenience: start the default (synthetic) chain.
    func startChain(workspace: String, target: String) async throws -> ChainRun {
        try await startChain(workspace: workspace, target: target, chain: "synthetic", options: .object([:]))
    }
}

private struct Request: Encodable {
    let protocolVersion = 1
    let requestId: String, method: String
    let params: JSONValue
}
private struct Response<T: Decodable>: Decodable {
    let protocolVersion: Int, requestId: String
    let result: T?
    let error: CoreFailure?
}

public struct CoreClient: CoreAPI {
    private let transport: any CoreTransport
    public init(transport: any CoreTransport) { self.transport = transport }

    private func call<T: Decodable>(_ method: String, _ parameters: [String: JSONValue] = [:], as: T.Type = T.self) async throws -> T {
        let request = Request(requestId: UUID().uuidString, method: method, params: .object(parameters))
        let data = try await transport.exchange(CoreCoding.encoder().encode(request))
        let response = try CoreCoding.decoder().decode(Response<T>.self, from: data)
        guard response.protocolVersion == 1, response.requestId == request.requestId else {
            throw CoreFailure(code: "ProtocolMismatch", message: "The Rust helper returned an incompatible response.")
        }
        if let error = response.error { throw error }
        guard let result = response.result else {
            throw CoreFailure(code: "InvalidResponse", message: "The Rust helper returned no result.")
        }
        return result
    }
    public func hello() async throws -> CoreHello { try await call("hello") }
    public func listWorkspaces() async throws -> [Workspace] { try await call("list_workspaces") }
    public func createWorkspace(name: String, scope: [String]) async throws -> Workspace {
        try await call("create_workspace", ["name": .string(name), "scope": .array(scope.map(JSONValue.string))])
    }
    public func updateWorkspaceScope(workspace: String, scope: [String]) async throws -> Workspace {
        try await call("update_workspace_scope", ["workspace_id": .string(workspace), "scope": .array(scope.map(JSONValue.string))])
    }
    public func addTarget(workspace: String, value: String) async throws -> Target {
        try await call("add_target", ["workspace_id": .string(workspace), "value": .string(value)])
    }
    public func snapshot(workspace: String) async throws -> Snapshot {
        try await call("snapshot", ["workspace_id": .string(workspace)])
    }
    public func chainResults(workspace: String, chain: String) async throws -> ChainResults {
        try await call("chain_results", ["workspace_id": .string(workspace), "chain_id": .string(chain)])
    }
    public func events(workspace: String, after: Int64) async throws -> [CoreEvent] {
        try await call("events_after", ["workspace_id": .string(workspace), "after": .number(Double(after))])
    }
    public func startChain(workspace: String, target: String, chain: String, options: JSONValue) async throws -> ChainRun {
        try await call("start_chain", ["workspace_id": .string(workspace), "target_id": .string(target), "chain": .string(chain), "options": options])
    }
    public func listProviders() async throws -> [ProviderStatus] { try await call("list_providers") }
    public func cancelChain(workspace: String, chain: String) async throws {
        let _: JSONValue = try await call("cancel_chain", ["workspace_id": .string(workspace), "chain_id": .string(chain)])
    }
    public func readEvidence(workspace: String, evidence: String) async throws -> EvidenceContent {
        try await call("read_evidence", ["workspace_id": .string(workspace), "evidence_id": .string(evidence)])
    }
    public func targetScopeStatus(workspace: String, target: String) async throws -> ScopeStatus {
        try await call("target_scope_status", ["workspace_id": .string(workspace), "target_id": .string(target)])
    }
    public func authorizeTarget(workspace: String, target: String) async throws -> AuthorizeResult {
        try await call("authorize_target", ["workspace_id": .string(workspace), "target_id": .string(target)])
    }
    public func startInstall(provider: String, method: String) async throws {
        let _: JSONValue = try await call("start_install", ["provider_id": .string(provider), "method": .string(method)])
    }
    public func cancelInstall() async throws {
        let _: JSONValue = try await call("cancel_install", [:])
    }
    public func proposeCorrelation(workspace: String, left: String, right: String, basis: String, confidence: String,
                                   rationale: String, observations: [String]) async throws -> Correlation {
        try await call("propose_correlation", [
            "workspace_id": .string(workspace), "left_asset_id": .string(left), "right_asset_id": .string(right),
            "basis": .string(basis), "confidence": .string(confidence), "rationale": .string(rationale),
            "observation_ids": .array(observations.map { JSONValue.string($0) }),
        ])
    }
    public func reviewCorrelation(workspace: String, correlation: String, decision: String, note: String) async throws -> Correlation {
        try await call("review_correlation", [
            "workspace_id": .string(workspace), "correlation_id": .string(correlation),
            "decision": .string(decision), "note": .string(note),
        ])
    }
    public func installStatus() async throws -> InstallState {
        try await call("install_status", [:])
    }
    public func createFinding(workspace: String, finding: NewFinding) async throws -> Finding {
        try await call("create_finding", ["workspace_id": .string(workspace), "finding": try JSONValue.encoding(finding)])
    }
    public func updateFinding(workspace: String, finding: String, edit: FindingEdit) async throws -> Finding {
        try await call("update_finding", [
            "workspace_id": .string(workspace), "finding_id": .string(finding), "edit": try JSONValue.encoding(edit),
        ])
    }
    public func setFindingStatus(workspace: String, finding: String, status: String, note: String) async throws -> Finding {
        try await call("set_finding_status", [
            "workspace_id": .string(workspace), "finding_id": .string(finding),
            "status": .string(status), "note": .string(note),
        ])
    }
    public func linkFindingEvidence(workspace: String, finding: String, evidence: String) async throws -> Finding {
        try await call("link_finding_evidence", [
            "workspace_id": .string(workspace), "finding_id": .string(finding), "evidence_id": .string(evidence),
        ])
    }
    public func unlinkFindingEvidence(workspace: String, finding: String, evidence: String) async throws -> Finding {
        try await call("unlink_finding_evidence", [
            "workspace_id": .string(workspace), "finding_id": .string(finding), "evidence_id": .string(evidence),
        ])
    }
    public func resultProjection(workspace: String, chain: String) async throws -> ResultProjection {
        try await call("result_projection", ["workspace_id": .string(workspace), "chain_id": .string(chain)])
    }
}
