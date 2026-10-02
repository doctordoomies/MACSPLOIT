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
    func events(workspace: String, after: Int64) async throws -> [CoreEvent]
    func startChain(workspace: String, target: String, chain: String) async throws -> ChainRun
    func cancelChain(workspace: String, chain: String) async throws
    func readEvidence(workspace: String, evidence: String) async throws -> EvidenceContent
    func listProviders() async throws -> [ProviderStatus]
}

public extension CoreAPI {
    /// Convenience: start the default (synthetic) chain.
    func startChain(workspace: String, target: String) async throws -> ChainRun {
        try await startChain(workspace: workspace, target: target, chain: "synthetic")
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
    public func events(workspace: String, after: Int64) async throws -> [CoreEvent] {
        try await call("events_after", ["workspace_id": .string(workspace), "after": .number(Double(after))])
    }
    public func startChain(workspace: String, target: String, chain: String) async throws -> ChainRun {
        try await call("start_chain", ["workspace_id": .string(workspace), "target_id": .string(target), "chain": .string(chain)])
    }
    public func listProviders() async throws -> [ProviderStatus] { try await call("list_providers") }
    public func cancelChain(workspace: String, chain: String) async throws {
        let _: JSONValue = try await call("cancel_chain", ["workspace_id": .string(workspace), "chain_id": .string(chain)])
    }
    public func readEvidence(workspace: String, evidence: String) async throws -> EvidenceContent {
        try await call("read_evidence", ["workspace_id": .string(workspace), "evidence_id": .string(evidence)])
    }
}
