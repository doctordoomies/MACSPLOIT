import Foundation
import Combine

public enum WorkspaceSection: String, CaseIterable, Identifiable {
    case dashboard = "Dashboard", targets = "Targets", assets = "Assets", recon = "Recon", evidence = "Evidence", activity = "Activity"
    public var id: String { rawValue }
    public var symbol: String {
        switch self {
        case .dashboard: return "square.grid.2x2"
        case .targets: return "scope"
        case .assets: return "square.stack.3d.up"
        case .recon: return "point.3.connected.trianglepath.dotted"
        case .evidence: return "doc.text.magnifyingglass"
        case .activity: return "waveform.path"
        }
    }
}

@MainActor
public final class WorkspaceModel: ObservableObject {
    @Published public private(set) var workspaces: [Workspace] = []
    @Published public private(set) var providerStatuses: [ProviderStatus] = []
    @Published public private(set) var snapshot: Snapshot?
    @Published public private(set) var selectedWorkspaceId: String?
    @Published public var section: WorkspaceSection? = .dashboard
    @Published public var selectedTargetId: String?
    @Published public var selectedAssetId: String?
    @Published public var selectedChainId: String?
    @Published public var selectedEvidenceId: String?
    @Published public var targetInput = ""
    @Published public private(set) var lastTargetType: String?
    @Published public private(set) var isBusy = false
    @Published public private(set) var isConnected = false
    @Published public var errorMessage: String?
    @Published public private(set) var connectionError: String?
    @Published public private(set) var evidenceText = "Select evidence to inspect its verified raw JSON."
    public let client: any CoreAPI

    public init(client: any CoreAPI) { self.client = client }

    public func boot() async {
        do {
            let hello = try await client.hello()
            guard hello.offlineOnly else { throw CoreFailure(code: "ProtocolMismatch", message: "This app requires the offline Phase 0 core.") }
            workspaces = try await client.listWorkspaces()
            providerStatuses = (try? await client.listProviders()) ?? []
            isConnected = true; connectionError = nil
            let previous = selectedWorkspaceId
            if let id = previous, workspaces.contains(where: { $0.id == id }) { await selectWorkspace(id) }
            else if let workspace = workspaces.last { await selectWorkspace(workspace.id) }
        } catch { isConnected = false; connectionError = error.localizedDescription }
    }

    public func selectWorkspace(_ id: String) async {
        selectedWorkspaceId = id.isEmpty ? nil : id; snapshot = nil
        selectedTargetId = nil; selectedAssetId = nil; selectedChainId = nil; selectedEvidenceId = nil
        lastTargetType = nil; evidenceText = "Select evidence to inspect its verified raw JSON."
        do { try await refresh() } catch { errorMessage = error.localizedDescription }
    }

    public func refresh() async throws {
        guard let id = selectedWorkspaceId else { return }
        let updated = try await client.snapshot(workspace: id)
        guard selectedWorkspaceId == id else { return }
        snapshot = updated
        if let index = workspaces.firstIndex(where: { $0.id == id }) { workspaces[index] = updated.workspace }
        if selectedTargetId == nil { selectedTargetId = updated.targets.first?.id }
        if selectedChainId == nil { selectedChainId = updated.chains.last?.id }
    }

    public func pollOnce() async {
        guard isConnected, let id = selectedWorkspaceId, let current = snapshot else { return }
        do {
            let events = try await client.events(workspace: id, after: current.lastSequence)
            guard selectedWorkspaceId == id else { return }
            if !events.isEmpty { try await refresh() }
        } catch { isConnected = false; connectionError = error.localizedDescription }
    }

    public func observe() async {
        while !Task.isCancelled {
            await pollOnce()
            do { try await Task.sleep(nanoseconds: 250_000_000) } catch { return }
        }
    }

    public func createWorkspace(name: String, scopeText: String) async -> Bool {
        isBusy = true; defer { isBusy = false }
        do {
            let entries = scopeText.split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
            let workspace = try await client.createWorkspace(name: name, scope: entries)
            workspaces = try await client.listWorkspaces()
            await selectWorkspace(workspace.id)
            return true
        } catch { errorMessage = error.localizedDescription; return false }
    }

    public func addTarget() async {
        guard let id = selectedWorkspaceId else { return }
        isBusy = true; defer { isBusy = false }
        do {
            let target = try await client.addTarget(workspace: id, value: targetInput)
            guard selectedWorkspaceId == id else { return }
            selectedTargetId = target.id; lastTargetType = target.targetType; targetInput = ""
            try await refresh()
        } catch { errorMessage = error.localizedDescription }
    }

    public func runRecon(kind: String = "synthetic") async {
        guard let id = selectedWorkspaceId, let target = selectedTargetId else { return }
        isBusy = true; defer { isBusy = false }
        do {
            let chain = try await client.startChain(workspace: id, target: target, chain: kind)
            guard selectedWorkspaceId == id else { return }
            selectedChainId = chain.id; section = .recon; try await refresh()
        } catch { errorMessage = error.localizedDescription }
    }

    public func provider(_ id: String) -> ProviderStatus? { providerStatuses.first { $0.id == id } }
    public var subfinder: ProviderStatus? { provider("subfinder") }
    public var nativeDns: ProviderStatus? { provider("native_dns") }
    public var nmap: ProviderStatus? { provider("nmap") }
    public var httpx: ProviderStatus? { provider("httpx") }

    public func cancelRecon() async {
        guard let id = selectedWorkspaceId, let chain = selectedChainId else { return }
        do { try await client.cancelChain(workspace: id, chain: chain); try await refresh() }
        catch { errorMessage = error.localizedDescription }
    }

    public func loadEvidence() async {
        guard let workspace = selectedWorkspaceId, let evidence = selectedEvidenceId else { return }
        evidenceText = "Verifying SHA-256 and reading stored JSON…"
        do {
            let content = try await client.readEvidence(workspace: workspace, evidence: evidence)
            guard selectedWorkspaceId == workspace, selectedEvidenceId == evidence else { return }
            evidenceText = content.rawJson
        } catch { evidenceText = error.localizedDescription }
    }

    public func showEvidence(_ id: String) { selectedEvidenceId = id; section = .evidence }
    public var selectedAsset: Asset? { snapshot?.assets.first { $0.id == selectedAssetId } }
    public var selectedChain: ChainRun? { snapshot?.chains.first { $0.id == selectedChainId } }
    public func source(for asset: Asset) -> String {
        snapshot?.observations.last { $0.assetId == asset.id }?.discoveredBy ?? "Unknown"
    }
    public func assetName(_ id: String) -> String { snapshot?.assets.first { $0.id == id }?.displayValue ?? id }
}
