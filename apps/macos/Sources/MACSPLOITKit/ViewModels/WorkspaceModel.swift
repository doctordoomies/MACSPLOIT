import Foundation
import Combine

public enum WorkspaceSection: String, CaseIterable, Identifiable {
    case dashboard = "Dashboard", targets = "Targets", assets = "Assets", recon = "Recon", evidence = "Evidence", activity = "Activity"
    case toolManager = "Tool Manager"
    public var id: String { rawValue }
    public var symbol: String {
        switch self {
        case .dashboard: return "square.grid.2x2"
        case .targets: return "scope"
        case .assets: return "square.stack.3d.up"
        case .recon: return "point.3.connected.trianglepath.dotted"
        case .evidence: return "doc.text.magnifyingglass"
        case .activity: return "waveform.path"
        case .toolManager: return "wrench.and.screwdriver"
        }
    }
}

@MainActor
public final class WorkspaceModel: ObservableObject {
    @Published public private(set) var workspaces: [Workspace] = []
    @Published public private(set) var isRefreshingProviders = false
    @Published public private(set) var providerRefreshError: String?
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
    @Published public private(set) var coreVersion: String?
    @Published public var errorMessage: String?
    @Published public private(set) var connectionError: String?
    @Published public private(set) var evidenceText = "Select evidence to inspect its verified raw JSON."
    public let client: any CoreAPI

    public init(client: any CoreAPI) { self.client = client }

    public func boot() async {
        do {
            let hello = try await client.hello()
            coreVersion = hello.coreVersion
            workspaces = try await client.listWorkspaces()
            isConnected = true; connectionError = nil
            await refreshProviders()
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
            // Poll install status only while an install is active (or just finished) to
            // reflect progress without steady background chatter.
            if installState?.running != nil || wasInstalling { await refreshInstallStatus() }
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
        let value = targetInput
        if await addTarget(value: value) {
            targetInput = ""
        }
    }

    @discardableResult
    public func addTarget(value: String) async -> Bool {
        guard let id = selectedWorkspaceId else { return false }
        isBusy = true; defer { isBusy = false }
        do {
            let target = try await client.addTarget(workspace: id, value: value)
            guard selectedWorkspaceId == id else { return false }
            selectedTargetId = target.id
            lastTargetType = target.targetType
            try await refresh()
            return true
        } catch {
            errorMessage = error.localizedDescription
            return false
        }
    }

    public func updateScope(scopeText: String) async -> Bool {
        guard let id = selectedWorkspaceId else { return false }
        let entries = scopeText
            .split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        isBusy = true; defer { isBusy = false }
        do {
            let workspace = try await client.updateWorkspaceScope(workspace: id, scope: entries)
            guard selectedWorkspaceId == id else { return false }
            if let index = workspaces.firstIndex(where: { $0.id == id }) {
                workspaces[index] = workspace
            }
            try await refresh()
            return true
        } catch {
            errorMessage = error.localizedDescription
            return false
        }
    }

    public func refreshProviders() async {
        guard isConnected, !isRefreshingProviders else { return }
        isRefreshingProviders = true
        providerRefreshError = nil
        defer { isRefreshingProviders = false }
        do { providerStatuses = try await client.listProviders() }
        catch { providerRefreshError = "Could not refresh providers: \(error.localizedDescription)" }
    }

    /// The dedicated, clearly-labelled workspace used by the offline tutorial.
    public static let tutorialWorkspaceName = "MACSPLOIT Tutorial (demo)"

    /// Prepare safe tutorial demo state through the normal path: reuse the labelled
    /// tutorial workspace if it already exists (never deleting or overwriting any other
    /// workspace), otherwise create it with the offline demo scope, then ensure the
    /// invented `example.test` target exists. Launches nothing — the caller runs Synthetic
    /// Recon only on an explicit user action.
    public func prepareTutorialDemo() async {
        if let existing = workspaces.first(where: { $0.name == Self.tutorialWorkspaceName }) {
            await selectWorkspace(existing.id)
        } else {
            _ = await createWorkspace(name: Self.tutorialWorkspaceName, scopeText: "example.test\n*.example.test\n192.0.2.0/24")
        }
        _ = await addTarget(value: "example.test")
    }

    /// Whether the current workspace is the tutorial demo workspace.
    public var isTutorialWorkspace: Bool { snapshot?.workspace.name == Self.tutorialWorkspaceName }

    public func runRecon(kind: String = "synthetic", options: JSONValue = .object([:])) async {
        guard let id = selectedWorkspaceId, let target = selectedTargetId else { return }
        isBusy = true; defer { isBusy = false }
        do {
            let chain = try await client.startChain(workspace: id, target: target, chain: kind, options: options)
            guard selectedWorkspaceId == id else { return }
            selectedChainId = chain.id; section = .recon; try await refresh()
        } catch { errorMessage = error.localizedDescription }
    }

    /// Selected content-discovery wordlist (local path) and a conservative estimate
    /// of the maximum requests (usable, non-comment lines).
    @Published public var selectedWordlistPath: String?
    @Published public private(set) var wordlistEstimatedRequests: Int?

    public func chooseWordlist(_ path: String?) {
        selectedWordlistPath = path
        guard let path, let text = try? String(contentsOfFile: path, encoding: .utf8) else {
            wordlistEstimatedRequests = nil
            return
        }
        wordlistEstimatedRequests = text.split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.hasPrefix("#") }
            .count
    }

    public func runContentDiscovery() async {
        guard let path = selectedWordlistPath else {
            errorMessage = "Choose a wordlist before running Content Discovery."
            return
        }
        await runRecon(kind: "content_discovery", options: .object(["wordlist_path": .string(path)]))
    }

    /// Core-authoritative scope coverage for the currently selected target. Refreshed
    /// when the selection changes and after an authorization; drives the Recon
    /// authorization state without Swift reimplementing scope matching.
    @Published public private(set) var scopeStatus: ScopeStatus?

    public func refreshScopeStatus() async {
        guard isConnected, let id = selectedWorkspaceId, let target = selectedTargetId else {
            scopeStatus = nil
            return
        }
        do {
            let status = try await client.targetScopeStatus(workspace: id, target: target)
            guard selectedWorkspaceId == id, selectedTargetId == target else { return }
            scopeStatus = status
        } catch { scopeStatus = nil }
    }

    /// Add only the narrowest exact scope entry for the selected target (no-op if already
    /// covered), persist it, and refresh. Returns whether the target is now authorized.
    @discardableResult
    public func authorizeSelectedTarget() async -> Bool {
        guard let id = selectedWorkspaceId, let target = selectedTargetId else { return false }
        isBusy = true; defer { isBusy = false }
        do {
            let result = try await client.authorizeTarget(workspace: id, target: target)
            guard selectedWorkspaceId == id else { return false }
            if let index = workspaces.firstIndex(where: { $0.id == id }) { workspaces[index] = result.workspace }
            try await refresh()
            await refreshScopeStatus()
            return result.authorized
        } catch { errorMessage = error.localizedDescription; return false }
    }

    /// Authorize if needed, then launch the workflow — the "Authorize & Run" sequence.
    /// Scope is persisted and re-checked by the core before any provider starts.
    public func authorizeAndRun(kind: String, options: JSONValue = .object([:])) async {
        if scopeStatus?.authorized != true {
            guard await authorizeSelectedTarget() else { return }
        }
        await runRecon(kind: kind, options: options)
    }

    /// Console lines for the selected chain, derived from durable snapshot state.
    public var consoleLines: [ConsoleLine] {
        guard let snapshot, let chain = selectedChainId else { return [] }
        return reconConsoleLines(snapshot: snapshot, chainId: chain)
    }

    /// Current provider-install state (running + last outcome), polled alongside events.
    @Published public private(set) var installState: InstallState?
    private var wasInstalling = false

    public func refreshInstallStatus() async {
        guard isConnected else { return }
        let state = try? await client.installStatus()
        installState = state
        let running = state?.running != nil
        // When an install finishes, refresh provider status so the UI reflects it.
        if wasInstalling && !running { await refreshProviders() }
        wasInstalling = running
    }

    /// Start a typed provider installation (e.g. Homebrew). Observed via installState.
    public func installProvider(_ id: String, method: String) async {
        guard isConnected else { return }
        do {
            try await client.startInstall(provider: id, method: method)
            await refreshInstallStatus()
        } catch { errorMessage = error.localizedDescription }
    }

    public func cancelInstall() async {
        try? await client.cancelInstall()
        await refreshInstallStatus()
    }

    public func provider(_ id: String) -> ProviderStatus? { providerStatuses.first { $0.id == id } }
    public var subfinder: ProviderStatus? { provider("subfinder") }
    public var nativeDns: ProviderStatus? { provider("native_dns") }
    public var nmap: ProviderStatus? { provider("nmap") }
    public var httpx: ProviderStatus? { provider("httpx") }
    public var katana: ProviderStatus? { provider("katana") }
    public var nativeHttp: ProviderStatus? { provider("native_http") }
    public var ffuf: ProviderStatus? { provider("ffuf") }

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
