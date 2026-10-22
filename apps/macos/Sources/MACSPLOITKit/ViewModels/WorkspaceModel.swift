import Foundation
import Combine

public enum WorkspaceSection: String, CaseIterable, Identifiable {
    case dashboard = "Dashboard", targets = "Targets", assets = "Assets", recon = "Recon", osint = "OSINT", findings = "Findings", evidence = "Evidence", activity = "Activity"
    case toolManager = "Tool Manager"
    case terminal = "Terminal"
    public var id: String { rawValue }
    public var symbol: String {
        switch self {
        case .dashboard: return "square.grid.2x2"
        case .targets: return "scope"
        case .assets: return "square.stack.3d.up"
        case .recon: return "point.3.connected.trianglepath.dotted"
        case .osint: return "person.crop.rectangle.stack"
        case .findings: return "exclamationmark.shield"
        case .evidence: return "doc.text.magnifyingglass"
        case .activity: return "waveform.path"
        case .toolManager: return "wrench.and.screwdriver"
        case .terminal: return "apple.terminal"
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
    @Published public private(set) var selectedChainResults: ChainResults?
    @Published public private(set) var chainResultsError: String?
    @Published public private(set) var isLoadingChainResults = false
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
    private var chainResultsGeneration = 0
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
        chainResultsGeneration += 1
        selectedWorkspaceId = id.isEmpty ? nil : id; snapshot = nil; selectedChainResults = nil
        chainResultsError = nil; isLoadingChainResults = false
        selectedTargetId = nil; selectedAssetId = nil; selectedChainId = nil; selectedEvidenceId = nil
        selectedOSINTChainId = nil; osintTargetId = nil
        selectedFindingId = nil; pendingFindingDraft = nil; pendingFindingChainId = nil; pendingDraftContext = nil
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
        if selectedOSINTChainId == nil { selectedOSINTChainId = updated.osintChains.first?.id }
        await refreshSelectedChainResults()
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

    public func selectChain(_ id: String?) async {
        selectedChainId = id
        await refreshSelectedChainResults()
    }

    /// Fetch one durable run-scoped Results record. A monotonically increasing request
    /// generation prevents a slower response for an older selection/workspace from
    /// replacing the Results for the user's newer selection.
    public func refreshSelectedChainResults() async {
        chainResultsGeneration += 1
        let generation = chainResultsGeneration
        guard isConnected, let workspace = selectedWorkspaceId, let chain = selectedChainId else {
            selectedChainResults = nil
            chainResultsError = nil
            isLoadingChainResults = false
            return
        }

        isLoadingChainResults = true
        chainResultsError = nil
        do {
            let results = try await client.chainResults(workspace: workspace, chain: chain)
            guard generation == chainResultsGeneration,
                  selectedWorkspaceId == workspace,
                  selectedChainId == chain else { return }
            selectedChainResults = results
        } catch {
            guard generation == chainResultsGeneration,
                  selectedWorkspaceId == workspace,
                  selectedChainId == chain else { return }
            selectedChainResults = nil
            chainResultsError = error.localizedDescription
        }
        if generation == chainResultsGeneration { isLoadingChainResults = false }
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

    // MARK: OSINT

    /// Selected OSINT workflow, subject target, and provider. Nothing runs until
    /// `runOSINT()` is called from an explicit user action; adding a target never
    /// launches OSINT.
    @Published public var osintMode: OSINTMode = .username
    @Published public var osintTargetId: String?
    @Published public var osintProviderId: String?
    @Published public var selectedOSINTChainId: String?

    /// Registered providers compatible with the selected OSINT workflow.
    public var osintProviders: [ProviderStatus] { osintMode.compatibleProviders(providerStatuses) }

    /// The provider that will run: the explicit choice if still compatible, otherwise
    /// the first compatible provider.
    public var effectiveOSINTProvider: ProviderStatus? {
        let providers = osintProviders
        return providers.first { $0.id == osintProviderId } ?? providers.first
    }

    /// Workspace targets compatible with the selected OSINT workflow.
    public var osintTargets: [Target] { osintMode.compatibleTargets(snapshot?.targets ?? []) }

    /// The selected subject, if it is compatible with the selected workflow.
    public var osintTarget: Target? {
        let targets = osintTargets
        return targets.first { $0.id == osintTargetId } ?? targets.first
    }

    /// Results for the selected OSINT run, from durable core state.
    public var osintResults: OSINTRunResults? {
        guard let snapshot else { return nil }
        return OSINTRunResults.make(snapshot: snapshot, chainId: selectedOSINTChainId)
    }

    /// Why Run is unavailable, or nil when an explicit run can start.
    public var osintRunBlocker: String? {
        if !isConnected { return "The Rust core is not connected." }
        if snapshot?.chains.contains(where: \.isRunning) == true { return "Another run is in progress. Wait or cancel it." }
        if osintTarget == nil { return osintMode.targetHint }
        guard let provider = effectiveOSINTProvider else {
            return "No registered provider supports \(osintMode.rawValue)."
        }
        if !provider.installation.isAvailable {
            return "\(provider.name) is \(provider.installation.summary.lowercased()). Open Provider Center for setup details, then Refresh."
        }
        return nil
    }

    /// Core-authoritative scope coverage for the selected Domain OSINT target. Only
    /// Domain OSINT uses host scope; identifier subjects (username/email/phone) use the
    /// separate OSINT authorization model and never consult it.
    @Published public private(set) var osintScopeStatus: ScopeStatus?
    /// Set when a Domain OSINT run was requested for an out-of-scope target; the view
    /// shows the explicit Authorize & Run confirmation instead of launching.
    @Published public var osintAuthorizationRequested = false

    /// Whether the selected workflow needs host-scope authorization before it can run.
    public var osintNeedsAuthorization: Bool {
        osintMode == .domain && osintTarget != nil && osintScopeStatus?.authorized != true
    }

    public func refreshOSINTScopeStatus() async {
        guard isConnected, osintMode == .domain, let id = selectedWorkspaceId, let target = osintTarget?.id else {
            osintScopeStatus = nil
            return
        }
        do {
            let status = try await client.targetScopeStatus(workspace: id, target: target)
            guard selectedWorkspaceId == id, osintMode == .domain, osintTarget?.id == target else { return }
            osintScopeStatus = status
        } catch { osintScopeStatus = nil }
    }

    /// Confirmed "Authorize & Run Domain OSINT": the core adds only the exact entry it
    /// reports, persists it, and re-checks; the run starts only if the core then
    /// reports the target authorized. Nothing is launched on failure.
    public func authorizeAndRunOSINT() async {
        osintAuthorizationRequested = false
        guard osintMode == .domain, let id = selectedWorkspaceId, let target = osintTarget?.id else { return }
        do {
            let result = try await client.authorizeTarget(workspace: id, target: target)
            guard selectedWorkspaceId == id else { return }
            if let index = workspaces.firstIndex(where: { $0.id == id }) { workspaces[index] = result.workspace }
            try await refresh()
            await refreshOSINTScopeStatus()
            guard result.authorized, osintScopeStatus?.authorized == true else {
                errorMessage = "The core did not authorize \(osintTarget?.normalizedValue ?? "the target"); Domain OSINT was not started."
                return
            }
        } catch {
            errorMessage = error.localizedDescription
            return
        }
        await runOSINT()
    }

    /// Dismiss the Authorize & Run confirmation without changing scope.
    public func cancelOSINTAuthorization() { osintAuthorizationRequested = false }

    /// Start one bounded OSINT run for the selected subject with the selected provider.
    /// An out-of-scope Domain OSINT target requests explicit authorization instead.
    public func runOSINT() async {
        guard let id = selectedWorkspaceId, let target = osintTarget, osintRunBlocker == nil else {
            if let blocker = osintRunBlocker { errorMessage = blocker }
            return
        }
        if osintMode == .domain {
            await refreshOSINTScopeStatus()
            if osintScopeStatus?.authorized != true {
                osintAuthorizationRequested = true
                return
            }
        }
        isBusy = true; defer { isBusy = false }
        var options: [String: JSONValue] = [:]
        if let provider = effectiveOSINTProvider { options["provider_id"] = .string(provider.id) }
        do {
            let chain = try await client.startChain(workspace: id, target: target.id, chain: osintMode.chainKind, options: .object(options))
            guard selectedWorkspaceId == id else { return }
            selectedOSINTChainId = chain.id
            section = .osint
            try await refresh()
        } catch { errorMessage = error.localizedDescription }
    }

    /// Cancel the selected OSINT run (the core kills the provider process group).
    public func cancelOSINT() async {
        guard let id = selectedWorkspaceId, let chain = selectedOSINTChainId else { return }
        do { try await client.cancelChain(workspace: id, chain: chain); try await refresh() }
        catch { errorMessage = error.localizedDescription }
    }

    // MARK: Correlation (explicit, evidence-backed, reviewable)

    /// Analyst correlations, oldest first. Never created automatically.
    public var correlations: [Correlation] { snapshot?.correlations ?? [] }

    /// Propose a correlation between two different assets. The cited evidence is the
    /// assets' own evidence-backed observations; the core validates everything
    /// (both sides cited, evidence present, weak-signal confidence cap) and never
    /// merges or edits the assets.
    @discardableResult
    public func proposeCorrelation(left: String, right: String, basis: String, confidence: String, rationale: String) async -> Bool {
        guard let id = selectedWorkspaceId, let snapshot else { return false }
        let cited = snapshot.citableObservations(for: left) + snapshot.citableObservations(for: right)
        do {
            _ = try await client.proposeCorrelation(workspace: id, left: left, right: right, basis: basis,
                                                    confidence: confidence, rationale: rationale, observations: cited)
            try await refresh()
            return true
        } catch {
            errorMessage = error.localizedDescription
            return false
        }
    }

    /// Apply an explicit review decision with a note (appended to the review log).
    @discardableResult
    public func reviewCorrelation(_ correlation: String, decision: CorrelationDecision, note: String) async -> Bool {
        guard let id = selectedWorkspaceId else { return false }
        do {
            _ = try await client.reviewCorrelation(workspace: id, correlation: correlation, decision: decision.rawValue, note: note)
            try await refresh()
            return true
        } catch {
            errorMessage = error.localizedDescription
            return false
        }
    }

    // MARK: Findings

    /// The currently selected finding in the Findings workbench.
    @Published public var selectedFindingId: String?

    /// Durable findings, newest first. Never created automatically.
    public var findings: [Finding] { snapshot?.findingsNewestFirst ?? [] }

    /// The selected finding (or the newest) from durable state.
    public var selectedFinding: Finding? {
        let all = findings
        if let id = selectedFindingId, let found = all.first(where: { $0.id == id }) { return found }
        return all.first
    }

    /// Create a durable finding. Returns the new finding's id on success.
    @discardableResult
    public func createFinding(_ new: NewFinding) async -> String? {
        guard let id = selectedWorkspaceId, !isBusy else { return nil }
        isBusy = true; defer { isBusy = false }
        do {
            let finding = try await client.createFinding(workspace: id, finding: new)
            guard selectedWorkspaceId == id else { return nil }
            try await refresh()
            guard selectedWorkspaceId == id else { return nil }
            selectedFindingId = finding.id
            return finding.id
        } catch {
            if selectedWorkspaceId == id { errorMessage = error.localizedDescription }
            return nil
        }
    }

    @discardableResult
    public func updateFinding(_ finding: String, edit: FindingEdit) async -> Bool {
        guard let id = selectedWorkspaceId, !isBusy else { return false }
        isBusy = true; defer { isBusy = false }
        do {
            _ = try await client.updateFinding(workspace: id, finding: finding, edit: edit)
            guard selectedWorkspaceId == id else { return false }
            try await refresh()
            guard selectedWorkspaceId == id else { return false }
            return true
        } catch {
            if selectedWorkspaceId == id { errorMessage = error.localizedDescription }
            return false
        }
    }

    @discardableResult
    public func setFindingStatus(_ finding: String, to status: FindingStatus, note: String) async -> Bool {
        guard let id = selectedWorkspaceId, !isBusy else { return false }
        isBusy = true; defer { isBusy = false }
        do {
            _ = try await client.setFindingStatus(workspace: id, finding: finding, status: status.rawValue, note: note)
            guard selectedWorkspaceId == id else { return false }
            try await refresh()
            guard selectedWorkspaceId == id else { return false }
            return true
        } catch {
            if selectedWorkspaceId == id { errorMessage = error.localizedDescription }
            return false
        }
    }

    @discardableResult
    public func linkFindingEvidence(_ finding: String, evidence: String) async -> Bool {
        guard let id = selectedWorkspaceId, !isBusy else { return false }
        isBusy = true; defer { isBusy = false }
        do {
            _ = try await client.linkFindingEvidence(workspace: id, finding: finding, evidence: evidence)
            guard selectedWorkspaceId == id else { return false }
            try await refresh()
            guard selectedWorkspaceId == id else { return false }
            return true
        } catch {
            if selectedWorkspaceId == id { errorMessage = error.localizedDescription }
            return false
        }
    }

    @discardableResult
    public func unlinkFindingEvidence(_ finding: String, evidence: String) async -> Bool {
        guard let id = selectedWorkspaceId, !isBusy else { return false }
        isBusy = true; defer { isBusy = false }
        do {
            _ = try await client.unlinkFindingEvidence(workspace: id, finding: finding, evidence: evidence)
            guard selectedWorkspaceId == id else { return false }
            try await refresh()
            guard selectedWorkspaceId == id else { return false }
            return true
        } catch {
            if selectedWorkspaceId == id { errorMessage = error.localizedDescription }
            return false
        }
    }

    /// Fetch the normalized, provenance-carrying result projection for a chain. Used by
    /// "Create Finding from a result" to prefill factual references (never console text).
    public func resultProjection(chain: String) async -> ResultProjection? {
        guard let id = selectedWorkspaceId else { return nil }
        do {
            let result = try await client.resultProjection(workspace: id, chain: chain)
            guard selectedWorkspaceId == id, !Task.isCancelled else { return nil }
            guard result.workspaceId == id, result.chainId == chain else {
                throw CoreFailure(code: "InvalidResponse", message: "Results do not match the selected run.")
            }
            return result
        } catch {
            if selectedWorkspaceId == id { errorMessage = error.localizedDescription }
            return nil
        }
    }

    /// A `NewFinding` prefilled with ONLY the factual references from a selected result
    /// item: affected asset, supporting evidence, and source provider/run. The analyst
    /// supplies the title, severity, confidence, and conclusion text.
    public func draftFinding(from item: ResultItem) -> NewFinding {
        var draft = NewFinding()
        draft.primaryAssetId = item.assetId
        if let evidence = item.evidenceId { draft.evidenceIds = [evidence] }
        draft.sourceProvider = item.providerId ?? item.discoveredBy
        draft.sourceRunId = item.runId
        draft.status = .open
        return draft
    }

    /// Pending prefilled draft handed from a result context to the Findings editor.
    @Published public var pendingFindingDraft: NewFinding?
    /// A chain whose normalized results the Findings workbench should open a
    /// "Create Finding from a result" picker for (set from Recon/OSINT).
    @Published public var pendingFindingChainId: String?
    /// A typed selection the Findings workbench should deterministically draft from and
    /// open the editor already populated (set from the result picker or an asset action).
    @Published public var pendingDraftContext: FindingDraftContext?

    /// Begin "Create Finding" from a result item: prefill references and open Findings.
    public func beginFinding(from item: ResultItem) {
        pendingFindingDraft = draftFinding(from: item)
        section = .findings
    }

    /// Begin "Create Finding" from a completed chain: open Findings and let the analyst
    /// pick which normalized result items to base the finding on.
    public func beginFinding(fromChain chain: String) {
        pendingFindingChainId = chain
        section = .findings
    }

    /// Begin "Create Finding" directly from one durable result, bypassing the selection
    /// picker: the core drafts from exactly that observation (within its run, for run
    /// context) and the editor opens already populated. One shared path — result views
    /// only build the typed context, never their own draft logic.
    public func beginFinding(result observationId: String, inRun chainId: String?) {
        pendingDraftContext = FindingDraftContext(runId: chainId, observationIds: [observationId])
        section = .findings
    }

    /// Begin "Create Finding" from a single asset: the core drafts a factual informational
    /// finding for it and the editor opens already populated.
    public func beginFinding(fromAsset assetId: String) {
        pendingDraftContext = FindingDraftContext(assetIds: [assetId])
        section = .findings
    }

    /// Console lines for the selected OSINT run.
    public var osintConsoleLines: [ConsoleLine] {
        guard let snapshot, let chain = selectedOSINTChainId else { return [] }
        return reconConsoleLines(snapshot: snapshot, chainId: chain)
    }

    public var userScanner: ProviderStatus? { provider("user_scanner") }

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
