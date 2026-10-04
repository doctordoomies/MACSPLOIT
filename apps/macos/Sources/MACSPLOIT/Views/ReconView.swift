import AppKit
import SwiftUI
import MACSPLOITKit

enum ReconMode: String, CaseIterable, Identifiable {
    case synthetic = "Synthetic Recon"
    case dns = "DNS Recon"
    case domain = "Domain Recon"
    case ip = "IP Recon"
    case web = "Web Recon"
    case webAnalysis = "Web Analysis"
    case contentDiscovery = "Content Discovery"

    var id: String { rawValue }

    var chainKind: String {
        switch self {
        case .synthetic: return "synthetic"
        case .dns: return "dns_recon"
        case .domain: return "domain_recon"
        case .ip: return "ip_recon"
        case .web: return "web_recon"
        case .webAnalysis: return "web_analysis"
        case .contentDiscovery: return "content_discovery"
        }
    }

    /// Live workflows perform network activity and show the authorization reminder.
    var isLive: Bool { self != .synthetic }

    var icon: String {
        switch self {
        case .synthetic: return "theatermasks"
        case .dns: return "globe"
        case .domain: return "network"
        case .ip: return "number"
        case .web: return "safari"
        case .webAnalysis: return "doc.text.magnifyingglass"
        case .contentDiscovery: return "folder.badge.questionmark"
        }
    }

    var purpose: String {
        switch self {
        case .synthetic: return "Synthetic demo using invented discoveries. Performs no network activity."
        case .dns: return "Built-in A/AAAA resolution for a domain or hostname."
        case .domain: return "Subdomains → DNS → ports/services → HTTP probing."
        case .ip: return "Ports/services → HTTP probing for one selected IP. No DNS required."
        case .web: return "Bounded same-host crawling from an in-scope URL."
        case .webAnalysis: return "Headers, cookies, CORS, redirects, robots for a URL."
        case .contentDiscovery: return "Bounded path discovery (ffuf) with a chosen wordlist."
        }
    }

    var subtitle: String { purpose }

    var badge: String {
        switch self {
        case .synthetic: return "PASSIVE · SYNTHETIC"
        case .dns, .web, .webAnalysis: return "ACTIVE · LOW"
        case .domain: return "MIXED · DOMAIN"
        case .ip: return "MIXED · IP"
        case .contentDiscovery: return "ACTIVE"
        }
    }

    var targetRequirement: String {
        switch self {
        case .synthetic: return "the demo domain example.test"
        case .dns: return "a Domain or Hostname target"
        case .domain: return "a Domain target"
        case .ip: return "an IPAddress target"
        case .web, .webAnalysis, .contentDiscovery: return "an HTTP(S) URL target"
        }
    }
}

struct ReconView: View {
    @ObservedObject var model: WorkspaceModel
    @State private var mode: ReconMode = .synthetic
    @State private var showAuthorizeDialog = false
    @State private var consoleExpanded = true

    // MARK: Selection & readiness

    private var selectedTarget: Target? {
        model.snapshot?.targets.first { $0.id == model.selectedTargetId }
    }
    private var selectedTargetIsLocal: Bool { selectedTarget?.isLocalOrPrivateHost ?? false }

    private var subfinderReady: Bool { model.subfinder?.installation.isAvailable ?? false }
    private var nmapReady: Bool { model.nmap?.installation.isAvailable ?? false }
    private var httpxReady: Bool { model.httpx?.installation.isAvailable ?? false }
    private var katanaReady: Bool { model.katana?.installation.isAvailable ?? false }
    private var ffufReady: Bool { model.ffuf?.installation.isAvailable ?? false }

    private func providersReady(for mode: ReconMode) -> Bool {
        switch mode {
        case .synthetic, .dns, .webAnalysis: return true // built in
        case .domain: return subfinderReady && nmapReady && httpxReady
        case .ip: return nmapReady && httpxReady
        case .web: return katanaReady
        case .contentDiscovery: return ffufReady
        }
    }

    private func readinessLabel(for mode: ReconMode) -> String {
        switch mode {
        case .synthetic, .dns, .webAnalysis: return "Built in"
        default: return providersReady(for: mode) ? "Providers ready" : "Setup needed"
        }
    }

    private var selectedTargetIsCompatible: Bool {
        guard let target = selectedTarget else { return false }
        switch mode {
        case .synthetic: return target.targetType == "Domain" && target.normalizedValue == "example.test"
        case .dns: return ["Domain", "Hostname"].contains(target.targetType)
        case .domain: return target.targetType == "Domain"
        case .ip: return target.targetType == "IPAddress"
        case .web, .webAnalysis, .contentDiscovery: return target.targetType == "URL"
        }
    }

    /// Everything except authorization: a Run can still begin the authorization flow.
    private var otherPrerequisitesMet: Bool {
        selectedTargetIsCompatible
            && providerSetupIssue == nil
            && (mode != .contentDiscovery || model.selectedWordlistPath != nil)
    }

    private var noRunningChain: Bool { model.snapshot?.chains.contains(where: \.isRunning) != true }

    private var canAttemptRun: Bool {
        model.isConnected && !model.isBusy && noRunningChain && otherPrerequisitesMet
    }

    private var authorized: Bool { model.scopeStatus?.authorized ?? false }

    private var providerSetupIssue: String? {
        switch mode {
        case .domain:
            var missing: [String] = []
            if !subfinderReady { missing.append("Subfinder") }
            if !nmapReady { missing.append("Nmap") }
            if !httpxReady { missing.append("HTTPX") }
            guard !missing.isEmpty else { return nil }
            return "Domain Recon needs a compatible executable for: \(missing.joined(separator: ", ")). Open Provider Center for setup details."
        case .ip:
            var missing: [String] = []
            if !nmapReady { missing.append("Nmap") }
            if !httpxReady { missing.append("HTTPX") }
            guard !missing.isEmpty else { return nil }
            return "IP Recon needs a compatible executable for: \(missing.joined(separator: ", ")). Open Provider Center for setup details."
        case .web:
            return katanaReady ? nil : "Web Recon needs a compatible Katana executable. Open Provider Center for setup details."
        case .contentDiscovery:
            return ffufReady ? nil : "Content Discovery needs a compatible ffuf executable. Open Provider Center for setup details."
        case .synthetic, .dns, .webAnalysis:
            return nil
        }
    }

    // MARK: Body

    var body: some View {
        WorkbenchPage(maxWidth: 1200) {
            VStack(alignment: .leading, spacing: 22) {
                PageHeading(title: "Recon", subtitle: "Choose a workflow, select an authorized target, and run. Clean by default — detail on demand.")
                workflowGrid
                Divider()
                executionPanel
                liveConsole
                chainDetail
                runHistory
            }
        }
        .sheet(isPresented: $showAuthorizeDialog) { authorizeDialog }
        .task(id: model.selectedTargetId) { await model.refreshScopeStatus() }
        .task(id: model.snapshot?.workspace.scope ?? []) { await model.refreshScopeStatus() }
    }

    // MARK: Workflow cards

    private var workflowGrid: some View {
        LazyVGrid(columns: [GridItem(.adaptive(minimum: 250), spacing: 14)], spacing: 14) {
            ForEach(ReconMode.allCases) { workflow in
                workflowCard(workflow)
            }
        }
    }

    private func workflowCard(_ workflow: ReconMode) -> some View {
        let selected = workflow == mode
        return Button {
            mode = workflow
        } label: {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Image(systemName: workflow.icon).font(.title3).foregroundStyle(selected ? Color.accentColor : .secondary)
                    Spacer()
                    RiskBadge(risk: workflow.badge)
                }
                Text(workflow.rawValue).font(.headline)
                Text(workflow.purpose).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 6) {
                    Circle().fill(providersReady(for: workflow) ? Color.green : Color.secondary).frame(width: 6, height: 6)
                    Text(readinessLabel(for: workflow)).font(.caption2).foregroundStyle(.secondary)
                }
            }
            .padding(14)
            .frame(maxWidth: .infinity, minHeight: 118, alignment: .topLeading)
            .background((selected ? Color.accentColor.opacity(0.10) : Color.gray.opacity(0.12)),
                        in: RoundedRectangle(cornerRadius: 12))
            .overlay(RoundedRectangle(cornerRadius: 12).stroke(selected ? Color.accentColor : Color.gray.opacity(0.4), lineWidth: selected ? 1.5 : 1))
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(selected ? [.isSelected] : [])
    }

    // MARK: Execution panel

    private var executionPanel: some View {
        WorkbenchCard {
            VStack(alignment: .leading, spacing: 16) {
                HStack(alignment: .firstTextBaseline) {
                    VStack(alignment: .leading, spacing: 3) {
                        Text(mode.rawValue).font(.title3.weight(.semibold))
                        Text(mode.purpose).font(.callout).foregroundStyle(.secondary)
                    }
                    Spacer()
                    if selectedTargetIsLocal {
                        Text("LOCAL TARGET").font(.system(.caption2, design: .monospaced))
                            .padding(.horizontal, 6).padding(.vertical, 2)
                            .background(Color.secondary.opacity(0.18), in: Capsule()).foregroundStyle(.secondary)
                            .help("Local/private by classification only — not an authorization or safety claim.")
                    }
                    RiskBadge(risk: mode.badge)
                }

                targetRow
                authorizationRow
                providerPanel

                if mode == .contentDiscovery { wordlistRow }

                HStack(spacing: 12) {
                    Button(action: attemptRun) {
                        Label(runButtonTitle, systemImage: "play.fill")
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(!canAttemptRun)
                    if model.selectedChain?.isRunning == true {
                        Button("Cancel") { Task { await model.cancelRecon() } }
                    }
                    Spacer()
                    Text(mode.badge).font(.system(.caption2, design: .monospaced)).foregroundStyle(.secondary)
                }

                runHint
                if mode.isLive { AuthorizationReminder() }
            }
        }
    }

    private var runButtonTitle: String {
        if mode.isLive && !authorized && otherPrerequisitesMet { return "Authorize & Run \(mode.rawValue)" }
        return "Run \(mode.rawValue)"
    }

    private var targetRow: some View {
        HStack(spacing: 12) {
            Text("Target").font(.callout.weight(.medium)).frame(width: 90, alignment: .leading)
            Picker("Target", selection: $model.selectedTargetId) {
                Text("Choose a target").tag(String?.none)
                ForEach(model.snapshot?.targets ?? []) {
                    Text("\($0.normalizedValue)  ·  \($0.targetType)").tag(Optional($0.id))
                }
            }
            .labelsHidden()
            .frame(maxWidth: 420)
            Spacer()
        }
    }

    @ViewBuilder private var authorizationRow: some View {
        HStack(spacing: 12) {
            Text("Authorization").font(.callout.weight(.medium)).frame(width: 90, alignment: .leading)
            AuthorizationBadge(authorized: authorized, noNetwork: !mode.isLive)
            Spacer()
        }
    }

    // MARK: Authorize & Run dialog

    private var authorizeDialog: some View {
        let entry = model.scopeStatus?.requiredScopeEntry ?? selectedTarget?.normalizedValue ?? "this target"
        return VStack(alignment: .leading, spacing: 16) {
            Label("Authorize Target", systemImage: "exclamationmark.shield").font(.title2.weight(.semibold))
            Text("\(selectedTarget?.normalizedValue ?? "The target") is not currently included in this workspace's authorized scope.")
                .foregroundStyle(.secondary)
            Text("By continuing, you confirm that you own this system or have explicit permission to assess it.")
                .foregroundStyle(.secondary)
            Text("MACSPLOIT will add only the required exact entry — \(entry) — to this workspace's scope before starting.")
                .font(.callout)
            HStack {
                Spacer()
                Button("Cancel") { showAuthorizeDialog = false }.keyboardShortcut(.cancelAction)
                Button("Authorize & Run") {
                    showAuthorizeDialog = false
                    Task { await model.authorizeAndRun(kind: mode.chainKind, options: contentOptions) }
                }
                .buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)
            }
        }
        .padding(26).frame(width: 460)
    }

    private var contentOptions: JSONValue {
        if mode == .contentDiscovery, let path = model.selectedWordlistPath {
            return .object(["wordlist_path": .string(path)])
        }
        return .object([:])
    }

    // MARK: Run

    private func attemptRun() {
        if let providerSetupIssue {
            model.errorMessage = providerSetupIssue
            return
        }
        if mode.isLive && !authorized {
            showAuthorizeDialog = true
            return
        }
        if mode == .contentDiscovery {
            Task { await model.runContentDiscovery() }
        } else {
            // Synthetic may still need its demo entry in scope; authorize-if-needed
            // silently (offline, no live-network confirmation).
            Task { await model.authorizeAndRun(kind: mode.chainKind) }
        }
    }

    private func chooseWordlist() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.message = "Choose a wordlist for Content Discovery (≤ 500 entries, ≤ 1 MiB)."
        if panel.runModal() == .OK, let url = panel.url { model.chooseWordlist(url.path) }
    }

    // MARK: Provider panels (compact, reused per workflow)

    private struct ProviderRowData: Identifiable {
        let id = UUID()
        let name: String, detail: String, available: Bool, status: String, risk: String, warn: Bool
    }

    @ViewBuilder private var providerPanel: some View {
        switch mode {
        case .synthetic:
            Text("Synthetic demo — no external providers and no network activity.")
                .font(.caption).foregroundStyle(.secondary)
        case .dns:
            providerList([ProviderRowData(name: "Native DNS Resolver", detail: "A + AAAA resolution (system resolver)", available: model.nativeDns?.installation.isAvailable ?? true, status: model.nativeDns?.installation.summary ?? "Built in", risk: "ACTIVE · LOW", warn: false)])
        case .domain:
            providerList([
                ProviderRowData(name: "Subfinder", detail: "Subdomain discovery · passive", available: subfinderReady, status: model.subfinder?.installation.summary ?? "", risk: "PASSIVE", warn: false),
                ProviderRowData(name: "Native DNS", detail: "DNS resolution", available: model.nativeDns?.installation.isAvailable ?? true, status: "Built in", risk: "ACTIVE · LOW", warn: false),
                ProviderRowData(name: "Nmap", detail: "Port + service discovery", available: nmapReady, status: model.nmap?.installation.summary ?? "", risk: "ACTIVE", warn: true),
                ProviderRowData(name: "HTTPX", detail: "HTTP probing", available: httpxReady, status: model.httpx?.installation.summary ?? "", risk: "ACTIVE · LOW", warn: false),
            ])
        case .ip:
            providerList([
                ProviderRowData(name: "Nmap", detail: "Port + service discovery", available: nmapReady, status: model.nmap?.installation.summary ?? "", risk: "ACTIVE", warn: true),
                ProviderRowData(name: "HTTPX", detail: "HTTP probing", available: httpxReady, status: model.httpx?.installation.summary ?? "", risk: "ACTIVE · LOW", warn: false),
            ])
        case .web:
            providerList([ProviderRowData(name: "Katana", detail: "Same-host crawling · depth 2", available: katanaReady, status: model.katana?.installation.summary ?? "", risk: "ACTIVE · LOW", warn: false)])
        case .webAnalysis:
            providerList([ProviderRowData(name: "Native HTTP Analysis", detail: "Headers · cookies · CORS · redirects · robots", available: model.nativeHttp?.installation.isAvailable ?? true, status: model.nativeHttp?.installation.summary ?? "Built in", risk: "ACTIVE · LOW", warn: false)])
        case .contentDiscovery:
            providerList([ProviderRowData(name: "ffuf", detail: "Bounded path discovery · ≤ 500 · no recursion", available: ffufReady, status: model.ffuf?.installation.summary ?? "", risk: "ACTIVE", warn: true)])
        }
    }

    private func providerList(_ rows: [ProviderRowData]) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Providers").font(.callout.weight(.medium))
                Spacer()
                Button { Task { await model.refreshProviders() } } label: { Label("Refresh", systemImage: "arrow.clockwise") }
                    .controlSize(.small)
                Button("Provider Center") { model.section = .toolManager }.controlSize(.small)
            }
            ForEach(Array(rows.enumerated()), id: \.offset) { _, row in
                HStack(spacing: 10) {
                    Image(systemName: row.available ? "checkmark.seal.fill" : "exclamationmark.triangle.fill")
                        .foregroundStyle(row.available ? Color.green : Color.orange)
                    Text(row.name).font(.callout)
                    Text(row.risk).font(.system(.caption2, design: .monospaced))
                        .padding(.horizontal, 5).padding(.vertical, 1)
                        .background((row.warn ? Color.orange : Color.gray).opacity(0.16), in: Capsule())
                        .foregroundStyle(row.warn ? Color.orange : Color.secondary)
                    Spacer()
                    Text(row.available ? row.status : "Not detected").font(.caption.monospaced())
                        .foregroundStyle(row.available ? Color.secondary : Color.orange)
                }
            }
        }
        .padding(12)
        .background(Color.primary.opacity(0.035), in: RoundedRectangle(cornerRadius: 10))
    }

    private var wordlistRow: some View {
        HStack(spacing: 12) {
            Image(systemName: model.selectedWordlistPath == nil ? "doc.badge.plus" : "doc.text")
                .foregroundStyle(model.selectedWordlistPath == nil ? Color.orange : Color.secondary)
            VStack(alignment: .leading, spacing: 3) {
                Text("Wordlist").font(.callout.weight(.medium))
                Text((model.selectedWordlistPath as NSString?)?.lastPathComponent ?? "None selected")
                    .font(.caption.monospaced())
                    .foregroundStyle(model.selectedWordlistPath == nil ? Color.orange : Color.secondary)
                if let n = model.wordlistEstimatedRequests {
                    Text("Estimated maximum requests: \(n)").font(.caption).foregroundStyle(.secondary)
                }
            }
            Spacer()
            Button("Choose Wordlist…", action: chooseWordlist)
        }
        .padding(12)
        .background(Color.primary.opacity(0.035), in: RoundedRectangle(cornerRadius: 10))
    }

    // MARK: Live console

    @ViewBuilder private var liveConsole: some View {
        let lines = model.consoleLines
        DisclosureGroup(isExpanded: $consoleExpanded) {
            if lines.isEmpty {
                Text("No execution output yet. Run a workflow to see live provider activity.")
                    .font(.callout).foregroundStyle(.secondary).padding(.vertical, 6)
            } else {
                ScrollViewReader { proxy in
                    ScrollView {
                        VStack(alignment: .leading, spacing: 2) {
                            ForEach(lines) { line in
                                HStack(alignment: .top, spacing: 10) {
                                    Text(line.clock).foregroundStyle(.tertiary)
                                    Text(line.label).foregroundStyle(line.label == "$" ? Color.cyan : .secondary)
                                        .frame(width: line.label == "$" ? 12 : 92, alignment: .leading)
                                    Text(line.detail).foregroundStyle(.primary).textSelection(.enabled)
                                    Spacer(minLength: 0)
                                }
                                .id(line.id)
                            }
                        }
                        .font(.system(.caption, design: .monospaced))
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(10)
                    }
                    .frame(height: 170)
                    .background(Color.black.opacity(0.22), in: RoundedRectangle(cornerRadius: 8))
                    .onChange(of: lines.count) { _ in
                        if let last = lines.last { withAnimation { proxy.scrollTo(last.id, anchor: .bottom) } }
                    }
                }
                HStack {
                    Spacer()
                    Button("View evidence") { model.section = .evidence }.controlSize(.small)
                    Button("View activity") { model.section = .activity }.controlSize(.small)
                }
            }
        } label: {
            Label("Live console", systemImage: "terminal").font(.callout.weight(.medium))
        }
    }

    // MARK: Chain detail + history

    @ViewBuilder private var chainDetail: some View {
        if let chain = model.selectedChain {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Text(chain.name).font(.headline)
                    Text(String(chain.id.prefix(8))).foregroundStyle(.secondary).font(.caption)
                    Text(displayTime(chain.createdAt)).foregroundStyle(.secondary).font(.caption)
                    Spacer()
                    StatusBadge(status: chain.status)
                }
                let stages = (model.snapshot?.stages ?? []).filter { $0.chainId == chain.id }.sorted { $0.position < $1.position }
                VStack(spacing: 0) {
                    ForEach(stages) { stage in
                        HStack(spacing: 14) {
                            stageSymbol(stage.status).frame(width: 24, height: 24)
                            VStack(alignment: .leading, spacing: 3) {
                                Text(stage.name).font(.callout.weight(.medium))
                                if let provider = stage.providerId {
                                    Text(provider.uppercased()).font(.caption2.monospaced()).foregroundStyle(.secondary)
                                }
                            }
                            Spacer()
                            StatusBadge(status: stage.status)
                        }
                        .padding(.vertical, 10).padding(.horizontal, 14)
                        if stage.id != stages.last?.id { Divider().padding(.leading, 52) }
                    }
                }
                .background(Color.primary.opacity(0.03), in: RoundedRectangle(cornerRadius: 10))
                if let code = chain.errorCode {
                    Label(code, systemImage: "exclamationmark.triangle").foregroundStyle(.orange)
                }
            }
        }
    }

    @ViewBuilder private var runHistory: some View {
        if let chains = model.snapshot?.chains, chains.count > 1 {
            VStack(alignment: .leading, spacing: 6) {
                Text("Run history").font(.headline)
                ForEach(chains.reversed()) { chain in
                    Button { model.selectedChainId = chain.id } label: {
                        HStack {
                            Text(chain.name).frame(width: 140, alignment: .leading)
                            Text(displayTime(chain.createdAt)).foregroundStyle(.secondary)
                            Text(String(chain.id.prefix(8))).foregroundStyle(.tertiary)
                            Spacer()
                            StatusBadge(status: chain.status)
                        }
                    }
                    .buttonStyle(.plain).padding(.vertical, 4)
                }
            }
        }
    }

    // MARK: Hints

    @ViewBuilder private var runHint: some View {
        if model.snapshot?.targets.isEmpty != false {
            Text(emptyTargetHint).font(.callout).foregroundStyle(.secondary)
        } else if let target = selectedTarget, !selectedTargetIsCompatible {
            VStack(alignment: .leading, spacing: 8) {
                Text(incompatibleTargetHint(target)).font(.callout).foregroundStyle(.secondary)
                if matchesWebMode, ["Domain", "Hostname"].contains(target.targetType) {
                    Button {
                        Task { _ = await model.addTarget(value: "https://\(target.normalizedValue)/") }
                    } label: { Label("Add HTTPS URL target for \(target.normalizedValue)", systemImage: "link.badge.plus") }
                        .controlSize(.small)
                }
            }
        } else if let providerSetupIssue {
            Text(providerSetupIssue).font(.callout).foregroundStyle(.orange).textSelection(.enabled)
        } else if mode == .contentDiscovery && model.selectedWordlistPath == nil {
            Text("Choose a wordlist before running Content Discovery.").font(.callout).foregroundStyle(.orange)
        }
    }

    private var matchesWebMode: Bool { mode == .web || mode == .webAnalysis || mode == .contentDiscovery }

    private var emptyTargetHint: String {
        switch mode {
        case .synthetic: return "Add example.test using the target bar above."
        case .dns: return "Add an in-scope domain or hostname using the target bar above."
        case .domain: return "Add an in-scope domain using the target bar above."
        case .ip: return "Add an explicitly authorized IPv4 or IPv6 address using the target bar above."
        case .web, .webAnalysis, .contentDiscovery:
            return "Add an HTTP(S) URL using the target bar above — public (https://your-domain.example/) or local (http://localhost:3000). No public DNS is required."
        }
    }

    private func incompatibleTargetHint(_ target: Target) -> String {
        "\(mode.rawValue) requires \(mode.targetRequirement); the selected target is \(target.targetType)."
    }

    @ViewBuilder private func stageSymbol(_ status: String) -> some View {
        if status == "RUNNING" { ProgressView().controlSize(.small) }
        else if status == "COMPLETED" { Image(systemName: "checkmark.circle.fill").foregroundStyle(.green) }
        else if ["FAILED", "CANCELLED"].contains(status) { Image(systemName: "xmark.circle").foregroundStyle(.orange) }
        else { Image(systemName: "circle").foregroundStyle(.tertiary) }
    }
}
