import AppKit
import SwiftUI
import MACSPLOITKit

private enum ReconMode: String, CaseIterable, Identifiable {
    case synthetic = "Synthetic Recon"
    case dns = "DNS Recon"
    case domain = "Domain Recon"
    case web = "Web Recon"
    case webAnalysis = "Web Analysis"

    var id: String { rawValue }

    var chainKind: String {
        switch self {
        case .synthetic: return "synthetic"
        case .dns: return "dns_recon"
        case .domain: return "domain_recon"
        case .web: return "web_recon"
        case .webAnalysis: return "web_analysis"
        }
    }

    var subtitle: String {
        switch self {
        case .synthetic:
            return "Offline demo using invented discoveries. No network activity."
        case .dns:
            return "Built-in A/AAAA resolution for an in-scope domain or hostname. No external tool required."
        case .domain:
            return "Subdomains → DNS → ports/services → HTTP probing for an in-scope domain."
        case .web:
            return "Bounded same-host crawling from an explicitly selected in-scope HTTP(S) URL."
        case .webAnalysis:
            return "Built-in HTTP analysis of an in-scope URL: headers, cookies, CORS, redirects, robots."
        }
    }

    var badge: String {
        switch self {
        case .synthetic: return "PASSIVE · SYNTHETIC"
        case .dns, .web, .webAnalysis: return "ACTIVE · LOW"
        case .domain: return "MIXED · DOMAIN"
        }
    }
}

struct ReconView: View {
    @ObservedObject var model: WorkspaceModel
    @State private var mode: ReconMode = .synthetic

    private var selectedTarget: Target? {
        model.snapshot?.targets.first { $0.id == model.selectedTargetId }
    }

    private var subfinderReady: Bool { model.subfinder?.installation.isAvailable ?? false }
    private var nmapReady: Bool { model.nmap?.installation.isAvailable ?? false }
    private var httpxReady: Bool { model.httpx?.installation.isAvailable ?? false }
    private var katanaReady: Bool { model.katana?.installation.isAvailable ?? false }

    private var selectedTargetIsCompatible: Bool {
        guard let target = selectedTarget else { return false }
        switch mode {
        case .synthetic:
            return target.targetType == "Domain" && target.normalizedValue == "example.test"
        case .dns:
            return ["Domain", "Hostname"].contains(target.targetType)
        case .domain:
            return target.targetType == "Domain"
        case .web, .webAnalysis:
            return target.targetType == "URL"
        }
    }

    private var canAttemptRun: Bool {
        model.isConnected
            && !model.isBusy
            && model.snapshot?.chains.contains(where: \.isRunning) != true
            && selectedTargetIsCompatible
    }

    private var providerSetupIssue: String? {
        switch mode {
        case .domain:
            var missing: [String] = []
            if !subfinderReady { missing.append("Subfinder (brew install subfinder)") }
            if !nmapReady { missing.append("Nmap (brew install nmap)") }
            if !httpxReady { missing.append("HTTPX (brew install httpx)") }
            guard !missing.isEmpty else { return nil }
            return "Domain Recon needs these external providers before it can complete:\n\n" + missing.joined(separator: "\n") + "\n\nInstall them, then click Refresh Providers."
        case .web:
            return katanaReady ? nil : "Web Recon needs Katana. Install it with:\n\nbrew install katana\n\nThen click Refresh Providers."
        case .synthetic, .dns, .webAnalysis:
            return nil
        }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                PageHeading(title: mode.rawValue, subtitle: mode.subtitle)

                Picker("Recon", selection: $mode) {
                    ForEach(ReconMode.allCases) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented)
                .frame(maxWidth: 560)

                if mode == .dns {
                    dnsProviderPanel
                } else if mode == .domain {
                    domainProviderPanel
                } else if mode == .web {
                    webProviderPanel
                } else if mode == .webAnalysis {
                    webAnalysisProviderPanel
                }

                HStack(spacing: 14) {
                    Picker("Target", selection: $model.selectedTargetId) {
                        Text("Choose a target").tag(String?.none)
                        ForEach(model.snapshot?.targets ?? []) {
                            Text("\($0.normalizedValue)  ·  \($0.targetType)").tag(Optional($0.id))
                        }
                    }
                    .frame(maxWidth: 460)

                    Button(action: runSelectedMode) {
                        Label("Run", systemImage: "play.fill")
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(!canAttemptRun)

                    if model.selectedChain?.isRunning == true {
                        Button("Cancel") { Task { await model.cancelRecon() } }
                    }

                    Spacer()
                    Text(mode.badge)
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(.secondary)
                }

                runHint

                if let chain = model.selectedChain {
                    HStack {
                        Text(chain.name).font(.headline)
                        Text(String(chain.id.prefix(8))).foregroundStyle(.secondary).font(.caption)
                        Text(displayTime(chain.createdAt)).foregroundStyle(.secondary).font(.caption)
                        Spacer()
                        StatusBadge(status: chain.status)
                    }

                    VStack(spacing: 0) {
                        let stages = (model.snapshot?.stages ?? [])
                            .filter { $0.chainId == chain.id }
                            .sorted { $0.position < $1.position }
                        ForEach(stages) { stage in
                            HStack(spacing: 16) {
                                stageSymbol(stage.status).frame(width: 28, height: 28)
                                VStack(alignment: .leading, spacing: 5) {
                                    Text(stage.name).font(.body.weight(.medium))
                                    if let provider = stage.providerId {
                                        Text(provider.uppercased())
                                            .font(.caption2.monospaced())
                                            .foregroundStyle(.secondary)
                                    } else if let capability = stage.capability {
                                        Text(capability)
                                            .font(.caption2.monospaced())
                                            .foregroundStyle(.secondary)
                                    }
                                }
                                Spacer()
                                StatusBadge(status: stage.status)
                            }
                            .padding(18)

                            if stage.id != stages.last?.id {
                                Divider().padding(.leading, 60)
                            }
                        }
                    }
                    .background(Color.primary.opacity(0.035), in: RoundedRectangle(cornerRadius: 10))

                    if let code = chain.errorCode {
                        Label(code, systemImage: "exclamationmark.triangle")
                            .foregroundStyle(.orange)
                    }

                    HStack {
                        Button("View assets") { model.section = .assets }
                        Button("View evidence") { model.section = .evidence }
                        Button("View activity") { model.section = .activity }
                    }
                } else {
                    EmptyMessage(
                        title: "Choose a target and run a workflow",
                        detail: "MACSPLOIT records provider runs, evidence, discoveries, relationships, and durable events in this workspace.",
                        symbol: "point.3.connected.trianglepath.dotted"
                    )
                    .frame(minHeight: 220)
                }

                if let chains = model.snapshot?.chains, chains.count > 1 {
                    Divider()
                    Text("Run history").font(.headline)
                    ForEach(chains.reversed()) { chain in
                        Button { model.selectedChainId = chain.id } label: {
                            HStack {
                                Text(chain.name).frame(width: 130, alignment: .leading)
                                Text(displayTime(chain.createdAt))
                                Text(String(chain.id.prefix(8))).foregroundStyle(.secondary)
                                Spacer()
                                StatusBadge(status: chain.status)
                            }
                        }
                        .buttonStyle(.plain)
                        .padding(.vertical, 5)
                    }
                }
            }
            .padding(26)
        }
    }

    private func runSelectedMode() {
        if let providerSetupIssue {
            model.errorMessage = providerSetupIssue
            return
        }
        Task { await model.runRecon(kind: mode.chainKind) }
    }

    @ViewBuilder private var dnsProviderPanel: some View {
        VStack(spacing: 10) {
            providerHeader("No external installation required")
            Divider()
            providerRow(
                title: "Native DNS Resolver",
                detail: "A + AAAA resolution using the system resolver",
                available: model.nativeDns?.installation.isAvailable ?? true,
                status: model.nativeDns?.installation.summary ?? "Built in",
                risk: "ACTIVE · LOW"
            )
        }
        .padding(14)
        .background(Color.primary.opacity(0.035), in: RoundedRectangle(cornerRadius: 10))
    }

    @ViewBuilder private var domainProviderPanel: some View {
        VStack(spacing: 10) {
            providerHeader("Domain Recon uses external tools plus the built-in DNS resolver")
            Divider()
            providerRow(
                title: "Subfinder",
                detail: "Subdomain Discovery · Passive",
                available: subfinderReady,
                status: model.subfinder?.installation.summary ?? "Provider status unavailable",
                installCommand: "brew install subfinder"
            )
            Divider()
            providerRow(
                title: "Native DNS Resolver",
                detail: "DNS Resolution",
                available: model.nativeDns?.installation.isAvailable ?? true,
                status: model.nativeDns?.installation.summary ?? "Built in",
                risk: "ACTIVE · LOW"
            )
            Divider()
            providerRow(
                title: "Nmap",
                detail: "Port + Service Discovery",
                available: nmapReady,
                status: model.nmap?.installation.summary ?? "Provider status unavailable",
                risk: "ACTIVE",
                warn: true,
                installCommand: "brew install nmap"
            )
            Divider()
            providerRow(
                title: "HTTPX",
                detail: "HTTP Probing",
                available: httpxReady,
                status: model.httpx?.installation.summary ?? "Provider status unavailable",
                risk: "ACTIVE · LOW",
                installCommand: "brew install httpx"
            )
        }
        .padding(14)
        .background(Color.primary.opacity(0.035), in: RoundedRectangle(cornerRadius: 10))
    }

    @ViewBuilder private var webProviderPanel: some View {
        VStack(spacing: 10) {
            providerHeader("Web Recon uses Katana")
            Divider()
            providerRow(
                title: "Katana",
                detail: "Same-host Web Crawling · depth 2 · 20s crawl budget",
                available: katanaReady,
                status: model.katana?.installation.summary ?? "Provider status unavailable",
                risk: "ACTIVE · LOW",
                installCommand: "brew install katana"
            )
        }
        .padding(14)
        .background(Color.primary.opacity(0.035), in: RoundedRectangle(cornerRadius: 10))
    }

    @ViewBuilder private var webAnalysisProviderPanel: some View {
        VStack(spacing: 10) {
            providerHeader("No external installation required")
            Divider()
            providerRow(
                title: "Native HTTP Analysis",
                detail: "Headers · Cookies · CORS · Redirects · robots.txt",
                available: model.nativeHttp?.installation.isAvailable ?? true,
                status: model.nativeHttp?.installation.summary ?? "Built in",
                risk: "ACTIVE · LOW"
            )
        }
        .padding(14)
        .background(Color.primary.opacity(0.035), in: RoundedRectangle(cornerRadius: 10))
    }

    @ViewBuilder private func providerHeader(_ text: String) -> some View {
        HStack {
            Text(text).font(.caption).foregroundStyle(.secondary)
            Spacer()
            Button {
                Task { await model.refreshProviders() }
            } label: {
                Label("Refresh Providers", systemImage: "arrow.clockwise")
            }
            .controlSize(.small)
        }
    }

    @ViewBuilder
    private func providerRow(
        title: String,
        detail: String,
        available: Bool,
        status: String,
        risk: String = "PASSIVE",
        warn: Bool = false,
        installCommand: String? = nil
    ) -> some View {
        HStack(spacing: 12) {
            Image(systemName: available ? "checkmark.seal.fill" : "exclamationmark.triangle.fill")
                .foregroundStyle(available ? .green : .orange)

            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 8) {
                    Text("Provider: \(title)").font(.body.weight(.medium))
                    Text(risk)
                        .font(.system(.caption2, design: .monospaced).weight(.bold))
                        .padding(.horizontal, 6)
                        .padding(.vertical, 1)
                        .background((warn ? Color.orange : Color.secondary).opacity(0.18), in: Capsule())
                        .foregroundStyle(warn ? Color.orange : Color.secondary)
                }

                Text("Capability: \(detail)")
                    .font(.caption)
                    .foregroundStyle(.secondary)

                Text(status)
                    .font(.caption.monospaced())
                    .foregroundStyle(available ? Color.secondary : Color.orange)

                if !available, let installCommand {
                    HStack(spacing: 8) {
                        Text(installCommand)
                            .font(.caption.monospaced())
                            .textSelection(.enabled)
                        Button("Copy") {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(installCommand, forType: .string)
                        }
                        .controlSize(.small)
                    }
                }
            }
            Spacer()
        }
    }

    @ViewBuilder private var runHint: some View {
        if model.snapshot?.targets.isEmpty != false {
            Text(emptyTargetHint)
                .font(.callout)
                .foregroundStyle(.secondary)
        } else if let target = selectedTarget, !selectedTargetIsCompatible {
            VStack(alignment: .leading, spacing: 8) {
                Text(incompatibleTargetHint(target))
                    .font(.callout)
                    .foregroundStyle(.secondary)

                if matchesWebMode, ["Domain", "Hostname"].contains(target.targetType) {
                    Button {
                        Task { _ = await model.addTarget(value: "https://\(target.normalizedValue)/") }
                    } label: {
                        Label("Add HTTPS URL target for \(target.normalizedValue)", systemImage: "link.badge.plus")
                    }
                    .controlSize(.small)
                }
            }
        } else if let providerSetupIssue {
            Text(providerSetupIssue)
                .font(.callout)
                .foregroundStyle(.orange)
                .textSelection(.enabled)
        } else if let target = selectedTarget, target.normalizedValue == "example.test", mode != .synthetic {
            Text("example.test is the offline demo domain. This mode performs live network activity; use a real target that you own or are explicitly authorized to assess.")
                .font(.callout)
                .foregroundStyle(.secondary)
        } else {
            Text("The selected target must also be covered by the workspace scope. If the core reports ScopeViolation, use Edit Scope in the toolbar and add the authorized domain/IP/CIDR.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    private var matchesWebMode: Bool {
        mode == .web || mode == .webAnalysis
    }

    private var emptyTargetHint: String {
        switch mode {
        case .synthetic:
            return "Add example.test using the target bar above."
        case .dns:
            return "Add an in-scope domain or hostname using the target bar above."
        case .domain:
            return "Add an in-scope domain using the target bar above."
        case .web, .webAnalysis:
            return "Add an in-scope HTTP(S) URL such as https://your-domain.example/ using the target bar above."
        }
    }

    private func incompatibleTargetHint(_ target: Target) -> String {
        switch mode {
        case .synthetic:
            return "Synthetic Recon requires the demo target example.test."
        case .dns:
            return "DNS Recon requires a Domain or Hostname target; the selected target is \(target.targetType)."
        case .domain:
            return "Domain Recon requires a Domain target; the selected target is \(target.targetType)."
        case .web:
            return "Web Recon requires an HTTP(S) URL target; the selected target is \(target.targetType)."
        case .webAnalysis:
            return "Web Analysis requires an HTTP(S) URL target; the selected target is \(target.targetType)."
        }
    }

    @ViewBuilder private func stageSymbol(_ status: String) -> some View {
        if status == "RUNNING" {
            ProgressView().controlSize(.small)
        } else if status == "COMPLETED" {
            Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
        } else if ["FAILED", "CANCELLED"].contains(status) {
            Image(systemName: "xmark.circle").foregroundStyle(.orange)
        } else {
            Image(systemName: "circle").foregroundStyle(.tertiary)
        }
    }
}
