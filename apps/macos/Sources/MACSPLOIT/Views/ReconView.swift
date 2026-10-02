import SwiftUI
import MACSPLOITKit

private enum ReconMode: String, CaseIterable, Identifiable {
    case synthetic = "Synthetic Recon"
    case domain = "Domain Recon"
    case web = "Web Recon"
    case webAnalysis = "Web Analysis"
    var id: String { rawValue }
    var chainKind: String {
        switch self {
        case .synthetic: return "synthetic"
        case .domain: return "domain_recon"
        case .web: return "web_recon"
        case .webAnalysis: return "web_analysis"
        }
    }
    var subtitle: String {
        switch self {
        case .synthetic: return "A real orchestration path using invented discoveries. No network activity."
        case .domain: return "Subdomains → DNS → ports/services → HTTP probing for an in-scope domain."
        case .web: return "Bounded same-host crawling from an explicitly selected in-scope HTTP(S) URL."
        case .webAnalysis: return "Native HTTP analysis of an in-scope URL: headers, cookies, CORS, redirects, robots."
        }
    }
    var badge: String {
        switch self {
        case .synthetic: return "PASSIVE · SYNTHETIC"
        case .domain: return "MIXED · DOMAIN"
        case .web, .webAnalysis: return "ACTIVE · LOW"
        }
    }
}

struct ReconView: View {
    @ObservedObject var model: WorkspaceModel
    @State private var mode: ReconMode = .synthetic

    private var selectedTarget: Target? {
        model.snapshot?.targets.first { $0.id == model.selectedTargetId }
    }
    private var subfinderReady: Bool { model.subfinder?.installation.isInstalled ?? false }
    private var katanaReady: Bool { model.katana?.installation.isInstalled ?? false }

    private var canRun: Bool {
        guard model.isConnected, !model.isBusy,
              model.snapshot?.chains.contains(where: \.isRunning) != true,
              let target = selectedTarget else { return false }
        switch mode {
        case .synthetic: return target.normalizedValue == "example.test"
        case .domain: return target.targetType == "Domain" && subfinderReady
        case .web: return target.targetType == "URL" && katanaReady
        case .webAnalysis: return target.targetType == "URL" // native, built-in
        }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                PageHeading(title: mode.rawValue, subtitle: mode.subtitle)
                Picker("Recon", selection: $mode) {
                    ForEach(ReconMode.allCases) { Text($0.rawValue).tag($0) }
                }.pickerStyle(.segmented).frame(maxWidth: 360)

                if mode == .domain { domainProviderPanel }
                else if mode == .web { webProviderPanel }
                else if mode == .webAnalysis { webAnalysisProviderPanel }

                HStack(spacing: 14) {
                    Picker("Target", selection: $model.selectedTargetId) {
                        Text("Choose a target").tag(String?.none)
                        ForEach(model.snapshot?.targets ?? []) { Text($0.normalizedValue).tag(Optional($0.id)) }
                    }.frame(maxWidth: 420)
                    Button { Task { await model.runRecon(kind: mode.chainKind) } } label: { Label("Run", systemImage: "play.fill") }
                        .buttonStyle(.borderedProminent).disabled(!canRun)
                    if model.selectedChain?.isRunning == true {
                        Button("Cancel") { Task { await model.cancelRecon() } }
                    }
                    Spacer()
                    Text(mode.badge).font(.system(.caption2, design: .monospaced)).foregroundStyle(.secondary)
                }
                runHint

                if let chain = model.selectedChain {
                    HStack {
                        Text(chain.name).font(.headline)
                        Text(String(chain.id.prefix(8))).foregroundStyle(.secondary).font(.caption)
                        Text(displayTime(chain.createdAt)).foregroundStyle(.secondary).font(.caption)
                        Spacer(); StatusBadge(status: chain.status)
                    }
                    VStack(spacing: 0) {
                        let stages = (model.snapshot?.stages ?? []).filter { $0.chainId == chain.id }.sorted { $0.position < $1.position }
                        ForEach(stages) { stage in
                            HStack(spacing: 16) {
                                stageSymbol(stage.status).frame(width: 28, height: 28)
                                VStack(alignment: .leading, spacing: 5) {
                                    Text(stage.name).font(.body.weight(.medium))
                                    if let provider = stage.providerId {
                                        Text(provider.uppercased()).font(.caption2.monospaced()).foregroundStyle(.secondary)
                                    } else if let capability = stage.capability {
                                        Text(capability).font(.caption2.monospaced()).foregroundStyle(.secondary)
                                    }
                                }
                                Spacer(); StatusBadge(status: stage.status)
                            }.padding(18)
                            if stage.id != stages.last?.id { Divider().padding(.leading, 60) }
                        }
                    }.background(Color.primary.opacity(0.035), in: RoundedRectangle(cornerRadius: 10))
                    if let code = chain.errorCode { Label(code, systemImage: "exclamationmark.triangle").foregroundStyle(.orange) }
                    HStack {
                        Button("View assets") { model.section = .assets }
                        Button("View evidence") { model.section = .evidence }
                        Button("View activity") { model.section = .activity }
                    }
                } else {
                    EmptyMessage(title: "Ready to prove the chain", detail: "Rust records tasks, runs the selected provider, persists discoveries and evidence, and publishes durable events.", symbol: "point.3.connected.trianglepath.dotted")
                        .frame(minHeight: 220)
                }
                if let chains = model.snapshot?.chains, chains.count > 1 {
                    Divider()
                    Text("Run history").font(.headline)
                    ForEach(chains.reversed()) { chain in
                        Button { model.selectedChainId = chain.id } label: {
                            HStack {
                                Text(chain.name).frame(width: 130, alignment: .leading)
                                Text(displayTime(chain.createdAt)); Text(String(chain.id.prefix(8))).foregroundStyle(.secondary)
                                Spacer(); StatusBadge(status: chain.status)
                            }
                        }.buttonStyle(.plain).padding(.vertical, 5)
                    }
                }
            }.padding(26)
        }
    }

    @ViewBuilder private var domainProviderPanel: some View {
        VStack(spacing: 10) {
            providerRow(
                title: "Subfinder",
                detail: "Subdomain Discovery · Passive",
                available: subfinderReady,
                status: model.subfinder?.installation.summary ?? "Provider status unavailable"
            )
            Divider()
            providerRow(
                title: "Native DNS Resolver",
                detail: "DNS Resolution",
                available: model.nativeDns?.installation.isAvailable ?? true,
                status: model.nativeDns?.installation.summary ?? "Built in",
                risk: "ACTIVE · LOW", warn: false
            )
            Divider()
            providerRow(
                title: "Nmap",
                detail: "Port + Service Discovery",
                available: model.nmap?.installation.isAvailable ?? false,
                status: model.nmap?.installation.summary ?? "Provider status unavailable",
                risk: "ACTIVE", warn: true
            )
            Divider()
            providerRow(
                title: "HTTPX",
                detail: "HTTP Probing",
                available: model.httpx?.installation.isAvailable ?? false,
                status: model.httpx?.installation.summary ?? "Provider status unavailable",
                risk: "ACTIVE · LOW", warn: false
            )
        }
        .padding(14)
        .background(Color.primary.opacity(0.035), in: RoundedRectangle(cornerRadius: 10))
    }

    @ViewBuilder private var webProviderPanel: some View {
        VStack(spacing: 10) {
            providerRow(
                title: "Katana",
                detail: "Same-host Web Crawling · depth 2 · 20s crawl budget",
                available: katanaReady,
                status: model.katana?.installation.summary ?? "Provider status unavailable",
                risk: "ACTIVE · LOW", warn: false
            )
        }
        .padding(14)
        .background(Color.primary.opacity(0.035), in: RoundedRectangle(cornerRadius: 10))
    }

    @ViewBuilder private var webAnalysisProviderPanel: some View {
        VStack(spacing: 10) {
            providerRow(
                title: "Native HTTP Analysis",
                detail: "Headers · Cookies · CORS · Redirects · robots.txt",
                available: model.nativeHttp?.installation.isAvailable ?? true,
                status: model.nativeHttp?.installation.summary ?? "Built in",
                risk: "ACTIVE · LOW", warn: false
            )
        }
        .padding(14)
        .background(Color.primary.opacity(0.035), in: RoundedRectangle(cornerRadius: 10))
    }

    @ViewBuilder private func providerRow(title: String, detail: String, available: Bool, status: String, risk: String = "PASSIVE", warn: Bool = false) -> some View {
        HStack(spacing: 12) {
            Image(systemName: available ? "checkmark.seal.fill" : "exclamationmark.triangle.fill")
                .foregroundStyle(available ? .green : .orange)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 8) {
                    Text("Provider: \(title)").font(.body.weight(.medium))
                    Text(risk)
                        .font(.system(.caption2, design: .monospaced).weight(.bold))
                        .padding(.horizontal, 6).padding(.vertical, 1)
                        .background((warn ? Color.orange : Color.secondary).opacity(0.18), in: Capsule())
                        .foregroundStyle(warn ? Color.orange : Color.secondary)
                }
                Text("Capability: \(detail)").font(.caption).foregroundStyle(.secondary)
                Text(status).font(.caption.monospaced())
                    .foregroundStyle(available ? Color.secondary : Color.orange)
            }
            Spacer()
        }
    }

    @ViewBuilder private var runHint: some View {
        if model.snapshot?.targets.isEmpty != false {
            Text(mode == .synthetic
                 ? "Add example.test using the target bar above."
                 : mode == .domain
                 ? "Add an in-scope domain using the target bar above."
                 : "Add an in-scope HTTP(S) URL using the target bar above.")
                .foregroundStyle(.secondary)
        } else if mode == .domain && !subfinderReady {
            Text("Subfinder is not installed. Install it manually (or via a future Tool Manager) to run Domain Recon.")
                .font(.callout).foregroundStyle(.orange)
        } else if mode == .domain && !(model.nmap?.installation.isAvailable ?? false) {
            Text("Nmap is not installed. Subfinder and DNS stages will run, but the active Port + Service Discovery stage will fail until Nmap is installed.")
                .font(.callout).foregroundStyle(.orange)
        } else if mode == .domain, let target = selectedTarget, target.targetType != "Domain" {
            Text("Domain Recon requires a domain target.").font(.callout).foregroundStyle(.secondary)
        } else if mode == .web && !katanaReady {
            Text("Katana is not installed. Install it manually to run Web Recon.")
                .font(.callout).foregroundStyle(.orange)
        } else if mode == .web, let target = selectedTarget, target.targetType != "URL" {
            Text("Web Recon requires an HTTP(S) URL target.").font(.callout).foregroundStyle(.secondary)
        } else if mode == .webAnalysis, let target = selectedTarget, target.targetType != "URL" {
            Text("Web Analysis requires an HTTP(S) URL target.").font(.callout).foregroundStyle(.secondary)
        }
    }

    @ViewBuilder private func stageSymbol(_ status: String) -> some View {
        if status == "RUNNING" { ProgressView().controlSize(.small) }
        else if status == "COMPLETED" { Image(systemName: "checkmark.circle.fill").foregroundStyle(.green) }
        else if ["FAILED", "CANCELLED"].contains(status) { Image(systemName: "xmark.circle").foregroundStyle(.orange) }
        else { Image(systemName: "circle").foregroundStyle(.tertiary) }
    }
}
