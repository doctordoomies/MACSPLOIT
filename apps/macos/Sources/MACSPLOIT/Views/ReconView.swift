import SwiftUI
import MACSPLOITKit

private enum ReconMode: String, CaseIterable, Identifiable {
    case synthetic = "Synthetic Recon"
    case domain = "Domain Recon"
    var id: String { rawValue }
    var chainKind: String { self == .synthetic ? "synthetic" : "domain_recon" }
    var subtitle: String {
        switch self {
        case .synthetic: return "A real orchestration path using invented discoveries. No network activity."
        case .domain: return "Passive subdomain discovery for an in-scope domain, via the external Subfinder tool."
        }
    }
    var badge: String { self == .synthetic ? "PASSIVE · SYNTHETIC" : "PASSIVE · SUBFINDER" }
}

struct ReconView: View {
    @ObservedObject var model: WorkspaceModel
    @State private var mode: ReconMode = .synthetic

    private var selectedTarget: Target? {
        model.snapshot?.targets.first { $0.id == model.selectedTargetId }
    }
    private var subfinderReady: Bool { model.subfinder?.installation.isInstalled ?? false }

    private var canRun: Bool {
        guard model.isConnected, !model.isBusy,
              model.snapshot?.chains.contains(where: \.isRunning) != true,
              let target = selectedTarget else { return false }
        switch mode {
        case .synthetic: return target.normalizedValue == "example.test"
        case .domain: return target.targetType == "Domain" && subfinderReady
        }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                PageHeading(title: mode.rawValue, subtitle: mode.subtitle)
                Picker("Recon", selection: $mode) {
                    ForEach(ReconMode.allCases) { Text($0.rawValue).tag($0) }
                }.pickerStyle(.segmented).frame(maxWidth: 360)

                if mode == .domain { providerPanel }

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

    @ViewBuilder private var providerPanel: some View {
        HStack(spacing: 12) {
            Image(systemName: subfinderReady ? "checkmark.seal.fill" : "exclamationmark.triangle.fill")
                .foregroundStyle(subfinderReady ? .green : .orange)
            VStack(alignment: .leading, spacing: 3) {
                Text("Provider: Subfinder").font(.body.weight(.medium))
                Text("Capability: Subdomain Discovery · Risk: Passive").font(.caption).foregroundStyle(.secondary)
                Text(model.subfinder?.installation.summary ?? "Provider status unavailable")
                    .font(.caption.monospaced())
                    .foregroundStyle(subfinderReady ? Color.secondary : Color.orange)
            }
            Spacer()
        }
        .padding(14)
        .background(Color.primary.opacity(0.035), in: RoundedRectangle(cornerRadius: 10))
    }

    @ViewBuilder private var runHint: some View {
        if model.snapshot?.targets.isEmpty != false {
            Text(mode == .synthetic ? "Add example.test using the target bar above." : "Add an in-scope domain using the target bar above.")
                .foregroundStyle(.secondary)
        } else if mode == .domain && !subfinderReady {
            Text("Subfinder is not installed. Install it manually (or via a future Tool Manager) to run Domain Recon.")
                .font(.callout).foregroundStyle(.orange)
        } else if mode == .domain, let target = selectedTarget, target.targetType != "Domain" {
            Text("Domain Recon requires a domain target.").font(.callout).foregroundStyle(.secondary)
        }
    }

    @ViewBuilder private func stageSymbol(_ status: String) -> some View {
        if status == "RUNNING" { ProgressView().controlSize(.small) }
        else if status == "COMPLETED" { Image(systemName: "checkmark.circle.fill").foregroundStyle(.green) }
        else if ["FAILED", "CANCELLED"].contains(status) { Image(systemName: "xmark.circle").foregroundStyle(.orange) }
        else { Image(systemName: "circle").foregroundStyle(.tertiary) }
    }
}
