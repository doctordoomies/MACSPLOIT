import SwiftUI
import MACSPLOITKit

struct ReconView: View {
    @ObservedObject var model: WorkspaceModel
    private var canRun: Bool {
        model.isConnected && !model.isBusy &&
        model.snapshot?.targets.first(where: { $0.id == model.selectedTargetId })?.normalizedValue == "example.test" &&
        model.snapshot?.chains.contains(where: \.isRunning) != true
    }
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                PageHeading(title: "Synthetic Recon", subtitle: "A real orchestration path using invented discoveries. No network activity.")
                HStack(spacing: 14) {
                    Picker("Target", selection: $model.selectedTargetId) {
                        Text("Choose a target").tag(String?.none)
                        ForEach(model.snapshot?.targets ?? []) { Text($0.normalizedValue).tag(Optional($0.id)) }
                    }.frame(maxWidth: 420)
                    Button { Task { await model.runRecon() } } label: { Label("Run", systemImage: "play.fill") }
                        .buttonStyle(.borderedProminent).disabled(!canRun)
                    if model.selectedChain?.isRunning == true {
                        Button("Cancel") { Task { await model.cancelRecon() } }
                    }
                    Spacer()
                    Text("PASSIVE · SYNTHETIC").font(.system(.caption2, design: .monospaced)).foregroundStyle(.secondary)
                }
                if model.snapshot?.targets.isEmpty != false {
                    Text("Add example.test using the target bar above.").foregroundStyle(.secondary)
                }
                if let chain = model.selectedChain {
                    HStack {
                        Text("Run \(chain.id.prefix(8))").font(.headline)
                        Text(displayTime(chain.createdAt)).foregroundStyle(.secondary).font(.caption)
                        Spacer(); StatusBadge(status: chain.status)
                    }
                    VStack(spacing: 0) {
                        ForEach((model.snapshot?.stages ?? []).filter { $0.chainId == chain.id }.sorted { $0.position < $1.position }) { stage in
                            HStack(spacing: 16) {
                                stageSymbol(stage.status).frame(width: 28, height: 28)
                                VStack(alignment: .leading, spacing: 5) {
                                    Text(stage.name).font(.body.weight(.medium))
                                    if let capability = stage.capability { Text(capability).font(.caption2.monospaced()).foregroundStyle(.secondary) }
                                }
                                Spacer(); StatusBadge(status: stage.status)
                            }.padding(18)
                            if stage.position < 4 { Divider().padding(.leading, 60) }
                        }
                    }.background(Color.primary.opacity(0.035), in: RoundedRectangle(cornerRadius: 10))
                    if let code = chain.errorCode { Label(code, systemImage: "exclamationmark.triangle").foregroundStyle(.orange) }
                    HStack {
                        Button("View assets") { model.section = .assets }
                        Button("View evidence") { model.section = .evidence }
                        Button("View activity") { model.section = .activity }
                    }
                } else {
                    EmptyMessage(title: "Ready to prove the chain", detail: "Rust will record tasks, run the synthetic provider, persist discoveries and evidence, and publish durable events.", symbol: "point.3.connected.trianglepath.dotted")
                        .frame(minHeight: 240)
                }
                if let chains = model.snapshot?.chains, chains.count > 1 {
                    Divider()
                    Text("Run history").font(.headline)
                    ForEach(chains.reversed()) { chain in
                        Button { model.selectedChainId = chain.id } label: {
                            HStack { Text(displayTime(chain.createdAt)); Text(String(chain.id.prefix(8))).foregroundStyle(.secondary); Spacer(); StatusBadge(status: chain.status) }
                        }.buttonStyle(.plain).padding(.vertical, 5)
                    }
                }
            }.padding(26)
        }
    }
    @ViewBuilder private func stageSymbol(_ status: String) -> some View {
        if status == "RUNNING" { ProgressView().controlSize(.small) }
        else if status == "COMPLETED" { Image(systemName: "checkmark.circle.fill").foregroundStyle(.green) }
        else if ["FAILED", "CANCELLED"].contains(status) { Image(systemName: "xmark.circle").foregroundStyle(.orange) }
        else { Image(systemName: "circle").foregroundStyle(.tertiary) }
    }
}
