import SwiftUI
import MACSPLOITKit

struct DashboardView: View {
    @ObservedObject var model: WorkspaceModel

    private var providersReady: Int { model.providerStatuses.filter { $0.installation.isAvailable }.count }
    private var providersTotal: Int { model.providerStatuses.count }

    var body: some View {
        WorkbenchPage {
            VStack(alignment: .leading, spacing: 22) {
                PageHeading(title: model.snapshot?.workspace.name ?? "Dashboard",
                            subtitle: "A calm overview of this authorized workspace. Detailed evidence and activity stay one click away.")

                LazyVGrid(columns: [GridItem(.adaptive(minimum: 150), spacing: 14)], spacing: 14) {
                    MetricTile(name: "Targets", value: model.snapshot?.targets.count ?? 0, symbol: "scope")
                    MetricTile(name: "Assets", value: model.snapshot?.assets.count ?? 0, symbol: "square.stack.3d.up")
                    MetricTile(name: "Evidence", value: model.snapshot?.evidence.count ?? 0, symbol: "doc.text.magnifyingglass")
                    providersTile
                }

                LazyVGrid(columns: [GridItem(.adaptive(minimum: 340), spacing: 16)], alignment: .leading, spacing: 16) {
                    recentActivityCard
                    latestReconCard
                    scopeCard
                    quickActionsCard
                }

                Text("Live providers run only when you explicitly launch a workflow. The Rust core enforces scope again before dispatch.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    private var providersTile: some View {
        WorkbenchCard {
            VStack(alignment: .leading, spacing: 10) {
                Label("Providers Ready", systemImage: "checkmark.seal").font(.callout).foregroundStyle(.secondary)
                Text(providersTotal == 0 ? "—" : "\(providersReady)/\(providersTotal)")
                    .font(.system(size: 30, weight: .semibold, design: .rounded))
            }
        }
    }

    private var recentActivityCard: some View {
        WorkbenchCard {
            VStack(alignment: .leading, spacing: 10) {
                Label("Recent Activity", systemImage: "waveform.path").font(.headline)
                let events = (model.snapshot?.events ?? []).suffix(6).reversed()
                if events.isEmpty {
                    Text("No activity yet. Launch a workflow to populate the workspace.")
                        .font(.callout).foregroundStyle(.secondary)
                } else {
                    ForEach(Array(events)) { event in
                        HStack(spacing: 8) {
                            Text(ConsoleLine.clockString(from: event.timestamp))
                                .font(.system(.caption2, design: .monospaced)).foregroundStyle(.tertiary)
                            Text(event.summary).font(.callout).lineLimit(1)
                        }
                    }
                    Button("View activity") { model.section = .activity }.controlSize(.small)
                }
            }
        }
    }

    private var latestReconCard: some View {
        WorkbenchCard {
            VStack(alignment: .leading, spacing: 10) {
                Label("Latest Recon", systemImage: "point.3.connected.trianglepath.dotted").font(.headline)
                if let chain = model.snapshot?.chains.last {
                    HStack { Text(chain.name).font(.callout.weight(.medium)); Spacer(); StatusBadge(status: chain.status) }
                    let stages = (model.snapshot?.stages ?? []).filter { $0.chainId == chain.id }
                    let done = stages.filter { $0.status == "COMPLETED" }.count
                    Text("\(done)/\(stages.count) stages complete").font(.caption).foregroundStyle(.secondary)
                    Button("Open Recon") { model.section = .recon }.controlSize(.small)
                } else {
                    Text("No recon runs yet.").font(.callout).foregroundStyle(.secondary)
                    Button("Open Recon") { model.section = .recon }.controlSize(.small)
                }
            }
        }
    }

    private var scopeCard: some View {
        WorkbenchCard {
            VStack(alignment: .leading, spacing: 8) {
                Label("Assessment Scope", systemImage: "scope").font(.headline)
                if model.snapshot?.workspace.scope.isEmpty == true {
                    Text("No scope configured. Live recon dispatch is blocked until you authorize a target.")
                        .font(.callout).foregroundStyle(.orange)
                } else {
                    ForEach(model.snapshot?.workspace.scope ?? [], id: \.self) {
                        Text($0).font(.system(.callout, design: .monospaced)).textSelection(.enabled).lineLimit(1)
                    }
                }
            }
        }
    }

    private var quickActionsCard: some View {
        WorkbenchCard {
            VStack(alignment: .leading, spacing: 10) {
                Label("Quick Actions", systemImage: "bolt").font(.headline)
                Button { model.section = .recon } label: { Label("Open Recon", systemImage: "play.circle") }
                Button { model.section = .targets } label: { Label("View Targets", systemImage: "scope") }
                Button { model.section = .toolManager } label: { Label("Provider Center", systemImage: "wrench.and.screwdriver") }
            }
        }
    }
}

struct TargetsView: View {
    @ObservedObject var model: WorkspaceModel
    var body: some View {
        VStack(alignment: .leading) {
            PageHeading(title: "Targets", subtitle: "Classified and normalized by Rust. Add domains for DNS/Domain Recon or full HTTP(S) URLs for Web Recon and Web Analysis.").padding([.top, .horizontal], 24)
            if model.snapshot?.targets.isEmpty != false {
                EmptyMessage(title: "Add your first target", detail: "Enter an authorized domain or HTTP(S) URL above — public or local (e.g. http://localhost:3000). For the offline demo, use example.test.", symbol: "scope")
            } else {
                Table(model.snapshot?.targets ?? [], selection: $model.selectedTargetId) {
                    TableColumn("Type", value: \.targetType).width(100)
                    TableColumn("Value", value: \.normalizedValue)
                    TableColumn("Original input", value: \.originalValue)
                    TableColumn("Added") { Text(displayTime($0.createdAt)) }.width(min: 180, ideal: 210)
                }
            }
        }
    }
}

struct StatusBadge: View {
    let status: String
    private var color: Color {
        switch status {
        case "COMPLETED": return .green
        case "RUNNING": return .cyan
        case "FAILED", "PARTIAL": return .orange
        default: return .secondary
        }
    }
    var body: some View {
        Text(status.replacingOccurrences(of: "_", with: " "))
            .font(.system(.caption2, design: .monospaced).weight(.medium))
            .padding(.horizontal, 8).padding(.vertical, 5).foregroundStyle(color)
            .background(color.opacity(0.1), in: Capsule())
    }
}
