import SwiftUI
import MACSPLOITKit

struct DashboardView: View {
    @ObservedObject var model: WorkspaceModel
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                PageHeading(title: model.snapshot?.workspace.name ?? "Dashboard", subtitle: "A persistent workspace for the first synthetic investigation.")
                HStack(spacing: 16) {
                    metric("Targets", model.snapshot?.targets.count ?? 0, "scope")
                    metric("Assets", model.snapshot?.assets.count ?? 0, "square.stack.3d.up")
                    metric("Relationships", model.snapshot?.relationships.count ?? 0, "point.3.connected.trianglepath.dotted")
                    metric("Evidence", model.snapshot?.evidence.count ?? 0, "doc.text.magnifyingglass")
                }
                GroupBox {
                    VStack(alignment: .leading, spacing: 12) {
                        Label("Start with example.test", systemImage: "play.circle").font(.headline)
                        Text("Add the synthetic target above, open Recon, and run Synthetic Recon. Discoveries, relationships, and evidence flow from Rust into this workspace.")
                            .foregroundStyle(.secondary)
                        Button("Open Recon") { model.section = .recon }
                    }.padding(12).frame(maxWidth: .infinity, alignment: .leading)
                }
                GroupBox("Assessment scope") {
                    VStack(alignment: .leading, spacing: 8) {
                        if model.snapshot?.workspace.scope.isEmpty == true { Text("No scope configured. Recon dispatch is blocked.").foregroundStyle(.orange) }
                        ForEach(model.snapshot?.workspace.scope ?? [], id: \.self) { Text($0).font(.system(.body, design: .monospaced)).textSelection(.enabled) }
                    }.padding(12).frame(maxWidth: .infinity, alignment: .leading)
                }
                if let chain = model.snapshot?.chains.last {
                    GroupBox("Latest Recon Chain") {
                        HStack { Text(chain.name); Spacer(); StatusBadge(status: chain.status) }.padding(12)
                    }
                }
                Text("All discoveries in Phase 0 are invented. There are no scanners, DNS lookups, or external requests.")
                    .font(.caption).foregroundStyle(.secondary)
            }.padding(26)
        }
    }
    private func metric(_ name: String, _ value: Int, _ symbol: String) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Label(name, systemImage: symbol).font(.callout).foregroundStyle(.secondary)
            Text(value.formatted()).font(.system(size: 32, weight: .medium, design: .rounded))
        }.frame(maxWidth: .infinity, alignment: .leading).padding(20)
            .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 10))
    }
}

struct TargetsView: View {
    @ObservedObject var model: WorkspaceModel
    var body: some View {
        VStack(alignment: .leading) {
            PageHeading(title: "Targets", subtitle: "Classified and normalized by Rust. Synthetic Recon currently accepts example.test.").padding([.top, .horizontal], 24)
            if model.snapshot?.targets.isEmpty != false {
                EmptyMessage(title: "Add your first target", detail: "Enter example.test in the target bar to begin.", symbol: "scope")
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
