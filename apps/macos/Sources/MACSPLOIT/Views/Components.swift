import SwiftUI
import MACSPLOITKit

/// Centered, gutter-padded content container for a workbench page. Keeps primary
/// content off the window edges and prevents giant edge-to-edge forms on wide displays
/// while still allowing wide content (tables) when `maxWidth` is nil.
struct WorkbenchPage<Content: View>: View {
    var maxWidth: CGFloat? = 1180
    @ViewBuilder var content: Content
    var body: some View {
        ScrollView {
            content
                .frame(maxWidth: maxWidth ?? .infinity, alignment: .leading)
                .frame(maxWidth: .infinity, alignment: .center)
                .padding(.horizontal, 28)
                .padding(.vertical, 24)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

/// A calm, bordered surface used for dashboard and recon cards.
struct WorkbenchCard<Content: View>: View {
    @ViewBuilder var content: Content
    var body: some View {
        content
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(.quaternary.opacity(0.28), in: RoundedRectangle(cornerRadius: 12))
            .overlay(RoundedRectangle(cornerRadius: 12).stroke(.quaternary.opacity(0.7)))
    }
}

/// Compact metric tile (label + value + icon).
struct MetricTile: View {
    let name: String, value: Int, symbol: String
    var body: some View {
        WorkbenchCard {
            VStack(alignment: .leading, spacing: 10) {
                Label(name, systemImage: symbol).font(.callout).foregroundStyle(.secondary)
                Text(value.formatted()).font(.system(size: 30, weight: .semibold, design: .rounded))
            }
        }
    }
}

/// Risk/activity indicator shared by recon cards and panels.
struct RiskBadge: View {
    let risk: String
    private var text: String {
        switch risk {
        case "PASSIVE · SYNTHETIC": return "OFFLINE"
        case "ACTIVE · LOW": return "ACTIVE · LOW"
        default: return risk
        }
    }
    private var color: Color {
        if risk.contains("OFFLINE") || risk.contains("SYNTHETIC") { return .secondary }
        if risk == "ACTIVE" { return .orange }
        return .cyan
    }
    var body: some View {
        Text(text)
            .font(.system(.caption2, design: .monospaced).weight(.semibold))
            .padding(.horizontal, 7).padding(.vertical, 3)
            .background(color.opacity(0.14), in: Capsule()).foregroundStyle(color)
    }
}

/// Authorization state dot + label, driven only by core scope status.
struct AuthorizationBadge: View {
    let authorized: Bool
    let offline: Bool
    var body: some View {
        if offline {
            Label("Offline · No Network", systemImage: "network.slash")
                .font(.caption).foregroundStyle(.secondary)
        } else {
            HStack(spacing: 6) {
                Circle().fill(authorized ? Color.green : Color.secondary).frame(width: 8, height: 8)
                Text(authorized ? "In Scope" : "Not in Workspace Scope")
                    .font(.caption).foregroundStyle(authorized ? .primary : .secondary)
            }
        }
    }
}

/// Persistent authorization reminder shown near every live Run action.
struct AuthorizationReminder: View {
    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "exclamationmark.shield").foregroundStyle(.secondary)
            Text("Only scan systems you own or have explicit permission to assess. Do not scan targets without authorization.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }
}
