import AppKit
import SwiftUI
import MACSPLOITKit

struct ToolManagerView: View {
    @ObservedObject var model: WorkspaceModel
    @State private var search = ""
    @State private var filter: ProviderFilter = .all

    private var visibleProviders: [ProviderStatus] {
        model.providerStatuses.filter { filter.includes($0, search: search) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(alignment: .top) {
                PageHeading(title: "Tool Manager", subtitle: "\(model.providerStatuses.count) providers · Status, diagnostics, and setup help")
                if model.isRefreshingProviders { ProgressView().controlSize(.small).accessibilityLabel("Refreshing providers") }
                Button {
                    Task { await model.refreshProviders() }
                } label: { Label("Refresh Providers", systemImage: "arrow.clockwise") }
                .disabled(!model.isConnected || model.isRefreshingProviders)
                .help("Refresh local availability and version probes without restarting the core")
            }
            Text("Setup commands are copy-only. MACSPLOIT never installs or updates providers.")
                .font(.callout).foregroundStyle(.secondary)
            if let error = model.providerRefreshError {
                Label(error, systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.orange).textSelection(.enabled)
            }
            if !model.isConnected {
                Label("Connect to the Rust core to refresh provider status.", systemImage: "link")
                    .foregroundStyle(.secondary)
            }
            HStack {
                Picker("Provider status", selection: $filter) {
                    ForEach(ProviderFilter.allCases) { value in
                        Text("\(value.rawValue) (\(model.providerStatuses.filter { value.includes($0) }.count))").tag(value)
                    }
                }.pickerStyle(.menu).frame(maxWidth: 220)
                TextField("Search name, ID, or capability", text: $search).textFieldStyle(.roundedBorder)
            }
            if visibleProviders.isEmpty {
                EmptyMessage(title: model.isRefreshingProviders ? "Checking providers…" : "No providers to display",
                             detail: model.providerStatuses.isEmpty ? "Refresh when the core is connected to load the provider registry." : "Try another filter or search.",
                             symbol: "wrench.and.screwdriver")
            } else {
                ScrollView {
                    LazyVStack(spacing: 12) {
                        ForEach(visibleProviders) { provider in ProviderCard(provider: provider) }
                    }.padding(1)
                }
            }
            Text("Risk labels describe provider behavior. Scope and authorization still govern every scan.")
                .font(.caption).foregroundStyle(.secondary)
        }.padding(24).frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
}

private struct ProviderCard: View {
    let provider: ProviderStatus
    private var statusColor: Color {
        switch provider.installation.state {
        case "BUILT_IN", "INSTALLED": return .green
        case "MISSING": return .secondary
        default: return .orange
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline) {
                Text(provider.name).font(.headline)
                Text(provider.id).font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary)
                Spacer()
                Text(provider.installation.statusTitle).font(.caption.weight(.semibold))
                    .padding(.horizontal, 8).padding(.vertical, 4)
                    .background(statusColor.opacity(0.12), in: Capsule()).foregroundStyle(statusColor)
            }
            Text(provider.description).font(.callout).foregroundStyle(.secondary)
            HStack(spacing: 12) {
                Label(provider.installation.isBuiltIn ? "Built in" : "External", systemImage: provider.installation.isBuiltIn ? "shippingbox" : "terminal")
                Label(provider.offline ? "Offline" : "Network provider", systemImage: provider.offline ? "network.slash" : "network")
                Text(provider.riskClass == "ACTIVE_LOW_IMPACT" ? "Active · Low Impact" : providerLabel(provider.riskClass))
                    .help(provider.riskClass)
            }.font(.caption)
            Text("Capabilities: \(provider.capabilities.map(providerLabel).joined(separator: ", "))").font(.callout)
            Text("Target types: \(provider.supportedTargetTypes.map(providerLabel).joined(separator: ", "))")
                .font(.caption).foregroundStyle(.secondary)
            if provider.installation.isBuiltIn {
                Text("No external installation required").font(.callout)
            } else {
                if ["INSTALLED", "UNSUPPORTED_VERSION"].contains(provider.installation.state) {
                    Text(provider.installation.versionLabel).font(.callout)
                }
                if let path = provider.installation.path {
                    Text(path).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                }
                if let message = provider.installation.message {
                    Text(message).font(.callout).foregroundStyle(.orange).textSelection(.enabled)
                }
                if let setup = provider.setup {
                    if let command = setup.installCommand {
                        HStack {
                            Text(command).font(.system(.callout, design: .monospaced)).textSelection(.enabled)
                            Button {
                                NSPasteboard.general.clearContents()
                                NSPasteboard.general.setString(command, forType: .string)
                            } label: { Label("Copy Install Command", systemImage: "doc.on.doc") }.controlSize(.small)
                        }
                    }
                    HStack {
                        if let url = setup.homepageURL { Link("Homepage", destination: url) }
                        if let url = setup.documentationURL { Link("Documentation", destination: url) }
                    }.font(.caption)
                }
            }
        }.padding(16).frame(maxWidth: .infinity, alignment: .leading)
            .background(.quaternary.opacity(0.3), in: RoundedRectangle(cornerRadius: 10))
            .overlay(RoundedRectangle(cornerRadius: 10).stroke(.quaternary))
    }
}
