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
                PageHeading(title: "Provider Center", subtitle: "\(model.providerStatuses.count) providers · How your security-tool environment is configured")
                if model.isRefreshingProviders { ProgressView().controlSize(.small).accessibilityLabel("Refreshing providers") }
                Button {
                    Task { await model.refreshProviders() }
                } label: { Label("Refresh Providers", systemImage: "arrow.clockwise") }
                .disabled(!model.isConnected || model.isRefreshingProviders)
                .help("Refresh local availability and version probes without restarting the core")
            }
            Text("MACSPLOIT needs a compatible provider executable — it does not require Homebrew. You explicitly start every install: MACSPLOIT never installs tools silently and never installs Homebrew itself. Reviewed providers can be installed with Homebrew or by a verified, checksummed app-managed download of the official release; existing executables on PATH or an explicit override are fully supported. There are no background or automatic updates.")
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
                        ForEach(visibleProviders) { provider in ProviderCard(provider: provider, model: model) }
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
    @ObservedObject var model: WorkspaceModel

    private var installRunningHere: Bool {
        model.installState?.running?.providerId == provider.id
    }
    private var lastOutcomeHere: InstallOutcome? {
        let last = model.installState?.last
        return last?.providerId == provider.id ? last : nil
    }

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
                Label(
                    provider.performsNetworkActivity ? "Network activity" : "No network activity",
                    systemImage: provider.performsNetworkActivity ? "network" : "network.slash"
                )
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
                if provider.installation.state == "MISSING" {
                    Text("Not detected. MACSPLOIT needs a compatible \(provider.name) executable. Install it below, by any method on PATH, or set an explicit provider override.")
                        .font(.caption).foregroundStyle(.secondary)
                    installControls
                }
                if let setup = provider.setup {
                    if let command = setup.installCommand {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(command.hasPrefix("brew ")
                                 ? "Recommended on macOS: Homebrew (optional)"
                                 : "Recommended install — run it yourself in Terminal, then Refresh. MACSPLOIT never installs this provider.")
                                .font(.caption).foregroundStyle(.secondary)
                            HStack {
                                Text(command).font(.system(.callout, design: .monospaced)).textSelection(.enabled)
                                Button {
                                    NSPasteboard.general.clearContents()
                                    NSPasteboard.general.setString(command, forType: .string)
                                } label: { Label("Copy Recommended Command", systemImage: "doc.on.doc") }.controlSize(.small)
                            }
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

    /// Install actions for a missing external provider. The user explicitly initiates each
    /// install; MACSPLOIT runs no shell and installs nothing silently.
    @ViewBuilder private var installControls: some View {
        if installRunningHere {
            HStack(spacing: 8) {
                ProgressView().controlSize(.small)
                Text("Installing \(provider.name)…").font(.caption)
                Button("Cancel") { Task { await model.cancelInstall() } }.controlSize(.small)
            }
        } else {
            HStack(spacing: 8) {
                if provider.homebrewSupported {
                    Button {
                        Task { await model.installProvider(provider.id, method: "homebrew") }
                    } label: { Label("Install with Homebrew", systemImage: "shippingbox") }
                        .controlSize(.small)
                        .disabled(!model.isConnected || model.installState?.running != nil)
                }
                if provider.managedDownloadSupported {
                    Button {
                        Task { await model.installProvider(provider.id, method: "managed_download") }
                    } label: { Label("Install without Homebrew", systemImage: "arrow.down.circle") }
                        .controlSize(.small)
                        .disabled(!model.isConnected || model.installState?.running != nil)
                } else if let urlString = provider.install?.officialInstallerUrl,
                          let url = URL(string: urlString) {
                    // No safe app-managed download for this provider (e.g. Nmap):
                    // offer the official installer page instead of a managed action.
                    Link(destination: url) {
                        Label("Official installer", systemImage: "arrow.up.forward.app")
                    }.controlSize(.small)
                }
            }
            if !provider.homebrewSupported && !provider.managedDownloadSupported {
                Text("MACSPLOIT has no in-app install for this provider. Run the recommended command below yourself (for user-scanner, pipx places it in ~/.local/bin, which MACSPLOIT checks), use an existing executable on PATH, or set a provider override; then Refresh.")
                    .font(.caption2).foregroundStyle(.tertiary)
            } else if provider.managedDownloadSupported {
                Text("You explicitly start each install. Homebrew runs as a normal executable (no shell, no sudo). “Install without Homebrew” downloads the verified, checksummed official release into MACSPLOIT’s own providers directory. Or use an existing executable on PATH / a provider override.")
                    .font(.caption2).foregroundStyle(.tertiary)
            } else {
                Text("You explicitly start each install. Homebrew runs as a normal executable (no shell, no sudo). This provider has no app-managed download; use Homebrew, an existing executable on PATH, a provider override, or the official installer.")
                    .font(.caption2).foregroundStyle(.tertiary)
            }
        }
        if let outcome = lastOutcomeHere {
            let color: Color = outcome.status == "SUCCEEDED" ? .green : (outcome.status == "FAILED" ? .orange : .secondary)
            VStack(alignment: .leading, spacing: 2) {
                Text(outcome.message).font(.caption).foregroundStyle(color)
                if let detail = outcome.detail {
                    if detail.hasPrefix("https://"), let url = URL(string: detail) {
                        Link("Official installer", destination: url).font(.caption2)
                    } else {
                        Text(detail).font(.caption2.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
                    }
                }
            }
        }
    }
}
