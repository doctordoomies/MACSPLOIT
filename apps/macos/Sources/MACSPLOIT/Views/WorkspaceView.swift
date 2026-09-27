import SwiftUI
import MACSPLOITKit

struct WorkspaceView: View {
    @ObservedObject var model: WorkspaceModel
    @State private var creatingWorkspace = false

    var body: some View {
        NavigationSplitView {
            List(selection: $model.section) {
                Section("Workspace") {
                    ForEach(WorkspaceSection.allCases) { section in
                        Label(section.rawValue, systemImage: section.symbol).tag(section)
                    }
                }
                Section("Future") {
                    Label("Findings", systemImage: "exclamationmark.shield")
                    Label("Graph", systemImage: "point.3.filled.connected.trianglepath.dotted")
                    Label("Reports", systemImage: "doc.richtext")
                    Label("Tool Manager", systemImage: "wrench.and.screwdriver")
                }.foregroundStyle(.tertiary).disabled(true)
            }
            .listStyle(.sidebar)
            .safeAreaInset(edge: .bottom) {
                VStack(alignment: .leading, spacing: 5) {
                    Text("MACSPLOIT").font(.headline).tracking(1.5)
                    Text("PHASE 0 · OFFLINE").font(.caption2).foregroundStyle(.secondary)
                }.frame(maxWidth: .infinity, alignment: .leading).padding()
            }
            .navigationSplitViewColumnWidth(min: 180, ideal: 205)
        } detail: {
            VStack(spacing: 0) {
                if let message = model.connectionError {
                    HStack {
                        Image(systemName: "exclamationmark.triangle").foregroundStyle(.orange)
                        Text(message).font(.callout).textSelection(.enabled)
                        Spacer()
                        Button("Reconnect") { Task { await model.boot() } }
                    }.padding().background(Color.orange.opacity(0.08))
                }
                if model.snapshot != nil {
                    TargetBar(model: model)
                    Divider()
                    Group {
                        switch model.section ?? .dashboard {
                        case .dashboard: DashboardView(model: model)
                        case .targets: TargetsView(model: model)
                        case .assets: AssetsView(model: model)
                        case .recon: ReconView(model: model)
                        case .evidence: EvidenceView(model: model)
                        case .activity: ActivityView(model: model)
                        }
                    }.frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    VStack(spacing: 18) {
                        Image(systemName: "square.stack.3d.up").font(.system(size: 44, weight: .light)).foregroundStyle(.secondary)
                        Text("One workspace. Every discovery.").font(.title2.weight(.semibold))
                        Text("No workspace selected. Create a workspace to start the offline synthetic workflow.")
                            .foregroundStyle(.secondary).multilineTextAlignment(.center).frame(maxWidth: 460)
                        Button("Create Workspace") { creatingWorkspace = true }
                            .buttonStyle(.borderedProminent).disabled(!model.isConnected)
                    }.frame(maxWidth: .infinity, maxHeight: .infinity)
                }
                Divider()
                HStack(spacing: 8) {
                    Circle().fill(model.isConnected ? Color.green : Color.orange).frame(width: 6, height: 6)
                    Text(model.isConnected ? "Rust core connected" : "Rust core unavailable")
                    Spacer()
                    if let sequence = model.snapshot?.lastSequence { Text("Event \(sequence) · persisted in SQLite") }
                    Text("Synthetic data only").foregroundStyle(.secondary)
                }.font(.caption).foregroundStyle(.secondary).padding(.horizontal, 18).padding(.vertical, 9)
            }
        }
        .toolbar {
            ToolbarItem(placement: .navigation) {
                Picker("Workspace", selection: Binding(get: { model.selectedWorkspaceId ?? "" }, set: { id in Task { await model.selectWorkspace(id) } })) {
                    Text("Select workspace").tag("")
                    ForEach(model.workspaces) { Text($0.name).tag($0.id) }
                }.frame(width: 235).disabled(model.workspaces.isEmpty || model.isBusy)
            }
            ToolbarItem {
                Button { creatingWorkspace = true } label: { Label("Create Workspace", systemImage: "plus") }
                    .help("Create Workspace").keyboardShortcut("n", modifiers: [.command, .shift]).disabled(!model.isConnected)
            }
        }
        .sheet(isPresented: $creatingWorkspace) { CreateWorkspaceView(model: model) }
        .alert("MACSPLOIT", isPresented: Binding(get: { model.errorMessage != nil }, set: { if !$0 { model.errorMessage = nil } })) {
            Button("OK") { model.errorMessage = nil }
        } message: { Text(model.errorMessage ?? "") }
        .task { await model.boot(); await model.observe() }
    }
}

private struct CreateWorkspaceView: View {
    @ObservedObject var model: WorkspaceModel
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var scope = "example.test\n*.example.test\n192.0.2.0/24"
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Create Workspace").font(.title2.weight(.semibold))
            Text("A separate SQLite workspace with explicit assessment scope.").foregroundStyle(.secondary)
            TextField("Workspace name", text: $name).textFieldStyle(.roundedBorder)
            Text("Scope · one domain, wildcard, IP, or CIDR per line").font(.caption).foregroundStyle(.secondary)
            TextEditor(text: $scope).font(.system(.body, design: .monospaced)).frame(height: 105).padding(6)
                .overlay(RoundedRectangle(cornerRadius: 6).stroke(.quaternary))
            Text("The suggested scope contains only the synthetic example.test domain and documentation addresses. No network requests will run.")
                .font(.callout).foregroundStyle(.secondary)
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Create") { Task { if await model.createWorkspace(name: name, scopeText: scope) { dismiss() } } }
                    .buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)
                    .disabled(name.trimmingCharacters(in: .whitespaces).isEmpty || model.isBusy)
            }
        }.padding(26).frame(width: 500)
    }
}

private struct TargetBar: View {
    @ObservedObject var model: WorkspaceModel
    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "scope").foregroundStyle(.secondary)
            TextField("Domain, URL, IP, CIDR, email, or @username", text: $model.targetInput)
                .textFieldStyle(.plain).onSubmit { Task { await model.addTarget() } }
                .accessibilityLabel("Target input")
            if let kind = model.lastTargetType { Text("Detected: \(kind)").font(.caption).foregroundStyle(.secondary) }
            Button("Add Target") { Task { await model.addTarget() } }
                .disabled(model.targetInput.trimmingCharacters(in: .whitespaces).isEmpty || model.isBusy || !model.isConnected)
        }.padding(18)
    }
}

struct PageHeading: View {
    let title: String, subtitle: String
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.title2.weight(.semibold))
            Text(subtitle).foregroundStyle(.secondary).font(.callout)
        }.frame(maxWidth: .infinity, alignment: .leading).padding(.bottom, 8)
    }
}

struct EmptyMessage: View {
    let title: String, detail: String, symbol: String
    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: symbol).font(.largeTitle).foregroundStyle(.secondary)
            Text(title).font(.headline)
            Text(detail).foregroundStyle(.secondary).multilineTextAlignment(.center).frame(maxWidth: 420)
        }.frame(maxWidth: .infinity, maxHeight: .infinity).padding()
    }
}
