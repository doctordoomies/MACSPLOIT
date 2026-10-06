import SwiftUI
import MACSPLOITKit

/// Application settings (⌘,). Lets the user change presentation preferences and re-run
/// first-run setup or the tutorial. Re-running setup never deletes workspaces, evidence,
/// SQLite data, or installs providers.
struct SettingsView: View {
    @ObservedObject var model: WorkspaceModel
    @ObservedObject var setup: SetupModel

    var body: some View {
        Form {
            Section("Appearance") {
                Picker("Appearance", selection: Binding(get: { setup.appearance }, set: { setup.setAppearance($0) })) {
                    ForEach(AppearancePreference.allCases) { Text($0.label).tag($0) }
                }
            }
            Section("Interface") {
                Picker("Detail", selection: Binding(get: { setup.interfaceDetail }, set: { setup.setInterfaceDetail($0) })) {
                    ForEach(InterfaceDetail.allCases) { Text($0.label).tag($0) }
                }
                Text("Standard keeps diagnostic surfaces collapsed by default; Advanced expands them. Presentation only — never security capability.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("Dashboard") {
                Picker("Preset", selection: Binding(get: { setup.dashboardPreset }, set: { setup.setDashboardPreset($0) })) {
                    ForEach(DashboardPreset.allCases) { Text($0.label).tag($0) }
                }
            }
            Section("Setup & Environment") {
                Button("Run Setup Again") { setup.rerun() }
                Button("Start Tutorial") { setup.startTutorial() }
                Text("Re-running setup guides you through onboarding again. It does not delete workspaces, evidence, or SQLite data, and never installs software.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .frame(width: 460, height: 420)
    }
}

/// Lightweight, safe guided tour shown over the workbench. It navigates between sections
/// and, only on an explicit user action, prepares a clearly-labelled demo workspace and
/// runs the real **Synthetic Recon** workflow (offline, invented `example.test` data) via
/// the normal WorkspaceModel/CoreClient path. It auto-runs nothing and performs no network
/// activity, and it never deletes or widens any real workspace.
struct TutorialOverlay: View {
    @ObservedObject var model: WorkspaceModel
    @ObservedObject var setup: SetupModel
    @State private var index = 0
    @State private var preparing = false

    private enum Kind { case plain, demoRun, console, assets, evidence, activity }
    private struct Stop { let section: WorkspaceSection; let title: String; let detail: String; let kind: Kind }
    private let stops: [Stop] = [
        .init(section: .dashboard, title: "Workspace", detail: "Everything lives in a workspace with an explicit authorized scope. The dashboard is your calm overview.", kind: .plain),
        .init(section: .targets, title: "Target", detail: "Workflows run against an authorized target. This tour uses the offline demo domain example.test in a separate, clearly labelled tutorial workspace.", kind: .plain),
        .init(section: .recon, title: "Synthetic Recon", detail: "Synthetic Recon is fully offline — it invents discoveries and performs no network activity. Prepare the demo, then run it when you're ready.", kind: .demoRun),
        .init(section: .recon, title: "Live console", detail: "While a workflow runs, the live console streams real provider activity (sanitized for display).", kind: .console),
        .init(section: .assets, title: "Assets", detail: "Discoveries become normalized assets with relationships you can explore.", kind: .assets),
        .init(section: .evidence, title: "Evidence", detail: "Every run preserves hash-verified raw evidence you can inspect.", kind: .evidence),
        .init(section: .activity, title: "Activity", detail: "A durable, replayable event log records everything that happened.", kind: .activity)
    ]

    private var stop: Stop { stops[min(index, stops.count - 1)] }

    var body: some View {
        WorkbenchCard {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Label("Guided tour", systemImage: "graduationcap").font(.headline)
                    Spacer()
                    Text("\(index + 1) / \(stops.count)").font(.caption).foregroundStyle(.secondary)
                    Button("Skip") { setup.finishTutorial() }.controlSize(.small)
                }
                Text(stop.title).font(.title3.weight(.semibold))
                Text(stop.detail).font(.callout).foregroundStyle(.secondary)
                stepExtras
                HStack {
                    Spacer()
                    if index > 0 { Button("Back") { index -= 1; navigate() } }
                    if index < stops.count - 1 {
                        Button("Next") { index += 1; navigate() }.buttonStyle(.borderedProminent)
                    } else {
                        Button("Finish") { setup.finishTutorial() }.buttonStyle(.borderedProminent)
                    }
                }
            }
        }
        .frame(maxWidth: 580)
        .padding(16)
        .onAppear { navigate() }
    }

    @ViewBuilder private var stepExtras: some View {
        switch stop.kind {
        case .demoRun:
            HStack(spacing: 10) {
                if !model.isTutorialWorkspace {
                    Button {
                        preparing = true
                        Task { await model.prepareTutorialDemo(); preparing = false }
                    } label: { Label("Prepare Tutorial Demo", systemImage: "wand.and.stars") }
                    .disabled(preparing || !model.isConnected)
                } else {
                    Button {
                        Task { await model.runRecon(kind: "synthetic") }
                    } label: { Label("Run Synthetic Demo", systemImage: "play.fill") }
                    .buttonStyle(.borderedProminent)
                    .disabled(model.selectedChain?.isRunning == true)
                }
                if let chain = model.selectedChain {
                    Text("Demo chain: \(chain.status)").font(.caption.monospaced()).foregroundStyle(.secondary)
                }
            }
        case .console:
            Text(model.consoleLines.isEmpty ? "Run the demo on the previous step to populate the console." : "The console shows \(model.consoleLines.count) lines from the demo run.")
                .font(.caption).foregroundStyle(.secondary)
        case .assets:
            Text("This demo workspace has \(model.snapshot?.assets.count ?? 0) assets.").font(.caption).foregroundStyle(.secondary)
        case .evidence:
            Text("This demo workspace has \(model.snapshot?.evidence.count ?? 0) evidence records.").font(.caption).foregroundStyle(.secondary)
        case .activity:
            Text("This demo workspace has \(model.snapshot?.events.count ?? 0) recorded events.").font(.caption).foregroundStyle(.secondary)
        case .plain:
            EmptyView()
        }
    }

    private func navigate() { model.section = stop.section }
}
