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

/// Lightweight, safe guided tour shown over the workbench. Teaches the workflow and
/// navigates between sections; it launches nothing and performs no network activity
/// (the demo it describes uses offline Synthetic Recon on example.test).
struct TutorialOverlay: View {
    @ObservedObject var model: WorkspaceModel
    @ObservedObject var setup: SetupModel
    @State private var index = 0

    private struct Stop { let section: WorkspaceSection; let title: String; let detail: String }
    private let stops: [Stop] = [
        .init(section: .dashboard, title: "Workspace", detail: "Everything lives in a workspace with an explicit authorized scope. The dashboard is your calm overview."),
        .init(section: .targets, title: "Targets", detail: "Add an authorized target — for this safe tour, the offline demo domain example.test."),
        .init(section: .recon, title: "Recon", detail: "Pick a workflow. Synthetic Recon is offline and performs no network activity — ideal for learning."),
        .init(section: .recon, title: "Live console", detail: "While a workflow runs, the live console shows real provider activity (sanitized for display)."),
        .init(section: .assets, title: "Assets", detail: "Discoveries become normalized assets with relationships you can explore."),
        .init(section: .evidence, title: "Evidence", detail: "Every run preserves hash-verified raw evidence you can inspect."),
        .init(section: .activity, title: "Activity", detail: "A durable, replayable event log records everything that happened.")
    ]

    var body: some View {
        let stop = stops[min(index, stops.count - 1)]
        return WorkbenchCard {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Label("Guided tour", systemImage: "graduationcap").font(.headline)
                    Spacer()
                    Text("\(index + 1) / \(stops.count)").font(.caption).foregroundStyle(.secondary)
                    Button("Skip") { setup.finishTutorial() }.controlSize(.small)
                }
                Text(stop.title).font(.title3.weight(.semibold))
                Text(stop.detail).font(.callout).foregroundStyle(.secondary)
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
        .frame(maxWidth: 560)
        .padding(16)
        .onAppear { navigate() }
    }

    private func navigate() { model.section = stops[min(index, stops.count - 1)].section }
}
