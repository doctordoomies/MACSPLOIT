import SwiftUI
import AppKit
import MACSPLOITKit

final class AppDelegate: NSObject, NSApplicationDelegate {
    static var transport: PipeTransport?
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }
    func applicationWillTerminate(_ notification: Notification) { Self.transport?.shutdown() }
}

extension AppearancePreference {
    /// nil follows the system setting.
    var colorScheme: ColorScheme? {
        switch self {
        case .system: return nil
        case .light: return .light
        case .dark: return .dark
        }
    }
}

@main
struct MACSPLOITApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var model: WorkspaceModel
    @StateObject private var setup = SetupModel()

    init() {
        let arguments = CommandLine.arguments
        let override = arguments.firstIndex(of: "--data-dir").flatMap { index in
            index + 1 < arguments.count ? URL(fileURLWithPath: arguments[index + 1], isDirectory: true) : nil
        }
        let storage = override ?? FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("MACSPLOIT", isDirectory: true)
        let executable = Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/macsploit-core")
        let transport = PipeTransport(executable: executable, dataDirectory: storage)
        AppDelegate.transport = transport
        _model = StateObject(wrappedValue: WorkspaceModel(client: CoreClient(transport: transport)))
    }

    var body: some Scene {
        Window("MACSPLOIT", id: "main") {
            AppRootView(model: model, setup: setup)
                .frame(minWidth: 1050, minHeight: 680)
                .preferredColorScheme(setup.appearance.colorScheme)
        }
        .defaultSize(width: 1280, height: 800)
        .commands { CommandGroup(replacing: .newItem) { } }

        Settings {
            SettingsView(model: model, setup: setup)
                .preferredColorScheme(setup.appearance.colorScheme)
        }
    }
}

/// Owns the single application boot lifecycle and routes between first-run Setup and the
/// normal Workbench. Core boot/observe happen exactly once here so switching Setup →
/// Workbench never spawns duplicate observers.
struct AppRootView: View {
    @ObservedObject var model: WorkspaceModel
    @ObservedObject var setup: SetupModel

    var body: some View {
        Group {
            if setup.isPresentingSetup {
                SetupView(model: model, setup: setup)
            } else {
                WorkspaceView(model: model)
                    .environment(\.interfaceDetail, setup.interfaceDetail)
                    .environment(\.dashboardPreset, setup.dashboardPreset)
                    .overlay(alignment: .bottom) {
                        if setup.tutorialActive { TutorialOverlay(model: model, setup: setup) }
                    }
            }
        }
        .task { await model.boot(); await model.observe() }
    }
}
