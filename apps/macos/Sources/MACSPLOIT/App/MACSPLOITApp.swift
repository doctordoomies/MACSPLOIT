import SwiftUI
import AppKit
import MACSPLOITKit

final class AppDelegate: NSObject, NSApplicationDelegate {
    static var transport: PipeTransport?
    static var stopLinuxForTermination: (@MainActor () async -> Bool)?
    private var terminationPending = false
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard !terminationPending else { return .terminateLater }
        guard let stop = Self.stopLinuxForTermination else { return .terminateNow }
        terminationPending = true
        Task { @MainActor in
            let stopped = await stop()
            terminationPending = false
            if !stopped {
                let alert = NSAlert()
                alert.messageText = "MACSPLOIT could not stop the Linux VM."
                alert.informativeText = "Quit was cancelled to keep the guest managed. Use Force Stop in Linux Terminal, then quit again."
                alert.runModal()
            }
            sender.reply(toApplicationShouldTerminate: stopped)
        }
        return .terminateLater
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
    @StateObject private var linux: LinuxEnvironmentModel
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

        // The managed Linux terminal is app-global and stored separately from workspace
        // data, so removing it never touches workspaces/providers. It never auto-starts.
        let linuxPaths = LinuxEnvironmentPaths.standard(applicationSupport: storage)
        let backend: any LinuxEnvironmentBackend = MACSPLOITApp.makeLinuxBackend()
        let linuxModel = LinuxEnvironmentModel(paths: linuxPaths, backend: backend, downloader: URLSessionLinuxImageDownloader())
        _linux = StateObject(wrappedValue: linuxModel)
        AppDelegate.stopLinuxForTermination = { [weak linuxModel] in
            guard let linuxModel else { return true }
            return await linuxModel.shutdownForApplicationTermination()
        }
    }

    private static func makeLinuxBackend() -> any LinuxEnvironmentBackend {
        // Production never uses the fake backend. Unsupported hosts fail closed.
        #if canImport(Virtualization) && arch(arm64)
        if #available(macOS 13.0, *) { return VZLinuxEnvironmentBackend() }
        #endif
        return UnsupportedLinuxEnvironmentBackend(
            reason: "The managed Linux terminal requires macOS 13 or later on Apple Silicon.")
    }

    var body: some Scene {
        Window("MACSPLOIT", id: "main") {
            AppRootView(model: model, setup: setup, linux: linux)
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
    @ObservedObject var linux: LinuxEnvironmentModel

    var body: some View {
        Group {
            if setup.isPresentingSetup {
                SetupView(model: model, setup: setup)
            } else {
                WorkspaceView(model: model, linux: linux)
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
