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

@main
struct MACSPLOITApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var model: WorkspaceModel

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
            WorkspaceView(model: model)
                .frame(minWidth: 1050, minHeight: 680)
                .preferredColorScheme(.dark)
        }
        .defaultSize(width: 1280, height: 800)
        .commands { CommandGroup(replacing: .newItem) { } }
    }
}
