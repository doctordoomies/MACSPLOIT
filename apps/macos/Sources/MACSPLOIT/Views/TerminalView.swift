import SwiftUI
import MACSPLOITKit
#if canImport(Virtualization)
import Virtualization
#endif

/// Installation and guest control remain separate from provider authorization. Only
/// explicit actions can download, boot, confirm installation, or remove an environment.
struct TerminalView: View {
    @ObservedObject var model: LinuxEnvironmentModel
    @State private var showingSetup = false
    @State private var confirmingRemove = false
    @State private var confirmingInstalled = false

    var body: some View {
        WorkbenchPage(maxWidth: 1200) {
            VStack(alignment: .leading, spacing: 16) {
                PageHeading(title: "Linux Terminal", subtitle: "An optional managed Kali ARM64 environment. It never downloads or starts on its own.")
                Label("Guest commands are controlled by you, outside MACSPLOIT's provider scope controls. They are not recorded as authorized provider actions or imported into Assets, Evidence or Findings.", systemImage: "exclamationmark.shield")
                    .font(.caption).foregroundStyle(.secondary)
                content
                if let error = model.errorMessage { Text(error).font(.callout).foregroundStyle(.orange).textSelection(.enabled) }
            }
        }
        .disabled(model.isShuttingDown)
        .sheet(isPresented: $showingSetup) { LinuxSetupSheet(model: model) }
        .confirmationDialog("Remove the Linux environment? Its installer, disk, machine identity and EFI variables will be deleted. Workspaces, Evidence, Findings and Providers are untouched.", isPresented: $confirmingRemove, titleVisibility: .visible) {
            Button("Remove Environment", role: .destructive) { Task { await model.remove() } }
            Button("Cancel", role: .cancel) {}
        }
        .confirmationDialog("Has the Kali installer reported a successful installation? Confirm only after it finishes. MACSPLOIT will stop the installer, mark this environment installed, and boot the writable disk without installer media.", isPresented: $confirmingInstalled, titleVisibility: .visible) {
            Button("Installation Complete — Boot Installed Kali") {
                Task { if await model.confirmInstallationComplete() { await model.start() } }
            }
            Button("Cancel", role: .cancel) {}
        }
    }

    @ViewBuilder private var content: some View {
        switch model.state {
        case .unsupported:
            EmptyMessage(title: "Not available on this Mac", detail: model.errorMessage ?? "Requires macOS 13+ on Apple Silicon.", symbol: "exclamationmark.triangle")
        case .notConfigured:
            EmptyMessage(title: "Linux Terminal is not set up", detail: "Review the official Kali installer download first. Preparation creates a sparse disk; installing and booting Kali are separate explicit steps.", symbol: "apple.terminal")
            Button("Set Up Terminal…") { showingSetup = true }.buttonStyle(.borderedProminent)
        case .settingUp:
            Text(model.setupStage).font(.headline)
            ProgressView(value: model.setupProgress)
            Button("Cancel Setup", role: .cancel) { model.cancelSetup() }
        case .installReady:
            summary("Installation not confirmed")
            Text("The installer is ready. An empty disk or a stopped installer does not prove Kali was installed. Resume installation, or confirm completion only after Kali reports success.").font(.callout)
            HStack {
                Button("Install Kali") { Task { await model.installKali() } }.buttonStyle(.borderedProminent)
                Button("Installation Complete — Boot Installed Kali…") { confirmingInstalled = true }
                removeButton
            }
        case .installing:
            summary("Kali installer running")
            HStack {
                Button("Stop Installer") { Task { await model.stop() } }
                Button("Installation Complete — Boot Installed Kali…") { confirmingInstalled = true }
            }
            guestDisplay
        case .stopped:
            summary("Stopped")
            HStack {
                Button("Start Kali") { Task { await model.start() } }.buttonStyle(.borderedProminent)
                removeButton
            }
        case .starting: busy("Starting the guest…")
        case .stopping: busy("Stopping the guest…")
        case .running:
            summary("Kali running")
            Button("Stop Kali") { Task { await model.stop() } }
            guestDisplay
        case .failed:
            Text("Linux Environment · Failed").font(.headline)
            if model.hasRunningHandle {
                Text("The VM handle is still retained. Stop it before removing the environment or quitting.").font(.callout)
                Button("Force Stop") { Task { await model.forceStop() } }
                guestDisplay
            } else {
                HStack {
                    if model.canRetry { Button("Retry") { model.recover() } }
                    removeButton
                }
            }
        }
    }

    private var removeButton: some View {
        Button("Remove / Recreate…", role: .destructive) { confirmingRemove = true }
    }
    private func busy(_ text: String) -> some View { HStack { ProgressView().controlSize(.small); Text(text) } }
    private func summary(_ status: String) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text("Linux Environment · \(status)").font(.headline)
            if let config = model.config {
                Text("\(config.image.displayName) · \(config.cpuCount) CPU · \(config.memoryBytes / (1024 * 1024 * 1024)) GiB RAM · \(config.diskSizeBytes / (1024 * 1024 * 1024)) GiB sparse disk")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
    }
    @ViewBuilder private var guestDisplay: some View {
        #if canImport(Virtualization)
        if let run = model.runningEnvironment as? VZLinuxRunningEnvironment {
            Text("Real guest display · click inside to use the keyboard and pointer. Interactive terminal tabs are a later #90 slice.")
                .font(.caption).foregroundStyle(.secondary)
            LinuxGuestDisplay(run: run).frame(height: 600)
                .accessibilityLabel("Kali virtual machine display")
        }
        #endif
    }
}

#if canImport(Virtualization)
/// Only presentation. The model/backend own VM creation, lifecycle and delegates.
private struct LinuxGuestDisplay: NSViewRepresentable {
    let run: VZLinuxRunningEnvironment
    func makeNSView(context: Context) -> VZVirtualMachineView {
        let view = VZVirtualMachineView()
        view.virtualMachine = run.virtualMachine
        if #available(macOS 14.0, *) { view.automaticallyReconfiguresDisplay = true }
        return view
    }
    func updateNSView(_ view: VZVirtualMachineView, context: Context) { view.virtualMachine = run.virtualMachine }
    static func dismantleNSView(_ view: VZVirtualMachineView, coordinator: ()) { view.virtualMachine = nil }
}
#endif

private struct LinuxSetupSheet: View {
    @ObservedObject var model: LinuxEnvironmentModel
    @Environment(\.dismiss) private var dismiss
    private var manifest: LinuxImageManifest? { LinuxImageCatalog.availableManifest }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Set Up Linux Terminal").font(.title2.weight(.semibold))
            if let manifest {
                Text(manifest.displayName).font(.headline)
                Text(String(format: "Installer download: %.2f GiB (%llu bytes). The ISO remains cached alongside the sparse root disk until you remove the environment.", Double(manifest.downloadByteCount) / 1_073_741_824, manifest.downloadByteCount))
                    .font(.callout)
                Text("Official versioned source").font(.caption.weight(.semibold))
                Text(manifest.installerURL).font(.caption).textSelection(.enabled)
                Text("Pinned SHA-256 (verified before use)").font(.caption.weight(.semibold))
                Text(manifest.sha256).font(.caption.monospaced()).textSelection(.enabled)
                Text("Provenance: Kali's signed SHA256SUMS release metadata. No runtime GPG installation is required.").font(.caption)
                Text(manifest.provenanceURL).font(.caption).textSelection(.enabled)
                Text("Preparation creates a \(model.defaultResources.diskSizeBytes / (1024 * 1024 * 1024)) GiB sparse writable disk, a persistent machine identifier and EFI variables under \(model.paths.root.path). It does not start a VM. Installing Kali is interactive and requires its own Install Kali action.")
                    .font(.caption).foregroundStyle(.secondary)
                HStack {
                    Spacer()
                    Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                    Button("Download & Prepare Installer") {
                        model.startSetUp(manifest: manifest, resources: model.defaultResources)
                        dismiss()
                    }.buttonStyle(.borderedProminent)
                }
            } else {
                Text("No reviewed installer manifest is available.")
                Button("Close") { dismiss() }
            }
        }.padding(24).frame(width: 640)
    }
}
