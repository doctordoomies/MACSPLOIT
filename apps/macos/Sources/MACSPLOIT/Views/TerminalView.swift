import SwiftUI
import MACSPLOITKit

/// The integrated Linux terminal: a dedicated top-level destination for the optional,
/// explicitly started managed Linux (Kali ARM64) environment. The UI renders every
/// lifecycle state from the typed `LinuxEnvironmentModel`; nothing starts a VM or downloads
/// anything except on an explicit user action. This is a separate trust boundary — the
/// shell is driven by the user, not scope-checked, and its output is never imported.
struct TerminalView: View {
    @ObservedObject var model: LinuxEnvironmentModel
    @State private var showingSetup = false
    @State private var confirmingRemove = false

    var body: some View {
        WorkbenchPage(maxWidth: 1100) {
            VStack(alignment: .leading, spacing: 18) {
                PageHeading(title: "Linux Terminal",
                            subtitle: "An optional managed Linux environment for tools and command combinations not yet wrapped as native workflows. It is off by default and never starts on its own.")
                scopeBoundaryNote
                Group {
                    switch model.state {
                    case .unsupported: unsupported
                    case .notConfigured: notConfigured
                    case .settingUp: settingUp
                    case .stopped: stopped
                    case .starting: busy("Starting the Linux environment…")
                    case .running: running
                    case .stopping: busy("Stopping the Linux environment…")
                    case .failed: failed
                    }
                }
                if let error = model.errorMessage, model.state != .failed {
                    Text(error).font(.callout).foregroundStyle(.orange).textSelection(.enabled)
                }
            }
        }
        .sheet(isPresented: $showingSetup) { SetupSheet(model: model) }
    }

    private var scopeBoundaryNote: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "exclamationmark.shield").foregroundStyle(.orange)
            Text("Commands you run in the Linux terminal are controlled by you. They are **not** restricted by MACSPLOIT's workflow scope controls, are not recorded as authorized provider actions, and their output is not imported into Assets, Evidence, or Findings.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }
        .padding(10)
        .background(Color.orange.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
    }

    // MARK: States

    private var unsupported: some View {
        EmptyMessage(title: "Not available on this Mac",
                     detail: model.errorMessage ?? "The managed Linux terminal requires macOS 13 or later on Apple Silicon.",
                     symbol: "exclamationmark.triangle")
    }

    private var notConfigured: some View {
        VStack(alignment: .leading, spacing: 14) {
            EmptyMessage(title: "Linux Terminal is not set up",
                         detail: "Run a managed Linux environment inside MACSPLOIT. Nothing is downloaded or started until you explicitly set it up.",
                         symbol: "apple.terminal")
            Button("Set Up Terminal…") { showingSetup = true }
                .buttonStyle(.borderedProminent)
        }
    }

    private var settingUp: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) { ProgressView().controlSize(.small); Text(model.setupStage.isEmpty ? "Setting up…" : model.setupStage) }
            Text("MACSPLOIT is downloading and verifying the reviewed image, then preparing the environment.")
                .font(.caption).foregroundStyle(.secondary)
            Button("Cancel Setup", role: .cancel) { model.cancelSetup() }
        }
    }

    @ViewBuilder private var stopped: some View {
        VStack(alignment: .leading, spacing: 14) {
            environmentSummary
            HStack(spacing: 10) {
                Button("Start Terminal") { Task { await model.start() } }
                    .buttonStyle(.borderedProminent)
                Button("Remove Environment…", role: .destructive) { confirmingRemove = true }
                Spacer()
            }
        }
        .confirmationDialog("Remove the Linux environment? This deletes only the VM disk and configuration — your workspaces, Assets, Evidence, Findings, and installed providers are untouched.",
                            isPresented: $confirmingRemove, titleVisibility: .visible) {
            Button("Remove Environment", role: .destructive) { Task { await model.remove() } }
            Button("Cancel", role: .cancel) {}
        }
    }

    private var running: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                statusLabel("Running", color: .green)
                Spacer()
                Button("Stop VM") { Task { await model.stop() } }
            }
            tabsBar
            terminalCanvas
        }
    }

    private var failed: some View {
        VStack(alignment: .leading, spacing: 12) {
            statusLabel("Failed", color: .orange)
            Text(model.errorMessage ?? "The Linux environment entered a failed state.")
                .font(.callout).foregroundStyle(.secondary).textSelection(.enabled)
            HStack(spacing: 10) {
                if model.hasRunningHandle {
                    // A VM is still held (a stop that did not confirm). Offer a forced stop
                    // rather than pretending it is gone.
                    Button("Force Stop") { Task { await model.forceStop() } }
                        .buttonStyle(.borderedProminent)
                } else {
                    Button("Retry") { model.recover(); Task { await model.start() } }
                        .buttonStyle(.borderedProminent)
                    Button("Recreate Environment…", role: .destructive) { confirmingRemove = true }
                }
            }
        }
        .confirmationDialog("Recreate the Linux environment? This removes the current VM disk and configuration (workspaces and providers are untouched), then you can set it up again.",
                            isPresented: $confirmingRemove, titleVisibility: .visible) {
            Button("Remove Environment", role: .destructive) { Task { await model.remove() } }
            Button("Cancel", role: .cancel) {}
        }
    }

    private func busy(_ message: String) -> some View {
        HStack(spacing: 8) { ProgressView().controlSize(.small); Text(message) }
    }

    // MARK: Pieces

    @ViewBuilder private var environmentSummary: some View {
        if let config = model.config {
            VStack(alignment: .leading, spacing: 6) {
                statusLabel("Stopped", color: .secondary)
                HStack(spacing: 20) {
                    summaryItem("Image", config.image.displayName)
                    summaryItem("CPU", "\(config.cpuCount) cores")
                    summaryItem("Memory", byteLabel(config.memoryBytes))
                    summaryItem("Disk", byteLabel(config.diskSizeBytes))
                }
                Text("Stored at \(model.paths.root.path)").font(.caption2).foregroundStyle(.tertiary).textSelection(.enabled)
            }
        } else {
            statusLabel("Stopped", color: .secondary)
        }
    }

    private var tabsBar: some View {
        HStack(spacing: 6) {
            ForEach(Array(model.sessionIDs.enumerated()), id: \.element) { index, id in
                Text("shell \(index + 1)")
                    .font(.caption.monospaced())
                    .padding(.horizontal, 8).padding(.vertical, 3)
                    .background(Color.primary.opacity(0.06), in: RoundedRectangle(cornerRadius: 6))
                    .overlay(alignment: .trailing) {
                        if model.sessionIDs.count > 1 {
                            Button { model.closeSession(id) } label: { Image(systemName: "xmark.circle.fill").font(.caption2) }
                                .buttonStyle(.plain).foregroundStyle(.secondary).offset(x: 10)
                        }
                    }
            }
            Button { model.openSession() } label: { Label("New Tab", systemImage: "plus") }
                .controlSize(.small)
                .disabled(model.sessionIDs.count >= LinuxEnvironmentLimits.maxSessions)
            Spacer()
        }
    }

    private var terminalCanvas: some View {
        // Honest placeholder: the real interactive VT emulator binds to the VM's virtio
        // console in the follow-up (it needs the guest console transport and a verified
        // bootable image). This never pretends to be a live shell.
        RoundedRectangle(cornerRadius: 8)
            .fill(Color.black.opacity(0.85))
            .frame(minHeight: 260)
            .overlay(
                Text("Interactive terminal connects here once the guest console transport and a verified bootable image land.")
                    .font(.callout.monospaced()).foregroundStyle(.green.opacity(0.8))
                    .multilineTextAlignment(.center).padding()
            )
    }

    private func statusLabel(_ text: String, color: Color) -> some View {
        HStack(spacing: 6) {
            Circle().fill(color).frame(width: 7, height: 7)
            Text("Linux Environment · \(text)").font(.callout.weight(.medium))
        }
    }
    private func summaryItem(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title.uppercased()).font(.caption2.weight(.semibold)).foregroundStyle(.secondary)
            Text(value).font(.callout)
        }
    }
    private func byteLabel(_ bytes: UInt64) -> String {
        let gib = Double(bytes) / Double(1024 * 1024 * 1024)
        return String(format: "%.0f GiB", gib)
    }
}

/// The explicit setup plan. Download/preparation begins only when the user confirms, and
/// only a reviewed, pinned image is used. With no verified production image bundled yet,
/// the confirm action is disabled and the pending state is stated plainly.
private struct SetupSheet: View {
    @ObservedObject var model: LinuxEnvironmentModel
    @Environment(\.dismiss) private var dismiss
    private var manifest: LinuxImageManifest? { LinuxImageCatalog.availableManifest }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Set Up Linux Terminal").font(.title2.weight(.semibold))
            if let manifest {
                Text("MACSPLOIT will download and verify a reviewed image, then prepare a persistent environment. Nothing runs until you start it.")
                    .font(.callout).foregroundStyle(.secondary)
                plan(manifest)
                HStack {
                    Spacer()
                    Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                    Button("Download & Set Up") {
                        model.startSetUp(manifest: manifest, resources: model.defaultResources)
                        dismiss()
                    }.buttonStyle(.borderedProminent)
                }
            } else {
                Label("A verified Kali image is not available yet.", systemImage: "clock.badge.exclamationmark")
                    .font(.callout.weight(.medium))
                Text("This build ships the full Terminal foundation — lifecycle, verified-download pipeline, persistent storage, and the Virtualization.framework adapter. A reviewed, pinned Kali-for-Virtualization.framework image and the app's virtualization signing are the remaining steps before the environment can be installed and booted.")
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                HStack { Spacer(); Button("Close") { dismiss() }.keyboardShortcut(.cancelAction) }
            }
        }
        .padding(24).frame(width: 520)
    }

    private func plan(_ manifest: LinuxImageManifest) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            planRow("Image", manifest.displayName)
            planRow("Source", manifest.diskImageURL)
            planRow("Verify", "SHA-256 pinned")
            planRow("Location", model.paths.root.path)
            planRow("Resources", "\(model.defaultResources.cpuCount) CPU · \(model.defaultResources.memoryBytes / (1024*1024*1024)) GiB RAM")
        }
        .font(.caption)
        .padding(10)
        .background(Color.primary.opacity(0.04), in: RoundedRectangle(cornerRadius: 8))
    }
    private func planRow(_ title: String, _ value: String) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Text(title).foregroundStyle(.secondary).frame(width: 80, alignment: .leading)
            Text(value).textSelection(.enabled)
        }
    }
}
