import Foundation
import Combine

/// Owns one VM across preparation, installer boot, and installed boot. No workspace/provider
/// mutations, no implicit download/boot, and no inferred installation success.
@MainActor
public final class LinuxEnvironmentModel: ObservableObject {
    @Published public private(set) var state: LinuxEnvironmentState
    @Published public private(set) var config: LinuxEnvironmentConfig?
    @Published public private(set) var errorMessage: String?
    @Published public private(set) var bootStage = ""
    @Published public private(set) var setupStage = ""
    @Published public private(set) var setupProgress: Double = 0
    @Published public private(set) var sessionIDs: [UUID] = []
    @Published public private(set) var hasRunningHandle = false
    @Published public private(set) var isShuttingDown = false
    public let paths: LinuxEnvironmentPaths
    private let backend: any LinuxEnvironmentBackend
    private let downloader: any LinuxImageDownloader
    private let installerVerifier: any LinuxInstallerVerifying
    private var installerVerificationTask: Task<Void, Error>?
    private var requiresInstallerRecreation = false
    private var running: (any LinuxRunningEnvironment)?
    private var sessions: [any LinuxTerminalSession] = []
    private var setupTask: Task<Void, Never>?
    private var generation = 0

    /// The presentation bridge may expose the real VM's graphical console, never a fake
    /// shell. Lifecycle operations still go exclusively through this model.
    public var runningEnvironment: (any LinuxRunningEnvironment)? { running }

    public init(paths: LinuxEnvironmentPaths, backend: any LinuxEnvironmentBackend,
                downloader: any LinuxImageDownloader,
                installerVerifier: any LinuxInstallerVerifying = StreamingLinuxInstallerVerifier()) {
        self.paths = paths; self.backend = backend; self.downloader = downloader
        self.installerVerifier = installerVerifier
        if let reason = backend.unsupportedReason {
            state = .unsupported; errorMessage = reason
        } else {
            let (resolved, loaded) = Self.resolve(paths: paths)
            state = resolved; config = loaded
            if let loaded, resolved != .failed {
                do { try backend.validate(config: loaded, paths: paths) }
                catch { state = .failed }
            }
            if state == .failed { errorMessage = "The Linux environment is incomplete or corrupt. Recreate it to start over; existing VM identity is never silently replaced." }
        }
    }

    static func resolve(paths: LinuxEnvironmentPaths) -> (LinuxEnvironmentState, LinuxEnvironmentConfig?) {
        let fm = FileManager.default
        guard fm.fileExists(atPath: paths.root.path) else { return (.notConfigured, nil) }
        guard (try? paths.root.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink) != true,
              let children = try? fm.contentsOfDirectory(atPath: paths.root.path) else { return (.failed, nil) }
        if children.isEmpty { return (.notConfigured, nil) }
        guard (try? LinuxVMStorage.requireRegularFile(paths.configFile, maximumBytes: 64 * 1024)) != nil,
              let data = try? Data(contentsOf: paths.configFile),
              let config = try? JSONDecoder().decode(LinuxEnvironmentConfig.self, from: data),
              config.schemaVersion == LinuxEnvironmentConfig.supportedSchema else { return (.failed, nil) }
        do {
            try LinuxVMStorage.validate(config: config, paths: paths)
            guard !fm.fileExists(atPath: paths.staging.path) else { return (.failed, config) }
            return (config.installationStatus == .installed ? .stopped : .installReady, config)
        } catch { return (.failed, config) }
    }

    public var defaultResources: LinuxResources { .defaults() }
    public var isSupported: Bool { state != .unsupported }
    public var canCancelBootVerification: Bool { installerVerificationTask != nil && state == .starting }
    public var canRetry: Bool {
        guard !requiresInstallerRecreation, running == nil else { return false }
        let (resolved, loaded) = Self.resolve(paths: paths)
        guard resolved == .stopped || resolved == .installReady, let loaded else { return false }
        return (try? backend.validate(config: loaded, paths: paths)) != nil
    }

    @discardableResult
    public func startSetUp(manifest: LinuxImageManifest, resources: LinuxResources) -> Task<Void, Never>? {
        guard !isShuttingDown, state == .notConfigured, Self.resolve(paths: paths).0 == .notConfigured else { return nil }
        generation += 1
        let gen = generation
        state = .settingUp; errorMessage = nil; setupStage = "Preparing setup…"; setupProgress = 0
        let task = Task { [weak self] in
            guard let self else { return }
            await self.performSetUp(manifest: manifest, resources: resources.clamped(), gen: gen)
            if gen == self.generation { self.setupTask = nil }
        }
        setupTask = task
        return task
    }

    public func cancelSetup() { if state == .settingUp { setupTask?.cancel() } }

    private func performSetUp(manifest: LinuxImageManifest, resources: LinuxResources, gen: Int) async {
        do {
            try manifest.validate(); try Task.checkCancellation()
            guard gen == generation else { return }
            try FileManager.default.createDirectory(at: paths.root, withIntermediateDirectories: true,
                                                     attributes: [.posixPermissions: 0o700])
            setupStage = "Downloading and verifying \(manifest.displayName)…"
            try await downloader.fetch(manifest, into: paths) { [weak self] progress in
                Task { @MainActor in
                    guard let self, self.generation == gen, self.state == .settingUp else { return }
                    self.setupProgress = min(1, max(0, progress))
                }
            }
            try Task.checkCancellation(); guard gen == generation else { return }
            setupStage = "Creating sparse disk and persistent VM identity…"
            try LinuxVMStorage.createSparseDisk(at: paths.diskImage, byteCount: resources.diskSizeBytes)
            var prepared = LinuxEnvironmentConfig(image: manifest, resources: resources)
            try await backend.prepare(config: prepared, paths: paths)
            try Task.checkCancellation(); guard gen == generation else { return }
            try LinuxVMStorage.recordIdentity(in: &prepared, paths: paths)
            // The download is installer media, never the installed root disk.
            guard !FileManager.default.fileExists(atPath: paths.installerISO.path) else { throw LinuxBackendError.notPrepared }
            try FileManager.default.moveItem(at: paths.stagedInstaller, to: paths.installerISO)
            try backend.validate(config: prepared, paths: paths)
            try Task.checkCancellation()
            try persist(prepared) // commit only after all owned artifacts are ready
            try FileManager.default.removeItem(at: paths.staging)
            config = prepared; state = .installReady; setupStage = ""; setupProgress = 1
        } catch {
            guard gen == generation else { return }
            // Setup is fresh-only; never remove/overwrite a previously installed disk.
            for url in [paths.staging, paths.diskImage, paths.installerISO, paths.machineIdentifier, paths.auxStorage, paths.configFile] {
                if FileManager.default.fileExists(atPath: url.path) { try? FileManager.default.removeItem(at: url) }
            }
            config = nil; state = Self.resolve(paths: paths).0; setupStage = ""
            errorMessage = error is CancellationError ? "Setup was cancelled." : Self.describe(error)
        }
    }

    public func installKali() async {
        guard state == .installReady, config?.installationStatus == .awaitingOwnerConfirmation else { return }
        await boot(mode: .installation)
    }

    public func start() async {
        guard state == .stopped, config?.installationStatus == .installed else { return }
        await boot(mode: .installed)
    }

    private func boot(mode: LinuxBootMode) async {
        guard !isShuttingDown, running == nil, let config else { return }
        generation += 1; let gen = generation
        state = .starting; errorMessage = nil
        if mode == .installation, !(await verifyCachedInstaller(config: config, gen: gen)) { return }
        guard gen == generation, !isShuttingDown else { return }
        if Task.isCancelled { state = restingState; return }
        do {
            try backend.validate(config: config, paths: paths)
            let run = try backend.makeEnvironment(config: config, paths: paths, mode: mode)
            running = run; hasRunningHandle = true // own it even during asynchronous start
            run.didStop = { [weak self, weak run] error in
                guard let self, let run, self.running === run else { return }
                self.generation += 1
                self.releaseStoppedHandle()
                self.state = error == nil ? self.restingState : .failed
                self.errorMessage = error
            }
            try await run.start()
            guard gen == generation, running === run else { return }
            state = mode == .installation ? .installing : .running
            // Real VT transport is a later slice. Never turn a fake session into a live shell.
            if mode == .installed, run.supportsTerminalSessions { try openSessionLocked() }
        } catch {
            guard gen == generation else { return }
            if let run = running {
                if await attemptStop(run, graceful: false, timeout: 5) { releaseStoppedHandle() }
            }
            guard gen == generation else { return }
            state = .failed; errorMessage = Self.describe(error)
        }
    }

    /// Recheck the persisted artifact immediately before installation VM construction.
    /// Normal installed boots never enter this boundary or depend on cached media.
    private func verifyCachedInstaller(config: LinuxEnvironmentConfig, gen: Int) async -> Bool {
        let verifier = installerVerifier
        let installerISO = paths.installerISO
        let task = Task { try await verifier.verify(at: installerISO, manifest: config.image) }
        installerVerificationTask = task
        bootStage = "Verifying cached Kali installer…"
        defer {
            if gen == generation { installerVerificationTask = nil; bootStage = "" }
        }
        do {
            try await withTaskCancellationHandler {
                try await task.value
            } onCancel: { task.cancel() }
            guard gen == generation, !isShuttingDown else { return false }
            try Task.checkCancellation()
            if task.isCancelled { throw CancellationError() }
            return true
        } catch {
            guard gen == generation else { return false }
            if Task.isCancelled || task.isCancelled || error is CancellationError || (error as? LinuxImageDownloadError) == .cancelled {
                state = restingState; errorMessage = "Installer verification was cancelled."
            } else {
                requiresInstallerRecreation = true
                state = .failed
                errorMessage = "Cached Kali installer integrity verification failed. Recreate the environment before installing. Existing files were preserved. " + Self.describe(error)
            }
            return false
        }
    }

    /// Invalidate boot intent before cancelling, then drain verification before removal/quit.
    /// Even a late successful verifier cannot construct or start a VM afterward.
    public func cancelBootVerification() async {
        guard let task = installerVerificationTask else { return }
        generation += 1; let gen = generation
        task.cancel()
        _ = await task.result
        guard gen == generation else { return }
        installerVerificationTask = nil; bootStage = ""
        state = restingState; errorMessage = "Installer verification was cancelled."
    }

    /// Explicit owner attestation after Kali reports success; neither file existence nor
    /// installer shutdown can promote an incomplete environment to installed.
    @discardableResult
    public func confirmInstallationComplete() async -> Bool {
        guard !isShuttingDown, config?.installationStatus == .awaitingOwnerConfirmation,
              state == .installReady || state == .installing else { return false }
        if running != nil, !(await stop()) { return false }
        guard running == nil, var updated = config else { return false }
        do {
            try backend.validate(config: updated, paths: paths)
            updated.installationStatus = .installed
            try persist(updated)
            config = updated; state = .stopped; errorMessage = nil
            return true
        } catch { state = .failed; errorMessage = Self.describe(error); return false }
    }

    public func recover() {
        guard !requiresInstallerRecreation, state == .failed, running == nil else { return }
        let (resolved, loaded) = Self.resolve(paths: paths)
        do {
            if let loaded { try backend.validate(config: loaded, paths: paths) }
            state = resolved; config = loaded; errorMessage = resolved == .failed ? "Recreate the incomplete environment." : nil
        } catch { errorMessage = Self.describe(error) }
    }

    private var restingState: LinuxEnvironmentState { config?.installationStatus == .installed ? .stopped : .installReady }

    @discardableResult
    public func stop() async -> Bool {
        if installerVerificationTask != nil { await cancelBootVerification() }
        guard let run = running else { return state == .stopped || state == .installReady }
        guard state != .stopping else { return false }
        generation += 1; let gen = generation
        state = .stopping; errorMessage = nil
        if await attemptStop(run, graceful: true, timeout: 15) { return finishStopped(run: run, gen: gen) }
        guard gen == generation else { return running == nil }
        if await attemptStop(run, graceful: false, timeout: 5) { return finishStopped(run: run, gen: gen) }
        guard gen == generation else { return running == nil }
        state = .failed; errorMessage = "The VM did not stop. Its handle is retained; try Force Stop."
        return false
    }

    @discardableResult
    public func forceStop() async -> Bool {
        guard let run = running else { return false }
        generation += 1; let gen = generation; state = .stopping
        if await attemptStop(run, graceful: false, timeout: 5) { return finishStopped(run: run, gen: gen) }
        guard gen == generation else { return running == nil }
        state = .failed; errorMessage = "Forced stop did not complete. The VM is still held."
        return false
    }

    private func attemptStop(_ run: any LinuxRunningEnvironment, graceful: Bool, timeout: TimeInterval) async -> Bool {
        do { try await run.stop(graceful: graceful, timeout: timeout); return true } catch { return false }
    }

    private func finishStopped(run: any LinuxRunningEnvironment, gen: Int) -> Bool {
        guard gen == generation else { return running == nil }
        if running === run { releaseStoppedHandle() }
        state = restingState
        return true
    }

    private func releaseStoppedHandle() {
        running?.didStop = nil; closeAllSessions(); running = nil; hasRunningHandle = false
    }

    /// Called by the app's narrow termination hook. Refuse quit on an uncertain stop;
    /// cancelling a quit is preferable to abandoning a live managed guest.
    public func shutdownForApplicationTermination() async -> Bool {
        guard !isShuttingDown else { return false }
        isShuttingDown = true
        if let setupTask { setupTask.cancel(); await setupTask.value }
        await cancelBootVerification()
        var stopped = running == nil
        if !stopped { stopped = await stop() }
        if !stopped { isShuttingDown = false }
        return stopped
    }

    @discardableResult
    public func openSession() -> Bool {
        guard state == .running, running?.supportsTerminalSessions == true else { return false }
        do { try openSessionLocked(); return true } catch { errorMessage = Self.describe(error); return false }
    }
    public func closeSession(_ id: UUID) {
        guard let i = sessions.firstIndex(where: { $0.id == id }) else { return }
        sessions[i].close(); sessions.remove(at: i); sessionIDs = sessions.map(\.id)
    }
    private func openSessionLocked() throws {
        guard let running else { throw LinuxBackendError.notPrepared }
        sessions.append(try running.openSession()); sessionIDs = sessions.map(\.id)
    }
    private func closeAllSessions() { sessions.forEach { $0.close() }; sessions = []; sessionIDs = [] }

    public func remove() async {
        guard !isShuttingDown, state != .stopping else { return }
        if let setupTask { setupTask.cancel(); await setupTask.value }
        await cancelBootVerification()
        if running != nil, !(await stop()) { errorMessage = "Stop the VM before removing the environment."; return }
        generation += 1
        do {
            if FileManager.default.fileExists(atPath: paths.root.path) { try FileManager.default.removeItem(at: paths.root) }
            releaseStoppedHandle(); requiresInstallerRecreation = false; config = nil; errorMessage = nil; setupStage = ""; setupProgress = 0; state = .notConfigured
        } catch { state = .failed; errorMessage = Self.describe(error) }
    }

    private func persist(_ config: LinuxEnvironmentConfig) throws {
        try JSONEncoder().encode(config).write(to: paths.configFile, options: .atomic)
    }
    private static func describe(_ error: Error) -> String {
        switch error {
        case is CancellationError, LinuxImageDownloadError.cancelled: return "Setup was cancelled."
        case LinuxImageDownloadError.checksumMismatch: return "The installer failed its SHA-256 integrity check. Nothing was installed."
        case LinuxImageDownloadError.sizeMismatch: return "The installer size did not match the reviewed release."
        case LinuxImageDownloadError.oversized: return "The installer exceeded the allowed download size."
        case LinuxImageDownloadError.insecureRedirect: return "An unreviewed, insecure or credential-bearing redirect was refused."
        case LinuxImageDownloadError.tooManyRedirects: return "The download exceeded the allowed redirect count."
        case let LinuxBackendError.unsupportedPlatform(message), let LinuxBackendError.notYetAvailable(message),
             let LinuxBackendError.backendFailure(message): return message
        default: return error.localizedDescription
        }
    }
}
