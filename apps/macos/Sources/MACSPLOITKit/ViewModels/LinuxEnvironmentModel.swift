import Foundation
import Combine

/// Orchestrates the managed Linux terminal environment: the typed lifecycle, verified
/// setup, start/stop, interactive sessions (tabs), and persistence — all on top of a
/// `LinuxEnvironmentBackend` and `LinuxImageDownloader` so it is fully testable offline.
///
/// Guarantees: an unsupported host fails closed (never a fake VM); nothing starts a VM
/// except an explicit `start()`; a relaunch resolves to a non-running state; a superseded
/// or cancelled async operation never corrupts state (a monotonic generation gates every
/// post-await mutation); stop is graceful-then-forced and only reports STOPPED once the
/// backend confirms it (otherwise FAILED, retaining the handle); each UI tab owns one real
/// session handle that is closed exactly once; and removal deletes only this directory.
@MainActor
public final class LinuxEnvironmentModel: ObservableObject {
    @Published public private(set) var state: LinuxEnvironmentState
    @Published public private(set) var config: LinuxEnvironmentConfig?
    @Published public private(set) var errorMessage: String?
    @Published public private(set) var setupStage: String = ""
    /// Open terminal tabs (presentation mirror of the real session handles below).
    @Published public private(set) var sessionIDs: [UUID] = []
    /// True while a running VM handle is held (used to offer a forced stop from FAILED).
    @Published public private(set) var hasRunningHandle = false

    public let paths: LinuxEnvironmentPaths
    private let backend: any LinuxEnvironmentBackend
    private let downloader: any LinuxImageDownloader
    private var running: (any LinuxRunningEnvironment)?
    private var sessions: [any LinuxTerminalSession] = []
    private var setupTask: Task<Void, Never>?
    private var generation = 0

    public init(paths: LinuxEnvironmentPaths,
                backend: any LinuxEnvironmentBackend,
                downloader: any LinuxImageDownloader) {
        self.paths = paths
        self.backend = backend
        self.downloader = downloader
        if let reason = backend.unsupportedReason {
            self.state = .unsupported
            self.config = nil
            self.errorMessage = reason
        } else {
            let (initialState, loadedConfig) = Self.resolve(paths: paths)
            self.state = initialState
            self.config = loadedConfig
            if initialState == .failed {
                self.errorMessage = "The Linux environment is incomplete or corrupt — an earlier setup may not have finished. Recreate it to start over."
            }
        }
    }

    /// Resolve the on-launch state purely from disk. A valid config + its disk → STOPPED
    /// (never auto-started). Any setup-owned artifact present WITHOUT a complete valid
    /// environment → FAILED (an incomplete/corrupt environment, e.g. a crash or power loss
    /// mid-setup) so the UI can offer Recreate — never silently NOT_CONFIGURED over a
    /// possibly multi-GB orphan, and never auto-deleted at launch. A completely empty
    /// terminal directory → NOT_CONFIGURED.
    static func resolve(paths: LinuxEnvironmentPaths) -> (LinuxEnvironmentState, LinuxEnvironmentConfig?) {
        let fm = FileManager.default
        let hasDisk = fm.fileExists(atPath: paths.diskImage.path)
        let hasAux = fm.fileExists(atPath: paths.auxStorage.path)
        let hasStaging = fm.fileExists(atPath: paths.staging.path)
        guard fm.fileExists(atPath: paths.configFile.path) else {
            // No config: an orphaned artifact means an incomplete setup, not "nothing here".
            return (hasDisk || hasAux || hasStaging) ? (.failed, nil) : (.notConfigured, nil)
        }
        guard let data = try? Data(contentsOf: paths.configFile),
              let config = try? JSONDecoder().decode(LinuxEnvironmentConfig.self, from: data),
              config.schemaVersion == LinuxEnvironmentConfig.supportedSchema else {
            return (.failed, nil) // corrupt/incompatible config
        }
        guard hasDisk else { return (.failed, config) } // config without its disk
        return (.stopped, config)
    }

    public var defaultResources: LinuxResources { LinuxResources.defaults() }
    public var isSupported: Bool { state != .unsupported }

    // MARK: - Setup (owned, cancellable)

    /// Begin explicit setup in an owned task so it can be cancelled. Safe to call only from
    /// NOT_CONFIGURED or FAILED.
    /// Whether a FAILED environment can be retried as-is (a valid config + disk exist).
    /// Otherwise it is incomplete/corrupt and the only option is Recreate.
    public var canRetry: Bool { running == nil && Self.resolve(paths: paths).0 == .stopped }

    /// Begin explicit setup. **Fresh-only:** permitted only from NOT_CONFIGURED. A FAILED
    /// environment is handled by Retry (when valid) or explicit Recreate (remove →
    /// NOT_CONFIGURED → Set Up again); setup never runs over existing artifacts, so there is
    /// no prior disk/config to preserve or replace.
    @discardableResult
    public func startSetUp(manifest: LinuxImageManifest, resources: LinuxResources) -> Task<Void, Never>? {
        guard state == .notConfigured else { return nil }
        generation += 1
        let gen = generation
        state = .settingUp; errorMessage = nil; setupStage = "Preparing setup…"
        let clamped = resources.clamped()
        let task = Task { [weak self] in
            await self?.performSetUp(manifest: manifest, resources: clamped, gen: gen)
            await MainActor.run { self?.setupTask = nil }
        }
        setupTask = task
        return task
    }

    /// Cancel an in-progress setup: cancels the download/preparation task, wipes staging,
    /// leaves any finalized good state intact, and returns to a truthful state.
    public func cancelSetup() {
        guard state == .settingUp else { return }
        setupTask?.cancel()
    }

    private func performSetUp(manifest: LinuxImageManifest, resources: LinuxResources, gen: Int) async {
        // Fresh-only: the terminal directory is empty here, so there is no prior environment
        // to preserve. The order commits the config durably BEFORE the disk goes live, and
        // finalizes the disk LAST — so a crash or failure after the disk is live always has
        // a matching config, and any earlier failure leaves no live disk.
        do {
            try manifest.validate()
            try Task.checkCancellation()
            guard gen == generation else { return }
            setupStage = "Downloading \(manifest.displayName)…"
            try await downloader.fetch(manifest, into: paths) { _ in } // verifies into staging
            try Task.checkCancellation()
            guard gen == generation else { return }
            setupStage = "Preparing environment…"
            let config = LinuxEnvironmentConfig(image: manifest, resources: resources)
            try await backend.prepare(config: config, paths: paths) // small aux state only
            try Task.checkCancellation()
            guard gen == generation else { return }
            try persist(config) // config durably committed BEFORE the disk goes live
            try Task.checkCancellation()
            guard gen == generation else { return }
            // Finalize the disk LAST. A crash after this has a matching config (→ STOPPED);
            // a crash before it leaves config-without-disk (→ FAILED, recreatable).
            try LinuxImageFetch.atomicReplace(source: paths.stagedDisk, destination: paths.diskImage)
            try? FileManager.default.removeItem(at: paths.staging)
            self.config = config
            state = .stopped
            setupStage = ""
        } catch {
            guard gen == generation else { return }
            // Fresh-only: nothing pre-existing to preserve — remove every artifact this run
            // created and return to a truthful NOT_CONFIGURED.
            removeAllArtifacts()
            config = nil
            setupStage = ""
            state = .notConfigured
            if error is CancellationError || (error as? LinuxImageDownloadError) == .cancelled {
                errorMessage = "Setup was cancelled."
            } else {
                errorMessage = Self.describe(error)
            }
        }
    }

    // MARK: - Start / stop

    /// Boot the VM — only from an explicit user action on a STOPPED environment.
    public func start() async {
        guard state.canStart, let config else { return }
        generation += 1
        let gen = generation
        state = .starting; errorMessage = nil
        do {
            let run = try await backend.start(config: config, paths: paths)
            guard gen == generation else { try? await run.stop(graceful: false, timeout: 5); return }
            running = run
            hasRunningHandle = true
            state = .running
            try openSessionLocked() // first tab
        } catch {
            guard gen == generation else { return }
            running = nil
            hasRunningHandle = false
            closeAllSessions()
            state = .failed
            errorMessage = Self.describe(error)
        }
    }

    /// Return a FAILED-but-configured environment (with no live handle) to STOPPED.
    public func recover() {
        guard state == .failed, running == nil else { return }
        let (resolved, loaded) = Self.resolve(paths: paths)
        state = resolved
        config = loaded ?? config
        errorMessage = nil
    }

    /// Stop the VM: attempt graceful shutdown, then a forced stop, and only report STOPPED
    /// once the backend confirms. If both fail, go to FAILED while RETAINING the handle so
    /// the VM is never falsely reported gone. Returns whether the VM is confirmed stopped.
    @discardableResult
    public func stop() async -> Bool {
        guard let run = running, state == .running || state == .starting else { return state == .stopped }
        generation += 1
        let gen = generation
        state = .stopping; errorMessage = nil

        if await attemptStop(run, graceful: true, timeout: 15, gen: gen) { return finishStopped(gen: gen) }
        guard gen == generation else { return false }
        if await attemptStop(run, graceful: false, timeout: 5, gen: gen) { return finishStopped(gen: gen) }
        guard gen == generation else { return false }

        // Both failed: the VM may still be running. Do not pretend it is gone.
        state = .failed
        errorMessage = "The Linux VM did not stop. The environment is still held; try Force Stop."
        return false
    }

    /// Explicit forced stop, used from FAILED while a handle is still held (a stop that did
    /// not confirm). Attempts only the backend forced-stop path; on confirmed success it
    /// releases the handle and goes STOPPED, otherwise it remains FAILED with the handle.
    @discardableResult
    public func forceStop() async -> Bool {
        guard let run = running,
              state == .failed || state == .running || state == .starting || state == .stopping else { return false }
        generation += 1
        let gen = generation
        state = .stopping; errorMessage = nil
        if await attemptStop(run, graceful: false, timeout: 5, gen: gen) { return finishStopped(gen: gen) }
        guard gen == generation else { return false }
        state = .failed
        errorMessage = "Forced stop did not complete. The Linux VM is still held."
        return false
    }

    private func attemptStop(_ run: any LinuxRunningEnvironment, graceful: Bool, timeout: TimeInterval, gen: Int) async -> Bool {
        do { try await run.stop(graceful: graceful, timeout: timeout); return true }
        catch { return false }
    }

    private func finishStopped(gen: Int) -> Bool {
        guard gen == generation else { return false }
        closeAllSessions()
        running = nil
        hasRunningHandle = false
        state = .stopped
        return true
    }

    // MARK: - Sessions (real handle ownership)

    @discardableResult
    public func openSession() -> Bool {
        guard state == .running else { return false }
        do { try openSessionLocked(); return true }
        catch { errorMessage = Self.describe(error); return false }
    }

    public func closeSession(_ id: UUID) {
        guard let index = sessions.firstIndex(where: { $0.id == id }) else { return }
        sessions[index].close()
        sessions.remove(at: index)
        sessionIDs = sessions.map(\.id)
    }

    private func openSessionLocked() throws {
        guard let run = running else { throw LinuxBackendError.notPrepared }
        let session = try run.openSession()
        sessions.append(session)
        sessionIDs = sessions.map(\.id)
    }

    private func closeAllSessions() {
        sessions.forEach { $0.close() }
        sessions.removeAll()
        sessionIDs = []
    }

    // MARK: - Removal

    /// Remove the managed environment entirely. Stops a running VM first; if it cannot be
    /// stopped, removal is refused (never delete files out from under a live VM). Deletes
    /// ONLY the terminal's own directory — workspaces/Assets/Evidence/Findings/providers
    /// and other settings are untouched.
    public func remove() async {
        if running != nil {
            _ = await stop()
            if running != nil {
                errorMessage = "Stop the VM before removing the environment."
                return
            }
        }
        generation += 1
        closeAllSessions()
        try? FileManager.default.removeItem(at: paths.root)
        running = nil
        hasRunningHandle = false
        config = nil
        errorMessage = nil
        setupStage = ""
        state = .notConfigured
    }

    // MARK: - Persistence helpers

    private func persist(_ config: LinuxEnvironmentConfig) throws {
        try FileManager.default.createDirectory(at: paths.root, withIntermediateDirectories: true)
        let data = try JSONEncoder().encode(config)
        try data.write(to: paths.configFile, options: .atomic)
    }

    /// Remove every setup-owned artifact (fresh-only setup never has a prior env to keep).
    private func removeAllArtifacts() {
        try? FileManager.default.removeItem(at: paths.staging)
        try? FileManager.default.removeItem(at: paths.diskImage)
        try? FileManager.default.removeItem(at: paths.configFile)
        try? FileManager.default.removeItem(at: paths.auxStorage)
    }

    private static func describe(_ error: Error) -> String {
        switch error {
        case let e as LinuxImageError: return "Image error: \(e)"
        case LinuxImageDownloadError.checksumMismatch: return "The downloaded image failed its integrity check. Nothing was installed."
        case LinuxImageDownloadError.oversized: return "The image exceeded the allowed download size. Nothing was installed."
        case LinuxImageDownloadError.cancelled: return "Setup was cancelled."
        case let LinuxImageDownloadError.badStatus(code): return "Download failed with HTTP status \(code)."
        case LinuxImageDownloadError.insecureRedirect: return "The download attempted an insecure or credential-bearing redirect and was refused."
        case LinuxImageDownloadError.tooManyRedirects: return "The download exceeded the allowed number of redirects."
        case let LinuxImageDownloadError.transport(message): return "Download failed: \(message)"
        case let LinuxImageDownloadError.writeFailed(message): return "Could not write the environment: \(message)"
        case let LinuxBackendError.unsupportedPlatform(message): return message
        case let LinuxBackendError.notYetAvailable(message): return message
        case let LinuxBackendError.backendFailure(message): return message
        case LinuxBackendError.sessionLimitReached: return "The maximum number of terminal tabs is open."
        case LinuxBackendError.notPrepared: return "The environment is not prepared."
        default: return error.localizedDescription
        }
    }
}
