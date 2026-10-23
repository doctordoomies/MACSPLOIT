import Foundation

// The virtualization backend behind a protocol so the lifecycle/model layer is testable
// offline and never depends directly on Virtualization.framework. Conformers:
//
//   * `VZLinuxEnvironmentBackend`          — the real Apple Virtualization.framework adapter
//     (Apple Silicon, macOS 13+), guarded by `canImport(Virtualization)` and arch.
//   * `UnsupportedLinuxEnvironmentBackend` — PRODUCTION fail-closed backend for hosts that
//     cannot virtualize (Intel, or macOS < 13). It never pretends to run anything.
//   * `FakeLinuxEnvironmentBackend`        — TEST-ONLY deterministic backend. It must never
//     be used in production (an unsupported host gets `Unsupported`, not `Fake`).
//
// CI never boots a real guest; all automated coverage drives the fake backend.

public enum LinuxBackendError: Error, Equatable {
    case notPrepared
    case alreadyRunning
    case sessionLimitReached
    case unsupportedPlatform(String)
    /// Reserved interactive terminal transport is a later #90 slice. Real graphical
    /// installer/installed boot is supported independently of shell sessions.
    case notYetAvailable(String)
    case backendFailure(String)
}

/// One interactive shell session multiplexed over the single running VM. The on-screen VT
/// emulator binds to this; the foundation models identity and lifecycle, and the fake
/// backend exercises multi-session semantics offline. `close()` is idempotent.
public protocol LinuxTerminalSession: AnyObject, Sendable {
    var id: UUID { get }
    func close()
}

/// A running managed environment. Multiple terminal tabs share ONE of these.
@MainActor
public protocol LinuxRunningEnvironment: AnyObject, Sendable {
    var supportsTerminalSessions: Bool { get }
    var didStop: (@MainActor @Sendable (String?) -> Void)? { get set }
    func start() async throws
    var sessionCount: Int { get }
    func openSession() throws -> any LinuxTerminalSession
    /// Stop the VM. `graceful: true` requests an orderly shutdown within `timeout`; on
    /// failure the caller retries with `graceful: false` (forced). Throws if the stop does
    /// not complete, so the caller never assumes the VM is gone.
    func stop(graceful: Bool, timeout: TimeInterval) async throws
}

/// Prepares and boots the managed environment. Implementations must never start a VM
/// except from an explicit `start(...)` call.
@MainActor
public protocol LinuxEnvironmentBackend: Sendable {
    /// Non-nil when the host cannot run the managed VM; the reason is shown to the user and
    /// setup/start are blocked. `nil` means the platform is supported.
    var unsupportedReason: String? { get }
    /// Create new persistent machine identity and EFI variables. The model creates the
    /// sparse writable root disk; the downloader handles only installer media.
    func prepare(config: LinuxEnvironmentConfig, paths: LinuxEnvironmentPaths) async throws
    /// Validate identity and firmware without mutating or regenerating either.
    func validate(config: LinuxEnvironmentConfig, paths: LinuxEnvironmentPaths) throws
    /// Return an owned handle BEFORE asynchronous boot, so quit/remove cannot orphan it.
    func makeEnvironment(config: LinuxEnvironmentConfig, paths: LinuxEnvironmentPaths,
                         mode: LinuxBootMode) throws -> any LinuxRunningEnvironment
}

public extension LinuxEnvironmentBackend {
    var unsupportedReason: String? { nil }
    func validate(config: LinuxEnvironmentConfig, paths: LinuxEnvironmentPaths) throws { try LinuxVMStorage.validate(config: config, paths: paths) }
}

// MARK: - Production fail-closed backend

/// The backend installed on hosts that cannot virtualize. It reports an unsupported reason
/// and refuses every operation, so an Intel/old-macOS Mac can never appear to run a VM.
public struct UnsupportedLinuxEnvironmentBackend: LinuxEnvironmentBackend {
    public let unsupportedReason: String?
    public init(reason: String) { self.unsupportedReason = reason }
    public func prepare(config: LinuxEnvironmentConfig, paths: LinuxEnvironmentPaths) async throws {
        throw LinuxBackendError.unsupportedPlatform(unsupportedReason ?? "This Mac cannot run the managed Linux VM.")
    }
    public func makeEnvironment(config: LinuxEnvironmentConfig, paths: LinuxEnvironmentPaths, mode: LinuxBootMode) throws -> any LinuxRunningEnvironment {
        throw LinuxBackendError.unsupportedPlatform(unsupportedReason ?? "This Mac cannot run the managed Linux VM.")
    }
}

// MARK: - Offline fake backend (tests only)

/// A fully offline backend for tests and CI: it writes small placeholder artifacts, tracks
/// a single running environment, and vends in-memory sessions. Configurable to fail at
/// prepare/start and to fail graceful/forced stop, to exercise recovery paths. Boots no VM.
public final class FakeLinuxEnvironmentBackend: LinuxEnvironmentBackend, @unchecked Sendable {
    public enum Failure: Equatable { case none, onPrepare, onStart }
    private let failure: Failure
    private let startDelay: TimeInterval
    private let gracefulStopFails: Bool
    private let forcedStopFails: Bool
    private let forcedStopFailsTimes: Int
    /// The most recent running environment this backend vended (test inspection only).
    public private(set) var lastRunning: FakeRunningEnvironment?
    public private(set) var bootModes: [LinuxBootMode] = []
    public init(failure: Failure = .none, startDelay: TimeInterval = 0, gracefulStopFails: Bool = false,
                forcedStopFails: Bool = false, forcedStopFailsTimes: Int = 0) {
        self.failure = failure; self.startDelay = startDelay; self.gracefulStopFails = gracefulStopFails
        self.forcedStopFails = forcedStopFails; self.forcedStopFailsTimes = forcedStopFailsTimes
    }

    public func prepare(config: LinuxEnvironmentConfig, paths: LinuxEnvironmentPaths) async throws {
        if failure == .onPrepare { throw LinuxBackendError.backendFailure("Simulated prepare failure.") }
        // Small offline identity/EFI fixtures; sparse disk creation is shared production code.
        try FileManager.default.createDirectory(at: paths.root, withIntermediateDirectories: true)
        try LinuxVMStorage.writeNew(Data("fake-efi-vars".utf8), at: paths.auxStorage)
        try LinuxVMStorage.writeNew(Data("fake-machine-identifier".utf8), at: paths.machineIdentifier)
    }

    public func makeEnvironment(config: LinuxEnvironmentConfig, paths: LinuxEnvironmentPaths,
                                mode: LinuxBootMode) throws -> any LinuxRunningEnvironment {
        try validate(config: config, paths: paths)
        bootModes.append(mode)
        let run = FakeRunningEnvironment(gracefulStopFails: gracefulStopFails,
                                         forcedStopFails: forcedStopFails, forcedStopFailsTimes: forcedStopFailsTimes,
                                         startDelay: startDelay, startFails: failure == .onStart)
        lastRunning = run
        return run
    }

}

@MainActor
public final class FakeRunningEnvironment: LinuxRunningEnvironment, @unchecked Sendable {
    private let lock = NSLock()
    private var stopped = false
    public let supportsTerminalSessions = true
    public var didStop: (@MainActor @Sendable (String?) -> Void)?
    private let startDelay: TimeInterval
    private let startFails: Bool
    public private(set) var stopAttempts: [Bool] = []
    private var forcedFailuresRemaining: Int
    private let gracefulStopFails: Bool
    private let forcedStopFails: Bool
    /// Every session this environment vended (test inspection of close-exactly-once).
    public private(set) var vended: [FakeTerminalSession] = []
    public init(gracefulStopFails: Bool = false, forcedStopFails: Bool = false, forcedStopFailsTimes: Int = 0,
                startDelay: TimeInterval = 0, startFails: Bool = false) {
        self.startDelay = startDelay; self.startFails = startFails
        self.gracefulStopFails = gracefulStopFails; self.forcedStopFails = forcedStopFails
        self.forcedFailuresRemaining = forcedStopFailsTimes
    }

    public func start() async throws {
        if startDelay > 0 { try await Task.sleep(nanoseconds: UInt64(startDelay * 1_000_000_000)) }
        guard !stopped, !startFails else { throw LinuxBackendError.backendFailure("Simulated boot failure or stopped boot.") }
    }

    public func simulateGuestStop(error: String? = nil) { stopped = true; didStop?(error) }

    public var sessionCount: Int { lock.withLock { vended.count } }

    public func openSession() throws -> any LinuxTerminalSession {
        try lock.withLock {
            guard !stopped else { throw LinuxBackendError.notPrepared }
            guard vended.count < LinuxEnvironmentLimits.maxSessions else { throw LinuxBackendError.sessionLimitReached }
            let session = FakeTerminalSession()
            vended.append(session)
            return session
        }
    }

    public func stop(graceful: Bool, timeout: TimeInterval) async throws {
        stopAttempts.append(graceful)
        if graceful {
            if gracefulStopFails { throw LinuxBackendError.backendFailure("Simulated graceful-stop failure.") }
        } else {
            if forcedStopFails { throw LinuxBackendError.backendFailure("Simulated forced-stop failure.") }
            let shouldFail: Bool = lock.withLock {
                if forcedFailuresRemaining > 0 { forcedFailuresRemaining -= 1; return true }
                return false
            }
            if shouldFail { throw LinuxBackendError.backendFailure("Simulated forced-stop failure (transient).") }
        }
        lock.withLock { stopped = true } // vended retained for test inspection
    }
}

public final class FakeTerminalSession: LinuxTerminalSession, @unchecked Sendable {
    public let id = UUID()
    private let lock = NSLock()
    private var closes = 0
    public init() {}
    /// Idempotent; the test asserts the model closes each session exactly once.
    public func close() { lock.withLock { closes += 1 } }
    public var closeCount: Int { lock.withLock { closes } }
}

extension NSLock {
    func withLock<T>(_ body: () throws -> T) rethrows -> T {
        lock(); defer { unlock() }
        return try body()
    }
}
