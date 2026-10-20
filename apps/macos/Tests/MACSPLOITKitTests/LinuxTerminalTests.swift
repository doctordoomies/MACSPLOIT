import Foundation
import CryptoKit
import Testing
@testable import MACSPLOITKit

/// Offline coverage for the managed Linux terminal foundation (#90) and its hardening.
/// Everything runs against the fake/unsupported backends — no real image, no VM boot.
@MainActor @Suite struct LinuxTerminalTests {
    // MARK: Fixtures

    private func tempRoot() -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("macsploit-linux-\(UUID().uuidString)", isDirectory: true)
    }
    private func paths(_ appSupport: URL) -> LinuxEnvironmentPaths {
        LinuxEnvironmentPaths.standard(applicationSupport: appSupport)
    }
    private func fixtureManifest() -> LinuxImageManifest {
        LinuxImageManifest(identifier: "kali-arm64-fixture", displayName: "Kali Linux ARM64 (fixture)",
                           diskImageURL: "https://example.test/kali-arm64.img",
                           sha256: String(repeating: "a", count: 64), downloadByteCount: 4 * 1024 * 1024)
    }
    private func model(_ appSupport: URL, backend: any LinuxEnvironmentBackend = FakeLinuxEnvironmentBackend(),
                       downloader: any LinuxImageDownloader = FakeLinuxImageDownloader()) -> LinuxEnvironmentModel {
        LinuxEnvironmentModel(paths: paths(appSupport), backend: backend, downloader: downloader)
    }
    private func setUp(_ m: LinuxEnvironmentModel) async {
        await m.startSetUp(manifest: fixtureManifest(), resources: m.defaultResources)?.value
    }

    // MARK: Manifest validation (security envelope)

    @Test func manifestValidationEnforcesTheSecurityEnvelope() throws {
        try fixtureManifest().validate()

        var insecure = fixtureManifest(); insecure.diskImageURL = "http://example.test/x.img"
        #expect(throws: LinuxImageError.self) { try insecure.validate() }

        // Assemble a credential-bearing URL from fragments so no embedded-credential URL
        // literal ever exists in source (which repository policy correctly rejects).
        var credential = fixtureManifest()
        credential.diskImageURL = ["https://", "u", ":", "p", "@", "example.test/x.img"].joined()
        #expect(throws: LinuxImageError.self) { try credential.validate() }

        var badDigest = fixtureManifest(); badDigest.sha256 = "zz"
        #expect(throws: LinuxImageError.badChecksum) { try badDigest.validate() }

        var huge = fixtureManifest(); huge.downloadByteCount = LinuxImageManifest.maxArtifactBytes + 1
        #expect(throws: LinuxImageError.oversized) { try huge.validate() }

        var empty = fixtureManifest(); empty.downloadByteCount = 0
        #expect(throws: LinuxImageError.oversized) { try empty.validate() }

        var wrongSchema = fixtureManifest(); wrongSchema.schemaVersion = 99
        #expect(throws: LinuxImageError.unsupportedSchema(99)) { try wrongSchema.validate() }

        let data = try JSONEncoder().encode(fixtureManifest())
        #expect(try JSONDecoder().decode(LinuxImageManifest.self, from: data) == fixtureManifest())
        #expect(fixtureManifest().format == .efiRawDisk) // the only supported boot format
    }

    @Test func resourceDefaultsAndClampingStayWithinSaneBounds() {
        let host = LinuxHostResources(cpuCount: 10, memoryBytes: 32 * 1024 * 1024 * 1024)
        let defaults = LinuxResources.defaults(for: host)
        #expect(defaults.cpuCount == 5 && defaults.cpuCount <= host.maxCPU)
        #expect(defaults.memoryBytes >= LinuxEnvironmentLimits.minMemoryBytes && defaults.memoryBytes <= host.maxMemoryBytes)
        let greedy = LinuxResources(cpuCount: 999, memoryBytes: .max, diskSizeBytes: .max).clamped(to: host)
        #expect(greedy.cpuCount == host.maxCPU)
        #expect(greedy.memoryBytes <= host.maxMemoryBytes)
        #expect(greedy.diskSizeBytes == LinuxEnvironmentLimits.maxDiskBytes)
    }

    // MARK: Fail-closed unsupported backend

    @Test func unsupportedHostFailsClosedAndNeverRunsAFakeVM() async throws {
        let appSupport = tempRoot(); defer { try? FileManager.default.removeItem(at: appSupport) }
        let backend = UnsupportedLinuxEnvironmentBackend(reason: "Requires Apple Silicon.")
        let m = model(appSupport, backend: backend)
        #expect(m.state == .unsupported)
        #expect(!m.isSupported)
        #expect(m.errorMessage == "Requires Apple Silicon.")
        // Setup is refused; state stays unsupported.
        await setUp(m)
        #expect(m.state == .unsupported)
        // The backend itself refuses every operation.
        await #expect(throws: LinuxBackendError.self) { try await backend.prepare(config: LinuxEnvironmentConfig(image: fixtureManifest(), resources: .defaults()), paths: paths(appSupport)) }
        await #expect(throws: LinuxBackendError.self) { _ = try await backend.start(config: LinuxEnvironmentConfig(image: fixtureManifest(), resources: .defaults()), paths: paths(appSupport)) }
    }

    // MARK: Setup lifecycle

    @Test func setUpDownloadsVerifiesPersistsAndStops() async throws {
        let appSupport = tempRoot(); defer { try? FileManager.default.removeItem(at: appSupport) }
        let m = model(appSupport)
        #expect(m.state == .notConfigured)
        await setUp(m)
        #expect(m.state == .stopped)
        #expect(m.config?.image.identifier == "kali-arm64-fixture")
        #expect(FileManager.default.fileExists(atPath: m.paths.configFile.path))
        #expect(FileManager.default.fileExists(atPath: m.paths.diskImage.path))
    }

    @Test func checksumAndDownloadFailuresLeaveNothingConfigured() async throws {
        for outcome in [FakeLinuxImageDownloader.Outcome.checksumMismatch, .transportFailure, .oversized] {
            let appSupport = tempRoot(); defer { try? FileManager.default.removeItem(at: appSupport) }
            let m = model(appSupport, downloader: FakeLinuxImageDownloader(outcome))
            await setUp(m)
            #expect(m.state == .notConfigured)
            #expect(m.config == nil)
            #expect(m.errorMessage != nil)
            #expect(!FileManager.default.fileExists(atPath: m.paths.configFile.path))
        }
    }

    @Test func prepareFailureIsReportedAndRecoverable() async throws {
        let appSupport = tempRoot(); defer { try? FileManager.default.removeItem(at: appSupport) }
        let m = model(appSupport, backend: FakeLinuxEnvironmentBackend(failure: .onPrepare))
        await setUp(m)
        #expect(m.state == .notConfigured)
        #expect(m.errorMessage != nil)
    }

    @Test func setupCanBeCancelledAndReturnsToATruthfulState() async throws {
        let appSupport = tempRoot(); defer { try? FileManager.default.removeItem(at: appSupport) }
        let m = model(appSupport, downloader: FakeLinuxImageDownloader(.success, delay: 0.5))
        let task = m.startSetUp(manifest: fixtureManifest(), resources: m.defaultResources)
        #expect(m.state == .settingUp)
        m.cancelSetup()
        await task?.value
        #expect(m.state == .notConfigured)
        #expect(m.config == nil)
        #expect(m.errorMessage == "Setup was cancelled.")
        #expect(!FileManager.default.fileExists(atPath: m.paths.configFile.path))
        #expect(!FileManager.default.fileExists(atPath: m.paths.diskImage.path))
    }

    // MARK: Persistence / restart

    @Test func configurationPersistsAndRelaunchResolvesToStoppedNeverRunning() async throws {
        let appSupport = tempRoot(); defer { try? FileManager.default.removeItem(at: appSupport) }
        let first = model(appSupport)
        await setUp(first)
        await first.start()
        #expect(first.state == .running)

        let relaunched = model(appSupport)
        #expect(relaunched.state == .stopped)
        #expect(relaunched.config?.image.identifier == "kali-arm64-fixture")
        #expect(relaunched.sessionIDs.isEmpty)
        #expect(!relaunched.hasRunningHandle)
    }

    @Test func corruptOrIncompleteEnvironmentIsDetectedAsFailed() throws {
        let garbage = tempRoot(); defer { try? FileManager.default.removeItem(at: garbage) }
        let p1 = paths(garbage)
        try FileManager.default.createDirectory(at: p1.root, withIntermediateDirectories: true)
        try Data("not json".utf8).write(to: p1.configFile)
        #expect(LinuxEnvironmentModel.resolve(paths: p1).0 == .failed)

        let noDisk = tempRoot(); defer { try? FileManager.default.removeItem(at: noDisk) }
        let p2 = paths(noDisk)
        try FileManager.default.createDirectory(at: p2.root, withIntermediateDirectories: true)
        let config = LinuxEnvironmentConfig(image: fixtureManifest(), resources: LinuxResources.defaults())
        try JSONEncoder().encode(config).write(to: p2.configFile)
        #expect(LinuxEnvironmentModel.resolve(paths: p2).0 == .failed)
    }

    // MARK: Start / stop / sessions

    @Test func startStopAndTabsShareOneVM() async throws {
        let appSupport = tempRoot(); defer { try? FileManager.default.removeItem(at: appSupport) }
        let backend = FakeLinuxEnvironmentBackend()
        let m = model(appSupport, backend: backend)
        await setUp(m)
        await m.start()
        #expect(m.state == .running)
        #expect(m.sessionIDs.count == 1)
        for _ in 0..<3 { #expect(m.openSession()) }
        #expect(m.sessionIDs.count == 4)
        #expect(backend.lastRunning?.sessionCount == 4) // all on the one running VM
        await m.stop()
        #expect(m.state == .stopped)
        #expect(m.sessionIDs.isEmpty)
        #expect(!m.hasRunningHandle)
    }

    @Test func sessionCountIsBounded() async throws {
        let appSupport = tempRoot(); defer { try? FileManager.default.removeItem(at: appSupport) }
        let m = model(appSupport)
        await setUp(m); await m.start()
        while m.sessionIDs.count < LinuxEnvironmentLimits.maxSessions { #expect(m.openSession()) }
        #expect(!m.openSession())
        #expect(m.sessionIDs.count == LinuxEnvironmentLimits.maxSessions)
    }

    @Test func eachSessionIsClosedExactlyOnce() async throws {
        let appSupport = tempRoot(); defer { try? FileManager.default.removeItem(at: appSupport) }
        let backend = FakeLinuxEnvironmentBackend()
        let m = model(appSupport, backend: backend)
        await setUp(m); await m.start()
        _ = m.openSession(); _ = m.openSession() // 3 total (one opened by start)
        let vended = try #require(backend.lastRunning?.vended)
        #expect(vended.count == 3)
        // Closing one tab closes exactly that session handle.
        m.closeSession(m.sessionIDs[0])
        await m.stop() // closes the rest
        for session in vended { #expect(session.closeCount == 1) }
    }

    // MARK: Stop semantics (graceful → forced → confirmed-or-FAILED)

    @Test func stopGracefulSuccess() async throws {
        let appSupport = tempRoot(); defer { try? FileManager.default.removeItem(at: appSupport) }
        let m = model(appSupport, backend: FakeLinuxEnvironmentBackend())
        await setUp(m); await m.start()
        #expect(await m.stop())
        #expect(m.state == .stopped && !m.hasRunningHandle)
    }

    @Test func stopGracefulFailsThenForcedSucceeds() async throws {
        let appSupport = tempRoot(); defer { try? FileManager.default.removeItem(at: appSupport) }
        let m = model(appSupport, backend: FakeLinuxEnvironmentBackend(gracefulStopFails: true))
        await setUp(m); await m.start()
        #expect(await m.stop())
        #expect(m.state == .stopped && !m.hasRunningHandle)
    }

    @Test func stopGracefulAndForcedBothFailRetainsHandleAsFailed() async throws {
        let appSupport = tempRoot(); defer { try? FileManager.default.removeItem(at: appSupport) }
        let m = model(appSupport, backend: FakeLinuxEnvironmentBackend(gracefulStopFails: true, forcedStopFails: true))
        await setUp(m); await m.start()
        #expect(!(await m.stop()))
        #expect(m.state == .failed)
        #expect(m.hasRunningHandle) // the VM is NOT falsely reported gone
        #expect(m.errorMessage != nil)
    }

    @Test func forceStopFromFailedWithRetainedHandleStopsOnSuccess() async throws {
        let appSupport = tempRoot(); defer { try? FileManager.default.removeItem(at: appSupport) }
        // Graceful always fails; forced fails once (during stop) then succeeds (on Force Stop).
        let m = model(appSupport, backend: FakeLinuxEnvironmentBackend(gracefulStopFails: true, forcedStopFailsTimes: 1))
        await setUp(m); await m.start()
        #expect(!(await m.stop()))          // graceful fail + forced fail(1) → FAILED, handle held
        #expect(m.state == .failed && m.hasRunningHandle)
        #expect(await m.forceStop())        // forced now succeeds
        #expect(m.state == .stopped && !m.hasRunningHandle && m.sessionIDs.isEmpty)
    }

    @Test func forceStopFailureStaysFailedWithHandleRetained() async throws {
        let appSupport = tempRoot(); defer { try? FileManager.default.removeItem(at: appSupport) }
        let m = model(appSupport, backend: FakeLinuxEnvironmentBackend(gracefulStopFails: true, forcedStopFails: true))
        await setUp(m); await m.start()
        #expect(!(await m.stop()))
        #expect(!(await m.forceStop()))     // forced still fails
        #expect(m.state == .failed && m.hasRunningHandle)
    }

    @Test func failedStartIsRecoverable() async throws {
        let appSupport = tempRoot(); defer { try? FileManager.default.removeItem(at: appSupport) }
        let m = model(appSupport, backend: FakeLinuxEnvironmentBackend(failure: .onStart))
        await setUp(m)
        #expect(m.state == .stopped)
        await m.start()
        #expect(m.state == .failed && !m.hasRunningHandle)
        m.recover()
        #expect(m.state == .stopped)
    }

    @Test func staleStartCannotResurrectARemovedEnvironment() async throws {
        let appSupport = tempRoot(); defer { try? FileManager.default.removeItem(at: appSupport) }
        let m = model(appSupport, backend: FakeLinuxEnvironmentBackend(startDelay: 0.3))
        await setUp(m)
        let starting = Task { await m.start() }
        await Task.yield()
        await m.remove()
        await starting.value
        #expect(m.state == .notConfigured)
        #expect(m.sessionIDs.isEmpty && !m.hasRunningHandle && m.config == nil)
    }

    // MARK: Removal isolation

    @Test func removingTerminalDeletesOnlyItsOwnDirectory() async throws {
        let appSupport = tempRoot(); defer { try? FileManager.default.removeItem(at: appSupport) }
        let workspaces = appSupport.appendingPathComponent("workspaces", isDirectory: true)
        let providers = appSupport.appendingPathComponent("Providers", isDirectory: true)
        try FileManager.default.createDirectory(at: workspaces, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: providers, withIntermediateDirectories: true)
        try Data("ws".utf8).write(to: workspaces.appendingPathComponent("ws1.json"))
        try Data("tool".utf8).write(to: providers.appendingPathComponent("nmap"))

        let m = model(appSupport)
        await setUp(m)
        #expect(FileManager.default.fileExists(atPath: m.paths.root.path))
        await m.remove()
        #expect(m.state == .notConfigured)
        #expect(!FileManager.default.fileExists(atPath: m.paths.root.path))
        #expect(FileManager.default.fileExists(atPath: workspaces.appendingPathComponent("ws1.json").path))
        #expect(FileManager.default.fileExists(atPath: providers.appendingPathComponent("nmap").path))
    }

    // MARK: Downloader security helpers (offline)

    @Test func redirectPerURLPolicyEnforcesHttpsHostAndNoCredentials() {
        let allowed: Set<String> = ["example.test"]
        #expect(LinuxImageFetch.allowRedirect(to: URL(string: "https://example.test/x"), allowedHosts: allowed))
        #expect(!LinuxImageFetch.allowRedirect(to: URL(string: "http://example.test/x"), allowedHosts: allowed))
        let credential = URL(string: ["https://", "u", ":", "p", "@", "example.test/x"].joined())
        #expect(!LinuxImageFetch.allowRedirect(to: credential, allowedHosts: allowed))
        #expect(!LinuxImageFetch.allowRedirect(to: URL(string: "https://evil.test/x"), allowedHosts: allowed)) // unapproved host
        #expect(!LinuxImageFetch.allowRedirect(to: nil, allowedHosts: allowed))
    }

    @Test func redirectCounterEnforcesBudgetAcrossAChainWithoutACallerHeader() {
        let counter = LinuxImageRedirectCounter(maximum: 2, allowedHosts: ["example.test"])
        let url = URL(string: "https://example.test/next")
        #expect(counter.shouldFollow(to: url))   // 1
        #expect(counter.shouldFollow(to: url))   // 2 (exactly at limit)
        #expect(!counter.shouldFollow(to: url))  // 3 over limit, refused
        #expect(counter.redirectCount == 3)      // counter really incremented each time
        // A policy-violating target is refused even within budget.
        let fresh = LinuxImageRedirectCounter(maximum: 5, allowedHosts: ["example.test"])
        #expect(!fresh.shouldFollow(to: URL(string: "https://evil.test/x")))
        #expect(!fresh.shouldFollow(to: URL(string: "http://example.test/x")))
    }

    // MARK: Partial first-time setup cleanup

    @Test func freshSetupPrepareFailureRemovesTheNewlyStagedDisk() async throws {
        let appSupport = tempRoot(); defer { try? FileManager.default.removeItem(at: appSupport) }
        let m = model(appSupport, backend: FakeLinuxEnvironmentBackend(failure: .onPrepare))
        await setUp(m)
        #expect(m.state == .notConfigured)
        #expect(!FileManager.default.fileExists(atPath: m.paths.diskImage.path)) // never finalized
        #expect(!FileManager.default.fileExists(atPath: m.paths.staging.path))   // staging wiped
        #expect(!FileManager.default.fileExists(atPath: m.paths.configFile.path))
    }

    @Test func replacementFailurePreservesAPreExistingGoodDisk() async throws {
        let appSupport = tempRoot(); defer { try? FileManager.default.removeItem(at: appSupport) }
        let p = paths(appSupport)
        // A pre-existing good disk plus a corrupt config → the model resolves to FAILED with
        // the disk present (so setUp is permitted and a prior disk exists).
        try FileManager.default.createDirectory(at: p.root, withIntermediateDirectories: true)
        try Data("OLD-GOOD".utf8).write(to: p.diskImage)
        try Data("corrupt".utf8).write(to: p.configFile)
        let m = model(appSupport, backend: FakeLinuxEnvironmentBackend(failure: .onPrepare))
        #expect(m.state == .failed)
        await setUp(m) // prepare fails → finalize never runs → old disk preserved
        #expect(try String(contentsOf: p.diskImage, encoding: .utf8) == "OLD-GOOD")
        #expect(!FileManager.default.fileExists(atPath: p.staging.path))
    }

    @Test func streamingSHA256MatchesCryptoKitAndAtomicReplacePreservesGoodArtifact() throws {
        let dir = tempRoot(); defer { try? FileManager.default.removeItem(at: dir) }
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let file = dir.appendingPathComponent("payload.bin")
        let payload = Data((0..<(3 * 1024 * 1024)).map { UInt8($0 % 251) }) // > 1 MiB → multiple chunks
        try payload.write(to: file)
        let expected = SHA256.hash(data: payload).map { String(format: "%02x", $0) }.joined()
        #expect(try LinuxImageFetch.streamingSHA256(ofFileAt: file) == expected)

        // Atomic replace swaps in the new artifact and does not leave the old one behind.
        let destination = dir.appendingPathComponent("root.img")
        try Data("old-good".utf8).write(to: destination)
        let replacement = dir.appendingPathComponent("new.img")
        try Data("new-good".utf8).write(to: replacement)
        try LinuxImageFetch.atomicReplace(source: replacement, destination: destination)
        #expect(try String(contentsOf: destination, encoding: .utf8) == "new-good")
        #expect(!FileManager.default.fileExists(atPath: replacement.path))
    }
}
