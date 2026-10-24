import Foundation
import CryptoKit
import Testing
@testable import MACSPLOITKit

/// Exercises the actual shared streaming boundary with tiny, offline persisted media.
@MainActor @Suite struct LinuxCachedInstallerTests {
    private func root() -> URL { FileManager.default.temporaryDirectory.appendingPathComponent("macsploit-cached-iso-\(UUID())") }
    private func model(_ root: URL, backend: FakeLinuxEnvironmentBackend,
                       verifier: any LinuxInstallerVerifying = StreamingLinuxInstallerVerifier()) -> LinuxEnvironmentModel {
        LinuxEnvironmentModel(paths: .standard(applicationSupport: root), backend: backend,
                              downloader: FakeLinuxImageDownloader(), installerVerifier: verifier)
    }
    private func prepare(_ m: LinuxEnvironmentModel) async {
        let bytes = Data("fake-installer-iso".utf8)
        let manifest = LinuxImageManifest(identifier: "cached-fixture", displayName: "Offline cache fixture",
            installerURL: "https://example.test/installer.iso",
            sha256: SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined(), downloadByteCount: UInt64(bytes.count))
        await m.startSetUp(manifest: manifest, resources: m.defaultResources)?.value
        #expect(m.state == .installReady)
    }

    @Test func sameSizeTamperAfterRelaunchFailsBeforeVMCreationAndPreservesData() async throws {
        let root = root(); defer { try? FileManager.default.removeItem(at: root) }
        let backend = FakeLinuxEnvironmentBackend()
        let original = model(root, backend: backend); await prepare(original)
        let configBytes = try Data(contentsOf: original.paths.configFile)
        let id = try Data(contentsOf: original.paths.machineIdentifier)
        var bytes = try Data(contentsOf: original.paths.installerISO)
        let count = bytes.count; bytes[0] ^= 1
        try bytes.write(to: original.paths.installerISO)
        #expect(bytes.count == count)
        let relaunched = model(root, backend: backend)
        #expect(relaunched.state == .installReady) // cheap size checks alone cannot catch this
        await relaunched.installKali()
        #expect(relaunched.state == .failed && !relaunched.canRetry)
        #expect(relaunched.errorMessage?.contains("integrity") == true)
        #expect(relaunched.errorMessage?.contains("Recreate") == true)
        #expect(backend.bootModes.isEmpty && backend.lastRunning == nil && !relaunched.hasRunningHandle)
        #expect(relaunched.config?.installationStatus == .awaitingOwnerConfirmation)
        #expect(!(await relaunched.confirmInstallationComplete()))
        relaunched.recover(); #expect(relaunched.state == .failed)
        #expect(try Data(contentsOf: original.paths.configFile) == configBytes)
        #expect(try Data(contentsOf: original.paths.machineIdentifier) == id)
        #expect(try Data(contentsOf: original.paths.installerISO) == bytes) // no redownload or deletion
        #expect(FileManager.default.fileExists(atPath: original.paths.diskImage.path))
        let persisted = try JSONDecoder().decode(LinuxEnvironmentConfig.self, from: configBytes)
        #expect(persisted.installationStatus == .awaitingOwnerConfirmation)
    }

    @Test func validPersistedCachePassesRealVerifierBeforeInstallationBoot() async throws {
        let root = root(); defer { try? FileManager.default.removeItem(at: root) }
        let backend = FakeLinuxEnvironmentBackend()
        let original = model(root, backend: backend); await prepare(original)
        let relaunched = model(root, backend: backend)
        await relaunched.installKali()
        #expect(backend.bootModes == [.installation] && relaunched.state == .installing)
        #expect(relaunched.hasRunningHandle && relaunched.bootStage.isEmpty)
        #expect(relaunched.config?.installationStatus == .awaitingOwnerConfirmation)
        #expect(await relaunched.stop())
    }

    @Test func symlinkSubstitutedAfterPreparationIsRejectedAndPreserved() async throws {
        let root = root(); defer { try? FileManager.default.removeItem(at: root) }
        let backend = FakeLinuxEnvironmentBackend(); let m = model(root, backend: backend)
        await prepare(m)
        let other = root.appendingPathComponent("fixture.iso")
        try FileManager.default.moveItem(at: m.paths.installerISO, to: other)
        try FileManager.default.createSymbolicLink(at: m.paths.installerISO, withDestinationURL: other)
        await m.installKali()
        #expect(m.state == .failed && !m.hasRunningHandle && backend.bootModes.isEmpty)
        #expect(try m.paths.installerISO.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink == true)
        #expect(try Data(contentsOf: other) == Data("fake-installer-iso".utf8))
    }

    @Test func installedBootNeverCallsVerifierWithCorruptOrMissingCache() async throws {
        let root = root(); defer { try? FileManager.default.removeItem(at: root) }
        let backend = FakeLinuxEnvironmentBackend(); let spy = RejectingInstallerVerifier()
        let m = model(root, backend: backend, verifier: spy); await prepare(m)
        #expect(await m.confirmInstallationComplete())
        try Data(repeating: 0, count: 18).write(to: m.paths.installerISO)
        await m.start(); #expect(m.state == .running); #expect(await m.stop())
        try FileManager.default.removeItem(at: m.paths.installerISO)
        let relaunched = model(root, backend: backend, verifier: spy)
        await relaunched.start(); #expect(relaunched.state == .running)
        #expect(backend.bootModes == [.installed, .installed])
        #expect(await spy.calls == 0)
        #expect(await relaunched.stop())
    }

    @Test(arguments: ["cancel", "caller", "quit", "remove"])
    func cancellationDrainsVerificationAndLateSuccessCannotBoot(action: String) async throws {
        let root = root(); defer { try? FileManager.default.removeItem(at: root) }
        let backend = FakeLinuxEnvironmentBackend(); let gate = GatedInstallerVerifier()
        let m = model(root, backend: backend, verifier: gate); await prepare(m)
        let configBytes = try Data(contentsOf: m.paths.configFile)
        let boot = Task { await m.installKali() }
        await gate.waitStarted()
        #expect(m.state == .starting && m.canCancelBootVerification && !m.hasRunningHandle)
        #expect(m.bootStage.contains("Verifying"))
        let cancellation = Task {
            switch action {
            case "caller": boot.cancel()
            case "quit": #expect(await m.shutdownForApplicationTermination())
            case "remove": await m.remove()
            default: await m.cancelBootVerification()
            }
        }
        await gate.waitCancelled()
        #expect(backend.bootModes.isEmpty && !m.hasRunningHandle)
        // Deliberately noncooperative success after cancellation: generation/cancel guards
        // must still prevent VM creation. No sleeps or scheduler timing assumptions.
        await gate.release()
        await cancellation.value; await boot.value
        #expect(backend.bootModes.isEmpty && backend.lastRunning == nil && !m.hasRunningHandle)
        #expect(!m.canCancelBootVerification && m.bootStage.isEmpty)
        if action == "remove" {
            #expect(m.state == .notConfigured && !FileManager.default.fileExists(atPath: m.paths.root.path))
        } else {
            #expect(m.state == .installReady && m.config?.installationStatus == .awaitingOwnerConfirmation)
            #expect(try Data(contentsOf: m.paths.configFile) == configBytes)
        }
    }
}

private actor RejectingInstallerVerifier: LinuxInstallerVerifying {
    private(set) var calls = 0
    func verify(at installerISO: URL, manifest: LinuxImageManifest) async throws {
        calls += 1; throw LinuxImageDownloadError.checksumMismatch
    }
}

private actor GatedInstallerVerifier: LinuxInstallerVerifying {
    private var started = false
    private var cancelled = false
    private var startWaiters: [CheckedContinuation<Void, Never>] = []
    private var cancelWaiters: [CheckedContinuation<Void, Never>] = []
    private var completion: CheckedContinuation<Void, Never>?
    func verify(at installerISO: URL, manifest: LinuxImageManifest) async throws {
        await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                completion = continuation; started = true
                startWaiters.forEach { $0.resume() }; startWaiters = []
            }
        } onCancel: { Task { await self.didCancel() } }
    }
    func waitStarted() async {
        if !started { await withCheckedContinuation { startWaiters.append($0) } }
    }
    func waitCancelled() async {
        if !cancelled { await withCheckedContinuation { cancelWaiters.append($0) } }
    }
    private func didCancel() {
        cancelled = true; cancelWaiters.forEach { $0.resume() }; cancelWaiters = []
    }
    func release() { completion?.resume(); completion = nil }
}
