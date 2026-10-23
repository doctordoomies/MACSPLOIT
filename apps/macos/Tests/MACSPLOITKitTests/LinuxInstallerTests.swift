import Foundation
import CryptoKit
import Testing
@testable import MACSPLOITKit

/// Small fixtures only. No network, OS installation, real VM start or guest commands.
@MainActor @Suite struct LinuxInstallerTests {
    private func support() -> URL { FileManager.default.temporaryDirectory.appendingPathComponent("macsploit-installer-\(UUID())") }
    private func manifest() -> LinuxImageManifest {
        LinuxImageManifest(identifier: "offline-installer", displayName: "Offline installer fixture", installerURL: "https://example.test/installer.iso",
                           sha256: String(repeating: "a", count: 64), downloadByteCount: 18)
    }
    private func model(_ root: URL, backend: (any LinuxEnvironmentBackend)? = nil,
                       downloader: any LinuxImageDownloader = FakeLinuxImageDownloader()) -> LinuxEnvironmentModel {
        LinuxEnvironmentModel(paths: .standard(applicationSupport: root), backend: backend ?? FakeLinuxEnvironmentBackend(), downloader: downloader)
    }
    private func prepare(_ m: LinuxEnvironmentModel) async {
        await m.startSetUp(manifest: manifest(), resources: LinuxResources(cpuCount: 1, memoryBytes: LinuxEnvironmentLimits.minMemoryBytes,
                                                                          diskSizeBytes: LinuxEnvironmentLimits.minDiskBytes))?.value
    }
    private func installed(_ m: LinuxEnvironmentModel) async {
        await prepare(m); #expect(await m.confirmInstallationComplete())
    }

    @Test func productionManifestPinsOfficialVersionedInstallerAndProvenance() throws {
        let m = try #require(LinuxImageCatalog.availableManifest)
        try m.validate()
        #expect(m.schemaVersion == 2 && m.release == "2026.3" && m.architecture == "arm64")
        #expect(m.format == .installerISO)
        #expect(m.installerURL == "https://cdimage.kali.org/kali-2026.3/kali-linux-2026.3-installer-arm64.iso")
        #expect(!m.installerURL.contains("current"))
        #expect(m.sha256 == "c4a7f9bf3a0ff07c8263fe9e9b0edba0cc3d9b408f1d8f06c066df0afce23072")
        #expect(m.downloadByteCount == 4_051_513_344)
        #expect(m.provenanceURL == "https://cdimage.kali.org/kali-2026.3/SHA256SUMS")
        #expect(LinuxImageFetch.allowRedirect(to: URL(string: "https://kali.download/base-images/kali-2026.3/installer.iso"), allowedHosts: m.allowedRedirectHosts))
        #expect(!LinuxImageFetch.allowRedirect(to: URL(string: "https://unreviewed.example.test/installer.iso"), allowedHosts: m.allowedRedirectHosts))
        var bad = m; bad.architecture = "amd64"
        #expect(throws: LinuxImageError.self) { try bad.validate() }
        bad = m; bad.redirectAllowedHosts = ["*.example.test"]
        #expect(throws: LinuxImageError.self) { try bad.validate() }
    }

    @Test func realVerificationBoundaryRejectsChecksumAndSizeMismatches() throws {
        let root = support(); defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let file = root.appendingPathComponent("installer.iso")
        let bytes = Data("offline synthetic ISO fixture".utf8); try bytes.write(to: file)
        var m = manifest(); m.downloadByteCount = UInt64(bytes.count)
        m.sha256 = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
        try LinuxImageFetch.verifyInstaller(at: file, manifest: m)
        m.sha256 = String(repeating: "0", count: 64)
        #expect(throws: LinuxImageDownloadError.checksumMismatch) { try LinuxImageFetch.verifyInstaller(at: file, manifest: m) }
        m.downloadByteCount += 1
        #expect(throws: LinuxImageDownloadError.sizeMismatch) { try LinuxImageFetch.verifyInstaller(at: file, manifest: m) }
    }

    @Test func preparationSeparatesInstallerFromSparseUninstalledRoot() async throws {
        let root = support(); defer { try? FileManager.default.removeItem(at: root) }
        let m = model(root); await prepare(m)
        #expect(m.state == .installReady && !m.hasRunningHandle)
        #expect(m.config?.installationStatus == .awaitingOwnerConfirmation)
        #expect(m.paths.installerISO != m.paths.diskImage)
        #expect(try Data(contentsOf: m.paths.installerISO) == Data("fake-installer-iso".utf8))
        let sizes = try m.paths.diskImage.resourceValues(forKeys: [.fileSizeKey, .fileAllocatedSizeKey])
        #expect(sizes.fileSize == Int(LinuxEnvironmentLimits.minDiskBytes))
        #expect((sizes.fileAllocatedSize ?? Int.max) < 1024 * 1024)
        let file = try FileHandle(forReadingFrom: m.paths.diskImage); defer { try? file.close() }
        #expect(try file.read(upToCount: 512) == Data(repeating: 0, count: 512))
        #expect(!FileManager.default.fileExists(atPath: m.paths.staging.path))
    }

    @Test func sparseDiskCreationIsBoundedAndNeverOverwritesExistingDataOrSymlinks() throws {
        let root = support(); defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let disk = root.appendingPathComponent("root.img")
        #expect(throws: LinuxImageError.oversized) { try LinuxVMStorage.createSparseDisk(at: disk, byteCount: 1) }
        #expect(throws: LinuxImageError.oversized) { try LinuxVMStorage.createSparseDisk(at: disk, byteCount: .max) }
        try Data("existing owner disk".utf8).write(to: disk)
        #expect(throws: (any Error).self) { try LinuxVMStorage.createSparseDisk(at: disk, byteCount: LinuxEnvironmentLimits.minDiskBytes) }
        #expect(try String(contentsOf: disk, encoding: .utf8) == "existing owner disk")
        let link = root.appendingPathComponent("link.img")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: disk)
        #expect(throws: (any Error).self) { try LinuxVMStorage.createSparseDisk(at: link, byteCount: LinuxEnvironmentLimits.minDiskBytes) }
        #expect(try String(contentsOf: disk, encoding: .utf8) == "existing owner disk")
    }

    @Test func installAndNormalBootIntentsAreExplicitAndKeepIdentity() {
        let p = LinuxEnvironmentPaths.standard(applicationSupport: support())
        let install = LinuxVMConfigurationIntent(mode: .installation, paths: p)
        let normal = LinuxVMConfigurationIntent(mode: .installed, paths: p)
        #expect(install.installerMedia == p.installerISO && install.installerReadOnly)
        #expect(normal.installerMedia == nil)
        #expect(!install.rootReadOnly && !normal.rootReadOnly)
        #expect(install.rootDisk == normal.rootDisk && install.machineIdentifier == normal.machineIdentifier)
        #expect(install.efiVariables == normal.efiVariables && normal.networking == "NAT")
        #expect(!install.hostShares && !normal.hostShares && install.graphics)
    }

    @Test func installerStartAndGuestShutdownNeverInferInstallationSuccess() async throws {
        let root = support(); defer { try? FileManager.default.removeItem(at: root) }
        let backend = FakeLinuxEnvironmentBackend(); let m = model(root, backend: backend)
        await prepare(m)
        await m.start() // installed boot is forbidden before confirmation
        #expect(backend.bootModes.isEmpty)
        await m.installKali(); #expect(m.state == .installing)
        backend.lastRunning?.simulateGuestStop()
        #expect(m.state == .installReady && !m.hasRunningHandle)
        #expect(m.config?.installationStatus == .awaitingOwnerConfirmation)
        let relaunched = model(root)
        #expect(relaunched.state == .installReady && !relaunched.hasRunningHandle)
        #expect(backend.bootModes == [.installation])
    }

    @Test func ownerConfirmationPersistsAndEveryLaterBootOmitsTheISO() async throws {
        let root = support(); defer { try? FileManager.default.removeItem(at: root) }
        let backend = FakeLinuxEnvironmentBackend(); let m = model(root, backend: backend)
        await prepare(m)
        let id = try Data(contentsOf: m.paths.machineIdentifier)
        let efi = try Data(contentsOf: m.paths.auxStorage)
        await m.installKali()
        #expect(await m.confirmInstallationComplete())
        #expect(m.state == .stopped && !m.hasRunningHandle)
        await m.start(); #expect(m.state == .running)
        #expect(backend.bootModes == [.installation, .installed])
        #expect(await m.stop())
        try FileManager.default.removeItem(at: m.paths.installerISO) // normal boot has no media dependency
        let relaunched = model(root, backend: backend)
        #expect(relaunched.state == .stopped && !relaunched.hasRunningHandle)
        await relaunched.start(); #expect(relaunched.state == .running)
        #expect(backend.bootModes == [.installation, .installed, .installed])
        #expect(try Data(contentsOf: m.paths.machineIdentifier) == id)
        #expect(try Data(contentsOf: m.paths.auxStorage) == efi)
        #expect(await relaunched.stop())
    }

    @Test func confirmationDoesNotCommitIfInstallerCannotStop() async throws {
        let root = support(); defer { try? FileManager.default.removeItem(at: root) }
        let m = model(root, backend: FakeLinuxEnvironmentBackend(gracefulStopFails: true, forcedStopFails: true))
        await prepare(m); await m.installKali()
        #expect(!(await m.confirmInstallationComplete()))
        #expect(m.config?.installationStatus == .awaitingOwnerConfirmation)
        let persisted = try JSONDecoder().decode(LinuxEnvironmentConfig.self, from: Data(contentsOf: m.paths.configFile))
        #expect(persisted.installationStatus == .awaitingOwnerConfirmation)
        #expect(m.hasRunningHandle && m.state == .failed)
    }

    @Test func confirmationDoesNotClaimInstalledWhenPersistenceFails() async throws {
        let root = support(); defer { try? FileManager.default.removeItem(at: root) }
        let m = model(root); await prepare(m)
        try FileManager.default.removeItem(at: m.paths.configFile)
        try FileManager.default.createDirectory(at: m.paths.configFile, withIntermediateDirectories: false)
        #expect(!(await m.confirmInstallationComplete()))
        #expect(m.config?.installationStatus == .awaitingOwnerConfirmation)
        #expect(m.state == .failed)
    }

    @Test func missingOrCorruptIdentityAndEFIStateFailClosedWithoutReplacement() async throws {
        for artifact in ["machine-identifier", "efi-vars.img"] {
            for corrupt in [false, true] {
                let root = support(); defer { try? FileManager.default.removeItem(at: root) }
                let m = model(root); await prepare(m)
                let file = m.paths.root.appendingPathComponent(artifact)
                if corrupt { try Data("corrupt".utf8).write(to: file) }
                else { try FileManager.default.removeItem(at: file) }
                let after = model(root)
                #expect(after.state == .failed && !after.canRetry)
                #expect(after.startSetUp(manifest: manifest(), resources: after.defaultResources) == nil)
                if corrupt { #expect(try Data(contentsOf: file) == Data("corrupt".utf8)) }
                else { #expect(!FileManager.default.fileExists(atPath: file.path)) }
            }
        }
    }

    @Test func oldSchemaRequiresRecreateRatherThanFabricatingMachineIdentity() throws {
        let root = support(); defer { try? FileManager.default.removeItem(at: root) }
        let p = LinuxEnvironmentPaths.standard(applicationSupport: root)
        try FileManager.default.createDirectory(at: p.root, withIntermediateDirectories: true)
        try Data("{\"schemaVersion\":1}".utf8).write(to: p.configFile)
        let m = model(root)
        #expect(m.state == .failed)
        #expect(!FileManager.default.fileExists(atPath: p.machineIdentifier.path))
    }

    @Test func ownsStartingHandleAndDoesNotClaimRunningBeforeBackendSuccess() async throws {
        let root = support(); defer { try? FileManager.default.removeItem(at: root) }
        let m = model(root, backend: FakeLinuxEnvironmentBackend(startDelay: 0.15))
        await installed(m)
        let boot = Task { await m.start() }; await Task.yield()
        #expect(m.state == .starting && m.hasRunningHandle)
        #expect(m.sessionIDs.isEmpty)
        await boot.value; #expect(m.state == .running)
        #expect(await m.stop())
    }

    @Test func stopDuringBootAndLateCompletionCannotResurrectTheGuest() async throws {
        let root = support(); defer { try? FileManager.default.removeItem(at: root) }
        let m = model(root, backend: FakeLinuxEnvironmentBackend(startDelay: 0.15))
        await installed(m)
        let boot = Task { await m.start() }; await Task.yield()
        #expect(await m.stop())
        await boot.value
        #expect(m.state == .stopped && !m.hasRunningHandle)
    }

    @Test func guestStopAndErrorsUpdateTheInstalledLifecycleTruthfully() async throws {
        let root = support(); defer { try? FileManager.default.removeItem(at: root) }
        let backend = FakeLinuxEnvironmentBackend(); let m = model(root, backend: backend)
        await installed(m); await m.start()
        backend.lastRunning?.simulateGuestStop()
        #expect(m.state == .stopped && !m.hasRunningHandle && m.sessionIDs.isEmpty)
        await m.start(); backend.lastRunning?.simulateGuestStop(error: "Fixture guest failure")
        #expect(m.state == .failed && !m.hasRunningHandle && m.errorMessage == "Fixture guest failure")
        m.recover(); #expect(m.state == .stopped)
    }

    @Test func quitStopsTheOneGuestGracefullyThenForcesIfRequired() async throws {
        let root = support(); defer { try? FileManager.default.removeItem(at: root) }
        let backend = FakeLinuxEnvironmentBackend(gracefulStopFails: true)
        let m = model(root, backend: backend); await installed(m); await m.start()
        let run = try #require(backend.lastRunning)
        #expect(await m.shutdownForApplicationTermination())
        #expect(run.stopAttempts == [true, false])
        #expect(!m.hasRunningHandle && m.state == .stopped)
        #expect(run.vended.allSatisfy { $0.closeCount == 1 })
        #expect(model(root).state == .stopped)
        await m.start(); #expect(!m.hasRunningHandle) // no reentrant start during quit
    }

    @Test func quitRefusesUncertainStopAndRetainsTheGuest() async throws {
        let root = support(); defer { try? FileManager.default.removeItem(at: root) }
        let m = model(root, backend: FakeLinuxEnvironmentBackend(gracefulStopFails: true, forcedStopFails: true))
        await installed(m); await m.start()
        #expect(!(await m.shutdownForApplicationTermination()))
        #expect(m.hasRunningHandle && m.state == .failed && !m.isShuttingDown)
        await m.remove(); #expect(FileManager.default.fileExists(atPath: m.paths.diskImage.path))
    }

    @Test func quitDuringPreparationCancelsAndCleansOnlyOwnedArtifacts() async throws {
        let root = support(); defer { try? FileManager.default.removeItem(at: root) }
        let m = model(root, downloader: FakeLinuxImageDownloader(.success, delay: 0.2))
        let setup = m.startSetUp(manifest: manifest(), resources: m.defaultResources)
        #expect(await m.shutdownForApplicationTermination())
        await setup?.value
        #expect(m.state == .notConfigured && !m.hasRunningHandle)
        #expect(!FileManager.default.fileExists(atPath: m.paths.installerISO.path))
    }

    @Test func failedBootWithFailedStopRetainsOwnershipForQuitAndRecovery() async throws {
        let root = support(); defer { try? FileManager.default.removeItem(at: root) }
        let m = model(root, backend: FakeLinuxEnvironmentBackend(failure: .onStart, gracefulStopFails: true, forcedStopFails: true))
        await installed(m); await m.start()
        #expect(m.state == .failed && m.hasRunningHandle)
        #expect(!(await m.shutdownForApplicationTermination()))
    }

}
