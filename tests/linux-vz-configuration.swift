import Foundation
import Virtualization

// Opt-in local configuration check. No VZVirtualMachine instance, guest boot, network,
// image download or owner-data access. Compiled with the exact production source files.
@main struct LinuxVZConfigurationCheck {
    @MainActor static func main() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("macsploit-vz-config-\(UUID())"); defer { try? FileManager.default.removeItem(at: root) }
        let p = LinuxEnvironmentPaths.standard(applicationSupport: root)
        try FileManager.default.createDirectory(at: p.root, withIntermediateDirectories: true)
        let image = LinuxImageManifest(identifier: "offline-configuration", displayName: "Offline fixture", installerURL: "https://example.test/installer.iso", sha256: String(repeating: "a", count: 64), downloadByteCount: 4096)
        var config = LinuxEnvironmentConfig(image: image, resources: .init(cpuCount: 1, memoryBytes: LinuxEnvironmentLimits.minMemoryBytes, diskSizeBytes: LinuxEnvironmentLimits.minDiskBytes))
        try LinuxVMStorage.createSparseDisk(at: p.diskImage, byteCount: config.diskSizeBytes)
        try Data(repeating: 0, count: 4096).write(to: p.installerISO)
        let backend = VZLinuxEnvironmentBackend()
        try await backend.prepare(config: config, paths: p)
        try LinuxVMStorage.recordIdentity(in: &config, paths: p)
        let originalID = try Data(contentsOf: p.machineIdentifier)
        try backend.validate(config: config, paths: p)
        let install = try VZLinuxEnvironmentBackend.makeConfiguration(config: config, paths: p, mode: .installation)
        let normal = try VZLinuxEnvironmentBackend.makeConfiguration(config: config, paths: p, mode: .installed)
        try require(install.storageDevices.count == 2 && normal.storageDevices.count == 1)
        try require(install.storageDevices[0] is VZUSBMassStorageDeviceConfiguration)
        try require(normal.storageDevices[0] is VZVirtioBlockDeviceConfiguration)
        try require((install.storageDevices[0].attachment as? VZDiskImageStorageDeviceAttachment)?.isReadOnly == true)
        try require((normal.storageDevices[0].attachment as? VZDiskImageStorageDeviceAttachment)?.isReadOnly == false)
        try require(install.graphicsDevices.count == 1 && install.keyboards.count == 1 && install.pointingDevices.count == 1)
        try require(install.networkDevices.first?.attachment is VZNATNetworkDeviceAttachment)
        try require(normal.networkDevices.first?.attachment is VZNATNetworkDeviceAttachment)
        try require(install.directorySharingDevices.isEmpty && normal.directorySharingDevices.isEmpty)
        try require((normal.platform as? VZGenericPlatformConfiguration)?.machineIdentifier.dataRepresentation == originalID)
        print("Real install/normal VZ configurations validated: persistent identity/EFI, USB read-only installer, writable VirtIO root, NAT, graphics/input, no host shares. No guest booted.")
    }
    static func require(_ condition: @autoclosure () -> Bool) throws {
        if !condition() { throw LinuxBackendError.backendFailure("VZ configuration assertion failed.") }
    }
}
