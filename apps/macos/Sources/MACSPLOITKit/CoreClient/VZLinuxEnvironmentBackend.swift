import Foundation

#if canImport(Virtualization)
import Virtualization

// Real Apple Virtualization.framework adapter (Apple Silicon, macOS 13+). It encodes the
// exact VM architecture MACSPLOIT will boot — an ARM64 Linux/Kali guest via the EFI boot
// loader with a prepared root disk, NAT networking, and a virtio console reserved for the
// interactive terminal transport.
//
// This foundation builds and validates the real `VZVirtualMachineConfiguration` and
// prepares persistent VM files, but deliberately does NOT yet perform a live boot: a
// verified bootable Kali artifact and the guest console/session transport are required
// first (and the app must be signed with `com.apple.security.virtualization`). `start`
// therefore surfaces a clear `notYetAvailable` rather than shipping an untested,
// unbootable VM path. When the image + transport land, only the boot/console wiring is
// added here; the configuration and lifecycle shape are already in place.
@available(macOS 13.0, *)
public final class VZLinuxEnvironmentBackend: LinuxEnvironmentBackend, @unchecked Sendable {
    public init() {}

    public func prepare(config: LinuxEnvironmentConfig, paths: LinuxEnvironmentPaths) async throws {
        try FileManager.default.createDirectory(at: paths.root, withIntermediateDirectories: true)
        // Create only the small EFI variable store (guest boot state). The verified root
        // disk is still staged; the model finalizes it (atomic move) after prepare+persist
        // succeed, so a prepare failure never orphans a multi-GB disk.
        if !FileManager.default.fileExists(atPath: paths.auxStorage.path) {
            _ = try VZEFIVariableStore(creatingVariableStoreAt: paths.auxStorage)
        }
    }

    public func start(config: LinuxEnvironmentConfig, paths: LinuxEnvironmentPaths) async throws -> any LinuxRunningEnvironment {
        // Build and validate the real configuration so the architecture is exercised the
        // moment a bootable image exists.
        _ = try Self.makeConfiguration(config: config, paths: paths)
        throw LinuxBackendError.notYetAvailable(
            "The managed Linux VM is configured but a verified bootable image and the guest console transport are not available yet."
        )
    }

    /// Construct the ARM64 Linux VM configuration MACSPLOIT boots: EFI boot loader + a
    /// generic platform, a virtio block device on the prepared root disk, NAT networking,
    /// entropy and a memory balloon, and a virtio console reserved for the terminal.
    static func makeConfiguration(config: LinuxEnvironmentConfig, paths: LinuxEnvironmentPaths) throws -> VZVirtualMachineConfiguration {
        let vm = VZVirtualMachineConfiguration()

        vm.cpuCount = min(max(config.cpuCount, VZVirtualMachineConfiguration.minimumAllowedCPUCount),
                          VZVirtualMachineConfiguration.maximumAllowedCPUCount)
        vm.memorySize = min(max(config.memoryBytes, VZVirtualMachineConfiguration.minimumAllowedMemorySize),
                            VZVirtualMachineConfiguration.maximumAllowedMemorySize)

        vm.platform = VZGenericPlatformConfiguration()

        let bootLoader = VZEFIBootLoader()
        bootLoader.variableStore = VZEFIVariableStore(url: paths.auxStorage)
        vm.bootLoader = bootLoader

        let diskAttachment = try VZDiskImageStorageDeviceAttachment(url: paths.diskImage, readOnly: false)
        vm.storageDevices = [VZVirtioBlockDeviceConfiguration(attachment: diskAttachment)]

        let network = VZVirtioNetworkDeviceConfiguration()
        network.attachment = VZNATNetworkDeviceAttachment()
        vm.networkDevices = [network]

        vm.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]
        vm.memoryBalloonDevices = [VZVirtioTraditionalMemoryBalloonDeviceConfiguration()]

        // Reserve a virtio console for the interactive terminal transport (wired in the
        // follow-up). The host side binds to a pipe pair the terminal emulator will drive.
        let console = VZVirtioConsoleDeviceSerialPortConfiguration()
        let guestInput = Pipe(), guestOutput = Pipe()
        console.attachment = VZFileHandleSerialPortAttachment(
            fileHandleForReading: guestOutput.fileHandleForReading,
            fileHandleForWriting: guestInput.fileHandleForWriting
        )
        vm.serialPorts = [console]

        try vm.validate()
        return vm
    }
}
#endif
