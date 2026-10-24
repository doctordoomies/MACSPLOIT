import Foundation

#if canImport(Virtualization)
import Virtualization

/// Apple's documented GUI-Linux EFI installation pattern, confined to the isolated VM
/// directory. The same machine identifier/firmware are loaded for every subsequent boot.
@available(macOS 13.0, *)
@MainActor
public final class VZLinuxEnvironmentBackend: LinuxEnvironmentBackend {
    public init() {}
    public var unsupportedReason: String? {
        VZVirtualMachine.isSupported ? nil : "Virtualization is not supported on this Mac."
    }

    public func prepare(config: LinuxEnvironmentConfig, paths: LinuxEnvironmentPaths) async throws {
        try Task.checkCancellation()
        guard !FileManager.default.fileExists(atPath: paths.machineIdentifier.path),
              !FileManager.default.fileExists(atPath: paths.auxStorage.path) else { throw LinuxBackendError.notPrepared }
        try LinuxVMStorage.writeNew(VZGenericMachineIdentifier().dataRepresentation, at: paths.machineIdentifier)
        _ = try VZEFIVariableStore(creatingVariableStoreAt: paths.auxStorage)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: paths.auxStorage.path)
        try Task.checkCancellation()
    }

    public func validate(config: LinuxEnvironmentConfig, paths: LinuxEnvironmentPaths) throws {
        try LinuxVMStorage.validate(config: config, paths: paths)
        guard VZGenericMachineIdentifier(dataRepresentation: try Data(contentsOf: paths.machineIdentifier)) != nil else {
            throw LinuxBackendError.backendFailure("The persisted machine identifier is invalid. Recreate the environment.")
        }
    }

    public func makeEnvironment(config: LinuxEnvironmentConfig, paths: LinuxEnvironmentPaths,
                                mode: LinuxBootMode) throws -> any LinuxRunningEnvironment {
        try validate(config: config, paths: paths)
        guard (mode == .installed) == (config.installationStatus == .installed) else { throw LinuxBackendError.notPrepared }
        return VZLinuxRunningEnvironment(configuration: try Self.makeConfiguration(config: config, paths: paths, mode: mode))
    }

    /// Internal for local object-construction tests; CI exercises the identical intent with
    /// offline fakes and never instantiates/boots a real VZVirtualMachine.
    static func makeConfiguration(config: LinuxEnvironmentConfig, paths: LinuxEnvironmentPaths,
                                  mode: LinuxBootMode) throws -> VZVirtualMachineConfiguration {
        let intent = LinuxVMConfigurationIntent(mode: mode, paths: paths)
        let vm = VZVirtualMachineConfiguration()
        vm.cpuCount = min(max(config.cpuCount, VZVirtualMachineConfiguration.minimumAllowedCPUCount), VZVirtualMachineConfiguration.maximumAllowedCPUCount)
        vm.memorySize = min(max(config.memoryBytes, VZVirtualMachineConfiguration.minimumAllowedMemorySize), VZVirtualMachineConfiguration.maximumAllowedMemorySize)
        let platform = VZGenericPlatformConfiguration()
        guard let identifier = VZGenericMachineIdentifier(dataRepresentation: try Data(contentsOf: intent.machineIdentifier)) else {
            throw LinuxBackendError.notPrepared
        }
        platform.machineIdentifier = identifier
        vm.platform = platform
        let boot = VZEFIBootLoader()
        boot.variableStore = VZEFIVariableStore(url: intent.efiVariables)
        vm.bootLoader = boot
        let root = try VZDiskImageStorageDeviceAttachment(url: intent.rootDisk, readOnly: intent.rootReadOnly)
        // Installer is USB/read-only; root is VirtIO/writable. Normal boot has no ISO.
        vm.storageDevices = [VZVirtioBlockDeviceConfiguration(attachment: root)]
        if let iso = intent.installerMedia {
            let media = try VZDiskImageStorageDeviceAttachment(url: iso, readOnly: intent.installerReadOnly)
            vm.storageDevices.insert(VZUSBMassStorageDeviceConfiguration(attachment: media), at: 0)
        }
        let network = VZVirtioNetworkDeviceConfiguration()
        network.attachment = VZNATNetworkDeviceAttachment()
        vm.networkDevices = [network]
        vm.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]
        vm.memoryBalloonDevices = [VZVirtioTraditionalMemoryBalloonDeviceConfiguration()]
        let graphics = VZVirtioGraphicsDeviceConfiguration()
        graphics.scanouts = [VZVirtioGraphicsScanoutConfiguration(widthInPixels: 1280, heightInPixels: 800)]
        vm.graphicsDevices = [graphics]
        vm.keyboards = [VZUSBKeyboardConfiguration()]
        vm.pointingDevices = [VZUSBScreenCoordinatePointingDeviceConfiguration()]
        // Reserved serial device, deliberately disconnected until real VT transport lands.
        // No clipboard/SPICE agent, host filesystem shares, credentials or guest agents.
        let console = VZVirtioConsoleDeviceSerialPortConfiguration()
        console.attachment = VZFileHandleSerialPortAttachment(fileHandleForReading: nil, fileHandleForWriting: nil)
        vm.serialPorts = [console]
        try vm.validate()
        return vm
    }
}

/// Owns the VZ instance and delegate on its main queue. The model retains this handle
/// before boot begins and until an actual stopped state is confirmed.
@available(macOS 13.0, *)
@MainActor
public final class VZLinuxRunningEnvironment: NSObject, LinuxRunningEnvironment, VZVirtualMachineDelegate {
    public let virtualMachine: VZVirtualMachine
    public let supportsTerminalSessions = false
    public var sessionCount: Int { 0 }
    public var didStop: (@MainActor @Sendable (String?) -> Void)?
    private var startResult: Result<Void, Error>?
    private var forcedStopError: Error?
    private var startRequested = false

    init(configuration: VZVirtualMachineConfiguration) {
        virtualMachine = VZVirtualMachine(configuration: configuration)
        super.init()
        virtualMachine.delegate = self
    }

    public func start() async throws {
        guard !startRequested, virtualMachine.canStart else { throw LinuxBackendError.alreadyRunning }
        startRequested = true
        virtualMachine.start { [weak self] result in self?.startResult = result }
        let deadline = Date().addingTimeInterval(30)
        while startResult == nil, Date() < deadline { try await Task.sleep(nanoseconds: 50_000_000) }
        guard let result = startResult else { throw LinuxBackendError.backendFailure("VM start timed out; stopping the retained guest.") }
        try result.get()
        guard virtualMachine.state == .running else { throw LinuxBackendError.backendFailure("The guest stopped before boot completed.") }
    }

    public func openSession() throws -> any LinuxTerminalSession {
        throw LinuxBackendError.notYetAvailable("Interactive terminal transport is the next #90 slice. Use the real graphical guest console for this install/boot slice.")
    }

    public func stop(graceful: Bool, timeout: TimeInterval) async throws {
        if isStopped { return }
        let deadline = Date().addingTimeInterval(timeout)
        if graceful {
            guard virtualMachine.canRequestStop else { throw LinuxBackendError.backendFailure("Guest cannot accept a clean shutdown request yet.") }
            try virtualMachine.requestStop()
        } else {
            // A VM still completing start may not accept force stop yet. Keep ownership
            // while waiting, and report failure rather than assuming an uncertain stop.
            while !virtualMachine.canStop, !isStopped, Date() < deadline { try await Task.sleep(nanoseconds: 50_000_000) }
            if isStopped { return }
            guard virtualMachine.canStop else { throw LinuxBackendError.backendFailure("VM is not ready to stop; its handle is still retained.") }
            forcedStopError = nil
            virtualMachine.stop { [weak self] error in self?.forcedStopError = error }
        }
        while !isStopped, Date() < deadline {
            if let forcedStopError { throw forcedStopError }
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        guard isStopped else { throw LinuxBackendError.backendFailure("VM stop timed out.") }
    }

    private var isStopped: Bool { virtualMachine.state == .stopped || virtualMachine.state == .error }
    nonisolated public func guestDidStop(_ virtualMachine: VZVirtualMachine) {
        Task { @MainActor [weak self] in self?.didStop?(nil) }
    }
    nonisolated public func virtualMachine(_ virtualMachine: VZVirtualMachine, didStopWithError error: Error) {
        let message = "The Linux guest stopped with an error: \(error.localizedDescription)"
        Task { @MainActor [weak self] in self?.didStop?(message) }
    }
}
#endif
