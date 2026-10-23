import Foundation
import CryptoKit
import Darwin

/// Only the isolated Linux directory is writable by VM setup. Existing files are never
/// silently replaced. These checks are not a sandbox against a hostile same-user process.
public enum LinuxVMStorage {
    public static func requireRegularFile(_ url: URL, maximumBytes: UInt64 = .max) throws -> UInt64 {
        let values = try url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey])
        guard values.isRegularFile == true, values.isSymbolicLink != true,
              let size = values.fileSize, size > 0, UInt64(size) <= maximumBytes else {
            throw LinuxBackendError.notPrepared
        }
        return UInt64(size)
    }

    public static func createSparseDisk(at url: URL, byteCount: UInt64) throws {
        guard byteCount >= LinuxEnvironmentLimits.minDiskBytes,
              byteCount <= LinuxEnvironmentLimits.maxDiskBytes else { throw LinuxImageError.oversized }
        try Task.checkCancellation()
        let fd = open(url.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, S_IRUSR | S_IWUSR)
        guard fd >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        var success = false
        defer {
            close(fd)
            if !success { try? FileManager.default.removeItem(at: url) }
        }
        guard ftruncate(fd, off_t(byteCount)) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        try Task.checkCancellation()
        success = true
    }

    public static func writeNew(_ data: Data, at url: URL) throws {
        try data.write(to: url, options: .withoutOverwriting)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }

    public static func recordIdentity(in config: inout LinuxEnvironmentConfig, paths: LinuxEnvironmentPaths) throws {
        _ = try requireRegularFile(paths.machineIdentifier, maximumBytes: 4096)
        config.machineIdentifierSHA256 = try LinuxImageFetch.streamingSHA256(ofFileAt: paths.machineIdentifier)
        config.efiStoreByteCount = try requireRegularFile(paths.auxStorage, maximumBytes: 128 * 1024 * 1024)
    }

    public static func validate(config: LinuxEnvironmentConfig, paths: LinuxEnvironmentPaths) throws {
        guard config.schemaVersion == LinuxEnvironmentConfig.supportedSchema,
              config.cpuCount >= 1, config.cpuCount <= LinuxHostResources.current.maxCPU,
              config.memoryBytes >= LinuxEnvironmentLimits.minMemoryBytes,
              config.memoryBytes <= LinuxHostResources.current.maxMemoryBytes,
              config.diskSizeBytes >= LinuxEnvironmentLimits.minDiskBytes,
              config.diskSizeBytes <= LinuxEnvironmentLimits.maxDiskBytes else { throw LinuxBackendError.notPrepared }
        try config.image.validate()
        guard try requireRegularFile(paths.diskImage, maximumBytes: LinuxEnvironmentLimits.maxDiskBytes) == config.diskSizeBytes,
              try requireRegularFile(paths.auxStorage, maximumBytes: 128 * 1024 * 1024) == config.efiStoreByteCount else {
            throw LinuxBackendError.notPrepared
        }
        _ = try requireRegularFile(paths.machineIdentifier, maximumBytes: 4096)
        guard try LinuxImageFetch.streamingSHA256(ofFileAt: paths.machineIdentifier) == config.machineIdentifierSHA256 else {
            throw LinuxBackendError.notPrepared
        }
        // Installed boots do not depend on cached media. Incomplete installations must
        // still have their verified installer. Do not hash a multi-GiB ISO on every launch.
        if config.installationStatus == .awaitingOwnerConfirmation {
            guard try requireRegularFile(paths.installerISO, maximumBytes: config.image.downloadByteCount) == config.image.downloadByteCount else {
                throw LinuxBackendError.notPrepared
            }
        }
    }
}

/// Testable configuration intent consumed by the real adapter. No device mode is inferred
/// from whether files happen to exist.
public struct LinuxVMConfigurationIntent: Sendable, Equatable {
    public let mode: LinuxBootMode
    public let rootDisk: URL
    public let installerMedia: URL?
    public let machineIdentifier: URL
    public let efiVariables: URL
    public let installerReadOnly: Bool
    public let rootReadOnly = false
    public let networking = "NAT"
    public let graphics = true
    public let hostShares = false

    public init(mode: LinuxBootMode, paths: LinuxEnvironmentPaths) {
        self.mode = mode; self.rootDisk = paths.diskImage
        self.installerMedia = mode == .installation ? paths.installerISO : nil
        self.machineIdentifier = paths.machineIdentifier; self.efiVariables = paths.auxStorage
        self.installerReadOnly = true
    }
}
