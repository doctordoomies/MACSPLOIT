import Foundation

public protocol LinuxInstallerVerifying: Sendable {
    func verify(at installerISO: URL, manifest: LinuxImageManifest) async throws
}

/// Explicit detached worker: the multi-GiB streaming walk never runs on MainActor.
/// Cancellation is forwarded and the worker is drained before the caller returns.
public struct StreamingLinuxInstallerVerifier: LinuxInstallerVerifying {
    public init() {}

    public func verify(at installerISO: URL, manifest: LinuxImageManifest) async throws {
        try Task.checkCancellation()
        let worker = Task.detached(priority: .userInitiated) {
            try Task.checkCancellation()
            try LinuxImageFetch.verifyInstaller(at: installerISO, manifest: manifest)
            try Task.checkCancellation()
        }
        try await withTaskCancellationHandler {
            try await worker.value
        } onCancel: {
            worker.cancel()
        }
        try Task.checkCancellation()
    }
}
