import Foundation
import Darwin

/// All process, pipe, and buffer state is confined to the dedicated serial queue.
/// Blocking pipe operations never run on SwiftUI's main actor or its task executor.
public final class PipeTransport: CoreTransport, @unchecked Sendable {
    private let executable: URL, dataDirectory: URL
    private let queue = DispatchQueue(label: "MACSPLOIT.CoreIPC", qos: .userInitiated)
    private var process: Process?
    private var input: FileHandle?, output: FileHandle?, log: FileHandle?
    private var pending = Data()

    public init(executable: URL, dataDirectory: URL) {
        self.executable = executable; self.dataDirectory = dataDirectory
    }

    public func exchange(_ request: Data) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            queue.async { [self] in
                do { continuation.resume(returning: try exchangeOnQueue(request)) }
                catch { stopOnQueue(); continuation.resume(throwing: error) }
            }
        }
    }

    public func shutdown() {
        queue.sync { stopOnQueue() }
    }

    private func startOnQueue() throws {
        if process?.isRunning == true { return }
        stopOnQueue()
        guard FileManager.default.isExecutableFile(atPath: executable.path) else {
            throw CoreFailure(code: "CoreUnavailable", message: "The bundled Rust helper is missing. Rebuild MACSPLOIT.")
        }
        let logDirectory = dataDirectory.appendingPathComponent("logs", isDirectory: true)
        try FileManager.default.createDirectory(at: logDirectory, withIntermediateDirectories: true,
                                               attributes: [.posixPermissions: 0o700])
        let logURL = logDirectory.appendingPathComponent("application.jsonl")
        if let size = try? logURL.resourceValues(forKeys: [.fileSizeKey]).fileSize, size > 1_048_576 {
            let previous = logDirectory.appendingPathComponent("application.previous.jsonl")
            if FileManager.default.fileExists(atPath: previous.path) { try FileManager.default.removeItem(at: previous) }
            try FileManager.default.moveItem(at: logURL, to: previous)
        }
        if !FileManager.default.fileExists(atPath: logURL.path) {
            FileManager.default.createFile(atPath: logURL.path, contents: nil, attributes: [.posixPermissions: 0o600])
        }
        let logHandle = try FileHandle(forWritingTo: logURL)
        try logHandle.seekToEnd()
        let child = Process(), toCore = Pipe(), fromCore = Pipe()
        child.executableURL = executable
        child.arguments = ["--data-dir", dataDirectory.path]
        // Minimal environment by design. Forward only the explicit tool-location
        // overrides when the app itself was launched with them (manual testing).
        var environment = ["HOME": NSHomeDirectory(), "PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8"]
        for key in ["MACSPLOIT_SUBFINDER", "MACSPLOIT_TOOLS_DIR"] {
            if let value = ProcessInfo.processInfo.environment[key] { environment[key] = value }
        }
        child.environment = environment
        child.standardInput = toCore; child.standardOutput = fromCore; child.standardError = logHandle
        try child.run()
        process = child; input = toCore.fileHandleForWriting; output = fromCore.fileHandleForReading; log = logHandle
        // The parent must not retain the child's pipe ends; EOF drives clean shutdown.
        try toCore.fileHandleForReading.close(); try fromCore.fileHandleForWriting.close()
    }

    private func exchangeOnQueue(_ request: Data) throws -> Data {
        guard request.count < 64 * 1024 else {
            throw CoreFailure(code: "InvalidRequest", message: "Request exceeds the local protocol limit.")
        }
        try startOnQueue()
        guard let input, let output else { throw transportError("Core pipes are unavailable.") }
        var line = request; line.append(10)
        try input.write(contentsOf: line)
        let deadline = Date().addingTimeInterval(10)
        while true {
            if let newline = pending.firstIndex(of: 10) {
                let frame = pending.subdata(in: pending.startIndex..<newline)
                pending.removeSubrange(pending.startIndex...newline)
                return frame
            }
            guard pending.count <= 8 * 1024 * 1024 else { throw transportError("Core response exceeds 8 MiB.") }
            let remaining = deadline.timeIntervalSinceNow
            guard remaining > 0 else { throw transportError("The Rust helper did not respond within 10 seconds.") }
            var descriptor = pollfd(fd: output.fileDescriptor, events: Int16(POLLIN), revents: 0)
            let ready = Darwin.poll(&descriptor, 1, Int32(min(remaining * 1000, 10_000)))
            if ready < 0 && errno == EINTR { continue }
            guard ready > 0 else { throw transportError("The Rust helper stopped responding.") }
            var bytes = [UInt8](repeating: 0, count: 16_384)
            let count = Darwin.read(output.fileDescriptor, &bytes, bytes.count)
            if count < 0 && errno == EINTR { continue }
            guard count > 0 else { throw transportError("The Rust helper disconnected. Reconnect to recover persisted state.") }
            pending.append(contentsOf: bytes.prefix(count))
        }
    }

    private func stopOnQueue() {
        try? input?.close(); input = nil
        if let process, process.isRunning {
            // Closing stdin asks the helper to cancel bounded work and release its storage lock.
            let deadline = Date().addingTimeInterval(1)
            while process.isRunning && Date() < deadline { Thread.sleep(forTimeInterval: 0.01) }
            if process.isRunning { process.terminate() }
        }
        try? output?.close(); try? log?.close()
        process = nil; output = nil; log = nil; pending.removeAll()
    }

    private func transportError(_ message: String) -> CoreFailure {
        CoreFailure(code: "CoreUnavailable", message: message)
    }
}
