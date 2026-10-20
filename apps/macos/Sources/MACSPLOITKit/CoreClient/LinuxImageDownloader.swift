import Foundation
import CryptoKit

// Verified acquisition of the guest image, kept OFF the core provider protocol (a separate
// trust boundary) but holding to the same download discipline as the core installer:
// HTTPS-only on the initial request AND every redirect, no credential-bearing URLs, a
// bounded redirect count, a bounded streamed size, a validated HTTP status, a SHA-256
// computed by streaming (never by loading the multi-GB image into memory), cancellation
// honoured through download and hashing, and an ATOMIC finalize that never deletes a
// known-good artifact until its fully-verified replacement is ready.

public enum LinuxImageDownloadError: Error, Equatable {
    case badStatus(Int)
    case insecureRedirect
    case tooManyRedirects
    case oversized
    case checksumMismatch
    case cancelled
    case transport(String)
    case writeFailed(String)
}

public protocol LinuxImageDownloader: Sendable {
    /// Download and verify the manifest's single pinned artifact, placing it at its final
    /// path atomically. Reports 0...1 progress. Throws before finalizing on any status/
    /// redirect/size/digest/transport failure, honours cancellation, and never destroys an
    /// existing known-good artifact on failure.
    func fetch(_ manifest: LinuxImageManifest, into paths: LinuxEnvironmentPaths,
               progress: @escaping @Sendable (Double) -> Void) async throws
}

/// Pure, unit-testable security helpers shared by the real downloader.
public enum LinuxImageFetch {
    public static let maxRedirects = 5

    /// Whether a redirect target satisfies the per-URL policy: HTTPS, a non-empty host with
    /// no embedded credentials, and a host within the reviewed allow-list. The redirect
    /// *count* is enforced separately by `LinuxImageRedirectCounter` (never a caller header).
    public static func allowRedirect(to url: URL?, allowedHosts: Set<String>) -> Bool {
        guard let url, let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              components.scheme?.lowercased() == "https", let host = components.host, !host.isEmpty,
              components.user == nil, components.password == nil, allowedHosts.contains(host) else { return false }
        return true
    }

    /// SHA-256 of a file computed by streaming 1 MiB chunks (never loads the whole file).
    /// Honours task cancellation between chunks.
    public static func streamingSHA256(ofFileAt url: URL) throws -> String {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var hasher = SHA256()
        while true {
            if Task.isCancelled { throw LinuxImageDownloadError.cancelled }
            let chunk = try handle.read(upToCount: 1 << 20) ?? Data()
            if chunk.isEmpty { break }
            hasher.update(data: chunk)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    /// Replace `destination` with `source` atomically, WITHOUT deleting an existing good
    /// `destination` until the swap is ready. Falls back to a move when none exists.
    public static func atomicReplace(source: URL, destination: URL) throws {
        let fm = FileManager.default
        try fm.createDirectory(at: destination.deletingLastPathComponent(), withIntermediateDirectories: true)
        if fm.fileExists(atPath: destination.path) {
            _ = try fm.replaceItemAt(destination, withItemAt: source)
        } else {
            try fm.moveItem(at: source, to: destination)
        }
    }
}

/// Delegate-owned redirect budget + host policy. The count is server-independent state held
/// here (never a caller-supplied request header), incremented once per redirect.
public final class LinuxImageRedirectCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    private let maximum: Int
    private let allowedHosts: Set<String>
    public init(maximum: Int = LinuxImageFetch.maxRedirects, allowedHosts: Set<String>) {
        self.maximum = maximum; self.allowedHosts = allowedHosts
    }
    /// Called once per redirect: increments the counter and returns whether to follow
    /// (within budget AND satisfying the per-URL policy).
    public func shouldFollow(to url: URL?) -> Bool {
        lock.withLock {
            count += 1
            return count <= maximum && LinuxImageFetch.allowRedirect(to: url, allowedHosts: allowedHosts)
        }
    }
    /// Whether the last-evaluated redirect was within budget (to distinguish error copy).
    public func withinBudget() -> Bool { lock.withLock { count <= maximum } }
    public var redirectCount: Int { lock.withLock { count } }
}

/// Real downloader built on a delegate-driven `URLSessionDownloadTask`: it enforces the
/// redirect policy, caps streamed bytes mid-download, validates status, then streams the
/// digest and finalizes atomically. Not exercised in CI (which never downloads a live
/// image); its security-relevant pieces are covered via `LinuxImageFetch`.
public struct URLSessionLinuxImageDownloader: LinuxImageDownloader {
    public init() {}

    public func fetch(_ manifest: LinuxImageManifest, into paths: LinuxEnvironmentPaths,
                      progress: @escaping @Sendable (Double) -> Void) async throws {
        try manifest.validate()
        let fm = FileManager.default
        try? fm.removeItem(at: paths.staging)
        try fm.createDirectory(at: paths.staging, withIntermediateDirectories: true)

        guard let url = URL(string: manifest.diskImageURL) else { throw LinuxImageDownloadError.transport("Invalid URL.") }
        progress(0)
        let counter = LinuxImageRedirectCounter(allowedHosts: manifest.allowedRedirectHosts)
        // Download into staging and verify the pinned digest. The model finalizes (atomic
        // move into the live disk) only after prepare+persist succeed, so a failure here
        // never destroys an existing good disk.
        try await LinuxImageDownloadTask.run(url: url, to: paths.stagedDisk, maxBytes: manifest.downloadByteCount,
                                             counter: counter, allowedHosts: manifest.allowedRedirectHosts,
                                             progress: progress)
        try Task.checkCancellation()
        let digest = try LinuxImageFetch.streamingSHA256(ofFileAt: paths.stagedDisk)
        guard digest == manifest.sha256.lowercased() else { throw LinuxImageDownloadError.checksumMismatch }
        progress(1)
    }
}

/// Bridges a delegate-driven download task to async, enforcing redirect and byte-cap policy
/// and resuming its continuation exactly once.
private final class LinuxImageDownloadTask: NSObject, URLSessionDownloadDelegate, @unchecked Sendable {
    static func run(url: URL, to destination: URL, maxBytes: UInt64, counter: LinuxImageRedirectCounter,
                    allowedHosts: Set<String>, progress: @escaping @Sendable (Double) -> Void) async throws {
        let delegate = LinuxImageDownloadTask(destination: destination, maxBytes: maxBytes,
                                              counter: counter, allowedHosts: allowedHosts, progress: progress)
        let session = URLSession(configuration: .ephemeral, delegate: delegate, delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        let task = session.downloadTask(with: url)
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                delegate.continuation = continuation
                task.resume()
            }
        } onCancel: { task.cancel() }
    }

    private let destination: URL
    private let maxBytes: UInt64
    private let counter: LinuxImageRedirectCounter
    private let allowedHosts: Set<String>
    private let progress: @Sendable (Double) -> Void
    private let lock = NSLock()
    private var finished = false
    var continuation: CheckedContinuation<Void, Error>?

    init(destination: URL, maxBytes: UInt64, counter: LinuxImageRedirectCounter,
         allowedHosts: Set<String>, progress: @escaping @Sendable (Double) -> Void) {
        self.destination = destination; self.maxBytes = maxBytes
        self.counter = counter; self.allowedHosts = allowedHosts; self.progress = progress
    }

    private func succeed() { finish(nil) }
    private func fail(_ error: LinuxImageDownloadError) { finish(error) }
    private func finish(_ error: LinuxImageDownloadError?) {
        let cont: CheckedContinuation<Void, Error>? = lock.withLock {
            guard !finished else { return nil }
            finished = true
            let c = continuation; continuation = nil; return c
        }
        guard let cont else { return }
        if let error { cont.resume(throwing: error) } else { cont.resume() }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        if counter.shouldFollow(to: request.url) {
            completionHandler(request)
        } else {
            completionHandler(nil)
            // Distinguish "over the redirect budget" from "policy-violating target".
            let policyOK = LinuxImageFetch.allowRedirect(to: request.url, allowedHosts: allowedHosts)
            fail(policyOK && !counter.withinBudget() ? .tooManyRedirects : .insecureRedirect)
        }
    }

    func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask,
                    didWriteData bytesWritten: Int64, totalBytesWritten: Int64, totalBytesExpectedToWrite: Int64) {
        if totalBytesExpectedToWrite > 0 && UInt64(totalBytesExpectedToWrite) > maxBytes {
            downloadTask.cancel(); fail(.oversized); return
        }
        if totalBytesWritten >= 0 && UInt64(totalBytesWritten) > maxBytes {
            downloadTask.cancel(); fail(.oversized); return
        }
        if totalBytesExpectedToWrite > 0 {
            progress(min(1, Double(totalBytesWritten) / Double(totalBytesExpectedToWrite)))
        }
    }

    func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask,
                    didFinishDownloadingTo location: URL) {
        guard let http = downloadTask.response as? HTTPURLResponse else { fail(.transport("No HTTP response.")); return }
        guard http.statusCode == 200 else { fail(.badStatus(http.statusCode)); return }
        if let final = downloadTask.currentRequest?.url ?? downloadTask.originalRequest?.url,
           URLComponents(url: final, resolvingAgainstBaseURL: false)?.scheme?.lowercased() != "https" {
            fail(.insecureRedirect); return
        }
        do {
            try? FileManager.default.removeItem(at: destination)
            try FileManager.default.moveItem(at: location, to: destination)
            succeed()
        } catch {
            fail(.writeFailed(error.localizedDescription))
        }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        guard let error else { return } // success handled in didFinishDownloadingTo
        if (error as NSError).code == NSURLErrorCancelled { fail(.cancelled) }
        else { fail(.transport(error.localizedDescription)) }
    }
}

/// Offline downloader for tests/CI: no network. Writes a placeholder root disk on success
/// (after an optional cancellable delay), or throws a chosen failure. The destination's
/// staging is removed on failure; a finalized good disk is never destroyed by a failure.
public struct FakeLinuxImageDownloader: LinuxImageDownloader {
    public enum Outcome: Sendable, Equatable { case success, checksumMismatch, transportFailure, oversized }
    private let outcome: Outcome
    private let delay: TimeInterval
    public init(_ outcome: Outcome = .success, delay: TimeInterval = 0) {
        self.outcome = outcome; self.delay = delay
    }

    public func fetch(_ manifest: LinuxImageManifest, into paths: LinuxEnvironmentPaths,
                      progress: @escaping @Sendable (Double) -> Void) async throws {
        try manifest.validate()
        progress(0)
        if delay > 0 { try await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000)) } // cancellable
        try Task.checkCancellation()
        switch outcome {
        case .checksumMismatch: throw LinuxImageDownloadError.checksumMismatch
        case .transportFailure: throw LinuxImageDownloadError.transport("Simulated transport failure.")
        case .oversized: throw LinuxImageDownloadError.oversized
        case .success:
            // Stage the verified disk; the model finalizes it (atomic move) only after
            // prepare + persist succeed, so a later failure never orphans a new disk.
            try FileManager.default.createDirectory(at: paths.staging, withIntermediateDirectories: true)
            try Data("fake-root-disk".utf8).write(to: paths.stagedDisk)
            progress(1)
        }
    }
}
