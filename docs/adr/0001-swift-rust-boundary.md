# ADR 0001: bundled Rust helper over local pipes

Status: accepted for Phase 0 (2026-09-27).

## Decision

Use one Rust crate with a reusable library and a `macsploit-core` executable.
Swift launches the bundled helper through Foundation `Process`, using an
executable URL and argument array. Versioned newline-delimited JSON requests and
responses travel over anonymous stdin/stdout pipes. No shell, port, network
listener, privileged helper, or independently installed service is involved.

Swift Codable types and Rust serde types define the internal contract. Requests
have a protocol version and correlation ID; responses carry typed results or
structured error codes. Contract tests cover both sides. Rust owns all domain
state and SQLite writes. A worker executes the synthetic chain while the command
loop remains responsive. The client retrieves committed events after its last
sequence and refreshes a consistent snapshot. Pipe operations run on a dedicated
serial queue, never the SwiftUI main thread.

## Options considered

| Option | Benefits | Costs for this project |
| --- | --- | --- |
| UniFFI | Generated typed Swift APIs and errors, async/callback support | Binding generation and linked library packaging; in-process lifetime still tied to UI; generated concurrency integration needs testing |
| Small C ABI | Small linkage surface; static library can simplify a single executable | Manual ownership, buffers, error conversion and async callback rules; unsafe boundary; UI and core still share a process |
| Local IPC helper | Process separation, easy protocol debugging and independent core tests; same contract can later connect to a service | Explicit wire versioning and Codable/serde parity; helper packaging; lifecycle and transport errors must be handled |

The existing design favored local IPC. Anonymous pipes prove that boundary with
less operational complexity than a persistent socket service. Typed decoding is
runtime checked rather than compiler-generated across languages; integration
tests and an explicit version are the compensating controls.

## Lifecycle and future implications

Phase 0 is an app-owned helper, not an installed daemon. Closing a window need
not quit the application. On pipe closure the helper finishes/cancels bounded
synthetic work and exits; after an abnormal interruption, startup marks unfinished
work failed and records recovery events. Completed data always survives restart.
No automatic restart of interrupted assessment work is allowed.

Work surviving a full UI quit is a future service-lifecycle milestone. A per-user
service can reuse the same commands, durable event cursors, provider interface,
and storage without changing domain models. Before adopting a socket or XPC,
define peer authorization, launch ownership, reconnection, and version negotiation.

The development bundle is ad-hoc signed, unsandboxed, and runs as the current
user. It requests no root access, network access, or special entitlements. App
Store distribution, App Sandbox compatibility for external scanners, signing,
notarization, and privileged operations require a separate future decision. This
choice does not relax the private repository or publishing policy.

## Platform and packaging

Minimum macOS: 13 (Ventura), enabling native `NavigationSplitView` and tables
without requiring newer UI APIs. Apple Silicon is the verified development
target; no architecture-specific application logic is introduced. Swift Package
Manager builds the SwiftUI executable; a small script assembles the `.app` and
bundles the Rust helper. Full Xcode is optional for the CLI workflow, avoiding an
unnecessary project generator or installer. Verified with Swift 6.3.2 and Rust
1.98.1 on arm64 macOS 26; Rust 1.90 is the lockfile dependency baseline. The CLI
tests use the installed Swift Testing framework (including its CLT runtime path),
so XCTest/full Xcode is not required. The local test framework targets macOS 14;
the application remains compiled for 13, which needs separate device validation.

## Primary references reviewed

- [UniFFI Swift bindings](https://mozilla.github.io/uniffi-rs/latest/swift/overview.html)
  describes generated records, enums, errors, and its Swift concurrency caveats.
- [Rust FFI guide](https://doc.rust-lang.org/nomicon/ffi.html) explains C ABI,
  ownership, and safety obligations.
- [Apple Foundation Process](https://developer.apple.com/documentation/foundation/process)
  is the native subprocess API.
- [Rust process module](https://doc.rust-lang.org/std/process/index.html) covers
  argument arrays and pipe I/O, including pipe deadlock considerations.
- [Apple App Sandbox](https://developer.apple.com/documentation/security/app-sandbox)
  and [NavigationSplitView](https://developer.apple.com/documentation/swiftui/navigationsplitview)
  inform future distribution and the native UI boundary.
