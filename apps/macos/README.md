# Native macOS application

**IMPLEMENTED:** SwiftUI executable and `MACSPLOITKit` library, built with SwiftPM.
Sources separate App, Views, Models, CoreClient, and ViewModels. The Foundation
Process transport runs off the main thread and talks to the bundled Rust helper.
There is no web shell or direct Swift database access.

From the repository root, `scripts/run.sh` builds and opens `build/MACSPLOIT.app`.
`scripts/test.sh` includes Swift Testing tests plus the real helper integration.
See [development](../../docs/development.md) for prerequisites, the synthetic
walkthrough, and the remaining blocked GUI acceptance check.
