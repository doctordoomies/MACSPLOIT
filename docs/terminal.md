# Integrated Linux terminal (managed VM foundation)

Status: **FOUNDATION — Issue #90 (parent #27). Owner acceptance pending. Does not boot a
live guest yet** (see *Remaining blockers*). This slice ships the durable architecture,
lifecycle, verified-download pipeline, persistent storage, the Virtualization.framework
adapter, entitlements, and the full Terminal UI — all offline-tested — so the live boot is
an additive follow-up, not a redesign.

## What this is (and is not)

MACSPLOIT's structured, scope-aware provider workflows remain the preferred path. The Linux
terminal is a deliberate **power-user escape hatch**: an optional, explicitly started
managed Linux (Kali ARM64) environment whose shell the user drives directly, for tools and
command combinations not yet wrapped as native providers.

It is **not** a macOS zsh shell dressed up as Linux, a fake terminal text box, a plugin
system, an AI agent, a workflow editor, or a Metasploit/exploit-automation feature. It does
**not** provide Wi‑Fi monitor mode, packet injection, USB/Bluetooth/SDR passthrough, or
bare‑metal hardware parity — those are separate future hardware milestones.

## Trust boundary (important)

Normal MACSPLOIT execution is: typed request → core scope validation → reviewed provider →
bounded argv → Evidence → normalized state. The Linux terminal is different: **you** type
arbitrary guest shell commands. Therefore:

- commands run in the terminal are **controlled by you** and are **not** restricted by
  MACSPLOIT's workflow scope controls;
- they are **not** recorded as core-authorized provider actions;
- their output is **never** auto-imported into Assets, Evidence, or Findings;
- there is no hidden command execution, and AI cannot run terminal commands.

The UI states this boundary on the Terminal screen.

## Virtualization architecture

- **Framework:** Apple **Virtualization.framework** (`VZVirtualMachineConfiguration`),
  chosen because it is the macOS-native, Apple-supported path for a hardware-virtualized
  ARM64 Linux guest and needs no third-party hypervisor.
- **Minimum platform:** macOS **13+** on **Apple Silicon** (the app's deployment target is
  macOS 13; the EFI boot loader used here is macOS 13+). On Intel/unsupported hosts the
  feature is inert.
- **Guest:** ARM64 Linux, user-facing identity **Kali Linux ARM64**. The only supported
  boot format is `EFI_RAW_DISK`: `VZEFIBootLoader` + a single prepared root disk that
  carries its own boot files. A direct-kernel path is intentionally **not** supported — it
  would require separately downloaded kernel/initrd artifacts, each needing its own pinned
  SHA-256, which is out of scope for this foundation. The real backend builds exactly this
  EFI configuration, so the manifest, model, docs, and backend all agree.
- **Devices:** virtio block (root disk), **NAT networking** (`VZNATNetworkDeviceAttachment`
  — the smallest predictable mode; normal outbound/in-scope TCP/IP only, documented as not
  bare-metal parity), virtio entropy, a memory balloon, and a **virtio console** reserved
  for the interactive terminal transport.
- **Separation:** VM management lives in `LinuxEnvironmentModel` → a
  `LinuxEnvironmentBackend` protocol → the `VZLinuxEnvironmentBackend` adapter. UI,
  lifecycle, image/disk management, and session handling are separate.
- **Fail-closed on unsupported hosts:** on a Mac that cannot virtualize (Intel, or
  macOS < 13) production installs an `UnsupportedLinuxEnvironmentBackend` that reports a
  clear reason and refuses every operation — the app enters an `UNSUPPORTED` state and
  never pretends to run a VM. The `FakeLinuxEnvironmentBackend` exists **only** for tests
  and explicit test injection; it is never used in production.

## Lifecycle

Typed states: `UNSUPPORTED`, `NOT_CONFIGURED → SETTING_UP → STOPPED → STARTING → RUNNING →
STOPPING`, plus `FAILED`. Rules enforced by the model:

- the app launch and merely opening Terminal **never** start the VM;
- only a configured, `STOPPED` environment can start, and only on explicit user action;
- **stop** moves to `STOPPING`, attempts a graceful shutdown within a bounded timeout, then
  a forced stop, and transitions to `STOPPED` (releasing the handle) **only once the backend
  confirms the stop**. If both fail it goes to `FAILED` while **retaining** the running
  handle, so a VM is never falsely reported gone; the UI then offers **Force Stop**, which
  calls a dedicated `forceStop()` (backend forced-stop only) that reaches `STOPPED` on
  confirmed success or stays `FAILED` with the handle on failure;
- a relaunch resolves state purely from disk and never auto-starts (transient states are
  never persisted);
- a failed boot returns to a recoverable state (Retry / Recreate);
- **setup is a cancellable, owned task:** while `SETTING_UP` the user can Cancel Setup; the
  cancellation propagates to the downloader/preparation, staging is wiped, any finalized
  good artifact is left intact, and the state returns to `NOT_CONFIGURED`;
- a superseded or cancelled async operation can never corrupt state (a monotonic
  generation gates every post-await mutation).

## Setup and verified download

Setup is explicit: opening Terminal downloads nothing. **Set Up Terminal** shows the plan
(image, source, SHA‑256 verification, storage location, resources); only on confirmation
does MACSPLOIT download. The Swift `LinuxImageDownloader` mirrors the core installer's
discipline and actually enforces it: **HTTPS-only on the initial request and every
redirect**, **credential-bearing URLs rejected**, redirects confined to a **reviewed host
allow-list** (the disk URL's host plus any manifest-declared hosts — not an open set), a
**bounded redirect count held as delegate-owned state** (never a caller-supplied header), a
validated HTTP status, a **bounded streamed size** (capped mid-download), a **SHA‑256
computed by streaming** 1 MiB chunks (never by loading the multi‑GB image into memory), and
**cancellation honoured through download and hashing**. The single network-delivered
artifact is the pinned root disk — there are no separately delivered, unpinned files.

Crucially, the verified disk is downloaded into **staging** and the environment is finalized
**last**: `prepare` (small EFI vars) and config persistence happen first, and only then is
the disk **atomically moved** into place. So a failed, cancelled, or checksum-bad setup
never orphans a multi‑GB disk and never destroys an existing known-good disk — staging is
wiped, a fresh setup's partial artifacts are removed, and a pre-existing good environment is
preserved untouched. No `curl | sh`, no arbitrary remote scripts, no `sudo`, no writes to
system directories, no host package installation.

## Persistent storage and removal

The environment lives at `~/Library/Application Support/MACSPLOIT/Virtual Machines/Linux/`
(`environment.json`, `root.img`, `efi-vars.img`, `staging/`).
It is **separate** from workspace storage and `Providers/`, survives replacing
MACSPLOIT.app, and **removing it deletes only that directory** — workspaces, Assets,
Evidence, Findings, provider installs, and unrelated settings are untouched.

## Resources

Safe typed defaults derived from the host: about half the cores (capped, always leaving the
host ≥1), a quarter of RAM (reserving several GiB for the host), and a 32 GiB sparse disk.
All values are clamped to sane minimums/maximums so the VM can never be configured to
starve the host. User-editable resource settings are a follow-up.

## Terminal sessions

Multiple terminal tabs share the **one** running VM (never one VM per tab, never one-off
command execution). The model **owns the real session handles**: each UI tab corresponds to
one `LinuxTerminalSession`, closing a tab closes exactly that handle, and stopping or
removing the VM closes all of them exactly once (no stale sessions survive a stop/restart).
Tab count is bounded to a small maximum. The on-screen VT emulator binds to the VM's virtio
console in the follow-up.

## Entitlements / signing

The app carries `com.apple.security.virtualization` (`apps/macos/Resources/MACSPLOIT.entitlements`),
applied at signing (`build-macos.sh`). Ad-hoc signing carries it for local runs; **public
distribution to other users requires signing/notarizing the app with this entitlement** (a
consideration for a free, open-source, download-and-run app).

## Remaining blockers to a live boot (documented, not faked)

1. **A verified, pinned Kali-for-Virtualization.framework image.** No official artifact
   exists; `LinuxImageCatalog.availableManifest` is `nil`, and the setup UI states this
   plainly. A follow-up decides the smallest reliable format (prepared root disk we host +
   pin, or an EFI installer flow) — no fabricated production checksum is committed.
2. **The guest console transport.** The interactive VT emulator + its binding to the virtio
   console (and any narrowly-scoped guest helper) land once an image is bootable.

Until both land, `VZLinuxEnvironmentBackend.start` builds and **validates the real VM
configuration** and then surfaces a clear "not available yet" rather than shipping an
untested, unbootable VM path.

## What is implemented vs deferred

Implemented: Terminal destination + all state UIs (including an `UNSUPPORTED`, fail-closed
screen); typed lifecycle + model; fail-closed `UnsupportedLinuxEnvironmentBackend` in
production (fake backend is test-only); the hardened verified download pipeline
(HTTPS-on-redirects, no credentials, bounded redirects + streamed size, status check,
streaming SHA‑256, cancellation, non-destructive atomic finalize) with an offline fake;
EFI-only single-pinned-artifact image model; persistent storage + isolation + removal; the
real `VZVirtualMachineConfiguration` construction + the backend protocol; resource
defaults/bounds; a real-handle multi-tab/one-VM session model with exactly-once close;
graceful→forced→confirmed stop semantics; cancellable owned setup; entitlements; and
comprehensive offline tests.

Deferred: a verified bootable image, the live boot + VT console transport, user-editable
resources, and any later Evidence import / plugin / AI / hardware work (explicitly out of
scope here).
