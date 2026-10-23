# Integrated Linux terminal — Kali installer and boot

Status: **EXPERIMENTAL — Issue #90, second implementation slice; owner install/boot
acceptance pending.** PR #92's foundation was merged and owner-accepted. This slice adds
real graphical Kali installation and installed-guest boot. **Issue #90 is not complete:**
interactive terminal transport, a VT emulator and guest shell multiplexing remain pending.

MACSPLOIT's typed, scope-aware providers remain the preferred assessment path. The optional
managed guest is a separate trust boundary: user commands are not core-authorized provider
actions, are not scope-validated and never auto-import into Assets/Evidence/Findings. There
is no AI shell access, hidden scan, host filesystem share, clipboard/credential forwarding,
guest agent, SSH management, tool auto-installation, or wireless/USB passthrough.

## Reviewed official installer

The previous claim that no official ARM64 installer artifact exists was stale. Kali
publishes the **full Installer**, not NetInstaller, used here:

- Release: **Kali Linux 2026.3**; architecture: **arm64**.
- Artifact: `kali-linux-2026.3-installer-arm64.iso` (installer media, not a root disk).
- Source: <https://cdimage.kali.org/kali-2026.3/kali-linux-2026.3-installer-arm64.iso>.
- Exact size: **4,051,513,344 bytes** (about 3.77 GiB).
- SHA-256: `c4a7f9bf3a0ff07c8263fe9e9b0edba0cc3d9b408f1d8f06c066df0afce23072`.
- Provenance: official versioned [SHA256SUMS](https://cdimage.kali.org/kali-2026.3/SHA256SUMS)
  and [detached signature](https://cdimage.kali.org/kali-2026.3/SHA256SUMS.gpg).
- Review verified the detached RSA/SHA-512 signature using Kali's published archive key
  fingerprint **827C8569F2518CC677FECA1AED65462EC8D5E4C5** from
  [Kali's official verification instructions](https://www.kali.org/docs/introduction/download-official-kali-linux-images/)
  and <https://archive.kali.org/archive-key.asc>. Review date: 2026-10-22 (America/Detroit).

`LinuxImageManifest` schema 2 identifies the release, architecture, `INSTALLER_ISO` kind,
exact source, digest/byte count, provenance URL and reviewed redirect hosts. No mutable
`current` URL, custom root image or third-party VM image is used. Runtime verifies the
pinned SHA-256; **there is no runtime GPG dependency**. The full installer carries local
installation packages, reducing dependency on live package mirrors during acceptance.

The official cdimage redirector may select an official mirror. The committed allow-list
contains only explicitly reviewed destinations advertised by that redirector (including
`kali.download`); no wildcard or arbitrary mirror is accepted. A newly selected unreviewed
mirror fails closed and requires a manifest review, not an insecure fallback.

## Explicit setup and storage

Nothing downloads or boots on app launch or Terminal navigation. **Set Up Terminal** shows
the exact release, bytes, source, provenance, pinned SHA-256, disk allocation and location.
Only **Download & Prepare Installer** begins acquisition. The downloader enforces:

- HTTPS on the initial URL and all redirects, no embedded credentials;
- reviewed redirect hosts, delegate-owned redirect budget (five maximum);
- HTTP 200, advertised and streamed byte caps, exact final byte count;
- streaming SHA-256 in 1 MiB chunks and cancellation through download and hashing;
- 120-second request timeout and four-hour total resource deadline;
- ephemeral URLSession, staged files, no shell downloader, sudo or host package installer.

The isolated layout is:

```text
~/Library/Application Support/MACSPLOIT/Virtual Machines/Linux/
├── environment.json       # schema 2, resources, installation status, identity digest
├── installer.iso          # verified, read-only official installer media
├── root.img               # locally created writable sparse RAW disk
├── machine-identifier     # VZGenericMachineIdentifier.dataRepresentation
├── efi-vars.img           # persistent VZEFIVariableStore
└── staging/               # only while preparing; never evidence/provider data
```

The root disk is created locally with exclusive/no-follow file creation and `ftruncate`:
32 GiB logical default, bounded to 8–128 GiB, without physically writing zeroes. Existing
disks are never silently overwritten. New identity files and disk are private to the user;
setup owns only this directory. Preparation verifies the ISO first, creates the sparse disk,
creates machine identity/EFI state once, records identity metadata, finalizes installer
media and atomically writes config, then removes staging. Failure/cancellation removes the
fresh attempt's artifacts; a crash leaves a visible incomplete environment requiring
Recreate. Setup never runs over an installed or incomplete environment.

The ISO remains cached until environment removal: allow about 3.77 GiB **plus actual root
disk usage**, which can grow to the configured logical limit. Removing the environment
removes the cache too. Installed boots do not require the cached ISO.

Only explicit **Remove / Recreate** deletes this Linux directory; it never deletes
workspaces, Assets, Evidence, Findings, Activity, Providers or unrelated preferences.
Removal refuses to delete a guest whose stop is uncertain. Source/build changes do not
replace this directory or the owner's existing TEST workspace.

## Persistent identity and EFI

A new `VZGenericMachineIdentifier` is created during preparation, saved once, and loaded
from the same bytes for every install/normal boot. Config records its SHA-256; missing,
changed or undecodable identity is FAILED/Recreate, never silently regenerated. EFI
variables are likewise created once and reused. Missing/truncated/oversized EFI storage
fails closed; its contents are mutable firmware data, so they cannot have an immutable
post-install hash. Further firmware corruption is surfaced by Virtualization.framework
validation/boot failure, not repaired heuristically. Legacy schema-1 environments require
explicit Recreate rather than guessing their identity or installation status.

## Real VM configurations and display

The adapter follows [Apple's GUI Linux installation pattern](https://developer.apple.com/documentation/virtualization/running-gui-linux-in-a-virtual-machine-on-a-mac).
On macOS 13+ Apple Silicon, both modes use the same persisted generic machine identifier,
EFI variable store, bounded CPU/RAM, writable VirtIO root disk, NAT, entropy and memory
balloon. A VirtIO graphics scanout, USB keyboard and screen-coordinate pointer feed a
real `VZVirtualMachineView` embedded through `NSViewRepresentable`.

- **Install mode:** additionally attaches `installer.iso` **read-only as USB mass storage**.
- **Normal mode:** has **no installer device**; boots the installed `root.img` only.

Graphics remains available in normal mode to prove boot and interact with Kali. The
reserved virtio serial console and `LinuxTerminalSession` interface remain for the next
slice; production does **not** fabricate live shell sessions/tabs. The real backend's
session method explicitly reports transport pending. Unsupported hosts fail closed.
Networking is NAT only, not direct host-interface access or hardware parity.

## Typed lifecycle and truthful installation completion

```text
NOT_CONFIGURED → SETTING_UP → INSTALL_READY
INSTALL_READY → STARTING → INSTALLING → (guest stops) INSTALL_READY
INSTALL_READY / INSTALLING → owner confirms success → STOPPED
STOPPED → STARTING → RUNNING → STOPPING → STOPPED
```

`FAILED` and `UNSUPPORTED` are explicit states. Shutdown of an installer, creation of a
root disk, or successful VM start **never** marks installation complete. Only after Kali
reports success may the owner choose **Installation Complete — Boot Installed Kali…** and
confirm. MACSPLOIT first confirms the installer is stopped, atomically persists the
installed status, then starts in normal mode without the ISO. If stopping or persistence
fails, installed status is not committed. An unfinished installer remains INSTALL_READY
on relaunch and can be resumed; an installed environment always relaunches STOPPED.
Neither ever starts automatically.

The model owns the VM handle **before** async start. `VZVirtualMachine` gets its delegate
before its actual start API is called; no RUNNING/INSTALLING claim precedes framework
success. Start has a 30-second bound; timeout/failure attempts a forced stop and retains
ownership if that stop is uncertain. Delegate guest-stop/error events update the model.
Generation and handle checks prevent late start/setup/stop results from resurrecting a
removed/superseded guest.

Stop requests a graceful shutdown (15 seconds), then forced stop (5 seconds). Handle and
session resources are released only after a confirmed stopped/error VM state. A failed
stop retains the handle and offers Force Stop. A narrow AppDelegate termination hook asks
the model to cancel preparation and stop its guest before replying to macOS's deferred
quit. If shutdown cannot be confirmed, **quit is cancelled**, the handle remains managed,
and the owner sees an error; the next launch never auto-starts a guest.

## Validation and owner acceptance

Default CI uses tiny fixtures and fake backend/downloader only. It never downloads Kali
or boots a VM. Tests cover manifest/integrity/redirects, sparse allocation/no overwrite,
installer/root separation, identity/EFI damage, install/normal device intent, installation
confirmation/persistence, delayed/failed starts, guest stops, cancellation, quit behavior,
stale operations, and workspace/provider isolation. An opt-in local configuration test
constructs actual VZ configurations with synthetic media **without booting a VM**:
`./scripts/test-linux-vz-configuration.sh`. It compiles the exact production model/storage/
backend sources into a temporary build executable, signs that executable with the existing
virtualization entitlement, and checks both real device configurations. This avoids
SwiftPM's unsigned system test host; no toolchain binary is modified. The check is separate
from live owner acceptance and is not part of CI.

Owner acceptance (after current-head CI and Advanced CodeQL pass):

1. Keep the existing TEST workspace and providers; remove only an old Terminal environment
   if one exists. Open Linux Terminal and confirm it is unconfigured.
2. Open Set Up Terminal. Verify Kali 2026.3 ARM64 Installer, exact source/provenance, size
   and SHA-256. Explicitly select Download & Prepare Installer.
3. Wait for verification and preparation. Confirm INSTALL_READY, persistent machine/EFI
   files and sparse `root.img`. Nothing should have booted yet.
4. Click Install Kali. Confirm the **real Kali ARM64 installer** appears in MACSPLOIT.
   Complete its normal installation onto the virtual writable disk. Guest installer
   choices/credentials belong to the owner; MACSPLOIT never supplies or forwards them.
5. Only after Kali reports success, choose Installation Complete — Boot Installed Kali
   and confirm. Verify installed Kali boots **without installer media**.
6. Stop Kali. Quit/reopen MACSPLOIT: the environment must remain STOPPED. Start Kali again
   and verify the installed system persists. Confirm the TEST workspace remains intact.
7. Remove/recreate only the Linux environment; verify workspace/Evidence/Findings/Activity
   and host providers remain intact.

Do not call Issue #90 complete after this slice. Its remaining exit gate is a real
interactive guest terminal with bounded multiple sessions over one VM, followed by owner
terminal acceptance. VT transport/emulator, SSH/guest agents, AI execution, tool
installation, Evidence import, plugins and workflows are not implemented by this PR.
