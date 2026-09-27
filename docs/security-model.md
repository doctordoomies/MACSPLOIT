# Security model

Status: requirements for implementation, plus active repository safeguards.

## Repository and sensitive data

The repository is private. The ignore policy, commit audit, push audit, and
private-destination verification are implemented now. See
[repository policy](repository-policy.md) for prohibited data and limitations.
Tests and examples must use synthetic information only.

## Application trust boundaries

Targets, provider output, remote content, filenames, and tool metadata are
untrusted. Validate input, use process argument arrays, constrain evidence paths,
parameterize database operations, bound resource use, and sanitize terminal
control sequences in the viewer. Preserve protected raw evidence separately.
Do not allow parsers to write arbitrary files or issue further network requests.

Future API credentials belong in macOS Keychain. Never place them in plaintext
configuration, command history, source, environment files, logs, or reports.
Redact sensitive display fields without falsely claiming captured evidence
contains no secrets. Access, retention, deletion, and export controls must be
designed alongside workspace persistence.

## Scope and authorization

Require explicit assessment scope before active scanning. Apply controls again
when targets resolve, redirect, or produce new assets. Scope, exclusions, impact
class, concurrency, request limits, and discovery budgets are dispatch inputs.
Passive-only mode excludes active providers even when a preset contains them.

Normal reconnaissance must not automatically attempt authentication, execute
payloads, obtain credentials, persist on systems, or escalate a finding into
compromise. Future authorized-validation/lab functionality is opt-in and
architecturally separate. Wireless attacks and hardware payloads are out of
scope for the initial platform.

## Local execution and permissions

Do not run the whole application as root. Research macOS sandbox and helper
requirements before choosing a distribution architecture. Request only narrow
privileges for a specific operation when required. A separate core service, if
chosen, must restrict access to the intended local user and validate all IPC.
Tool installation/update/repair must show the proposed action for approval.

Audit records should capture user approvals, scope changes, task dispatch,
provider versions, findings review, and export actions. Logging itself must not
leak credentials. Security requirements need executable tests as their features
are implemented; this design document does not claim runtime enforcement exists.
