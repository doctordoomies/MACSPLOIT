# Privacy & local data

MACSPLOIT is a **local** tool. It has **no telemetry or analytics** and makes no
network requests of its own. The only network activity is the reconnaissance you
explicitly launch (a provider contacting resolvers or targets you configured).

## Where your data lives

- **Workspaces and evidence:** `~/Library/Application Support/MACSPLOIT/` — one
  directory per workspace, each with a SQLite database and an `evidence/` folder.
  These are created with restrictive permissions (directories `0700`, evidence files
  `0600`) and live **outside** the source repository.
- **Preferences:** standard macOS preferences (`com.doctordoomies.MACSPLOIT`).
- **Logs:** a helper log under the workspace data directory. Logs record tool
  lifecycle and operation status; they intentionally exclude target values and
  evidence bodies, and rotate on startup above a size threshold.

## What is persisted

Targets, the asset graph (subdomains, IPs, ports, services, websites, technologies),
relationships, provider runs, raw provider evidence (e.g. Nmap XML, httpx JSON), and
durable events. This is sensitive assessment data — treat the data directory
accordingly.

## What leaves your computer

Only provider traffic you initiate:

- Subfinder queries its configured passive sources.
- Native DNS uses your **system resolver configuration** (no hardcoded public
  resolver).
- Nmap and HTTPX contact **in-scope** targets you added.

Nothing is sent to the MACSPLOIT project or any third party.

## Backing up and removing data

- **Back up** a workspace by copying its directory under
  `~/Library/Application Support/MACSPLOIT/`.
- **Remove** data by deleting that directory (or a specific workspace subdirectory).
  A guided in-app "Delete Workspace" action is planned; until then, delete the
  folder manually. Deletion never follows symlinks outside application storage.

## Sharing safely

Before sharing logs, evidence, or screenshots (e.g. in a bug report), remove real
target data, private IPs, credentials, tokens, and any client information. Use the
offline **Synthetic Recon** demo data where possible.
