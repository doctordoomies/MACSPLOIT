# OSINT workflow

Status: **BETA — Milestone 6 implementation (Issues #22, #58, #64, #65, #66, and the
implementation portion of #67). Owner acceptance of Milestone 6 is still pending.**
Umbrella: Issue #58. Four workflows share one typed contract and one orchestration
path:

| Workflow | Target | Providers |
| --- | --- | --- |
| Username OSINT | `@handle` | user-scanner, Sherlock, Maigret, socialscan |
| Email OSINT | `name@example.test` | user-scanner, socialscan |
| Phone OSINT | `+<country code> <number>` (E.164) | PhoneInfoga |
| Domain OSINT | an **in-scope** domain | native certificate transparency (crt.sh), native RDAP, theHarvester |

Not integrated after upstream review (evidence in
[OSINT correlation](osint-correlation.md#aggregator-review-and-decision)): Holehe,
OWASP Amass, SpiderFoot. Correlation between different assets is an explicit analyst
action — see [OSINT correlation](osint-correlation.md).

## What works

1. Add a target in the target bar: `@handle` (Username), `name@example.test` (Email),
   `+1 202 555 0143` (Phone — international format required; MACSPLOIT never guesses
   a country), or a domain (Domain OSINT also requires it in workspace scope). Adding a
   target **never** starts OSINT. For an out-of-scope domain, Run becomes **Authorize &
   Run Domain OSINT**: the core reports the exact scope entry, the confirmation names it,
   and only after the core adds and re-checks that entry does the run start (cancel
   changes nothing; identifier subjects never use host scope).
2. Open **OSINT** in the sidebar, choose the workflow, the subject, and a compatible
   provider. Provider readiness/version/setup comes from the core.
3. Press **Run**. The core runs one bounded scan or lookup (external tools through the
   existing process supervisor; built-in RDAP/CT through a bounded HTTPS client).
   **Cancel** stops it.
4. The run ends **Completed**, **Completed with partial results** (`PARTIAL`),
   **Failed**, or **Cancelled**. Accounts (Username/Email), numbering facts (Phone), or
   passive observations with "also observed by" provenance (Domain), plus summary
   counts and links to Assets / Evidence / Activity, are shown.
5. Everything is persisted in the workspace SQLite database and evidence directory and
   is restored after an app or core restart (OSINT history lists every run).

## Typed contract (shared by future OSINT providers)

| Piece | Where | Notes |
| --- | --- | --- |
| Capabilities `USERNAME_OSINT`, `EMAIL_OSINT`, `PHONE_OSINT`, `DOMAIN_OSINT` | `core/src/providers` | `Capability::is_osint()`; `is_identifier_osint()` for username/email/phone |
| Chains `username_osint`, `email_osint`, `phone_osint`, `domain_osint` | `core/src/orchestration` | One subject → one provider stage; optional `options.provider_id` |
| Provider selection | `ProviderRegistry::osint_provider` | Explicit id must advertise the capability **and** the subject's target type; otherwise the first compatible provider |
| Subject validation | `core/src/osint` | `@handle`: ASCII letters/digits/`_-.`, 1–64, no leading `-`/`.`; email: ASCII dot-atom local part, dotted domain, no leading `-`, no pattern characters |
| Check normalization | `osint::OsintCheck`, `CheckStatus` | `POSITIVE`, `NEGATIVE`, `BLOCKED` (not performed by policy), `ERROR`, `UNKNOWN`; the upstream label is always kept |
| Graph mapping | `osint::build_output` | Subject asset + run summary; `Account` per positive platform; optional profile `URL` |
| Structured artifacts | `Execution::artifacts` | A report written outside stdout becomes its own hashed evidence record before parsing |
| Partial results | `Provider::parse_outcome` | `ParsedOutput { discoveries, partial, summary }` → chain status `PARTIAL` |

### Authorization model for identifiers

Workspace scope lists hosts/networks the analyst may actively test. An OSINT subject
is an identifier, not a network destination: the provider queries third-party public
platforms with it and never contacts subject-owned infrastructure. Host scope therefore
neither authorizes nor forbids the subject. Authorization is the explicitly added
workspace target plus the explicit Run action, and the core still enforces the risk
policy (`scope::authorize_osint_subject`): only `PASSIVE` and `ACTIVE_LOW_IMPACT` OSINT
providers may run; `ACTIVE`, validation, and lab providers are rejected.

Domain OSINT is different: a domain is a workspace host. `scope::authorize_domain_osint`
requires the domain in workspace scope **and** a `PASSIVE` provider, at chain creation
and again before execution. The providers query public third parties (registries, CT
logs, public passive sources) and never contact the domain or any host they report. Discovered
profile URLs are stored with their real scope status (`in_scope: false` unless the
workspace scope covers them) and are never dispatched to another provider.

### Normalized model

| Element | Identity | Meaning |
| --- | --- | --- |
| `Username` asset | `@handle` | The subject (case preserved, like the target) |
| `EmailAddress` asset | `local@domain` | The subject (domain lowercased) |
| `Account` asset | `<platform_key>:<identifier>` (e.g. `github:octo`, `amazon:a@example.test`) | "The provider reported this identifier on this platform." |
| `has_account` relationship | subject → Account | Provider claim, not proof of ownership |
| `URL` asset + `profile_url` | Account → URL | Only validated `http(s)` URLs without credentials |
| `PhoneNumber` asset | `+<digits>` (E.164) | The phone subject; the original input is kept on the target |
| `Subdomain` asset + `has_subdomain` | Domain → host | Same type Subfinder produces, so passive sources deduplicate with recon data |
| `EmailAddress` asset + `has_email` | Domain → email | A public source reported the address (only at the domain or a subdomain) |
| `Hostname`/`Subdomain` + `has_nameserver` | Domain → nameserver | From the registry's RDAP record |
| `IPAddress` + `observed_ip` | host/Domain → IP | A passive source associated them; MACSPLOIT did **not** resolve it (not `resolves_to`) |
| Observation `metadata` (migration 004) | per run | Upstream status, platform, category, URL, reason, bounded profile fields/media, upstream confidence, identity note |

`Account` is justified by the actual data: email registration results usually have
**no** profile URL, so URL assets alone would lose them. Accounts are never merged
across platforms or identifiers; the username and the email subject produce separate
accounts even on the same platform. Observation confidence is `REPORTED` (the
provider said so; MACSPLOIT did not verify it). Every summary carries the note that a
matching username or email is not proof that accounts belong to one person.

Repeat runs reuse canonical assets/relationships and add new per-run observations and
relationship observations, so history is kept without duplicate nodes. Negative
results are counted on the run summary (the full list remains in the evidence report)
rather than creating thousands of nodes.

## user-scanner integration

Upstream: [kaifcodec/user-scanner](https://github.com/kaifcodec/user-scanner), MIT,
PyPI package `user-scanner`, console script `user-scanner`.

**Verified** by reading the published source of 1.5.0, 1.5.1.3, 1.5.2, and 1.5.2.1
(the latest on PyPI and in upstream `version.json` at the time of integration;
sdist SHA-256 `51b6590d60e87606220d05d82b4ce793676723c9cb137fb03e8758fea17ea084`), and
by running the real 1.5.2.1 CLI for `--version` and argument parsing only (no scan).
**Supported: 1.5.x.** Other versions report *Unsupported version* in Provider Center
and do not run.

| Topic | Upstream behavior | MACSPLOIT usage |
| --- | --- | --- |
| Install | `pip`/`pipx` package; no Homebrew formula | Copy-only `pipx install user-scanner`; never installed by MACSPLOIT |
| Discovery | — | `MACSPLOIT_USER_SCANNER` override, then `PATH`, Homebrew dirs, managed dir, then `$PIPX_BIN_DIR` / `~/.local/bin` (the app starts the core with a minimal `PATH`) |
| Version | `--version` → `user-scanner current version -> X` from bundled `version.json`, exits before any network | 15 s probe |
| Subject | `-u/--username`, `-e/--email` | `--username=<handle>` / `--email=<address>` (`=` form + strict validation: never parsed as an option) |
| Structured output | `--format json --output FILE` writes a JSON array of **all** module results at the **end** of the scan; appends to an existing file | Fresh private temp dir per run; report read without following symlinks, capped at 1 MiB, stored as its own evidence |
| Record schema | `status` (`Found`/`Not Found`, `Registered`/`Not Registered`, `Error`, `Skipped`), `reason`, `username` or `email`, `site_name`, `category`, `url`, `extra` (string/int/bool map), `media` (string map) | Mapped to `POSITIVE`/`NEGATIVE`/`ERROR`/`BLOCKED`; unrecognized → `UNKNOWN` |
| Concurrency | default 60 (username) / 25 (email), `-C` | `--concurrency 20` / `8` |
| Request timeout | default 15 s per module (+10 s module cap), `-t` | `--timeout 10` |
| Module selection | `-m`, `-c`, `--no-nsfw`; NSFW **included by default** | Full catalog with `--no-nsfw` (2,489 username / 194 email modules in 1.5.2.1) |
| Pattern expansion | Username input is a pattern language (`[a-z]{2}` …), `--stop` default 100 | Pattern characters rejected; `--stop 1` |
| Update check | **On by default**: contacts PyPI and prompts interactively unless the config at `USER_SCANNER_CONFIG` sets `auto_update_status=false` | Private per-run config disables it |
| Loud modules | Modules that may notify the subject (e.g. password reset) are skipped unless `--allow-loud` | Never passed; reported as `BLOCKED` |
| Recursion | `--cross-scan` (+ `--cross-*`) follows discovered handles/links/emails | **Never passed** |
| Breach data | `--hudson` (Hudson Rock infostealer intelligence) | **Never passed** |
| Proxies | `--proxy-file`, `--validate-proxies` | **Never passed** |
| Other | `--email-domains`, `-uf/-ef`, `--update`, PDF, MCP server | Never used |

Bounds: 15-minute provider timeout (OSINT chain ceiling 16 min), stdout 256 KiB and
stderr 64 KiB (excess drained and discarded), report 1 MiB, 5,000 records, 250
accounts per run, 512-byte strings, 2,048-byte URLs, 24 metadata keys, 100 listed
errors/blocked/unknown checks per summary. Controls/bidi characters are stripped.

Evidence: each run stores an envelope (exact argv with the private report path
replaced by `<private-run-dir>/results.json`, exit status, timing, `cancelled`,
stdout/stderr, and references to artifact evidence ids/SHA-256) plus, when present,
the raw upstream report byte-for-byte. Observations link to the report evidence. On
cancel, timeout, non-zero exit, missing/oversized/malformed report, the evidence that
exists is kept and the provider run is marked accordingly.

## Username OSINT provider wave (Sherlock, Maigret, socialscan)

Three additional **username-only** providers (capability `USERNAME_OSINT`, target type
`Username`, risk `ACTIVE_LOW_IMPACT`) plug into the same typed contract and
`osint::build_output`, so cross-provider results deduplicate into one canonical
`Account`/profile-`URL` asset while each provider keeps its own observation, evidence,
and provenance. None of them perform login, credential checks, breach-data ingestion,
recursion, or proxy/anti-blocking behavior. All are discovered via the shared
pip/pipx plumbing (`MACSPLOIT_<TOOL>` override, then `PATH`, Homebrew dirs, managed
dir, `$PIPX_BIN_DIR`/`~/.local/bin`), run in a private contained working directory and
`HOME`, and capture their structured report as hashed evidence (symlink-safe, ≤1 MiB)
before parsing. Each is bounded by its own wall-clock timeout plus the OSINT chain
ceiling, captures ≤256 KiB stdout / ≤64 KiB stderr, and supports cancellation via the
process group. They are not in the managed-download installer matrix (truthful
copy-only `pipx`/`pip` setup guidance is shown instead); existing binaries on `PATH`
or an override are first-class.

| Provider | Upstream | Install | Version | Subject | Structured output | Positive = | Bounds / safety |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **Sherlock** | [sherlock-project/sherlock](https://github.com/sherlock-project/sherlock), MIT, console `sherlock` | `pipx install sherlock-project` | `--version` → `sherlock v0.x` (series `0.`) | positional username after `--` (strictly validated) | `--csv --local --no-color --timeout 10` writes `<username>.csv` (`username,name,url_main,url_user,exists,http_status,response_time_s`) in the run dir; no JSON | `exists == Claimed` (`Available`→negative, `Illegal`→blocked, `WAF`/`Unknown`→error, other→unknown) | bundled site list (`--local`), NSFW excluded, no recursion/proxy; minimal CSV parser (quoted fields), columns resolved by header |
| **Maigret** | [soxoj/maigret](https://github.com/soxoj/maigret), MIT, console `maigret` | `pipx install maigret` | `--version` (series `0.`) | positional username (strictly validated) | `--json simple -fo <dir>` writes `report_<username>_simple.json`, a site-keyed object containing **only claimed sites** (`url_user`, `status`, `ids_data`) | presence in the simple report (claimed) | `--no-recursion --no-extracting --top-sites 500 --timeout 10 --retries 1`; never `-a`/`--permute`/`--parse`/`--proxy`/`--cloudflare-bypass`; `ids_data` bounded into profile metadata |
| **socialscan** | [iojw/socialscan](https://github.com/iojw/socialscan), MIT, console `socialscan` | `pip install socialscan` | `--version` (series `1.` and `2.`; latest 2.0.1) | positional query (username or email; strictly validated) | `--json <file> --show-urls --view-by platform` writes a platform-keyed object of record lists (`query`, `platform`, `available`, `valid`, `success`, `message`, `link`) | `success && !available && valid` (taken); `available`→negative, `!success`→error, `!valid`→unknown. Booleans are accepted as JSON booleans or the `"True"`/`"False"` strings upstream actually emits | never `--available-only`/`--proxy-list`/`--input`/`--cache-tokens`; availability only — never login, credentials, or private data; less actively maintained upstream, so platform coverage is smaller |

Cross-provider example (all offline fixtures): for `@octo-synthetic`, Sherlock, Maigret,
and socialscan each report `github.com/octo-synthetic`. The result is **one** canonical
`github:octo-synthetic` Account and **one** profile URL asset, with **three**
observations (one per provider run), each attributable to its own provider and evidence;
Maigret's additional `keybase:octo-synthetic` stays a separate account. Agreement across
providers is **not** treated as proof the accounts belong to one person — the identity
note travels with every observation and summary.

## Email OSINT completion (Issue #64)

- **socialscan** now advertises `EMAIL_OSINT` as well as `USERNAME_OSINT`. Email
  records map to **registered** (`Account`, `REPORTED`), **not registered** (counted),
  and **failed lookup** (`success: false` → `ERROR`, run `PARTIAL`) — a failed lookup is
  never reported as "not registered". Upstream review found that socialscan's JSON
  emits booleans as `"True"`/`"False"` strings and that the current release is 2.0.1;
  both are handled (the earlier integration would have rejected 2.x and treated every
  string-boolean record as an error).
- user-scanner and socialscan email discoveries of the same platform deduplicate into
  one `Account` with one observation per provider run.
- **Holehe is not integrated**: it determines registration by driving each site's
  signup or password-reset flow, which is account interaction that can notify the
  subject (and upstream has been inactive since 2024-09).
- theHarvester email discoveries come only from Domain OSINT (below); there is no
  second theHarvester path for Email OSINT.

## Phone OSINT — PhoneInfoga (Issue #65)

Upstream: [sundowndev/phoneinfoga](https://github.com/sundowndev/phoneinfoga),
GPL-3.0, run as a separate executable; verified against v2.11.0 (Homebrew
`phoneinfoga` 2.11.0). Supported series `2.`.

| Topic | Behavior |
| --- | --- |
| Target | `PhoneNumber`, canonical E.164. Input must start with `+` and a country code (optional `tel:`; spaces, `-`, `.`, `()` allowed; 7–15 digits). A number without `+` is rejected with guidance — no country is ever guessed. The original input is preserved on the target |
| Invocation | `phoneinfoga scan --number=<E.164> --disable=numverify --disable=googlecse --disable=googlesearch` in a private directory/`HOME`; `--plugin`/`--env-file`/`serve` never used |
| Sources | `local` (offline libphonenumber facts) and `ovh` (OVH's public number-range lookup). API-key services and Google dork generation are disabled |
| Parsing | The `scan` CLI has no JSON output, so the fixed console renderer is parsed with a strict grammar (`Results for <scanner>`, `Field: value`, an errors block, and a required `<N> scanner(s) succeeded` trailer); malformed lines make the run `PARTIAL`; a missing trailer fails the run; output over 256 KiB fails with `BudgetExceeded`. Raw output is evidence |
| Result | One `PhoneNumber` subject with a run-summary observation (per-source facts, source errors, a mismatch flag if the tool reports a different E.164) and the note that numbering data can be outdated after porting and does not identify the subscriber |
| Never | Calls, SMS, OTP, account recovery, subscriber/private lookups, credentials, SIM attacks, social engineering, tracking, or pivots — one number, one bounded run (120 s) |

## Domain / public-infrastructure OSINT (Issue #66)

All three providers advertise `DOMAIN_OSINT` for `Domain` targets, are `PASSIVE`, and
run only on an in-scope domain. Every value they return is untrusted: names are
re-validated with the core's domain normalizer, kept only inside the subject domain
(nameservers excepted), deduplicated, and bounded (250 hosts, 100 emails, 100 IPs, 20
nameservers per run; the rest are counted and the run is `PARTIAL`). Every observation
carries `passive: true`, `liveness: "unverified"`, the provider id, and a note; nothing
is resolved, probed, or passed to another stage.

### Native certificate transparency (`native_ct`, built-in)

- One HTTPS GET to `https://crt.sh/?q=%25.<domain>&output=json` (names under the
  domain); 90 s deadline; 4 MiB body bound — a larger response fails with
  `BudgetExceeded` rather than parsing a truncated document; 20,000 records.
- Raw bytes are stored as evidence (1 MiB chunks) before parsing; a compact request
  log (URL, status, size, truncation) is the envelope's stdout.
- `name_value`/`common_name` names are lowercased, trailing dots removed, validated,
  deduplicated across certificates; `*.x` becomes `x` with `wildcard: true`; a wildcard
  for the subject itself is only counted; email SANs are discarded.
- Each host observation is **historical** and records certificate count, first
  `not_before`, last `not_after`, `all_certificates_expired`, and up to three issuers.
  A CT name is not proof that a host exists or is live today.

### Native RDAP (`native_rdap`, built-in)

- IANA DNS bootstrap (`https://data.iana.org/rdap/dns.json`, ≤512 KiB) → the
  longest matching suffix's first `https` base URL → `GET <base>/domain/<domain>`
  (≤1 MiB, 60 s). At most two redirects, only to `https` hosts listed in the bootstrap;
  `related` links are recorded, never followed. 404 → "not found at the registry"
  (RDAP answers for registered domains; subdomains are usually not found).
- Kept: ldhName, handle, status, event dates, DNSSEC delegation flag, port43, the
  registrar's name and IANA ID, and entity **role counts**. Registrant/admin/tech
  contact vCards are never copied into results (they remain only in the raw evidence).
  Nameservers become `has_nameserver` relationships. A response for a different
  ldhName makes the run `PARTIAL`.

### theHarvester (`theharvester`, external)

Upstream [laramies/theHarvester](https://github.com/laramies/theHarvester), GPL-2.0,
run as a separate executable; verified against release 4.11.1 (Homebrew `theharvester`
4.11.1) and the 4.10 CLI. Supported series `4.10.`, `4.11.`; version from the `-h`
banner. Setup: `brew install theharvester` (copy-only).

- Fixed argv: `-d <domain> -b certspotter,crtsh,duckduckgo,hackertarget,otx,rapiddns,subdomaincenter,thc,urlscan,waybackarchive -l 500 -q -f report`
  in a private directory/`HOME`; 300 s limit; `report.json` captured (≤1 MiB) as
  evidence before parsing.
- **Never passed:** `-r/--dns-resolve`, `-n/--dns-lookup`, `-c/--dns-brute`,
  `-t/--take-over`, `-s/--shodan`, `--screenshot`, `-a/--api-scan`, `-e`, `-p/--proxies`,
  vhost options. Without them theHarvester sends no DNS queries and does not contact the
  target. Breach/infostealer sources (dehashed, haveibeenpwned, hudsonrock, leaklookup),
  API-key sources, and DNS-activity sources are not in the allow-list. Upstream rotates
  browser User-Agent strings for some sources; MACSPLOIT adds no evasion.
- `hosts` (`host` or `host:ip`), `ips`, and in-domain `emails` are kept; `people`,
  social links, and URLs are only counted; ASNs are listed (≤20) on the summary.

### Reusing Subfinder data

Domain OSINT never runs Subfinder. Hosts use the same `Subdomain` asset type, so a name
Subfinder already found is one canonical asset; the OSINT results list shows "also
observed by" for observations from other runs (e.g. Subfinder), and asset first-seen
metadata is never overwritten.

### Regression example (offline)

theHarvester reports `api.example.test` and `person@example.test`; CT reports
`api.example.test` and `old.example.test`. Result: one canonical `api.example.test`
with one observation per provider run and evidence per provider; `old.example.test`
marked historical with expired certificates only; `person@example.test` with
theHarvester provenance via `has_email`; no `resolves_to` relationships and no other
provider runs. (OWASP Amass is not integrated; see the aggregator decision.)

### Live verification

crt.sh and IANA/registry RDAP could not be reached from the development environment
(egress-blocked), so these clients are verified against the documented formats and
offline fixtures. A real-network run is part of the owner's acceptance walkthrough.

## Known limitations

- **No partial structured results on cancel/timeout.** user-scanner writes its JSON
  only when the scan finishes, so a cancelled or timed-out run keeps stdout/stderr
  evidence but no discoveries. MACSPLOIT does not scrape terminal text.
- **Progress is stage-level.** Upstream offers no structured progress stream, so the
  UI shows the running stage and elapsed time, not per-module progress.
- **Full catalog only.** Category/module selection, NSFW opt-in, and cross-scan
  pivots are not exposed yet; any future pivot mode needs explicit opt-in and hard
  depth/result limits.
- A report larger than 1 MiB fails the run (`BudgetExceeded`) with output evidence
  kept; the workspace asset limit (1,000) also applies.
- `PARTIAL` is common on real networks because some platforms rate-limit or time out.
- Upstream check accuracy is upstream's; MACSPLOIT preserves but does not re-verify it.
- Automated tests are offline (`fixtures/fake-*.sh` for user-scanner, Sherlock,
  Maigret, socialscan, PhoneInfoga, theHarvester; static web fixtures for RDAP/CT). A
  real-network run is the owner's manual acceptance step.
- Domain OSINT bounds are per run; the workspace asset limit (1,000) still applies and a
  run that would exceed it fails without partial persistence.
