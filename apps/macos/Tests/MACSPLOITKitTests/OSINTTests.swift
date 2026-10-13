import Foundation
import Testing
@testable import MACSPLOITKit

/// A snapshot shaped exactly like the Rust core's `snapshot` result after one
/// Username OSINT run (snake_case JSON, decoded with the production decoder).
let osintSnapshotJSON = #"""
{
  "workspace": {"id": "w", "name": "OSINT", "created_at": "2026-10-08T00:00:00Z", "updated_at": "2026-10-08T00:00:00Z", "scope": ["example.test"]},
  "targets": [
    {"id": "t-user", "workspace_id": "w", "original_value": "@octo-synthetic", "normalized_value": "@octo-synthetic", "target_type": "Username", "created_at": "2026-10-08T00:00:00Z", "asset_id": null},
    {"id": "t-mail", "workspace_id": "w", "original_value": "researcher@example.test", "normalized_value": "researcher@example.test", "target_type": "EmailAddress", "created_at": "2026-10-08T00:00:00Z", "asset_id": null},
    {"id": "t-dom", "workspace_id": "w", "original_value": "example.test", "normalized_value": "example.test", "target_type": "Domain", "created_at": "2026-10-08T00:00:00Z", "asset_id": "a-dom"}
  ],
  "assets": [
    {"id": "a-user", "workspace_id": "w", "asset_type": "Username", "canonical_identity": "@octo-synthetic", "display_value": "@octo-synthetic", "metadata": {"in_scope": false}, "first_seen": "t", "last_seen": "t"},
    {"id": "a-gh", "workspace_id": "w", "asset_type": "Account", "canonical_identity": "github:octo-synthetic", "display_value": "github:octo-synthetic", "metadata": {"platform": "Github", "in_scope": false}, "first_seen": "t", "last_seen": "t"}
  ],
  "relationships": [
    {"id": "r1", "workspace_id": "w", "source_asset_id": "a-user", "destination_asset_id": "a-gh", "relationship_type": "has_account", "created_at": "t"}
  ],
  "observations": [
    {"id": "o-legacy", "workspace_id": "w", "asset_id": "a-dom", "source_asset_id": null, "provider_run_id": null, "evidence_id": null, "discovered_by": "Analyst", "observed_value": "example.test", "timestamp": "t", "confidence": "CONFIRMED", "metadata": null},
    {"id": "o-sum", "workspace_id": "w", "asset_id": "a-user", "source_asset_id": null, "provider_run_id": "p1", "evidence_id": "e-report", "discovered_by": "user-scanner", "observed_value": "@octo-synthetic", "timestamp": "t", "confidence": "CONFIRMED",
     "metadata": {"kind": "osint_run_summary", "provider": "user_scanner", "subject": "@octo-synthetic", "subject_kind": "USERNAME", "checked": 8,
                  "counts": {"positive": 4, "negative": 2, "blocked": 1, "error": 1, "unknown": 0}, "accounts": 3, "duplicates": 1, "urls_rejected": 1,
                  "positive_over_limit": 0, "records_dropped_over_limit": 0, "records_malformed": 0, "records_mismatched_subject": 0,
                  "errors": [{"platform": "Instagram", "category": "Social", "upstream_status": "Error", "reason": "ConnectError: Connection timed out"}],
                  "blocked": [{"platform": "Somesite", "category": "Other", "upstream_status": "Skipped", "reason": "Notifies the target"}],
                  "unknown": [], "partial": true, "identity_note": "A provider reporting the same username or email on several platforms is not proof that those accounts belong to one person."}},
    {"id": "o-gh", "workspace_id": "w", "asset_id": "a-gh", "source_asset_id": "a-user", "provider_run_id": "p1", "evidence_id": "e-report", "discovered_by": "user-scanner", "observed_value": "github:octo-synthetic", "timestamp": "t", "confidence": "REPORTED",
     "metadata": {"kind": "osint_account", "provider": "user_scanner", "platform": "Github", "platform_key": "github", "category": "Dev", "status": "POSITIVE", "upstream_status": "Found",
                  "url": "https://github.example.test/octo-synthetic", "reason": null, "profile": {"name": "Synthetic Octo", "followers": 42, "verified": false}, "media": {}}}
  ],
  "chains": [
    {"id": "c-old", "workspace_id": "w", "target_id": "t-dom", "name": "DNS Recon", "status": "COMPLETED", "created_at": "t", "updated_at": "t", "error_code": null},
    {"id": "c1", "workspace_id": "w", "target_id": "t-user", "name": "Username OSINT", "status": "PARTIAL", "created_at": "t", "updated_at": "t", "error_code": null}
  ],
  "stages": [
    {"id": "s1", "workspace_id": "w", "chain_id": "c1", "position": 1, "name": "Username OSINT", "capability": "USERNAME_OSINT", "status": "COMPLETED", "started_at": "t", "ended_at": "t", "provider_id": "user_scanner"},
    {"id": "s0", "workspace_id": "w", "chain_id": "c1", "position": 0, "name": "Subject Validation", "capability": null, "status": "COMPLETED", "started_at": "t", "ended_at": "t", "provider_id": null}
  ],
  "tasks": [],
  "provider_runs": [
    {"id": "p1", "workspace_id": "w", "chain_id": "c1", "stage_id": "s1", "provider_id": "user_scanner", "provider_version": "1.5.2.1", "target": "@octo-synthetic", "start_time": "t", "end_time": "t", "status": "COMPLETED", "raw_output_reference": "e-env", "exit_status": 0}
  ],
  "evidence": [
    {"id": "e-report", "workspace_id": "w", "provider_run_id": "p1", "provider": "user-scanner", "target": "@octo-synthetic", "timestamp": "t", "sha256": "aa", "media_type": "application/json", "relative_path": "evidence/e-report.json", "byte_count": 10},
    {"id": "e-env", "workspace_id": "w", "provider_run_id": "p1", "provider": "user-scanner", "target": "@octo-synthetic", "timestamp": "t", "sha256": "bb", "media_type": "application/json", "relative_path": "evidence/e-env.json", "byte_count": 20}
  ],
  "events": [],
  "last_sequence": 40
}
"""#

func osintSnapshot() throws -> Snapshot {
    try CoreCoding.decoder().decode(Snapshot.self, from: Data(osintSnapshotJSON.utf8))
}

func osintProviderStatus(state: String = "INSTALLED", version: String? = "1.5.2.1") -> ProviderStatus {
    ProviderStatus(
        id: "user_scanner", name: "user-scanner", description: "Username + Email OSINT", version: "external",
        capabilities: ["USERNAME_OSINT", "EMAIL_OSINT"], supportedTargetTypes: ["Username", "EmailAddress"],
        riskClass: "ACTIVE_LOW_IMPACT", networkActivity: "NETWORK", offline: false,
        installation: ProviderInstallation(state: state, path: nil, version: version, message: nil),
        setup: ProviderSetup(installCommand: "pipx install user-scanner", homepage: "https://github.com/kaifcodec/user-scanner", documentation: nil),
        install: ProviderInstallInfo(homebrew: false, managedDownload: false, officialInstallerUrl: nil))
}

@Suite struct OSINTPresentationTests {
    @Test func testObservationMetadataDecodesAndLegacyRowsStayNil() throws {
        let snapshot = try osintSnapshot()
        #expect(snapshot.observations.first { $0.id == "o-legacy" }?.metadata == nil)
        #expect(snapshot.observations.first { $0.id == "o-gh" }?.metadata?["upstream_status"].string == "Found")
        // Rows from an older core without the field still decode.
        let old = #"{"id":"x","workspace_id":"w","asset_id":"a","source_asset_id":null,"provider_run_id":null,"evidence_id":null,"discovered_by":"Analyst","observed_value":"v","timestamp":"t","confidence":"CONFIRMED"}"#
        let decoded = try CoreCoding.decoder().decode(Observation.self, from: Data(old.utf8))
        #expect(decoded.metadata == nil)
    }

    @Test func testModesSelectOnlyCompatibleTargetsAndProviders() throws {
        let snapshot = try osintSnapshot()
        #expect(OSINTMode.username.compatibleTargets(snapshot.targets).map(\.id) == ["t-user"])
        #expect(OSINTMode.email.compatibleTargets(snapshot.targets).map(\.id) == ["t-mail"])
        #expect(OSINTMode.username.chainKind == "username_osint")
        #expect(OSINTMode.email.chainKind == "email_osint")
        #expect(OSINTMode.mode(forTargetType: "EmailAddress") == .email)
        #expect(OSINTMode.mode(forTargetType: "Domain") == .domain)
        #expect(OSINTMode.mode(forTargetType: "PhoneNumber") == .phone)
        #expect(OSINTMode.mode(forTargetType: "IPAddress") == nil)
        #expect(OSINTMode.domain.compatibleTargets(snapshot.targets).map(\.id) == ["t-dom"])
        #expect((OSINTMode.phone.chainKind, OSINTMode.phone.capability) == ("phone_osint", "PHONE_OSINT"))
        #expect((OSINTMode.domain.chainKind, OSINTMode.domain.capability) == ("domain_osint", "DOMAIN_OSINT"))
        #expect(OSINTMode.domain.riskLabel == "PASSIVE" && !OSINTMode.domain.reportsAccounts)
        #expect(OSINTMode.chainNames.contains("Domain OSINT") && OSINTMode.chainNames.contains("Phone OSINT"))
        let unrelated = ProviderStatus(
            id: "nmap", name: "Nmap", description: "", version: "external", capabilities: ["PORT_DISCOVERY"],
            supportedTargetTypes: ["IPAddress"], riskClass: "ACTIVE", networkActivity: "NETWORK", offline: false,
            installation: ProviderInstallation(state: "INSTALLED", path: nil, version: "7.95", message: nil), setup: nil, install: nil)
        #expect(OSINTMode.username.compatibleProviders([unrelated, osintProviderStatus()]).map(\.id) == ["user_scanner"])
        #expect(providerLabel("USERNAME_OSINT") == "Username OSINT")
    }

    @Test func testUsernameWaveProvidersDecodeAndAreOfferedByThePicker() throws {
        // A list_providers reply including the whole username wave decodes, and the
        // Username workflow offers every compatible provider (the picker is dynamic;
        // readiness is carried per provider so a missing one still appears).
        let json = #"""
        {"result":[
          {"id":"sherlock","name":"Sherlock","description":"Username OSINT","version":"external",
           "capabilities":["USERNAME_OSINT"],"supported_target_types":["Username"],"risk_class":"ACTIVE_LOW_IMPACT",
           "network_activity":"NETWORK","offline":false,"installation":{"state":"MISSING"},
           "setup":{"install_command":"pipx install sherlock-project","homepage":"https://github.com/sherlock-project/sherlock","documentation":null},
           "install":{"homebrew":false,"managed_download":false}},
          {"id":"maigret","name":"Maigret","description":"Username OSINT","version":"external",
           "capabilities":["USERNAME_OSINT"],"supported_target_types":["Username"],"risk_class":"ACTIVE_LOW_IMPACT",
           "network_activity":"NETWORK","offline":false,"installation":{"state":"INSTALLED","version":"0.5.0"},
           "setup":{"install_command":"pipx install maigret","homepage":"https://github.com/soxoj/maigret","documentation":null},
           "install":{"homebrew":false,"managed_download":false}},
          {"id":"socialscan","name":"socialscan","description":"Username OSINT","version":"external",
           "capabilities":["USERNAME_OSINT"],"supported_target_types":["Username"],"risk_class":"ACTIVE_LOW_IMPACT",
           "network_activity":"NETWORK","offline":false,"installation":{"state":"MISSING"},
           "setup":{"install_command":"pip install socialscan","homepage":"https://github.com/iojw/socialscan","documentation":null},
           "install":{"homebrew":false,"managed_download":false}}
        ]}
        """#
        struct Reply: Decodable { let result: [ProviderStatus] }
        let providers = try CoreCoding.decoder().decode(Reply.self, from: Data(json.utf8)).result
            + [osintProviderStatus()]
        let offered = OSINTMode.username.compatibleProviders(providers).map(\.id).sorted()
        #expect(offered == ["maigret", "sherlock", "socialscan", "user_scanner"])
        // Username-only providers never appear under the Email workflow.
        #expect(OSINTMode.email.compatibleProviders(providers).map(\.id) == ["user_scanner"])
        // Readiness is independent of listing (a missing provider still appears).
        let sherlock = try #require(providers.first { $0.id == "sherlock" })
        #expect(sherlock.installation.state == "MISSING")
        #expect(sherlock.managedDownloadSupported == false && sherlock.homebrewSupported == false)
    }

    @Test func testRunResultsExposeSummaryAccountsEvidenceAndPartialState() throws {
        let snapshot = try osintSnapshot()
        #expect(snapshot.osintChains.map(\.id) == ["c1"])
        #expect(OSINTRunResults.make(snapshot: snapshot, chainId: "c-old") == nil)
        let results = try #require(OSINTRunResults.make(snapshot: snapshot, chainId: "c1"))
        #expect(results.state == .partial)
        #expect(results.state.title == "Completed with partial results")
        #expect(results.stages.map(\.name) == ["Subject Validation", "Username OSINT"])
        #expect(results.providerRun?.providerVersion == "1.5.2.1")
        #expect(results.evidence.map(\.id) == ["e-report", "e-env"])
        let summary = try #require(results.summary)
        #expect(summary.positive == 4 && summary.negative == 2 && summary.blocked == 1 && summary.error == 1)
        #expect(summary.partial)
        #expect(summary.errors.first?.platform == "Instagram")
        #expect(summary.blockedChecks.first?.platform == "Somesite")
        #expect(summary.identityNote.contains("not proof"))
        let account = try #require(results.accounts.first)
        #expect(results.accounts.count == 1)
        #expect(account.platform == "Github" && account.assetId == "a-gh")
        #expect(account.confidence == "REPORTED")
        #expect(account.upstreamStatus == "Found")
        #expect(account.profileURL == "https://github.example.test/octo-synthetic")
        #expect(account.evidenceId == "e-report")
        #expect(account.profile == [
            OSINTProfileField(key: "followers", value: "42"),
            OSINTProfileField(key: "name", value: "Synthetic Octo"),
            OSINTProfileField(key: "verified", value: "false"),
        ])
    }

    @Test func testRunStatesMapEveryTerminalStatus() {
        func state(_ status: String, _ code: String? = nil) -> OSINTRunState {
            OSINTRunState(chain: ChainRun(id: "c", workspaceId: "w", targetId: "t", name: "Email OSINT", status: status, createdAt: "t", updatedAt: "t", errorCode: code))
        }
        #expect(state("RUNNING") == .running)
        #expect(state("PENDING") == .running)
        #expect(state("COMPLETED") == .completed)
        #expect(state("PARTIAL") == .partial)
        #expect(state("CANCELLED") == .cancelled)
        #expect(state("FAILED", "ProviderMissing").title == "Failed · ProviderMissing")
        #expect(state("CANCELLED").detail.contains("evidence"))
    }
}

/// A Domain OSINT run (native CT) after an earlier Subfinder recon run, plus a
/// Phone OSINT run, shaped like the core's snapshot.
let domainSnapshotJSON = #"""
{
  "workspace": {"id": "w", "name": "OSINT", "created_at": "t", "updated_at": "t", "scope": ["example.test", "*.example.test"]},
  "targets": [
    {"id": "t-dom", "workspace_id": "w", "original_value": "example.test", "normalized_value": "example.test", "target_type": "Domain", "created_at": "t", "asset_id": "a-dom"},
    {"id": "t-tel", "workspace_id": "w", "original_value": "+1 202 555 0143", "normalized_value": "+12025550143", "target_type": "PhoneNumber", "created_at": "t", "asset_id": "a-tel"}
  ],
  "assets": [
    {"id": "a-dom", "workspace_id": "w", "asset_type": "Domain", "canonical_identity": "example.test", "display_value": "example.test", "metadata": {"in_scope": true}, "first_seen": "t", "last_seen": "t"},
    {"id": "a-api", "workspace_id": "w", "asset_type": "Subdomain", "canonical_identity": "api.example.test", "display_value": "api.example.test", "metadata": {"in_scope": true}, "first_seen": "t", "last_seen": "t"},
    {"id": "a-old", "workspace_id": "w", "asset_type": "Subdomain", "canonical_identity": "old.example.test", "display_value": "old.example.test", "metadata": {"in_scope": true}, "first_seen": "t", "last_seen": "t"},
    {"id": "a-tel", "workspace_id": "w", "asset_type": "PhoneNumber", "canonical_identity": "+12025550143", "display_value": "+12025550143", "metadata": {"in_scope": false}, "first_seen": "t", "last_seen": "t"}
  ],
  "relationships": [],
  "observations": [
    {"id": "o-sf", "workspace_id": "w", "asset_id": "a-api", "source_asset_id": "a-dom", "provider_run_id": "p-sf", "evidence_id": "e-sf", "discovered_by": "Subfinder", "observed_value": "api.example.test", "timestamp": "t", "confidence": "CONFIRMED", "metadata": {"tool": "subfinder"}},
    {"id": "o-sum", "workspace_id": "w", "asset_id": "a-dom", "source_asset_id": null, "provider_run_id": "p-ct", "evidence_id": "e-ct", "discovered_by": "Certificate Transparency (crt.sh)", "observed_value": "example.test", "timestamp": "t", "confidence": "REPORTED",
     "metadata": {"kind": "osint_run_summary", "provider": "native_ct", "subject": "example.test", "subject_kind": "domain", "historical": true, "partial": false,
                  "counts": {"hosts": 2, "emails": 0, "ips": 0, "nameservers": 0, "dropped_out_of_domain": 1, "dropped_invalid": 0, "dropped_over_limit": 0},
                  "note": "Certificate-transparency name: Historical; not proof."}},
    {"id": "o-api", "workspace_id": "w", "asset_id": "a-api", "source_asset_id": "a-dom", "provider_run_id": "p-ct", "evidence_id": "e-ct", "discovered_by": "Certificate Transparency (crt.sh)", "observed_value": "api.example.test", "timestamp": "t", "confidence": "REPORTED",
     "metadata": {"kind": "osint_domain_observation", "provider": "native_ct", "passive": true, "historical": true, "liveness": "unverified", "note": "n", "facts": {"certificates": 2, "wildcard": false}}},
    {"id": "o-old", "workspace_id": "w", "asset_id": "a-old", "source_asset_id": "a-dom", "provider_run_id": "p-ct", "evidence_id": "e-ct", "discovered_by": "Certificate Transparency (crt.sh)", "observed_value": "old.example.test", "timestamp": "t", "confidence": "REPORTED",
     "metadata": {"kind": "osint_domain_observation", "provider": "native_ct", "passive": true, "historical": true, "liveness": "unverified", "note": "n", "facts": {"all_certificates_expired": true}}},
    {"id": "o-tel", "workspace_id": "w", "asset_id": "a-tel", "source_asset_id": null, "provider_run_id": "p-tel", "evidence_id": "e-tel", "discovered_by": "PhoneInfoga", "observed_value": "+12025550143", "timestamp": "t", "confidence": "REPORTED",
     "metadata": {"kind": "osint_run_summary", "provider": "phoneinfoga", "subject": "+12025550143", "subject_kind": "phone", "partial": true,
                  "counts": {"sources_reported": 1, "source_errors": 1, "lines_malformed": 0},
                  "sources": {"local": {"country": "US", "e164": "+12025550143"}},
                  "errors": [{"source": "ovh", "reason": "country lookup failed"}], "identity_note": "Numbering metadata does not identify the subscriber."}}
  ],
  "chains": [
    {"id": "c-recon", "workspace_id": "w", "target_id": "t-dom", "name": "Domain Recon", "status": "COMPLETED", "created_at": "t", "updated_at": "t", "error_code": null},
    {"id": "c-ct", "workspace_id": "w", "target_id": "t-dom", "name": "Domain OSINT", "status": "COMPLETED", "created_at": "t", "updated_at": "t", "error_code": null},
    {"id": "c-tel", "workspace_id": "w", "target_id": "t-tel", "name": "Phone OSINT", "status": "PARTIAL", "created_at": "t", "updated_at": "t", "error_code": null}
  ],
  "stages": [],
  "tasks": [],
  "provider_runs": [
    {"id": "p-sf", "workspace_id": "w", "chain_id": "c-recon", "stage_id": "s", "provider_id": "subfinder", "provider_version": "2.6.6", "target": "example.test", "start_time": "t", "end_time": "t", "status": "COMPLETED", "raw_output_reference": "e-sf", "exit_status": 0},
    {"id": "p-ct", "workspace_id": "w", "chain_id": "c-ct", "stage_id": "s", "provider_id": "native_ct", "provider_version": "core 0.1.0", "target": "example.test", "start_time": "t", "end_time": "t", "status": "COMPLETED", "raw_output_reference": "e-ct", "exit_status": 0},
    {"id": "p-tel", "workspace_id": "w", "chain_id": "c-tel", "stage_id": "s", "provider_id": "phoneinfoga", "provider_version": "2.11.0", "target": "+12025550143", "start_time": "t", "end_time": "t", "status": "COMPLETED", "raw_output_reference": "e-tel", "exit_status": 0}
  ],
  "evidence": [],
  "events": [],
  "last_sequence": 9
}
"""#

@Suite struct OSINTDomainPhonePresentationTests {
    func snapshot() throws -> Snapshot {
        try CoreCoding.decoder().decode(Snapshot.self, from: Data(domainSnapshotJSON.utf8))
    }

    @Test func testDomainRunShowsPassiveHistoricalObservationsAndReusesSubfinderData() throws {
        let snapshot = try snapshot()
        #expect(snapshot.osintChains.map(\.id) == ["c-tel", "c-ct"])
        let results = try #require(OSINTRunResults.make(snapshot: snapshot, chainId: "c-ct"))
        let summary = try #require(results.summary)
        #expect(summary.subjectKind == "domain" && summary.hosts == 2 && summary.droppedOutOfDomain == 1)
        #expect(summary.historical && summary.identityNote.contains("Historical"))
        #expect(results.accounts.isEmpty)
        #expect(results.domainResults.map(\.value) == ["api.example.test", "old.example.test"])
        let api = try #require(results.domainResults.first)
        #expect(api.assetType == "Subdomain" && api.historical && api.inScope == true)
        #expect(api.confidence == "REPORTED" && api.provider == "native_ct")
        // The earlier Subfinder observation of the same canonical asset is surfaced,
        // not re-collected.
        #expect(api.alsoObservedBy == ["Subfinder"])
        #expect(api.facts.contains(OSINTProfileField(key: "certificates", value: "2")))
        #expect(results.domainResults[1].facts == [OSINTProfileField(key: "all_certificates_expired", value: "true")])
    }

    @Test func testPhoneRunShowsNumberingFactsAndSourceErrors() throws {
        let results = try #require(OSINTRunResults.make(snapshot: try snapshot(), chainId: "c-tel"))
        #expect(results.state == .partial)
        let summary = try #require(results.summary)
        #expect(summary.subjectKind == "phone")
        #expect(summary.details.contains(OSINTProfileField(key: "local.country", value: "US")))
        #expect(summary.errors.first?.platform == "ovh")
        #expect(summary.identityNote.contains("does not identify"))
        #expect(results.domainResults.isEmpty && results.accounts.isEmpty)
    }

    @Test func testRegistrationFactsFlattenWithoutContacts() {
        let value: JSONValue = .object([
            "kind": .string("osint_run_summary"), "subject_kind": .string("domain"),
            "registration": .object([
                "found": .bool(true), "status": .array([.string("active"), .string("client hold")]),
                "registrar": .object(["name": .string("Example Registrar"), "iana_id": .string("9999")]),
                "events": .array([.object(["action": .string("registration"), "date": .string("2001-02-03")])]),
                "entity_roles": .object(["registrant": .number(1)]),
            ]),
        ])
        let summary = OSINTRunSummary(value)
        let keys = summary?.details.map(\.key) ?? []
        #expect(keys.contains("registration.registrar.name"))
        #expect(summary?.details.contains(OSINTProfileField(key: "registration.status", value: "active, client hold")) == true)
        #expect(summary?.details.contains(OSINTProfileField(key: "registration.events[0]", value: "registration · 2001-02-03")) == true)
        #expect(summary?.details.contains(OSINTProfileField(key: "registration.entity_roles.registrant", value: "1")) == true)
    }
}

/// Records chain starts/cancels; returns the OSINT snapshot.
actor OSINTAPI: CoreAPI {
    private(set) var started: [(target: String, chain: String, options: JSONValue)] = []
    private(set) var cancelled: [String] = []
    private(set) var addedTargets: [String] = []
    let providers: [ProviderStatus]
    init(providers: [ProviderStatus]) { self.providers = providers }
    func hello() async throws -> CoreHello { CoreHello(coreVersion: "0.1.0", protocolVersion: 1, offlineOnly: false) }
    func listWorkspaces() async throws -> [Workspace] { [try osintSnapshot().workspace] }
    func createWorkspace(name: String, scope: [String]) async throws -> Workspace { try osintSnapshot().workspace }
    func updateWorkspaceScope(workspace: String, scope: [String]) async throws -> Workspace { try osintSnapshot().workspace }
    func addTarget(workspace: String, value: String) async throws -> Target {
        addedTargets.append(value)
        return try osintSnapshot().targets[0]
    }
    func snapshot(workspace: String) async throws -> Snapshot { try osintSnapshot() }
    func events(workspace: String, after: Int64) async throws -> [CoreEvent] { [] }
    func startChain(workspace: String, target: String, chain: String, options: JSONValue) async throws -> ChainRun {
        started.append((target, chain, options))
        return ChainRun(id: "c1", workspaceId: workspace, targetId: target, name: "Username OSINT", status: "PENDING", createdAt: "t", updatedAt: "t", errorCode: nil)
    }
    func cancelChain(workspace: String, chain: String) async throws { cancelled.append(chain) }
    func readEvidence(workspace: String, evidence: String) async throws -> EvidenceContent { EvidenceContent(evidenceId: evidence, rawJson: "{}") }
    func listProviders() async throws -> [ProviderStatus] { providers }
    func targetScopeStatus(workspace: String, target: String) async throws -> ScopeStatus { ScopeStatus(authorized: false, requiredScopeEntry: nil) }
    func authorizeTarget(workspace: String, target: String) async throws -> AuthorizeResult {
        AuthorizeResult(workspace: try osintSnapshot().workspace, authorized: false, addedEntry: nil)
    }
}

@MainActor
@Suite struct OSINTWorkflowModelTests {
    @Test func testAddingTargetsNeverStartsOSINT() async {
        let api = OSINTAPI(providers: [osintProviderStatus()])
        let model = WorkspaceModel(client: api)
        await model.boot()
        _ = await model.addTarget(value: "@octo-synthetic")
        let started = await api.started
        let added = await api.addedTargets
        #expect(started.isEmpty)
        #expect(added == ["@octo-synthetic"])
    }

    @Test func testRunStartsTypedChainWithSelectedProviderAndCancelTargetsIt() async {
        let api = OSINTAPI(providers: [osintProviderStatus()])
        let model = WorkspaceModel(client: api)
        await model.boot()
        model.osintMode = .email
        #expect(model.osintTarget?.id == "t-mail")
        model.osintMode = .username
        #expect(model.osintTarget?.id == "t-user")
        #expect(model.effectiveOSINTProvider?.id == "user_scanner")
        #expect(model.osintRunBlocker == nil)
        await model.runOSINT()
        let started = await api.started
        #expect(started.count == 1)
        #expect(started.first?.chain == "username_osint")
        #expect(started.first?.target == "t-user")
        #expect(started.first?.options["provider_id"].string == "user_scanner")
        #expect(model.selectedOSINTChainId == "c1")
        #expect(model.section == .osint)
        #expect(model.osintResults?.accounts.count == 1)
        #expect(!model.isBusy)
        await model.cancelOSINT()
        let cancelled = await api.cancelled
        #expect(cancelled == ["c1"])
    }

    @Test func testMissingOrUnsupportedProviderBlocksRunWithGuidance() async {
        for state in ["MISSING", "UNSUPPORTED_VERSION"] {
            let api = OSINTAPI(providers: [osintProviderStatus(state: state, version: state == "MISSING" ? nil : "2.0.0")])
            let model = WorkspaceModel(client: api)
            await model.boot()
            #expect(model.osintRunBlocker?.contains("Provider Center") == true)
            await model.runOSINT()
            let started = await api.started
            #expect(started.isEmpty)
            #expect(model.errorMessage != nil)
        }
        let none = WorkspaceModel(client: OSINTAPI(providers: []))
        await none.boot()
        #expect(none.osintRunBlocker?.contains("No registered provider") == true)
    }

    @Test func testDomainModeStartsDomainOSINTWithTheSelectedPassiveProvider() async {
        let ct = ProviderStatus(
            id: "native_ct", name: "Certificate Transparency (crt.sh)", description: "", version: "built-in",
            capabilities: ["DOMAIN_OSINT"], supportedTargetTypes: ["Domain"], riskClass: "PASSIVE",
            networkActivity: "NETWORK", offline: false,
            installation: ProviderInstallation(state: "BUILT_IN", path: nil, version: nil, message: nil), setup: nil, install: nil)
        let api = OSINTAPI(providers: [osintProviderStatus(), ct])
        let model = WorkspaceModel(client: api)
        await model.boot()
        model.osintMode = .domain
        #expect(model.osintTarget?.id == "t-dom")
        #expect(model.osintProviders.map(\.id) == ["native_ct"])
        #expect(model.osintRunBlocker == nil)
        await model.runOSINT()
        let started = await api.started
        #expect(started.first?.chain == "domain_osint")
        #expect(started.first?.target == "t-dom")
        #expect(started.first?.options["provider_id"].string == "native_ct")
    }

    @Test func testRestoredWorkspaceSelectsLatestOSINTRun() async {
        let model = WorkspaceModel(client: OSINTAPI(providers: [osintProviderStatus()]))
        await model.boot()
        #expect(model.selectedOSINTChainId == "c1")
        #expect(model.osintResults?.summary?.positive == 4)
    }
}
