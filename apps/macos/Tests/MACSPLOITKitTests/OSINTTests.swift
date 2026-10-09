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
        riskClass: "ACTIVE_LOW_IMPACT", offline: false,
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
        #expect(OSINTMode.mode(forTargetType: "Domain") == nil)
        let unrelated = ProviderStatus(
            id: "nmap", name: "Nmap", description: "", version: "external", capabilities: ["PORT_DISCOVERY"],
            supportedTargetTypes: ["IPAddress"], riskClass: "ACTIVE", offline: false,
            installation: ProviderInstallation(state: "INSTALLED", path: nil, version: "7.95", message: nil), setup: nil, install: nil)
        #expect(OSINTMode.username.compatibleProviders([unrelated, osintProviderStatus()]).map(\.id) == ["user_scanner"])
        #expect(providerLabel("USERNAME_OSINT") == "Username OSINT")
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

    @Test func testRestoredWorkspaceSelectsLatestOSINTRun() async {
        let model = WorkspaceModel(client: OSINTAPI(providers: [osintProviderStatus()]))
        await model.boot()
        #expect(model.selectedOSINTChainId == "c1")
        #expect(model.osintResults?.summary?.positive == 4)
    }
}
