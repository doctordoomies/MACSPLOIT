import Foundation
import Testing
@testable import MACSPLOITKit

@MainActor
@Suite struct FindingsModelTests {
    /// A snapshot carrying one finding, decoded through the real protocol decoder.
    let snapshotJSON = #"""
    {
      "workspace": {"id":"w","name":"W","created_at":"t","updated_at":"t","scope":["example.test"]},
      "targets": [], "assets": [
        {"id":"a-web","workspace_id":"w","asset_type":"Website","canonical_identity":"https://example.test/","display_value":"https://example.test/","metadata":{},"first_seen":"t","last_seen":"t"}
      ],
      "relationships": [], "observations": [],
      "chains": [], "stages": [], "tasks": [], "provider_runs": [],
      "evidence": [
        {"id":"e1","workspace_id":"w","provider_run_id":"p","provider":"native_http","target":"https://example.test/","timestamp":"t","sha256":"aa","media_type":"application/json","relative_path":"evidence/e1.json","byte_count":10}
      ],
      "events": [], "last_sequence": 1,
      "findings": [
        {"id":"f1","workspace_id":"w","title":"Expired TLS certificate","severity":"MEDIUM","confidence":"HIGH","status":"OPEN",
         "description":"The certificate is expired.","reproduction":"Inspect validity dates.","remediation":"Reissue the certificate.",
         "source_provider":"native_http","source_run_id":"p","tags":["tls"],"cwe_ids":["CWE-295"],"cve_ids":[],
         "affected_assets":[{"asset_id":"a-web","is_primary":true}],"evidence_ids":["e1"],
         "created_by":"Analyst","created_at":"t1","updated_at":"t2",
         "history":[
           {"id":"h1","kind":"CREATED","from_value":null,"to_value":"OPEN","note":"Finding created.","actor":"Analyst","timestamp":"t1"},
           {"id":"h2","kind":"STATUS","from_value":"OPEN","to_value":"CONFIRMED","note":"Verified.","actor":"Analyst","timestamp":"t2"}
         ]}
      ]
    }
    """#

    @Test func testFindingDecodesWithTypedDimensionsAndReferences() throws {
        let snapshot = try CoreCoding.decoder().decode(Snapshot.self, from: Data(snapshotJSON.utf8))
        let finding = try #require(snapshot.findingsNewestFirst.first)
        // Three independent typed dimensions.
        #expect(finding.severity == .medium)
        #expect(finding.confidence == .high)
        #expect(finding.status == .open)
        // Durable references, not console text.
        #expect(finding.primaryAssetId == "a-web")
        #expect(finding.evidenceIds == ["e1"])
        #expect(finding.sourceProvider == "native_http")
        #expect(finding.cweIds == ["CWE-295"])
        #expect(finding.history.count == 2)
        #expect(finding.history.first?.kind == "CREATED")
    }

    @Test func testOldCoreSnapshotWithoutFindingsDecodes() throws {
        // The `findings` key is absent from older cores; decoding must still succeed.
        let minimal = #"""
        {"workspace":{"id":"w","name":"W","created_at":"t","updated_at":"t","scope":[]},
         "targets":[],"assets":[],"relationships":[],"observations":[],"chains":[],"stages":[],
         "tasks":[],"provider_runs":[],"evidence":[],"events":[],"last_sequence":0}
        """#
        let snapshot = try CoreCoding.decoder().decode(Snapshot.self, from: Data(minimal.utf8))
        #expect(snapshot.findings == nil)
        #expect(snapshot.findingsNewestFirst.isEmpty)
    }

    @Test func testLifecycleTransitionsMirrorTheCore() {
        #expect(FindingStatus.open.allowedTransitions.contains(.confirmed))
        #expect(FindingStatus.open.allowedTransitions.contains(.falsePositive))
        #expect(FindingStatus.confirmed.allowedTransitions.contains(.resolved))
        #expect(FindingStatus.resolved.allowedTransitions.contains(.retestPassed))
        #expect(!FindingStatus.open.allowedTransitions.contains(.retestPassed))
        #expect(!FindingStatus.open.allowedTransitions.contains(.open))
        #expect(FindingStatus.initialChoices == [.draft, .open, .confirmed, .informational])
    }

    @Test func testSeverityOrdersFromInformationalToCritical() {
        #expect(FindingSeverity.critical > FindingSeverity.high)
        #expect(FindingSeverity.high > FindingSeverity.medium)
        #expect(FindingSeverity.low > FindingSeverity.informational)
    }

    @Test func testNewFindingEncodesToTheCoreSnakeCaseShape() throws {
        var draft = NewFinding()
        draft.title = "T"
        draft.severity = .high
        draft.primaryAssetId = "a-1"
        draft.evidenceIds = ["e-1"]
        draft.sourceRunId = "r-1"
        let json = JSONValue.encoding(draft)
        #expect(json["title"].string == "T")
        #expect(json["severity"].string == "HIGH")
        #expect(json["primary_asset_id"].string == "a-1")
        #expect(json["evidence_ids"].array.first?.string == "e-1")
        #expect(json["source_run_id"].string == "r-1")
    }

    @Test func testDraftFindingFromResultPrefillsOnlyFactualReferences() {
        let model = WorkspaceModel(client: CoreClient(transport: FailingTransport()))
        let item = ResultItem(
            kind: "ASSET_OBSERVATION", observationId: "o1", assetId: "a-web", assetType: "Website",
            assetIdentity: "https://example.test/", sourceAssetId: nil, runId: "r1", providerId: "native_http",
            discoveredBy: "Native HTTP", evidenceId: "e1", observedValue: "https://example.test/",
            confidence: "CONFIRMED", timestamp: "t")
        let draft = model.draftFinding(from: item)
        // Only facts are prefilled — never a title, severity, or conclusion.
        #expect(draft.primaryAssetId == "a-web")
        #expect(draft.evidenceIds == ["e1"])
        #expect(draft.sourceProvider == "native_http")
        #expect(draft.sourceRunId == "r1")
        #expect(draft.title.isEmpty)
        #expect(draft.severity == .informational)
    }
}

/// A transport that never succeeds — the model logic under test makes no calls.
private struct FailingTransport: CoreTransport {
    func exchange(_ request: Data) async throws -> Data {
        throw CoreFailure(code: "Unsupported", message: "no transport in this unit test")
    }
}
