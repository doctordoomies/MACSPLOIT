import SwiftUI
import MACSPLOITKit

struct AssetsView: View {
    @ObservedObject var model: WorkspaceModel
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            PageHeading(title: "Assets", subtitle: "Select a discovery to inspect its relationships, provenance, and evidence.").padding(24)
            HSplitView {
                Table(model.snapshot?.assets ?? [], selection: $model.selectedAssetId) {
                    TableColumn("Type", value: \.assetType).width(min: 75, ideal: 100)
                    TableColumn("Value", value: \.displayValue).width(min: 170, ideal: 250)
                    TableColumn("First seen") { Text(displayTime($0.firstSeen)).font(.caption) }.width(min: 100, ideal: 145)
                    TableColumn("Source") { Text(model.source(for: $0)).font(.caption) }.width(min: 100, ideal: 165)
                }.frame(minWidth: 420)
                if let asset = model.selectedAsset {
                    AssetInspector(model: model, asset: asset).frame(minWidth: 290, idealWidth: 330, maxWidth: 420)
                } else {
                    EmptyMessage(title: "Asset inspector", detail: "Choose an asset to see why it exists.", symbol: "sidebar.right")
                        .frame(minWidth: 290, idealWidth: 320, maxWidth: 400)
                }
            }
        }
    }
}

private struct AssetInspector: View {
    @ObservedObject var model: WorkspaceModel
    let asset: Asset
    private var relationships: [Relationship] {
        model.snapshot?.relationships.filter { $0.sourceAssetId == asset.id || $0.destinationAssetId == asset.id } ?? []
    }
    private var observations: [Observation] { model.snapshot?.observations.filter { $0.assetId == asset.id } ?? [] }
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                Text(asset.displayValue).font(.title3.weight(.semibold)).textSelection(.enabled)
                field("Type", asset.assetType)
                field("Canonical identity", asset.canonicalIdentity)
                field("First seen", displayTime(asset.firstSeen))
                field("Last seen", displayTime(asset.lastSeen))
                if asset.metadata["in_scope"].isFalse {
                    Label("Out of scope · not scheduled", systemImage: "hand.raised").font(.caption).foregroundStyle(.orange)
                }
                Divider()
                Text("Relationships").font(.headline)
                if relationships.isEmpty { Text("No relationships yet.").foregroundStyle(.secondary).font(.callout) }
                ForEach(relationships) { relation in
                    let outgoing = relation.sourceAssetId == asset.id
                    let other = outgoing ? relation.destinationAssetId : relation.sourceAssetId
                    VStack(alignment: .leading, spacing: 4) {
                        Text("\(outgoing ? "→" : "←") \(relation.relationshipType)").font(.caption).foregroundStyle(.secondary)
                        Button(model.assetName(other)) { model.selectedAssetId = other }.buttonStyle(.link)
                    }
                }
                Divider()
                Text("Provenance · \(observations.count) observations").font(.headline)
                ForEach(observations) { observation in
                    VStack(alignment: .leading, spacing: 6) {
                        Text(observation.discoveredBy).font(.callout.weight(.medium))
                        Text(observation.observedValue).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                        Text("\(displayTime(observation.timestamp)) · confidence \(observation.confidence)").font(.caption2).foregroundStyle(.secondary)
                        if let source = observation.sourceAssetId { Text("Source: \(model.assetName(source))").font(.caption) }
                        if let evidence = observation.evidenceId {
                            Button("Open raw evidence") { model.showEvidence(evidence) }.buttonStyle(.link)
                        } else { Text("Analyst-provided target").font(.caption).foregroundStyle(.secondary) }
                        if let metadata = observation.metadata, metadata != .null {
                            DisclosureGroup("Run details") {
                                Text(metadata.pretty).font(.system(.caption2, design: .monospaced)).textSelection(.enabled)
                                    .frame(maxWidth: .infinity, alignment: .leading).padding(.top, 4)
                            }.font(.caption)
                        }
                    }.padding(10).frame(maxWidth: .infinity, alignment: .leading)
                        .background(Color.primary.opacity(0.04), in: RoundedRectangle(cornerRadius: 7))
                }
                DisclosureGroup("Metadata") {
                    Text(asset.metadata.pretty).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading).padding(.top, 8)
                }
            }.padding(20).frame(maxWidth: .infinity, alignment: .leading)
        }
    }
    private func field(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            Text(value).font(.callout).textSelection(.enabled)
        }
    }
}
