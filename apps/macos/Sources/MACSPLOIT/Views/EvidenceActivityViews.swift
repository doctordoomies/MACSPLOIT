import SwiftUI
import MACSPLOITKit

struct EvidenceView: View {
    @ObservedObject var model: WorkspaceModel
    private var selected: Evidence? { model.snapshot?.evidence.first { $0.id == model.selectedEvidenceId } }
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            PageHeading(title: "Evidence", subtitle: "Original provider JSON, stored separately from assets and verified by SHA-256 when opened.").padding(24)
            if model.snapshot?.evidence.isEmpty != false {
                EmptyMessage(title: "No evidence yet", detail: "Run Synthetic Recon to capture the provider's original structured output.", symbol: "doc.text.magnifyingglass")
            } else {
                HSplitView {
                    List(selection: $model.selectedEvidenceId) {
                        ForEach(model.snapshot?.evidence ?? []) { evidence in
                            VStack(alignment: .leading, spacing: 6) {
                                Text(evidence.provider).font(.callout.weight(.medium))
                                Text(evidence.target).font(.caption)
                                Text(displayTime(evidence.timestamp)).font(.caption2).foregroundStyle(.secondary)
                                Text("\(evidence.mediaType) · \(evidence.byteCount) bytes").font(.caption2).foregroundStyle(.secondary)
                                Text(String(evidence.sha256.prefix(16)) + "…").font(.caption2.monospaced()).foregroundStyle(.secondary)
                            }.padding(.vertical, 6).tag(evidence.id)
                        }
                    }.frame(minWidth: 245, idealWidth: 290, maxWidth: 350)
                    if let selected {
                        VStack(alignment: .leading, spacing: 12) {
                            Text("Verified raw evidence").font(.headline)
                            Text("SHA-256").font(.caption).foregroundStyle(.secondary)
                            Text(selected.sha256).font(.caption.monospaced()).textSelection(.enabled)
                            Divider()
                            ScrollView([.vertical, .horizontal]) {
                                Text(model.evidenceText).font(.system(.body, design: .monospaced)).textSelection(.enabled)
                                    .frame(maxWidth: .infinity, alignment: .leading).padding(12)
                            }.background(Color.black.opacity(0.18), in: RoundedRectangle(cornerRadius: 7))
                        }.padding(20).frame(minWidth: 400)
                    } else {
                        EmptyMessage(title: "Select evidence", detail: "The Rust core verifies the stored hash before returning the raw JSON.", symbol: "doc.text")
                    }
                }
            }
        }.task(id: model.selectedEvidenceId) { await model.loadEvidence() }
    }
}

struct ActivityView: View {
    @ObservedObject var model: WorkspaceModel
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            PageHeading(title: "Activity", subtitle: "Durable Rust events in sequence order. Showing the most recent 1,000 events.").padding(24)
            ScrollViewReader { proxy in
                List(model.snapshot?.events ?? []) { event in
                    DisclosureGroup {
                        Text(event.payload.pretty).font(.caption.monospaced()).textSelection(.enabled).padding(.vertical, 8)
                    } label: {
                        HStack(alignment: .firstTextBaseline, spacing: 16) {
                            Text("#\(event.sequence)").font(.caption.monospaced()).foregroundStyle(.tertiary).frame(width: 46, alignment: .trailing)
                            Text(displayTime(event.timestamp)).font(.caption.monospaced()).foregroundStyle(.secondary).frame(width: 195, alignment: .leading)
                            Text(event.summary).font(.callout)
                            Spacer()
                        }.padding(.vertical, 5)
                    }.id(event.id)
                }.onChange(of: model.snapshot?.lastSequence) { _ in
                    if let last = model.snapshot?.events.last { proxy.scrollTo(last.id, anchor: .bottom) }
                }.onAppear { if let last = model.snapshot?.events.last { proxy.scrollTo(last.id, anchor: .bottom) } }
            }
        }
    }
}
