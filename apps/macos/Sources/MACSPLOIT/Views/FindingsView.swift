import AppKit
import SwiftUI
import MACSPLOITKit

/// The Findings workbench: a master/detail view of durable analyst Findings. Everything
/// shown comes from durable core state. Findings reference assets/evidence; they are
/// never created automatically — the analyst writes the security conclusion. Creating a
/// finding from a result prefills only factual references (asset/evidence/source).
struct FindingsView: View {
    @ObservedObject var model: WorkspaceModel
    @State private var editor: EditorContext?
    @State private var fromResult: FromResultContext?
    @State private var statusNote = ""
    @State private var pendingStatus: FindingStatus?

    var body: some View {
        WorkbenchPage(maxWidth: 1200) {
            VStack(alignment: .leading, spacing: 18) {
                HStack(alignment: .firstTextBaseline) {
                    PageHeading(title: "Findings", subtitle: "Reviewable security conclusions drawn from evidence. A finding references the assets and evidence it concerns — it is never a copy of a tool's output, and nothing creates one automatically.")
                    Spacer()
                    Menu {
                        Button("Blank finding") { editor = EditorContext(new: NewFinding()) }
                        Button("From a result…") { fromResult = FromResultContext() }
                    } label: { Label("New Finding", systemImage: "plus") }
                        .menuStyle(.borderlessButton).fixedSize()
                        .disabled(!model.isConnected)
                }
                if model.findings.isEmpty {
                    EmptyMessage(title: "No findings yet",
                                 detail: "Create a finding manually, or open Recon/OSINT, select a result, and choose Create Finding — the affected asset and evidence are referenced for you.",
                                 symbol: "exclamationmark.shield")
                } else {
                    HStack(alignment: .top, spacing: 16) {
                        masterList.frame(width: 320)
                        Divider()
                        detail.frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
            }
        }
        .task(id: model.pendingFindingDraft) {
            if let draft = model.pendingFindingDraft {
                editor = EditorContext(new: draft)
                model.pendingFindingDraft = nil
            }
        }
        .task(id: model.pendingFindingChainId) {
            if let chain = model.pendingFindingChainId {
                fromResult = FromResultContext(chainId: chain)
                model.pendingFindingChainId = nil
            }
        }
        .sheet(item: $editor) { ctx in FindingEditorView(model: model, context: ctx) }
        .sheet(item: $fromResult) { ctx in FromResultPicker(model: model, context: ctx) { item in
            editor = EditorContext(new: model.draftFinding(from: item))
        } }
    }

    // MARK: Master

    private var grouped: [(FindingStatus, [Finding])] {
        let order: [FindingStatus] = [.open, .confirmed, .draft, .informational, .retestPassed, .resolved, .falsePositive]
        return order.compactMap { status in
            let items = model.findings.filter { $0.status == status }
            return items.isEmpty ? nil : (status, items)
        }
    }

    private var masterList: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                ForEach(grouped, id: \.0) { status, items in
                    VStack(alignment: .leading, spacing: 4) {
                        Text("\(status.label.uppercased()) · \(items.count)").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                        ForEach(items) { finding in masterRow(finding) }
                    }
                }
            }
        }
    }

    private func masterRow(_ finding: Finding) -> some View {
        let selected = model.selectedFinding?.id == finding.id
        return Button { model.selectedFindingId = finding.id } label: {
            HStack(spacing: 8) {
                SeverityTag(finding.severity)
                Text(finding.title).lineLimit(2).frame(maxWidth: .infinity, alignment: .leading)
            }
            .padding(8)
            .background(selected ? Color.accentColor.opacity(0.15) : Color.primary.opacity(0.04),
                        in: RoundedRectangle(cornerRadius: 7))
        }
        .buttonStyle(.plain)
    }

    // MARK: Detail

    @ViewBuilder private var detail: some View {
        if let finding = model.selectedFinding {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    Text(finding.title).font(.title3.weight(.semibold)).textSelection(.enabled)
                    dimensionRow(finding)
                    sourceRow(finding)
                    affectedRow(finding)
                    section("Description", finding.description)
                    section("Reproduction / verification", finding.reproduction)
                    section("Remediation", finding.remediation)
                    identifiersRow(finding)
                    evidenceSection(finding)
                    historySection(finding)
                    actions(finding)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            Text("Select a finding.").foregroundStyle(.secondary)
        }
    }

    private func dimensionRow(_ finding: Finding) -> some View {
        HStack(spacing: 20) {
            labelled("Status") { StatusTag(finding.status) }
            labelled("Severity") { SeverityTag(finding.severity) }
            labelled("Confidence") { Text(finding.confidence.label).font(.callout.weight(.medium)) }
        }
    }

    @ViewBuilder private func sourceRow(_ finding: Finding) -> some View {
        if finding.sourceProvider != nil || finding.sourceRunId != nil {
            HStack(spacing: 8) {
                Image(systemName: "shippingbox").foregroundStyle(.secondary)
                Text("Source: \(finding.sourceProvider ?? "—")")
                    .font(.caption).foregroundStyle(.secondary)
                if finding.sourceRunId != nil { Text("· from a provider run").font(.caption).foregroundStyle(.tertiary) }
            }
            .help("Immutable provenance from the result this finding was created from. Distinct from your written conclusion.")
        }
    }

    @ViewBuilder private func affectedRow(_ finding: Finding) -> some View {
        if !finding.affectedAssets.isEmpty {
            VStack(alignment: .leading, spacing: 3) {
                Text("Affected").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                ForEach(finding.affectedAssets) { link in
                    HStack(spacing: 8) {
                        if link.isPrimary { Text("primary").font(.caption2).padding(.horizontal, 5).padding(.vertical, 1).background(Color.accentColor.opacity(0.15), in: Capsule()) }
                        Text(assetLabel(link.assetId)).font(.callout.monospaced()).textSelection(.enabled)
                        Button("Asset") { model.selectedAssetId = link.assetId; model.section = .assets }.buttonStyle(.link)
                    }
                }
            }
        }
    }

    @ViewBuilder private func section(_ title: String, _ body: String) -> some View {
        if !body.isEmpty {
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                Text(body).font(.callout).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    @ViewBuilder private func identifiersRow(_ finding: Finding) -> some View {
        let chips = finding.cveIds + finding.cweIds + finding.tags
        if !chips.isEmpty {
            HStack {
                ForEach(chips, id: \.self) { chip in
                    Text(chip).font(.caption2.monospaced()).padding(.horizontal, 6).padding(.vertical, 2)
                        .background(Color.gray.opacity(0.16), in: Capsule())
                }
            }
        }
    }

    @ViewBuilder private func evidenceSection(_ finding: Finding) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text("Evidence · \(finding.evidenceIds.count)").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                Spacer()
                let linkable = (model.snapshot?.evidence ?? []).filter { !finding.evidenceIds.contains($0.id) }
                if !linkable.isEmpty {
                    Menu("Link evidence") {
                        ForEach(linkable) { e in
                            Button(evidenceLabel(e.id)) { Task { await model.linkFindingEvidence(finding.id, evidence: e.id) } }
                        }
                    }.menuStyle(.borderlessButton).fixedSize().controlSize(.small)
                }
            }
            if finding.evidenceIds.isEmpty {
                Text("No evidence linked. Evidence is the proof; the text above is your conclusion.").font(.caption).foregroundStyle(.secondary)
            }
            ForEach(finding.evidenceIds, id: \.self) { evidence in
                HStack(spacing: 8) {
                    Image(systemName: "doc.text.magnifyingglass").foregroundStyle(.secondary)
                    Text(evidenceLabel(evidence)).font(.caption.monospaced()).textSelection(.enabled)
                    Spacer()
                    Button("Open") { model.showEvidence(evidence) }.buttonStyle(.link)
                    Button("Unlink") { Task { await model.unlinkFindingEvidence(finding.id, evidence: evidence) } }.buttonStyle(.link)
                }
            }
        }
    }

    @ViewBuilder private func historySection(_ finding: Finding) -> some View {
        DisclosureGroup("History (\(finding.history.count))") {
            VStack(alignment: .leading, spacing: 2) {
                ForEach(finding.history) { h in
                    let change = [h.fromValue, h.toValue].compactMap { $0 }.joined(separator: " → ")
                    Text("\(displayTime(h.timestamp)) · \(h.kind)\(change.isEmpty ? "" : " · \(change)") · \(h.note)")
                        .font(.caption2).foregroundStyle(.secondary).textSelection(.enabled)
                }
            }.padding(.top, 3)
        }.font(.callout)
    }

    private func actions(_ finding: Finding) -> some View {
        HStack(spacing: 10) {
            Button("Edit") { editor = EditorContext(editing: finding) }
            Menu("Change status") {
                ForEach(finding.status.allowedTransitions) { next in
                    Button(next.label) { pendingStatus = next; statusNote = "" }
                }
            }.menuStyle(.borderlessButton).fixedSize()
                .disabled(finding.status.allowedTransitions.isEmpty)
            Spacer()
        }
        .padding(.top, 4)
        .sheet(item: $pendingStatus) { next in
            VStack(alignment: .leading, spacing: 14) {
                Text("Change status to \(next.label)").font(.title3.weight(.semibold))
                Text("Record why. The transition and note are appended to the finding's history.").foregroundStyle(.secondary)
                TextField("Review note", text: $statusNote)
                HStack {
                    Spacer()
                    Button("Cancel") { pendingStatus = nil }.keyboardShortcut(.cancelAction)
                    Button("Apply") {
                        let note = statusNote
                        Task { if await model.setFindingStatus(finding.id, to: next, note: note) { pendingStatus = nil } }
                    }
                    .buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)
                    .disabled(statusNote.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            }.padding(24).frame(width: 440)
        }
    }

    // MARK: Helpers

    private func labelled<V: View>(_ title: String, @ViewBuilder _ value: () -> V) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title.uppercased()).font(.caption2.weight(.semibold)).foregroundStyle(.secondary)
            value()
        }
    }
    private func assetLabel(_ id: String) -> String {
        guard let asset = model.snapshot?.assets.first(where: { $0.id == id }) else { return id }
        return "\(asset.canonicalIdentity) · \(asset.assetType)"
    }
    private func evidenceLabel(_ id: String) -> String {
        guard let e = model.snapshot?.evidence.first(where: { $0.id == id }) else { return id }
        return "\(e.provider) · \(e.target)"
    }
}

// MARK: Tags

private struct SeverityTag: View {
    let severity: FindingSeverity
    init(_ s: FindingSeverity) { severity = s }
    var body: some View {
        Text(severity.label).font(.caption2.weight(.semibold))
            .padding(.horizontal, 6).padding(.vertical, 2)
            .background(color.opacity(0.18), in: Capsule()).foregroundStyle(color)
    }
    private var color: Color {
        switch severity {
        case .critical: return .red
        case .high: return .orange
        case .medium: return .yellow
        case .low: return .blue
        case .informational: return .secondary
        }
    }
}

private struct StatusTag: View {
    let status: FindingStatus
    init(_ s: FindingStatus) { status = s }
    var body: some View {
        Text(status.label).font(.callout.weight(.medium))
    }
}

// MARK: Editor

/// Create (new) or edit (existing) context for the finding editor sheet.
struct EditorContext: Identifiable {
    let id = UUID()
    var new: NewFinding?
    var editing: Finding?
    init(new: NewFinding) { self.new = new }
    init(editing: Finding) { self.editing = editing }
}

private struct FindingEditorView: View {
    @ObservedObject var model: WorkspaceModel
    let context: EditorContext
    @Environment(\.dismiss) private var dismiss

    @State private var title = ""
    @State private var severity: FindingSeverity = .informational
    @State private var confidence: FindingConfidence = .low
    @State private var status: FindingStatus = .open
    @State private var description = ""
    @State private var reproduction = ""
    @State private var remediation = ""
    @State private var tagsText = ""
    @State private var cveText = ""
    @State private var cweText = ""
    @State private var primaryAssetId: String?

    private var isEditing: Bool { context.editing != nil }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(isEditing ? "Edit Finding" : "New Finding").font(.title2.weight(.semibold)).padding(.bottom, 4)
            Text(isEditing ? "Edit your analyst-controlled fields. Status and source attribution are changed elsewhere."
                           : "Record a security conclusion. Any prefilled asset/evidence/source references are facts from the result; you supply the conclusion.")
                .font(.callout).foregroundStyle(.secondary).padding(.bottom, 10)
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    field("Title") { TextField("Short, specific title", text: $title).textFieldStyle(.roundedBorder) }
                    HStack(spacing: 18) {
                        field("Severity") { Picker("", selection: $severity) { ForEach(FindingSeverity.allCases) { Text($0.label).tag($0) } }.labelsHidden() }
                        field("Confidence") { Picker("", selection: $confidence) { ForEach(FindingConfidence.allCases) { Text($0.label).tag($0) } }.labelsHidden() }
                        if !isEditing {
                            field("Status") { Picker("", selection: $status) { ForEach(FindingStatus.initialChoices) { Text($0.label).tag($0) } }.labelsHidden() }
                        }
                    }
                    if !isEditing {
                        field("Affected asset") {
                            Picker("", selection: $primaryAssetId) {
                                Text("None").tag(String?.none)
                                ForEach(model.snapshot?.assets ?? []) { asset in
                                    Text("\(asset.canonicalIdentity) · \(asset.assetType)").tag(Optional(asset.id))
                                }
                            }.labelsHidden()
                        }
                    }
                    field("Description") { editorBox($description) }
                    field("Reproduction / verification") { editorBox($reproduction) }
                    field("Remediation") { editorBox($remediation) }
                    HStack(spacing: 18) {
                        field("Tags (comma-separated)") { TextField("e.g. tls, auth", text: $tagsText).textFieldStyle(.roundedBorder) }
                        field("CVE ids") { TextField("CVE-2021-44228", text: $cveText).textFieldStyle(.roundedBorder) }
                        field("CWE ids") { TextField("CWE-295", text: $cweText).textFieldStyle(.roundedBorder) }
                    }
                }
            }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button(isEditing ? "Save" : "Create") { Task { await save() } }
                    .buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)
                    .disabled(title.trimmingCharacters(in: .whitespaces).isEmpty || model.isBusy)
            }.padding(.top, 10)
        }
        .padding(24).frame(width: 640, height: 640)
        .onAppear(perform: load)
    }

    private func field<V: View>(_ title: String, @ViewBuilder _ content: () -> V) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title).font(.caption.weight(.medium)).foregroundStyle(.secondary)
            content()
        }
    }
    private func editorBox(_ text: Binding<String>) -> some View {
        TextEditor(text: text).font(.body).frame(height: 70).padding(5)
            .overlay(RoundedRectangle(cornerRadius: 6).stroke(.quaternary))
    }

    private func load() {
        if let f = context.editing {
            title = f.title; severity = f.severity; confidence = f.confidence
            description = f.description; reproduction = f.reproduction; remediation = f.remediation
            tagsText = f.tags.joined(separator: ", "); cveText = f.cveIds.joined(separator: ", "); cweText = f.cweIds.joined(separator: ", ")
        } else if let n = context.new {
            title = n.title; severity = n.severity; confidence = n.confidence; status = n.status ?? .open
            description = n.description; reproduction = n.reproduction; remediation = n.remediation
            primaryAssetId = n.primaryAssetId
            tagsText = n.tags.joined(separator: ", "); cveText = n.cveIds.joined(separator: ", "); cweText = n.cweIds.joined(separator: ", ")
        }
    }

    private func list(_ text: String) -> [String] {
        text.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }

    private func save() async {
        if let editing = context.editing {
            var edit = FindingEdit()
            edit.title = title; edit.severity = severity; edit.confidence = confidence
            edit.description = description; edit.reproduction = reproduction; edit.remediation = remediation
            edit.tags = list(tagsText); edit.cveIds = list(cveText); edit.cweIds = list(cweText)
            if await model.updateFinding(editing.id, edit: edit) { dismiss() }
        } else {
            var new = context.new ?? NewFinding()
            new.title = title; new.severity = severity; new.confidence = confidence; new.status = status
            new.description = description; new.reproduction = reproduction; new.remediation = remediation
            new.tags = list(tagsText); new.cveIds = list(cveText); new.cweIds = list(cweText)
            new.primaryAssetId = primaryAssetId
            if await model.createFinding(new) != nil { dismiss() }
        }
    }
}

// MARK: Create from a result (normalized projection)

struct FromResultContext: Identifiable {
    let id = UUID()
    var chainId: String?
}

/// Lets the analyst pick a completed chain and then a normalized result item to base a
/// finding on. The item carries durable references (asset/evidence/run/provider) — the
/// prefill is never console text.
private struct FromResultPicker: View {
    @ObservedObject var model: WorkspaceModel
    let context: FromResultContext
    let onPick: (ResultItem) -> Void
    @Environment(\.dismiss) private var dismiss

    @State private var chainId: String?
    @State private var projection: ResultProjection?
    @State private var loading = false

    private var chains: [ChainRun] { (model.snapshot?.chains ?? []).reversed() }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Create Finding from a result").font(.title2.weight(.semibold))
            Text("Pick a run, then the normalized result its finding concerns. MACSPLOIT prefills the affected asset, supporting evidence, and source — you write the conclusion.")
                .font(.callout).foregroundStyle(.secondary)
            Picker("Run", selection: $chainId) {
                Text("Choose a run…").tag(String?.none)
                ForEach(chains) { c in Text("\(c.name) · \(displayTime(c.createdAt))").tag(Optional(c.id)) }
            }
            .onChange(of: chainId) { _ in Task { await loadProjection() } }
            if loading { ProgressView().controlSize(.small) }
            if let projection {
                if projection.items.isEmpty {
                    Text("This run produced no normalized results to base a finding on.").font(.callout).foregroundStyle(.secondary)
                } else {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 4) {
                            ForEach(projection.items) { item in
                                Button { onPick(item); dismiss() } label: {
                                    HStack(spacing: 8) {
                                        Text(item.assetType).font(.caption.monospaced()).foregroundStyle(.secondary).frame(width: 90, alignment: .leading)
                                        Text(item.assetIdentity).font(.callout.monospaced()).lineLimit(1)
                                        Spacer()
                                        Text(item.discoveredBy).font(.caption2).foregroundStyle(.secondary)
                                        if item.evidenceId != nil { Image(systemName: "doc.text.magnifyingglass").foregroundStyle(.secondary) }
                                    }
                                    .padding(7).frame(maxWidth: .infinity, alignment: .leading)
                                    .background(Color.primary.opacity(0.04), in: RoundedRectangle(cornerRadius: 6))
                                }.buttonStyle(.plain)
                            }
                        }
                    }.frame(maxHeight: 300)
                }
            }
            HStack { Spacer(); Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction) }
        }
        .padding(24).frame(width: 620, height: 520)
        .onAppear {
            chainId = context.chainId
            Task { await loadProjection() }
        }
    }

    private func loadProjection() async {
        guard let chainId else { projection = nil; return }
        loading = true
        projection = await model.resultProjection(chain: chainId)
        loading = false
    }
}
