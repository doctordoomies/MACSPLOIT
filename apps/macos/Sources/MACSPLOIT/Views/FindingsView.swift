import AppKit
import SwiftUI
import MACSPLOITKit

/// The Findings workbench: a master/detail view of durable analyst Findings. Everything
/// shown comes from durable core state. Findings reference assets/evidence; they are
/// never created automatically — the analyst writes the security conclusion. When created
/// from existing context (a result, a selection, a run, or an asset), the core builds a
/// deterministic draft and the editor opens already populated; the analyst reviews or
/// changes anything and presses Create. No separate Edit step is required.
struct FindingsView: View {
    @ObservedObject var model: WorkspaceModel
    @State private var editor: EditorContext?
    @State private var fromResult: FromResultContext?
    @State private var requestedContext: FindingDraftContext?
    @State private var statusNote = ""
    @State private var pendingStatus: FindingStatus?
    @State private var draftError: String?
    @StateObject private var draftLoader = FindingDraftLoader()

    var body: some View {
        WorkbenchPage(maxWidth: 1200) {
            VStack(alignment: .leading, spacing: 18) {
                HStack(alignment: .firstTextBaseline) {
                    PageHeading(title: "Findings", subtitle: "Reviewable security conclusions drawn from evidence. A finding references the assets and evidence it concerns — it is never a copy of a tool's output, and nothing creates one automatically.")
                    Spacer()
                    if draftLoader.isLoading { ProgressView().controlSize(.small).padding(.trailing, 6) }
                    Menu {
                        Button("Blank finding") { editor = EditorContext(new: NewFinding()) }
                        Button("From results…") { fromResult = FromResultContext() }
                    } label: { Label("New Finding", systemImage: "plus") }
                        .menuStyle(.borderlessButton).fixedSize()
                        .disabled(!model.isConnected || draftLoader.isLoading)
                }
                if model.findings.isEmpty {
                    EmptyMessage(title: "No findings yet",
                                 detail: "Create a finding manually, or open Recon/OSINT, select one or more results, and choose Create Finding — MACSPLOIT prefills the affected assets, evidence, and source, and the editor opens already filled in.",
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
        .task(id: model.pendingDraftContext) {
            if let context = model.pendingDraftContext {
                model.pendingDraftContext = nil
                await draftLoader.load(client: model.client, workspace: model.selectedWorkspaceId, context: context)
            }
        }
        .onChange(of: draftLoader.draft) { newDraft in
            if let newDraft { editor = EditorContext(draft: newDraft); draftLoader.clear() }
        }
        .onChange(of: draftLoader.errorMessage) { message in
            if let message { draftError = message; draftLoader.clear() }
        }
        .sheet(item: $editor) { ctx in FindingEditorView(model: model, context: ctx) }
        .onChange(of: model.selectedWorkspaceId) { _ in
            editor = nil; fromResult = nil; requestedContext = nil; pendingStatus = nil; draftError = nil
            draftLoader.clear()
        }
        .sheet(item: $fromResult, onDismiss: {
            // Route the picker's selection through the same shared draft path.
            if let context = requestedContext { requestedContext = nil; model.pendingDraftContext = context }
        }) { ctx in
            FromResultPicker(model: model, context: ctx) { context in
                requestedContext = context
                fromResult = nil
            }
        }
        .alert("Couldn't build a draft", isPresented: Binding(get: { draftError != nil }, set: { if !$0 { draftError = nil } })) {
            Button("New blank finding") { editor = EditorContext(new: NewFinding()) }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(draftError ?? "The selected context could not be drafted. Nothing was created.")
        }
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
        return "\(findingReferenceLabel(asset.canonicalIdentity)) · \(asset.assetType)"
    }
    private func evidenceLabel(_ id: String) -> String {
        guard let e = model.snapshot?.evidence.first(where: { $0.id == id }) else { return id }
        return "\(findingReferenceLabel(e.provider)) · \(findingReferenceLabel(e.target))"
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

/// Create (blank), create-from-draft, or edit context for the finding editor sheet.
struct EditorContext: Identifiable {
    let id = UUID()
    var new: NewFinding?
    var editing: Finding?
    var draft: FindingDraft?
    init(new: NewFinding) { self.new = new }
    init(editing: Finding) { self.editing = editing }
    init(draft: FindingDraft) { self.draft = draft }
}

private struct FindingEditorView: View {
    @ObservedObject var model: WorkspaceModel
    let context: EditorContext
    @Environment(\.dismiss) private var dismiss

    @State private var title = ""
    @State private var severity: FindingSeverity = .informational
    @State private var confidence: FindingConfidence = .low
    @State private var status: FindingStatus = .draft
    @State private var description = ""
    @State private var reproduction = ""
    @State private var remediation = ""
    @State private var tagsText = ""
    @State private var cveText = ""
    @State private var cweText = ""
    // Create-mode editable context (prefilled from the draft).
    @State private var affected: [DraftAsset] = []
    @State private var evidence: [DraftEvidence] = []
    @State private var sourceProvider: String?
    @State private var sourceRunId: String?
    @State private var provenance: [String] = []

    private var isEditing: Bool { context.editing != nil }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(isEditing ? "Edit Finding" : "New Finding").font(.title2.weight(.semibold)).padding(.bottom, 4)
            Text(isEditing ? "Edit your analyst-controlled fields. Status and source attribution are changed elsewhere."
                           : "Review the draft and change anything before creating. Prefilled assets, evidence, and source are facts from the selected context; you own the conclusion.")
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
                        affectedEditor
                        evidenceEditor
                        sourceAndProvenance
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
        .padding(24).frame(width: 660, height: 680)
        .onAppear(perform: load)
    }

    // MARK: Affected assets (create mode)

    private var affectedEditor: some View {
        field("Affected assets") {
            VStack(alignment: .leading, spacing: 4) {
                if affected.isEmpty {
                    Text("No affected asset selected. Add one so the finding references what it concerns.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                ForEach(affected) { asset in
                    HStack(spacing: 8) {
                        Button {
                            setPrimary(asset.assetId)
                        } label: {
                            Image(systemName: asset.isPrimary ? "star.fill" : "star")
                                .foregroundStyle(asset.isPrimary ? Color.accentColor : .secondary)
                        }
                        .buttonStyle(.plain)
                        .help(asset.isPrimary ? "Primary affected asset" : "Make primary")
                        Text("\(findingReferenceLabel(asset.assetIdentity)) · \(asset.assetType)")
                            .font(.callout.monospaced()).lineLimit(1)
                        Spacer()
                        Button(role: .destructive) { removeAsset(asset.assetId) } label: { Image(systemName: "minus.circle") }
                            .buttonStyle(.plain).foregroundStyle(.secondary)
                    }
                }
                let addable = (model.snapshot?.assets ?? []).filter { a in !affected.contains { $0.assetId == a.id } }
                if !addable.isEmpty {
                    Menu("Add asset") {
                        ForEach(addable) { a in
                            Button("\(findingReferenceLabel(a.canonicalIdentity)) · \(a.assetType)") { addAsset(a.id) }
                        }
                    }.menuStyle(.borderlessButton).fixedSize().controlSize(.small)
                }
            }
        }
    }

    private var evidenceEditor: some View {
        field("Evidence") {
            VStack(alignment: .leading, spacing: 4) {
                if evidence.isEmpty {
                    Text("No evidence selected. Evidence is the proof the finding references.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                ForEach(evidence) { item in
                    HStack(spacing: 8) {
                        Image(systemName: "doc.text.magnifyingglass").foregroundStyle(.secondary)
                        Text(findingReferenceLabel(item.label)).font(.caption.monospaced()).lineLimit(1)
                        Spacer()
                        Button(role: .destructive) { evidence.removeAll { $0.evidenceId == item.evidenceId } } label: { Image(systemName: "minus.circle") }
                            .buttonStyle(.plain).foregroundStyle(.secondary)
                    }
                }
                let addable = (model.snapshot?.evidence ?? []).filter { e in !evidence.contains { $0.evidenceId == e.id } }
                if !addable.isEmpty {
                    Menu("Add evidence") {
                        ForEach(addable) { e in
                            Button("\(findingReferenceLabel(e.provider)) · \(findingReferenceLabel(e.target))") {
                                evidence.append(DraftEvidence(evidenceId: e.id, label: "\(e.provider) · \(e.target)"))
                            }
                        }
                    }.menuStyle(.borderlessButton).fixedSize().controlSize(.small)
                }
            }
        }
    }

    @ViewBuilder private var sourceAndProvenance: some View {
        if sourceProvider != nil || sourceRunId != nil || !provenance.isEmpty {
            VStack(alignment: .leading, spacing: 3) {
                if sourceProvider != nil || sourceRunId != nil {
                    HStack(spacing: 8) {
                        Image(systemName: "shippingbox").foregroundStyle(.secondary)
                        Text("Source: \(sourceProvider ?? "—")\(sourceRunId != nil ? " · from a provider run" : "")")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                ForEach(provenance, id: \.self) { note in
                    Text(findingReferenceLabel(note)).font(.caption2).foregroundStyle(.tertiary)
                }
            }
        }
    }

    private func setPrimary(_ id: String) {
        affected = affected.map { var a = $0; a.isPrimary = (a.assetId == id); return a }
    }
    private func addAsset(_ id: String) {
        guard let a = model.snapshot?.assets.first(where: { $0.id == id }), !affected.contains(where: { $0.assetId == id }) else { return }
        affected.append(DraftAsset(assetId: id, assetType: a.assetType, assetIdentity: a.canonicalIdentity, isPrimary: affected.isEmpty))
    }
    private func removeAsset(_ id: String) {
        let wasPrimary = affected.first(where: { $0.assetId == id })?.isPrimary ?? false
        affected.removeAll { $0.assetId == id }
        if wasPrimary, let first = affected.first { setPrimary(first.assetId) }
    }

    // MARK: Fields

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
        } else if let d = context.draft {
            title = d.title; severity = d.severity; confidence = d.confidence; status = d.suggestedStatus
            description = d.description; reproduction = d.reproduction; remediation = d.remediation
            affected = d.affectedAssets; evidence = d.evidence
            sourceProvider = d.sourceProvider; sourceRunId = d.sourceRunId; provenance = d.provenance
            tagsText = d.tags.joined(separator: ", "); cveText = d.cveIds.joined(separator: ", "); cweText = d.cweIds.joined(separator: ", ")
        } else if let n = context.new {
            title = n.title; severity = n.severity; confidence = n.confidence; status = n.status ?? .draft
            description = n.description; reproduction = n.reproduction; remediation = n.remediation
            affected = draftAssets(primary: n.primaryAssetId, additional: n.additionalAssetIds)
            evidence = n.evidenceIds.compactMap(draftEvidence(_:))
            sourceProvider = n.sourceProvider; sourceRunId = n.sourceRunId
            tagsText = n.tags.joined(separator: ", "); cveText = n.cveIds.joined(separator: ", "); cweText = n.cweIds.joined(separator: ", ")
        }
    }

    private func draftAssets(primary: String?, additional: [String]) -> [DraftAsset] {
        var ids: [String] = []
        if let primary { ids.append(primary) }
        for id in additional where !ids.contains(id) { ids.append(id) }
        return ids.compactMap { id in
            guard let a = model.snapshot?.assets.first(where: { $0.id == id }) else { return nil }
            return DraftAsset(assetId: id, assetType: a.assetType, assetIdentity: a.canonicalIdentity, isPrimary: id == primary)
        }
    }
    private func draftEvidence(_ id: String) -> DraftEvidence? {
        guard let e = model.snapshot?.evidence.first(where: { $0.id == id }) else { return nil }
        return DraftEvidence(evidenceId: id, label: "\(e.provider) · \(e.target)")
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
            var new = NewFinding()
            new.title = title; new.severity = severity; new.confidence = confidence; new.status = status
            new.description = description; new.reproduction = reproduction; new.remediation = remediation
            let primary = affected.first(where: \.isPrimary)?.assetId ?? affected.first?.assetId
            new.primaryAssetId = primary
            new.additionalAssetIds = affected.filter { $0.assetId != primary }.map(\.assetId)
            new.evidenceIds = evidence.map(\.evidenceId)
            new.sourceProvider = sourceProvider; new.sourceRunId = sourceRunId
            new.tags = list(tagsText); new.cveIds = list(cveText); new.cweIds = list(cweText)
            if await model.createFinding(new) != nil { dismiss() }
        }
    }
}

// MARK: Create from results (normalized projection)

struct FromResultContext: Identifiable {
    let id = UUID()
    var chainId: String?
}

/// Lets the analyst pick a completed run and select one or more normalized result items
/// to base a finding on. Each item carries durable references (asset/evidence/run/
/// provider) — the selection is handed to the core, which builds a deterministic draft.
/// Nothing here parses console text.
private struct FromResultPicker: View {
    @ObservedObject var model: WorkspaceModel
    let context: FromResultContext
    let onCreate: (FindingDraftContext) -> Void
    @Environment(\.dismiss) private var dismiss

    @State private var chainId: String?
    @State private var selected: Set<String> = []
    @State private var primaryAssetId: String?
    @StateObject private var loader = FindingResultLoader()
    private var selection: [String?] { [model.selectedWorkspaceId, chainId] }

    private var chains: [ChainRun] { (model.snapshot?.chains ?? []).reversed() }

    private var visibleItems: [ResultItem] {
        guard let projection = loader.projection,
              projection.workspaceId == model.selectedWorkspaceId, projection.chainId == chainId
        else { return [] }
        return projection.items
    }

    /// Distinct assets among the selected result items — the primary chooser's options.
    private var selectedAssets: [(id: String, label: String)] {
        var seen = Set<String>()
        var out: [(String, String)] = []
        for item in visibleItems where selected.contains(item.observationId) {
            if seen.insert(item.assetId).inserted {
                out.append((item.assetId, "\(findingReferenceLabel(item.assetIdentity)) · \(item.assetType)"))
            }
        }
        return out
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Create Finding from results").font(.title2.weight(.semibold))
            Text("Pick a run, then select the normalized results this finding concerns. MACSPLOIT prefills the affected assets, supporting evidence, and source, and builds a draft — you write the conclusion.")
                .font(.callout).foregroundStyle(.secondary)
            Picker("Run", selection: $chainId) {
                Text("Choose a run…").tag(String?.none)
                ForEach(chains) { c in Text("\(c.name) · \(displayTime(c.createdAt))").tag(Optional(c.id)) }
            }
            if loader.isLoading { ProgressView().controlSize(.small) }
            if let error = loader.errorMessage {
                Text(error).font(.callout).foregroundStyle(.secondary)
                Button("Retry") { Task { await loadProjection() } }
            }
            if loader.projection != nil {
                if visibleItems.isEmpty {
                    Text("This run produced no normalized results to base a finding on.").font(.callout).foregroundStyle(.secondary)
                } else {
                    resultList
                    if !selectedAssets.isEmpty {
                        Picker("Primary asset", selection: $primaryAssetId) {
                            Text("Choose automatically").tag(String?.none)
                            ForEach(selectedAssets, id: \.id) { asset in Text(asset.label).tag(Optional(asset.id)) }
                        }
                    }
                }
            }
            HStack {
                Button(selected.isEmpty ? "Select results above" : "Create Finding (\(selected.count))") { createFromSelection() }
                    .buttonStyle(.borderedProminent).disabled(selected.isEmpty)
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
            }
        }
        .padding(24).frame(width: 640, height: 560)
        .onAppear { chainId = context.chainId }
        .task(id: selection) { await loadProjection() }
        .onChange(of: selection) { _ in selected = []; primaryAssetId = nil }
        .onDisappear { loader.clear() }
    }

    private var resultList: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 4) {
                ForEach(visibleItems) { item in
                    let isOn = selected.contains(item.observationId)
                    Button { toggle(item.observationId) } label: {
                        HStack(spacing: 8) {
                            Image(systemName: isOn ? "checkmark.square.fill" : "square").foregroundStyle(isOn ? Color.accentColor : .secondary)
                            Text(item.assetType).font(.caption.monospaced()).foregroundStyle(.secondary).frame(width: 90, alignment: .leading)
                            Text(findingReferenceLabel(item.assetIdentity)).font(.callout.monospaced()).lineLimit(1)
                            Spacer()
                            Text(findingReferenceLabel(item.discoveredBy)).font(.caption2).foregroundStyle(.secondary)
                            if item.evidenceId != nil { Image(systemName: "doc.text.magnifyingglass").foregroundStyle(.secondary) }
                        }
                        .padding(7).frame(maxWidth: .infinity, alignment: .leading)
                        .background((isOn ? Color.accentColor.opacity(0.12) : Color.primary.opacity(0.04)), in: RoundedRectangle(cornerRadius: 6))
                    }.buttonStyle(.plain)
                }
            }
        }.frame(maxHeight: 280)
    }

    private func toggle(_ id: String) {
        if selected.contains(id) { selected.remove(id) } else { selected.insert(id) }
        // Drop a primary choice that is no longer among the selected assets.
        if let primary = primaryAssetId, !selectedAssets.contains(where: { $0.id == primary }) { primaryAssetId = nil }
    }

    private func createFromSelection() {
        guard !selected.isEmpty, let chainId else { return }
        // Preserve the on-screen order of the selected results.
        let orderedObservations = visibleItems.map(\.observationId).filter { selected.contains($0) }
        onCreate(FindingDraftContext(runId: chainId, observationIds: orderedObservations, primaryAssetId: primaryAssetId))
    }

    private func loadProjection() async {
        guard let workspace = model.selectedWorkspaceId, let chainId else { loader.clear(); return }
        await loader.load(client: model.client, workspace: workspace, chain: chainId)
    }
}
