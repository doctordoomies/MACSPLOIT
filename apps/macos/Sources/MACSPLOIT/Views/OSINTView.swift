import AppKit
import SwiftUI
import MACSPLOITKit

/// Dedicated OSINT workflow: explicit subject + provider selection, an explicit Run,
/// cancellation, run state, and access to discoveries and evidence. Everything shown
/// comes from durable core state; nothing here launches work implicitly.
struct OSINTView: View {
    @ObservedObject var model: WorkspaceModel
    @State private var consoleExpanded = false

    var body: some View {
        WorkbenchPage(maxWidth: 1200) {
            VStack(alignment: .leading, spacing: 22) {
                PageHeading(title: "OSINT", subtitle: "Public-source research on one explicitly selected username or email. One bounded scan per Run — nothing starts automatically.")
                Picker("Workflow", selection: $model.osintMode) {
                    ForEach(OSINTMode.allCases) { Label($0.rawValue, systemImage: $0.icon).tag($0) }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(maxWidth: 420)
                executionPanel
                if let results = model.osintResults {
                    resultsPanel(results)
                    console
                }
                history
            }
        }
    }

    // MARK: Execution

    private var running: Bool { model.osintResults?.state == .running }

    private var executionPanel: some View {
        WorkbenchCard {
            VStack(alignment: .leading, spacing: 16) {
                HStack(alignment: .firstTextBaseline) {
                    VStack(alignment: .leading, spacing: 3) {
                        Text(model.osintMode.rawValue).font(.title3.weight(.semibold))
                        Text(model.osintMode.purpose).font(.callout).foregroundStyle(.secondary)
                    }
                    Spacer()
                    RiskBadge(risk: "ACTIVE · LOW")
                }
                targetRow
                providerRow
                activityNote
                HStack(spacing: 12) {
                    Button { Task { await model.runOSINT() } } label: {
                        Label("Run \(model.osintMode.rawValue)", systemImage: "play.fill")
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(model.osintRunBlocker != nil || model.isBusy)
                    if running {
                        Button("Cancel") { Task { await model.cancelOSINT() } }
                    }
                    Spacer()
                }
                if let blocker = model.osintRunBlocker, !running {
                    Text(blocker).font(.callout).foregroundStyle(.orange).textSelection(.enabled)
                }
                HStack(alignment: .top, spacing: 8) {
                    Image(systemName: "exclamationmark.shield").foregroundStyle(.secondary)
                    Text("Use OSINT only for lawful, authorized research. Results are public-source provider claims: a matching username or email on several platforms does not prove the accounts belong to one person.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
        }
    }

    private var targetRow: some View {
        HStack(spacing: 12) {
            Text("Subject").font(.callout.weight(.medium)).frame(width: 90, alignment: .leading)
            if model.osintTargets.isEmpty {
                Text(model.osintMode.targetHint).font(.callout).foregroundStyle(.secondary)
            } else {
                Picker("Subject", selection: Binding(get: { model.osintTarget?.id }, set: { model.osintTargetId = $0 })) {
                    ForEach(model.osintTargets) { Text("\($0.normalizedValue)  ·  \($0.targetType)").tag(Optional($0.id)) }
                }
                .labelsHidden()
                .frame(maxWidth: 420)
            }
            Spacer()
        }
    }

    @ViewBuilder private var providerRow: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 12) {
                Text("Provider").font(.callout.weight(.medium)).frame(width: 90, alignment: .leading)
                if model.osintProviders.isEmpty {
                    Text("No registered provider supports this workflow.").font(.callout).foregroundStyle(.orange)
                } else {
                    Picker("Provider", selection: Binding(get: { model.effectiveOSINTProvider?.id }, set: { model.osintProviderId = $0 })) {
                        ForEach(model.osintProviders) { Text($0.name).tag(Optional($0.id)) }
                    }
                    .labelsHidden()
                    .frame(maxWidth: 220)
                }
                if let provider = model.effectiveOSINTProvider {
                    Image(systemName: provider.installation.isAvailable ? "checkmark.seal.fill" : "exclamationmark.triangle.fill")
                        .foregroundStyle(provider.installation.isAvailable ? Color.green : Color.orange)
                    Text(provider.installation.summary).font(.caption.monospaced())
                        .foregroundStyle(provider.installation.isAvailable ? Color.secondary : Color.orange)
                }
                Spacer()
                Button { Task { await model.refreshProviders() } } label: { Label("Refresh", systemImage: "arrow.clockwise") }
                    .controlSize(.small).disabled(model.isRefreshingProviders)
                Button("Provider Center") { model.section = .toolManager }.controlSize(.small)
            }
            if let provider = model.effectiveOSINTProvider, !provider.installation.isAvailable,
               let command = provider.setup?.installCommand {
                HStack(spacing: 8) {
                    Text("Install it yourself, then Refresh:").font(.caption).foregroundStyle(.secondary)
                    Text(command).font(.caption.monospaced()).textSelection(.enabled)
                    Button("Copy") { copy(command) }.controlSize(.small)
                }
                .padding(.leading, 102)
            }
        }
    }

    private var activityNote: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "network").foregroundStyle(.secondary)
            Text("Sends ordinary requests to third-party public platforms — never to the subject's own systems — so workspace host scope does not apply to an identifier. Modules that can notify the subject, recursive cross-scanning, breach/infostealer lookups, and proxies are disabled. Runs are bounded (concurrency, request timeout, 15-minute limit) and cancellable.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }
    }

    // MARK: Results

    @ViewBuilder private func resultsPanel(_ results: OSINTRunResults) -> some View {
        WorkbenchCard {
            VStack(alignment: .leading, spacing: 14) {
                HStack {
                    Text(results.chain.name).font(.headline)
                    if let run = results.providerRun {
                        Text("\(run.target) · \(run.providerId) \(run.providerVersion)").font(.caption.monospaced()).foregroundStyle(.secondary)
                    }
                    Spacer()
                    StatusBadge(status: results.chain.status)
                }
                HStack(spacing: 8) {
                    if results.state == .running { ProgressView().controlSize(.small) }
                    VStack(alignment: .leading, spacing: 2) {
                        Text(results.state.title).font(.callout.weight(.medium))
                        Text(results.state.detail).font(.caption).foregroundStyle(.secondary)
                        Text("Started \(displayTime(results.chain.createdAt))").font(.caption2).foregroundStyle(.tertiary)
                    }
                }
                stageList(results.stages)
                if let summary = results.summary { summaryView(summary) }
                accountList(results)
                HStack {
                    Spacer()
                    Button("View assets") { model.section = .assets }.controlSize(.small)
                    Button("View evidence") {
                        if let evidence = results.evidence.first { model.showEvidence(evidence.id) } else { model.section = .evidence }
                    }
                    .controlSize(.small)
                    Button("View activity") { model.section = .activity }.controlSize(.small)
                }
            }
        }
    }

    private func stageList(_ stages: [ChainStage]) -> some View {
        HStack(spacing: 14) {
            ForEach(stages) { stage in
                HStack(spacing: 5) {
                    stageSymbol(stage.status)
                    Text(stage.name).font(.caption)
                }
            }
        }
    }

    @ViewBuilder private func stageSymbol(_ status: String) -> some View {
        if status == "RUNNING" { ProgressView().controlSize(.mini) }
        else if status == "COMPLETED" { Image(systemName: "checkmark.circle.fill").foregroundStyle(.green) }
        else if ["FAILED", "CANCELLED"].contains(status) { Image(systemName: "xmark.circle").foregroundStyle(.orange) }
        else { Image(systemName: "circle").foregroundStyle(.tertiary) }
    }

    @ViewBuilder private func summaryView(_ summary: OSINTRunSummary) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 120), spacing: 10)], spacing: 10) {
                countTile("Reported", summary.positive, "checkmark.circle", .green)
                countTile("Not found", summary.negative, "minus.circle", .secondary)
                countTile("Blocked by policy", summary.blocked, "hand.raised", .secondary)
                countTile("Errors", summary.error, "exclamationmark.triangle", .orange)
                countTile("Unknown", summary.unknown, "questionmark.circle", .orange)
                countTile("Checked", summary.checked, "list.bullet", .secondary)
            }
            if summary.duplicates + summary.urlsRejected + summary.dropped + summary.malformed + summary.mismatched + summary.positiveOverLimit > 0 {
                Text("Safety bounds: \(summary.duplicates) duplicate, \(summary.urlsRejected) invalid URL, \(summary.malformed) malformed, \(summary.mismatched) other-identifier, \(summary.dropped) over record limit, \(summary.positiveOverLimit) over account limit.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            if !summary.identityNote.isEmpty {
                Label(summary.identityNote, systemImage: "person.2.slash").font(.caption).foregroundStyle(.secondary)
            }
            if !summary.errors.isEmpty { noteList("Errors (\(summary.error))", summary.errors) }
            if !summary.blockedChecks.isEmpty { noteList("Blocked by policy (\(summary.blocked))", summary.blockedChecks) }
            if !summary.unknownChecks.isEmpty { noteList("Unknown status (\(summary.unknown))", summary.unknownChecks) }
        }
    }

    private func countTile(_ name: String, _ value: Int, _ symbol: String, _ color: Color) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Label(name, systemImage: symbol).font(.caption).foregroundStyle(color)
            Text(value.formatted()).font(.title3.weight(.semibold).monospacedDigit())
        }
        .padding(10).frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.primary.opacity(0.04), in: RoundedRectangle(cornerRadius: 8))
    }

    private func noteList(_ title: String, _ notes: [OSINTCheckNote]) -> some View {
        DisclosureGroup(title) {
            VStack(alignment: .leading, spacing: 4) {
                ForEach(notes) { note in
                    HStack(alignment: .top, spacing: 8) {
                        Text(note.platform).font(.caption.weight(.medium)).frame(width: 150, alignment: .leading)
                        Text(note.reason ?? note.upstreamStatus).font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                    }
                }
            }.padding(.top, 4)
        }
        .font(.callout)
    }

    @ViewBuilder private func accountList(_ results: OSINTRunResults) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Reported accounts · \(results.accounts.count)").font(.headline)
            if results.accounts.isEmpty {
                Text(results.state == .running ? "Results appear when the scan finishes." : "No accounts were reported in this run.")
                    .font(.callout).foregroundStyle(.secondary)
            }
            ForEach(results.accounts) { account in
                VStack(alignment: .leading, spacing: 6) {
                    HStack(spacing: 8) {
                        Text(account.platform).font(.callout.weight(.medium))
                        if let category = account.category { Text(category).font(.caption).foregroundStyle(.secondary) }
                        Text("upstream: \(account.upstreamStatus)").font(.caption2.monospaced()).foregroundStyle(.secondary)
                        Text(account.confidence).font(.system(.caption2, design: .monospaced))
                            .padding(.horizontal, 5).padding(.vertical, 1)
                            .background(Color.gray.opacity(0.16), in: Capsule())
                            .help("REPORTED: the provider reported this account; MACSPLOIT has not verified it or who owns it.")
                        if let upstream = account.upstreamConfidence {
                            Text("upstream confidence: \(upstream)").font(.caption2).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button("Asset") { model.selectedAssetId = account.assetId; model.section = .assets }
                            .buttonStyle(.link)
                        if let evidence = account.evidenceId {
                            Button("Evidence") { model.showEvidence(evidence) }.buttonStyle(.link)
                        }
                    }
                    if let url = account.profileURL {
                        HStack(spacing: 6) {
                            Image(systemName: "link").foregroundStyle(.secondary)
                            // Untrusted provider output: shown as text and copyable, never opened automatically.
                            Text(url).font(.caption.monospaced()).textSelection(.enabled).lineLimit(1).truncationMode(.middle)
                            Button("Copy") { copy(url) }.controlSize(.mini)
                        }
                    }
                    if !account.profile.isEmpty {
                        DisclosureGroup("Public profile fields (\(account.profile.count))") {
                            VStack(alignment: .leading, spacing: 3) {
                                ForEach(account.profile) { field in
                                    HStack(alignment: .top, spacing: 8) {
                                        Text(field.key).font(.caption.monospaced()).foregroundStyle(.secondary).frame(width: 140, alignment: .leading)
                                        Text(field.value).font(.caption).textSelection(.enabled)
                                    }
                                }
                            }.padding(.top, 4)
                        }
                        .font(.caption)
                    }
                }
                .padding(10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.primary.opacity(0.035), in: RoundedRectangle(cornerRadius: 8))
            }
        }
    }

    @ViewBuilder private var console: some View {
        let lines = model.osintConsoleLines
        DisclosureGroup(isExpanded: $consoleExpanded) {
            VStack(alignment: .leading, spacing: 2) {
                ForEach(lines) { line in
                    HStack(alignment: .top, spacing: 10) {
                        Text(line.clock).foregroundStyle(.tertiary)
                        Text(line.label).foregroundStyle(.secondary).frame(width: 92, alignment: .leading)
                        Text(line.detail).textSelection(.enabled)
                        Spacer(minLength: 0)
                    }
                }
            }
            .font(.system(.caption, design: .monospaced))
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.black.opacity(0.22), in: RoundedRectangle(cornerRadius: 8))
        } label: {
            Label("Live console", systemImage: "terminal").font(.callout.weight(.medium))
        }
    }

    // MARK: History

    @ViewBuilder private var history: some View {
        let chains = model.snapshot?.osintChains ?? []
        if !chains.isEmpty {
            VStack(alignment: .leading, spacing: 6) {
                Text("OSINT history").font(.headline)
                ForEach(chains) { chain in
                    Button { model.selectedOSINTChainId = chain.id } label: {
                        HStack {
                            Image(systemName: chain.id == model.selectedOSINTChainId ? "largecircle.fill.circle" : "circle")
                                .foregroundStyle(.secondary)
                            Text(chain.name).frame(width: 130, alignment: .leading)
                            Text(subject(for: chain)).font(.callout.monospaced()).frame(width: 220, alignment: .leading)
                            Text(displayTime(chain.createdAt)).foregroundStyle(.secondary)
                            Spacer()
                            StatusBadge(status: chain.status)
                        }
                    }
                    .buttonStyle(.plain).padding(.vertical, 3)
                }
            }
        }
    }

    private func subject(for chain: ChainRun) -> String {
        model.snapshot?.targets.first { $0.id == chain.targetId }?.normalizedValue ?? ""
    }

    private func copy(_ value: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(value, forType: .string)
    }
}
