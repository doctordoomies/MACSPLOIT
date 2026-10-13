import AppKit
import SwiftUI
import MACSPLOITKit

/// A terminal-like, read-only Install Console. It renders the typed install event
/// stream the core reports (stages, the reviewed executable + argv, and bounded
/// stdout/stderr) for one provider, plus progress and the final outcome. It is **not**
/// an interactive shell: there is no prompt and the user cannot type commands —
/// MACSPLOIT only ever runs typed, reviewed install plans.
struct InstallConsoleView: View {
    @ObservedObject var model: WorkspaceModel
    let providerId: String
    let providerName: String

    private var runningHere: Bool { model.installState?.running?.providerId == providerId }
    private var outcomeHere: InstallOutcome? {
        let last = model.installState?.last
        return last?.providerId == providerId ? last : nil
    }
    /// Only show the console for an install that concerns this provider.
    private var concernsThisProvider: Bool { runningHere || outcomeHere != nil }

    var body: some View {
        if concernsThisProvider, let state = model.installState {
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 8) {
                    Image(systemName: "terminal").foregroundStyle(.secondary)
                    Text("Install Console · \(providerName)").font(.callout.weight(.medium))
                    if let method = state.running?.method ?? outcomeHere?.method {
                        Text(methodLabel(method)).font(.caption2.monospaced()).foregroundStyle(.secondary)
                    }
                    Spacer()
                    if let stage = state.currentStage {
                        HStack(spacing: 5) {
                            if runningHere && !terminalStages.contains(stage) { ProgressView().controlSize(.mini) }
                            Text(stage).font(.caption2.weight(.semibold))
                                .foregroundStyle(stageColor(stage))
                        }
                    }
                    if runningHere {
                        Button("Cancel") { Task { await model.cancelInstall() } }.controlSize(.small)
                    }
                }
                consoleLog(state.events ?? [])
                if let outcome = outcomeHere {
                    let color: Color = outcome.status == "SUCCEEDED" ? .green
                        : (outcome.status == "CANCELLED" ? .secondary : .orange)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(outcome.message).font(.caption.weight(.medium)).foregroundStyle(color)
                        if let detail = outcome.detail {
                            if detail.hasPrefix("https://"), let url = URL(string: detail) {
                                Link("Official installer", destination: url).font(.caption2)
                            } else {
                                // Detected executable path after rediscovery.
                                Text(detail).font(.caption2.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
                            }
                        }
                    }
                }
            }
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.black.opacity(0.22), in: RoundedRectangle(cornerRadius: 8))
        }
    }

    private var terminalStages: Set<String> { ["READY", "FAILED", "CANCELLED"] }

    private func stageColor(_ stage: String) -> Color {
        switch stage {
        case "READY": return .green
        case "FAILED": return .orange
        case "CANCELLED": return .secondary
        default: return .accentColor
        }
    }

    private func methodLabel(_ method: String) -> String {
        switch method {
        case "homebrew": return "Homebrew"
        case "managed_download": return "MACSPLOIT managed download"
        case "managed_python": return "MACSPLOIT managed Python (uv)"
        case "managed": return "MACSPLOIT managed"
        default: return method
        }
    }

    private func consoleLog(_ events: [InstallEvent]) -> some View {
        ScrollViewReader { proxy in
            ScrollView {
                VStack(alignment: .leading, spacing: 1) {
                    ForEach(events) { event in
                        lineView(event).id(event.seq)
                    }
                    if events.isEmpty {
                        Text("Starting…").foregroundStyle(.tertiary)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(maxHeight: 220)
            .font(.system(.caption, design: .monospaced))
            .onChange(of: events.count) { _ in
                if let last = events.last { withAnimation { proxy.scrollTo(last.seq, anchor: .bottom) } }
            }
        }
    }

    @ViewBuilder private func lineView(_ event: InstallEvent) -> some View {
        switch event.kind {
        case "STAGE":
            Text("• \(event.text)").foregroundStyle(stageColor(event.text))
        case "COMMAND":
            // The reviewed executable + argv (display only; never executed from text).
            Text(event.text).foregroundStyle(.cyan).textSelection(.enabled)
        case "STDERR":
            Text(event.text).foregroundStyle(.orange).textSelection(.enabled)
        case "INFO":
            Text(event.text).foregroundStyle(.secondary).textSelection(.enabled)
        default:
            Text(event.text).foregroundStyle(.primary.opacity(0.85)).textSelection(.enabled)
        }
    }
}
