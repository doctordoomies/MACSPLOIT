import SwiftUI
import MACSPLOITKit

/// Local, no-network environment facts for the setup Environment step.
enum SetupEnvironment {
    static var macOSVersion: String {
        let v = ProcessInfo.processInfo.operatingSystemVersion
        return "\(v.majorVersion).\(v.minorVersion).\(v.patchVersion)"
    }
    static var architecture: String {
        var info = utsname()
        uname(&info)
        let machine = withUnsafeBytes(of: &info.machine) { raw -> String in
            let bytes = raw.prefix { $0 != 0 }
            return String(decoding: bytes, as: UTF8.self)
        }
        return machine.isEmpty ? "unknown" : machine
    }
    /// Local filesystem check only — never a network call. Looks for the brew binary in
    /// the standard Apple-silicon and Intel Homebrew locations.
    static var homebrewPath: String? {
        for path in ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"] where FileManager.default.isExecutableFile(atPath: path) {
            return path
        }
        return nil
    }
    static var homebrewAvailable: Bool { homebrewPath != nil }
    static let officialHomebrewURL = URL(string: "https://brew.sh")!
}

/// First-run guided setup. Centered onboarding surface with a step indicator; one
/// decision per screen, matching the M1.3 workbench visual language.
struct SetupView: View {
    @ObservedObject var model: WorkspaceModel
    @ObservedObject var setup: SetupModel
    @State private var providerChoice: ProviderSetupChoice = .recommended
    @State private var expandedProviderGuidance: Set<String> = []

    var body: some View {
        VStack(spacing: 0) {
            stepIndicator
            Divider()
            ScrollView {
                content
                    .frame(maxWidth: 680, alignment: .leading)
                    .frame(maxWidth: .infinity, alignment: .center)
                    .padding(.horizontal, 32).padding(.vertical, 28)
            }
            Divider()
            footer
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var steps: [SetupStep] { SetupStep.allCases }
    private var stepNumber: Int { (steps.firstIndex(of: setup.step) ?? 0) + 1 }

    private var stepIndicator: some View {
        HStack(spacing: 10) {
            Text("MACSPLOIT Setup").font(.headline)
            Spacer()
            Text("Step \(stepNumber) of \(steps.count) · \(setup.step.title)")
                .font(.caption).foregroundStyle(.secondary)
        }
        .padding(.horizontal, 24).padding(.vertical, 14)
    }

    @ViewBuilder private var content: some View {
        switch setup.step {
        case .welcome: welcomeStep
        case .authorization: authorizationStep
        case .environment: environmentStep
        case .providers: providersStep
        case .homebrew: homebrewStep
        case .appearance: appearanceStep
        case .interfaceDetail: interfaceStep
        case .dashboard: dashboardStep
        case .tutorial: tutorialStep
        case .ready: readyStep
        }
    }

    // MARK: Footer / navigation

    private var footer: some View {
        HStack {
            if setup.step != .welcome {
                Button("Back") { setup.back() }
            }
            Spacer()
            if setup.step == .ready {
                Button("Open MACSPLOIT") { setup.complete() }
                    .buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)
            } else {
                Button(primaryTitle) { setup.advance() }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                    .disabled(!setup.canAdvance)
            }
        }
        .padding(.horizontal, 24).padding(.vertical, 14)
    }

    private var primaryTitle: String {
        switch setup.step {
        case .welcome: return "Get Started"
        default: return "Continue"
        }
    }

    // MARK: Steps

    private func heading(_ title: String, _ subtitle: String) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.largeTitle.weight(.semibold))
            Text(subtitle).font(.title3).foregroundStyle(.secondary)
        }
    }

    private var welcomeStep: some View {
        VStack(alignment: .leading, spacing: 20) {
            Image(systemName: "shield.lefthalf.filled").font(.system(size: 48, weight: .light)).foregroundStyle(.tint)
            heading("Welcome to MACSPLOIT", "A native macOS security workbench.")
            VStack(alignment: .leading, spacing: 10) {
                bullet("lock.laptopcomputer", "Local-first", "Your workspaces, scope, and evidence stay on this Mac.")
                bullet("doc.text.magnifyingglass", "Evidence-first", "Every provider run preserves verifiable raw output.")
                bullet("checkmark.shield", "For authorized research", "Designed for systems you own or are permitted to assess.")
                bullet("network", "You control the network", "Live activity happens only when you launch a workflow.")
            }
        }
    }

    private var authorizationStep: some View {
        VStack(alignment: .leading, spacing: 18) {
            heading("Authorization responsibility", "Please acknowledge before continuing.")
            WorkbenchCard {
                VStack(alignment: .leading, spacing: 12) {
                    Text("I understand that MACSPLOIT is a security assessment tool. I will only scan, test, validate, or otherwise assess systems that I own or have explicit authorization to assess.")
                        .font(.body)
                    Toggle(isOn: Binding(
                        get: { setup.authorizationAcknowledged },
                        set: { setup.setAuthorizationAcknowledged($0) }
                    )) {
                        Text("I understand and agree to this responsibility.").font(.callout)
                    }
                    .toggleStyle(.checkbox)
                }
            }
            Text("This is an acknowledgement of responsibility — not legal proof of authorization. Workspace scope and the per-target Authorize & Run confirmation remain separate technical boundaries, and the Rust core still enforces scope on every run.")
                .font(.caption).foregroundStyle(.secondary)
            if !setup.authorizationAcknowledged {
                Label("Continue is disabled until you acknowledge.", systemImage: "exclamationmark.circle")
                    .font(.caption).foregroundStyle(.orange)
            }
        }
    }

    private var environmentStep: some View {
        VStack(alignment: .leading, spacing: 18) {
            heading("Environment check", "What MACSPLOIT found on this Mac. No network activity.")
            WorkbenchCard {
                VStack(alignment: .leading, spacing: 10) {
                    envRow("MACSPLOIT Core", model.isConnected ? "Connected\(model.coreVersion.map { " · \($0)" } ?? "")" : "Unavailable", ok: model.isConnected)
                    Divider()
                    envRow("macOS", SetupEnvironment.macOSVersion, ok: true)
                    envRow("Architecture", SetupEnvironment.architecture, ok: true)
                    Divider()
                    envRow("Homebrew", SetupEnvironment.homebrewAvailable ? "Available (optional)" : "Not configured (optional)", ok: SetupEnvironment.homebrewAvailable, neutral: !SetupEnvironment.homebrewAvailable)
                }
            }
            Text("Homebrew is a recommended convenience on macOS, not a requirement — MACSPLOIT can use compatible executables installed by other methods. Providers are summarized on the next step.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    /// Recommended external providers, in the registry order when present.
    private var recommendedProviders: [ProviderStatus] {
        RecommendedProviders.ids.compactMap { id in model.providerStatuses.first { $0.id == id } }
    }

    private var providersStep: some View {
        VStack(alignment: .leading, spacing: 16) {
            heading("Provider setup", "Choose how to approach external tools. Nothing is installed.")

            Picker("Provider setup", selection: $providerChoice) {
                ForEach(ProviderSetupChoice.allCases) { Text($0.label).tag($0) }
            }
            .pickerStyle(.segmented).frame(maxWidth: 360)
            Text(providerChoice.summary).font(.caption).foregroundStyle(.secondary)

            switch providerChoice {
            case .recommended: recommendedProvidersView
            case .customize: customizeProvidersView
            case .skip: skipProvidersView
            }

            HStack {
                Button("Refresh") { Task { await model.refreshProviders() } }.controlSize(.small)
                Button("Open Provider Center") { } // navigation happens post-setup; informational here
                    .controlSize(.small).disabled(true)
                    .help("Provider Center is available in the workbench after setup.")
                Spacer()
            }
            Text("MACSPLOIT never installs providers and runs no shell or remote scripts. Homebrew is optional. Setup commands shown in Provider Center are copy-only guidance.")
                .font(.caption2).foregroundStyle(.tertiary)
        }
    }

    private var recommendedProvidersView: some View {
        WorkbenchCard {
            VStack(alignment: .leading, spacing: 10) {
                Text("The normal recommended external provider set:").font(.caption).foregroundStyle(.secondary)
                if recommendedProviders.isEmpty {
                    Text("Provider status unavailable. You can review it later in Provider Center.")
                        .font(.callout).foregroundStyle(.secondary)
                } else {
                    ForEach(Array(recommendedProviders.enumerated()), id: \.offset) { _, p in
                        providerStatusRow(p)
                    }
                }
            }
        }
    }

    private var customizeProvidersView: some View {
        WorkbenchCard {
            VStack(alignment: .leading, spacing: 10) {
                Text("Tap a provider to show or hide its setup guidance. This only changes what is shown — it installs nothing.")
                    .font(.caption).foregroundStyle(.secondary)
                ForEach(Array(recommendedProviders.enumerated()), id: \.offset) { _, p in
                    VStack(alignment: .leading, spacing: 6) {
                        Button {
                            if expandedProviderGuidance.contains(p.id) { expandedProviderGuidance.remove(p.id) }
                            else { expandedProviderGuidance.insert(p.id) }
                        } label: {
                            HStack {
                                Image(systemName: expandedProviderGuidance.contains(p.id) ? "chevron.down" : "chevron.right")
                                    .font(.caption).foregroundStyle(.secondary)
                                providerStatusRow(p)
                            }
                        }
                        .buttonStyle(.plain)
                        if expandedProviderGuidance.contains(p.id) {
                            VStack(alignment: .leading, spacing: 3) {
                                Text(p.description).font(.caption).foregroundStyle(.secondary)
                                if p.installation.isBuiltIn {
                                    Text("Built in — no installation required.").font(.caption2).foregroundStyle(.secondary)
                                } else if let command = p.setup?.installCommand {
                                    Text("Recommended on macOS (optional): \(command)")
                                        .font(.caption2.monospaced()).textSelection(.enabled).foregroundStyle(.secondary)
                                    Text("Or install by any method and ensure it is on PATH. Full guidance is in Provider Center.")
                                        .font(.caption2).foregroundStyle(.tertiary)
                                }
                            }
                            .padding(.leading, 20)
                        }
                    }
                }
            }
        }
    }

    private var skipProvidersView: some View {
        WorkbenchCard {
            VStack(alignment: .leading, spacing: 8) {
                Label("Continue without external providers", systemImage: "forward.end").font(.headline)
                Text("You can set up external providers later — Recon routes you to Provider Center when one is needed.")
                    .font(.callout).foregroundStyle(.secondary)
                Text("Synthetic Recon still works (offline), and built-in workflows (DNS Recon, Web Analysis) remain available.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    private func providerStatusRow(_ p: ProviderStatus) -> some View {
        HStack(spacing: 10) {
            Image(systemName: p.installation.isAvailable ? "checkmark.seal.fill" : "exclamationmark.triangle.fill")
                .foregroundStyle(p.installation.isAvailable ? Color.green : Color.orange)
            VStack(alignment: .leading, spacing: 1) {
                Text(p.name).font(.callout)
                Text(p.description).font(.caption2).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer()
            Text(p.installation.isBuiltIn ? "Built in" : (p.installation.isAvailable ? p.installation.summary : "Not detected"))
                .font(.caption.monospaced())
                .foregroundStyle(p.installation.isAvailable ? Color.secondary : Color.orange)
        }
    }

    private var homebrewStep: some View {
        VStack(alignment: .leading, spacing: 18) {
            heading("Homebrew", "Optional — a convenient way to install external providers.")
            WorkbenchCard {
                if SetupEnvironment.homebrewAvailable {
                    Label("Homebrew is available on this Mac.", systemImage: "checkmark.seal.fill")
                        .foregroundStyle(.green)
                } else {
                    VStack(alignment: .leading, spacing: 10) {
                        Label("Homebrew is not configured.", systemImage: "info.circle").foregroundStyle(.secondary)
                        Text("Homebrew (brew.sh) makes installing and updating external providers like Nmap or HTTPX easier. It is entirely optional — MACSPLOIT works with compatible executables installed any way you prefer.")
                            .font(.callout).foregroundStyle(.secondary)
                        Link("Official installation instructions (brew.sh)", destination: SetupEnvironment.officialHomebrewURL)
                            .font(.callout)
                    }
                }
            }
            Text("MACSPLOIT does not install Homebrew for you and runs no remote install scripts. You can continue without it.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    private var appearanceStep: some View {
        VStack(alignment: .leading, spacing: 18) {
            heading("Appearance", "Choose how MACSPLOIT looks. You can change this later.")
            Picker("Appearance", selection: Binding(get: { setup.appearance }, set: { setup.setAppearance($0) })) {
                ForEach(AppearancePreference.allCases) { Text($0.label).tag($0) }
            }
            .pickerStyle(.segmented).frame(maxWidth: 360)
            Text("System follows your macOS Light/Dark setting.").font(.caption).foregroundStyle(.secondary)
        }
    }

    private var interfaceStep: some View {
        VStack(alignment: .leading, spacing: 18) {
            heading("Interface detail", "How much technical detail to show by default.")
            Picker("Interface detail", selection: Binding(get: { setup.interfaceDetail }, set: { setup.setInterfaceDetail($0) })) {
                ForEach(InterfaceDetail.allCases) { Text($0.label).tag($0) }
            }
            .pickerStyle(.segmented).frame(maxWidth: 300)
            Text("Standard keeps diagnostic surfaces (like the Recon live console) collapsed by default. Advanced expands them. This affects presentation only — never security capability or authorization — and you can change it anytime.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    private var dashboardStep: some View {
        VStack(alignment: .leading, spacing: 18) {
            heading("Dashboard preset", "Pick a starting dashboard. You can change it later.")
            ForEach(DashboardPreset.allCases) { preset in
                Button { setup.setDashboardPreset(preset) } label: {
                    HStack(spacing: 12) {
                        Image(systemName: setup.dashboardPreset == preset ? "largecircle.fill.circle" : "circle")
                            .foregroundStyle(setup.dashboardPreset == preset ? Color.accentColor : .secondary)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(preset.label).font(.headline)
                            Text(preset.summary).font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                    }
                    .padding(12)
                    .background((setup.dashboardPreset == preset ? Color.accentColor.opacity(0.10) : Color.gray.opacity(0.10)), in: RoundedRectangle(cornerRadius: 10))
                }
                .buttonStyle(.plain)
            }
            Text("Research adds a clearly-labelled reserved area for future research tooling; it shows no fabricated data.")
                .font(.caption2).foregroundStyle(.tertiary)
        }
    }

    private var tutorialStep: some View {
        VStack(alignment: .leading, spacing: 18) {
            heading("Guided tutorial", "Optional — learn the workbench with a safe demo.")
            WorkbenchCard {
                VStack(alignment: .leading, spacing: 10) {
                    Toggle(isOn: $setup.startTutorialAfterSetup) {
                        Text("Show me a guided tour after setup").font(.callout)
                    }.toggleStyle(.switch)
                    Text("The tutorial walks through Workspace → Target → Recon → Live Console → Assets → Evidence → Activity using Synthetic Recon, which performs no network activity. You can skip it now and start it later from Settings.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
        }
    }

    private var readyStep: some View {
        VStack(alignment: .leading, spacing: 18) {
            Image(systemName: "checkmark.circle.fill").font(.system(size: 44)).foregroundStyle(.green)
            heading("MACSPLOIT is ready", "A quick summary of your setup.")
            WorkbenchCard {
                VStack(alignment: .leading, spacing: 8) {
                    summaryRow("Core", model.isConnected ? "Ready" : "Unavailable")
                    let ready = model.providerStatuses.filter { $0.installation.isAvailable }.count
                    summaryRow("Providers", model.providerStatuses.isEmpty ? "—" : "\(ready) / \(model.providerStatuses.count) ready")
                    summaryRow("Homebrew", SetupEnvironment.homebrewAvailable ? "Available" : "Not configured")
                    summaryRow("Appearance", setup.appearance.label)
                    summaryRow("Interface", setup.interfaceDetail.label)
                    summaryRow("Dashboard", setup.dashboardPreset.label)
                    summaryRow("Tutorial", setup.startTutorialAfterSetup ? "Starts after setup" : "Skipped")
                }
            }
            Text("You can re-run setup anytime from Settings → Setup & Environment. Existing workspaces and evidence are never affected.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    // MARK: Small helpers

    private func bullet(_ icon: String, _ title: String, _ detail: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: icon).foregroundStyle(.tint).frame(width: 22)
            VStack(alignment: .leading, spacing: 1) {
                Text(title).font(.headline)
                Text(detail).font(.callout).foregroundStyle(.secondary)
            }
        }
    }

    private func envRow(_ name: String, _ value: String, ok: Bool, neutral: Bool = false) -> some View {
        HStack {
            Text(name).font(.callout.weight(.medium))
            Spacer()
            HStack(spacing: 6) {
                Circle().fill(neutral ? Color.secondary : (ok ? Color.green : Color.orange)).frame(width: 7, height: 7)
                Text(value).font(.callout.monospaced()).foregroundStyle(.secondary)
            }
        }
    }

    private func summaryRow(_ name: String, _ value: String) -> some View {
        HStack {
            Text(name).font(.callout).foregroundStyle(.secondary).frame(width: 110, alignment: .leading)
            Text(value).font(.callout.weight(.medium))
            Spacer()
        }
    }
}
