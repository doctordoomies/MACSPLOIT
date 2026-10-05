import Foundation

/// Appearance preference applied to the whole app. `system` follows macOS. The mapping
/// to a SwiftUI `ColorScheme` lives in the app module to keep this library UI-agnostic.
public enum AppearancePreference: String, CaseIterable, Codable, Sendable, Identifiable {
    case system, light, dark
    public var id: String { rawValue }
    public var label: String { rawValue.capitalized }
}

/// Presentation-detail preference. Affects defaults only — never security capability.
public enum InterfaceDetail: String, CaseIterable, Codable, Sendable, Identifiable {
    case standard, advanced
    public var id: String { rawValue }
    public var label: String { rawValue.capitalized }
    /// Advanced expands diagnostic surfaces (e.g. the Recon live console) by default.
    public var expandsDetailByDefault: Bool { self == .advanced }
}

/// Starting dashboard composition. Uses the existing modular M1.3 dashboard cards.
public enum DashboardPreset: String, CaseIterable, Codable, Sendable, Identifiable {
    case minimal
    case operatorView = "operator"
    case research
    public var id: String { rawValue }
    public var label: String {
        switch self {
        case .minimal: return "Minimal"
        case .operatorView: return "Operator"
        case .research: return "Research"
        }
    }
    public var summary: String {
        switch self {
        case .minimal: return "Core metrics, scope, and quick actions only."
        case .operatorView: return "The full operational security-workbench view."
        case .research: return "Operational essentials plus a reserved research area."
        }
    }
}

/// Ordered first-run steps. `authorization` is required and cannot be silently skipped.
public enum SetupStep: String, CaseIterable, Codable, Sendable, Identifiable {
    case welcome, authorization, environment, providers, homebrew, appearance, interfaceDetail, dashboard, tutorial, ready
    public var id: String { rawValue }
    public var title: String {
        switch self {
        case .welcome: return "Welcome"
        case .authorization: return "Authorization"
        case .environment: return "Environment"
        case .providers: return "Providers"
        case .homebrew: return "Homebrew"
        case .appearance: return "Appearance"
        case .interfaceDetail: return "Interface"
        case .dashboard: return "Dashboard"
        case .tutorial: return "Tutorial"
        case .ready: return "Ready"
        }
    }
}

/// Versioned, global application setup state persisted in UserDefaults (NOT in any
/// workspace SQLite database). Bump `currentVersion` when a future release adds a
/// required onboarding/migration step; users whose `completedVersion` is lower are
/// guided through setup again without losing workspaces, evidence, or other data.
public struct SetupStore: Sendable {
    /// The setup schema this build expects. Increment to require re-onboarding.
    public static let currentVersion = 1

    private let defaults: UserDefaults
    private enum Key {
        static let completedVersion = "setup.completedVersion"
        static let currentStep = "setup.currentStep"
        static let authorizationAcknowledged = "setup.authorizationAcknowledged"
        static let appearance = "setup.appearancePreference"
        static let interfaceDetail = "setup.interfaceDetail"
        static let dashboardPreset = "setup.dashboardPreset"
        static let tutorialCompleted = "setup.tutorialCompleted"
    }

    public init(defaults: UserDefaults = .standard) { self.defaults = defaults }

    // Completion ------------------------------------------------------------
    /// The setup version the user last completed, or nil if setup never finished.
    public var completedVersion: Int? {
        get { defaults.object(forKey: Key.completedVersion) as? Int }
        nonmutating set {
            if let v = newValue { defaults.set(v, forKey: Key.completedVersion) }
            else { defaults.removeObject(forKey: Key.completedVersion) }
        }
    }
    /// True on a fresh install or after a setup-version bump (existing data untouched).
    public var needsSetup: Bool {
        guard let done = completedVersion else { return true }
        return done < Self.currentVersion
    }

    // Resume ----------------------------------------------------------------
    public var currentStep: SetupStep {
        get { (defaults.string(forKey: Key.currentStep)).flatMap(SetupStep.init(rawValue:)) ?? .welcome }
        nonmutating set { defaults.set(newValue.rawValue, forKey: Key.currentStep) }
    }

    // Required acknowledgement ---------------------------------------------
    public var authorizationAcknowledged: Bool {
        get { defaults.bool(forKey: Key.authorizationAcknowledged) }
        nonmutating set { defaults.set(newValue, forKey: Key.authorizationAcknowledged) }
    }

    // Presentation preferences ---------------------------------------------
    public var appearance: AppearancePreference {
        get { (defaults.string(forKey: Key.appearance)).flatMap(AppearancePreference.init(rawValue:)) ?? .system }
        nonmutating set { defaults.set(newValue.rawValue, forKey: Key.appearance) }
    }
    public var interfaceDetail: InterfaceDetail {
        get { (defaults.string(forKey: Key.interfaceDetail)).flatMap(InterfaceDetail.init(rawValue:)) ?? .standard }
        nonmutating set { defaults.set(newValue.rawValue, forKey: Key.interfaceDetail) }
    }
    public var dashboardPreset: DashboardPreset {
        get { (defaults.string(forKey: Key.dashboardPreset)).flatMap(DashboardPreset.init(rawValue:)) ?? .operatorView }
        nonmutating set { defaults.set(newValue.rawValue, forKey: Key.dashboardPreset) }
    }
    public var tutorialCompleted: Bool {
        get { defaults.bool(forKey: Key.tutorialCompleted) }
        nonmutating set { defaults.set(newValue, forKey: Key.tutorialCompleted) }
    }

    /// Mark the current setup version complete. Preferences and acknowledgement persist;
    /// no workspace/evidence/SQLite data is touched.
    public func markComplete() { completedVersion = Self.currentVersion; currentStep = .ready }

    /// Reset ONLY setup progress so the guided flow can run again. Preserves presentation
    /// preferences and the authorization acknowledgement; never touches workspace data.
    public func resetForRerun() {
        completedVersion = nil
        currentStep = .welcome
    }

    /// Development-only: clear every setup preference (never touches workspace data).
    /// Not wired into normal UI; intended for manual/dev resets and tests.
    public func developmentResetAll() {
        for key in [Key.completedVersion, Key.currentStep, Key.authorizationAcknowledged,
                    Key.appearance, Key.interfaceDetail, Key.dashboardPreset, Key.tutorialCompleted] {
            defaults.removeObject(forKey: key)
        }
    }
}

/// Observable driver for the first-run flow and the live presentation preferences the
/// workbench reads. Persists every change through `SetupStore`.
@MainActor
public final class SetupModel: ObservableObject {
    @Published public private(set) var isPresentingSetup: Bool
    @Published public var step: SetupStep
    @Published public var authorizationAcknowledged: Bool
    @Published public var appearance: AppearancePreference
    @Published public var interfaceDetail: InterfaceDetail
    @Published public var dashboardPreset: DashboardPreset
    @Published public var startTutorialAfterSetup: Bool = false
    /// True while the in-workbench guided tutorial overlay should be shown.
    @Published public var tutorialActive: Bool = false

    private let store: SetupStore

    public init(store: SetupStore = SetupStore()) {
        self.store = store
        self.isPresentingSetup = store.needsSetup
        self.step = store.needsSetup ? store.currentStep : .ready
        self.authorizationAcknowledged = store.authorizationAcknowledged
        self.appearance = store.appearance
        self.interfaceDetail = store.interfaceDetail
        self.dashboardPreset = store.dashboardPreset
    }

    /// The authorization step gates forward navigation until explicitly acknowledged.
    public var canAdvance: Bool {
        if step == .authorization { return authorizationAcknowledged }
        return true
    }

    public func persistPreferences() {
        store.authorizationAcknowledged = authorizationAcknowledged
        store.appearance = appearance
        store.interfaceDetail = interfaceDetail
        store.dashboardPreset = dashboardPreset
    }

    public func advance() {
        guard canAdvance else { return }
        persistPreferences()
        let all = SetupStep.allCases
        guard let idx = all.firstIndex(of: step), idx + 1 < all.count else { return }
        step = all[idx + 1]
        store.currentStep = step
    }

    public func back() {
        let all = SetupStep.allCases
        guard let idx = all.firstIndex(of: step), idx > 0 else { return }
        step = all[idx - 1]
        store.currentStep = step
    }

    /// Finish setup: persist preferences, mark the version complete, and (optionally)
    /// arm the tutorial. Transitions the app to the workbench without a restart.
    public func complete() {
        persistPreferences()
        store.markComplete()
        isPresentingSetup = false
        if startTutorialAfterSetup {
            store.tutorialCompleted = false
            tutorialActive = true
        }
    }

    /// Start the guided tutorial on demand (e.g. from Settings). Safe/offline only.
    public func startTutorial() { store.tutorialCompleted = false; tutorialActive = true }

    /// Finish or skip the tutorial overlay.
    public func finishTutorial() { store.tutorialCompleted = true; tutorialActive = false }

    /// Re-run setup from Settings. Never deletes workspaces/evidence/preferences-in-use.
    public func rerun() {
        store.resetForRerun()
        step = .welcome
        // Keep current acknowledgement/preferences as the starting values.
        authorizationAcknowledged = store.authorizationAcknowledged
        isPresentingSetup = true
    }

    public var tutorialCompleted: Bool { store.tutorialCompleted }
    public func markTutorialComplete() { store.tutorialCompleted = true }
    public func requestTutorialRerun() { store.tutorialCompleted = false }

    /// Live appearance preference for the root scene; also persists eagerly so a change
    /// from Settings survives even without stepping through the flow.
    public func setAppearance(_ value: AppearancePreference) { appearance = value; store.appearance = value }
    public func setInterfaceDetail(_ value: InterfaceDetail) { interfaceDetail = value; store.interfaceDetail = value }
    public func setDashboardPreset(_ value: DashboardPreset) { dashboardPreset = value; store.dashboardPreset = value }
}
