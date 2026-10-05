import Foundation
import Testing
@testable import MACSPLOITKit

@MainActor
@Suite struct SetupStateTests {
    /// An isolated, volatile UserDefaults so tests never touch real app preferences.
    private func freshDefaults() -> UserDefaults {
        let suite = "macsploit.test.\(UUID().uuidString)"
        let d = UserDefaults(suiteName: suite)!
        d.removePersistentDomain(forName: suite)
        return d
    }

    @Test func freshInstallRequiresSetup() {
        let store = SetupStore(defaults: freshDefaults())
        #expect(store.completedVersion == nil)
        #expect(store.needsSetup)
    }

    @Test func completedCurrentVersionSkipsSetup() {
        let store = SetupStore(defaults: freshDefaults())
        store.markComplete()
        #expect(store.completedVersion == SetupStore.currentVersion)
        #expect(!store.needsSetup)
    }

    @Test func olderCompletedVersionRequiresSetupAgain() {
        let d = freshDefaults()
        d.set(SetupStore.currentVersion - 1, forKey: "setup.completedVersion")
        let store = SetupStore(defaults: d)
        #expect(store.needsSetup, "an older setup version must re-run onboarding")
    }

    @Test func incompleteSetupResumesAtSavedStep() {
        let d = freshDefaults()
        let store = SetupStore(defaults: d)
        store.currentStep = .appearance // persisted mid-flow
        let model = SetupModel(store: SetupStore(defaults: d))
        #expect(model.isPresentingSetup)
        #expect(model.step == .appearance)
    }

    @Test func authorizationCannotBeBypassedByNavigation() {
        let d = freshDefaults()
        let model = SetupModel(store: SetupStore(defaults: d))
        model.step = .authorization
        model.authorizationAcknowledged = false
        #expect(!model.canAdvance)
        model.advance()
        #expect(model.step == .authorization, "advance must be a no-op until acknowledged")
        model.authorizationAcknowledged = true
        #expect(model.canAdvance)
        model.advance()
        #expect(model.step != .authorization)
        // Persisted for a later relaunch.
        #expect(SetupStore(defaults: d).authorizationAcknowledged)
    }

    @Test func preferencesPersistAcrossStores() {
        let d = freshDefaults()
        let model = SetupModel(store: SetupStore(defaults: d))
        model.setAppearance(.dark)
        model.setInterfaceDetail(.advanced)
        model.setDashboardPreset(.research)
        let reloaded = SetupStore(defaults: d)
        #expect(reloaded.appearance == .dark)
        #expect(reloaded.interfaceDetail == .advanced)
        #expect(reloaded.dashboardPreset == .research)
    }

    @Test func completeThenRelaunchGoesToWorkbench() {
        let d = freshDefaults()
        let model = SetupModel(store: SetupStore(defaults: d))
        model.authorizationAcknowledged = true
        model.complete()
        #expect(!model.isPresentingSetup)
        // A fresh model (relaunch) sees setup as done.
        let relaunched = SetupModel(store: SetupStore(defaults: d))
        #expect(!relaunched.isPresentingSetup)
        #expect(relaunched.step == .ready)
    }

    @Test func rerunPreservesPreferencesAndAcknowledgementAndDoesNotWipeData() {
        let d = freshDefaults()
        let model = SetupModel(store: SetupStore(defaults: d))
        model.authorizationAcknowledged = true
        model.setAppearance(.light)
        model.setDashboardPreset(.minimal)
        model.complete()
        // Re-run: setup shows again but preferences/acknowledgement survive.
        model.rerun()
        #expect(model.isPresentingSetup)
        #expect(model.step == .welcome)
        let store = SetupStore(defaults: d)
        #expect(store.appearance == .light)
        #expect(store.dashboardPreset == .minimal)
        #expect(store.authorizationAcknowledged)
        #expect(store.completedVersion == nil, "rerun re-opens setup")
    }

    @Test func homebrewAndProviderStepsDoNotGateCompletion() {
        // Only the authorization step gates navigation; environment/providers/homebrew do
        // not. Homebrew absence (an app-module filesystem fact) never blocks setup here.
        let model = SetupModel(store: SetupStore(defaults: freshDefaults()))
        for step in [SetupStep.environment, .providers, .homebrew, .appearance, .interfaceDetail, .dashboard, .tutorial] {
            model.step = step
            #expect(model.canAdvance, "\(step) must not block advancing")
        }
    }

    @Test func tutorialArmingIsOfflineByToggleOnly() {
        let d = freshDefaults()
        let model = SetupModel(store: SetupStore(defaults: d))
        model.authorizationAcknowledged = true
        model.startTutorialAfterSetup = true
        model.complete()
        #expect(model.tutorialActive, "tutorial overlay is armed after setup")
        #expect(!SetupStore(defaults: d).tutorialCompleted)
        model.finishTutorial()
        #expect(!model.tutorialActive)
        #expect(SetupStore(defaults: d).tutorialCompleted)
    }

    @Test func interfaceDetailDrivesDefaultExpansion() {
        #expect(InterfaceDetail.advanced.expandsDetailByDefault)
        #expect(!InterfaceDetail.standard.expandsDetailByDefault)
    }

    @Test func acknowledgementPersistsImmediatelyWithoutAdvancing() {
        let d = freshDefaults()
        do {
            let model = SetupModel(store: SetupStore(defaults: d))
            model.step = .authorization
            model.setAuthorizationAcknowledged(true) // no advance() call
        }
        // Persisted at the store level...
        #expect(SetupStore(defaults: d).authorizationAcknowledged)
        // ...and a recreated model (relaunch) sees it checked.
        let relaunched = SetupModel(store: SetupStore(defaults: d))
        #expect(relaunched.authorizationAcknowledged)
    }

    @Test func providerSetupOffersRecommendedCustomizeSkip() {
        #expect(ProviderSetupChoice.allCases.map(\.rawValue) == ["recommended", "customize", "skip"])
        // The recommended external provider set is the normal five; MACSPLOIT installs none.
        #expect(RecommendedProviders.ids == ["subfinder", "nmap", "httpx", "katana", "ffuf"])
    }
}
