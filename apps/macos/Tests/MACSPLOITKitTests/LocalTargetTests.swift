import Foundation
import Testing
@testable import MACSPLOITKit

@Suite struct LocalTargetTests {
    private func target(_ type: String, _ normalized: String) -> Target {
        Target(
            id: "t", workspaceId: "w", originalValue: normalized, normalizedValue: normalized,
            targetType: type, createdAt: "now", assetId: nil
        )
    }

    @Test func scopeHostExtractsUrlHostAndStripsIpv6Brackets() {
        #expect(target("URL", "http://localhost:3000/").scopeHost == "localhost")
        #expect(target("URL", "http://127.0.0.1:8080/").scopeHost == "127.0.0.1")
        #expect(target("URL", "http://[::1]:8080/").scopeHost == "::1")
        #expect(target("URL", "http://app.localhost:5173/").scopeHost == "app.localhost")
        #expect(target("IPAddress", "192.168.1.50").scopeHost == "192.168.1.50")
        #expect(target("Hostname", "localhost").scopeHost == "localhost")
        #expect(target("EmailAddress", "a@b.test").scopeHost == nil)
    }

    @Test func classifiesLocalAndPrivateHosts() {
        for host in ["localhost", "app.localhost", "127.0.0.1", "127.5.5.5", "::1",
                     "10.0.0.5", "192.168.1.50", "172.16.0.1", "172.31.255.255",
                     "169.254.1.1", "fe80::1", "fd00::1"] {
            #expect(Target.isLocalOrPrivateHost(host), "expected local: \(host)")
        }
    }

    @Test func doesNotClassifyPublicHostsAsLocal() {
        for host in ["example.test", "8.8.8.8", "172.32.0.1", "172.15.0.1",
                     "192.167.0.1", "2001:db8::1", "notlocalhost.test"] {
            #expect(!Target.isLocalOrPrivateHost(host), "expected public: \(host)")
        }
    }

    @Test func localUrlTargetsReportLocalByClassification() {
        #expect(target("URL", "http://localhost:3000/").isLocalOrPrivateHost)
        #expect(target("URL", "http://[::1]:8080/").isLocalOrPrivateHost)
        #expect(target("URL", "http://192.168.1.50:8000/").isLocalOrPrivateHost)
        #expect(!target("URL", "https://example.test/").isLocalOrPrivateHost)
    }
}
