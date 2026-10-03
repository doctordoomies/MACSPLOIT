import Foundation

/// Static help supplied by the provider registry. Commands are display/copy only.
public struct ProviderSetup: Codable, Sendable, Equatable {
    public let installCommand: String?
    public let homepage: String?
    public let documentation: String?

    public var homepageURL: URL? { Self.helpURL(homepage) }
    public var documentationURL: URL? { Self.helpURL(documentation) }
    private static func helpURL(_ value: String?) -> URL? {
        guard let value, let url = URL(string: value), url.scheme == "https",
              url.host != nil, url.user == nil, url.password == nil else { return nil }
        return url
    }
}

public enum ProviderFilter: String, CaseIterable, Identifiable {
    case all = "All", builtIn = "Built In", installed = "Installed", missing = "Missing", issues = "Issues"
    public var id: String { rawValue }
    public func includes(_ provider: ProviderStatus, search: String = "") -> Bool {
        let state = provider.installation.state
        let matchesState: Bool
        switch self {
        case .all: matchesState = true
        case .builtIn: matchesState = state == "BUILT_IN"
        case .installed: matchesState = state == "INSTALLED"
        case .missing: matchesState = state == "MISSING"
        case .issues: matchesState = !["BUILT_IN", "INSTALLED", "MISSING"].contains(state)
        }
        let query = search.trimmingCharacters(in: .whitespacesAndNewlines)
        let text = ([provider.name, provider.id] + provider.capabilities + provider.capabilities.map(providerLabel)).joined(separator: " ")
        return matchesState && (query.isEmpty || text.localizedCaseInsensitiveContains(query))
    }
}

public func providerLabel(_ value: String) -> String {
    value.replacingOccurrences(of: "_", with: " ").capitalized
}

public extension ProviderInstallation {
    var statusTitle: String {
        switch state {
        case "BUILT_IN": return "Built In"
        case "INSTALLED": return "Installed"
        case "MISSING": return "Missing"
        case "UNSUPPORTED_VERSION": return "Unsupported"
        case "EXECUTION_ERROR": return "Error"
        default: return "Unknown status"
        }
    }
    var versionLabel: String {
        guard let version, !version.trimmingCharacters(in: .whitespaces).isEmpty,
              version.lowercased() != "unknown" else { return "Version unknown" }
        return "Version \(version)"
    }
    var isBuiltIn: Bool { state == "BUILT_IN" }
}
