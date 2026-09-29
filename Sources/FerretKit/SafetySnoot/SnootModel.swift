import FerretParsers
import Foundation

/// The overall Safety Snoot result. Wording rule: green never claims "safe".
public enum SnootVerdict: String, Codable, Sendable, Comparable {
    case green
    case yellow
    case red

    public var title: String {
        switch self {
        case .green: return "No problems detected"
        case .yellow: return "Something is off"
        case .red: return "This network is tampering with traffic"
        }
    }

    public var advice: String {
        switch self {
        case .green:
            return "Ferret didn't find anything wrong in its checks. That isn't a guarantee: some attacks can't be seen from a phone. If you're worried, talk to an expert."
        case .yellow:
            return "Avoid sensitive logins on this network, or turn on a VPN you trust."
        case .red:
            return "Disconnect from this network. Don't sign in to anything while you're on it."
        }
    }

    /// Snoot animation for the result screen.
    public var mood: MascotMood {
        switch self {
        case .green: return .happy
        case .yellow: return .twitchy
        case .red: return .growling
        }
    }

    private var rank: Int {
        switch self {
        case .green: return 0
        case .yellow: return 1
        case .red: return 2
        }
    }

    public static func < (a: SnootVerdict, b: SnootVerdict) -> Bool { a.rank < b.rank }
}

public enum MascotMood: String, Codable, Sendable {
    case sniffing
    case sitting
    case happy
    case twitchy
    case growling
}

public enum SnootCheckKind: String, Codable, CaseIterable, Sendable {
    case dnsHijack
    case tlsInterception
    case captivePortal
    case openNetwork
    case bonjour

    public var title: String {
        switch self {
        case .dnsHijack: return "DNS answers"
        case .tlsInterception: return "Encrypted connections"
        case .captivePortal: return "Web page tampering"
        case .openNetwork: return "Wi-Fi security"
        case .bonjour: return "Nearby services"
        }
    }

    public var explanation: String {
        switch self {
        case .dnsHijack: return "Looks up names with well-known answers and a name that shouldn't exist, to see if the network rewrites DNS."
        case .tlsInterception: return "Opens encrypted connections to well-known sites and checks who signed their certificates."
        case .captivePortal: return "Fetches a known plain-HTTP page to see if the network redirects or edits it."
        case .openNetwork: return "Checks whether this Wi-Fi uses a password and modern encryption."
        case .bonjour: return "Listens for devices on this network offering remote access or file sharing."
        }
    }
}

public enum SnootSeverity: Int, Codable, Sendable, Comparable {
    case info = 0
    case warning = 1
    case danger = 2

    public static func < (a: SnootSeverity, b: SnootSeverity) -> Bool { a.rawValue < b.rawValue }
}

public struct SnootFinding: Hashable, Codable, Sendable, Identifiable {
    public var kind: SnootCheckKind
    public var severity: SnootSeverity
    public var title: String
    public var detail: String

    public var id: String { "\(kind.rawValue):\(title)" }
}

public enum SnootCheckStatus: Hashable, Codable, Sendable {
    case passed
    case findings
    /// The check couldn't run, e.g. no Wi-Fi permission. Never counts as a pass.
    case skipped(String)
}

public struct SnootCheckResult: Hashable, Codable, Sendable, Identifiable {
    public var kind: SnootCheckKind
    public var status: SnootCheckStatus
    public var findings: [SnootFinding]

    public var id: SnootCheckKind { kind }
    public var worstSeverity: SnootSeverity? { findings.map(\.severity).max() }
}

public struct SnootReport: Hashable, Codable, Sendable {
    public var verdict: SnootVerdict
    public var results: [SnootCheckResult]
    public var startedAt: Date
    public var duration: TimeInterval
    public var isPractice: Bool
    public var networkName: String?

    public var findings: [SnootFinding] { results.flatMap(\.findings).sorted { $0.severity > $1.severity } }
    public var skippedChecks: [SnootCheckKind] {
        results.compactMap { if case .skipped = $0.status { return $0.kind } else { return nil } }
    }

    static func verdict(for results: [SnootCheckResult]) -> SnootVerdict {
        let worst = results.compactMap(\.worstSeverity).max()
        switch worst {
        case .danger: return .red
        case .warning: return .yellow
        default: return .green
        }
    }
}

// MARK: - Probe results

public enum DNSProbeResult: Hashable, Sendable {
    case addresses([IPAddress])
    case nameNotFound
    case failed(String)
}

public struct TLSProbeResult: Hashable, Sendable {
    public var host: String
    /// True if the system trust evaluation accepted the chain.
    public var trusted: Bool
    /// Leaf issuer, e.g. "WE2" or "Google Trust Services".
    public var issuerOrganization: String?
    public var issuerCommonName: String?
    public var error: String?

    public init(host: String, trusted: Bool, issuerOrganization: String?, issuerCommonName: String? = nil, error: String? = nil) {
        self.host = host
        self.trusted = trusted
        self.issuerOrganization = issuerOrganization
        self.issuerCommonName = issuerCommonName
        self.error = error
    }
}

public struct HTTPProbeResult: Hashable, Sendable {
    public var statusCode: Int
    public var body: String
    public var redirectLocation: String?
    public var headers: [String: String]

    public init(statusCode: Int, body: String, redirectLocation: String? = nil, headers: [String: String] = [:]) {
        self.statusCode = statusCode
        self.body = body
        self.redirectLocation = redirectLocation
        self.headers = headers
    }
}

public enum WiFiSecurity: String, Hashable, Sendable {
    case open
    case wep
    case personal
    case enterprise
    case unknown
    case notOnWiFi
}

public struct WiFiProbeResult: Hashable, Sendable {
    public var ssid: String?
    public var security: WiFiSecurity

    public init(ssid: String?, security: WiFiSecurity) {
        self.ssid = ssid
        self.security = security
    }
}

/// Everything Safety Snoot needs from the outside world. The app implements this
/// with Network.framework and NetworkExtension; practice mode simulates it.
public protocol SnootProbes: Sendable {
    func resolve(_ name: String) async -> DNSProbeResult
    func tlsHandshake(host: String) async -> TLSProbeResult
    func fetchCaptivePortalCheck() async -> HTTPProbeResult?
    func wifi() async -> WiFiProbeResult
    /// Service types seen, with how many instances of each.
    func bonjourServices() async -> [String: Int]?
}
