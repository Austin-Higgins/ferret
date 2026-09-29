import FerretParsers
import Foundation

/// Practice mode: simulated networks, each staging one attack, so people can
/// learn what results look like (and so tests can prove each one is caught).
public enum PracticeScenario: String, CaseIterable, Codable, Sendable, Identifiable {
    case cleanHomeNetwork
    case dnsHijack
    case nxdomainRewriting
    case tlsInterception
    case rogueRootCertificate
    case captivePortal
    case contentInjection
    case openCafeWiFi
    case wepNetwork
    case remoteAccessNeighbours

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .cleanHomeNetwork: return "A normal home network"
        case .dnsHijack: return "DNS hijacking"
        case .nxdomainRewriting: return "Rewritten failed lookups"
        case .tlsInterception: return "Intercepted encryption"
        case .rogueRootCertificate: return "Rogue root certificate"
        case .captivePortal: return "Hotel sign-in page"
        case .contentInjection: return "Injected web content"
        case .openCafeWiFi: return "Open café Wi-Fi"
        case .wepNetwork: return "Ancient router"
        case .remoteAccessNeighbours: return "Chatty neighbours"
        }
    }

    public var story: String {
        switch self {
        case .cleanHomeNetwork: return "Everything behaves. Notice the result still says “no problems detected”, not “safe”."
        case .dnsHijack: return "The router answers lookups for well-known names with its own addresses, steering you to servers it controls."
        case .nxdomainRewriting: return "Mistyped addresses land on an ad page instead of failing. Common with some ISPs."
        case .tlsInterception: return "A box on the network decrypts HTTPS using a certificate your iPhone doesn't trust."
        case .rogueRootCertificate: return "A configuration profile installed a trusted root, so interception passes the usual checks. Only the unexpected issuers give it away."
        case .captivePortal: return "The network redirects web pages until you sign in."
        case .contentInjection: return "The network adds its own script to unencrypted pages."
        case .openCafeWiFi: return "No password: anyone nearby can join and watch unencrypted traffic."
        case .wepNetwork: return "WEP encryption, broken since the 2000s."
        case .remoteAccessNeighbours: return "Other devices on the network advertise SSH and file sharing."
        }
    }

    /// The check that should catch this scenario and the verdict it should produce.
    public var expected: (check: SnootCheckKind?, verdict: SnootVerdict) {
        switch self {
        case .cleanHomeNetwork: return (nil, .green)
        case .dnsHijack: return (.dnsHijack, .red)
        case .nxdomainRewriting: return (.dnsHijack, .yellow)
        case .tlsInterception: return (.tlsInterception, .red)
        case .rogueRootCertificate: return (.tlsInterception, .red)
        case .captivePortal: return (.captivePortal, .yellow)
        case .contentInjection: return (.captivePortal, .red)
        case .openCafeWiFi: return (.openNetwork, .yellow)
        case .wepNetwork: return (.openNetwork, .yellow)
        case .remoteAccessNeighbours: return (.bonjour, .yellow)
        }
    }

    public var probes: SnootProbes { SimulatedProbes(scenario: self) }
}

/// Probe results for a simulated network. Never touches the real network.
public struct SimulatedProbes: SnootProbes {
    public var scenario: PracticeScenario

    public init(scenario: PracticeScenario) {
        self.scenario = scenario
    }

    static let attacker = IPAddress("192.0.2.66")!

    public func resolve(_ name: String) async -> DNSProbeResult {
        if let expected = SafetySnoot.knownAnswers[name] {
            if scenario == .dnsHijack { return .addresses([Self.attacker]) }
            return .addresses(Array(expected).filter(\.isV4).sorted())
        }
        return scenario == .nxdomainRewriting ? .addresses([IPAddress("198.51.100.7")!]) : .nameNotFound
    }

    public func tlsHandshake(host: String) async -> TLSProbeResult {
        switch scenario {
        case .tlsInterception:
            return TLSProbeResult(host: host, trusted: false, issuerOrganization: "Corporate Web Filter", error: "certificate not trusted")
        case .rogueRootCertificate:
            return TLSProbeResult(host: host, trusted: true, issuerOrganization: "Totally Legit Security Ltd")
        case .captivePortal:
            return TLSProbeResult(host: host, trusted: false, issuerOrganization: "Hotel Portal", error: "certificate not trusted")
        default:
            let issuer = SafetySnoot.tlsHosts[host]?.first ?? "DigiCert"
            return TLSProbeResult(host: host, trusted: true, issuerOrganization: issuer)
        }
    }

    public func fetchCaptivePortalCheck() async -> HTTPProbeResult? {
        switch scenario {
        case .captivePortal:
            return HTTPProbeResult(statusCode: 302, body: "", redirectLocation: "http://portal.hotel.example/login")
        case .contentInjection:
            return HTTPProbeResult(statusCode: 200, body: SafetySnoot.captivePortalBody.replacingOccurrences(
                of: "</BODY>", with: "<script src=\"http://ads.example/inject.js\"></script></BODY>"))
        default:
            return HTTPProbeResult(statusCode: 200, body: SafetySnoot.captivePortalBody)
        }
    }

    public func wifi() async -> WiFiProbeResult {
        switch scenario {
        case .openCafeWiFi: return WiFiProbeResult(ssid: "Café Free WiFi", security: .open)
        case .wepNetwork: return WiFiProbeResult(ssid: "linksys", security: .wep)
        case .captivePortal: return WiFiProbeResult(ssid: "Hotel Guest", security: .personal)
        default: return WiFiProbeResult(ssid: "Practice network", security: .personal)
        }
    }

    public func bonjourServices() async -> [String: Int]? {
        switch scenario {
        case .remoteAccessNeighbours: return ["_ssh._tcp": 2, "_smb._tcp": 1, "_airplay._tcp": 3]
        default: return ["_airplay._tcp": 1, "_ipp._tcp": 1]
        }
    }
}
