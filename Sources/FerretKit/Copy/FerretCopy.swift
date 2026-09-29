import Foundation

/// User-facing strings with the brand voice: investigative and friendly.
/// Rule: hex views, packet fields and exports carry no jokes, so nothing here
/// is used in those places.
public enum FerretCopy {
    public static let emptyState = "Nothing to sniff yet. Go open an app."
    public static let caseOpened = "Case opened"
    public static let caseClosed = "Case closed"
    public static let startCapture = "Start sniffing"
    public static let stopCapture = "Stop"

    public static func evidenceCollected(packets: Int) -> String {
        "Evidence collected: \(formatCount(packets)) \(packets == 1 ? "packet" : "packets")"
    }

    public enum LostScentReason: Sendable {
        case permissionDenied
        case otherVPNActive
        case configurationFailed(String)
        case extensionStopped

        public var message: String {
            switch self {
            case .permissionDenied: return "Lost the scent: VPN permission was denied"
            case .otherVPNActive: return "Lost the scent: another VPN is active"
            case .configurationFailed(let why): return "Lost the scent: \(why)"
            case .extensionStopped: return "Lost the scent: the capture stopped unexpectedly"
            }
        }
    }

    /// Shown on the capture screen (spec: explain the one-VPN limit clearly).
    public static let oneVPNExplanation =
        "iOS allows one VPN at a time. Ferret captures by acting as a local VPN, so starting a capture pauses any other VPN you use. Your traffic never leaves this phone through Ferret."

    public static let localOnlyPromise =
        "Ferret works entirely on this iPhone. No accounts, no analytics, no servers."

    /// Suspects wording: the phone contacted a domain; never name an app.
    public static func suspectSentence(domain: String, contacts: Int) -> String {
        contacts == 1
            ? "Your phone contacted \(domain) once."
            : "Your phone contacted \(domain) \(formatCount(contacts)) times."
    }

    public static let suspectsFootnote =
        "iOS doesn't tell VPN apps which app opened a connection, so Ferret shows domains, not apps. Being on this list means a domain is known for tracking, not that anything is wrong."

    public static func formatCount(_ n: Int) -> String {
        let f = NumberFormatter()
        f.numberStyle = .decimal
        return f.string(from: NSNumber(value: n)) ?? "\(n)"
    }

    public static func formatBytes(_ n: Int) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(n), countStyle: .binary)
    }
}

/// Where to go for real help. Ferret points to experts rather than acting as the last word.
public struct ExpertResource: Identifiable, Hashable, Sendable {
    public var name: String
    public var summary: String
    public var url: URL

    public var id: String { name }

    public static let all: [ExpertResource] = [
        ExpertResource(
            name: "Coalition Against Stalkerware",
            summary: "Guidance and support if you think someone is monitoring your phone.",
            url: URL(string: "https://stopstalkerware.org")!),
        ExpertResource(
            name: "Amnesty Tech Security Lab",
            summary: "Forensic help for activists, journalists and human rights defenders.",
            url: URL(string: "https://securitylab.amnesty.org")!),
        ExpertResource(
            name: "Citizen Lab",
            summary: "Research on targeted spyware and digital threats to civil society.",
            url: URL(string: "https://citizenlab.ca")!),
        ExpertResource(
            name: "OONI",
            summary: "Open data and tools for measuring internet censorship.",
            url: URL(string: "https://ooni.org")!),
    ]
}
