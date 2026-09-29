import Foundation

/// Service names for ports, from the full IANA Service Name and Transport
/// Protocol Port Number Registry (public data, bundled as `iana-services.tsv`).
/// A few friendlier names for ports that phones use heavily take precedence.
public enum ServiceNames {
    public struct Entry: Hashable, Sendable {
        public var name: String
        public var description: String
    }

    public static func name(port: UInt16, isUDP: Bool) -> String? {
        entry(port: port, isUDP: isUDP)?.name
    }

    public static func entry(port: UInt16, isUDP: Bool) -> Entry? {
        if let friendly = overrides[port] { return friendly }
        return registry.entries[Key(port: port, udp: isUDP)]
    }

    /// Number of registry rows loaded, for tests and the About screen.
    public static var registryCount: Int { registry.entries.count }

    struct Key: Hashable {
        var port: UInt16
        var udp: Bool
    }

    /// Ports where the registry name is misleading for phone traffic.
    static let overrides: [UInt16: Entry] = [
        5223: Entry(name: "apple-push", description: "Apple Push Notification service"),
        5228: Entry(name: "google-push", description: "Firebase Cloud Messaging"),
        853: Entry(name: "domain-s", description: "DNS over TLS or QUIC"),
    ]

    final class Registry: @unchecked Sendable {
        let entries: [Key: Entry]

        init(tsv: String) {
            var entries: [Key: Entry] = [:]
            for line in tsv.split(separator: "\n") where !line.hasPrefix("#") {
                let cols = line.split(separator: "\t", maxSplits: 3, omittingEmptySubsequences: false)
                guard cols.count >= 3, let port = UInt16(cols[0]) else { continue }
                let key = Key(port: port, udp: cols[1] == "udp")
                if entries[key] == nil {
                    entries[key] = Entry(name: String(cols[2]), description: cols.count > 3 ? String(cols[3]) : "")
                }
            }
            self.entries = entries
        }
    }

    static let registry: Registry = {
        guard let url = Bundle.module.url(forResource: "iana-services", withExtension: "tsv"),
              let text = try? String(contentsOf: url, encoding: .utf8) else {
            return Registry(tsv: "")
        }
        return Registry(tsv: text)
    }()
}

/// Domains Apple uses for its own services, for the "Hide Apple" filter.
public enum AppleDomains {
    public static let registrable: Set<String> = [
        "apple.com", "icloud.com", "icloud-content.com", "mzstatic.com", "apple-dns.net",
        "aaplimg.com", "cdn-apple.com", "apple-cloudkit.com", "apple.news", "itunes.com",
        "me.com", "mac.com", "apple-mapkit.com", "applemusic.com", "apple-livephotoskit.com",
        "push-apple.com.akadns.net", "safebrowsing.apple", "apple",
    ]

    public static func contains(_ host: String) -> Bool {
        Domain.firstMatch(of: host, in: registrable) != nil
    }
}
