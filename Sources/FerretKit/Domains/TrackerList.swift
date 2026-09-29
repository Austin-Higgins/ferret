import Foundation

public struct TrackerEntry: Hashable, Sendable, Codable {
    public var domain: String
    public var organisation: String
    public var category: String
}

/// A domain list used by the Suspects view. Matches a host and all its parents.
/// Suspects only ever says the phone contacted a domain, never which app did.
public final class TrackerList: @unchecked Sendable {
    private let entries: [String: TrackerEntry]
    private let domains: Set<String>

    public static let bundled: TrackerList = {
        guard let url = Bundle.module.url(forResource: "trackers", withExtension: "tsv"),
              let text = try? String(contentsOf: url, encoding: .utf8) else {
            return TrackerList(entries: [])
        }
        return TrackerList(tsv: text)
    }()

    public init(entries: [TrackerEntry]) {
        var map: [String: TrackerEntry] = [:]
        for e in entries { map[Domain.normalize(e.domain)] = e }
        self.entries = map
        self.domains = Set(map.keys)
    }

    /// Parses `domain<TAB>organisation<TAB>category` lines; `#` starts a comment.
    public convenience init(tsv: String) {
        var entries: [TrackerEntry] = []
        for line in tsv.split(whereSeparator: \.isNewline) where !line.hasPrefix("#") {
            let cols = line.split(separator: "\t", omittingEmptySubsequences: false).map {
                $0.trimmingCharacters(in: .whitespaces)
            }
            guard let domain = cols.first, !domain.isEmpty else { continue }
            entries.append(TrackerEntry(
                domain: domain,
                organisation: cols.count > 1 ? cols[1] : "",
                category: cols.count > 2 ? cols[2] : "tracking"))
        }
        self.init(entries: entries)
    }

    /// Accepts hosts-file lines (`0.0.0.0 example.com`) or bare domains.
    public convenience init(hostsFile: String, organisation: String = "", category: String = "tracking") {
        var entries: [TrackerEntry] = []
        for raw in hostsFile.split(whereSeparator: \.isNewline) {
            let line = raw.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false)[0]
            let parts = line.split(whereSeparator: { $0 == " " || $0 == "\t" })
            guard let domain = parts.last.map(String.init), domain.contains("."), !Domain.isIPAddress(domain) else { continue }
            if domain == "localhost" || domain.hasSuffix(".localdomain") { continue }
            entries.append(TrackerEntry(domain: domain, organisation: organisation, category: category))
        }
        self.init(entries: entries)
    }

    public var count: Int { entries.count }

    public func match(_ host: String) -> TrackerEntry? {
        guard let key = Domain.firstMatch(of: host, in: domains) else { return nil }
        return entries[key]
    }
}
