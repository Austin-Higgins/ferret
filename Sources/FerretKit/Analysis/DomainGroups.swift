import Foundation
import FerretParsers

/// Traffic list filters: search plus the two toggles from the spec.
public struct TrafficFilter: Hashable, Codable, Sendable {
    public var searchText = ""
    /// Show only DNS lookups.
    public var dnsOnly = false
    /// Hide Apple's own services.
    public var hideApple = false
    /// If non-empty, only groups carrying one of these tags.
    public var tags: Set<ProtocolTag> = []

    public init(searchText: String = "", dnsOnly: Bool = false, hideApple: Bool = false, tags: Set<ProtocolTag> = []) {
        self.searchText = searchText
        self.dnsOnly = dnsOnly
        self.hideApple = hideApple
        self.tags = tags
    }
}

/// Connections and DNS lookups grouped under one registrable domain.
public struct DomainGroup: Identifiable, Hashable, Sendable {
    /// Registrable domain, or the bare IP address when there is no name.
    public var domain: String
    public var hosts: [String]
    public var connectionIDs: [Int]
    public var lookupIDs: [Int]
    public var tags: Set<ProtocolTag>
    public var packets: Int
    public var bytes: Int
    public var firstSeen: CaptureTimestamp
    public var lastSeen: CaptureTimestamp
    public var isApple: Bool
    public var tracker: TrackerEntry?

    public var id: String { domain }
    public var isAddressOnly: Bool { Domain.isIPAddress(domain) }
}

public enum DomainGrouper {
    public static func groups(
        connections: [Connection], lookups: [DNSLookup], filter: TrafficFilter = TrafficFilter(),
        psl: PublicSuffixList = .shared, trackers: TrackerList = .bundled
    ) -> [DomainGroup] {
        var groups: [String: DomainGroup] = [:]

        func add(host: String?, fallback: String, at time: CaptureTimestamp, _ update: (inout DomainGroup) -> Void) {
            let name = host.map(Domain.normalize)
            let key = name.flatMap { psl.registrableDomain(of: $0) } ?? name ?? fallback
            var g = groups[key] ?? DomainGroup(
                domain: key, hosts: [], connectionIDs: [], lookupIDs: [], tags: [], packets: 0, bytes: 0,
                firstSeen: time, lastSeen: time, isApple: AppleDomains.contains(key), tracker: nil)
            if let name, !g.hosts.contains(name) {
                g.hosts.append(name)
                if g.tracker == nil { g.tracker = trackers.match(name) }
                if !g.isApple { g.isApple = AppleDomains.contains(name) }
            }
            g.firstSeen = min(g.firstSeen, time)
            g.lastSeen = max(g.lastSeen, time)
            update(&g)
            groups[key] = g
        }

        if !filter.dnsOnly {
            for c in connections where !c.tags.contains(.dns) {
                add(host: c.host, fallback: c.key.remote.address.description, at: c.firstSeen) { g in
                    g.connectionIDs.append(c.id)
                    g.tags.formUnion(c.tags)
                    g.packets += c.packets
                    g.bytes += c.bytes
                    g.lastSeen = max(g.lastSeen, c.lastSeen)
                }
            }
        }
        for l in lookups {
            add(host: l.name, fallback: l.name, at: l.queriedAt) { g in
                g.lookupIDs.append(l.id)
                g.tags.insert(.dns)
            }
        }

        let query = filter.searchText.trimmingCharacters(in: .whitespaces).lowercased()
        return groups.values
            .filter { g in
                if filter.hideApple && g.isApple { return false }
                if !filter.tags.isEmpty && g.tags.isDisjoint(with: filter.tags) { return false }
                if !query.isEmpty {
                    return g.domain.contains(query) || g.hosts.contains { $0.contains(query) }
                        || (g.tracker?.organisation.lowercased().contains(query) ?? false)
                }
                return true
            }
            .sorted { a, b in a.lastSeen == b.lastSeen ? a.domain < b.domain : a.lastSeen > b.lastSeen }
    }
}

/// How often the phone contacted a tracker domain.
public enum ContactFrequency: String, CaseIterable, Sendable {
    case frequent = "Frequent"
    case occasional = "Occasional"
    case rare = "Once or twice"

    init(count: Int) {
        switch count {
        case 10...: self = .frequent
        case 3...: self = .occasional
        default: self = .rare
        }
    }
}

public struct Suspect: Identifiable, Hashable, Sendable {
    public var domain: String
    public var hosts: [String]
    public var tracker: TrackerEntry
    /// Connections plus DNS lookups.
    public var contacts: Int
    public var bytes: Int
    public var firstSeen: CaptureTimestamp
    public var lastSeen: CaptureTimestamp

    public var id: String { domain }
    public var frequency: ContactFrequency { ContactFrequency(count: contacts) }

    /// Spec rule: say the phone contacted it; never name an app.
    public var sentence: String { FerretCopy.suspectSentence(domain: domain, contacts: contacts) }
}

public enum SuspectsReport {
    public static func suspects(from groups: [DomainGroup]) -> [Suspect] {
        groups.compactMap { g -> Suspect? in
            guard let tracker = g.tracker else { return nil }
            return Suspect(
                domain: g.domain, hosts: g.hosts, tracker: tracker,
                contacts: g.connectionIDs.count + g.lookupIDs.count, bytes: g.bytes,
                firstSeen: g.firstSeen, lastSeen: g.lastSeen)
        }
        .sorted { a, b in a.contacts == b.contacts ? a.domain < b.domain : a.contacts > b.contacts }
    }

    /// Suspects bucketed by frequency, most frequent first.
    public static func grouped(_ suspects: [Suspect]) -> [(ContactFrequency, [Suspect])] {
        ContactFrequency.allCases.compactMap { f in
            let items = suspects.filter { $0.frequency == f }
            return items.isEmpty ? nil : (f, items)
        }
    }
}
