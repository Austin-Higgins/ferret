import FerretParsers
import Foundation

/// A labelled window from a sniff test: close other apps, use one app for
/// 30 seconds, and label the window with that app's name. iOS doesn't tell VPN
/// apps which app opened a connection, so this guided experiment stands in for
/// per-app attribution. Results are about the window, never proof about the app.
public struct SniffWindow: Codable, Hashable, Sendable {
    public var label: String
    public var start: CaptureTimestamp
    public var end: CaptureTimestamp

    public init(label: String, start: CaptureTimestamp, end: CaptureTimestamp) {
        self.label = label
        self.start = start
        self.end = end
    }

    public static let defaultDuration: TimeInterval = 30

    public func contains(_ t: CaptureTimestamp) -> Bool { t >= start && t <= end }
}

public struct SniffTestResult: Sendable {
    public var window: SniffWindow
    /// Domains whose first contact in the whole capture falls inside the window.
    public var firstContacted: [DomainGroup]
    /// Domains also active in the window but already seen before it started.
    public var alsoActive: [DomainGroup]

    public var trackers: [DomainGroup] { firstContacted.filter { $0.tracker != nil } }
}

public enum SniffTest {
    public static func evaluate(
        window: SniffWindow, connections: [Connection], lookups: [DNSLookup],
        psl: PublicSuffixList = .shared, trackers: TrackerList = .bundled
    ) -> SniffTestResult {
        let groups = DomainGrouper.groups(connections: connections, lookups: lookups, psl: psl, trackers: trackers)
        var first: [DomainGroup] = []
        var also: [DomainGroup] = []
        for g in groups {
            if window.contains(g.firstSeen) {
                first.append(g)
            } else if g.firstSeen < window.start && g.lastSeen >= window.start && Self.active(g, in: window, connections: connections, lookups: lookups) {
                also.append(g)
            }
        }
        let byTime: (DomainGroup, DomainGroup) -> Bool = { a, b in
            a.firstSeen == b.firstSeen ? a.domain < b.domain : a.firstSeen < b.firstSeen
        }
        return SniffTestResult(window: window, firstContacted: first.sorted(by: byTime), alsoActive: also.sorted { $0.domain < $1.domain })
    }

    /// True if any connection or lookup of the group had traffic inside the window.
    static func active(_ g: DomainGroup, in window: SniffWindow, connections: [Connection], lookups: [DNSLookup]) -> Bool {
        for id in g.connectionIDs where connections.indices.contains(id) {
            let c = connections[id]
            if c.samples.contains(where: { window.contains($0.timestamp) }) { return true }
            if c.firstSeen <= window.end && c.lastSeen >= window.start && c.samples.isEmpty { return true }
        }
        for id in g.lookupIDs where lookups.indices.contains(id) {
            if window.contains(lookups[id].queriedAt) { return true }
        }
        return false
    }
}
