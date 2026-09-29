import Foundation

/// Before/after comparison of two captures by registrable domain.
public struct CaptureDiff: Sendable {
    public struct Change: Identifiable, Hashable, Sendable {
        public var domain: String
        public var before: DomainGroup
        public var after: DomainGroup

        public var id: String { domain }
        public var contactsBefore: Int { before.connectionIDs.count + before.lookupIDs.count }
        public var contactsAfter: Int { after.connectionIDs.count + after.lookupIDs.count }
        public var bytesDelta: Int { after.bytes - before.bytes }
    }

    /// Present only in the first capture.
    public var onlyBefore: [DomainGroup]
    /// Present only in the second capture.
    public var onlyAfter: [DomainGroup]
    /// Present in both, most-changed first.
    public var inBoth: [Change]

    public static func compare(before: [DomainGroup], after: [DomainGroup]) -> CaptureDiff {
        let a = Dictionary(before.map { ($0.domain, $0) }, uniquingKeysWith: { x, _ in x })
        let b = Dictionary(after.map { ($0.domain, $0) }, uniquingKeysWith: { x, _ in x })
        let contacts: (DomainGroup) -> Int = { $0.connectionIDs.count + $0.lookupIDs.count }
        let order: (DomainGroup, DomainGroup) -> Bool = { x, y in
            contacts(x) == contacts(y) ? x.domain < y.domain : contacts(x) > contacts(y)
        }
        let onlyBefore = a.keys.filter { b[$0] == nil }.compactMap { a[$0] }.sorted(by: order)
        let onlyAfter = b.keys.filter { a[$0] == nil }.compactMap { b[$0] }.sorted(by: order)
        let both = a.keys.filter { b[$0] != nil }.map { Change(domain: $0, before: a[$0]!, after: b[$0]!) }
            .sorted { x, y in
                let dx = abs(x.contactsAfter - x.contactsBefore), dy = abs(y.contactsAfter - y.contactsBefore)
                return dx == dy ? x.domain < y.domain : dx > dy
            }
        return CaptureDiff(onlyBefore: onlyBefore, onlyAfter: onlyAfter, inBoth: both)
    }
}
