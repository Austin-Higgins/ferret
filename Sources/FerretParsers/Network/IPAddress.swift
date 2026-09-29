import Foundation

/// An IPv4 or IPv6 address.
public enum IPAddress: Hashable, Sendable, Comparable, CustomStringConvertible {
    case v4(UInt32)
    case v6(UInt64, UInt64)

    public init?<C: Collection>(bytes: C) where C.Element == UInt8 {
        let b = Array(bytes)
        switch b.count {
        case 4:
            self = .v4(UInt32(b[0]) << 24 | UInt32(b[1]) << 16 | UInt32(b[2]) << 8 | UInt32(b[3]))
        case 16:
            var hi: UInt64 = 0, lo: UInt64 = 0
            for i in 0..<8 { hi = hi << 8 | UInt64(b[i]) }
            for i in 8..<16 { lo = lo << 8 | UInt64(b[i]) }
            self = .v6(hi, lo)
        default:
            return nil
        }
    }

    /// Parses dotted-quad IPv4 or RFC 4291 IPv6 text.
    public init?(_ string: String) {
        if string.contains(":") {
            guard let bytes = IPAddress.parseV6(string) else { return nil }
            self.init(bytes: bytes)
        } else {
            let parts = string.split(separator: ".", omittingEmptySubsequences: false)
            guard parts.count == 4 else { return nil }
            var bytes: [UInt8] = []
            for p in parts {
                guard !p.isEmpty, p.count <= 3, let v = UInt8(p) else { return nil }
                bytes.append(v)
            }
            self.init(bytes: bytes)
        }
    }

    public var isV4: Bool {
        if case .v4 = self { return true }
        return false
    }

    public var bytes: [UInt8] {
        switch self {
        case .v4(let v):
            return [UInt8(v >> 24), UInt8((v >> 16) & 0xFF), UInt8((v >> 8) & 0xFF), UInt8(v & 0xFF)]
        case .v6(let hi, let lo):
            var out: [UInt8] = []
            out.reserveCapacity(16)
            for shift in stride(from: 56, through: 0, by: -8) { out.append(UInt8((hi >> UInt64(shift)) & 0xFF)) }
            for shift in stride(from: 56, through: 0, by: -8) { out.append(UInt8((lo >> UInt64(shift)) & 0xFF)) }
            return out
        }
    }

    /// RFC 5952 canonical text, which is also how Wireshark prints addresses.
    public var description: String {
        switch self {
        case .v4:
            return bytes.map(String.init).joined(separator: ".")
        case .v6:
            let b = bytes
            var groups: [UInt16] = []
            for i in stride(from: 0, to: 16, by: 2) { groups.append(UInt16(b[i]) << 8 | UInt16(b[i + 1])) }
            // Find the longest run of zero groups (length >= 2); first one wins ties.
            var bestStart = -1, bestLen = 0, curStart = -1, curLen = 0
            for (i, g) in groups.enumerated() {
                if g == 0 {
                    if curStart < 0 { curStart = i; curLen = 0 }
                    curLen += 1
                    if curLen > bestLen { bestStart = curStart; bestLen = curLen }
                } else {
                    curStart = -1; curLen = 0
                }
            }
            if bestLen < 2 { bestStart = -1 }
            // IPv4-mapped addresses print the tail as dotted quad.
            if groups[0..<5].allSatisfy({ $0 == 0 }) && groups[5] == 0xFFFF {
                return "::ffff:" + b[12..<16].map(String.init).joined(separator: ".")
            }
            var parts: [String] = []
            var i = 0
            var out = ""
            while i < 8 {
                if i == bestStart {
                    out += parts.joined(separator: ":") + "::"
                    parts = []
                    i += bestLen
                    continue
                }
                parts.append(String(groups[i], radix: 16))
                i += 1
            }
            out += parts.joined(separator: ":")
            return out
        }
    }

    public static func < (lhs: IPAddress, rhs: IPAddress) -> Bool {
        switch (lhs, rhs) {
        case (.v4(let a), .v4(let b)): return a < b
        case (.v4, .v6): return true
        case (.v6, .v4): return false
        case (.v6(let ah, let al), .v6(let bh, let bl)): return ah == bh ? al < bl : ah < bh
        }
    }

    /// True for RFC 1918, loopback, link-local and unique-local ranges.
    public var isPrivate: Bool {
        switch self {
        case .v4(let v):
            let a = v >> 24, b = (v >> 16) & 0xFF
            return a == 10 || a == 127 || (a == 172 && (16...31).contains(b)) || (a == 192 && b == 168)
                || (a == 169 && b == 254) || (a == 100 && (64...127).contains(b))
        case .v6(let hi, let lo):
            let top = hi >> 48
            return (hi == 0 && lo == 1) || (top & 0xFE00) == 0xFC00 || (top & 0xFFC0) == 0xFE80
        }
    }

    public var isMulticast: Bool {
        switch self {
        case .v4(let v): return (v >> 28) == 0xE
        case .v6(let hi, _): return (hi >> 56) == 0xFF
        }
    }

    private static func parseV6(_ s: String) -> [UInt8]? {
        var text = Substring(s)
        var tailV4: [UInt8] = []
        if let lastColon = text.lastIndex(of: ":"), text[lastColon...].contains(".") {
            guard let v4 = IPAddress(String(text[text.index(after: lastColon)...])) else { return nil }
            tailV4 = v4.bytes
            text = text[...lastColon]
            if text.hasSuffix(":") && !text.hasSuffix("::") { text = text.dropLast() }
        }
        let halves = text.components(separatedBy: "::")
        guard halves.count <= 2 else { return nil }
        func groups(_ part: String) -> [UInt16]? {
            if part.isEmpty { return [] }
            var out: [UInt16] = []
            for g in part.split(separator: ":", omittingEmptySubsequences: false) {
                guard !g.isEmpty, g.count <= 4, let v = UInt16(g, radix: 16) else { return nil }
                out.append(v)
            }
            return out
        }
        guard let head = groups(halves[0]) else { return nil }
        let tail = halves.count == 2 ? groups(halves[1]) : []
        guard let tail else { return nil }
        let needed = 8 - tailV4.count / 2
        var all: [UInt16]
        if halves.count == 2 {
            let fill = needed - head.count - tail.count
            guard fill >= 1 else { return nil }
            all = head + Array(repeating: 0, count: fill) + tail
        } else {
            all = head
        }
        guard all.count == needed else { return nil }
        var bytes: [UInt8] = []
        for g in all { bytes.appendU16(g) }
        return bytes + tailV4
    }
}

extension IPAddress: Codable {
    public init(from decoder: Decoder) throws {
        let text = try decoder.singleValueContainer().decode(String.self)
        guard let address = IPAddress(text) else {
            throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "Invalid IP address \(text)"))
        }
        self = address
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(description)
    }
}
