/// pcap/pcapng link-layer header types (https://www.tcpdump.org/linktypes.html).
public struct LinkType: RawRepresentable, Hashable, Sendable, CustomStringConvertible {
    public var rawValue: UInt32
    public init(rawValue: UInt32) { self.rawValue = rawValue }

    public static let null = LinkType(rawValue: 0)
    public static let ethernet = LinkType(rawValue: 1)
    public static let raw = LinkType(rawValue: 101)
    public static let loop = LinkType(rawValue: 108)
    public static let linuxSLL = LinkType(rawValue: 113)
    public static let ipv4 = LinkType(rawValue: 228)
    public static let ipv6 = LinkType(rawValue: 229)
    public static let linuxSLL2 = LinkType(rawValue: 276)

    public var description: String {
        switch self {
        case .null: return "BSD loopback"
        case .ethernet: return "Ethernet"
        case .raw: return "Raw IP"
        case .loop: return "OpenBSD loopback"
        case .linuxSLL: return "Linux cooked"
        case .ipv4: return "Raw IPv4"
        case .ipv6: return "Raw IPv6"
        case .linuxSLL2: return "Linux cooked v2"
        default: return "Link type \(rawValue)"
        }
    }
}

public enum LinkLayer {
    /// Returns the byte offset where the IP header starts, or nil if the frame
    /// does not carry IPv4/IPv6.
    public static func ipOffset(in frame: ArraySlice<UInt8>, linkType: LinkType) -> Int? {
        var r = ByteReader(frame)
        do {
            switch linkType {
            case .raw, .ipv4, .ipv6:
                return 0
            case .null, .loop:
                // 4-byte address family in host (null) or network (loop) byte order.
                guard frame.count >= 4 else { return nil }
                return 4
            case .ethernet:
                try r.skip(12)
                var etherType = try r.readU16()
                while etherType == 0x8100 || etherType == 0x88A8 || etherType == 0x9100 {
                    try r.skip(2)
                    etherType = try r.readU16()
                }
                return (etherType == 0x0800 || etherType == 0x86DD) ? r.offset : nil
            case .linuxSLL:
                try r.skip(14)
                let proto = try r.readU16()
                return (proto == 0x0800 || proto == 0x86DD) ? 16 : nil
            case .linuxSLL2:
                let proto = try r.readU16()
                return (proto == 0x0800 || proto == 0x86DD) ? 20 : nil
            default:
                return nil
            }
        } catch {
            return nil
        }
    }

    /// The IP datagram inside a link-layer frame.
    public static func ipPayload(of frame: ArraySlice<UInt8>, linkType: LinkType) -> ArraySlice<UInt8>? {
        guard let offset = ipOffset(in: frame, linkType: linkType), offset <= frame.count else { return nil }
        return frame[(frame.startIndex + offset)...]
    }
}
