/// IANA protocol numbers Ferret cares about.
public enum IPProtocolNumber {
    public static let icmp: UInt8 = 1
    public static let tcp: UInt8 = 6
    public static let udp: UInt8 = 17
    public static let icmpv6: UInt8 = 58
    public static let noNextHeader: UInt8 = 59

    public static func name(_ n: UInt8) -> String {
        switch n {
        case 0: return "IPv6 Hop-by-Hop"
        case icmp: return "ICMP"
        case 2: return "IGMP"
        case tcp: return "TCP"
        case udp: return "UDP"
        case 41: return "IPv6"
        case 43: return "IPv6 Routing"
        case 44: return "IPv6 Fragment"
        case 50: return "ESP"
        case 51: return "AH"
        case icmpv6: return "ICMPv6"
        case noNextHeader: return "No Next Header"
        case 60: return "IPv6 Destination Options"
        case 132: return "SCTP"
        default: return "Protocol \(n)"
        }
    }
}

/// A parsed IPv4 or IPv6 header. `payload` is trimmed to the length the header declares.
public struct IPPacket: Sendable {
    public var version: Int
    public var source: IPAddress
    public var destination: IPAddress
    /// The upper-layer protocol after any IPv6 extension headers.
    public var protocolNumber: UInt8
    /// The protocol or next-header value in the fixed header itself.
    public var headerNextHeader: UInt8
    /// Header bytes including IPv6 extension headers.
    public var headerLength: Int
    /// Total datagram length as declared in the header.
    public var totalLength: Int
    public var ttl: UInt8
    public var trafficClass: UInt8
    public var identification: UInt16?
    public var flowLabel: UInt32?
    public var dontFragment: Bool
    public var moreFragments: Bool
    public var fragmentOffset: Int
    public var headerChecksum: UInt16?
    public var headerChecksumValid: Bool?
    public var payload: ArraySlice<UInt8>

    public var isFragment: Bool { moreFragments || fragmentOffset != 0 }

    public static func parse(_ bytes: ArraySlice<UInt8>) throws -> IPPacket {
        guard let first = bytes.first else { throw ParseError.truncated }
        switch first >> 4 {
        case 4: return try parseV4(bytes)
        case 6: return try parseV6(bytes)
        default: throw ParseError.unsupported("IP version \(first >> 4)")
        }
    }

    public static func parse(_ bytes: [UInt8]) throws -> IPPacket {
        try parse(bytes[...])
    }

    private static func parseV4(_ bytes: ArraySlice<UInt8>) throws -> IPPacket {
        var r = ByteReader(bytes)
        let vihl = try r.readU8()
        let ihl = Int(vihl & 0x0F) * 4
        guard ihl >= 20 else { throw ParseError.malformed("IPv4 header length \(ihl)") }
        let tos = try r.readU8()
        let total = Int(try r.readU16())
        let ident = try r.readU16()
        let flagsFrag = try r.readU16()
        let ttl = try r.readU8()
        let proto = try r.readU8()
        let checksum = try r.readU16()
        let src = IPAddress(bytes: try r.readBytes(4))!
        let dst = IPAddress(bytes: try r.readBytes(4))!
        guard bytes.count >= ihl else { throw ParseError.truncated }
        // Captures may be truncated (snaplen) or padded (Ethernet minimum frame).
        let end = min(max(total, ihl), bytes.count)
        let header = bytes[bytes.startIndex..<(bytes.startIndex + ihl)]
        let valid = InternetChecksum.checksum(header) == 0
        return IPPacket(
            version: 4, source: src, destination: dst, protocolNumber: proto, headerNextHeader: proto,
            headerLength: ihl, totalLength: total, ttl: ttl, trafficClass: tos,
            identification: ident, flowLabel: nil,
            dontFragment: flagsFrag & 0x4000 != 0, moreFragments: flagsFrag & 0x2000 != 0,
            fragmentOffset: Int(flagsFrag & 0x1FFF) * 8,
            headerChecksum: checksum, headerChecksumValid: valid,
            payload: bytes[(bytes.startIndex + ihl)..<(bytes.startIndex + end)]
        )
    }

    private static func parseV6(_ bytes: ArraySlice<UInt8>) throws -> IPPacket {
        var r = ByteReader(bytes)
        let word = try r.readU32()
        let payloadLength = Int(try r.readU16())
        var next = try r.readU8()
        let firstNext = next
        let hopLimit = try r.readU8()
        let src = IPAddress(bytes: try r.readBytes(16))!
        let dst = IPAddress(bytes: try r.readBytes(16))!
        var moreFragments = false
        var fragmentOffset = 0
        var ident: UInt16?
        // Walk extension headers so protocolNumber names the real upper layer.
        extensionLoop: while true {
            switch next {
            case 0, 43, 60:
                let nh = try r.readU8()
                let len = (Int(try r.readU8()) + 1) * 8
                try r.skip(len - 2)
                next = nh
            case 44:
                let nh = try r.readU8()
                try r.skip(1)
                let off = try r.readU16()
                let id = try r.readU32()
                fragmentOffset = Int(off >> 3) * 8
                moreFragments = off & 1 != 0
                ident = UInt16(truncatingIfNeeded: id)
                next = nh
            case 51:
                let nh = try r.readU8()
                let len = (Int(try r.readU8()) + 2) * 4
                try r.skip(len - 2)
                next = nh
            default:
                break extensionLoop
            }
        }
        let headerLength = r.offset
        let end = min(40 + payloadLength, bytes.count)
        guard end >= headerLength else { throw ParseError.truncated }
        return IPPacket(
            version: 6, source: src, destination: dst, protocolNumber: next, headerNextHeader: firstNext,
            headerLength: headerLength, totalLength: 40 + payloadLength, ttl: hopLimit,
            trafficClass: UInt8((word >> 20) & 0xFF),
            identification: ident, flowLabel: word & 0xFFFFF,
            dontFragment: false, moreFragments: moreFragments, fragmentOffset: fragmentOffset,
            headerChecksum: nil, headerChecksumValid: nil,
            payload: bytes[(bytes.startIndex + headerLength)..<(bytes.startIndex + end)]
        )
    }
}

/// Builds IP headers for packets the tunnel synthesises (UDP replies, ICMP errors).
public enum IPPacketBuilder {
    public static func ipv4Header(
        source: IPAddress, destination: IPAddress, protocolNumber: UInt8,
        payloadLength: Int, ttl: UInt8 = 64, identification: UInt16 = 0
    ) -> [UInt8] {
        var h: [UInt8] = [0x45, 0]
        h.appendU16(UInt16(20 + payloadLength))
        h.appendU16(identification)
        h.appendU16(0x4000)
        h.append(ttl)
        h.append(protocolNumber)
        h.appendU16(0)
        h.append(contentsOf: source.bytes)
        h.append(contentsOf: destination.bytes)
        let sum = InternetChecksum.checksum(h)
        h[10] = UInt8(sum >> 8)
        h[11] = UInt8(sum & 0xFF)
        return h
    }

    public static func ipv6Header(
        source: IPAddress, destination: IPAddress, nextHeader: UInt8,
        payloadLength: Int, hopLimit: UInt8 = 64
    ) -> [UInt8] {
        var h: [UInt8] = [0x60, 0, 0, 0]
        h.appendU16(UInt16(payloadLength))
        h.append(nextHeader)
        h.append(hopLimit)
        h.append(contentsOf: source.bytes)
        h.append(contentsOf: destination.bytes)
        return h
    }

    /// A complete IPv4 or IPv6 UDP datagram with a valid checksum.
    public static func udpPacket(
        source: IPAddress, sourcePort: UInt16,
        destination: IPAddress, destinationPort: UInt16,
        payload: [UInt8]
    ) -> [UInt8] {
        var udp: [UInt8] = []
        udp.appendU16(sourcePort)
        udp.appendU16(destinationPort)
        udp.appendU16(UInt16(8 + payload.count))
        udp.appendU16(0)
        udp.append(contentsOf: payload)
        var sum = InternetChecksum.transportChecksum(
            source: source, destination: destination, protocolNumber: IPProtocolNumber.udp, segment: udp)
        if sum == 0 { sum = 0xFFFF }
        udp[6] = UInt8(sum >> 8)
        udp[7] = UInt8(sum & 0xFF)
        let header = source.isV4
            ? ipv4Header(source: source, destination: destination, protocolNumber: IPProtocolNumber.udp, payloadLength: udp.count)
            : ipv6Header(source: source, destination: destination, nextHeader: IPProtocolNumber.udp, payloadLength: udp.count)
        return header + udp
    }
}
