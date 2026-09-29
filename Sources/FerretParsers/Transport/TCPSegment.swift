/// TCP header flags, laid out like Wireshark's 12-bit `tcp.flags` field.
public struct TCPFlags: OptionSet, Hashable, Sendable, CustomStringConvertible {
    public let rawValue: UInt16
    public init(rawValue: UInt16) { self.rawValue = rawValue }

    public static let fin = TCPFlags(rawValue: 0x001)
    public static let syn = TCPFlags(rawValue: 0x002)
    public static let rst = TCPFlags(rawValue: 0x004)
    public static let psh = TCPFlags(rawValue: 0x008)
    public static let ack = TCPFlags(rawValue: 0x010)
    public static let urg = TCPFlags(rawValue: 0x020)
    public static let ece = TCPFlags(rawValue: 0x040)
    public static let cwr = TCPFlags(rawValue: 0x080)
    public static let ae = TCPFlags(rawValue: 0x100)

    /// Flag names in Wireshark's order, e.g. `[PSH, ACK]`.
    public var description: String {
        let names: [(TCPFlags, String)] = [
            (.fin, "FIN"), (.syn, "SYN"), (.rst, "RST"), (.psh, "PSH"),
            (.ack, "ACK"), (.urg, "URG"), (.ece, "ECE"), (.cwr, "CWR"), (.ae, "AE"),
        ]
        return "[" + names.filter { contains($0.0) }.map(\.1).joined(separator: ", ") + "]"
    }
}

public enum TCPOption: Hashable, Sendable {
    case maximumSegmentSize(UInt16)
    case windowScale(UInt8)
    case sackPermitted
    case sack([ClosedRange<UInt32>])
    case timestamps(value: UInt32, echoReply: UInt32)
    case other(kind: UInt8, data: [UInt8])
}

public struct TCPSegment: Sendable {
    public var sourcePort: UInt16
    public var destinationPort: UInt16
    public var sequenceNumber: UInt32
    public var acknowledgmentNumber: UInt32
    public var headerLength: Int
    public var flags: TCPFlags
    public var window: UInt16
    public var checksum: UInt16
    public var urgentPointer: UInt16
    public var options: [TCPOption]
    public var payload: ArraySlice<UInt8>

    public static func parse(_ bytes: ArraySlice<UInt8>) throws -> TCPSegment {
        var r = ByteReader(bytes)
        let src = try r.readU16()
        let dst = try r.readU16()
        let seq = try r.readU32()
        let ack = try r.readU32()
        let offsetByte = try r.readU8()
        let flagByte = try r.readU8()
        let headerLength = Int(offsetByte >> 4) * 4
        guard headerLength >= 20 else { throw ParseError.malformed("TCP header length \(headerLength)") }
        guard bytes.count >= headerLength else { throw ParseError.truncated }
        let window = try r.readU16()
        let checksum = try r.readU16()
        let urgent = try r.readU16()
        let optionBytes = try r.readBytes(headerLength - 20)
        return TCPSegment(
            sourcePort: src, destinationPort: dst, sequenceNumber: seq, acknowledgmentNumber: ack,
            headerLength: headerLength,
            flags: TCPFlags(rawValue: UInt16(offsetByte & 0x0F) << 8 | UInt16(flagByte)),
            window: window, checksum: checksum, urgentPointer: urgent,
            options: parseOptions(optionBytes),
            payload: bytes[(bytes.startIndex + headerLength)...]
        )
    }

    static func parseOptions(_ bytes: ArraySlice<UInt8>) -> [TCPOption] {
        var r = ByteReader(bytes)
        var out: [TCPOption] = []
        while !r.isAtEnd {
            guard let kind = try? r.readU8() else { break }
            if kind == 0 { break }
            if kind == 1 { continue }
            guard let len = try? r.readU8(), len >= 2, let data = try? r.readBytes(Int(len) - 2) else { break }
            var d = ByteReader(data)
            switch (kind, len) {
            case (2, 4): out.append(.maximumSegmentSize((try? d.readU16()) ?? 0))
            case (3, 3): out.append(.windowScale((try? d.readU8()) ?? 0))
            case (4, 2): out.append(.sackPermitted)
            case (5, _):
                var blocks: [ClosedRange<UInt32>] = []
                while d.remaining >= 8, let l = try? d.readU32(), let rr = try? d.readU32() {
                    blocks.append(l...max(l, rr))
                }
                out.append(.sack(blocks))
            case (8, 10):
                let v = (try? d.readU32()) ?? 0
                let e = (try? d.readU32()) ?? 0
                out.append(.timestamps(value: v, echoReply: e))
            default:
                out.append(.other(kind: kind, data: Array(data)))
            }
        }
        return out
    }
}

public struct UDPDatagram: Sendable {
    public var sourcePort: UInt16
    public var destinationPort: UInt16
    public var length: Int
    public var checksum: UInt16
    public var payload: ArraySlice<UInt8>

    public static func parse(_ bytes: ArraySlice<UInt8>) throws -> UDPDatagram {
        var r = ByteReader(bytes)
        let src = try r.readU16()
        let dst = try r.readU16()
        let len = Int(try r.readU16())
        let sum = try r.readU16()
        guard len >= 8 || len == 0 else { throw ParseError.malformed("UDP length \(len)") }
        let end = len == 0 ? bytes.count : min(len, bytes.count)
        return UDPDatagram(
            sourcePort: src, destinationPort: dst, length: len, checksum: sum,
            payload: bytes[(bytes.startIndex + 8)..<(bytes.startIndex + max(8, end))]
        )
    }
}

public struct ICMPMessage: Sendable {
    public var isV6: Bool
    public var type: UInt8
    public var code: UInt8
    public var checksum: UInt16
    public var body: ArraySlice<UInt8>

    public static func parse(_ bytes: ArraySlice<UInt8>, isV6: Bool) throws -> ICMPMessage {
        var r = ByteReader(bytes)
        let type = try r.readU8()
        let code = try r.readU8()
        let sum = try r.readU16()
        return ICMPMessage(isV6: isV6, type: type, code: code, checksum: sum, body: r.rest)
    }

    public var summary: String {
        switch (isV6, type) {
        case (false, 0), (true, 129): return "Echo reply"
        case (false, 8), (true, 128): return "Echo request"
        case (false, 3), (true, 1): return "Destination unreachable"
        case (false, 11), (true, 3): return "Time exceeded"
        case (true, 133): return "Router solicitation"
        case (true, 134): return "Router advertisement"
        case (true, 135): return "Neighbor solicitation"
        case (true, 136): return "Neighbor advertisement"
        case (true, 143): return "Multicast listener report v2"
        default: return "Type \(type), code \(code)"
        }
    }
}
