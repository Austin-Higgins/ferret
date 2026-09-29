import Foundation

/// pcapng reader (https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-02.html).
/// Handles SHB, IDB, EPB, SPB and the obsolete Packet Block, in either byte order.
public enum PcapNGReader {
    struct Interface {
        var linkType: LinkType
        var snapLength: UInt32
        /// Timestamp units per second.
        var unitsPerSecond: UInt64
        var offsetSeconds: Int64
    }

    public static func read(_ bytes: [UInt8]) throws -> [CaptureRecord] {
        var records: [CaptureRecord] = []
        var interfaces: [Interface] = []
        var littleEndian = true
        var offset = 0
        while bytes.count - offset >= 12 {
            // Block type and length need the section byte order, which the SHB itself declares.
            let typeLE = UInt32(bytes[offset]) | UInt32(bytes[offset + 1]) << 8 | UInt32(bytes[offset + 2]) << 16 | UInt32(bytes[offset + 3]) << 24
            if typeLE == 0x0A0D0D0A {
                let bom = Array(bytes[(offset + 8)..<(offset + 12)])
                if bom == [0x4D, 0x3C, 0x2B, 0x1A] { littleEndian = true }
                else if bom == [0x1A, 0x2B, 0x3C, 0x4D] { littleEndian = false }
                else { throw ParseError.malformed("pcapng byte-order magic") }
                interfaces = []
            }
            var r = EndianReader(bytes: bytes, offset: offset, littleEndian: littleEndian)
            let type = try r.u32()
            let length = Int(try r.u32())
            guard length >= 12, length % 4 == 0, offset + length <= bytes.count else {
                throw ParseError.malformed("pcapng block length \(length)")
            }
            let bodyEnd = offset + length - 4
            switch type {
            case 0x0000_0001:
                let linkType = LinkType(rawValue: UInt32(try r.u16()))
                _ = try r.u16()
                let snap = try r.u32()
                var iface = Interface(linkType: linkType, snapLength: snap, unitsPerSecond: 1_000_000, offsetSeconds: 0)
                for (code, value) in try options(&r, end: bodyEnd) {
                    if code == 9, let v = value.first {
                        if v & 0x80 == 0 {
                            var u: UInt64 = 1
                            for _ in 0..<Int(v) { u = u &* 10 }
                            iface.unitsPerSecond = u
                        } else {
                            iface.unitsPerSecond = 1 << UInt64(v & 0x7F)
                        }
                    } else if code == 14, value.count == 8 {
                        var o = EndianReader(bytes: value, offset: 0, littleEndian: littleEndian)
                        let hi = UInt64(try o.u32()), lo = UInt64(try o.u32())
                        iface.offsetSeconds = Int64(bitPattern: littleEndian ? (lo << 32 | hi) : (hi << 32 | lo))
                    }
                }
                interfaces.append(iface)
            case 0x0000_0006, 0x0000_0002:
                let ifaceID: Int
                if type == 6 {
                    ifaceID = Int(try r.u32())
                } else {
                    ifaceID = Int(try r.u16())
                    _ = try r.u16()
                }
                let tsHigh = UInt64(try r.u32())
                let tsLow = UInt64(try r.u32())
                let caplen = Int(try r.u32())
                let origlen = Int(try r.u32())
                guard ifaceID < interfaces.count else { throw ParseError.malformed("pcapng interface \(ifaceID)") }
                let data = try r.take(caplen)
                r.offset += (4 - caplen % 4) % 4
                var comment: String?
                var direction: CaptureDirection?
                if r.offset <= bodyEnd {
                    for (code, value) in try options(&r, end: bodyEnd) {
                        if code == 1 {
                            comment = String(decoding: value, as: UTF8.self)
                        } else if code == 2, value.count == 4 {
                            var f = EndianReader(bytes: value, offset: 0, littleEndian: littleEndian)
                            direction = CaptureDirection(rawValue: UInt8(try f.u32() & 0x3))
                        }
                    }
                }
                let iface = interfaces[ifaceID]
                records.append(CaptureRecord(
                    timestamp: timestamp(tsHigh << 32 | tsLow, iface),
                    data: data, originalLength: origlen, interfaceID: ifaceID,
                    linkType: iface.linkType, comment: comment, direction: direction))
            case 0x0000_0003:
                guard let iface = interfaces.first else { throw ParseError.malformed("SPB without IDB") }
                let origlen = Int(try r.u32())
                var caplen = min(origlen, bodyEnd - r.offset)
                if iface.snapLength > 0 { caplen = min(caplen, Int(iface.snapLength)) }
                let data = try r.take(caplen)
                records.append(CaptureRecord(
                    timestamp: CaptureTimestamp(seconds: 0, nanoseconds: 0),
                    data: data, originalLength: origlen, linkType: iface.linkType))
            default:
                break
            }
            offset += length
        }
        return records
    }

    static func timestamp(_ units: UInt64, _ iface: Interface) -> CaptureTimestamp {
        let seconds = units / iface.unitsPerSecond
        let remainder = units % iface.unitsPerSecond
        let nanos: UInt64
        if iface.unitsPerSecond >= 1_000_000_000 {
            nanos = remainder / (iface.unitsPerSecond / 1_000_000_000)
        } else {
            nanos = remainder * 1_000_000_000 / iface.unitsPerSecond
        }
        return CaptureTimestamp(seconds: Int64(seconds) + iface.offsetSeconds, nanoseconds: UInt32(nanos))
    }

    static func options(_ r: inout EndianReader, end: Int) throws -> [(UInt16, [UInt8])] {
        var out: [(UInt16, [UInt8])] = []
        while end - r.offset >= 4 {
            let code = try r.u16()
            let len = Int(try r.u16())
            if code == 0 { break }
            guard r.offset + len <= end else { break }
            out.append((code, try r.take(len)))
            r.offset += (4 - len % 4) % 4
        }
        return out
    }
}

/// Writes little-endian pcapng with one interface and microsecond timestamps.
public struct PcapNGWriter: Sendable {
    public var linkType: LinkType
    public var snapLength: UInt32
    public var application: String
    public var interfaceName: String

    public init(
        linkType: LinkType = .raw, snapLength: UInt32 = 65535,
        application: String = "Ferret", interfaceName: String = "Ferret packet tunnel"
    ) {
        self.linkType = linkType
        self.snapLength = snapLength
        self.application = application
        self.interfaceName = interfaceName
    }

    /// Section Header Block followed by one Interface Description Block.
    public func fileHeader() -> [UInt8] {
        var shbBody: [UInt8] = []
        shbBody.appendU32LE(0x1A2B3C4D)
        shbBody.appendU16LE(1)
        shbBody.appendU16LE(0)
        shbBody.appendU32LE(0xFFFF_FFFF)  // section length unknown
        shbBody.appendU32LE(0xFFFF_FFFF)
        shbBody += Self.options([(4, Array(application.utf8))])

        var idbBody: [UInt8] = []
        idbBody.appendU16LE(UInt16(truncatingIfNeeded: linkType.rawValue))
        idbBody.appendU16LE(0)
        idbBody.appendU32LE(snapLength)
        idbBody += Self.options([(2, Array(interfaceName.utf8)), (9, [6])])

        return Self.block(type: 0x0A0D0D0A, body: shbBody) + Self.block(type: 1, body: idbBody)
    }

    public func record(_ record: CaptureRecord) -> [UInt8] {
        let captured = Array(record.data.prefix(Int(snapLength)))
        let micros = UInt64(max(0, record.timestamp.seconds)) * 1_000_000 + UInt64(record.timestamp.microseconds)
        var body: [UInt8] = []
        body.reserveCapacity(20 + captured.count + 8)
        body.appendU32LE(0)
        body.appendU32LE(UInt32(micros >> 32))
        body.appendU32LE(UInt32(micros & 0xFFFF_FFFF))
        body.appendU32LE(UInt32(captured.count))
        body.appendU32LE(UInt32(max(record.originalLength, captured.count)))
        body += captured
        body += [UInt8](repeating: 0, count: (4 - captured.count % 4) % 4)
        var options: [(UInt16, [UInt8])] = []
        if let comment = record.comment, !comment.isEmpty {
            options.append((1, Array(comment.utf8)))
        }
        if let direction = record.direction {
            var flags: [UInt8] = []
            flags.appendU32LE(UInt32(direction.rawValue))
            options.append((2, flags))
        }
        body += Self.options(options)
        return Self.block(type: 6, body: body)
    }

    public func file(_ records: [CaptureRecord]) -> Data {
        var out = fileHeader()
        for r in records { out += record(r) }
        return Data(out)
    }

    static func block(type: UInt32, body: [UInt8]) -> [UInt8] {
        let total = UInt32(12 + body.count)
        var out: [UInt8] = []
        out.reserveCapacity(Int(total))
        out.appendU32LE(type)
        out.appendU32LE(total)
        out += body
        out.appendU32LE(total)
        return out
    }

    /// Encodes options with padding and the opt_endofopt terminator.
    static func options(_ options: [(UInt16, [UInt8])]) -> [UInt8] {
        guard !options.isEmpty else { return [] }
        var out: [UInt8] = []
        for (code, value) in options {
            out.appendU16LE(code)
            out.appendU16LE(UInt16(value.count))
            out += value
            out += [UInt8](repeating: 0, count: (4 - value.count % 4) % 4)
        }
        out.appendU16LE(0)
        out.appendU16LE(0)
        return out
    }
}
