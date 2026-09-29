import Foundation

/// Classic libpcap format (https://www.ietf.org/archive/id/draft-ietf-opsawg-pcap-04.html).
public enum PcapReader {
    public static func read(_ bytes: [UInt8]) throws -> [CaptureRecord] {
        guard bytes.count >= 24 else { throw ParseError.truncated }
        let magicBE = UInt32(bytes[0]) << 24 | UInt32(bytes[1]) << 16 | UInt32(bytes[2]) << 8 | UInt32(bytes[3])
        let littleEndian: Bool
        let nanos: Bool
        switch magicBE {
        case 0xA1B2C3D4: littleEndian = false; nanos = false
        case 0xD4C3B2A1: littleEndian = true; nanos = false
        case 0xA1B23C4D: littleEndian = false; nanos = true
        case 0x4D3CB2A1: littleEndian = true; nanos = true
        default: throw ParseError.unsupported("pcap magic")
        }
        var r = EndianReader(bytes: bytes, offset: 4, littleEndian: littleEndian)
        _ = try r.u16()  // major
        _ = try r.u16()  // minor
        _ = try r.u32()  // reserved (thiszone)
        _ = try r.u32()  // reserved (sigfigs)
        _ = try r.u32()  // snaplen
        let linkType = LinkType(rawValue: try r.u32() & 0x0FFF_FFFF)
        var records: [CaptureRecord] = []
        while r.remaining >= 16 {
            let sec = try r.u32()
            let frac = try r.u32()
            let caplen = Int(try r.u32())
            let origlen = Int(try r.u32())
            guard caplen <= r.remaining else { break }
            let data = try r.take(caplen)
            records.append(CaptureRecord(
                timestamp: CaptureTimestamp(seconds: Int64(sec), nanoseconds: nanos ? frac : frac * 1000),
                data: data, originalLength: origlen, linkType: linkType))
        }
        return records
    }
}

/// Writes classic pcap with microsecond timestamps, which every tool reads.
public struct PcapWriter: Sendable {
    public var linkType: LinkType
    public var snapLength: UInt32

    public init(linkType: LinkType = .raw, snapLength: UInt32 = 65535) {
        self.linkType = linkType
        self.snapLength = snapLength
    }

    public func fileHeader() -> [UInt8] {
        var out: [UInt8] = []
        out.appendU32LE(0xA1B2C3D4)
        out.appendU16LE(2)
        out.appendU16LE(4)
        out.appendU32LE(0)
        out.appendU32LE(0)
        out.appendU32LE(snapLength)
        out.appendU32LE(linkType.rawValue)
        return out
    }

    public func record(_ record: CaptureRecord) -> [UInt8] {
        let captured = record.data.prefix(Int(snapLength))
        var out: [UInt8] = []
        out.reserveCapacity(16 + captured.count)
        out.appendU32LE(UInt32(truncatingIfNeeded: record.timestamp.seconds))
        out.appendU32LE(record.timestamp.microseconds)
        out.appendU32LE(UInt32(captured.count))
        out.appendU32LE(UInt32(max(record.originalLength, captured.count)))
        out.append(contentsOf: captured)
        return out
    }

    public func file(_ records: [CaptureRecord]) -> Data {
        var out = fileHeader()
        for r in records { out.append(contentsOf: record(r)) }
        return Data(out)
    }
}
