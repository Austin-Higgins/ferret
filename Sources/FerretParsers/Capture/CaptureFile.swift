import Foundation

/// A capture timestamp with nanosecond precision.
public struct CaptureTimestamp: Hashable, Comparable, Sendable, Codable {
    public var seconds: Int64
    public var nanoseconds: UInt32

    public init(seconds: Int64, nanoseconds: UInt32) {
        self.seconds = seconds + Int64(nanoseconds / 1_000_000_000)
        self.nanoseconds = nanoseconds % 1_000_000_000
    }

    public init(date: Date) {
        let t = date.timeIntervalSince1970
        let s = t.rounded(.down)
        self.init(seconds: Int64(s), nanoseconds: UInt32(((t - s) * 1e9).rounded()))
    }

    public var timeInterval: TimeInterval { Double(seconds) + Double(nanoseconds) / 1e9 }
    public var date: Date { Date(timeIntervalSince1970: timeInterval) }
    public var microseconds: UInt32 { nanoseconds / 1000 }

    public static func < (a: CaptureTimestamp, b: CaptureTimestamp) -> Bool {
        a.seconds == b.seconds ? a.nanoseconds < b.nanoseconds : a.seconds < b.seconds
    }

    /// Nanoseconds between two timestamps.
    public func nanoseconds(since earlier: CaptureTimestamp) -> Int64 {
        (seconds - earlier.seconds) * 1_000_000_000 + Int64(nanoseconds) - Int64(earlier.nanoseconds)
    }
}

/// One captured frame.
public struct CaptureRecord: Sendable {
    public var timestamp: CaptureTimestamp
    public var originalLength: Int
    public var data: [UInt8]
    public var interfaceID: Int
    public var linkType: LinkType
    public var comment: String?

    public init(
        timestamp: CaptureTimestamp, data: [UInt8], originalLength: Int? = nil,
        interfaceID: Int = 0, linkType: LinkType = .raw, comment: String? = nil
    ) {
        self.timestamp = timestamp
        self.data = data
        self.originalLength = originalLength ?? data.count
        self.interfaceID = interfaceID
        self.linkType = linkType
        self.comment = comment
    }

    /// The IP datagram inside this frame, if any.
    public var ipBytes: ArraySlice<UInt8>? { LinkLayer.ipPayload(of: data[...], linkType: linkType) }
}

public enum CaptureFormat: String, Sendable, CaseIterable {
    case pcap
    case pcapng

    public var fileExtension: String { rawValue }
}

/// Reads classic pcap or pcapng, detecting the format from the magic number.
public enum CaptureFileReader {
    public static func read(_ data: Data) throws -> [CaptureRecord] {
        try read(Array(data))
    }

    public static func read(_ bytes: [UInt8]) throws -> [CaptureRecord] {
        guard bytes.count >= 4 else { throw ParseError.truncated }
        let magic = UInt32(bytes[0]) << 24 | UInt32(bytes[1]) << 16 | UInt32(bytes[2]) << 8 | UInt32(bytes[3])
        if magic == 0x0A0D0D0A { return try PcapNGReader.read(bytes) }
        return try PcapReader.read(bytes)
    }

    public static func format(of bytes: [UInt8]) -> CaptureFormat? {
        guard bytes.count >= 4 else { return nil }
        let magic = UInt32(bytes[0]) << 24 | UInt32(bytes[1]) << 16 | UInt32(bytes[2]) << 8 | UInt32(bytes[3])
        switch magic {
        case 0x0A0D0D0A: return .pcapng
        case 0xA1B2C3D4, 0xD4C3B2A1, 0xA1B23C4D, 0x4D3CB2A1: return .pcap
        default: return nil
        }
    }
}

/// A little-or-big-endian cursor for capture file headers.
struct EndianReader {
    var bytes: [UInt8]
    var offset: Int
    var littleEndian: Bool

    var remaining: Int { bytes.count - offset }

    mutating func u16() throws -> UInt16 {
        guard remaining >= 2 else { throw ParseError.truncated }
        defer { offset += 2 }
        let a = UInt16(bytes[offset]), b = UInt16(bytes[offset + 1])
        return littleEndian ? (b << 8 | a) : (a << 8 | b)
    }

    mutating func u32() throws -> UInt32 {
        guard remaining >= 4 else { throw ParseError.truncated }
        defer { offset += 4 }
        let a = UInt32(bytes[offset]), b = UInt32(bytes[offset + 1])
        let c = UInt32(bytes[offset + 2]), d = UInt32(bytes[offset + 3])
        return littleEndian ? (d << 24 | c << 16 | b << 8 | a) : (a << 24 | b << 16 | c << 8 | d)
    }

    mutating func take(_ n: Int) throws -> [UInt8] {
        guard n >= 0, remaining >= n else { throw ParseError.truncated }
        defer { offset += n }
        return Array(bytes[offset..<(offset + n)])
    }
}
