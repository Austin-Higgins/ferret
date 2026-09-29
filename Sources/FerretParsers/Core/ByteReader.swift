/// Errors thrown by Ferret's parsers.
public enum ParseError: Error, Equatable, Sendable {
    case truncated
    case malformed(String)
    case unsupported(String)
}

/// A cursor over a byte slice that reads big-endian (network order) integers.
///
/// Offsets are always relative to the start of the slice, so callers never
/// have to reason about `ArraySlice` indices.
public struct ByteReader: Sendable {
    public let data: ArraySlice<UInt8>
    public private(set) var offset: Int

    public init(_ data: ArraySlice<UInt8>) {
        self.data = data
        self.offset = 0
    }

    public init(_ bytes: [UInt8]) {
        self.init(bytes[...])
    }

    public var count: Int { data.count }
    public var remaining: Int { data.count - offset }
    public var isAtEnd: Bool { offset >= data.count }

    /// The unread part of the slice.
    public var rest: ArraySlice<UInt8> {
        data[(data.startIndex + min(offset, data.count))...]
    }

    @inline(__always)
    private func index(_ relative: Int) -> Int { data.startIndex + relative }

    public func peekU8(at relative: Int? = nil) throws -> UInt8 {
        let at = relative ?? offset
        guard at >= 0, at < data.count else { throw ParseError.truncated }
        return data[index(at)]
    }

    public mutating func seek(to relative: Int) throws {
        guard relative >= 0, relative <= data.count else { throw ParseError.truncated }
        offset = relative
    }

    public mutating func skip(_ n: Int) throws {
        guard n >= 0, n <= remaining else { throw ParseError.truncated }
        offset += n
    }

    public mutating func readU8() throws -> UInt8 {
        guard remaining >= 1 else { throw ParseError.truncated }
        defer { offset += 1 }
        return data[index(offset)]
    }

    public mutating func readU16() throws -> UInt16 {
        guard remaining >= 2 else { throw ParseError.truncated }
        defer { offset += 2 }
        let i = index(offset)
        return UInt16(data[i]) << 8 | UInt16(data[i + 1])
    }

    public mutating func readU24() throws -> UInt32 {
        guard remaining >= 3 else { throw ParseError.truncated }
        defer { offset += 3 }
        let i = index(offset)
        return UInt32(data[i]) << 16 | UInt32(data[i + 1]) << 8 | UInt32(data[i + 2])
    }

    public mutating func readU32() throws -> UInt32 {
        guard remaining >= 4 else { throw ParseError.truncated }
        defer { offset += 4 }
        let i = index(offset)
        return UInt32(data[i]) << 24 | UInt32(data[i + 1]) << 16 | UInt32(data[i + 2]) << 8 | UInt32(data[i + 3])
    }

    public mutating func readU64() throws -> UInt64 {
        let hi = UInt64(try readU32())
        let lo = UInt64(try readU32())
        return hi << 32 | lo
    }

    public mutating func readBytes(_ n: Int) throws -> ArraySlice<UInt8> {
        guard n >= 0, n <= remaining else { throw ParseError.truncated }
        defer { offset += n }
        return data[index(offset)..<index(offset + n)]
    }

    /// Reads a QUIC variable-length integer (RFC 9000, section 16).
    public mutating func readQUICVarInt() throws -> UInt64 {
        let first = try readU8()
        let length = 1 << Int(first >> 6)
        var value = UInt64(first & 0x3F)
        for _ in 1..<length {
            value = value << 8 | UInt64(try readU8())
        }
        return value
    }
}

extension Array where Element == UInt8 {
    public mutating func appendU16(_ v: UInt16) {
        append(UInt8(v >> 8)); append(UInt8(v & 0xFF))
    }

    public mutating func appendU32(_ v: UInt32) {
        append(UInt8(v >> 24)); append(UInt8((v >> 16) & 0xFF))
        append(UInt8((v >> 8) & 0xFF)); append(UInt8(v & 0xFF))
    }

    public mutating func appendU16LE(_ v: UInt16) {
        append(UInt8(v & 0xFF)); append(UInt8(v >> 8))
    }

    public mutating func appendU32LE(_ v: UInt32) {
        append(UInt8(v & 0xFF)); append(UInt8((v >> 8) & 0xFF))
        append(UInt8((v >> 16) & 0xFF)); append(UInt8(v >> 24))
    }
}

extension Collection where Element == UInt8 {
    /// Lowercase hex without separators, e.g. `203f9e9f`.
    public var hexString: String {
        var s = ""
        s.reserveCapacity(count * 2)
        for b in self {
            s.append(hexDigits[Int(b >> 4)])
            s.append(hexDigits[Int(b & 0x0F)])
        }
        return s
    }
}

private let hexDigits: [Character] = Array("0123456789abcdef")

extension Array where Element == UInt8 {
    /// Parses a hex string such as `"45 00 0a"` or `"45000a"`. Returns nil on bad input.
    public init?(hex: String) {
        var out: [UInt8] = []
        var high: UInt8?
        for ch in hex {
            if ch == " " || ch == ":" || ch == "\n" { continue }
            guard let v = ch.hexDigitValue else { return nil }
            if let h = high {
                out.append(h << 4 | UInt8(v))
                high = nil
            } else {
                high = UInt8(v)
            }
        }
        guard high == nil else { return nil }
        self = out
    }
}
