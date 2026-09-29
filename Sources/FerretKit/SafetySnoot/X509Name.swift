import FerretParsers

/// Reads the issuer and subject names from a DER-encoded X.509 certificate.
/// iOS doesn't expose a certificate's issuer organisation, and Safety Snoot
/// needs it to spot interception by a rogue but trusted root.
public struct X509Names: Hashable, Sendable {
    public var issuerOrganization: String?
    public var issuerCommonName: String?
    public var subjectCommonName: String?

    public init(der: [UInt8]) throws {
        var outer = DERReader(der[...])
        var cert = try outer.readElement(expecting: 0x30)
        var tbs = try cert.readElement(expecting: 0x30)
        if try tbs.peekTag() == 0xA0 { _ = try tbs.readAny() }  // version
        _ = try tbs.readAny()  // serialNumber
        _ = try tbs.readAny()  // signature algorithm
        let issuer = try Self.attributes(try tbs.readElement(expecting: 0x30))
        _ = try tbs.readAny()  // validity
        let subject = try Self.attributes(try tbs.readElement(expecting: 0x30))
        issuerOrganization = issuer["2.5.4.10"]
        issuerCommonName = issuer["2.5.4.3"]
        subjectCommonName = subject["2.5.4.3"]
    }

    static func attributes(_ name: DERReader) throws -> [String: String] {
        var name = name
        var out: [String: String] = [:]
        while !name.isAtEnd {
            var set = try name.readElement(expecting: 0x31)
            while !set.isAtEnd {
                var pair = try set.readElement(expecting: 0x30)
                let oid = try pair.readElement(expecting: 0x06)
                let (_, value) = try pair.readTagged()
                let key = Self.oidString(oid.bytes)
                if out[key] == nil { out[key] = String(decoding: value, as: UTF8.self) }
            }
        }
        return out
    }

    static func oidString(_ bytes: ArraySlice<UInt8>) -> String {
        guard let first = bytes.first else { return "" }
        var parts = [Int(first) / 40, Int(first) % 40]
        var value = 0
        for b in bytes.dropFirst() {
            value = value << 7 | Int(b & 0x7F)
            if b & 0x80 == 0 {
                parts.append(value)
                value = 0
            }
        }
        return parts.map(String.init).joined(separator: ".")
    }
}

/// Minimal DER TLV reader.
struct DERReader {
    var bytes: ArraySlice<UInt8>

    init(_ bytes: ArraySlice<UInt8>) {
        self.bytes = bytes
    }

    var isAtEnd: Bool { bytes.isEmpty }

    func peekTag() throws -> UInt8 {
        guard let t = bytes.first else { throw ParseError.truncated }
        return t
    }

    mutating func readTagged() throws -> (UInt8, ArraySlice<UInt8>) {
        guard bytes.count >= 2 else { throw ParseError.truncated }
        let tag = bytes[bytes.startIndex]
        var index = bytes.startIndex + 1
        var length = Int(bytes[index])
        index += 1
        if length & 0x80 != 0 {
            let count = length & 0x7F
            guard count > 0, count <= 4, index + count <= bytes.endIndex else { throw ParseError.malformed("DER length") }
            length = 0
            for _ in 0..<count {
                length = length << 8 | Int(bytes[index])
                index += 1
            }
        }
        guard index + length <= bytes.endIndex else { throw ParseError.truncated }
        let value = bytes[index..<(index + length)]
        bytes = bytes[(index + length)...]
        return (tag, value)
    }

    mutating func readAny() throws -> ArraySlice<UInt8> { try readTagged().1 }

    mutating func readElement(expecting tag: UInt8) throws -> DERReader {
        let (t, value) = try readTagged()
        guard t == tag else { throw ParseError.malformed("DER tag \(t), expected \(tag)") }
        return DERReader(value)
    }
}
