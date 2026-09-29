/// DNS resource record types (RFC 1035 and successors).
public struct DNSRecordType: RawRepresentable, Hashable, Sendable, CustomStringConvertible {
    public var rawValue: UInt16
    public init(rawValue: UInt16) { self.rawValue = rawValue }

    public static let a = DNSRecordType(rawValue: 1)
    public static let ns = DNSRecordType(rawValue: 2)
    public static let cname = DNSRecordType(rawValue: 5)
    public static let soa = DNSRecordType(rawValue: 6)
    public static let ptr = DNSRecordType(rawValue: 12)
    public static let mx = DNSRecordType(rawValue: 15)
    public static let txt = DNSRecordType(rawValue: 16)
    public static let aaaa = DNSRecordType(rawValue: 28)
    public static let srv = DNSRecordType(rawValue: 33)
    public static let opt = DNSRecordType(rawValue: 41)
    public static let svcb = DNSRecordType(rawValue: 64)
    public static let https = DNSRecordType(rawValue: 65)
    public static let any = DNSRecordType(rawValue: 255)

    public var description: String {
        switch rawValue {
        case 1: return "A"
        case 2: return "NS"
        case 5: return "CNAME"
        case 6: return "SOA"
        case 12: return "PTR"
        case 15: return "MX"
        case 16: return "TXT"
        case 28: return "AAAA"
        case 33: return "SRV"
        case 41: return "OPT"
        case 64: return "SVCB"
        case 65: return "HTTPS"
        case 255: return "ANY"
        default: return "TYPE\(rawValue)"
        }
    }
}

public enum DNSResponseCode: UInt8, Sendable, CustomStringConvertible {
    case noError = 0, formatError, serverFailure, nameError, notImplemented, refused

    public var description: String {
        switch self {
        case .noError: return "No error"
        case .formatError: return "Format error"
        case .serverFailure: return "Server failure"
        case .nameError: return "No such name"
        case .notImplemented: return "Not implemented"
        case .refused: return "Refused"
        }
    }
}

public struct DNSQuestion: Hashable, Sendable {
    public var name: String
    public var type: DNSRecordType
    public var recordClass: UInt16
    /// The mDNS "unicast response" bit, stripped from `recordClass`.
    public var unicastResponse: Bool
}

public enum DNSRecordData: Hashable, Sendable {
    case address(IPAddress)
    case name(String)
    case mx(preference: UInt16, exchange: String)
    case txt([String])
    case srv(priority: UInt16, weight: UInt16, port: UInt16, target: String)
    case soa(primary: String, responsible: String, serial: UInt32)
    case raw([UInt8])
}

public struct DNSResourceRecord: Hashable, Sendable {
    public var name: String
    public var type: DNSRecordType
    public var recordClass: UInt16
    public var ttl: UInt32
    public var data: DNSRecordData

    public var address: IPAddress? {
        if case .address(let a) = data { return a }
        return nil
    }
}

public struct DNSMessage: Hashable, Sendable {
    public var id: UInt16
    public var isResponse: Bool
    public var opcode: UInt8
    public var authoritative: Bool
    public var truncated: Bool
    public var recursionDesired: Bool
    public var recursionAvailable: Bool
    public var rawResponseCode: UInt8
    public var questions: [DNSQuestion]
    public var answers: [DNSResourceRecord]
    public var authorities: [DNSResourceRecord]
    public var additionals: [DNSResourceRecord]

    public var responseCode: DNSResponseCode? { DNSResponseCode(rawValue: rawResponseCode) }

    /// Every address in the answer section, following CNAME chains implicitly.
    public var answerAddresses: [IPAddress] { answers.compactMap(\.address) }

    public var cnames: [String] {
        answers.compactMap { rr in
            if rr.type == .cname, case .name(let n) = rr.data { return n }
            return nil
        }
    }

    /// Parses a DNS message carried over UDP (no length prefix).
    public static func parse(_ bytes: ArraySlice<UInt8>) throws -> DNSMessage {
        var r = ByteReader(bytes)
        let id = try r.readU16()
        let flags = try r.readU16()
        let qd = Int(try r.readU16())
        let an = Int(try r.readU16())
        let ns = Int(try r.readU16())
        let ar = Int(try r.readU16())
        // Sanity cap so garbage on port 53 cannot allocate huge arrays.
        guard qd <= 64, an + ns + ar <= 1024 else { throw ParseError.malformed("DNS counts") }
        var questions: [DNSQuestion] = []
        for _ in 0..<qd {
            let name = try readName(&r)
            let type = try r.readU16()
            let cls = try r.readU16()
            questions.append(DNSQuestion(
                name: name, type: DNSRecordType(rawValue: type),
                recordClass: cls & 0x7FFF, unicastResponse: cls & 0x8000 != 0))
        }
        func records(_ n: Int) throws -> [DNSResourceRecord] {
            var out: [DNSResourceRecord] = []
            for _ in 0..<n { out.append(try readRecord(&r)) }
            return out
        }
        let answers = try records(an)
        let authorities = try records(ns)
        let additionals = try records(ar)
        return DNSMessage(
            id: id, isResponse: flags & 0x8000 != 0, opcode: UInt8((flags >> 11) & 0xF),
            authoritative: flags & 0x0400 != 0, truncated: flags & 0x0200 != 0,
            recursionDesired: flags & 0x0100 != 0, recursionAvailable: flags & 0x0080 != 0,
            rawResponseCode: UInt8(flags & 0xF),
            questions: questions, answers: answers, authorities: authorities, additionals: additionals)
    }

    public static func parse(_ bytes: [UInt8]) throws -> DNSMessage { try parse(bytes[...]) }

    /// Parses every complete length-prefixed DNS message in a TCP stream.
    public static func parseTCPStream(_ bytes: ArraySlice<UInt8>) -> [DNSMessage] {
        var r = ByteReader(bytes)
        var out: [DNSMessage] = []
        while r.remaining >= 2 {
            guard let len = try? r.readU16(), let body = try? r.readBytes(Int(len)),
                  let msg = try? parse(body) else { break }
            out.append(msg)
        }
        return out
    }

    static func readRecord(_ r: inout ByteReader) throws -> DNSResourceRecord {
        let name = try readName(&r)
        let type = DNSRecordType(rawValue: try r.readU16())
        let cls = try r.readU16()
        let ttl = try r.readU32()
        let rdlength = Int(try r.readU16())
        let start = r.offset
        guard rdlength <= r.remaining else { throw ParseError.truncated }
        let data: DNSRecordData
        switch type {
        case .a where rdlength == 4, .aaaa where rdlength == 16:
            data = .address(IPAddress(bytes: try r.readBytes(rdlength))!)
        case .cname, .ns, .ptr:
            data = .name(try readName(&r))
        case .mx:
            let pref = try r.readU16()
            data = .mx(preference: pref, exchange: try readName(&r))
        case .srv:
            let prio = try r.readU16(), weight = try r.readU16(), port = try r.readU16()
            data = .srv(priority: prio, weight: weight, port: port, target: try readName(&r))
        case .soa:
            let primary = try readName(&r)
            let responsible = try readName(&r)
            data = .soa(primary: primary, responsible: responsible, serial: try r.readU32())
        case .txt:
            var strings: [String] = []
            while r.offset < start + rdlength {
                let len = Int(try r.readU8())
                strings.append(String(decoding: try r.readBytes(len), as: UTF8.self))
            }
            data = .txt(strings)
        default:
            data = .raw(Array(try r.readBytes(rdlength)))
        }
        try r.seek(to: start + rdlength)
        return DNSResourceRecord(name: name, type: type, recordClass: cls & 0x7FFF, ttl: ttl, data: data)
    }

    /// Reads a possibly-compressed domain name. The root name is returned as "".
    static func readName(_ r: inout ByteReader) throws -> String {
        var labels: [String] = []
        var position = r.offset
        var jumped = false
        var jumps = 0
        var total = 0
        while true {
            let len = try r.peekU8(at: position)
            if len == 0 {
                position += 1
                break
            }
            switch len & 0xC0 {
            case 0xC0:
                let lo = try r.peekU8(at: position + 1)
                let target = Int(len & 0x3F) << 8 | Int(lo)
                if !jumped { try r.seek(to: position + 2) }
                jumped = true
                jumps += 1
                guard jumps < 64, target < r.count else { throw ParseError.malformed("DNS name pointer loop") }
                position = target
            case 0x00:
                let n = Int(len)
                guard position + 1 + n <= r.count else { throw ParseError.truncated }
                var labelBytes: [UInt8] = []
                for i in 0..<n { labelBytes.append(try r.peekU8(at: position + 1 + i)) }
                labels.append(String(decoding: labelBytes, as: UTF8.self))
                total += n + 1
                guard total <= 255 else { throw ParseError.malformed("DNS name too long") }
                position += 1 + n
            default:
                throw ParseError.unsupported("DNS label type \(len >> 6)")
            }
        }
        if !jumped { try r.seek(to: position) }
        return labels.joined(separator: ".")
    }
}

/// Builds minimal DNS queries, used by Safety Snoot's resolver checks.
public enum DNSQueryBuilder {
    public static func query(id: UInt16, name: String, type: DNSRecordType, recursionDesired: Bool = true) -> [UInt8] {
        var out: [UInt8] = []
        out.appendU16(id)
        out.appendU16(recursionDesired ? 0x0100 : 0)
        out.appendU16(1)
        out.appendU16(0)
        out.appendU16(0)
        out.appendU16(0)
        for label in name.split(separator: ".") {
            let bytes = Array(label.utf8.prefix(63))
            out.append(UInt8(bytes.count))
            out.append(contentsOf: bytes)
        }
        out.append(0)
        out.appendU16(type.rawValue)
        out.appendU16(1)
        return out
    }
}
