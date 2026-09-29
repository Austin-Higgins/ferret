public enum TLSContentType: UInt8, Sendable {
    case changeCipherSpec = 20
    case alert = 21
    case handshake = 22
    case applicationData = 23
    case heartbeat = 24
}

public enum TLSHandshakeType: UInt8, Sendable {
    case helloRequest = 0
    case clientHello = 1
    case serverHello = 2
    case newSessionTicket = 4
    case endOfEarlyData = 5
    case encryptedExtensions = 8
    case certificate = 11
    case serverKeyExchange = 12
    case certificateRequest = 13
    case serverHelloDone = 14
    case certificateVerify = 15
    case clientKeyExchange = 16
    case finished = 20
    case keyUpdate = 24
}

public struct TLSRecord: Sendable {
    public var contentType: UInt8
    public var version: UInt16
    public var fragment: ArraySlice<UInt8>
}

public struct TLSExtension: Hashable, Sendable {
    public var type: UInt16
    public var data: [UInt8]

    public static let serverName: UInt16 = 0
    public static let alpn: UInt16 = 16
    public static let supportedVersions: UInt16 = 43
    public static let encryptedClientHello: UInt16 = 0xFE0D
}

public struct TLSClientHello: Hashable, Sendable {
    public var legacyVersion: UInt16
    public var random: [UInt8]
    public var sessionID: [UInt8]
    public var cipherSuites: [UInt16]
    public var compressionMethods: [UInt8]
    public var extensions: [TLSExtension]

    public var serverName: String? {
        guard let ext = extensions.first(where: { $0.type == TLSExtension.serverName }) else { return nil }
        var r = ByteReader(ext.data)
        guard let listLength = try? r.readU16(), Int(listLength) <= r.remaining else { return nil }
        while !r.isAtEnd {
            guard let type = try? r.readU8(), let len = try? r.readU16(),
                  let name = try? r.readBytes(Int(len)) else { return nil }
            if type == 0 { return String(decoding: name, as: UTF8.self) }
        }
        return nil
    }

    public var alpnProtocols: [String] { TLSClientHello.parseALPN(extensions) }

    public var supportedVersions: [UInt16] {
        guard let ext = extensions.first(where: { $0.type == TLSExtension.supportedVersions }) else { return [] }
        var r = ByteReader(ext.data)
        guard let len = try? r.readU8() else { return [] }
        var out: [UInt16] = []
        for _ in 0..<(Int(len) / 2) {
            guard let v = try? r.readU16() else { break }
            out.append(v)
        }
        return out
    }

    public var hasEncryptedClientHello: Bool {
        extensions.contains { $0.type == TLSExtension.encryptedClientHello }
    }

    /// Parses the body of a ClientHello handshake message (after the 4-byte handshake header).
    public static func parse(body: ArraySlice<UInt8>) throws -> TLSClientHello {
        var r = ByteReader(body)
        let version = try r.readU16()
        let random = Array(try r.readBytes(32))
        let sessionID = Array(try r.readBytes(Int(try r.readU8())))
        let suitesLength = Int(try r.readU16())
        var suitesReader = ByteReader(try r.readBytes(suitesLength))
        var suites: [UInt16] = []
        while suitesReader.remaining >= 2 { suites.append(try suitesReader.readU16()) }
        let compression = Array(try r.readBytes(Int(try r.readU8())))
        var extensions: [TLSExtension] = []
        if r.remaining >= 2 {
            let extLength = Int(try r.readU16())
            var e = ByteReader(try r.readBytes(min(extLength, r.remaining)))
            while e.remaining >= 4 {
                let type = try e.readU16()
                let len = Int(try e.readU16())
                extensions.append(TLSExtension(type: type, data: Array(try e.readBytes(len))))
            }
        }
        return TLSClientHello(
            legacyVersion: version, random: random, sessionID: sessionID,
            cipherSuites: suites, compressionMethods: compression, extensions: extensions)
    }

    static func parseALPN(_ extensions: [TLSExtension]) -> [String] {
        guard let ext = extensions.first(where: { $0.type == TLSExtension.alpn }) else { return [] }
        var r = ByteReader(ext.data)
        guard (try? r.readU16()) != nil else { return [] }
        var out: [String] = []
        while !r.isAtEnd {
            guard let len = try? r.readU8(), let p = try? r.readBytes(Int(len)) else { break }
            out.append(String(decoding: p, as: UTF8.self))
        }
        return out
    }
}

public struct TLSServerHello: Hashable, Sendable {
    public var legacyVersion: UInt16
    public var cipherSuite: UInt16
    public var extensions: [TLSExtension]

    /// The negotiated version, using supported_versions for TLS 1.3.
    public var negotiatedVersion: UInt16 {
        if let ext = extensions.first(where: { $0.type == TLSExtension.supportedVersions }), ext.data.count == 2 {
            return UInt16(ext.data[0]) << 8 | UInt16(ext.data[1])
        }
        return legacyVersion
    }

    public var alpnProtocol: String? { TLSClientHello.parseALPN(extensions).first }

    public static func parse(body: ArraySlice<UInt8>) throws -> TLSServerHello {
        var r = ByteReader(body)
        let version = try r.readU16()
        try r.skip(32)
        try r.skip(Int(try r.readU8()))
        let suite = try r.readU16()
        try r.skip(1)
        var extensions: [TLSExtension] = []
        if r.remaining >= 2 {
            let extLength = Int(try r.readU16())
            var e = ByteReader(try r.readBytes(min(extLength, r.remaining)))
            while e.remaining >= 4 {
                let type = try e.readU16()
                let len = Int(try e.readU16())
                extensions.append(TLSExtension(type: type, data: Array(try e.readBytes(len))))
            }
        }
        return TLSServerHello(legacyVersion: version, cipherSuite: suite, extensions: extensions)
    }
}

public enum TLS {
    /// True if the bytes look like the start of a TLS record stream.
    public static func looksLikeTLS(_ bytes: ArraySlice<UInt8>) -> Bool {
        guard bytes.count >= 3 else { return false }
        let i = bytes.startIndex
        let type = bytes[i]
        return (20...24).contains(type) && bytes[i + 1] == 3 && bytes[i + 2] <= 4
    }

    /// Splits a byte stream into complete TLS records; a trailing partial record is ignored.
    public static func records(in bytes: ArraySlice<UInt8>) -> [TLSRecord] {
        var r = ByteReader(bytes)
        var out: [TLSRecord] = []
        while r.remaining >= 5 {
            let start = r.offset
            guard let type = try? r.readU8(), let version = try? r.readU16(), let len = try? r.readU16() else { break }
            guard let fragment = try? r.readBytes(Int(len)) else {
                try? r.seek(to: start)
                break
            }
            out.append(TLSRecord(contentType: type, version: version, fragment: fragment))
        }
        return out
    }

    /// Complete handshake messages from a stream, reassembling across records.
    /// Parsing stops at the first non-handshake record (e.g. ChangeCipherSpec is skipped,
    /// but encrypted records end the plaintext handshake).
    public static func handshakeMessages(in stream: ArraySlice<UInt8>) -> [(type: UInt8, body: ArraySlice<UInt8>)] {
        var handshakeBytes: [UInt8] = []
        for record in records(in: stream) {
            if record.contentType == TLSContentType.handshake.rawValue {
                handshakeBytes.append(contentsOf: record.fragment)
            } else if record.contentType == TLSContentType.changeCipherSpec.rawValue {
                continue
            } else {
                break
            }
        }
        return messages(inHandshakeBytes: handshakeBytes[...])
    }

    /// Splits raw handshake-protocol bytes (as carried in QUIC CRYPTO frames) into messages.
    public static func messages(inHandshakeBytes bytes: ArraySlice<UInt8>) -> [(type: UInt8, body: ArraySlice<UInt8>)] {
        var r = ByteReader(bytes)
        var out: [(type: UInt8, body: ArraySlice<UInt8>)] = []
        while r.remaining >= 4 {
            guard let type = try? r.readU8(), let len = try? r.readU24(),
                  let body = try? r.readBytes(Int(len)) else { break }
            out.append((type, body))
        }
        return out
    }

    public static func clientHello(inStream stream: ArraySlice<UInt8>) -> TLSClientHello? {
        guard let msg = handshakeMessages(in: stream).first(where: { $0.type == TLSHandshakeType.clientHello.rawValue })
        else { return nil }
        return try? TLSClientHello.parse(body: msg.body)
    }

    public static func serverHello(inStream stream: ArraySlice<UInt8>) -> TLSServerHello? {
        guard let msg = handshakeMessages(in: stream).first(where: { $0.type == TLSHandshakeType.serverHello.rawValue })
        else { return nil }
        return try? TLSServerHello.parse(body: msg.body)
    }

    public static func versionName(_ v: UInt16) -> String {
        switch v {
        case 0x0300: return "SSL 3.0"
        case 0x0301: return "TLS 1.0"
        case 0x0302: return "TLS 1.1"
        case 0x0303: return "TLS 1.2"
        case 0x0304: return "TLS 1.3"
        default: return String(format4Hex: v)
        }
    }
}

extension String {
    /// `0x1301`-style formatting, matching Wireshark's field output.
    public init(format4Hex v: UInt16) {
        let digits = String(v, radix: 16)
        let zeros = String(repeating: "0", count: Swift.max(0, 4 - digits.count))
        self.init("0x" + zeros + digits)
    }
}
