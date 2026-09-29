import Foundation
#if canImport(CryptoKit)
import CryptoKit
#endif
#if canImport(CommonCrypto)
import CommonCrypto
#endif

public enum QUICPacketType: String, Sendable {
    case initial = "Initial"
    case zeroRTT = "0-RTT"
    case handshake = "Handshake"
    case retry = "Retry"
    case versionNegotiation = "Version Negotiation"
    case oneRTT = "1-RTT"
}

/// A QUIC long or short header (RFC 9000 section 17), without decrypting anything.
public struct QUICHeader: Sendable {
    public var isLongHeader: Bool
    public var version: UInt32?
    public var packetType: QUICPacketType
    /// The on-the-wire 2-bit long packet type (Wireshark's `quic.long.packet_type`).
    public var rawLongPacketType: UInt8?
    public var destinationConnectionID: [UInt8]
    public var sourceConnectionID: [UInt8]
    public var token: [UInt8]
    /// Offset of the (protected) packet number from the start of this packet.
    public var packetNumberOffset: Int?
    /// Value of the Length field: packet number plus payload.
    public var length: Int?

    /// Total bytes of this packet inside the datagram, for coalesced packets.
    public var packetSize: Int? {
        guard let pn = packetNumberOffset, let length else { return nil }
        return pn + length
    }

    public static let version1: UInt32 = 0x0000_0001
    public static let version2: UInt32 = 0x6B33_43CF

    /// Parses the first QUIC packet in a UDP datagram. Short headers need the
    /// connection ID length from context, so only the fixed bit is checked.
    public static func parse(_ bytes: ArraySlice<UInt8>, shortHeaderDCIDLength: Int = 0) throws -> QUICHeader {
        var r = ByteReader(bytes)
        let first = try r.readU8()
        if first & 0x80 == 0 {
            guard first & 0x40 != 0 else { throw ParseError.malformed("QUIC fixed bit not set") }
            let dcid = Array(try r.readBytes(min(shortHeaderDCIDLength, r.remaining)))
            return QUICHeader(
                isLongHeader: false, version: nil, packetType: .oneRTT, rawLongPacketType: nil,
                destinationConnectionID: dcid, sourceConnectionID: [], token: [],
                packetNumberOffset: r.offset, length: nil)
        }
        let version = try r.readU32()
        let dcidLength = Int(try r.readU8())
        guard dcidLength <= 20 || version == 0 else { throw ParseError.malformed("QUIC DCID length") }
        let dcid = Array(try r.readBytes(dcidLength))
        let scidLength = Int(try r.readU8())
        let scid = Array(try r.readBytes(scidLength))
        if version == 0 {
            return QUICHeader(
                isLongHeader: true, version: 0, packetType: .versionNegotiation, rawLongPacketType: nil,
                destinationConnectionID: dcid, sourceConnectionID: scid, token: [],
                packetNumberOffset: nil, length: nil)
        }
        let raw = (first >> 4) & 0x03
        let type = packetType(raw: raw, version: version)
        var token: [UInt8] = []
        if type == .initial {
            token = Array(try r.readBytes(Int(try r.readQUICVarInt())))
        }
        if type == .retry {
            return QUICHeader(
                isLongHeader: true, version: version, packetType: .retry, rawLongPacketType: raw,
                destinationConnectionID: dcid, sourceConnectionID: scid, token: Array(r.rest),
                packetNumberOffset: nil, length: nil)
        }
        let length = Int(try r.readQUICVarInt())
        return QUICHeader(
            isLongHeader: true, version: version, packetType: type, rawLongPacketType: raw,
            destinationConnectionID: dcid, sourceConnectionID: scid, token: token,
            packetNumberOffset: r.offset, length: length)
    }

    static func packetType(raw: UInt8, version: UInt32) -> QUICPacketType {
        if version == version2 {
            switch raw {
            case 0: return .retry
            case 1: return .initial
            case 2: return .zeroRTT
            default: return .handshake
            }
        }
        switch raw {
        case 0: return .initial
        case 1: return .zeroRTT
        case 2: return .handshake
        default: return .retry
        }
    }

    /// Cheap check used by the traffic analyzer to tag UDP flows as QUIC.
    public static func looksLikeQUIC(_ bytes: ArraySlice<UInt8>) -> Bool {
        guard let h = try? parse(bytes) else { return false }
        guard h.isLongHeader, let v = h.version else { return false }
        return v == version1 || v == version2 || v == 0 || (v & 0xFF00_0000) == 0xFF00_0000
            || (v & 0x0F0F_0F0F) == 0x0A0A_0A0A
    }

    public static func versionName(_ v: UInt32) -> String {
        switch v {
        case 0: return "Version Negotiation"
        case version1: return "1"
        case version2: return "2"
        default:
            if v & 0xFFFF_FF00 == 0xFF00_0000 { return "draft-\(v & 0xFF)" }
            let hex = String(v, radix: 16)
            return "0x" + String(repeating: "0", count: max(0, 8 - hex.count)) + hex
        }
    }
}

/// A CRYPTO frame from a decrypted QUIC Initial packet.
public struct QUICCryptoFrame: Hashable, Sendable {
    public var offset: UInt64
    public var data: [UInt8]
}

/// Removes header protection from and decrypts client Initial packets, whose keys
/// are derived from the public Destination Connection ID (RFC 9001 section 5.2).
/// This reveals only what any on-path observer can already read: the ClientHello.
public enum QUICInitialDecryptor {
    public static var isSupported: Bool {
        #if canImport(CryptoKit) && canImport(CommonCrypto)
        return true
        #else
        return false
        #endif
    }

    static let saltV1: [UInt8] = [UInt8](hex: "38762cf7f55934b34d179ae6a4c80cadccbb7f0a")!
    static let saltV2: [UInt8] = [UInt8](hex: "0dede3def700a6db819381be6e269dcbf9bd2ed9")!
    static let saltDraft29: [UInt8] = [UInt8](hex: "afbfec289993d24c9e9786f19c6111e04390a899")!

    /// Decrypts every client Initial packet in the datagram and returns its CRYPTO frames.
    /// `clientDCID` is the DCID of the client's first Initial; pass nil to use the packet's own.
    public static func cryptoFrames(inDatagram datagram: ArraySlice<UInt8>, clientDCID: [UInt8]? = nil) -> [QUICCryptoFrame] {
        var frames: [QUICCryptoFrame] = []
        var rest = datagram
        while !rest.isEmpty {
            guard let header = try? QUICHeader.parse(rest), header.isLongHeader,
                  let size = header.packetSize, size <= rest.count else { break }
            let packet = rest.prefix(size)
            if header.packetType == .initial,
               let plaintext = decryptInitial(packet: packet, header: header, dcid: clientDCID ?? header.destinationConnectionID) {
                frames.append(contentsOf: parseCryptoFrames(plaintext[...]))
            }
            rest = rest.dropFirst(size)
        }
        return frames
    }

    /// Joins CRYPTO frames contiguous from offset 0.
    public static func contiguousCryptoStream(_ frames: [QUICCryptoFrame]) -> [UInt8] {
        var stream: [UInt8] = []
        var pending = frames.sorted { $0.offset < $1.offset }
        var progressed = true
        while progressed {
            progressed = false
            for (i, frame) in pending.enumerated() where frame.offset <= UInt64(stream.count) {
                let skip = Int(UInt64(stream.count) - frame.offset)
                if skip < frame.data.count { stream.append(contentsOf: frame.data[skip...]) }
                pending.remove(at: i)
                progressed = true
                break
            }
        }
        return stream
    }

    public static func clientHello(inDatagrams datagrams: [ArraySlice<UInt8>]) -> TLSClientHello? {
        guard let first = datagrams.first, let header = try? QUICHeader.parse(first) else { return nil }
        let dcid = header.destinationConnectionID
        let frames = datagrams.flatMap { cryptoFrames(inDatagram: $0, clientDCID: dcid) }
        let stream = contiguousCryptoStream(frames)
        guard let msg = TLS.messages(inHandshakeBytes: stream[...]).first(where: { $0.type == TLSHandshakeType.clientHello.rawValue })
        else { return nil }
        return try? TLSClientHello.parse(body: msg.body)
    }

    static func parseCryptoFrames(_ payload: ArraySlice<UInt8>) -> [QUICCryptoFrame] {
        var r = ByteReader(payload)
        var out: [QUICCryptoFrame] = []
        do {
            while !r.isAtEnd {
                let type = try r.readQUICVarInt()
                switch type {
                case 0x00, 0x01:
                    continue
                case 0x02, 0x03:
                    _ = try r.readQUICVarInt()
                    _ = try r.readQUICVarInt()
                    let ranges = try r.readQUICVarInt()
                    _ = try r.readQUICVarInt()
                    for _ in 0..<min(ranges, 256) {
                        _ = try r.readQUICVarInt()
                        _ = try r.readQUICVarInt()
                    }
                    if type == 0x03 {
                        for _ in 0..<3 { _ = try r.readQUICVarInt() }
                    }
                case 0x06:
                    let offset = try r.readQUICVarInt()
                    let len = try r.readQUICVarInt()
                    out.append(QUICCryptoFrame(offset: offset, data: Array(try r.readBytes(Int(len)))))
                case 0x1C, 0x1D:
                    _ = try r.readQUICVarInt()
                    if type == 0x1C { _ = try r.readQUICVarInt() }
                    try r.skip(Int(try r.readQUICVarInt()))
                default:
                    return out
                }
            }
        } catch {
            return out
        }
        return out
    }

    #if canImport(CryptoKit) && canImport(CommonCrypto)
    static func decryptInitial(packet: ArraySlice<UInt8>, header: QUICHeader, dcid: [UInt8]) -> [UInt8]? {
        guard let version = header.version, let pnOffset = header.packetNumberOffset, let length = header.length else { return nil }
        let salt: [UInt8]
        let prefix: String
        switch version {
        case QUICHeader.version1: salt = saltV1; prefix = "quic"
        case QUICHeader.version2: salt = saltV2; prefix = "quicv2"
        case 0xFF00_001D: salt = saltDraft29; prefix = "quic"
        default: return nil
        }
        let initialSecret = HKDF<SHA256>.extract(inputKeyMaterial: SymmetricKey(data: dcid), salt: salt)
        let clientSecret = expandLabel(secret: initialSecret, label: "client in", length: 32)
        let key = expandLabel(secret: clientSecret, label: "\(prefix) key", length: 16)
        let iv = expandLabel(secret: clientSecret, label: "\(prefix) iv", length: 12)
        let hp = expandLabel(secret: clientSecret, label: "\(prefix) hp", length: 16)

        var bytes = Array(packet)
        let sampleStart = pnOffset + 4
        guard sampleStart + 16 <= bytes.count else { return nil }
        guard let mask = aesECB(key: hp, block: Array(bytes[sampleStart..<(sampleStart + 16)])) else { return nil }
        bytes[0] ^= mask[0] & 0x0F
        let pnLength = Int(bytes[0] & 0x03) + 1
        guard pnOffset + pnLength <= bytes.count, pnOffset + length <= bytes.count, length >= pnLength + 16 else { return nil }
        var packetNumber: UInt64 = 0
        for i in 0..<pnLength {
            bytes[pnOffset + i] ^= mask[1 + i]
            packetNumber = packetNumber << 8 | UInt64(bytes[pnOffset + i])
        }
        var nonce = iv
        for i in 0..<8 {
            nonce[11 - i] ^= UInt8((packetNumber >> UInt64(8 * i)) & 0xFF)
        }
        let aad = bytes[0..<(pnOffset + pnLength)]
        let payloadEnd = pnOffset + length
        let ciphertext = bytes[(pnOffset + pnLength)..<(payloadEnd - 16)]
        let tag = bytes[(payloadEnd - 16)..<payloadEnd]
        do {
            let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: nonce), ciphertext: ciphertext, tag: tag)
            let plain = try AES.GCM.open(box, using: SymmetricKey(data: key), authenticating: aad)
            return Array(plain)
        } catch {
            return nil
        }
    }

    static func expandLabel<S: ContiguousBytes>(secret: S, label: String, length: Int) -> [UInt8] {
        let fullLabel = Array("tls13 \(label)".utf8)
        var info: [UInt8] = []
        info.appendU16(UInt16(length))
        info.append(UInt8(fullLabel.count))
        info.append(contentsOf: fullLabel)
        info.append(0)
        let key = HKDF<SHA256>.expand(pseudoRandomKey: secret, info: info, outputByteCount: length)
        return key.withUnsafeBytes { Array($0) }
    }

    static func aesECB(key: [UInt8], block: [UInt8]) -> [UInt8]? {
        var out = [UInt8](repeating: 0, count: 16)
        var moved = 0
        let status = CCCrypt(
            CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionECBMode),
            key, key.count, nil, block, block.count, &out, out.count, &moved)
        return status == CCCryptorStatus(kCCSuccess) ? out : nil
    }
    #else
    static func decryptInitial(packet: ArraySlice<UInt8>, header: QUICHeader, dcid: [UInt8]) -> [UInt8]? { nil }
    #endif
}
