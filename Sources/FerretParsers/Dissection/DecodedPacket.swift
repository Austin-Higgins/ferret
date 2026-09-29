/// Transport-layer contents of a decoded packet.
public enum TransportLayer: Sendable {
    case tcp(TCPSegment)
    case udp(UDPDatagram)
    case icmp(ICMPMessage)
    case other(UInt8)
}

/// Application-layer hints visible within a single packet.
public enum ApplicationLayer: Sendable {
    case dns(DNSMessage)
    case tlsClientHello(TLSClientHello)
    case tlsServerHello(TLSServerHello)
    case tlsRecords([TLSRecord])
    case quic(QUICHeader)
    case httpRequest(HTTPRequestHead)
    case httpResponse(HTTPResponseHead)
}

/// A single IP packet decoded layer by layer.
public struct DecodedPacket: Sendable {
    public var ip: IPPacket
    public var transport: TransportLayer
    public var application: ApplicationLayer?

    public var sourcePort: UInt16? {
        switch transport {
        case .tcp(let t): return t.sourcePort
        case .udp(let u): return u.sourcePort
        default: return nil
        }
    }

    public var destinationPort: UInt16? {
        switch transport {
        case .tcp(let t): return t.destinationPort
        case .udp(let u): return u.destinationPort
        default: return nil
        }
    }

    public var transportPayload: ArraySlice<UInt8> {
        switch transport {
        case .tcp(let t): return t.payload
        case .udp(let u): return u.payload
        case .icmp(let i): return i.body
        case .other: return ip.payload
        }
    }

    public static func decode(ipBytes: ArraySlice<UInt8>) throws -> DecodedPacket {
        let ip = try IPPacket.parse(ipBytes)
        // Only the first fragment carries the transport header.
        guard ip.fragmentOffset == 0 else {
            return DecodedPacket(ip: ip, transport: .other(ip.protocolNumber), application: nil)
        }
        let transport: TransportLayer
        switch ip.protocolNumber {
        case IPProtocolNumber.tcp: transport = .tcp(try TCPSegment.parse(ip.payload))
        case IPProtocolNumber.udp: transport = .udp(try UDPDatagram.parse(ip.payload))
        case IPProtocolNumber.icmp: transport = .icmp(try ICMPMessage.parse(ip.payload, isV6: false))
        case IPProtocolNumber.icmpv6: transport = .icmp(try ICMPMessage.parse(ip.payload, isV6: true))
        default: transport = .other(ip.protocolNumber)
        }
        var packet = DecodedPacket(ip: ip, transport: transport, application: nil)
        packet.application = packet.sniffApplication()
        return packet
    }

    public static func decode(ipBytes: [UInt8]) throws -> DecodedPacket {
        try decode(ipBytes: ipBytes[...])
    }

    private func sniffApplication() -> ApplicationLayer? {
        let payload = transportPayload
        guard !payload.isEmpty else { return nil }
        let ports = [sourcePort ?? 0, destinationPort ?? 0]
        switch transport {
        case .udp:
            if ports.contains(53) || ports.contains(5353) || ports.contains(5355), let dns = try? DNSMessage.parse(payload) {
                return .dns(dns)
            }
            if QUICHeader.looksLikeQUIC(payload), let h = try? QUICHeader.parse(payload) {
                return .quic(h)
            }
        case .tcp:
            if ports.contains(53) {
                if let m = DNSMessage.parseTCPStream(payload).first { return .dns(m) }
            }
            if TLS.looksLikeTLS(payload) {
                if let ch = TLS.clientHello(inStream: payload) { return .tlsClientHello(ch) }
                if let sh = TLS.serverHello(inStream: payload) { return .tlsServerHello(sh) }
                let records = TLS.records(in: payload)
                if !records.isEmpty { return .tlsRecords(records) }
            }
            if let req = HTTP1.parseRequest(payload) { return .httpRequest(req) }
            if let resp = HTTP1.parseResponse(payload) { return .httpResponse(resp) }
        default:
            break
        }
        return nil
    }
}
