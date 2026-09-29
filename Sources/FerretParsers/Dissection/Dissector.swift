/// One node in a packet's field tree, like a row in Wireshark's details pane.
public struct PacketField: Identifiable, Hashable, Sendable {
    public var id: Int
    /// Wireshark display-filter name, e.g. `ip.src`. Used for tests and Learn mode.
    public var key: String?
    public var label: String
    public var value: String
    /// Byte range within the frame, for highlighting in the hex view.
    public var range: Range<Int>?
    public var children: [PacketField]

    public var text: String { value.isEmpty ? label : "\(label): \(value)" }
}

/// The dissected form of one captured frame.
public struct PacketDissection: Sendable {
    public var fields: [PacketField]
    /// Short protocol name for list rows, e.g. "DNS" or "TLS".
    public var protocolName: String
    /// One-line summary, like Wireshark's Info column.
    public var summary: String

    /// All values for a field key in tree order, as `tshark -T fields` prints them.
    public func values(_ key: String) -> [String] {
        var out: [String] = []
        func walk(_ f: [PacketField]) {
            for field in f {
                if field.key == key { out.append(field.value) }
                walk(field.children)
            }
        }
        walk(fields)
        return out
    }

    /// Values joined with commas, matching tshark's default aggregator.
    public func value(_ key: String) -> String { values(key).joined(separator: ",") }
}

/// Builds field trees for frames. Parsers are written from scratch; field names follow
/// Wireshark's display-filter vocabulary so results can be checked against tshark.
public enum Dissector {
    /// Dissects one frame. Pass a shared context, feeding frames in order, to get
    /// stream-level TLS dissection; without one each frame stands alone.
    public static func dissect(_ record: CaptureRecord, context: DissectionContext? = nil) -> PacketDissection {
        var b = TreeBuilder()
        var protocolName = record.linkType == .ethernet ? "Ethernet" : "Raw"
        var summary = ""
        let frame = record.data[...]

        b.open(label: "Frame", value: "\(record.originalLength) bytes on wire, \(record.data.count) bytes captured", range: 0..<record.data.count)
        b.leaf("frame.len", "Frame length", "\(record.originalLength)", nil)
        b.leaf("frame.cap_len", "Capture length", "\(record.data.count)", nil)
        b.close()

        guard let ipOffset = LinkLayer.ipOffset(in: frame, linkType: record.linkType),
              let ip = try? IPPacket.parse(frame[(frame.startIndex + ipOffset)...]) else {
            return PacketDissection(fields: b.roots, protocolName: protocolName, summary: "Not an IP packet")
        }
        let o = ipOffset
        dissectIP(ip, at: o, into: &b)
        protocolName = ip.version == 4 ? "IPv4" : "IPv6"
        summary = "\(ip.source) → \(ip.destination)"

        let t = o + ip.headerLength
        guard ip.fragmentOffset == 0 else {
            return PacketDissection(fields: b.roots, protocolName: protocolName, summary: "Fragment at offset \(ip.fragmentOffset)")
        }
        switch ip.protocolNumber {
        case IPProtocolNumber.tcp:
            guard let tcp = try? TCPSegment.parse(ip.payload) else { break }
            protocolName = "TCP"
            summary = "\(tcp.sourcePort) → \(tcp.destinationPort) \(tcp.flags) Seq=\(tcp.sequenceNumber) Len=\(tcp.payload.count)"
            dissectTCP(tcp, at: t, into: &b)
            let p = t + tcp.headerLength
            let payload = tcp.payload
            if payload.isEmpty { break }
            if let context {
                if let records = context.tlsRecords(ip: ip, tcp: tcp) {
                    var afterCCS = context.afterChangeCipherSpec(ip: ip, tcp: tcp)
                    var tls13 = context.isTLS13(ip: ip, tcp: tcp)
                    if let info = dissectTLS(records: records, payloadRange: p..<(p + payload.count), recordOffset: nil,
                                             afterChangeCipherSpec: &afterCCS, isTLS13: &tls13, into: &b) {
                        protocolName = "TLS"
                        summary = info
                    } else {
                        summary += " [TCP segment of a reassembled PDU]"
                    }
                    if afterCCS { context.setAfterChangeCipherSpec(ip: ip, tcp: tcp) }
                    if tls13 { context.markTLS13(ip: ip, tcp: tcp) }
                    break
                }
            } else if TLS.looksLikeTLS(payload) {
                var afterCCS = false
                var tls13 = false
                if let info = dissectTLS(records: TLS.records(in: payload), payloadRange: p..<(p + payload.count), recordOffset: p,
                                         afterChangeCipherSpec: &afterCCS, isTLS13: &tls13, into: &b) {
                    protocolName = "TLS"
                    summary = info
                }
                break
            }
            if let request = HTTP1.parseRequest(payload) {
                protocolName = "HTTP"
                summary = "\(request.method) \(request.target) \(request.version)"
                b.open(label: "Hypertext Transfer Protocol", value: "", range: p..<(p + payload.count))
                b.leaf("http.request.method", "Method", request.method, nil)
                b.leaf("http.request.uri", "Request URI", request.target, nil)
                b.leaf("http.request.version", "Version", request.version, nil)
                if let host = request.host { b.leaf("http.host", "Host", host, nil) }
                if let ua = request.userAgent { b.leaf("http.user_agent", "User-Agent", ua, nil) }
                b.close()
            } else if let response = HTTP1.parseResponse(payload) {
                protocolName = "HTTP"
                summary = "\(response.version) \(response.statusCode) \(response.reason)"
                b.open(label: "Hypertext Transfer Protocol", value: "", range: p..<(p + payload.count))
                b.leaf("http.response.version", "Version", response.version, nil)
                b.leaf("http.response.code", "Status code", "\(response.statusCode)", nil)
                b.leaf("http.response.phrase", "Reason phrase", response.reason, nil)
                b.close()
            }
        case IPProtocolNumber.udp:
            guard let udp = try? UDPDatagram.parse(ip.payload) else { break }
            protocolName = "UDP"
            summary = "\(udp.sourcePort) → \(udp.destinationPort) Len=\(udp.payload.count)"
            b.open(label: "User Datagram Protocol", value: "Src Port: \(udp.sourcePort), Dst Port: \(udp.destinationPort)", range: t..<(t + 8))
            b.leaf("udp.srcport", "Source port", "\(udp.sourcePort)", t..<(t + 2))
            b.leaf("udp.dstport", "Destination port", "\(udp.destinationPort)", (t + 2)..<(t + 4))
            b.leaf("udp.length", "Length", "\(udp.length)", (t + 4)..<(t + 6))
            b.leaf("udp.checksum", "Checksum", hex(udp.checksum), (t + 6)..<(t + 8))
            b.close()
            let p = t + 8
            let ports: Set<UInt16> = [udp.sourcePort, udp.destinationPort]
            if !ports.isDisjoint(with: [53, 5353, 5355]), let dns = try? DNSMessage.parse(udp.payload) {
                protocolName = ports.contains(5353) ? "MDNS" : "DNS"
                summary = dnsSummary(dns)
                dissectDNS(dns, at: p, length: udp.payload.count, into: &b)
            } else if QUICHeader.looksLikeQUIC(udp.payload) || (ports.contains(443) && isQUICShortHeader(udp.payload)) {
                protocolName = "QUIC"
                summary = dissectQUIC(datagram: udp.payload, at: p, into: &b)
            }
        case IPProtocolNumber.icmp, IPProtocolNumber.icmpv6:
            let v6 = ip.protocolNumber == IPProtocolNumber.icmpv6
            guard let icmp = try? ICMPMessage.parse(ip.payload, isV6: v6) else { break }
            protocolName = v6 ? "ICMPv6" : "ICMP"
            summary = icmp.summary
            let prefix = v6 ? "icmpv6" : "icmp"
            b.open(label: v6 ? "Internet Control Message Protocol v6" : "Internet Control Message Protocol", value: "", range: t..<(t + ip.payload.count))
            b.leaf("\(prefix).type", "Type", "\(icmp.type)", t..<(t + 1))
            b.leaf("\(prefix).code", "Code", "\(icmp.code)", (t + 1)..<(t + 2))
            b.leaf("\(prefix).checksum", "Checksum", hex(icmp.checksum), (t + 2)..<(t + 4))
            b.close()
        default:
            protocolName = IPProtocolNumber.name(ip.protocolNumber)
        }
        return PacketDissection(fields: b.roots, protocolName: protocolName, summary: summary)
    }

    // MARK: - Layers

    static func dissectIP(_ ip: IPPacket, at o: Int, into b: inout TreeBuilder) {
        if ip.version == 4 {
            b.open(label: "Internet Protocol Version 4", value: "Src: \(ip.source), Dst: \(ip.destination)", range: o..<(o + ip.headerLength))
            b.leaf("ip.version", "Version", "4", o..<(o + 1))
            b.leaf("ip.hdr_len", "Header length", "\(ip.headerLength)", o..<(o + 1))
            b.leaf("ip.dsfield", "Differentiated services", hex8(ip.trafficClass), (o + 1)..<(o + 2))
            b.leaf("ip.len", "Total length", "\(ip.totalLength)", (o + 2)..<(o + 4))
            b.leaf("ip.id", "Identification", hex(ip.identification ?? 0), (o + 4)..<(o + 6))
            b.leaf("ip.flags.df", "Don't fragment", bool(ip.dontFragment), (o + 6)..<(o + 7))
            b.leaf("ip.flags.mf", "More fragments", bool(ip.moreFragments), (o + 6)..<(o + 7))
            b.leaf("ip.frag_offset", "Fragment offset", "\(ip.fragmentOffset)", (o + 6)..<(o + 8))
            b.leaf("ip.ttl", "Time to live", "\(ip.ttl)", (o + 8)..<(o + 9))
            b.leaf("ip.proto", "Protocol", "\(ip.protocolNumber)", (o + 9)..<(o + 10))
            b.leaf("ip.checksum", "Header checksum", hex(ip.headerChecksum ?? 0), (o + 10)..<(o + 12))
            b.leaf("ip.src", "Source address", "\(ip.source)", (o + 12)..<(o + 16))
            b.leaf("ip.dst", "Destination address", "\(ip.destination)", (o + 16)..<(o + 20))
            b.close()
        } else {
            b.open(label: "Internet Protocol Version 6", value: "Src: \(ip.source), Dst: \(ip.destination)", range: o..<(o + ip.headerLength))
            b.leaf("ipv6.version", "Version", "6", o..<(o + 1))
            b.leaf("ipv6.tclass", "Traffic class", "0x" + pad(String(ip.trafficClass, radix: 16), 8), o..<(o + 2))
            b.leaf("ipv6.flow", "Flow label", "0x" + pad(String(ip.flowLabel ?? 0, radix: 16), 6), (o + 1)..<(o + 4))
            b.leaf("ipv6.plen", "Payload length", "\(ip.totalLength - 40)", (o + 4)..<(o + 6))
            b.leaf("ipv6.nxt", "Next header", "\(ip.headerNextHeader)", (o + 6)..<(o + 7))
            b.leaf("ipv6.hlim", "Hop limit", "\(ip.ttl)", (o + 7)..<(o + 8))
            b.leaf("ipv6.src", "Source address", "\(ip.source)", (o + 8)..<(o + 24))
            b.leaf("ipv6.dst", "Destination address", "\(ip.destination)", (o + 24)..<(o + 40))
            b.close()
        }
    }

    static func dissectTCP(_ tcp: TCPSegment, at t: Int, into b: inout TreeBuilder) {
        b.open(label: "Transmission Control Protocol", value: "Src Port: \(tcp.sourcePort), Dst Port: \(tcp.destinationPort), Len: \(tcp.payload.count)", range: t..<(t + tcp.headerLength))
        b.leaf("tcp.srcport", "Source port", "\(tcp.sourcePort)", t..<(t + 2))
        b.leaf("tcp.dstport", "Destination port", "\(tcp.destinationPort)", (t + 2)..<(t + 4))
        b.leaf("tcp.len", "Segment length", "\(tcp.payload.count)", nil)
        b.leaf("tcp.seq_raw", "Sequence number (raw)", "\(tcp.sequenceNumber)", (t + 4)..<(t + 8))
        b.leaf("tcp.ack_raw", "Acknowledgment number (raw)", "\(tcp.acknowledgmentNumber)", (t + 8)..<(t + 12))
        b.leaf("tcp.hdr_len", "Header length", "\(tcp.headerLength)", (t + 12)..<(t + 13))
        b.leaf("tcp.flags", "Flags \(tcp.flags)", hex(tcp.flags.rawValue), (t + 12)..<(t + 14))
        b.leaf("tcp.window_size_value", "Window", "\(tcp.window)", (t + 14)..<(t + 16))
        b.leaf("tcp.checksum", "Checksum", hex(tcp.checksum), (t + 16)..<(t + 18))
        b.leaf("tcp.urgent_pointer", "Urgent pointer", "\(tcp.urgentPointer)", (t + 18)..<(t + 20))
        if !tcp.options.isEmpty {
            b.open(label: "Options", value: "\(tcp.headerLength - 20) bytes", range: (t + 20)..<(t + tcp.headerLength))
            for option in tcp.options {
                switch option {
                case .maximumSegmentSize(let v): b.leaf("tcp.options.mss_val", "Maximum segment size", "\(v)", nil)
                case .windowScale(let v): b.leaf("tcp.options.wscale.shift", "Window scale shift", "\(v)", nil)
                case .sackPermitted: b.leaf("tcp.options.sack_perm", "SACK permitted", "", nil)
                case .sack(let blocks): b.leaf("tcp.options.sack", "SACK", blocks.map { "\($0.lowerBound)-\($0.upperBound)" }.joined(separator: " "), nil)
                case .timestamps(let v, let e): b.leaf("tcp.options.timestamp.tsval", "Timestamps", "TSval \(v), TSecr \(e)", nil)
                case .other(let kind, _): b.leaf(nil, "Option", "kind \(kind)", nil)
                }
            }
            b.close()
        }
        b.close()
    }

    /// Adds TLS records to the tree and returns an Info summary, or nil if there were none.
    /// `recordOffset` is the frame offset of the first record when records map directly
    /// onto this frame's bytes; reassembled records get no byte ranges.
    static func dissectTLS(
        records: [TLSRecord], payloadRange: Range<Int>, recordOffset: Int?,
        afterChangeCipherSpec: inout Bool, isTLS13: inout Bool, into b: inout TreeBuilder
    ) -> String? {
        guard !records.isEmpty else { return nil }
        var infos: [String] = []
        var offset = recordOffset
        func range(_ start: Int, _ length: Int) -> Range<Int>? {
            offset.map { ($0 + start)..<($0 + start + length) }
        }
        b.open(label: "Transport Layer Security", value: "", range: payloadRange)
        for record in records {
            let length = 5 + record.fragment.count
            let typeName = contentTypeName(record.contentType)
            b.open(label: "TLS record", value: "\(TLS.versionName(record.version)) \(typeName)", range: range(0, length))
            let opaque = isTLS13 && record.contentType == TLSContentType.applicationData.rawValue
            b.leaf(opaque ? "tls.record.opaque_type" : "tls.record.content_type", "Content type", "\(record.contentType)", range(0, 1))
            b.leaf("tls.record.version", "Version", hex(record.version), range(1, 2))
            b.leaf("tls.record.length", "Length", "\(record.fragment.count)", range(3, 2))
            if record.contentType == TLSContentType.changeCipherSpec.rawValue {
                afterChangeCipherSpec = true
                infos.append("Change Cipher Spec")
            } else if record.contentType == TLSContentType.handshake.rawValue && !afterChangeCipherSpec {
                var m = 5
                for message in TLS.messages(inHandshakeBytes: record.fragment) {
                    guard let type = TLSHandshakeType(rawValue: message.type) else { break }
                    b.open(label: "Handshake", value: handshakeName(type), range: range(m, 4 + message.body.count))
                    b.leaf("tls.handshake.type", "Handshake type", "\(message.type)", range(m, 1))
                    b.leaf("tls.handshake.length", "Length", "\(message.body.count)", range(m + 1, 3))
                    infos.append(handshakeName(type))
                    if type == .clientHello, let hello = try? TLSClientHello.parse(body: message.body) {
                        dissectClientHello(hello, into: &b)
                    } else if type == .serverHello, let hello = try? TLSServerHello.parse(body: message.body) {
                        b.leaf("tls.handshake.version", "Version", hex(hello.legacyVersion), nil)
                        b.leaf("tls.handshake.ciphersuite", "Cipher suite", hex(hello.cipherSuite), nil)
                        if hello.negotiatedVersion != hello.legacyVersion {
                            b.leaf("tls.handshake.extensions.supported_version", "Selected version", hex(hello.negotiatedVersion), nil)
                        }
                        if let alpn = hello.alpnProtocol {
                            b.leaf("tls.handshake.extensions_alpn_str", "ALPN protocol", alpn, nil)
                        }
                        if hello.negotiatedVersion == 0x0304 { isTLS13 = true }
                    }
                    b.close()
                    m += 4 + message.body.count
                }
            } else if record.contentType == TLSContentType.handshake.rawValue {
                infos.append("Encrypted Handshake Message")
            } else if record.contentType == TLSContentType.applicationData.rawValue {
                infos.append("Application Data")
            } else if record.contentType == TLSContentType.alert.rawValue {
                infos.append(afterChangeCipherSpec ? "Encrypted Alert" : "Alert")
            }
            b.close()
            offset = offset.map { $0 + length }
        }
        b.close()
        var seen = Set<String>()
        return infos.filter { seen.insert($0).inserted }.joined(separator: ", ")
    }

    static func dissectClientHello(_ hello: TLSClientHello, into b: inout TreeBuilder) {
        b.leaf("tls.handshake.version", "Version", hex(hello.legacyVersion), nil)
        b.leaf("tls.handshake.session_id_length", "Session ID length", "\(hello.sessionID.count)", nil)
        b.open(label: "Cipher suites", value: "\(hello.cipherSuites.count) suites", range: nil)
        for suite in hello.cipherSuites {
            b.leaf("tls.handshake.ciphersuite", "Cipher suite", hex(suite), nil)
        }
        b.close()
        if let sni = hello.serverName {
            b.leaf("tls.handshake.extensions_server_name", "Server name", sni, nil)
        }
        for proto in hello.alpnProtocols {
            b.leaf("tls.handshake.extensions_alpn_str", "ALPN protocol", proto, nil)
        }
        for v in hello.supportedVersions {
            b.leaf("tls.handshake.extensions.supported_version", "Supported version", hex(v), nil)
        }
        if hello.hasEncryptedClientHello {
            b.leaf(nil, "Encrypted Client Hello", "present", nil)
        }
    }

    static func dissectDNS(_ dns: DNSMessage, at p: Int, length: Int, into b: inout TreeBuilder) {
        b.open(label: "Domain Name System", value: dns.isResponse ? "response" : "query", range: p..<(p + length))
        b.leaf("dns.id", "Transaction ID", hex(dns.id), p..<(p + 2))
        b.leaf("dns.flags.response", "Response", bool(dns.isResponse), (p + 2)..<(p + 3))
        b.leaf("dns.flags.opcode", "Opcode", "\(dns.opcode)", (p + 2)..<(p + 3))
        if dns.isResponse {
            b.leaf("dns.flags.rcode", "Reply code", "\(dns.rawResponseCode)", (p + 3)..<(p + 4))
        }
        b.leaf("dns.count.queries", "Questions", "\(dns.questions.count)", (p + 4)..<(p + 6))
        b.leaf("dns.count.answers", "Answer RRs", "\(dns.answers.count)", (p + 6)..<(p + 8))
        b.leaf("dns.count.auth_rr", "Authority RRs", "\(dns.authorities.count)", (p + 8)..<(p + 10))
        b.leaf("dns.count.add_rr", "Additional RRs", "\(dns.additionals.count)", (p + 10)..<(p + 12))
        if !dns.questions.isEmpty {
            b.open(label: "Queries", value: "", range: nil)
            for q in dns.questions {
                b.open(label: displayName(q.name), value: "type \(q.type), class \(q.recordClass)", range: nil)
                b.leaf("dns.qry.name", "Name", displayName(q.name), nil)
                b.leaf("dns.qry.type", "Type", "\(q.type.rawValue)", nil)
                b.leaf("dns.qry.class", "Class", hex(q.recordClass), nil)
                b.close()
            }
            b.close()
        }
        for (title, section) in [("Answers", dns.answers), ("Authoritative nameservers", dns.authorities), ("Additional records", dns.additionals)] where !section.isEmpty {
            b.open(label: title, value: "", range: nil)
            for rr in section {
                b.open(label: displayName(rr.name), value: "type \(rr.type)", range: nil)
                b.leaf("dns.resp.name", "Name", displayName(rr.name), nil)
                b.leaf("dns.resp.type", "Type", "\(rr.type.rawValue)", nil)
                if rr.type != .opt {
                    b.leaf("dns.resp.ttl", "Time to live", "\(rr.ttl)", nil)
                }
                switch rr.data {
                case .address(let a): b.leaf(a.isV4 ? "dns.a" : "dns.aaaa", "Address", "\(a)", nil)
                case .name(let n):
                    let key: String? = rr.type == .cname ? "dns.cname" : rr.type == .ns ? "dns.ns" : rr.type == .ptr ? "dns.ptr.domain_name" : nil
                    b.leaf(key, "Name", n, nil)
                case .mx(let pref, let exchange):
                    b.leaf("dns.mx.preference", "Preference", "\(pref)", nil)
                    b.leaf("dns.mx.mail_exchange", "Mail exchange", exchange, nil)
                case .srv(let prio, let weight, let port, let target):
                    b.leaf("dns.srv.target", "Target", target, nil)
                    b.leaf("dns.srv.port", "Port", "\(port)", nil)
                    b.leaf(nil, "Priority / weight", "\(prio) / \(weight)", nil)
                case .txt(let strings): b.leaf("dns.txt", "Text", strings.joined(separator: " "), nil)
                case .soa(let primary, let responsible, let serial):
                    b.leaf("dns.soa.mname", "Primary name server", primary, nil)
                    b.leaf("dns.soa.rname", "Responsible authority", responsible, nil)
                    b.leaf("dns.soa.serial_number", "Serial", "\(serial)", nil)
                case .raw(let bytes): b.leaf(nil, "Data", "\(bytes.count) bytes", nil)
                }
                b.close()
            }
            b.close()
        }
        b.close()
    }

    static func dissectQUIC(datagram: ArraySlice<UInt8>, at p: Int, into b: inout TreeBuilder) -> String {
        var rest = datagram
        var offset = p
        var infos: [String] = []
        var clientDCID: [UInt8]?
        while !rest.isEmpty {
            guard let header = try? QUICHeader.parse(rest) else { break }
            let size = header.packetSize.map { min($0, rest.count) } ?? rest.count
            b.open(label: "QUIC", value: header.packetType.rawValue, range: offset..<(offset + size))
            b.leaf("quic.header_form", "Header form", header.isLongHeader ? "1" : "0", offset..<(offset + 1))
            if header.isLongHeader {
                if let raw = header.rawLongPacketType {
                    b.leaf("quic.long.packet_type", "Packet type", "\(raw)", offset..<(offset + 1))
                }
                if let v = header.version {
                    b.leaf("quic.version", "Version", "0x" + pad(String(v, radix: 16), 8), (offset + 1)..<(offset + 5))
                }
                if !header.destinationConnectionID.isEmpty {
                    b.leaf("quic.dcid", "Destination connection ID", header.destinationConnectionID.hexString, nil)
                }
                if !header.sourceConnectionID.isEmpty {
                    b.leaf("quic.scid", "Source connection ID", header.sourceConnectionID.hexString, nil)
                }
                if let length = header.length {
                    b.leaf("quic.length", "Length", "\(length)", nil)
                }
                if header.packetType == .initial {
                    if clientDCID == nil { clientDCID = header.destinationConnectionID }
                    let frames = QUICInitialDecryptor.cryptoFrames(inDatagram: rest.prefix(size), clientDCID: clientDCID)
                    let stream = QUICInitialDecryptor.contiguousCryptoStream(frames)
                    for message in TLS.messages(inHandshakeBytes: stream[...]) {
                        guard let type = TLSHandshakeType(rawValue: message.type) else { break }
                        b.open(label: "TLS handshake", value: handshakeName(type), range: nil)
                        b.leaf("tls.handshake.type", "Handshake type", "\(message.type)", nil)
                        if type == .clientHello, let hello = try? TLSClientHello.parse(body: message.body) {
                            dissectClientHello(hello, into: &b)
                        }
                        b.close()
                    }
                }
            }
            b.close()
            infos.append(header.packetType.rawValue)
            offset += size
            rest = rest.dropFirst(size)
            if !header.isLongHeader { break }
        }
        return infos.joined(separator: ", ")
    }

    // MARK: - Formatting

    static func isQUICShortHeader(_ payload: ArraySlice<UInt8>) -> Bool {
        guard let first = payload.first else { return false }
        return first & 0xC0 == 0x40
    }

    static func dnsSummary(_ dns: DNSMessage) -> String {
        let q = dns.questions.first.map { "\($0.type) \(displayName($0.name))" } ?? ""
        if !dns.isResponse { return "Standard query \(hex(dns.id)) \(q)" }
        let answers = dns.answers.map { rr -> String in
            switch rr.data {
            case .address(let a): return "\(rr.type) \(a)"
            case .name(let n): return "\(rr.type) \(n)"
            default: return "\(rr.type)"
            }
        }
        let rcode = dns.responseCode == .noError || dns.responseCode == nil ? "" : " \(dns.responseCode!)"
        return "Standard query response \(hex(dns.id))\(rcode) \(q) \(answers.joined(separator: " "))"
            .trimmingTrailingSpaces()
    }

    static func contentTypeName(_ t: UInt8) -> String {
        switch t {
        case 20: return "Change Cipher Spec"
        case 21: return "Alert"
        case 22: return "Handshake"
        case 23: return "Application Data"
        case 24: return "Heartbeat"
        default: return "Content type \(t)"
        }
    }

    static func handshakeName(_ t: TLSHandshakeType) -> String {
        switch t {
        case .helloRequest: return "Hello Request"
        case .clientHello: return "Client Hello"
        case .serverHello: return "Server Hello"
        case .newSessionTicket: return "New Session Ticket"
        case .endOfEarlyData: return "End of Early Data"
        case .encryptedExtensions: return "Encrypted Extensions"
        case .certificate: return "Certificate"
        case .serverKeyExchange: return "Server Key Exchange"
        case .certificateRequest: return "Certificate Request"
        case .serverHelloDone: return "Server Hello Done"
        case .certificateVerify: return "Certificate Verify"
        case .clientKeyExchange: return "Client Key Exchange"
        case .finished: return "Finished"
        case .keyUpdate: return "Key Update"
        }
    }

    static func displayName(_ name: String) -> String { name.isEmpty ? "<Root>" : name }
    static func bool(_ v: Bool) -> String { v ? "True" : "False" }
    static func hex(_ v: UInt16) -> String { String(format4Hex: v) }
    static func hex8(_ v: UInt8) -> String { "0x" + pad(String(v, radix: 16), 2) }
    static func pad(_ s: String, _ n: Int) -> String { String(repeating: "0", count: max(0, n - s.count)) + s }
}

extension String {
    func trimmingTrailingSpaces() -> String {
        var s = self
        while s.last == " " { s.removeLast() }
        return s
    }
}

/// Accumulates a field tree with stable, sequential ids.
struct TreeBuilder {
    private(set) var roots: [PacketField] = []
    private var stack: [PacketField] = []
    private var nextID = 0

    mutating func open(label: String, value: String, range: Range<Int>?, key: String? = nil) {
        stack.append(PacketField(id: takeID(), key: key, label: label, value: value, range: range, children: []))
    }

    mutating func close() {
        guard let node = stack.popLast() else { return }
        if stack.isEmpty { roots.append(node) } else { stack[stack.count - 1].children.append(node) }
    }

    mutating func leaf(_ key: String?, _ label: String, _ value: String, _ range: Range<Int>?) {
        let node = PacketField(id: takeID(), key: key, label: label, value: value, range: range, children: [])
        if stack.isEmpty { roots.append(node) } else { stack[stack.count - 1].children.append(node) }
    }

    private mutating func takeID() -> Int {
        defer { nextID += 1 }
        return nextID
    }
}
