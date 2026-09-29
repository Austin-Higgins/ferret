import FerretParsers

/// Turns raw IP packets into connections, DNS lookups and counters.
/// Runs in the app, never in the tunnel extension. Not thread-safe: confine
/// each instance to one actor or queue.
public final class TrafficAnalyzer {
    public private(set) var connections: [Connection] = []
    public private(set) var dnsLookups: [DNSLookup] = []
    public private(set) var stats = CaptureStats()

    /// Samples kept per connection for timelines; older ones are counted, not stored.
    public var maxSamplesPerConnection = 2_000
    /// UDP flows idle this long start a new connection.
    public var udpIdleTimeoutSeconds: Int64 = 120

    private var connectionIndex: [FlowKey: Int] = [:]
    private var streams: [Int: StreamSniffer] = [:]
    private var pendingLookups: [PendingLookupKey: Int] = [:]
    /// Remote address → most recent lookup that returned it.
    private var addressNames: [IPAddress: Int] = [:]
    private var localAddresses: Set<IPAddress> = []

    public init() {}

    /// Declares addresses that belong to the phone (the tunnel's interface
    /// addresses). Without this, the first sender of a flow is treated as local.
    public func setLocalAddresses(_ addresses: [IPAddress]) {
        localAddresses = Set(addresses)
    }

    public func ingest(record: CaptureRecord, frameIndex: Int) {
        guard let ip = record.ipBytes else { return }
        ingest(ipPacket: ip, timestamp: record.timestamp, direction: nil, frameIndex: frameIndex)
    }

    /// Adds one IP datagram. `direction` comes from the tunnel; pass nil for files.
    public func ingest(ipPacket bytes: ArraySlice<UInt8>, timestamp: CaptureTimestamp, direction: PacketDirection?, frameIndex: Int) {
        stats.packets += 1
        stats.bytes += bytes.count
        if stats.firstPacket == nil { stats.firstPacket = timestamp }
        stats.lastPacket = timestamp

        guard let packet = try? DecodedPacket.decode(ipBytes: bytes) else { return }
        let ip = packet.ip
        let transport: TransportKind
        var srcPort: UInt16 = 0, dstPort: UInt16 = 0
        var tcpFlags: TCPFlags?
        switch packet.transport {
        case .tcp(let t): transport = .tcp; srcPort = t.sourcePort; dstPort = t.destinationPort; tcpFlags = t.flags
        case .udp(let u): transport = .udp; srcPort = u.sourcePort; dstPort = u.destinationPort
        case .icmp: transport = .icmp
        case .other: transport = .other
        }
        let src = Endpoint(address: ip.source, port: srcPort)
        let dst = Endpoint(address: ip.destination, port: dstPort)

        let dir = direction ?? inferDirection(transport: transport, src: src, dst: dst)
        let key = dir == .outbound
            ? FlowKey(transport: transport, local: src, remote: dst)
            : FlowKey(transport: transport, local: dst, remote: src)

        let index = resolveConnection(for: key, timestamp: timestamp, tcpFlags: tcpFlags)
        var conn = connections[index]
        conn.lastSeen = timestamp
        if dir == .outbound {
            conn.packetsOut += 1
            conn.bytesOut += bytes.count
        } else {
            conn.packetsIn += 1
            conn.bytesIn += bytes.count
        }
        if conn.samples.count < maxSamplesPerConnection {
            conn.samples.append(PacketSample(
                timestamp: timestamp, direction: dir, size: bytes.count,
                frameIndex: frameIndex, tcpFlags: tcpFlags?.rawValue))
        } else {
            conn.droppedSamples += 1
        }
        if let flags = tcpFlags, flags.contains(.rst) || flags.contains(.fin) { conn.closed = true }

        inspectApplication(packet, direction: dir, connection: &conn, timestamp: timestamp, frameIndex: frameIndex)
        connections[index] = conn
    }

    public func connection(id: Int) -> Connection? {
        connections.indices.contains(id) ? connections[id] : nil
    }

    public func lookup(id: Int) -> DNSLookup? {
        dnsLookups.indices.contains(id) ? dnsLookups[id] : nil
    }

    // MARK: - Flow tracking

    private func inferDirection(transport: TransportKind, src: Endpoint, dst: Endpoint) -> PacketDirection {
        if localAddresses.contains(src.address) { return .outbound }
        if localAddresses.contains(dst.address) { return .inbound }
        // An existing flow decides.
        if connectionIndex[FlowKey(transport: transport, local: dst, remote: src)] != nil { return .inbound }
        if connectionIndex[FlowKey(transport: transport, local: src, remote: dst)] != nil { return .outbound }
        // Otherwise the side using a well-known port is the server.
        if src.port != 0 && src.port < 1024 && (dst.port >= 1024 || dst.port == 0) { return .inbound }
        return .outbound
    }

    private func resolveConnection(for key: FlowKey, timestamp: CaptureTimestamp, tcpFlags: TCPFlags?) -> Int {
        if let existing = connectionIndex[key] {
            let conn = connections[existing]
            let idle = timestamp.seconds - conn.lastSeen.seconds
            let reopened = (tcpFlags.map { $0.contains(.syn) && !$0.contains(.ack) } ?? false) && conn.closed
            let expired = key.transport != .tcp && idle > udpIdleTimeoutSeconds
            if !reopened && !expired { return existing }
        }
        var conn = Connection(id: connections.count, key: key, firstSeen: timestamp)
        if let lookupID = addressNames[key.remote.address] {
            conn.dnsName = dnsLookups[lookupID].name
            conn.dnsLookupID = lookupID
        }
        connections.append(conn)
        connectionIndex[key] = conn.id
        stats.connections += 1
        return conn.id
    }

    // MARK: - Application layer

    private func inspectApplication(
        _ packet: DecodedPacket, direction: PacketDirection, connection conn: inout Connection,
        timestamp: CaptureTimestamp, frameIndex: Int
    ) {
        switch packet.transport {
        case .udp(let udp):
            if case .dns(let dns) = packet.application {
                conn.tags.insert(.dns)
                recordDNS(dns, resolver: conn.key.remote.address, timestamp: timestamp, frameIndex: frameIndex, connection: &conn)
            } else if QUICHeader.looksLikeQUIC(udp.payload) || (conn.tags.contains(.quic) && !udp.payload.isEmpty) {
                conn.tags.insert(.quic)
                if direction == .outbound, conn.serverName == nil,
                   let header = try? QUICHeader.parse(udp.payload), header.packetType == .initial {
                    if let v = header.version { conn.quicVersion = QUICHeader.versionName(v) }
                    var sniffer = streams[conn.id] ?? StreamSniffer()
                    if sniffer.quicDatagrams.count < 4 {
                        sniffer.quicDatagrams.append(Array(udp.payload))
                        if let hello = QUICInitialDecryptor.clientHello(inDatagrams: sniffer.quicDatagrams.map { $0[...] }) {
                            applyClientHello(hello, to: &conn)
                            sniffer.quicDatagrams = []
                        }
                    }
                    streams[conn.id] = sniffer
                }
            }
        case .tcp(let tcp):
            if conn.key.remote.port == 53, let dns = DNSMessage.parseTCPStream(tcp.payload).first {
                conn.tags.insert(.dns)
                recordDNS(dns, resolver: conn.key.remote.address, timestamp: timestamp, frameIndex: frameIndex, connection: &conn)
                return
            }
            var sniffer = streams[conn.id] ?? StreamSniffer()
            guard !sniffer.done else { return }
            let fresh: [UInt8]
            if direction == .outbound {
                fresh = sniffer.outbound.accept(sequence: tcp.sequenceNumber, flags: tcp.flags, payload: tcp.payload)
                sniffer.outboundBytes.append(contentsOf: fresh.prefix(max(0, StreamSniffer.limit - sniffer.outboundBytes.count)))
            } else {
                fresh = sniffer.inbound.accept(sequence: tcp.sequenceNumber, flags: tcp.flags, payload: tcp.payload)
                sniffer.inboundBytes.append(contentsOf: fresh.prefix(max(0, StreamSniffer.limit - sniffer.inboundBytes.count)))
            }
            if !fresh.isEmpty { sniff(&sniffer, connection: &conn, timestamp: timestamp) }
            streams[conn.id] = sniffer.done ? StreamSniffer.finished : sniffer
        default:
            break
        }
    }

    private func sniff(_ s: inout StreamSniffer, connection conn: inout Connection, timestamp: CaptureTimestamp) {
        let out = s.outboundBytes[...]
        if TLS.looksLikeTLS(out) {
            conn.tags.insert(.tls)
            if !s.sawClientHello, let hello = TLS.clientHello(inStream: out) {
                applyClientHello(hello, to: &conn)
                s.sawClientHello = true
            }
            if s.sawClientHello, let server = TLS.serverHello(inStream: s.inboundBytes[...]) {
                conn.tlsVersion = TLS.versionName(server.negotiatedVersion)
                if let alpn = server.alpnProtocol { conn.alpn = [alpn] }
                s.done = true
            }
            if out.count >= StreamSniffer.limit || s.inboundBytes.count >= StreamSniffer.limit { s.done = true }
            return
        }
        if HTTP1.looksLikeRequest(out) {
            conn.tags.insert(.http)
            // Record each new request head as the stream grows.
            var cursor = s.httpCursor
            while cursor < out.count {
                let rest = out[(out.startIndex + cursor)...]
                guard let end = headEnd(rest) else { break }
                if let req = HTTP1.parseRequest(rest[..<end]), conn.httpRequests.count < 50 {
                    conn.httpRequests.append(HTTPRequestSummary(
                        timestamp: timestamp, method: req.method, host: req.host, path: req.target))
                }
                // Skip the body when Content-Length says how long it is.
                let head = HTTP1.parseRequest(rest[..<end])
                let bodyLength = head?.headers.first { $0.name.lowercased() == "content-length" }.flatMap { Int($0.value) } ?? 0
                cursor += (end - rest.startIndex) + bodyLength
                if head?.headers.contains(where: { $0.name.lowercased() == "transfer-encoding" }) == true {
                    cursor = out.count
                    s.done = true
                }
            }
            s.httpCursor = cursor
            if out.count >= StreamSniffer.limit { s.done = true }
            return
        }
        if out.count >= 3 { s.done = true }
    }

    /// Index just past the blank line ending an HTTP head, if present.
    private func headEnd(_ bytes: ArraySlice<UInt8>) -> Int? {
        var i = bytes.startIndex
        while i + 3 < bytes.endIndex {
            if bytes[i] == 0x0D && bytes[i + 1] == 0x0A && bytes[i + 2] == 0x0D && bytes[i + 3] == 0x0A { return i + 4 }
            i += 1
        }
        return nil
    }

    private func applyClientHello(_ hello: TLSClientHello, to conn: inout Connection) {
        if let sni = hello.serverName { conn.serverName = Domain.normalize(sni) }
        conn.alpn = hello.alpnProtocols
        conn.encryptedClientHello = hello.hasEncryptedClientHello
    }

    private func recordDNS(_ dns: DNSMessage, resolver: IPAddress, timestamp: CaptureTimestamp, frameIndex: Int, connection conn: inout Connection) {
        guard let q = dns.questions.first else { return }
        let key = PendingLookupKey(resolver: resolver, transactionID: dns.id, name: Domain.normalize(q.name))
        if !dns.isResponse {
            let lookup = DNSLookup(
                id: dnsLookups.count, name: Domain.normalize(q.name), type: q.type.rawValue, transactionID: dns.id,
                resolver: resolver, queriedAt: timestamp, answeredAt: nil, addresses: [], cnames: [],
                responseCode: nil, frameIndices: [frameIndex])
            dnsLookups.append(lookup)
            pendingLookups[key] = lookup.id
            stats.dnsLookups += 1
            if conn.dnsQueries.count < 200 { conn.dnsQueries.append(lookup.name) }
            return
        }
        let id: Int
        if let pending = pendingLookups.removeValue(forKey: key) {
            id = pending
        } else {
            // Response without a captured query (capture started mid-lookup).
            id = dnsLookups.count
            dnsLookups.append(DNSLookup(
                id: id, name: key.name, type: q.type.rawValue, transactionID: dns.id, resolver: resolver,
                queriedAt: timestamp, answeredAt: nil, addresses: [], cnames: [], responseCode: nil, frameIndices: []))
            stats.dnsLookups += 1
        }
        dnsLookups[id].answeredAt = timestamp
        dnsLookups[id].addresses = dns.answerAddresses
        dnsLookups[id].cnames = dns.cnames
        dnsLookups[id].responseCode = dns.rawResponseCode
        dnsLookups[id].frameIndices.append(frameIndex)
        for address in dns.answerAddresses { addressNames[address] = id }
    }
}

struct PendingLookupKey: Hashable {
    var resolver: IPAddress
    var transactionID: UInt16
    var name: String
}

/// Bounded per-connection stream state used to find ClientHello, ServerHello and HTTP heads.
struct StreamSniffer {
    static let limit = 32 * 1024
    static var finished: StreamSniffer {
        var s = StreamSniffer()
        s.done = true
        return s
    }

    var outbound = TCPStreamReassembler(maxPendingBytes: 64 * 1024)
    var inbound = TCPStreamReassembler(maxPendingBytes: 64 * 1024)
    var outboundBytes: [UInt8] = []
    var inboundBytes: [UInt8] = []
    var quicDatagrams: [[UInt8]] = []
    var sawClientHello = false
    var httpCursor = 0
    var done = false
}
