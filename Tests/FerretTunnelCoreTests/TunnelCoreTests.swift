import Foundation
import Testing
import FerretParsers
@testable import FerretTunnelCore

/// In-memory server: records what it receives and echoes it back uppercased.
final class EchoTCPUpstream: TCPUpstream {
    var onReady: ((Error?) -> Void)?
    var onReceive: (([UInt8]) -> Void)?
    var onClose: ((Error?) -> Void)?
    var received: [UInt8] = []
    var writeShutdown = false
    var cancelled = false

    func start() { onReady?(nil) }

    func send(_ bytes: [UInt8], completion: @escaping (Error?) -> Void) {
        received += bytes
        completion(nil)
        onReceive?(Array(String(decoding: bytes, as: UTF8.self).uppercased().utf8))
    }

    func receiveMore() {}
    func shutdownWrite() { writeShutdown = true }
    func cancel() { cancelled = true }
}

final class EchoUDPUpstream: UDPUpstream {
    var onReceive: (([UInt8]) -> Void)?
    var onClose: ((Error?) -> Void)?
    func start() {}
    func send(_ datagram: [UInt8]) { onReceive?(datagram.reversed()) }
    func cancel() {}
}

final class RecordingFactory: UpstreamFactory {
    var tcp: [(FlowEndpoints, EchoTCPUpstream)] = []
    var udp: [FlowEndpoints] = []

    func makeTCP(to endpoints: FlowEndpoints) -> TCPUpstream {
        let u = EchoTCPUpstream()
        tcp.append((endpoints, u))
        return u
    }

    func makeUDP(to endpoints: FlowEndpoints) -> UDPUpstream {
        udp.append(endpoints)
        return EchoUDPUpstream()
    }
}

/// Builds a TCP/IP packet the way iOS would hand it to the tunnel.
func tcpPacket(
    from src: IPAddress, _ sport: UInt16, to dst: IPAddress, _ dport: UInt16,
    seq: UInt32, ack: UInt32, flags: TCPFlags, payload: [UInt8] = []
) -> [UInt8] {
    var tcp: [UInt8] = []
    tcp.appendU16(sport)
    tcp.appendU16(dport)
    tcp.appendU32(seq)
    tcp.appendU32(ack)
    let withMSS = flags.contains(.syn)
    tcp.append(withMSS ? 0x60 : 0x50)
    tcp.append(UInt8(flags.rawValue & 0xFF))
    tcp.appendU16(65535)
    tcp.appendU16(0)
    tcp.appendU16(0)
    if withMSS { tcp += [2, 4, 0x05, 0xB4] }
    tcp += payload
    let sum = InternetChecksum.transportChecksum(source: src, destination: dst, protocolNumber: 6, segment: tcp)
    tcp[16] = UInt8(sum >> 8)
    tcp[17] = UInt8(sum & 0xFF)
    let header = src.isV4
        ? IPPacketBuilder.ipv4Header(source: src, destination: dst, protocolNumber: 6, payloadLength: tcp.count)
        : IPPacketBuilder.ipv6Header(source: src, destination: dst, nextHeader: 6, payloadLength: tcp.count)
    return header + tcp
}

@Suite(.serialized) struct TunnelCoreTests {
    /// lwIP is process-global, so one test drives the whole TCP lifecycle for both IP versions.
    @Test func relaysTCPToOriginalDestination() throws {
        let queue = DispatchQueue(label: "test.tunnel")
        let factory = RecordingFactory()
        let relay = TCPRelay(factory: factory, queue: queue)
        var toPhone: [[UInt8]] = []
        relay.output = { toPhone.append($0) }

        try queue.sync { try relay.start() }
        defer { queue.sync { relay.stop() } }

        let cases: [(IPAddress, IPAddress, UInt16)] = [
            (IPAddress("10.111.0.2")!, IPAddress("93.184.216.34")!, 443),
            (IPAddress("fd66:6572:7265::2")!, IPAddress("2606:4700:4700::1111")!, 8443),
        ]
        for (index, (phone, server, port)) in cases.enumerated() {
            toPhone.removeAll()
            let sport: UInt16 = 50_000 + UInt16(index)

            queue.sync { relay.input(tcpPacket(from: phone, sport, to: server, port, seq: 1000, ack: 0, flags: .syn)) }
            let synAck = try #require(toPhone.compactMap { try? DecodedPacket.decode(ipBytes: $0) }.first)
            guard case .tcp(let sa) = synAck.transport else {
                Issue.record("expected TCP SYN-ACK")
                return
            }
            #expect(sa.flags.contains([.syn, .ack]))
            #expect(sa.acknowledgmentNumber == 1001)
            #expect(synAck.ip.source == server)
            #expect(sa.sourcePort == port)
            #expect(synAck.ip.destination == phone)

            let serverSeq = sa.sequenceNumber &+ 1
            queue.sync { relay.input(tcpPacket(from: phone, sport, to: server, port, seq: 1001, ack: serverSeq, flags: .ack)) }
            let (endpoints, upstream) = try #require(factory.tcp.last)
            #expect(endpoints.destination == server)
            #expect(endpoints.destinationPort == port)
            #expect(endpoints.source == phone)
            #expect(endpoints.sourcePort == sport)

            toPhone.removeAll()
            queue.sync {
                relay.input(tcpPacket(from: phone, sport, to: server, port, seq: 1001, ack: serverSeq, flags: [.psh, .ack], payload: Array("hello".utf8)))
            }
            #expect(upstream.received == Array("hello".utf8))
            let payloads = toPhone.compactMap { packet -> [UInt8]? in
                guard let d = try? DecodedPacket.decode(ipBytes: packet), case .tcp(let t) = d.transport, !t.payload.isEmpty else { return nil }
                return Array(t.payload)
            }
            #expect(payloads.flatMap { $0 } == Array("HELLO".utf8))
            #expect(relay.activeFlows == 1 + index)
        }
    }

    @Test func relaysUDPAndRewritesReplies() throws {
        let queue = DispatchQueue(label: "test.udp")
        let factory = RecordingFactory()
        let relay = UDPRelay(factory: factory, queue: queue)
        var toPhone: [[UInt8]] = []
        relay.output = { toPhone.append($0) }

        let phone = IPAddress("10.111.0.2")!
        let resolver = IPAddress("192.168.1.1")!
        let query = DNSQueryBuilder.query(id: 7, name: "example.com", type: .a)
        let packet = IPPacketBuilder.udpPacket(source: phone, sourcePort: 53000, destination: resolver, destinationPort: 53, payload: query)
        let ip = try IPPacket.parse(packet)
        let udp = try UDPDatagram.parse(ip.payload)
        queue.sync { relay.input(ip: ip, udp: udp) }

        #expect(factory.udp == [FlowEndpoints(source: phone, sourcePort: 53000, destination: resolver, destinationPort: 53)])
        let reply = try IPPacket.parse(try #require(toPhone.first))
        let replyUDP = try UDPDatagram.parse(reply.payload)
        #expect(reply.source == resolver)
        #expect(reply.destination == phone)
        #expect(replyUDP.sourcePort == 53)
        #expect(replyUDP.destinationPort == 53000)
        #expect(Array(replyUDP.payload) == query.reversed())
        #expect(InternetChecksum.transportChecksum(source: reply.source, destination: reply.destination, protocolNumber: 17, segment: reply.payload) == 0)
    }
}

#if canImport(Darwin)
@Suite struct ICMPRelayTests {
    @Test func rebuildsEchoRepliesWithValidChecksums() throws {
        let server = IPAddress("1.1.1.1")!
        let phone = IPAddress("10.111.0.2")!
        let reply: [UInt8] = [0, 0, 0, 0, 0x12, 0x34, 0x00, 0x01] + Array("ping".utf8)
        let packet = ICMPRelay.packet(from: server, to: phone, icmp: reply, v6: false)
        let ip = try IPPacket.parse(packet)
        #expect(ip.source == server && ip.destination == phone)
        #expect(ip.headerChecksumValid == true)
        #expect(InternetChecksum.checksum(ip.payload) == 0)

        let v6 = ICMPRelay.packet(from: IPAddress("2606:4700:4700::1111")!, to: IPAddress("fd66:6572:7265::2")!,
                                  icmp: [129, 0, 0, 0, 0x12, 0x34, 0, 1], v6: true)
        let ip6 = try IPPacket.parse(v6)
        #expect(InternetChecksum.transportChecksum(source: ip6.source, destination: ip6.destination, protocolNumber: 58, segment: ip6.payload) == 0)
    }

    @Test func sockaddrRoundTrip() {
        for text in ["192.0.2.1", "2001:db8::1"] {
            var storage = sockaddr_storage()
            _ = ICMPRelay.fill(&storage, address: IPAddress(text)!)
            #expect(ICMPRelay.address(from: storage) == IPAddress(text))
        }
    }
}
#endif

#if canImport(Darwin)
@Suite struct ProcessMemoryTests {
    @Test func readsFootprint() throws {
        let bytes = try #require(ProcessMemory.footprintBytes())
        #expect(bytes > 1024 * 1024)
    }
}
#endif
