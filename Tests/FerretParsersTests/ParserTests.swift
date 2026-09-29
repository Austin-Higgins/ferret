import Foundation
import Testing
@testable import FerretParsers

@Suite struct ByteReaderTests {
    @Test func readsBigEndianIntegers() throws {
        var r = ByteReader([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07])
        #expect(try r.readU8() == 0x01)
        #expect(try r.readU16() == 0x0203)
        #expect(try r.readU32() == 0x0405_0607)
        #expect(r.isAtEnd)
        #expect(throws: ParseError.truncated) { try r.readU8() }
    }

    @Test func worksOnSlicesWithNonZeroStartIndex() throws {
        let bytes: [UInt8] = [0xFF, 0xFF, 0x12, 0x34]
        var r = ByteReader(bytes[2...])
        #expect(try r.readU16() == 0x1234)
    }

    // Examples from RFC 9000 appendix A.1.
    static let varInts: [([UInt8], UInt64)] = [
        ([0x25], 37),
        ([0x7B, 0xBD], 15293),
        ([0x9D, 0x7F, 0x3E, 0x7D], 494_878_333),
        ([0xC2, 0x19, 0x7C, 0x5E, 0xFF, 0x14, 0xE8, 0x8C], 151_288_809_941_952_652),
    ]

    @Test(arguments: varInts)
    func decodesQUICVarInts(bytes: [UInt8], value: UInt64) throws {
        var r = ByteReader(bytes)
        #expect(try r.readQUICVarInt() == value)
    }
}

@Suite struct IPAddressTests {
    @Test(arguments: [
        "192.168.170.8", "0.0.0.0", "255.255.255.255",
        "fe80::200:86ff:fe05:80fa", "ff05::9999", "2001:4f8:4:7:2e0:81ff:fe52:9a6b",
        "::", "::1", "2001:db8::1:0:0:1", "::ffff:10.0.0.1",
    ])
    func roundTripsCanonicalText(text: String) throws {
        let address = try #require(IPAddress(text))
        #expect(address.description == text)
        #expect(IPAddress(bytes: address.bytes) == address)
    }

    @Test func compressesLongestZeroRun() {
        #expect(IPAddress("2001:0db8:0000:0000:0001:0000:0000:0001")?.description == "2001:db8::1:0:0:1")
    }

    @Test func rejectsGarbage() {
        #expect(IPAddress("1.2.3") == nil)
        #expect(IPAddress("1.2.3.256") == nil)
        #expect(IPAddress("1::2::3") == nil)
        #expect(IPAddress("12345::") == nil)
    }

    @Test func classifiesRanges() {
        #expect(IPAddress("10.1.2.3")!.isPrivate)
        #expect(IPAddress("192.168.1.1")!.isPrivate)
        #expect(!IPAddress("8.8.8.8")!.isPrivate)
        #expect(IPAddress("fe80::1")!.isPrivate)
        #expect(IPAddress("224.0.0.251")!.isMulticast)
        #expect(IPAddress("ff02::fb")!.isMulticast)
    }
}

@Suite struct CaptureFileTests {
    @Test func readsTimestampsLikeWireshark() throws {
        let micro = try Fixtures.records("dhcp.pcapng")
        #expect(micro.count == 4)
        #expect(micro[0].timestamp == CaptureTimestamp(seconds: 1_102_274_184, nanoseconds: 317_453_000))
        #expect(micro[1].timestamp == CaptureTimestamp(seconds: 1_102_274_184, nanoseconds: 317_748_000))

        let nano = try Fixtures.records("dhcp-nanosecond.pcap")
        #expect(nano[0].timestamp == CaptureTimestamp(seconds: 1_102_274_184, nanoseconds: 317_453_000))

        let tls = try Fixtures.records("tls12.pcapng")
        #expect(tls[0].timestamp == CaptureTimestamp(seconds: 1_542_465_083, nanoseconds: 420_067_000))
        #expect(tls[0].linkType == .ipv4)
    }

    @Test func readsBigEndianPcapNG() throws {
        let records = try Fixtures.records("dhcp_big_endian.pcapng")
        #expect(records.map(\.originalLength) == [314, 342, 314, 342])
        #expect(records[0].linkType == .ethernet)
    }

    @Test(arguments: CaptureFormat.allCases)
    func writerRoundTrips(format: CaptureFormat) throws {
        let source = try Fixtures.records("dns.pcap")
        let raw = source.compactMap { r in
            r.ipBytes.map { CaptureRecord(timestamp: r.timestamp, data: Array($0), linkType: .raw, comment: "note") }
        }
        let data: Data = switch format {
        case .pcap: PcapWriter().file(raw)
        case .pcapng: PcapNGWriter().file(raw)
        }
        #expect(CaptureFileReader.format(of: Array(data.prefix(4))) == format)
        let back = try CaptureFileReader.read(data)
        #expect(back.count == raw.count)
        for (a, b) in zip(raw, back) {
            #expect(a.data == b.data)
            #expect(a.timestamp == b.timestamp)
            #expect(b.linkType == .raw)
            if format == .pcapng { #expect(b.comment == "note") }
        }
    }

    @Test func pcapNGBlocksAreFourByteAligned() {
        let record = CaptureRecord(timestamp: CaptureTimestamp(seconds: 1, nanoseconds: 0), data: [0x45, 0, 0])
        let bytes = PcapNGWriter().record(record)
        #expect(bytes.count % 4 == 0)
        // Block total length appears at both ends.
        #expect(Array(bytes[4..<8]) == Array(bytes[(bytes.count - 4)...]))
    }
}

@Suite struct DNSTests {
    @Test func parsesCompressedAnswers() throws {
        let records = try Fixtures.records("dns.pcap")
        let packet = try DecodedPacket.decode(ipBytes: try #require(records[15].ipBytes))
        guard case .dns(let dns) = packet.application else {
            Issue.record("frame 16 should be DNS")
            return
        }
        #expect(dns.isResponse)
        #expect(dns.questions.first?.name == "www.google.com")
        #expect(dns.cnames == ["www.l.google.com"])
    }

    @Test func rejectsPointerLoops() {
        // Header with one question whose name points at itself.
        let bytes: [UInt8] = [0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 12, 0, 1, 0, 1]
        #expect(throws: ParseError.self) { try DNSMessage.parse(bytes) }
    }

    @Test func buildsQueriesThatParse() throws {
        let query = DNSQueryBuilder.query(id: 0xBEEF, name: "example.com", type: .aaaa)
        let parsed = try DNSMessage.parse(query)
        #expect(parsed.id == 0xBEEF)
        #expect(parsed.questions == [DNSQuestion(name: "example.com", type: .aaaa, recordClass: 1, unicastResponse: false)])
    }
}

@Suite struct TLSAndQUICTests {
    @Test func extractsServerNameAndALPN() throws {
        let records = try Fixtures.records("tls12.pcapng")
        let packet = try DecodedPacket.decode(ipBytes: try #require(records[0].ipBytes))
        guard case .tlsClientHello(let hello) = packet.application else {
            Issue.record("frame 1 should carry a ClientHello")
            return
        }
        #expect(hello.serverName == "example.com")
        #expect(hello.alpnProtocols == ["http/1.1"])
    }

    @Test(.enabled(if: QUICInitialDecryptor.isSupported))
    func decryptsClientInitial() throws {
        let records = try Fixtures.records("quic.pcapng")
        let ip = try IPPacket.parse(try #require(records[46].ipBytes))
        let udp = try UDPDatagram.parse(ip.payload)
        let hello = try #require(QUICInitialDecryptor.clientHello(inDatagrams: [udp.payload]))
        #expect(hello.serverName == "cloudflare-quic.com")
        #expect(hello.alpnProtocols == ["h3"])
    }

    @Test func parsesQUICLongHeader() throws {
        let records = try Fixtures.records("quic.pcapng")
        let ip = try IPPacket.parse(try #require(records[46].ipBytes))
        let udp = try UDPDatagram.parse(ip.payload)
        let header = try QUICHeader.parse(udp.payload)
        #expect(header.packetType == .initial)
        #expect(header.version == QUICHeader.version1)
        #expect(header.destinationConnectionID.hexString == "203f9e9f68698274")
        #expect(QUICHeader.looksLikeQUIC(udp.payload))
    }
}

@Suite struct TCPReassemblyTests {
    @Test func reordersOutOfOrderHTTP() throws {
        let records = try Fixtures.records("http-ooo.pcap")
        var reassembler = TCPStreamReassembler()
        var stream: [UInt8] = []
        for record in records {
            let ip = try IPPacket.parse(try #require(record.ipBytes))
            let tcp = try TCPSegment.parse(ip.payload)
            stream += reassembler.accept(sequence: tcp.sequenceNumber, flags: tcp.flags, payload: tcp.payload)
        }
        let text = String(decoding: stream, as: UTF8.self)
        let requestLines = text.components(separatedBy: "\r\n").filter { $0.hasSuffix("HTTP/1.1") }
        #expect(requestLines == ["PUT /1 HTTP/1.1", "GET /2 HTTP/1.1", "PUT /3 HTTP/1.1", "PUT /4 HTTP/1.1", "PUT /5 HTTP/1.1"])
        #expect(reassembler.pendingBytes == 0)
    }

    @Test func handlesSequenceWraparound() {
        var r = TCPStreamReassembler()
        let a = r.accept(sequence: 0xFFFF_FFFE, flags: [], payload: [1, 2][...])
        let c = r.accept(sequence: 2, flags: [], payload: [5][...])
        let b = r.accept(sequence: 0, flags: [], payload: [3, 4][...])
        #expect(a == [1, 2])
        #expect(c == [])
        #expect(b == [3, 4, 5])
    }
}

@Suite struct BuilderAndHexTests {
    @Test func builtUDPPacketsHaveValidChecksums() throws {
        for (src, dst) in [("10.0.0.1", "8.8.8.8"), ("2001:db8::1", "2001:db8::53")] {
            let bytes = IPPacketBuilder.udpPacket(
                source: IPAddress(src)!, sourcePort: 53, destination: IPAddress(dst)!, destinationPort: 5353,
                payload: Array("hello".utf8))
            let ip = try IPPacket.parse(bytes)
            if ip.version == 4 { #expect(ip.headerChecksumValid == true) }
            let udp = try UDPDatagram.parse(ip.payload)
            #expect(Array(udp.payload) == Array("hello".utf8))
            let sum = InternetChecksum.transportChecksum(
                source: ip.source, destination: ip.destination, protocolNumber: IPProtocolNumber.udp, segment: ip.payload)
            #expect(sum == 0)
        }
    }

    @Test func hexDumpMatchesWiresharkLayout() {
        let lines = HexDump.lines(Array(0..<20).map(UInt8.init))
        #expect(lines.count == 2)
        #expect(lines[0].offsetText == "0000")
        #expect(lines[0].hexText == "00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f")
        #expect(lines[1].offsetText == "0010")
        #expect(HexDump.lines(Array("GET /".utf8))[0].asciiText == "GET /")
    }
}
