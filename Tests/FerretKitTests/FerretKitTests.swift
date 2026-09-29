import Foundation
import Testing
import FerretParsers
@testable import FerretKit

enum KitFixtures {
    static func records(_ name: String) throws -> [CaptureRecord] {
        let url = try #require(Bundle.module.url(forResource: name, withExtension: nil, subdirectory: "Fixtures"))
        return try CaptureFileReader.read(Data(contentsOf: url))
    }

    static func analyzer(_ names: String...) throws -> TrafficAnalyzer {
        let a = TrafficAnalyzer()
        var frame = 0
        for name in names {
            for r in try records(name) {
                a.ingest(record: r, frameIndex: frame)
                frame += 1
            }
        }
        return a
    }
}

@Suite struct PublicSuffixTests {
    let psl = PublicSuffixList.shared

    @Test func loadsBundledList() {
        #expect(psl.ruleCount > 5_000)
    }

    @Test(arguments: [
        ("www.example.com", "example.com"),
        ("a.b.example.co.uk", "example.co.uk"),
        ("example.com.", "example.com"),
        ("WWW.Example.COM", "example.com"),
        ("foo.github.io", "foo.github.io"),
        ("www.city.kawasaki.jp", "city.kawasaki.jp"),
        ("a.b.c.unknowntld", "c.unknowntld"),
    ])
    func findsRegistrableDomain(host: String, expected: String) {
        #expect(psl.registrableDomain(of: host) == expected)
    }

    @Test func publicSuffixesAndAddressesHaveNoRegistrableDomain() {
        #expect(psl.registrableDomain(of: "co.uk") == nil)
        #expect(psl.registrableDomain(of: "com") == nil)
        #expect(psl.registrableDomain(of: "192.168.1.1") == nil)
    }

    @Test func handlesWildcardsAndExceptions() {
        let list = PublicSuffixList(text: "*.ck\n!www.ck\ncom\n")
        #expect(list.registrableDomain(of: "a.b.ck") == "a.b.ck")
        #expect(list.publicSuffix(of: "a.b.ck") == "b.ck")
        #expect(list.registrableDomain(of: "www.ck") == "www.ck")
    }
}

@Suite struct TrackerTests {
    @Test func matchesSubdomains() {
        let list = TrackerList.bundled
        #expect(list.count > 100)
        #expect(list.match("stats.g.doubleclick.net")?.organisation == "Google")
        #expect(list.match("example.com") == nil)
    }

    @Test func parsesHostsFiles() {
        let list = TrackerList(hostsFile: "# comment\n0.0.0.0 ads.example.net\n127.0.0.1 localhost\ntracker.example.org # trailing\n")
        #expect(list.count == 2)
        #expect(list.match("x.ads.example.net") != nil)
    }
}

@Suite struct AnalyzerTests {
    @Test func correlatesDNSLookups() throws {
        let a = try KitFixtures.analyzer("dns.pcap")
        #expect(a.dnsLookups.count == 19)
        let netbsd = try #require(a.dnsLookups.first { $0.name == "www.netbsd.org" && $0.type == 1 })
        #expect(netbsd.addresses == [IPAddress("204.152.190.12")!])
        #expect(netbsd.latencyMilliseconds != nil)
        let missing = try #require(a.dnsLookups.first { $0.name == "www.example.notginh" })
        #expect(missing.failed)
        #expect(a.connections.allSatisfy { $0.tags == [.dns] })
    }

    @Test func namesTLSConnectionsBySNI() throws {
        let a = try KitFixtures.analyzer("tls12.pcapng")
        let names = Set(a.connections.compactMap(\.serverName))
        #expect(names == ["example.com", "example.net"])
        let first = try #require(a.connections.first { $0.serverName == "example.com" })
        #expect(first.tags.contains(.tls))
        #expect(first.alpn == ["http/1.1"])
        #expect(first.tlsVersion == "TLS 1.2")
        #expect(first.packetsOut == 4)
        #expect(first.packetsIn == 5)
    }

    @Test(.enabled(if: QUICInitialDecryptor.isSupported))
    func namesQUICConnections() throws {
        let a = try KitFixtures.analyzer("quic.pcapng")
        let quic = try #require(a.connections.first { $0.tags.contains(.quic) })
        #expect(quic.serverName == "cloudflare-quic.com")
        #expect(quic.alpn == ["h3"])
        let tcp = try #require(a.connections.first { $0.tags.contains(.tls) })
        #expect(tcp.serverName == "cloudflare-quic.com")
        #expect(tcp.tlsVersion == "TLS 1.3")
    }

    @Test func recordsHTTPRequests() throws {
        let a = try KitFixtures.analyzer("http.pcap")
        let conn = try #require(a.connections.first)
        #expect(conn.tags == [.http])
        #expect(conn.httpRequests.first?.method == "HEAD")
        #expect(conn.host == "windowsupdate.microsoft.com")
    }

    @Test func thousandConnectionsStayCheap() {
        // Synthetic SYNs to 1,000 destinations; the traffic list must handle this.
        let a = TrafficAnalyzer()
        let phone = IPAddress("10.10.0.2")!
        a.setLocalAddresses([phone])
        for i in 0..<1_000 {
            var tcp: [UInt8] = []
            tcp.appendU16(UInt16(40_000 + i))
            tcp.appendU16(443)
            tcp.appendU32(1); tcp.appendU32(0)
            tcp += [0x50, 0x02]
            tcp.appendU16(65535); tcp.appendU16(0); tcp.appendU16(0)
            let dst = IPAddress.v4(0x0A00_0000 | UInt32(i + 1))
            let ip = IPPacketBuilder.ipv4Header(source: phone, destination: dst, protocolNumber: 6, payloadLength: tcp.count) + tcp
            a.ingest(ipPacket: ip[...], timestamp: CaptureTimestamp(seconds: Int64(i), nanoseconds: 0), direction: .outbound, frameIndex: i)
        }
        #expect(a.connections.count == 1_000)
        let groups = DomainGrouper.groups(connections: a.connections, lookups: a.dnsLookups)
        #expect(groups.count == 1_000)
    }
}

@Suite struct GroupingTests {
    @Test func groupsByRegistrableDomainAndFilters() throws {
        let a = try KitFixtures.analyzer("dns.pcap", "tls12.pcapng")
        let all = DomainGrouper.groups(connections: a.connections, lookups: a.dnsLookups)
        let google = try #require(all.first { $0.domain == "google.com" })
        #expect(google.hosts.contains("www.google.com"))
        #expect(google.tags.contains(.dns))

        let dnsOnly = DomainGrouper.groups(connections: a.connections, lookups: a.dnsLookups, filter: TrafficFilter(dnsOnly: true))
        #expect(dnsOnly.allSatisfy { $0.connectionIDs.isEmpty })
        #expect(!dnsOnly.contains { $0.domain == "example.net" })

        let search = DomainGrouper.groups(connections: a.connections, lookups: a.dnsLookups, filter: TrafficFilter(searchText: "netbsd"))
        #expect(search.map(\.domain) == ["netbsd.org"])
    }

    @Test func hidesApple() {
        #expect(AppleDomains.contains("gateway.icloud.com"))
        #expect(AppleDomains.contains("init.itunes.apple.com"))
        #expect(!AppleDomains.contains("pineapple.com"))
    }

    @Test func suspectsWordingNeverNamesApps() {
        let entry = TrackerEntry(domain: "doubleclick.net", organisation: "Google", category: "advertising")
        let s = Suspect(domain: "doubleclick.net", hosts: [], tracker: entry, contacts: 42, bytes: 0,
                        firstSeen: CaptureTimestamp(seconds: 0, nanoseconds: 0), lastSeen: CaptureTimestamp(seconds: 0, nanoseconds: 0))
        #expect(s.sentence == "Your phone contacted doubleclick.net 42 times.")
        #expect(s.frequency == .frequent)
    }
}

@Suite struct StorageTests {
    func tempDirectory() -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("ferret-tests-\(UUID().uuidString)")
    }

    @Test func segmentsRoundTripAndRespectCap() throws {
        let dir = CaptureDirectory(url: tempDirectory())
        defer { try? FileManager.default.removeItem(at: dir.url) }
        let writer = try CaptureSegmentWriter(directory: dir, storageCap: 64 * 1024, segmentSize: 16 * 1024, flushThreshold: 1024)
        let reader = CaptureSegmentReader(directory: dir)
        let packet = IPPacketBuilder.udpPacket(
            source: IPAddress("10.0.0.2")!, sourcePort: 5000, destination: IPAddress("1.1.1.1")!, destinationPort: 53,
            payload: [UInt8](repeating: 0x41, count: 400))

        var seen = 0
        for i in 0..<1_000 {
            try writer.append(packet[...], timestamp: CaptureTimestamp(seconds: Int64(i), nanoseconds: 0), direction: .outbound)
            if i % 50 == 0 {
                let new = reader.readNew()
                #expect(new.allSatisfy { $0.data == packet && $0.direction == .outbound })
                seen += new.count
            }
        }
        try writer.close()
        seen += reader.readNew().count
        #expect(dir.totalBytes() <= 64 * 1024 + 16 * 1024)
        #expect(dir.segmentIndices().count > 1)
        #expect(seen > 100)

        let out = dir.url.appendingPathComponent("export.pcap")
        let exported = try CaptureExporter.export(from: dir, format: .pcap, to: out)
        let back = try CaptureFileReader.read(Data(contentsOf: out))
        #expect(back.count == exported)
        #expect(back.first?.data == packet)

        try dir.deleteAll()
        #expect(dir.segmentIndices().isEmpty)
    }

    @Test func sharedStatusIsVisibleAcrossMappings() throws {
        let url = tempDirectory().appendingPathExtension("status")
        defer { try? FileManager.default.removeItem(at: url) }
        let writer = try SharedCaptureStatus(url: url)
        let reader = try SharedCaptureStatus(url: url)
        writer.beginSession(id: 7)
        writer.add(.packets, 3)
        writer.add(.bytes, 1500)
        let snap = reader.snapshot
        #expect(snap.state == .capturing)
        #expect(snap.packets == 3)
        #expect(snap.bytes == 1500)
        #expect(snap.sessionID == 7)
    }
}

@Suite struct CopyTests {
    @Test func evidenceCopy() {
        #expect(FerretCopy.evidenceCollected(packets: 1).hasSuffix("1 packet"))
        #expect(FerretCopy.emptyState == "Nothing to sniff yet. Go open an app.")
    }

    @Test func glossaryFallsBackToProtocol() {
        #expect(Glossary.entry(for: "tls.handshake.extensions_server_name")?.title == "Server name (SNI)")
        #expect(Glossary.entry(for: "tcp.options.sack")?.title == "TCP")
    }
}
