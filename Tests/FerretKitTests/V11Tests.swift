import Foundation
import Testing
import FerretParsers
@testable import FerretKit

@Suite struct SniffTestTests {
    /// Done-when: the labelled window lists every domain first contacted during it.
    @Test func listsEveryDomainFirstContactedInTheWindow() throws {
        let a = try KitFixtures.analyzer("dns.pcap")
        let lookups = a.dnsLookups
        // Put the window around the www.netbsd.org lookups, after google.com was already seen.
        let netbsd = try #require(lookups.first { $0.name == "www.netbsd.org" })
        let window = SniffWindow(
            label: "Test app",
            start: netbsd.queriedAt,
            end: CaptureTimestamp(seconds: netbsd.queriedAt.seconds + 1, nanoseconds: 0))
        let result = SniffTest.evaluate(window: window, connections: a.connections, lookups: lookups)

        let expected = Set(DomainGrouper.groups(connections: a.connections, lookups: lookups)
            .filter { window.contains($0.firstSeen) }.map(\.domain))
        #expect(!expected.isEmpty)
        #expect(Set(result.firstContacted.map(\.domain)) == expected)
        #expect(result.firstContacted.contains { $0.domain == "netbsd.org" })
        #expect(!result.firstContacted.contains { $0.domain == "google.com" })
    }

    @Test func emptyWindowFindsNothing() throws {
        let a = try KitFixtures.analyzer("tls12.pcapng")
        let window = SniffWindow(label: "x", start: CaptureTimestamp(seconds: 0, nanoseconds: 0), end: CaptureTimestamp(seconds: 1, nanoseconds: 0))
        #expect(SniffTest.evaluate(window: window, connections: a.connections, lookups: a.dnsLookups).firstContacted.isEmpty)
    }
}

@Suite struct CaptureDiffTests {
    /// Done-when: shows the domains present in only one capture.
    @Test func showsDomainsInOnlyOneCapture() throws {
        let before = try KitFixtures.analyzer("dns.pcap")
        let after = try KitFixtures.analyzer("dns.pcap", "tls12.pcapng")
        let diff = CaptureDiff.compare(
            before: DomainGrouper.groups(connections: before.connections, lookups: before.dnsLookups),
            after: DomainGrouper.groups(connections: after.connections, lookups: after.dnsLookups))
        // dns.pcap already looks up www.example.com, so only example.net is new.
        #expect(diff.onlyAfter.map(\.domain) == ["example.net"])
        #expect(diff.onlyBefore.isEmpty)
        #expect(diff.inBoth.contains { $0.domain == "google.com" })
        #expect(diff.inBoth.contains { $0.domain == "example.com" && $0.contactsAfter > $0.contactsBefore })

        let reversed = CaptureDiff.compare(
            before: DomainGrouper.groups(connections: after.connections, lookups: after.dnsLookups),
            after: DomainGrouper.groups(connections: before.connections, lookups: before.dnsLookups))
        #expect(reversed.onlyBefore.map(\.domain) == ["example.net"])
    }
}

@Suite struct ThroughputTests {
    @Test func computesRatesAndResetsOnNewSession() {
        var s = ThroughputSampler(capacity: 3)
        let t0 = Date(timeIntervalSince1970: 1_000)
        s.add(bytes: 0, packets: 0, at: t0)
        s.add(bytes: 2_000, packets: 4, at: t0.addingTimeInterval(1))
        s.add(bytes: 5_000, packets: 10, at: t0.addingTimeInterval(3))
        #expect(s.samples.map(\.bytesPerSecond) == [2_000, 1_500])
        #expect(s.samples.map(\.packetsPerSecond) == [4, 3])
        for i in 4...8 { s.add(bytes: 5_000 + i, packets: 10, at: t0.addingTimeInterval(Double(i))) }
        #expect(s.samples.count == 3)
        s.add(bytes: 10, packets: 1, at: t0.addingTimeInterval(9))
        #expect(s.samples.isEmpty)
    }
}

@Suite struct SoakCheckTests {
    @Test func passesAfterThirtyMinutesUnderBudget() {
        let start = Date(timeIntervalSince1970: 0)
        var c = CaptureCounters(state: .capturing, packets: 10, startedAt: start, peakMemoryFootprint: 20 * 1024 * 1024)
        #expect(SoakCheck(counters: c, capturing: true, now: start.addingTimeInterval(600)).state == .running(elapsed: 600))
        #expect(SoakCheck(counters: c, capturing: true, now: start.addingTimeInterval(1_800)).state == .passed)
        c.peakMemoryFootprint = 60 * 1024 * 1024
        #expect(SoakCheck(counters: c, capturing: true, now: start.addingTimeInterval(1_800)).state == .overBudget)
    }
}

@Suite struct ServiceRegistryTests {
    @Test func loadsFullIANARegistry() {
        #expect(ServiceNames.registryCount > 10_000)
        #expect(ServiceNames.name(port: 443, isUDP: false) == "https")
        #expect(ServiceNames.name(port: 5353, isUDP: true) == "mdns")
        #expect(ServiceNames.name(port: 3389, isUDP: false) == "ms-wbt-server")
        #expect(ServiceNames.name(port: 5223, isUDP: false) == "apple-push")
    }
}

/// Speed check: guards against regressions in the app's analysis path. Older
/// iPhones are several times slower than CI runners, so the floor is generous;
/// the measured rate is printed for comparison across runs.
@Suite struct PerformanceTests {
    @Test func analyzesFiftyThousandPacketsQuickly() throws {
        let base = try KitFixtures.records("quic.pcapng") + KitFixtures.records("tls12.pcapng") + KitFixtures.records("dns.pcap")
        let packets = base.compactMap { $0.ipBytes.map { (Array($0), $0.count) } }
        let target = 50_000
        let analyzer = TrafficAnalyzer()
        let clock = ContinuousClock()
        let elapsed = clock.measure {
            var i = 0
            while i < target {
                let (bytes, _) = packets[i % packets.count]
                let t = CaptureTimestamp(seconds: Int64(1_700_000_000 + i / 1_000), nanoseconds: UInt32(i % 1_000) * 1_000_000)
                analyzer.ingest(ipPacket: bytes[...], timestamp: t, direction: nil, frameIndex: i)
                i += 1
            }
        }
        let seconds = Double(elapsed.components.seconds) + Double(elapsed.components.attoseconds) / 1e18
        let rate = Double(target) / seconds
        print("Analyzer throughput: \(Int(rate)) packets/s over \(target) packets")
        #expect(analyzer.stats.packets == target)
        #expect(rate > 5_000, "analysis too slow: \(Int(rate)) packets/s")
    }
}
