import Testing
import FerretParsers

/// "Every field matches Wireshark on the same pcap": each fixture is dissected
/// frame by frame and compared with tshark's output for the same fields.
@Suite struct WiresharkParityTests {
    static let captures = [
        "dns.pcap", "http.pcap", "ipv6.pcap", "tls13-rfc8446.pcap",
        "tls12.pcapng", "quic.pcapng", "dhcp.pcapng",
    ]

    @Test(arguments: captures)
    func fieldsMatchWireshark(capture: String) throws {
        let records = try Fixtures.records(capture)
        let expected = try Fixtures.expectations(capture)
        #expect(records.count == expected.count)

        let context = DissectionContext()
        var mismatches: [String] = []
        for (index, (record, row)) in zip(records, expected).enumerated() {
            let dissection = Dissector.dissect(record, context: context)
            for (key, want) in row.sorted(by: { $0.key < $1.key }) where !Self.skipped(key: key, row: row) {
                let got = dissection.value(key)
                if got != want {
                    mismatches.append("frame \(index + 1) \(key): Wireshark '\(want)', Ferret '\(got)'")
                }
            }
        }
        // Summarise by field so one systematic difference doesn't hide the rest.
        var byField: [String: [String]] = [:]
        for m in mismatches {
            let key = m.split(separator: " ")[2].dropLast()
            byField[String(key), default: []].append(m)
        }
        let summary = byField.keys.sorted().map { key in
            let items = byField[key]!
            return "\(key): \(items.count) frames, e.g. " + items.prefix(3).joined(separator: " | ")
        }
        #expect(mismatches.isEmpty, "\(mismatches.count) mismatches in \(capture):\n\(summary.joined(separator: "\n"))")
    }

    /// Fields Wireshark derives from state a single-pass, on-device dissector
    /// deliberately does not keep.
    static func skipped(key: String, row: [String: String]) -> Bool {
        let isQUIC = !(row["quic.header_form"] ?? "").isEmpty
        if isQUIC {
            // Server Initials are protected with keys derived from the client's DCID,
            // which only appears in an earlier frame.
            if key.hasPrefix("tls."), row["udp.srcport"] == "443" { return true }
            // Short-header connection IDs have no length on the wire.
            if key == "quic.dcid", (row["quic.header_form"] ?? "").contains("0") { return true }
            if key.hasPrefix("tls."), !QUICInitialDecryptor.isSupported { return true }
        }
        return false
    }
}
