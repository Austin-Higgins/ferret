import Charts
import FerretKit
import FerretParsers
import SwiftUI

/// Timeline, originating DNS lookup, TLS server name, packet sizes and packets.
struct ConnectionDetailView: View {
    let connectionID: Int
    @Environment(TrafficStore.self) private var store

    var body: some View {
        if let c = store.connection(connectionID) {
            List {
                Section("Summary") {
                    LabeledRow("Remote", "\(c.key.remote)", key: c.key.remote.address.isV4 ? "ip.dst" : "ipv6.dst")
                    LabeledRow("Local", "\(c.key.local)", key: nil)
                    LabeledRow("Transport", c.key.transport.rawValue + (c.serviceName.map { " · \($0)" } ?? ""), key: c.key.transport == .tcp ? "tcp" : "udp")
                    if let sni = c.serverName {
                        LabeledRow("TLS server name", sni, key: "tls.handshake.extensions_server_name")
                    }
                    if let v = c.tlsVersion { LabeledRow("TLS version", v, key: "tls.handshake.extensions.supported_version") }
                    if !c.alpn.isEmpty { LabeledRow("ALPN", c.alpn.joined(separator: ", "), key: "tls.handshake.extensions_alpn_str") }
                    if c.encryptedClientHello { LabeledRow("Encrypted Client Hello", "Offered", key: nil) }
                    if let q = c.quicVersion { LabeledRow("QUIC version", q, key: "quic.version") }
                    LabeledRow("Sent", "\(c.packetsOut.countText) packets · \(c.bytesOut.bytesText)", key: nil)
                    LabeledRow("Received", "\(c.packetsIn.countText) packets · \(c.bytesIn.bytesText)", key: nil)
                    LabeledRow("Duration", String(format: "%.2f s", c.durationSeconds), key: nil)
                }

                if let lookupID = c.dnsLookupID, let lookup = store.lookup(lookupID) {
                    Section("Originating DNS lookup") {
                        LookupRow(lookup: lookup)
                        LabeledRow("Resolver", lookup.resolver.description, key: nil)
                    }
                }

                if !c.httpRequests.isEmpty {
                    Section("HTTP requests (unencrypted)") {
                        ForEach(Array(c.httpRequests.enumerated()), id: \.offset) { _, r in
                            Text("\(r.method) \(r.host ?? "")\(r.path)")
                                .font(.caption.monospaced())
                                .lineLimit(2)
                        }
                    }
                }

                Section("Timeline") {
                    TimelineChart(connection: c)
                        .frame(height: 180)
                    if c.droppedSamples > 0 {
                        Text("Showing the first \(c.samples.count.countText) packets.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }

                Section("Packets") {
                    ForEach(Array(c.samples.prefix(500).enumerated()), id: \.offset) { index, sample in
                        NavigationLink {
                            PacketDetailView(frameIndex: sample.frameIndex)
                        } label: {
                            PacketSampleRow(index: index, sample: sample, start: c.firstSeen)
                        }
                    }
                }
            }
            .navigationTitle(c.displayName)
            .navigationBarTitleDisplayMode(.inline)
        } else {
            ContentUnavailableView("Connection not found", systemImage: "pawprint")
        }
    }
}

struct LabeledRow: View {
    let label: String
    let value: String
    let key: String?

    init(_ label: String, _ value: String, key: String?) {
        self.label = label
        self.value = value
        self.key = key
    }

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            Text(label).foregroundStyle(.secondary)
            LearnButton(key: key)
            Spacer()
            Text(value)
                .multilineTextAlignment(.trailing)
                .font(.callout.monospaced())
                .textSelection(.enabled)
        }
        .accessibilityElement(children: .combine)
    }
}

struct TimelineChart: View {
    let connection: Connection

    var body: some View {
        let start = connection.firstSeen
        Chart(Array(connection.samples.enumerated()), id: \.offset) { _, s in
            BarMark(
                x: .value("Time (s)", Double(s.timestamp.nanoseconds(since: start)) / 1e9),
                y: .value("Bytes", s.direction == .outbound ? s.size : -s.size),
                width: 2)
            .foregroundStyle(by: .value("Direction", s.direction == .outbound ? "Sent" : "Received"))
        }
        .chartForegroundStyleScale(["Sent": Color.accentColor, "Received": Color.green])
        .chartYAxisLabel("Bytes per packet")
        .chartXAxisLabel("Seconds")
        .accessibilityLabel("Packet sizes over time: \(connection.packetsOut) sent, \(connection.packetsIn) received")
    }
}

struct PacketSampleRow: View {
    let index: Int
    let sample: PacketSample
    let start: CaptureTimestamp

    var body: some View {
        HStack {
            Image(systemName: sample.direction == .outbound ? "arrow.up" : "arrow.down")
                .foregroundStyle(sample.direction == .outbound ? Color.accentColor : .green)
                .accessibilityLabel(sample.direction == .outbound ? "Sent" : "Received")
            Text(String(format: "+%.3f s", Double(sample.timestamp.nanoseconds(since: start)) / 1e9))
                .font(.caption.monospacedDigit())
            if let flags = sample.tcpFlags {
                Text(TCPFlags(rawValue: flags).description).font(.caption2.monospaced()).foregroundStyle(.secondary)
            }
            Spacer()
            Text("\(sample.size) B").font(.caption.monospacedDigit())
        }
    }
}
