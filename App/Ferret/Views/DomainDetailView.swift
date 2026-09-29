import FerretKit
import SwiftUI

struct DomainDetailView: View {
    let domain: String
    @Environment(TrafficStore.self) private var store

    var body: some View {
        let group = store.groups.first { $0.domain == domain }
            ?? DomainGrouper.groups(connections: store.snapshot.connections, lookups: store.snapshot.lookups).first { $0.domain == domain }
        List {
            if let group {
                if let tracker = group.tracker {
                    Section {
                        Label("\(tracker.organisation) · \(tracker.category)", systemImage: "eye.trianglebadge.exclamationmark")
                        Text(FerretCopy.suspectsFootnote).font(.footnote).foregroundStyle(.secondary)
                    }
                }
                if !group.hosts.isEmpty {
                    Section("Hosts") {
                        ForEach(group.hosts, id: \.self) { Text($0).font(.callout.monospaced()) }
                    }
                }
                if !group.connectionIDs.isEmpty {
                    Section("Connections") {
                        ForEach(group.connectionIDs.reversed(), id: \.self) { id in
                            if let c = store.connection(id) {
                                NavigationLink {
                                    ConnectionDetailView(connectionID: id)
                                } label: {
                                    ConnectionRow(connection: c)
                                }
                            }
                        }
                    }
                }
                if !group.lookupIDs.isEmpty {
                    Section("DNS lookups") {
                        ForEach(group.lookupIDs.reversed(), id: \.self) { id in
                            if let l = store.lookup(id) { LookupRow(lookup: l) }
                        }
                    }
                }
            } else {
                ContentUnavailableView("No longer in this capture", systemImage: "pawprint")
            }
        }
        .navigationTitle(domain)
        .navigationBarTitleDisplayMode(.inline)
    }
}

struct ConnectionRow: View {
    let connection: Connection

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack {
                Text(connection.displayName).lineLimit(1)
                Spacer()
                TagRow(tags: connection.tags)
            }
            HStack(spacing: 8) {
                Text("\(connection.key.transport.rawValue) \(connection.key.remote)")
                    .font(.caption.monospaced())
                Spacer()
                Text("↑\(connection.bytesOut.bytesText) ↓\(connection.bytesIn.bytesText)")
            }
            .font(.caption)
            .foregroundStyle(.secondary)
        }
    }
}

struct LookupRow: View {
    let lookup: DNSLookup

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack {
                Text(lookup.name).font(.callout.monospaced()).lineLimit(1)
                Spacer()
                Text(lookup.typeName).font(.caption.monospaced()).foregroundStyle(.secondary)
            }
            HStack {
                if lookup.failed {
                    Text("No such name").foregroundStyle(.orange)
                } else if lookup.addresses.isEmpty && !lookup.cnames.isEmpty {
                    Text("→ \(lookup.cnames.joined(separator: ", "))")
                } else {
                    Text(lookup.addresses.map(\.description).joined(separator: ", "))
                }
                Spacer()
                if let ms = lookup.latencyMilliseconds {
                    Text(String(format: "%.0f ms", ms))
                }
            }
            .font(.caption)
            .foregroundStyle(.secondary)
            .lineLimit(2)
        }
    }
}
