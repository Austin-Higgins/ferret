import FerretKit
import SwiftUI
import UniformTypeIdentifiers

/// Connections grouped by domain, with search and the DNS-only and Hide Apple filters.
struct TrafficListView: View {
    @Environment(TrafficStore.self) private var store
    @State private var importing = false
    @State private var importError: String?

    var body: some View {
        @Bindable var store = store
        NavigationStack {
            Group {
                if store.groups.isEmpty && store.filter == TrafficFilter() {
                    ContentUnavailableView {
                        Label(FerretCopy.emptyState, systemImage: "pawprint")
                    } description: {
                        Text("Start a capture, then use your apps as normal. Connections appear here grouped by domain.")
                    }
                } else {
                    List(store.groups) { group in
                        NavigationLink(value: group.domain) {
                            DomainRow(group: group)
                        }
                    }
                    .listStyle(.plain)
                    .overlay {
                        if store.groups.isEmpty {
                            ContentUnavailableView.search
                        }
                    }
                }
            }
            .navigationTitle("Traffic")
            .navigationDestination(for: String.self) { domain in
                DomainDetailView(domain: domain)
            }
            .searchable(text: $store.filter.searchText, prompt: "Domains, hosts, organisations")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Menu {
                        Toggle("DNS only", isOn: $store.filter.dnsOnly)
                        Toggle("Hide Apple", isOn: $store.filter.hideApple)
                        Section("Protocols") {
                            ForEach(ProtocolTag.allCases, id: \.self) { tag in
                                Toggle(tag.rawValue, isOn: Binding(
                                    get: { store.filter.tags.contains(tag) },
                                    set: { on in
                                        if on { store.filter.tags.insert(tag) } else { store.filter.tags.remove(tag) }
                                    }))
                            }
                        }
                    } label: {
                        Label("Filters", systemImage: store.filter == TrafficFilter(searchText: store.filter.searchText)
                              ? "line.3.horizontal.decrease.circle" : "line.3.horizontal.decrease.circle.fill")
                    }
                }
                ToolbarItem(placement: .topBarLeading) {
                    Button {
                        importing = true
                    } label: {
                        Label("Open capture file", systemImage: "folder")
                    }
                }
            }
            .safeAreaInset(edge: .bottom) {
                if let source = store.sourceName {
                    Text("\(source) · \(store.snapshot.stats.packets.countText) packets · \(store.groups.count) domains")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .padding(6)
                        .frame(maxWidth: .infinity)
                        .background(.bar)
                }
            }
            .fileImporter(isPresented: $importing, allowedContentTypes: Self.captureTypes) { result in
                guard case .success(let url) = result else { return }
                Task {
                    do { try await store.open(fileAt: url) } catch { importError = "That file isn't a pcap or pcapng capture." }
                }
            }
            .alert("Couldn't open file", isPresented: Binding(get: { importError != nil }, set: { if !$0 { importError = nil } })) {
                Button("OK", role: .cancel) {}
            } message: {
                Text(importError ?? "")
            }
        }
    }

    static var captureTypes: [UTType] {
        [UTType("com.tcpdump.pcap"), UTType("org.wireshark.pcapng"), UTType(filenameExtension: "pcap"), UTType(filenameExtension: "pcapng"), .data]
            .compactMap { $0 }
    }
}

struct DomainRow: View {
    let group: DomainGroup

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(group.domain)
                    .font(.body.weight(.medium))
                    .lineLimit(1)
                if group.tracker != nil {
                    Image(systemName: "eye.trianglebadge.exclamationmark")
                        .foregroundStyle(.orange)
                        .accessibilityLabel("Known tracker")
                }
                Spacer()
                TagRow(tags: group.tags)
            }
            HStack(spacing: 8) {
                if !group.connectionIDs.isEmpty {
                    Text("\(group.connectionIDs.count) conn")
                }
                if !group.lookupIDs.isEmpty {
                    Text("\(group.lookupIDs.count) lookups")
                }
                if group.bytes > 0 { Text(group.bytes.bytesText) }
                Spacer()
                Text(group.lastSeen.shortTime)
            }
            .font(.caption)
            .foregroundStyle(.secondary)
        }
        .padding(.vertical, 2)
    }
}
