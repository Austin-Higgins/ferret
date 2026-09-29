import FerretKit
import SwiftUI

/// Tracker domains the phone contacted, grouped by how often. Never names an app.
struct SuspectsView: View {
    @Environment(TrafficStore.self) private var store

    var body: some View {
        NavigationStack {
            List {
                if store.suspects.isEmpty {
                    ContentUnavailableView(
                        "No suspects yet",
                        systemImage: "magnifyingglass",
                        description: Text("Domains from the tracker list show up here once your phone contacts them."))
                } else {
                    ForEach(SuspectsReport.grouped(store.suspects), id: \.0) { frequency, suspects in
                        Section(frequency.rawValue) {
                            ForEach(suspects) { suspect in
                                NavigationLink(value: suspect.domain) {
                                    VStack(alignment: .leading, spacing: 4) {
                                        Text(suspect.sentence)
                                        Text("\(suspect.tracker.organisation) · \(suspect.tracker.category)")
                                            .font(.caption)
                                            .foregroundStyle(.secondary)
                                    }
                                }
                            }
                        }
                    }
                }
                Section {
                    Text(FerretCopy.suspectsFootnote)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
            .navigationTitle("Suspects")
            .navigationDestination(for: String.self) { DomainDetailView(domain: $0) }
        }
    }
}
