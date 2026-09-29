import FerretKit
import SwiftData
import SwiftUI

/// Before/after diff: which domains appear in only one of two captures.
struct CaptureDiffView: View {
    @Query(sort: \CaseFile.openedAt, order: .reverse) private var cases: [CaseFile]
    @State private var beforeID: String?
    @State private var afterID: String?
    @State private var diff: CaptureDiff?
    @State private var loading = false

    var body: some View {
        Form {
            Section {
                Picker("Before", selection: $beforeID) {
                    Text("Choose").tag(String?.none)
                    ForEach(cases) { Text($0.title).tag(Optional($0.sessionID)) }
                }
                Picker("After", selection: $afterID) {
                    Text("Choose").tag(String?.none)
                    ForEach(cases) { Text($0.title).tag(Optional($0.sessionID)) }
                }
                Button {
                    Task { await compare() }
                } label: {
                    if loading { ProgressView() } else { Text("Compare") }
                }
                .disabled(beforeID == nil || afterID == nil || beforeID == afterID || loading)
            } footer: {
                Text("For example, capture before and after installing an app, or on two networks.")
            }

            if let diff {
                Section {
                    if diff.onlyAfter.isEmpty { Text("None").foregroundStyle(.secondary) }
                    ForEach(diff.onlyAfter) { DiffRow(group: $0) }
                } header: {
                    Text("Only in after (\(diff.onlyAfter.count))")
                }
                Section {
                    if diff.onlyBefore.isEmpty { Text("None").foregroundStyle(.secondary) }
                    ForEach(diff.onlyBefore) { DiffRow(group: $0) }
                } header: {
                    Text("Only in before (\(diff.onlyBefore.count))")
                }
                Section("In both (\(diff.inBoth.count))") {
                    ForEach(diff.inBoth.prefix(100)) { change in
                        HStack {
                            Text(change.domain)
                            Spacer()
                            Text("\(change.contactsBefore) → \(change.contactsAfter)")
                                .font(.caption.monospacedDigit())
                                .foregroundStyle(.secondary)
                        }
                        .accessibilityElement(children: .combine)
                    }
                }
            }
        }
        .navigationTitle("Compare captures")
        .navigationBarTitleDisplayMode(.inline)
    }

    private func compare() async {
        guard let beforeID, let afterID else { return }
        loading = true
        async let before = Self.groups(sessionID: beforeID)
        async let after = Self.groups(sessionID: afterID)
        diff = CaptureDiff.compare(before: await before, after: await after)
        loading = false
    }

    static func groups(sessionID: String) async -> [DomainGroup] {
        let engine = AnalysisEngine()
        let snapshot = await engine.load(directory: SharedContainer.captureDirectory(sessionID: sessionID))
        return DomainGrouper.groups(connections: snapshot.connections, lookups: snapshot.lookups)
    }
}

private struct DiffRow: View {
    let group: DomainGroup

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(group.domain)
                if let tracker = group.tracker {
                    Text("\(tracker.organisation) · \(tracker.category)").font(.caption).foregroundStyle(.orange)
                }
            }
            Spacer()
            TagRow(tags: group.tags)
        }
    }
}
