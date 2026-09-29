import FerretKit
import FerretParsers
import SwiftData
import SwiftUI

/// Sniff test: a guided window standing in for per-app attribution, which iOS
/// doesn't give VPN apps. Close other apps, use one app for 30 seconds, and see
/// which domains the phone contacted for the first time during that window.
struct SniffTestView: View {
    enum Phase: Equatable {
        case setup
        case starting
        case running(end: Date)
        case collecting
        case done
    }

    @Environment(CaptureController.self) private var capture
    @Environment(TrafficStore.self) private var store
    @Environment(\.modelContext) private var modelContext
    @Query(sort: \SniffTestRecord.start, order: .reverse) private var history: [SniffTestRecord]

    @State private var label = ""
    @State private var phase: Phase = .setup
    @State private var result: SniffTestResult?
    @State private var error: String?

    var body: some View {
        List {
            switch phase {
            case .setup, .starting:
                setupSection
            case .running(let end):
                runningSection(end: end)
            case .collecting:
                Section { ProgressView("Gathering what the phone contacted…") }
            case .done:
                if let result { ResultSections(result: result) }
                Section {
                    Button("Run another sniff test") {
                        result = nil
                        label = ""
                        phase = .setup
                    }
                }
            }

            if !history.isEmpty && (phase == .setup || phase == .done) {
                Section("Earlier sniff tests") {
                    ForEach(history.prefix(20)) { record in
                        NavigationLink {
                            RecordView(record: record)
                        } label: {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(record.label)
                                Text("\(record.firstContacted.count) new domains · \(record.start.formatted(date: .abbreviated, time: .shortened))")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                    .onDelete { offsets in
                        for i in offsets { modelContext.delete(history[i]) }
                    }
                }
            }
        }
        .navigationTitle("Sniff test")
        .navigationBarTitleDisplayMode(.inline)
    }

    private var setupSection: some View {
        Group {
            Section {
                Label("Close every other app you can.", systemImage: "1.circle")
                Label("Type the name of the app you're checking.", systemImage: "2.circle")
                Label("Tap Start, switch to that app and use it for 30 seconds.", systemImage: "3.circle")
                Label("Come back to Ferret to see what it contacted.", systemImage: "4.circle")
            } header: {
                Text("How it works")
            } footer: {
                Text("iOS doesn't tell apps like Ferret which app opened a connection. iOS and background apps can also connect during the window, so treat results as clues, not proof.")
            }
            Section {
                TextField("App name, e.g. Weather", text: $label)
                    .textInputAutocapitalization(.words)
                Button {
                    Task { await start() }
                } label: {
                    if phase == .starting { ProgressView() } else { Text("Start 30-second window") }
                }
                .disabled(label.trimmingCharacters(in: .whitespaces).isEmpty || phase == .starting)
                if let error { Text(error).foregroundStyle(.orange) }
            }
        }
    }

    private func runningSection(end: Date) -> some View {
        Section {
            VStack(spacing: 12) {
                Text(timerInterval: Date()...end, countsDown: true)
                    .font(.system(size: 56, weight: .semibold, design: .rounded).monospacedDigit())
                Text("Now switch to \(label) and use it normally.")
                    .multilineTextAlignment(.center)
                Button("Finish early", role: .cancel) { Task { await finish(at: Date()) } }
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical)
        }
    }

    private func start() async {
        error = nil
        phase = .starting
        if !capture.isCapturing {
            await capture.start()
            // Wait up to 10 s for the tunnel to come up.
            for _ in 0..<40 where capture.phase != .capturing {
                try? await Task.sleep(for: .milliseconds(250))
            }
        }
        guard capture.phase == .capturing else {
            error = capture.lostScent ?? "Capture didn't start."
            phase = .setup
            return
        }
        let startDate = Date()
        let end = startDate.addingTimeInterval(SniffWindow.defaultDuration)
        phase = .running(end: end)
        try? await Task.sleep(for: .seconds(SniffWindow.defaultDuration))
        if case .running = phase { await finish(at: end, startedAt: startDate) }
    }

    private func finish(at end: Date, startedAt: Date? = nil) async {
        guard case .running(let plannedEnd) = phase else { return }
        let start = startedAt ?? plannedEnd.addingTimeInterval(-SniffWindow.defaultDuration)
        phase = .collecting
        // The tunnel writes in batches; give it a moment, then read everything.
        try? await Task.sleep(for: .seconds(2))
        await capture.refreshNow()
        let window = SniffWindow(
            label: label.trimmingCharacters(in: .whitespaces),
            start: CaptureTimestamp(date: start), end: CaptureTimestamp(date: end))
        let r = SniffTest.evaluate(window: window, connections: store.snapshot.connections, lookups: store.snapshot.lookups)
        result = r
        modelContext.insert(SniffTestRecord(
            label: window.label, sessionID: capture.sessionID ?? "", start: start, end: end,
            firstContacted: r.firstContacted.map(\.domain), trackers: r.trackers.map(\.domain),
            alsoActive: r.alsoActive.map(\.domain)))
        try? modelContext.save()
        phase = .done
    }
}

private struct ResultSections: View {
    let result: SniffTestResult

    var body: some View {
        Section {
            if result.firstContacted.isEmpty {
                Text("No new domains during this window.")
            }
            ForEach(result.firstContacted) { group in
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
        } header: {
            Text("First contacted while using \(result.window.label)")
        } footer: {
            Text("\(result.trackers.count) of \(result.firstContacted.count) are on the tracker list. Your phone contacted these domains for the first time during the window; iOS or another app may have made some of these connections.")
        }
        if !result.alsoActive.isEmpty {
            Section("Also active, seen before the window") {
                ForEach(result.alsoActive) { Text($0.domain).foregroundStyle(.secondary) }
            }
        }
    }
}

private struct RecordView: View {
    let record: SniffTestRecord

    var body: some View {
        List {
            Section {
                LabeledContent("Window", value: "\(record.start.formatted(date: .abbreviated, time: .standard)), \(Int(record.end.timeIntervalSince(record.start))) s")
            }
            Section("First contacted while using \(record.label)") {
                if record.firstContacted.isEmpty { Text("No new domains.") }
                ForEach(record.firstContacted, id: \.self) { domain in
                    HStack {
                        Text(domain)
                        if record.trackers.contains(domain) {
                            Spacer()
                            Image(systemName: "eye.trianglebadge.exclamationmark").foregroundStyle(.orange)
                                .accessibilityLabel("Known tracker")
                        }
                    }
                }
            }
            if !record.alsoActive.isEmpty {
                Section("Also active, seen before the window") {
                    ForEach(record.alsoActive, id: \.self) { Text($0).foregroundStyle(.secondary) }
                }
            }
        }
        .navigationTitle(record.label)
        .navigationBarTitleDisplayMode(.inline)
    }
}
