import FerretKit
import SwiftData
import SwiftUI

/// Past captures ("case files") with notes, reopen and export.
struct CasesView: View {
    @Query(sort: \CaseFile.openedAt, order: .reverse) private var cases: [CaseFile]
    @Environment(\.modelContext) private var modelContext
    @Environment(TrafficStore.self) private var store
    @Environment(CaptureController.self) private var capture

    var body: some View {
        List {
            if cases.isEmpty {
                ContentUnavailableView("No case files", systemImage: "folder", description: Text("Each capture becomes a case file you can reopen, annotate and export."))
            }
            ForEach(cases) { file in
                NavigationLink {
                    CaseDetailView(file: file)
                } label: {
                    VStack(alignment: .leading, spacing: 3) {
                        Text(file.title)
                        Text("\(file.packets.countText) packets · \(file.bytes.bytesText)")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .onDelete { offsets in
                for index in offsets {
                    let file = cases[index]
                    guard file.sessionID != capture.sessionID || !capture.isCapturing else { continue }
                    try? SharedContainer.captureDirectory(sessionID: file.sessionID).deleteAll()
                    try? FileManager.default.removeItem(at: SharedContainer.captureDirectory(sessionID: file.sessionID).url)
                    modelContext.delete(file)
                }
            }
        }
        .navigationTitle("Case files")
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                NavigationLink {
                    CaptureDiffView()
                } label: {
                    Label("Compare", systemImage: "arrow.left.arrow.right")
                }
                .disabled(cases.count < 2)
            }
        }
    }
}

struct CaseDetailView: View {
    @Bindable var file: CaseFile
    @Environment(TrafficStore.self) private var store
    @State private var opened = false

    var body: some View {
        let directory = SharedContainer.captureDirectory(sessionID: file.sessionID)
        Form {
            Section("Case") {
                TextField("Title", text: $file.title)
                LabeledContent("Opened", value: file.openedAt.formatted(date: .abbreviated, time: .standard))
                if let closed = file.closedAt {
                    LabeledContent("Closed", value: closed.formatted(date: .abbreviated, time: .standard))
                }
                LabeledContent("Evidence", value: "\(file.packets.countText) packets")
                LabeledContent("On disk", value: directory.totalBytes().bytesText)
                if file.peakTunnelMemory > 0 {
                    LabeledContent("Peak tunnel memory", value: file.peakTunnelMemory.bytesText)
                }
                if let verdict = file.snootVerdict.flatMap(SnootVerdict.init(rawValue:)) {
                    LabeledContent("Safety Snoot", value: verdict.title)
                }
            }
            Section("Notes") {
                TextEditor(text: $file.notes)
                    .frame(minHeight: 120)
            }
            Section {
                Button(opened ? "Opened in Traffic" : "Open in Traffic") {
                    Task {
                        await store.open(directory: directory, name: file.title)
                        opened = true
                    }
                }
                NavigationLink("Export") {
                    ExportView(directory: directory, baseName: "ferret-\(file.openedAt.formatted(.iso8601.year().month().day()))")
                }
            }
        }
        .navigationTitle(file.title)
        .navigationBarTitleDisplayMode(.inline)
    }
}
