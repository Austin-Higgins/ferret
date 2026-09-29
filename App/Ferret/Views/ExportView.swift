import FerretKit
import FerretParsers
import SwiftUI

/// Exports a capture as pcap or pcapng for Files, AirDrop or Wireshark on a Mac.
struct ExportView: View {
    let directory: CaptureDirectory
    let baseName: String

    @State private var format: CaptureFormat = .pcapng
    @State private var exported: URL?
    @State private var frames = 0
    @State private var working = false
    @State private var error: String?

    var body: some View {
        Form {
            Picker("Format", selection: $format) {
                Text("pcapng (keeps direction)").tag(CaptureFormat.pcapng)
                Text("pcap (widest support)").tag(CaptureFormat.pcap)
            }
            .pickerStyle(.inline)
            .onChange(of: format) { exported = nil }

            Section {
                if let exported {
                    ShareLink(item: exported) {
                        Label("Share \(frames.countText) packets", systemImage: "square.and.arrow.up")
                    }
                } else {
                    Button {
                        export()
                    } label: {
                        if working { ProgressView() } else { Label("Prepare file", systemImage: "doc.badge.gearshape") }
                    }
                    .disabled(working)
                }
            } footer: {
                Text("Files open in Wireshark and tcpdump. Unencrypted traffic, such as DNS lookups and plain HTTP, is readable by anyone you share the file with.")
            }
            if let error {
                Text(error).foregroundStyle(.red)
            }
        }
        .navigationTitle("Export")
    }

    private func export() {
        working = true
        let format = format
        let dest = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(baseName).\(format.fileExtension)")
        Task.detached {
            do {
                try? FileManager.default.removeItem(at: dest)
                let count = try CaptureExporter.export(from: directory, format: format, to: dest)
                await MainActor.run {
                    frames = count
                    exported = dest
                    working = false
                }
            } catch {
                await MainActor.run {
                    self.error = error.localizedDescription
                    working = false
                }
            }
        }
    }
}
