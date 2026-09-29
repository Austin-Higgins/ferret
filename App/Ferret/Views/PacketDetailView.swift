import FerretKit
import FerretParsers
import SwiftUI

/// Field tree over a hex view. Tapping a field highlights its bytes. No jokes here.
struct PacketDetailView: View {
    let frameIndex: Int
    @Environment(TrafficStore.self) private var store
    @State private var record: CaptureRecord?
    @State private var dissection: PacketDissection?
    @State private var selected: PacketField?
    @State private var loaded = false

    var body: some View {
        Group {
            if let record, let dissection {
                List {
                    Section {
                        Text(dissection.summary).font(.callout.monospaced())
                    } header: {
                        Text("Frame \(frameIndex + 1) · \(dissection.protocolName)")
                    }
                    Section("Fields") {
                        OutlineGroup(dissection.fields, children: \.childrenOrNil) { field in
                            FieldRow(field: field, selected: selected?.id == field.id)
                                .contentShape(Rectangle())
                                .onTapGesture { selected = field }
                        }
                    }
                    Section("Bytes") {
                        HexView(bytes: record.data, highlight: selected?.range)
                    }
                }
                .listStyle(.insetGrouped)
            } else if loaded {
                ContentUnavailableView(
                    "Packet not in memory",
                    systemImage: "tray",
                    description: Text("Older packets are kept on disk only. Export the capture to see every byte."))
            } else {
                ProgressView()
            }
        }
        .navigationTitle("Packet")
        .navigationBarTitleDisplayMode(.inline)
        .task {
            record = await store.engine.frame(frameIndex)
            dissection = await store.engine.dissect(frameIndex)
            loaded = true
        }
    }
}

extension PacketField {
    var childrenOrNil: [PacketField]? { children.isEmpty ? nil : children }
}

struct FieldRow: View {
    let field: PacketField
    let selected: Bool

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            Text(field.text)
                .font(.caption.monospaced())
                .foregroundStyle(selected ? Color.accentColor : .primary)
            Spacer(minLength: 4)
            LearnButton(key: field.key)
        }
        .accessibilityElement(children: .combine)
        .accessibilityHint(field.range == nil ? "" : "Highlights these bytes in the hex view")
    }
}

/// Offset, hex and ASCII columns, like Wireshark's bytes pane.
struct HexView: View {
    let bytes: [UInt8]
    let highlight: Range<Int>?

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            ForEach(HexDump.lines(bytes)) { line in
                Text(attributed(line))
                    .font(.system(size: 11, design: .monospaced))
                    .lineLimit(1)
                    .minimumScaleFactor(0.5)
            }
        }
        .textSelection(.enabled)
        .accessibilityLabel("Hex view, \(bytes.count) bytes")
    }

    private func attributed(_ line: HexDumpLine) -> AttributedString {
        var out = AttributedString(line.offsetText + "  ")
        for (i, b) in line.bytes.enumerated() {
            if i == 8 { out += AttributedString(" ") }
            var hex = AttributedString([b].hexString + " ")
            if let highlight, highlight.contains(line.offset + i) {
                hex.backgroundColor = .accentColor.opacity(0.3)
            }
            out += hex
        }
        let pad = (16 - line.bytes.count) * 3 + (line.bytes.count <= 8 ? 1 : 0)
        out += AttributedString(String(repeating: " ", count: pad + 1))
        for (i, b) in line.bytes.enumerated() {
            let ch = (0x20...0x7E).contains(b) ? String(UnicodeScalar(b)) : "."
            var a = AttributedString(ch)
            if let highlight, highlight.contains(line.offset + i) {
                a.backgroundColor = .accentColor.opacity(0.3)
            }
            out += a
        }
        return out
    }
}
