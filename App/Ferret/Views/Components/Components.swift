import FerretKit
import FerretParsers
import SwiftUI

/// Coloured collar tags for protocols.
struct ProtocolTagView: View {
    let tag: ProtocolTag

    var body: some View {
        Text(tag.rawValue)
            .font(.caption2.weight(.bold).monospaced())
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .foregroundStyle(.white)
            .background(color, in: Capsule())
            .accessibilityLabel(accessibilityName)
    }

    var color: Color {
        switch tag {
        case .dns: return .teal
        case .tls: return .green
        case .quic: return .purple
        case .http: return .orange
        }
    }

    var accessibilityName: String {
        switch tag {
        case .dns: return "DNS"
        case .tls: return "TLS encrypted"
        case .quic: return "QUIC"
        case .http: return "unencrypted HTTP"
        }
    }
}

struct TagRow: View {
    let tags: Set<ProtocolTag>

    var body: some View {
        HStack(spacing: 4) {
            ForEach(ProtocolTag.allCases.filter { tags.contains($0) }, id: \.self) { ProtocolTagView(tag: $0) }
        }
    }
}

/// A big number with a label, for live counters.
struct CounterTile: View {
    let value: String
    let label: String

    var body: some View {
        VStack(spacing: 2) {
            Text(value)
                .font(.title2.weight(.semibold).monospacedDigit())
                .contentTransition(.numericText())
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 10)
        .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 12))
        .accessibilityElement(children: .combine)
    }
}

/// Learn mode: an info button beside a field that explains it in plain words.
struct LearnButton: View {
    let key: String?
    @AppStorage(FerretSettings.Key.learnMode, store: SharedContainer.defaults) private var learnMode = true
    @State private var showing = false

    var body: some View {
        if learnMode, let key, let entry = Glossary.entry(for: key) {
            Button {
                showing = true
            } label: {
                Image(systemName: "questionmark.circle")
                    .foregroundStyle(.secondary)
            }
            .buttonStyle(.borderless)
            .accessibilityLabel("Explain \(entry.title)")
            .popover(isPresented: $showing) {
                VStack(alignment: .leading, spacing: 8) {
                    Text(entry.title).font(.headline)
                    Text(entry.explanation).font(.body)
                }
                .padding()
                .frame(idealWidth: 300)
                .presentationCompactAdaptation(.popover)
            }
        }
    }
}

extension CaptureTimestamp {
    var shortTime: String {
        date.formatted(.dateTime.hour().minute().second())
    }
}

extension Int {
    var bytesText: String { FerretCopy.formatBytes(self) }
    var countText: String { FerretCopy.formatCount(self) }
}
