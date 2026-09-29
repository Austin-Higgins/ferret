import FerretKit
import SwiftUI

/// One button to start and stop, with live counters.
struct CaptureView: View {
    @Environment(CaptureController.self) private var capture
    @AppStorage(FerretSettings.Key.discreetMode, store: SharedContainer.defaults) private var discreet = false

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 24) {
                    if !discreet {
                        MascotView(mood: capture.isCapturing ? .sniffing : .sitting)
                            .padding(.top, 16)
                    }
                    Text(headline)
                        .font(.title2.weight(.semibold))
                        .multilineTextAlignment(.center)

                    Button {
                        Task { await capture.toggle() }
                    } label: {
                        Text(capture.isCapturing ? FerretCopy.stopCapture : (discreet ? "Start" : FerretCopy.startCapture))
                            .font(.title3.weight(.semibold))
                            .frame(maxWidth: .infinity, minHeight: 56)
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(capture.isCapturing ? .red : .accentColor)
                    .disabled(capture.phase == .stopping)
                    .accessibilityHint(capture.isCapturing ? "Stops capturing traffic" : "Starts capturing this iPhone's traffic")

                    if let message = capture.lostScent {
                        Label(message, systemImage: "exclamationmark.triangle")
                            .foregroundStyle(.orange)
                            .font(.callout)
                    }

                    LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 12) {
                        CounterTile(value: capture.counters.packets.countText, label: "Packets")
                        CounterTile(value: capture.counters.bytes.bytesText, label: "Data")
                        CounterTile(value: capture.counters.connections.countText, label: "Connections")
                        CounterTile(value: elapsed, label: "Duration")
                    }

                    if capture.counters.droppedPackets > 0 {
                        Text("\(capture.counters.droppedPackets.countText) packets couldn't be saved.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }

                    VStack(alignment: .leading, spacing: 8) {
                        Label(FerretCopy.localOnlyPromise, systemImage: "lock.iphone")
                        Label(FerretCopy.oneVPNExplanation, systemImage: "network.badge.shield.half.filled")
                    }
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .padding()
            }
            .navigationTitle(discreet ? "Session" : "Ferret")
        }
    }

    private var headline: String {
        switch capture.phase {
        case .idle:
            return capture.counters.packets > 0 && !discreet
                ? FerretCopy.evidenceCollected(packets: capture.counters.packets)
                : (discreet ? "Ready" : "Ready when you are")
        case .starting: return discreet ? "Starting…" : "Opening the case…"
        case .capturing: return discreet ? "Recording" : FerretCopy.caseOpened
        case .stopping: return discreet ? "Stopping…" : FerretCopy.caseClosed
        }
    }

    private var elapsed: String {
        guard let start = capture.counters.startedAt ?? capture.startedAt else { return "0:00" }
        let end = capture.isCapturing ? Date() : (capture.counters.lastPacketAt ?? Date())
        let seconds = max(0, Int(end.timeIntervalSince(start)))
        return String(format: "%d:%02d", seconds / 60, seconds % 60)
    }
}
