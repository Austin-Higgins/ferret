import Charts
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

                    if capture.isCapturing || !capture.throughput.samples.isEmpty {
                        ThroughputChart(sampler: capture.throughput)
                    }

                    NavigationLink {
                        SniffTestView()
                    } label: {
                        Label(discreet ? "Guided app check" : "Sniff test: watch one app", systemImage: "stopwatch")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)

                    DiagnosticsSection(counters: capture.counters, capturing: capture.isCapturing)

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

/// Live bytes per second over the last two minutes.
struct ThroughputChart: View {
    let sampler: ThroughputSampler

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("Throughput").font(.headline)
                Spacer()
                Text("\(Int(sampler.current?.bytesPerSecond ?? 0).bytesText)/s")
                    .font(.callout.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
            Chart(sampler.samples) { s in
                AreaMark(x: .value("Time", s.time), y: .value("Bytes per second", s.bytesPerSecond))
                    .foregroundStyle(Color.accentColor.opacity(0.25))
                LineMark(x: .value("Time", s.time), y: .value("Bytes per second", s.bytesPerSecond))
                    .foregroundStyle(Color.accentColor)
            }
            .chartYAxis {
                AxisMarks { value in
                    AxisGridLine()
                    AxisValueLabel {
                        if let v = value.as(Double.self) { Text("\(Int(v).bytesText)/s") }
                    }
                }
            }
            .chartXAxis(.hidden)
            .frame(height: 120)
            .accessibilityLabel("Throughput over the last two minutes, currently \(Int(sampler.current?.bytesPerSecond ?? 0).bytesText) per second, peak \(Int(sampler.peakBytesPerSecond).bytesText) per second")
        }
    }
}

/// Numbers for the device soak test: tunnel memory against its ~50 MB limit.
struct DiagnosticsSection: View {
    let counters: CaptureCounters
    let capturing: Bool

    var body: some View {
        let soak = SoakCheck(counters: counters, capturing: capturing)
        DisclosureGroup("Diagnostics") {
            VStack(alignment: .leading, spacing: 6) {
                LabeledContent("Tunnel memory", value: "\(counters.memoryFootprint.bytesText) now, \(counters.peakMemoryFootprint.bytesText) peak")
                ProgressView(value: min(1, Double(counters.peakMemoryFootprint) / Double(SoakCheck.memoryBudget)))
                    .tint(counters.peakMemoryFootprint > SoakCheck.memoryBudget * 8 / 10 ? .orange : .green)
                    .accessibilityLabel("Peak memory against the 50 megabyte limit")
                LabeledContent("On disk", value: counters.bytesOnDisk.bytesText)
                LabeledContent("Packets not saved", value: counters.droppedPackets.countText)
                LabeledContent("30-minute soak", value: soakText(soak))
            }
            .font(.callout)
            .padding(.top, 6)
        }
    }

    private func soakText(_ soak: SoakCheck) -> String {
        switch soak.state {
        case .notRunning: return "Not running"
        case .running(let elapsed): return "\(Int(elapsed) / 60) of 30 min"
        case .passed: return "Passed, peak \(soak.peakMemory.bytesText)"
        case .overBudget: return "Over 50 MB (peak \(soak.peakMemory.bytesText))"
        }
    }
}
