import ActivityKit
import FerretKit
import SwiftUI
import WidgetKit

@main
struct FerretWidgetBundle: WidgetBundle {
    var body: some Widget {
        CaptureLiveActivity()
    }
}

/// Live Activity and Dynamic Island while capturing.
struct CaptureLiveActivity: Widget {
    var body: some WidgetConfiguration {
        ActivityConfiguration(for: CaptureActivityAttributes.self) { context in
            LockScreenView(context: context)
                .padding()
                .activityBackgroundTint(Color.black.opacity(0.6))
        } dynamicIsland: { context in
            DynamicIsland {
                DynamicIslandExpandedRegion(.leading) {
                    Label(context.attributes.discreet ? "Session" : "Sniffing", systemImage: context.attributes.discreet ? "circle.fill" : "pawprint.fill")
                        .font(.caption)
                }
                DynamicIslandExpandedRegion(.trailing) {
                    Text(timerInterval: context.attributes.startedAt...Date.distantFuture, countsDown: false)
                        .font(.caption.monospacedDigit())
                        .frame(maxWidth: 60)
                }
                DynamicIslandExpandedRegion(.bottom) {
                    HStack {
                        stat(context.state.packets.formatted(), "packets")
                        stat(ByteCountFormatter.string(fromByteCount: Int64(context.state.bytes), countStyle: .binary), "data")
                        stat(context.state.connections.formatted(), "connections")
                    }
                }
            } compactLeading: {
                Image(systemName: context.attributes.discreet ? "circle.fill" : "pawprint.fill")
                    .foregroundStyle(.orange)
            } compactTrailing: {
                Text(context.state.packets.formatted(.number.notation(.compactName)))
                    .font(.caption2.monospacedDigit())
            } minimal: {
                Image(systemName: context.attributes.discreet ? "circle.fill" : "pawprint.fill")
                    .foregroundStyle(.orange)
            }
        }
    }

    func stat(_ value: String, _ label: String) -> some View {
        VStack {
            Text(value).font(.headline.monospacedDigit())
            Text(label).font(.caption2).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity)
    }
}

struct LockScreenView: View {
    let context: ActivityViewContext<CaptureActivityAttributes>

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Label(title, systemImage: context.attributes.discreet ? "circle.fill" : "pawprint.fill")
                    .font(.headline)
                Spacer()
                if context.state.isCapturing {
                    Text(timerInterval: context.attributes.startedAt...Date.distantFuture, countsDown: false)
                        .font(.headline.monospacedDigit())
                        .frame(maxWidth: 80, alignment: .trailing)
                }
            }
            Text("\(context.state.packets.formatted()) packets · \(ByteCountFormatter.string(fromByteCount: Int64(context.state.bytes), countStyle: .binary)) · \(context.state.connections.formatted()) connections")
                .font(.subheadline)
                .foregroundStyle(.secondary)
        }
    }

    private var title: String {
        if context.attributes.discreet { return context.state.isCapturing ? "Session active" : "Session ended" }
        return context.state.isCapturing ? FerretCopy.caseOpened : FerretCopy.evidenceCollected(packets: context.state.packets)
    }
}
