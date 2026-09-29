#if canImport(ActivityKit)
import ActivityKit
import FerretKit
import Foundation

/// Drives the capture Live Activity. Updates are throttled; the elapsed timer
/// in the activity ticks on its own.
@MainActor
final class LiveActivityController {
    private var activity: Activity<CaptureActivityAttributes>?
    private var lastUpdate = Date.distantPast

    func start(startedAt: Date, discreet: Bool) {
        guard ActivityAuthorizationInfo().areActivitiesEnabled, activity == nil else { return }
        let attributes = CaptureActivityAttributes(startedAt: startedAt, discreet: discreet)
        let state = CaptureActivityAttributes.ContentState(packets: 0, bytes: 0, connections: 0, isCapturing: true)
        activity = try? Activity.request(attributes: attributes, content: .init(state: state, staleDate: nil))
    }

    func update(_ counters: CaptureCounters) {
        guard let activity, Date().timeIntervalSince(lastUpdate) >= 2 else { return }
        lastUpdate = Date()
        let state = CaptureActivityAttributes.ContentState(
            packets: counters.packets, bytes: counters.bytes, connections: counters.connections, isCapturing: true)
        Task { await activity.update(.init(state: state, staleDate: Date().addingTimeInterval(60))) }
    }

    func end(_ counters: CaptureCounters) {
        guard let activity else { return }
        let state = CaptureActivityAttributes.ContentState(
            packets: counters.packets, bytes: counters.bytes, connections: counters.connections, isCapturing: false)
        Task { await activity.end(.init(state: state, staleDate: nil), dismissalPolicy: .after(Date().addingTimeInterval(15 * 60))) }
        self.activity = nil
    }
}
#endif
