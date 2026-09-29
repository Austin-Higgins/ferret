#if canImport(ActivityKit)
import ActivityKit
import Foundation

/// Live Activity shown on the Lock Screen and in the Dynamic Island while capturing.
struct CaptureActivityAttributes: ActivityAttributes {
    struct ContentState: Codable, Hashable {
        var packets: Int
        var bytes: Int
        var connections: Int
        var isCapturing: Bool
    }

    var startedAt: Date
    /// Discreet mode: neutral wording, no mascot.
    var discreet: Bool
}
#endif
