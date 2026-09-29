import Foundation
import SwiftData

/// One capture session, kept until the user deletes it.
@Model
final class CaseFile {
    @Attribute(.unique) var sessionID: String
    var title: String
    var openedAt: Date
    var closedAt: Date?
    var packets: Int
    var bytes: Int
    var connections: Int
    var notes: String
    /// Last Safety Snoot verdict recorded during this case, if any.
    var snootVerdict: String?
    /// Highest tunnel memory footprint seen during the capture, in bytes.
    var peakTunnelMemory: Int = 0

    init(sessionID: String, openedAt: Date = Date()) {
        self.sessionID = sessionID
        self.title = "Case \(openedAt.formatted(date: .abbreviated, time: .shortened))"
        self.openedAt = openedAt
        self.packets = 0
        self.bytes = 0
        self.connections = 0
        self.notes = ""
    }
}

/// A saved sniff test: one labelled window and the domains first contacted in it.
@Model
final class SniffTestRecord {
    var label: String
    var sessionID: String
    var start: Date
    var end: Date
    var firstContacted: [String]
    var trackers: [String]
    var alsoActive: [String]

    init(label: String, sessionID: String, start: Date, end: Date, firstContacted: [String], trackers: [String], alsoActive: [String]) {
        self.label = label
        self.sessionID = sessionID
        self.start = start
        self.end = end
        self.firstContacted = firstContacted
        self.trackers = trackers
        self.alsoActive = alsoActive
    }
}
