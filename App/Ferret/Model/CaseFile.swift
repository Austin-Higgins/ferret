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
