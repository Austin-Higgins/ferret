import FerretKit
import FerretParsers
import Foundation
import Observation

/// What the traffic, suspects and detail screens show.
@MainActor
@Observable
final class TrafficStore {
    let engine = AnalysisEngine()

    private(set) var snapshot = TrafficSnapshot()
    private(set) var groups: [DomainGroup] = []
    private(set) var suspects: [Suspect] = []
    /// Where the current data came from, for the Traffic screen's subtitle.
    private(set) var sourceName: String?

    var filter = TrafficFilter() {
        didSet { if filter != oldValue { regroup() } }
    }

    func apply(_ new: TrafficSnapshot) {
        snapshot = new
        regroup()
    }

    func startFollowing(_ directory: CaptureDirectory, name: String) async {
        sourceName = name
        await engine.follow(directory)
        apply(TrafficSnapshot())
    }

    func poll() async {
        if let new = await engine.poll() { apply(new) }
    }

    func open(fileAt url: URL) async throws {
        let access = url.startAccessingSecurityScopedResource()
        defer { if access { url.stopAccessingSecurityScopedResource() } }
        let data = try Data(contentsOf: url)
        sourceName = url.lastPathComponent
        apply(try await engine.load(fileData: data))
    }

    func open(directory: CaptureDirectory, name: String) async {
        sourceName = name
        apply(await engine.load(directory: directory))
    }

    func clear() async {
        await engine.reset()
        sourceName = nil
        apply(TrafficSnapshot())
    }

    func connection(_ id: Int) -> Connection? {
        snapshot.connections.indices.contains(id) ? snapshot.connections[id] : nil
    }

    func lookup(_ id: Int) -> DNSLookup? {
        snapshot.lookups.indices.contains(id) ? snapshot.lookups[id] : nil
    }

    private func regroup() {
        groups = DomainGrouper.groups(connections: snapshot.connections, lookups: snapshot.lookups, filter: filter)
        let everything = DomainGrouper.groups(connections: snapshot.connections, lookups: snapshot.lookups)
        suspects = SuspectsReport.suspects(from: everything)
    }
}
