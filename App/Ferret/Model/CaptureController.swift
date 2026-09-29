import FerretKit
import Foundation
import NetworkExtension
import Observation
import SwiftData

/// Starts and stops capture, and relays live counters to the UI and Live Activity.
@MainActor
@Observable
final class CaptureController {
    enum Phase: Equatable {
        case idle
        case starting
        case capturing
        case stopping
    }

    private(set) var phase: Phase = .idle
    private(set) var counters = CaptureCounters()
    /// "Lost the scent" message from the last failure, if any.
    private(set) var lostScent: String?
    private(set) var sessionID: String?
    private(set) var startedAt: Date?

    let store: TrafficStore
    var modelContext: ModelContext?

    private var manager: NETunnelProviderManager?
    private var statusFile: SharedCaptureStatus?
    private var pollTask: Task<Void, Never>?
    private var observer: NSObjectProtocol?
    #if canImport(ActivityKit)
    private let liveActivity = LiveActivityController()
    #endif

    static var tunnelBundleID: String { (Bundle.main.bundleIdentifier ?? "com.example.ferret") + ".tunnel" }

    init(store: TrafficStore) {
        self.store = store
    }

    var isCapturing: Bool { phase == .capturing || phase == .starting }

    /// Loads existing configuration and resumes following a capture already running.
    func load() async {
        statusFile = try? SharedCaptureStatus(url: SharedContainer.statusURL)
        let managers = (try? await NETunnelProviderManager.loadAllFromPreferences()) ?? []
        manager = managers.first
        observeStatus()
        if let manager, manager.connection.status == .connected {
            phase = .capturing
            if let id = SharedContainer.defaults.string(forKey: "activeSessionID") {
                sessionID = id
                // Captures started from Shortcuts get their case file here.
                if let modelContext {
                    let descriptor = FetchDescriptor<CaseFile>(predicate: #Predicate { $0.sessionID == id })
                    if (try? modelContext.fetch(descriptor).first) == nil {
                        modelContext.insert(CaseFile(sessionID: id))
                        try? modelContext.save()
                    }
                }
                await store.startFollowing(SharedContainer.captureDirectory(sessionID: id), name: "Live capture")
            }
            startPolling()
        }
    }

    func toggle() async {
        if isCapturing { stop() } else { await start() }
    }

    func start() async {
        guard phase == .idle else { return }
        lostScent = nil
        phase = .starting
        do {
            let manager = try await preparedManager()
            let id = UUID().uuidString
            sessionID = id
            startedAt = Date()
            SharedContainer.defaults.set(id, forKey: "activeSessionID")
            try FileManager.default.createDirectory(at: SharedContainer.capturesURL, withIntermediateDirectories: true)
            await store.startFollowing(SharedContainer.captureDirectory(sessionID: id), name: "Live capture")
            if let modelContext {
                modelContext.insert(CaseFile(sessionID: id))
                try? modelContext.save()
            }
            try manager.connection.startVPNTunnel(options: [
                SharedContainer.StartOption.sessionID: id as NSString,
                SharedContainer.StartOption.storageCap: NSNumber(value: FerretSettings.storageCapBytes),
            ])
            startPolling()
            #if canImport(ActivityKit)
            liveActivity.start(startedAt: startedAt ?? Date(), discreet: SharedContainer.defaults.bool(forKey: FerretSettings.Key.discreetMode))
            #endif
        } catch {
            phase = .idle
            lostScent = Self.describe(error)
        }
    }

    func stop() {
        guard let manager, isCapturing else { return }
        phase = .stopping
        manager.connection.stopVPNTunnel()
    }

    // MARK: - Private

    private func preparedManager() async throws -> NETunnelProviderManager {
        let manager = self.manager ?? NETunnelProviderManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = Self.tunnelBundleID
        proto.serverAddress = "On this iPhone"
        proto.disconnectOnSleep = false
        manager.protocolConfiguration = proto
        manager.localizedDescription = "Ferret"
        manager.isEnabled = true
        // Saving shows the system's VPN permission prompt the first time.
        try await manager.saveToPreferences()
        try await manager.loadFromPreferences()
        self.manager = manager
        observeStatus()
        return manager
    }

    private func observeStatus() {
        if let observer { NotificationCenter.default.removeObserver(observer) }
        guard let connection = manager?.connection else { return }
        observer = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange, object: connection, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.statusChanged() }
        }
    }

    private func statusChanged() {
        guard let connection = manager?.connection else { return }
        switch connection.status {
        case .connected:
            phase = .capturing
        case .connecting, .reasserting:
            phase = .starting
        case .disconnecting:
            phase = .stopping
        case .disconnected, .invalid:
            let wasCapturing = phase == .capturing || phase == .starting
            if phase == .starting {
                lostScent = FerretCopy.LostScentReason.extensionStopped.message
                connection.fetchLastDisconnectError { [weak self] error in
                    guard let error else { return }
                    Task { @MainActor in self?.lostScent = Self.describe(error) }
                }
            }
            phase = .idle
            if wasCapturing { finishSession() }
        @unknown default:
            break
        }
    }

    private func startPolling() {
        pollTask?.cancel()
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.pollOnce()
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }

    private func pollOnce() async {
        if let status = statusFile {
            counters = status.snapshot
            #if canImport(ActivityKit)
            if phase == .capturing { liveActivity.update(counters) }
            #endif
        }
        if let session = manager?.connection as? NETunnelProviderSession, phase == .capturing {
            try? session.sendProviderMessage(Data("flush".utf8)) { _ in }
        }
        await store.poll()
    }

    private func finishSession() {
        pollTask?.cancel()
        pollTask = nil
        Task {
            await store.poll()
        }
        if let status = statusFile { counters = status.snapshot }
        #if canImport(ActivityKit)
        liveActivity.end(counters)
        #endif
        if let id = sessionID, let modelContext {
            let descriptor = FetchDescriptor<CaseFile>(predicate: #Predicate { $0.sessionID == id })
            if let file = try? modelContext.fetch(descriptor).first {
                file.closedAt = Date()
                file.packets = counters.packets
                file.bytes = counters.bytes
                file.connections = counters.connections
                try? modelContext.save()
            }
        }
        SharedContainer.defaults.removeObject(forKey: "activeSessionID")
    }

    static func describe(_ error: Error) -> String {
        let ns = error as NSError
        if ns.domain == NEVPNErrorDomain, ns.code == NEVPNError.configurationReadWriteFailed.rawValue || ns.code == 5 {
            return FerretCopy.LostScentReason.permissionDenied.message
        }
        return FerretCopy.LostScentReason.configurationFailed(error.localizedDescription).message
    }
}
