import AppIntents
import FerretKit
import Foundation
import NetworkExtension

/// Starts and stops capture from Shortcuts and Siri without opening the app.
enum TunnelControl {
    static func manager() async throws -> NETunnelProviderManager {
        guard let manager = try await NETunnelProviderManager.loadAllFromPreferences().first else {
            throw IntentError.notSetUp
        }
        return manager
    }

    enum IntentError: Error, CustomLocalizedStringResourceConvertible {
        case notSetUp

        var localizedStringResource: LocalizedStringResource {
            "Open Ferret and start one capture first, so iOS can ask for VPN permission."
        }
    }
}

struct StartCaptureIntent: AppIntent {
    static let title: LocalizedStringResource = "Start capture"
    static let description = IntentDescription("Starts capturing this iPhone's traffic.")

    func perform() async throws -> some IntentResult & ProvidesDialog {
        let manager = try await TunnelControl.manager()
        if manager.connection.status == .connected { return .result(dialog: "Ferret is already capturing.") }
        let id = UUID().uuidString
        SharedContainer.defaults.set(id, forKey: "activeSessionID")
        try manager.connection.startVPNTunnel(options: [
            SharedContainer.StartOption.sessionID: id as NSString,
            SharedContainer.StartOption.storageCap: NSNumber(value: FerretSettings.storageCapBytes),
        ])
        return .result(dialog: "Case opened.")
    }
}

struct StopCaptureIntent: AppIntent {
    static let title: LocalizedStringResource = "Stop capture"
    static let description = IntentDescription("Stops capturing traffic.")

    func perform() async throws -> some IntentResult & ProvidesDialog {
        let manager = try await TunnelControl.manager()
        manager.connection.stopVPNTunnel()
        let packets = (try? SharedCaptureStatus(url: SharedContainer.statusURL))?.snapshot.packets ?? 0
        return .result(dialog: "\(FerretCopy.evidenceCollected(packets: packets))")
    }
}

struct FerretShortcuts: AppShortcutsProvider {
    static var appShortcuts: [AppShortcut] {
        AppShortcut(intent: StartCaptureIntent(), phrases: ["Start capture in \(.applicationName)", "Start sniffing with \(.applicationName)"],
                    shortTitle: "Start capture", systemImageName: "record.circle")
        AppShortcut(intent: StopCaptureIntent(), phrases: ["Stop capture in \(.applicationName)"],
                    shortTitle: "Stop capture", systemImageName: "stop.circle")
    }
}
