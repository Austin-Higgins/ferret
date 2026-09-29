import Foundation

/// Paths and settings shared by the app and the packet tunnel through an App Group.
public enum SharedContainer {
    /// Must match the App Group in both targets' entitlements. The app and the
    /// extension read it from their Info.plist (`FerretAppGroup`, set in project.yml).
    public static var appGroupID: String =
        (Bundle.main.object(forInfoDictionaryKey: "FerretAppGroup") as? String) ?? "group.com.example.ferret"

    /// Keys passed from the app to the extension when a capture starts.
    public enum StartOption {
        public static let sessionID = "sessionID"
        public static let storageCap = "storageCap"
    }

    public static var rootURL: URL {
        if let url = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroupID) {
            return url
        }
        // Simulator builds without the entitlement, tests and previews.
        return FileManager.default.temporaryDirectory.appendingPathComponent("FerretShared", isDirectory: true)
    }

    public static var capturesURL: URL { rootURL.appendingPathComponent("Captures", isDirectory: true) }
    public static var statusURL: URL { rootURL.appendingPathComponent("capture-status.bin") }

    public static func captureDirectory(sessionID: String) -> CaptureDirectory {
        CaptureDirectory(url: capturesURL.appendingPathComponent(sessionID, isDirectory: true))
    }

    public static var defaults: UserDefaults {
        UserDefaults(suiteName: appGroupID) ?? .standard
    }

    /// Deletes every capture on disk: the spec's one-tap delete.
    public static func deleteAllCaptures() throws {
        if FileManager.default.fileExists(atPath: capturesURL.path) {
            try FileManager.default.removeItem(at: capturesURL)
        }
    }

    public static func totalCaptureBytes() -> Int {
        guard let enumerator = FileManager.default.enumerator(at: capturesURL, includingPropertiesForKeys: [.fileSizeKey]) else { return 0 }
        var total = 0
        for case let url as URL in enumerator {
            total += (try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
        }
        return total
    }
}

/// User settings. Stored in the shared defaults so the extension can read them.
public struct FerretSettings: Sendable {
    public enum Key {
        public static let storageCapMB = "storageCapMB"
        public static let discreetMode = "discreetMode"
        public static let learnMode = "learnMode"
        public static let hideAppleByDefault = "hideAppleByDefault"
    }

    public static let storageCapChoicesMB = [64, 128, 256, 512, 1024, 2048]
    public static let defaultStorageCapMB = 256

    public static var storageCapBytes: Int {
        let mb = SharedContainer.defaults.integer(forKey: Key.storageCapMB)
        return (mb > 0 ? mb : defaultStorageCapMB) * 1024 * 1024
    }
}
