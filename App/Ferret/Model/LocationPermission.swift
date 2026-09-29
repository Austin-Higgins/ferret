import CoreLocation

/// iOS only shares the Wi-Fi network's name and security type with apps that have
/// location access. Asked once, when Safety Snoot first runs for real.
final class LocationPermission: NSObject, CLLocationManagerDelegate {
    private let manager = CLLocationManager()

    override init() {
        super.init()
        manager.delegate = self
    }

    func requestIfNeeded() {
        if manager.authorizationStatus == .notDetermined {
            manager.requestWhenInUseAuthorization()
        }
    }
}
