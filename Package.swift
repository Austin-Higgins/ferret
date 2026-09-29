// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "Ferret",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "FerretParsers", targets: ["FerretParsers"]),
        .library(name: "FerretKit", targets: ["FerretKit"]),
        .library(name: "FerretTunnelCore", targets: ["FerretTunnelCore"]),
    ],
    targets: [
        // Protocol parsers and capture file formats. Written from scratch: no Wireshark code.
        .target(name: "FerretParsers"),
        // Small C shim for atomics in memory shared by the app and the extension.
        .target(name: "CFerretAtomics"),
        // Analysis, storage and Safety Snoot logic shared by the app and extension.
        .target(
            name: "FerretKit",
            dependencies: ["FerretParsers", "CFerretAtomics"],
            resources: [.copy("Resources/public_suffix_list.dat"), .copy("Resources/trackers.tsv")]
        ),
        // Vendored lwIP 2.2.1 (BSD) with Ferret's accept-any patches; see Sources/CLwIP/PATCHES.md.
        .target(
            name: "CLwIP",
            exclude: ["LICENSE", "PATCHES.md"],
            cSettings: [.define("FERRET_LWIP", to: "1"), .headerSearchPath("lwip-include")]
        ),
        // Userspace TCP/IP forwarding used by the packet tunnel.
        .target(name: "FerretTunnelCore", dependencies: ["CLwIP", "FerretParsers"]),
        .testTarget(
            name: "FerretParsersTests",
            dependencies: ["FerretParsers"],
            resources: [.copy("Fixtures")]
        ),
        .testTarget(
            name: "FerretKitTests",
            dependencies: ["FerretKit", "FerretParsers"],
            resources: [.copy("Fixtures")]
        ),
        .testTarget(name: "FerretTunnelCoreTests", dependencies: ["FerretTunnelCore", "FerretParsers"]),
    ],
    swiftLanguageModes: [.v5]
)
