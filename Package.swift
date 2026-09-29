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
        // Small C shim for cross-process atomics on the shared ring buffer.
        .target(name: "CFerretAtomics"),
        // Analysis, storage and Safety Snoot logic shared by the app and extension.
        .target(
            name: "FerretKit",
            dependencies: ["FerretParsers", "CFerretAtomics"],
            resources: [.process("Resources")]
        ),
        // Vendored lwIP (BSD) plus Ferret's port layer.
        .target(
            name: "CLwIP",
            exclude: ["LICENSE"],
            cSettings: [
                .headerSearchPath("src/include"),
                .headerSearchPath("port/include"),
                .define("FERRET_LWIP", to: "1"),
            ]
        ),
        // Userspace TCP/IP stack used by the packet tunnel to forward traffic.
        .target(name: "FerretTunnelCore", dependencies: ["CLwIP", "FerretParsers"]),
        .testTarget(
            name: "FerretParsersTests",
            dependencies: ["FerretParsers"],
            resources: [.copy("Fixtures")]
        ),
        .testTarget(name: "FerretKitTests", dependencies: ["FerretKit", "FerretParsers"]),
        .testTarget(name: "FerretTunnelCoreTests", dependencies: ["FerretTunnelCore", "FerretParsers"]),
    ],
    swiftLanguageModes: [.v5]
)
