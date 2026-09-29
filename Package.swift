// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "Ferret",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "FerretParsers", targets: ["FerretParsers"]),
    ],
    targets: [
        // Protocol parsers and capture file formats. Written from scratch: no Wireshark code.
        .target(name: "FerretParsers"),
        .testTarget(
            name: "FerretParsersTests",
            dependencies: ["FerretParsers"],
            resources: [.copy("Fixtures")]
        ),
    ],
    swiftLanguageModes: [.v5]
)
