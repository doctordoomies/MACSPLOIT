// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "MACSPLOIT",
    platforms: [.macOS(.v13)],
    products: [.executable(name: "MACSPLOIT", targets: ["MACSPLOIT"]),
               .library(name: "MACSPLOITKit", targets: ["MACSPLOITKit"])],
    targets: [
        .target(name: "MACSPLOITKit"),
        .executableTarget(name: "MACSPLOIT", dependencies: ["MACSPLOITKit"]),
        .testTarget(name: "MACSPLOITKitTests", dependencies: ["MACSPLOITKit"])
    ],
    swiftLanguageModes: [.v5]
)
