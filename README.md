# Ferret

A free, open-source, on-device network debugger for iPhone: packet-level capture,
readable protocol breakdowns and pcap export, with a friendly privacy layer on top.

*PCAPdroid for iPhone, with a ferret.* Ferret is a placeholder name.

## What it does

| Feature | What you get |
| --- | --- |
| **Capture** | One button to start and stop. Live packet, byte and connection counters, plus a Live Activity in the Dynamic Island. |
| **Traffic list** | Connections grouped by domain (Public Suffix List), tagged DNS / TLS / QUIC / HTTP, with search and "DNS only" / "Hide Apple" filters. |
| **Connection detail** | Timeline chart, originating DNS lookup, TLS server name (SNI), ALPN, packet sizes, a Wireshark-style field tree and a hex view. Learn mode explains any field. |
| **Suspects** | Tracker domains from an open list, grouped by how often the phone contacted them. Never names an app. |
| **Safety Snoot** | A ten-second Wi-Fi check for DNS hijacking, TLS interception, captive-portal tampering, open networks and remote-access Bonjour services. Practice mode stages each attack. |
| **pcap export** | pcap or pcapng to Files or AirDrop. Opens in Wireshark. |
| **Bounded storage** | Captures rotate within a storage cap you choose and delete in one tap. |

Not in v1, by design: HTTPS decryption (it needs a trusted root certificate), per-app
attribution (iOS doesn't give it to VPN extensions), and capturing other devices (no monitor mode).

## How it works

```
 apps ──► utun ──► PacketTunnelProvider ──► lwIP (TCP) / UDP relay ──► Network.framework ──► internet
                        │ writes every packet, untouched
                        ▼
              App Group: pcapng segments (storage-capped) + shared counters (mmap)
                        │
                        ▼
                  Ferret app: parse, analyse, display, export
```

The tunnel extension only captures and forwards. It never parses, keeping it well inside
the extension memory budget. Everything heavy happens in the app.

DNS stays with your network's own resolvers. At start the tunnel reads the system resolvers
and routes lookups to them through the tunnel, so they're captured but answered as before.

## Repository layout

| Path | Contents |
| --- | --- |
| `Sources/FerretParsers` | IPv4/IPv6, TCP, UDP, ICMP, DNS, TLS, QUIC (including Initial decryption for SNI), HTTP/1, pcap and pcapng, and a dissector with Wireshark field names. Written from scratch. |
| `Sources/FerretKit` | Traffic analyser, domain grouping, tracker list, Suspects, capture segments, shared status, Safety Snoot, copy and the Learn-mode glossary. |
| `Sources/FerretTunnelCore` | TCP relay over lwIP, UDP relay, packet router, Network.framework upstreams. |
| `Sources/CLwIP` | Vendored lwIP 2.2.1 core with small, documented patches (`PATCHES.md`). |
| `App/` | The iOS app, packet tunnel extension and Live Activity widget (SwiftUI, SwiftData, ActivityKit, App Intents). |
| `Tests/` | Swift Testing suites, including a field-by-field Wireshark parity check. |

## Building

Requirements: Xcode 16 or later, iOS 17+, and [XcodeGen](https://github.com/yonaskolb/XcodeGen).

```sh
swift test                 # parsers, analysis, Safety Snoot and the lwIP relay
xcodegen generate          # creates Ferret.xcodeproj
open Ferret.xcodeproj
```

To run on a device, set your team and identifiers in `project.yml`:
`FERRET_BUNDLE_PREFIX`, `FERRET_APP_GROUP` and `DEVELOPMENT_TEAM`.
Packet tunnels need the paid Apple Developer Program, and the Network Extension
capability has to be enabled for both App IDs. The simulator can't run packet
tunnels. There you can still open pcap files, browse traffic and use Safety Snoot's practice mode.

## Testing against Wireshark

`scripts/generate-fixture-expectations.sh` runs `tshark` over real captures from Wireshark's
sample and test captures, and records the values of roughly 60 fields. `WiresharkParityTests` dissects the
same files and requires every field to match, apart from a small, documented set that
Wireshark only derives from state kept across frames.

## Privacy

Local only: no accounts, analytics, telemetry or servers. See [PRIVACY.md](PRIVACY.md).

## Licence

MIT, see [LICENSE](LICENSE). Third-party components are listed in [NOTICE.md](NOTICE.md).
The parsers are written from scratch and contain no Wireshark (GPL) code.
