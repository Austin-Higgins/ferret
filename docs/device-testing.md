# Device testing checklist

These are the spec's "done when" tests that need a real iPhone and the paid developer program.

| Feature | Test | How |
| --- | --- | --- |
| Capture | Runs 30 minutes without breaking connectivity | Start a capture, stream video, browse, use FaceTime and switch between Wi-Fi and cellular for 30 minutes. Watch memory for the `FerretTunnel` process in Xcode's debug gauges; it must stay well under 50 MB. |
| Traffic list | 1,000 connections scroll smoothly | Capture a busy browsing session, or open a large pcap, then scroll the Traffic tab with Instruments' Animation Hitches. |
| Connection detail | Every field matches Wireshark on the same pcap | Automated in CI (`WiresharkParityTests`). Spot-check by exporting a capture and opening it in Wireshark. |
| Suspects | Wording says the phone contacted them, never names an app | Covered by tests; review the screen copy. |
| Safety Snoot | Detects each simulated attack in practice mode | Automated in CI. On devices, also run it on home Wi-Fi, a hotspot with a captive portal, and an open network. |
| pcap export | Opens cleanly in Wireshark on a Mac | AirDrop both formats to a Mac and open them in Wireshark. |

Networks to try: home Wi-Fi, cellular, a captive-portal hotspot, IPv6-only (NAT64) Wi-Fi,
and a network with a LAN DNS resolver (for example 192.168.1.1).
