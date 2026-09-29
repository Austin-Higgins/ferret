# App Review notes (draft)

**What the VPN is for.** Ferret is a network debugger. It uses `NEPacketTunnelProvider`
only to observe this device's own traffic, the way developer tools such as Wireshark do on a Mac.

**Local-only processing.** The tunnel runs on the device and relays each connection
directly to its original destination using Network.framework. No traffic is routed
through a remote server, modified, or collected. DNS continues to use the network's
own resolvers. There are no accounts, analytics or remote servers.

**No decryption.** Ferret doesn't install certificates or decrypt HTTPS. It shows
metadata that is already visible on the network: DNS names, server names from TLS handshakes,
and packet sizes and timing.

**User control.** Capture starts only when the user taps Start (or runs the Shortcut),
the storage limit is user-set, and all captures can be deleted in one tap.

**How to test.** Tap Start, allow the VPN configuration, open Safari and visit any site,
then check the Traffic tab. Safety Snoot > Practice mode demonstrates the network checks
without needing a hostile network.

**Privacy policy:** PRIVACY.md in the repository and the App Store listing.
