#!/usr/bin/env bash
# Regenerates the Wireshark reference values the parser tests compare against.
# Requires tshark. Fixtures with embedded TLS secrets are stripped first
# (editcap --discard-all-secrets) so Wireshark sees only what Ferret sees.
set -euo pipefail
cd "$(dirname "$0")/../Tests/FerretParsersTests/Fixtures"

FIELDS=(
  frame.len
  ip.version ip.hdr_len ip.len ip.id ip.ttl ip.proto ip.checksum ip.flags.df ip.src ip.dst
  ipv6.plen ipv6.nxt ipv6.hlim ipv6.src ipv6.dst ipv6.flow
  tcp.srcport tcp.dstport tcp.seq_raw tcp.ack_raw tcp.hdr_len tcp.flags tcp.window_size_value
  tcp.checksum tcp.len tcp.options.mss_val tcp.options.wscale.shift
  udp.srcport udp.dstport udp.length udp.checksum
  icmp.type icmpv6.type
  dns.id dns.flags.response dns.flags.opcode dns.flags.rcode dns.count.queries dns.count.answers
  dns.qry.name dns.qry.type dns.a dns.aaaa dns.cname dns.resp.ttl
  tls.record.content_type tls.record.opaque_type tls.record.version tls.handshake.type
  tls.handshake.version tls.handshake.ciphersuite tls.handshake.extensions_server_name
  tls.handshake.extensions_alpn_str tls.handshake.extensions.supported_version
  quic.header_form quic.long.packet_type quic.version quic.dcid quic.scid
  http.request.method http.request.uri http.host http.response.code
)

args=()
for f in "${FIELDS[@]}"; do args+=(-e "$f"); done

for capture in dns.pcap http.pcap ipv6.pcap tls13-rfc8446.pcap tls12.pcapng quic.pcapng dhcp.pcapng; do
  tshark -r "$capture" -T fields -E header=y -E separator=/t -E occurrence=a -E aggregator=, \
    "${args[@]}" > "$capture.fields.tsv"
done
tshark -v | head -1 > wireshark-version.txt
