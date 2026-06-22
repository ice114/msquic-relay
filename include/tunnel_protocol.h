/*
 * tunnel_protocol.h — shared wire formats for the CNP relay experiment.
 *
 * Two parties share this header:
 *   - shim/shim.c   (端侧网关, plain POSIX UDP proxy on each endpoint host)
 *   - relay/relay.c (DPDK data plane on the relay VM)
 *
 * It is deliberately free of any DPDK or POSIX byte-order dependency: every
 * helper takes/returns HOST-order integers, and all multi-byte fields in the
 * on-wire structs are stored in NETWORK order by whoever fills them. The
 * caller converts at the edges (htons/ntohs in the shim, rte_*_to_* in the
 * relay). This keeps the one header compilable on both sides.
 *
 *   ── On-wire datagram between a shim and the relay ──
 *   [ outer Ethernet ][ outer IPv4 ][ outer UDP ][ tunnel_header ][ inner payload ]
 *                                                  \__ TUNL __/    \_ QUIC or CNP _/
 *
 * The outer L2/L3/L4 is what actually gets routed (shim host <-> relay). The
 * tunnel_header carries the metadata the relay needs (flow id, direction,
 * type) plus the synthetic end-to-end 5-tuple. The inner payload is either a
 * raw QUIC datagram (type DATA) or a msquic "CNP1" control packet (type CNP).
 */
#ifndef TUNNEL_PROTOCOL_H
#define TUNNEL_PROTOCOL_H

#include <stdint.h>
#include <string.h>

/* ----------------------------------------------------------------------- */
/* Tunnel header                                                           */
/* ----------------------------------------------------------------------- */

#define TUNNEL_MAGIC      0x54554E4Cu  /* "TUNL" as a host-order uint32     */
#define TUNNEL_VERSION    1

/* tunnel_header.type */
#define TUNNEL_TYPE_DATA  0  /* inner payload is a raw QUIC datagram        */
#define TUNNEL_TYPE_CNP   1  /* inner payload is a msquic "CNP1" packet     */

/* tunnel_header.direction */
#define TUNNEL_DIR_C2S    0  /* client -> server                           */
#define TUNNEL_DIR_S2C    1  /* server -> client (and relay-originated CNP) */

/*
 * 28-byte tunnel header. All multi-byte fields are NETWORK byte order on the
 * wire. `magic` is compared against htonl(TUNNEL_MAGIC).
 */
struct tunnel_header {
    uint32_t magic;          /* htonl(TUNNEL_MAGIC)                         */
    uint8_t  version;        /* TUNNEL_VERSION                             */
    uint8_t  type;           /* TUNNEL_TYPE_*                              */
    uint8_t  direction;      /* TUNNEL_DIR_*                               */
    uint8_t  flags;          /* reserved, 0                                */
    uint32_t flow_id;        /* htonl(host-order flow id); set by the shim */
    uint16_t payload_len;    /* htons(inner payload length in bytes)       */
    uint16_t reserved;       /* 0                                          */
    uint32_t orig_src_ip;    /* synthetic endpoint identity (network order)*/
    uint32_t orig_dst_ip;    /* for DIR_C2S this is the server-shim addr   */
    uint16_t orig_src_port;  /* network order                              */
    uint16_t orig_dst_port;  /* network order                              */
} __attribute__((packed));

#define TUNNEL_HDR_LEN ((int)sizeof(struct tunnel_header))

/* TRUE if the leading bytes look like a tunnel header (magic is the wire,
 * i.e. network-order, value). Pass network-order magic from the packet. */
static inline int tunnel_is(const struct tunnel_header *h, uint32_t magic_netorder) {
    return h->magic == magic_netorder && h->version == TUNNEL_VERSION;
}

/*
 * Direction-canonical flow id from a host-order 5-tuple. Both directions of
 * the same connection hash to the SAME id, so the relay can tie the two legs
 * together; the tunnel_header.direction byte tells the legs apart. The shim
 * computes this once and stamps it into the header so the relay never has to
 * recompute (avoids any host/network-order mismatch).
 */
static inline uint32_t tunnel_flow_id(
        uint32_t ip_a, uint16_t port_a,
        uint32_t ip_b, uint16_t port_b) {
    /* Sort the two (ip,port) endpoints so order doesn't matter. */
    uint64_t ea = ((uint64_t)ip_a << 16) | port_a;
    uint64_t eb = ((uint64_t)ip_b << 16) | port_b;
    uint64_t lo = ea < eb ? ea : eb;
    uint64_t hi = ea < eb ? eb : ea;
    uint64_t h = lo * 0x9E3779B185EBCA87ull + hi * 0xC2B2AE3D27D4EB4Full;
    h ^= h >> 29; h *= 0xBF58476D1CE4E5B9ull; h ^= h >> 32;
    return (uint32_t)h;
}

/* ----------------------------------------------------------------------- */
/* msquic "CNP1" wire format (must match QuicBindingProcessCnpPacket)      */
/* ----------------------------------------------------------------------- */
/*
 *   offset size field
 *   0      1    marker  = 0x00 (QUIC fixed bit clear => unambiguously not QUIC)
 *   1      4    magic   = "CNP1"
 *   5      1    severity hint (0 = unspecified)
 *   6      2    suppress duration in milliseconds, LITTLE-endian uint16
 *   8      1    target DestCid length L (the sender's local connection ID)
 *   9      L    target DestCid bytes
 */
#define CNP_MARKER       0x00
#define CNP_MIN_LEN      9
#define CNP_MAX_CID_LEN  20   /* QUIC_MAX_CONNECTION_ID_LENGTH_V1 */
#define CNP_MAX_LEN      (CNP_MIN_LEN + CNP_MAX_CID_LEN)

/*
 * Build a msquic CNP packet into `out` (must be >= CNP_MAX_LEN bytes).
 * `cid`/`cid_len` is the target connection's local CID. `suppress_ms` is
 * clamped to uint16. Returns the total length written, or -1 on bad args.
 */
static inline int cnp_build(uint8_t *out, const uint8_t *cid, uint8_t cid_len,
                            uint32_t suppress_ms, uint8_t severity) {
    if (cid_len > CNP_MAX_CID_LEN) return -1;
    if (suppress_ms > 0xFFFF) suppress_ms = 0xFFFF;
    out[0] = CNP_MARKER;
    out[1] = 'C'; out[2] = 'N'; out[3] = 'P'; out[4] = '1';
    out[5] = severity;
    out[6] = (uint8_t)(suppress_ms & 0xFF);          /* little-endian */
    out[7] = (uint8_t)((suppress_ms >> 8) & 0xFF);
    out[8] = cid_len;
    if (cid_len) memcpy(out + CNP_MIN_LEN, cid, cid_len);
    return CNP_MIN_LEN + cid_len;
}

/* TRUE if `buf` (len bytes) is a msquic CNP packet. */
static inline int cnp_is(const uint8_t *buf, int len) {
    return len >= CNP_MIN_LEN && buf[0] == CNP_MARKER &&
           buf[1] == 'C' && buf[2] == 'N' && buf[3] == 'P' && buf[4] == '1';
}

/* ----------------------------------------------------------------------- */
/* Inner QUIC header parsing — extract the DestCID the relay needs         */
/* ----------------------------------------------------------------------- */
/*
 * For a short-header (1-RTT) packet traveling toward an endpoint, byte 0 has
 * the QUIC fixed bit (0x40) set and the long-header bit (0x80) clear, and the
 * DestCID immediately follows at offset 1. Short headers carry NO CID length
 * field, so the relay must know the endpoint's configured local CID length
 * (msquic default CidTotalLength = 9 when load balancing is disabled).
 *
 * Returns the number of CID bytes copied into `cid_out` (== cid_len) on
 * success, or 0 if the packet is not a usable short header / too small.
 * `cid_out` must hold at least cid_len bytes.
 */
static inline int quic_short_header_dcid(const uint8_t *quic, int len,
                                         uint8_t cid_len, uint8_t *cid_out) {
    if (len < 1 + cid_len) return 0;
    uint8_t b0 = quic[0];
    if (b0 & 0x80) return 0;          /* long header, not 1-RTT */
    if (!(b0 & 0x40)) return 0;       /* fixed bit clear: not a QUIC short hdr */
    memcpy(cid_out, quic + 1, cid_len);
    return cid_len;
}

#endif /* TUNNEL_PROTOCOL_H */
