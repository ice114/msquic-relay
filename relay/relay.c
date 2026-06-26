/*
 * relay.c — DPDK data plane for the CNP relay experiment.
 *
 * Sits on the relay VM's data NIC (ens192 / 10.103.238.111) and:
 *   1. receives tunnel datagrams from the端侧 shims (outer UDP to relay:port,
 *      carrying a tunnel_header + an inner QUIC/CNP payload),
 *   2. forwards them toward the other end (keeping the tunnel header so the
 *      far shim can strip it), learning each flow's client-side outer address,
 *   3. meters per-flow byte rate and picks the Top-K heavy hitters,
 *   4. injects a tunnel(type=CNP) packet back toward an elephant flow's client,
 *      carrying a msquic "CNP1" payload addressed by the client's QUIC DestCID
 *      (sniffed from the server->client inner short header). The client shim
 *      strips the tunnel header and hands the "CNP1" bytes to its local msquic,
 *      which suppresses BBR.
 *
 * Unlike the reference relay this does NOT rate-limit or queue locally: the
 * actual limiting happens at the source via CNP -> BBR. So no token bucket,
 * no per-flow packet queue. MACs are not hardcoded — the relay's own MAC is
 * read from the port and the next-hop (gateway) MAC is learned from RX.
 *
 * Build: see meson.build (pkg-config libdpdk).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>   /* ssize_t, required by some DPDK headers */

#include <rte_eal.h>
#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_branch_prediction.h>
#include <rte_lcore.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_arp.h>
#include <rte_errno.h>
#include <rte_byteorder.h>
#include <rte_random.h>

#include "tunnel_protocol.h"

/* ----------------------------- tunables ------------------------------- */
#define MAX_PKT_BURST        32
#define MEMPOOL_CACHE_SIZE   256
#define RX_RING_SIZE         1024
#define TX_RING_SIZE         1024
#define NUM_MBUFS            32767          /* must comfortably exceed shaper FIFO */
#define TX_BUFFER_MBUF_CNT   512

#define MAX_FLOWS            4096
#define FLOW_HASH_SIZE       8192            /* power of two */
#define FLOW_HASH_MASK       (FLOW_HASH_SIZE - 1)
#define FLOW_IDLE_SEC        120

/* msquic's default local CID length (CidTotalLength, load balancing off). */
#define CLIENT_CID_LEN       9

/* Detection / CNP. */
#define DETECT_INTERVAL_US   200000          /* re-scan flows every 200ms     */
#define CNP_MIN_INTERVAL_US  100000          /* >=100ms between CNPs per flow */
#define CNP_SUPPRESS_MS      200             /* BBR suppression per CNP       */
#define CNP_TOP_K            4               /* limit at most K elephants     */

/* anti-CNP (relay-driven "don't back off on this loss" signal). */
#define ANTICNP_WINDOW_MS    200             /* loss-relaxation window per ACN */
#define ANTICNP_MIN_INTERVAL_US 100000       /* >=100ms between ACNs per flow  */
#define OWD_FLAT_TOL_MS      20              /* recent OWD within floor+tol =>
                                                no queue => loss looks random.
                                                A real bottleneck queue adds
                                                ~100ms; jitter is a few ms, so
                                                20ms cleanly separates them.    */

/* Egress software shaper (imposes a per-segment bottleneck/loss/delay so the
 * relay is the queue owner; the backlog is the ground-truth congestion signal). */
#define SHAPER_QSIZE         16384           /* max packets held in egress FIFO */
#define DEFAULT_CONGEST_BYTES (50u * 1024)   /* backlog > this => "congested"   */

/* ----------------------------- config --------------------------------- */
struct relay_cfg {
    uint32_t relay_ip;        /* host order */
    uint16_t relay_port;      /* host order */
    uint64_t threshold_bps;   /* single-flow elephant threshold, bytes/sec */
    uint8_t  cid_len;         /* client local CID length (msquic CidTotalLength) */

    /* Multi-relay chain: where to forward C2S (toward the server). If
     * next_hop_ip is 0 we fall back to the tunnel header's orig_dst (the
     * original single-relay behavior). next-hop MAC is the L2 dst to reach it
     * (the next relay's MAC if on-subnet, or the gateway MAC if off-subnet);
     * if not set we fall back to the learned g_gw_mac. */
    uint32_t next_hop_ip;     /* host order, 0 = use tunnel orig_dst */
    uint16_t next_hop_port;   /* host order */
    uint8_t  next_hop_mac[6];
    uint8_t  have_next_hop_mac;

    /* Egress shaper (applied to the C2S/downstream forward). */
    uint64_t egress_rate_bps;   /* 0 = unlimited */
    uint32_t egress_delay_ms;   /* added one-way delay */
    uint64_t egress_delay_tsc;  /* derived from egress_delay_ms after tsc_hz */
    uint32_t egress_loss_ppm;   /* random egress drop, parts per million */
    uint64_t congest_q_bytes;   /* egress backlog threshold => "I'm bottleneck" */
    uint64_t egress_qcap_bytes; /* finite router buffer; tail-drop beyond it */

    /* Signal toggles (for A/B/ablation experiments). */
    uint8_t  cnp_on;            /* inject CNP when congested            */
    uint8_t  anticnp_on;        /* inject anti-CNP on random loss       */
    uint8_t  force_random;      /* ablation: treat ALL loss as random   */
    uint8_t  seg_id;            /* this relay's segment id (diagnostics) */
};
static struct relay_cfg g_cfg = {
    .relay_ip      = 0,                 /* set in main (default 10.103.238.111) */
    .relay_port    = 4433,
    .threshold_bps = (10ull * 1000 * 1000) / 8,  /* 10 Mbit/s */
    .cid_len       = CLIENT_CID_LEN,             /* 9 (load balancing off) */
    .congest_q_bytes  = DEFAULT_CONGEST_BYTES,
    .egress_qcap_bytes = (1u << 20),             /* 1 MB finite buffer */
    .cnp_on        = 1,
    .anticnp_on    = 1,
};

/* ----------------------------- flow table ----------------------------- */
struct flow {
    uint8_t  used;
    uint8_t  have_client;                 /* learned client outer addr?       */
    uint8_t  client_cid_len;
    uint8_t  client_mac[6];
    uint32_t flow_id;                     /* host order (carried by shim)      */
    uint32_t client_ip;                   /* network order (learned dir=0)     */
    uint16_t client_port;                 /* network order                     */
    uint8_t  client_cid[CNP_MAX_CID_LEN]; /* sniffed from dir=1 inner QUIC     */

    uint64_t bytes_period;                /* bytes since last rate calc        */
    uint64_t bytes_per_sec;
    uint64_t last_rate_tsc;
    uint64_t last_seen_tsc;
    uint64_t last_cnp_tsc;
    uint32_t cnp_count;

    /* ingress seq/OWD tracking (C2S DATA), for the segment classifier. */
    uint8_t  rx_seq_init;                 /* seen the first seq yet?           */
    uint8_t  owd_init;
    uint32_t rx_seq_max;                  /* highest seq seen (host order)     */
    uint64_t rx_pkts;                     /* DATA packets received             */
    uint64_t rx_loss;                     /* cumulative detected sequence gaps */
    uint64_t rx_loss_snap;                /* rx_loss at last detect scan       */
    uint32_t owd_base;                    /* first (recv_ms - send_ts): clock offset + base delay */
    int32_t  owd_min;                     /* min delay relative to base (ms): floor  */
    int32_t  owd_recent;                  /* EWMA delay relative to base (ms)        */
    uint64_t last_anticnp_tsc;
    uint32_t anticnp_count;

    struct flow *hash_next;
};

static struct flow      g_flows[MAX_FLOWS];
static struct flow     *g_hash[FLOW_HASH_SIZE];
static uint32_t         g_active_idx[MAX_FLOWS];
static uint32_t         g_active_cnt = 0;
static int              g_next_free = 0;

/* ----------------------------- globals -------------------------------- */
static struct rte_mempool        *g_pool = NULL;
static struct rte_eth_dev_tx_buffer *g_txbuf = NULL;
static uint16_t                   g_port = 0;
static struct rte_ether_addr      g_relay_mac;
static struct rte_ether_addr      g_gw_mac;          /* learned from RX */
static int                        g_gw_mac_known = 0;
static uint64_t                   g_tsc_hz = 0, g_tsc_us = 1, g_tsc_ms = 1;

static uint64_t now_tsc(void) { return rte_rdtsc(); }

/* ----------------------------- egress shaper -------------------------- */
/*
 * A single software FIFO models this relay's downstream (C2S) egress link.
 * Packets are metered by a token bucket (egress_rate_bps) and released after
 * egress_delay_tsc; random egress_loss_ppm drops happen on enqueue. The bytes
 * sitting in the FIFO (g_sq_bytes) ARE the queue depth — the classifier's
 * ground-truth "am I the bottleneck?" signal.
 */
struct shaped_pkt { struct rte_mbuf *m; uint64_t eligible_tsc; uint32_t len; };
static struct shaped_pkt g_sq[SHAPER_QSIZE];
static uint32_t  g_sq_head = 0, g_sq_tail = 0;      /* ring indices */
static uint64_t  g_sq_bytes = 0;                    /* backlog bytes = queue depth */
static uint64_t  g_tokens = 0;                      /* token bucket (bytes) */
static uint64_t  g_tok_last_tsc = 0;
static uint64_t  g_egress_loss_drops = 0;           /* random drops */
static uint64_t  g_egress_full_drops = 0;           /* FIFO-full tail drops */

static inline int shaper_enabled(void) {
    return g_cfg.egress_rate_bps || g_cfg.egress_delay_tsc || g_cfg.egress_loss_ppm;
}

/* ----------------------------- hashing -------------------------------- */
static inline uint32_t fhash(uint32_t id) {
    return (id ^ (id >> 16) ^ (id >> 8)) & FLOW_HASH_MASK;
}
static inline struct flow *flow_find(uint32_t id) {
    struct flow *f = g_hash[fhash(id)];
    while (f) { if (likely(f->flow_id == id)) return f; f = f->hash_next; }
    return NULL;
}
static struct flow *flow_create(uint32_t id, uint64_t t) {
    int idx = -1;
    for (int i = g_next_free; i < MAX_FLOWS; i++)
        if (!g_flows[i].used) { idx = i; g_next_free = i + 1; break; }
    if (idx < 0)
        for (int i = 0; i < MAX_FLOWS; i++)
            if (!g_flows[i].used) { idx = i; break; }
    if (idx < 0) return NULL;

    struct flow *f = &g_flows[idx];
    memset(f, 0, sizeof(*f));
    f->used = 1;
    f->flow_id = id;
    f->last_rate_tsc = t;
    f->last_seen_tsc = t;
    uint32_t h = fhash(id);
    f->hash_next = g_hash[h];
    g_hash[h] = f;
    if (g_active_cnt < MAX_FLOWS) g_active_idx[g_active_cnt++] = (uint32_t)idx;
    return f;
}

static void hash_remove(struct flow *f) {
    uint32_t h = fhash(f->flow_id);
    struct flow *cur = g_hash[h], *prev = NULL;
    while (cur) {
        if (cur == f) {
            if (prev) prev->hash_next = cur->hash_next;
            else g_hash[h] = cur->hash_next;
            return;
        }
        prev = cur; cur = cur->hash_next;
    }
}

/* ----------------------------- stats ---------------------------------- */
static inline void flow_account(struct flow *f, uint32_t bytes, uint64_t t) {
    f->bytes_period += bytes;
    f->last_seen_tsc = t;
    uint64_t diff = t - f->last_rate_tsc;
    if (diff >= g_tsc_hz) {                       /* recompute ~once a second */
        f->bytes_per_sec = (f->bytes_period * g_tsc_hz) / diff;
        f->bytes_period = 0;
        f->last_rate_tsc = t;
    }
}

/* ----------------------------- TX helpers ----------------------------- */
static void tx_err_cb(struct rte_mbuf **unsent, uint16_t n, void *u __rte_unused) {
    for (uint16_t i = 0; i < n; i++) rte_pktmbuf_free(unsent[i]);
}
static inline void tx_enqueue(struct rte_mbuf *m) {
    rte_eth_tx_buffer(g_port, 0, g_txbuf, m);
}
static inline void tx_flush(void) { rte_eth_tx_buffer_flush(g_port, 0, g_txbuf); }

/* Recompute IPv4 checksum, zero UDP checksum (optional for IPv4). */
static inline void fix_l3l4(struct rte_ipv4_hdr *ip, struct rte_udp_hdr *udp) {
    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);
    udp->dgram_cksum = 0;
}

/*
 * Hand a (downstream) packet to the egress shaper. Applies random loss, then
 * either passes straight through (no rate/delay configured) or queues it in the
 * FIFO to be released by shaper_drain. Takes ownership of `m`.
 */
static void shaper_enqueue(struct rte_mbuf *m, uint64_t t) {
    if (g_cfg.egress_loss_ppm) {
        if ((rte_rand() % 1000000u) < g_cfg.egress_loss_ppm) {
            rte_pktmbuf_free(m);
            g_egress_loss_drops++;
            return;
        }
    }
    if (!g_cfg.egress_rate_bps && !g_cfg.egress_delay_tsc) {
        tx_enqueue(m);                      /* loss-only shaper: forward now */
        return;
    }
    uint32_t len = rte_pktmbuf_pkt_len(m);
    uint32_t next = (g_sq_tail + 1) & (SHAPER_QSIZE - 1);
    if (next == g_sq_head ||                /* ring full, or finite buffer full */
        g_sq_bytes + len > g_cfg.egress_qcap_bytes) {
        rte_pktmbuf_free(m);                /* tail drop (a congestion drop) */
        g_egress_full_drops++;
        return;
    }
    g_sq[g_sq_tail].m = m;
    g_sq[g_sq_tail].eligible_tsc = t + g_cfg.egress_delay_tsc;
    g_sq[g_sq_tail].len = len;
    g_sq_bytes += len;
    g_sq_tail = next;
}

/* Release shaper-queued packets whose delay has elapsed and whose bytes the
 * token bucket can afford. Called once per main-loop iteration. */
static void shaper_drain(uint64_t t) {
    if (!shaper_enabled()) return;

    if (g_cfg.egress_rate_bps) {            /* refill token bucket (bytes) */
        uint64_t dt = t - g_tok_last_tsc;
        uint64_t add = (g_cfg.egress_rate_bps * dt) / g_tsc_hz;
        if (add > 0) {
            //
            // Credit whole bytes only, and advance the clock by EXACTLY the time
            // those bytes represent (not to `t`). The drain runs every tight-loop
            // iteration with a tiny dt, so `rate*dt/hz` truncates to 0 almost
            // every call; advancing to `t` each time would silently discard the
            // sub-byte remainder and starve the bucket (throughput collapse).
            //
            g_tokens += add;
            g_tok_last_tsc += (add * g_tsc_hz) / g_cfg.egress_rate_bps;
            uint64_t cap = g_cfg.egress_rate_bps / 50;   /* ~20ms burst */
            if (cap < 65536) cap = 65536;
            if (g_tokens > cap) g_tokens = cap;
        }
    }

    while (g_sq_head != g_sq_tail) {
        struct shaped_pkt *p = &g_sq[g_sq_head];
        if (t < p->eligible_tsc) break;                  /* delay not elapsed */
        if (g_cfg.egress_rate_bps && g_tokens < p->len) break; /* no tokens */
        if (g_cfg.egress_rate_bps) g_tokens -= p->len;
        g_sq_bytes -= p->len;
        tx_enqueue(p->m);
        g_sq_head = (g_sq_head + 1) & (SHAPER_QSIZE - 1);
    }
}

/* ----------------------------- forwarding ----------------------------- */
/*
 * Forward a tunnel datagram in place: keep the tunnel header + inner payload,
 * rewrite only the outer L2/L3/L4 toward `dst_ip:dst_port` via `dst_mac`.
 */
static void forward_to(struct rte_mbuf *m, struct rte_ether_hdr *eth,
                       struct rte_ipv4_hdr *ip, struct rte_udp_hdr *udp,
                       uint32_t dst_ip_net, uint16_t dst_port_net,
                       const uint8_t *dst_mac, uint64_t t, int via_shaper) {
    rte_ether_addr_copy(&g_relay_mac, &eth->src_addr);
    memcpy(eth->dst_addr.addr_bytes, dst_mac, 6);

    ip->src_addr = rte_cpu_to_be_32(g_cfg.relay_ip);
    ip->dst_addr = dst_ip_net;            /* already network order */

    udp->src_port = rte_cpu_to_be_16(g_cfg.relay_port);
    udp->dst_port = dst_port_net;         /* already network order */

    fix_l3l4(ip, udp);
    if (via_shaper && shaper_enabled()) shaper_enqueue(m, t);
    else                                tx_enqueue(m);
}

/* ----------------------------- control injection ---------------------- */
/*
 * Build a tunnel(type) S2C control packet carrying `payload` and send it
 * toward the flow's learned upstream neighbor (prev-hop). In a chain the
 * prev-hop is the next relay toward the client, which forwards it onward by
 * flow_id until the client shim delivers the inner bytes to msquic. Control
 * packets bypass the egress shaper (they must reach the sender promptly).
 */
static void inject_control(struct flow *f, uint8_t type,
                           const uint8_t *payload, int plen) {
    struct rte_mbuf *m = rte_pktmbuf_alloc(g_pool);
    if (!m) return;

    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct rte_ipv4_hdr  *ip  = (struct rte_ipv4_hdr *)(eth + 1);
    struct rte_udp_hdr   *udp = (struct rte_udp_hdr *)(ip + 1);
    struct tunnel_header *th  = (struct tunnel_header *)(udp + 1);
    uint8_t              *body = (uint8_t *)(th + 1);

    memset(th, 0, sizeof(*th));
    th->magic       = rte_cpu_to_be_32(TUNNEL_MAGIC);
    th->version     = TUNNEL_VERSION;
    th->type        = type;
    th->direction   = TUNNEL_DIR_S2C;
    th->flow_id     = rte_cpu_to_be_32(f->flow_id);
    th->payload_len = rte_cpu_to_be_16((uint16_t)plen);
    memcpy(body, payload, plen);

    uint16_t udp_len = sizeof(*udp) + sizeof(*th) + plen;
    uint16_t ip_len  = sizeof(*ip) + udp_len;

    rte_ether_addr_copy(&g_relay_mac, &eth->src_addr);
    memcpy(eth->dst_addr.addr_bytes, f->client_mac, 6);
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    ip->version_ihl     = 0x45;
    ip->type_of_service = 0;
    ip->total_length    = rte_cpu_to_be_16(ip_len);
    ip->packet_id       = 0;
    ip->fragment_offset = 0;
    ip->time_to_live    = 64;
    ip->next_proto_id   = IPPROTO_UDP;
    ip->src_addr        = rte_cpu_to_be_32(g_cfg.relay_ip);
    ip->dst_addr        = f->client_ip;          /* network order (prev-hop) */

    udp->src_port  = rte_cpu_to_be_16(g_cfg.relay_port);
    udp->dst_port  = f->client_port;             /* network order */
    udp->dgram_len = rte_cpu_to_be_16(udp_len);

    uint16_t total = sizeof(*eth) + ip_len;
    m->data_len = total;
    m->pkt_len  = total;
    fix_l3l4(ip, udp);
    tx_enqueue(m);
}

/* ----------------------------- CNP injection -------------------------- */
static void inject_cnp(struct flow *f, uint64_t t) {
    //
    // Address the flow by tunnel flow_id, NOT by QUIC CID: secnetperf clients
    // use a zero-length source CID, so the relay cannot sniff a usable CID. The
    // CNP is sent with cidlen 0; the client shim routes it to the right msquic
    // by flow_id, and msquic's single-connection binding accepts a CID-less CNP.
    //
    if (!f->have_client) return;
    if (t - f->last_cnp_tsc < (uint64_t)CNP_MIN_INTERVAL_US * g_tsc_us) return;

    //
    // Severity scales with how far the flow is over the elephant threshold:
    // 1x over => mild, >=5x over => hardest. The sender's BBR interprets
    // severity as "cut harder" (keep ~= 100 - severity percent of the window).
    //
    uint8_t severity;
    {
        uint64_t ratio = f->bytes_per_sec / (g_cfg.threshold_bps ? g_cfg.threshold_bps : 1);
        if (ratio <= 1)      severity = 50;   /* keep ~50% */
        else if (ratio >= 5) severity = 90;   /* keep ~10% */
        else                 severity = (uint8_t)(50 + (ratio - 1) * 10); /* 60..80 */
    }
    uint8_t buf[CNP_MAX_LEN];
    int cnp_len = cnp_build(buf, NULL, 0, CNP_SUPPRESS_MS, severity);
    if (cnp_len < 0) return;

    inject_control(f, TUNNEL_TYPE_CNP, buf, cnp_len);
    f->last_cnp_tsc = t;
    f->cnp_count++;

    static uint64_t last_log = 0;
    if (t - last_log > g_tsc_hz) {       /* at most ~1 log line/sec */
        printf("[relay] seg%u CNP -> flow 0x%08x bps=%.1fMbit q=%" PRIu64 "B count=%u\n",
               g_cfg.seg_id, f->flow_id, (double)(f->bytes_per_sec * 8) / 1e6,
               g_sq_bytes, f->cnp_count);
        last_log = t;
    }
}

/* ----------------------------- anti-CNP injection --------------------- */
/*
 * Tell the sender NOT to back off for the loss it's about to see on this
 * segment, because the relay observed loss with no queue (looks random, not
 * congestion). Same flow_id addressing as CNP; carries an "ACN1" payload.
 */
static void inject_anticnp(struct flow *f, uint64_t t) {
    if (!f->have_client) return;
    if (t - f->last_anticnp_tsc < (uint64_t)ANTICNP_MIN_INTERVAL_US * g_tsc_us) return;

    uint8_t buf[ACN_MAX_LEN];
    int acn_len = acn_build(buf, NULL, 0, ANTICNP_WINDOW_MS, 0 /* default relax */);
    if (acn_len < 0) return;

    inject_control(f, TUNNEL_TYPE_ANTICNP, buf, acn_len);
    f->last_anticnp_tsc = t;
    f->anticnp_count++;

    static uint64_t last_log = 0;
    if (t - last_log > g_tsc_hz) {       /* at most ~1 log line/sec */
        printf("[relay] seg%u ACN -> flow 0x%08x loss=%" PRIu64 " owd=%d/%d q=%" PRIu64 "B count=%u\n",
               g_cfg.seg_id, f->flow_id, f->rx_loss,
               f->owd_recent, f->owd_min, g_sq_bytes, f->anticnp_count);
        last_log = t;
    }
}

/* ----------------------------- ingress tracking ----------------------- */
/*
 * Per-flow loss (sequence gaps) and one-way-delay trend, from the seq/send_ts
 * the shim stamps on C2S DATA. A gap means a packet was lost UPSTREAM of this
 * relay; a flat OWD (recent ~= floor) means no queue built up => the loss
 * looks random rather than congestive. Only the trend matters, so the clock
 * offset between shim and relay is irrelevant (it cancels in recent - floor).
 */
static void ingress_track(struct flow *f, const struct tunnel_header *th, uint64_t t) {
    uint32_t seq     = rte_be_to_cpu_32(th->seq);
    uint32_t send_ts = rte_be_to_cpu_32(th->send_ts);
    uint32_t recv_ms = (uint32_t)(t / g_tsc_ms);
    uint32_t raw     = recv_ms - send_ts;            /* clock offset + delay (wraps) */

    f->rx_pkts++;
    if (!f->owd_init) {
        //
        // The shim and relay clocks have different origins, so the absolute
        // (recv_ms - send_ts) is offset by an arbitrary constant and can even
        // wrap. Anchor to the first sample and track delay RELATIVE to it
        // (signed); only the trend (recent - floor) matters for "is a queue
        // building", and int32 differencing is wrap-correct for any realistic
        // delay variation (< 24 days).
        //
        f->owd_base = raw; f->owd_min = 0; f->owd_recent = 0; f->owd_init = 1;
    } else {
        int32_t rel = (int32_t)(raw - f->owd_base);  /* ms above base; signed */
        if (rel < f->owd_min) f->owd_min = rel;
        /* light EWMA so a single jittered sample doesn't trip the classifier */
        f->owd_recent = (int32_t)(((int64_t)f->owd_recent * 7 + rel) / 8);
    }

    if (!f->rx_seq_init) { f->rx_seq_max = seq; f->rx_seq_init = 1; return; }
    /* Forward progress: count any skipped sequence numbers as losses. Ignore
     * reordering/dups (seq <= max) for loss accounting. */
    if ((int32_t)(seq - f->rx_seq_max) > 0) {
        uint32_t gap = seq - f->rx_seq_max - 1;
        if (gap) f->rx_loss += gap;
        f->rx_seq_max = seq;
    }
}

/* ----------------------------- tunnel RX ------------------------------ */
static void process_tunnel(struct rte_mbuf *m, struct rte_ether_hdr *eth,
                           struct rte_ipv4_hdr *ip, struct rte_udp_hdr *udp,
                           struct tunnel_header *th, uint64_t t) {
    if (!g_gw_mac_known) {                  /* learn next-hop MAC from RX */
        rte_ether_addr_copy(&eth->src_addr, &g_gw_mac);
        g_gw_mac_known = 1;
    }

    uint32_t flow_id  = rte_be_to_cpu_32(th->flow_id);
    uint16_t plen     = rte_be_to_cpu_16(th->payload_len);
    uint8_t  dir      = th->direction;

    struct flow *f = flow_find(flow_id);
    if (!f) f = flow_create(flow_id, t);
    if (!f) { rte_pktmbuf_free(m); return; }

    flow_account(f, plen, t);

    if (dir == TUNNEL_DIR_C2S) {
        /* Learn the upstream neighbor's outer address (prev-hop = where return
         * traffic and CNP/anti-CNP go). In a chain this is the previous relay. */
        f->client_ip   = ip->src_addr;        /* network order */
        f->client_port = udp->src_port;       /* network order */
        memcpy(f->client_mac, eth->src_addr.addr_bytes, 6);
        f->have_client = 1;

        if (th->type == TUNNEL_TYPE_DATA)
            ingress_track(f, th, t);

        /* C2S forward: to the configured next-hop (chain) or, if unset, the
         * tunnel header's orig_dst (single-relay fallback). Apply the egress
         * shaper so this relay can model a bottleneck/loss on its segment. */
        uint32_t dst_ip   = g_cfg.next_hop_ip
                          ? rte_cpu_to_be_32(g_cfg.next_hop_ip) : th->orig_dst_ip;
        uint16_t dst_port = g_cfg.next_hop_ip
                          ? rte_cpu_to_be_16(g_cfg.next_hop_port) : th->orig_dst_port;
        const uint8_t *dst_mac = g_cfg.have_next_hop_mac
                          ? g_cfg.next_hop_mac : g_gw_mac.addr_bytes;
        forward_to(m, eth, ip, udp, dst_ip, dst_port, dst_mac, t, 1 /* shaped */);
    } else { /* TUNNEL_DIR_S2C: return DATA, or a CNP/anti-CNP passing upstream */
        if (!f->have_client) { rte_pktmbuf_free(m); return; }
        /* Forward back toward the client (prev-hop), unshaped. */
        forward_to(m, eth, ip, udp,
                   f->client_ip, f->client_port, f->client_mac, t, 0 /* unshaped */);
    }
}

/* ----------------------------- ARP ------------------------------------ */
static void process_arp(struct rte_mbuf *m) {
    if (rte_pktmbuf_data_len(m) <
        sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr)) {
        rte_pktmbuf_free(m); return;
    }
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct rte_arp_hdr *arp = (struct rte_arp_hdr *)(eth + 1);
    if (rte_be_to_cpu_16(arp->arp_opcode) != RTE_ARP_OP_REQUEST ||
        rte_be_to_cpu_32(arp->arp_data.arp_tip) != g_cfg.relay_ip) {
        rte_pktmbuf_free(m); return;
    }
    rte_ether_addr_copy(&eth->src_addr, &eth->dst_addr);
    rte_ether_addr_copy(&g_relay_mac, &eth->src_addr);
    arp->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
    rte_ether_addr_copy(&arp->arp_data.arp_sha, &arp->arp_data.arp_tha);
    arp->arp_data.arp_tip = arp->arp_data.arp_sip;
    rte_ether_addr_copy(&g_relay_mac, &arp->arp_data.arp_sha);
    arp->arp_data.arp_sip = rte_cpu_to_be_32(g_cfg.relay_ip);
    tx_enqueue(m);
}

/* ----------------------------- detection / classifier ----------------- */
static void detect_and_inject(uint64_t t) {
    static uint64_t last = 0;
    if (t - last < (uint64_t)DETECT_INTERVAL_US * g_tsc_us) return;
    last = t;

    /* Ground-truth congestion signal: is MY egress backlog deep? */
    int egress_congested = shaper_enabled() && (g_sq_bytes > g_cfg.congest_q_bytes);

    /*
     * CNP — only when I'm actually the bottleneck (egress backlog deep). Then
     * throttle the Top-K elephants by rate. If my egress is shallow I send no
     * CNP even if a flow is "big": being big isn't a problem without congestion
     * (this is what avoids 误伤 / throttling flows I'm not bottlenecking).
     */
    if (g_cfg.cnp_on && egress_congested) {
        struct flow *top[CNP_TOP_K];
        int n = 0;
        for (uint32_t i = 0; i < g_active_cnt; i++) {
            struct flow *f = &g_flows[g_active_idx[i]];
            if (!f->used || f->bytes_per_sec <= g_cfg.threshold_bps) continue;
            if (n < CNP_TOP_K) {
                top[n++] = f;
            } else {
                int min = 0;
                for (int k = 1; k < CNP_TOP_K; k++)
                    if (top[k]->bytes_per_sec < top[min]->bytes_per_sec) min = k;
                if (f->bytes_per_sec > top[min]->bytes_per_sec) top[min] = f;
            }
        }
        for (int i = 0; i < n; i++) inject_cnp(top[i], t);
    }

    /*
     * anti-CNP — per flow: if new sequence gaps appeared this interval and the
     * OWD looks flat (no queue => loss looks random), tell the sender not to
     * back off. Gate: I must NOT be the bottleneck myself (if my egress is
     * congested I won't mask losses). The force_random ablation skips both the
     * OWD and the congestion gate to prove the queue/OWD signal is load-bearing.
     */
    if (g_cfg.anticnp_on) {
        for (uint32_t i = 0; i < g_active_cnt; i++) {
            struct flow *f = &g_flows[g_active_idx[i]];
            if (!f->used) continue;
            uint64_t new_loss = f->rx_loss - f->rx_loss_snap;
            f->rx_loss_snap = f->rx_loss;
            if (!new_loss) continue;
            int owd_flat = (f->owd_recent <= f->owd_min + OWD_FLAT_TOL_MS);
            if (g_cfg.force_random || (owd_flat && !egress_congested))
                inject_anticnp(f, t);
        }
    }
}

/* ----------------------------- housekeeping --------------------------- */
static void reap_idle(uint64_t t) {
    static uint64_t last = 0;
    if (t - last < 5 * g_tsc_hz) return;
    last = t;
    uint64_t to = (uint64_t)FLOW_IDLE_SEC * g_tsc_hz;
    uint32_t i = 0;
    while (i < g_active_cnt) {
        uint32_t idx = g_active_idx[i];
        struct flow *f = &g_flows[idx];
        if (f->used && (t - f->last_seen_tsc) > to) {
            hash_remove(f);
            memset(f, 0, sizeof(*f));
            g_active_idx[i] = g_active_idx[--g_active_cnt];
            if ((int)idx < g_next_free) g_next_free = (int)idx;
            continue;
        }
        i++;
    }
}

static void print_stats(uint64_t t) {
    static uint64_t last = 0;
    if (t - last < 5 * g_tsc_hz) return;
    last = t;
    uint64_t total = 0, loss = 0; uint32_t big = 0;
    for (uint32_t i = 0; i < g_active_cnt; i++) {
        struct flow *f = &g_flows[g_active_idx[i]];
        if (!f->used) continue;
        total += f->bytes_per_sec;
        loss  += f->rx_loss;
        if (f->bytes_per_sec > g_cfg.threshold_bps) big++;
    }
    /* The classifier label this relay would assign right now: CONGESTED if my
     * egress backlog is deep; LOSSY if backlog shallow but flows are losing;
     * else HEALTHY. Printed even with signals off (label-only verification). */
    const char *label = "HEALTHY";
    int congested = shaper_enabled() && (g_sq_bytes > g_cfg.congest_q_bytes);
    if (congested)      label = "CONGESTED";
    else if (loss > 0)  label = "LOSSY";
    printf("[relay] seg%u %s flows=%u big=%u total=%.1fMbit q=%" PRIu64
           "B loss=%" PRIu64 " drops(loss/full)=%" PRIu64 "/%" PRIu64 "\n",
           g_cfg.seg_id, label, g_active_cnt, big, (double)(total * 8) / 1e6,
           g_sq_bytes, loss, g_egress_loss_drops, g_egress_full_drops);
}

/* ----------------------------- main loop ------------------------------ */
static int main_loop(__rte_unused void *arg) {
    printf("[relay] loop on lcore %u, seg%u relay=%u.%u.%u.%u:%u thresh=%.1fMbit\n",
           rte_lcore_id(), g_cfg.seg_id,
           (g_cfg.relay_ip >> 24) & 0xFF, (g_cfg.relay_ip >> 16) & 0xFF,
           (g_cfg.relay_ip >> 8) & 0xFF, g_cfg.relay_ip & 0xFF, g_cfg.relay_port,
           (double)(g_cfg.threshold_bps * 8) / 1e6);
    if (g_cfg.next_hop_ip)
        printf("[relay] next-hop %u.%u.%u.%u:%u mac=%s\n",
               (g_cfg.next_hop_ip >> 24) & 0xFF, (g_cfg.next_hop_ip >> 16) & 0xFF,
               (g_cfg.next_hop_ip >> 8) & 0xFF, g_cfg.next_hop_ip & 0xFF,
               g_cfg.next_hop_port, g_cfg.have_next_hop_mac ? "static" : "learned-gw");
    printf("[relay] egress rate=%.1fMbit delay=%ums loss=%.2f%% congestQ=%" PRIu64 "B"
           " | cnp=%d anticnp=%d force_random=%d\n",
           (double)(g_cfg.egress_rate_bps * 8) / 1e6, g_cfg.egress_delay_ms,
           (double)g_cfg.egress_loss_ppm / 10000.0, g_cfg.congest_q_bytes,
           g_cfg.cnp_on, g_cfg.anticnp_on, g_cfg.force_random);

    const uint32_t min_tun = sizeof(struct rte_ether_hdr) +
        sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr) + TUNNEL_HDR_LEN;
    uint32_t relay_ip_be = rte_cpu_to_be_32(g_cfg.relay_ip);
    uint16_t relay_port_be = rte_cpu_to_be_16(g_cfg.relay_port);

    for (;;) {
        struct rte_mbuf *pkts[MAX_PKT_BURST];
        uint16_t nb = rte_eth_rx_burst(g_port, 0, pkts, MAX_PKT_BURST);
        uint64_t t = now_tsc();

        for (uint16_t i = 0; i < nb; i++) {
            struct rte_mbuf *m = pkts[i];
            if (i + 1 < nb) rte_prefetch0(rte_pktmbuf_mtod(pkts[i + 1], void *));

            uint32_t len = rte_pktmbuf_data_len(m);
            if (unlikely(len < sizeof(struct rte_ether_hdr))) {
                rte_pktmbuf_free(m); continue;
            }
            struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

            if (eth->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
                process_arp(m); continue;
            }
            if (eth->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4) ||
                len < min_tun) {
                rte_pktmbuf_free(m); continue;
            }
            struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
            if (ip->next_proto_id != IPPROTO_UDP) { rte_pktmbuf_free(m); continue; }
            struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(ip + 1);

            if (ip->dst_addr == relay_ip_be && udp->dst_port == relay_port_be) {
                struct tunnel_header *th = (struct tunnel_header *)(udp + 1);
                if (tunnel_is(th, rte_cpu_to_be_32(TUNNEL_MAGIC))) {
                    process_tunnel(m, eth, ip, udp, th, t);
                    continue;
                }
            }
            rte_pktmbuf_free(m);   /* not ours */
        }

        detect_and_inject(t);
        shaper_drain(t);       /* release egress-shaped packets */
        reap_idle(t);
        print_stats(t);
        tx_flush();
    }
    return 0;
}

/* ----------------------------- port init ------------------------------ */
static int init_port(uint16_t port) {
    struct rte_eth_conf conf;
    memset(&conf, 0, sizeof(conf));
    if (rte_eth_dev_configure(port, 1, 1, &conf) < 0) return -1;

    uint16_t rxd = RX_RING_SIZE, txd = TX_RING_SIZE;
    rte_eth_dev_adjust_nb_rx_tx_desc(port, &rxd, &txd);
    if (rte_eth_rx_queue_setup(port, 0, rxd, rte_eth_dev_socket_id(port),
                               NULL, g_pool) < 0) return -1;
    if (rte_eth_tx_queue_setup(port, 0, txd, rte_eth_dev_socket_id(port),
                               NULL) < 0) return -1;
    if (rte_eth_dev_start(port) < 0) return -1;
    rte_eth_promiscuous_enable(port);

    rte_eth_macaddr_get(port, &g_relay_mac);

    g_txbuf = rte_zmalloc_socket("txbuf",
        RTE_ETH_TX_BUFFER_SIZE(TX_BUFFER_MBUF_CNT), 0,
        rte_eth_dev_socket_id(port));
    if (!g_txbuf) return -ENOMEM;
    rte_eth_tx_buffer_init(g_txbuf, TX_BUFFER_MBUF_CNT);
    rte_eth_tx_buffer_set_err_callback(g_txbuf, tx_err_cb, NULL);

    printf("[relay] port %u up, mac %02x:%02x:%02x:%02x:%02x:%02x (rxd=%u txd=%u)\n",
           port,
           g_relay_mac.addr_bytes[0], g_relay_mac.addr_bytes[1],
           g_relay_mac.addr_bytes[2], g_relay_mac.addr_bytes[3],
           g_relay_mac.addr_bytes[4], g_relay_mac.addr_bytes[5], rxd, txd);
    return 0;
}

/* Parse "a.b.c.d" into host-order uint32. */
static uint32_t parse_ipv4(const char *s) {
    unsigned a, b, c, d;
    if (sscanf(s, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return 0;
    return (a << 24) | (b << 16) | (c << 8) | d;
}

/* Parse "aa:bb:cc:dd:ee:ff" into out[6]. Returns 0 on success. */
static int parse_mac(const char *s, uint8_t out[6]) {
    unsigned v[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x",
               &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6) return -1;
    for (int i = 0; i < 6; i++) out[i] = (uint8_t)v[i];
    return 0;
}

/* Parse "a.b.c.d:port" into host-order ip + port. Returns 0 on success. */
static int parse_ip_port(const char *s, uint32_t *ip, uint16_t *port) {
    char tmp[64];
    strncpy(tmp, s, sizeof(tmp) - 1); tmp[sizeof(tmp) - 1] = 0;
    char *colon = strrchr(tmp, ':');
    if (!colon) return -1;
    *colon = 0;
    uint32_t a = parse_ipv4(tmp);
    if (!a) return -1;
    *ip = a;
    *port = (uint16_t)atoi(colon + 1);
    return 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);   /* unbuffered: see logs live */

    int ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_panic("EAL init failed\n");
    argc -= ret; argv += ret;

    g_cfg.relay_ip = parse_ipv4("10.103.238.111");   /* default */

    /* App args after EAL's `--`. */
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--relay-ip") && i + 1 < argc)
            g_cfg.relay_ip = parse_ipv4(argv[++i]);
        else if (!strcmp(argv[i], "--relay-port") && i + 1 < argc)
            g_cfg.relay_port = (uint16_t)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--threshold-mbps") && i + 1 < argc)
            g_cfg.threshold_bps = ((uint64_t)atoi(argv[++i]) * 1000 * 1000) / 8;
        else if (!strcmp(argv[i], "--cid-len") && i + 1 < argc)
            g_cfg.cid_len = (uint8_t)atoi(argv[++i]);
        /* multi-relay chain forwarding */
        else if (!strcmp(argv[i], "--next-hop") && i + 1 < argc) {
            if (parse_ip_port(argv[++i], &g_cfg.next_hop_ip, &g_cfg.next_hop_port))
                rte_panic("bad --next-hop (want a.b.c.d:port)\n");
        }
        else if (!strcmp(argv[i], "--next-hop-mac") && i + 1 < argc) {
            if (parse_mac(argv[++i], g_cfg.next_hop_mac))
                rte_panic("bad --next-hop-mac (want aa:bb:cc:dd:ee:ff)\n");
            g_cfg.have_next_hop_mac = 1;
        }
        /* egress shaper (software-imposed per-segment conditions) */
        else if (!strcmp(argv[i], "--egress-rate-mbps") && i + 1 < argc)
            g_cfg.egress_rate_bps = ((uint64_t)atoi(argv[++i]) * 1000 * 1000) / 8;
        else if (!strcmp(argv[i], "--egress-delay-ms") && i + 1 < argc)
            g_cfg.egress_delay_ms = (uint32_t)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--egress-loss-pct") && i + 1 < argc)
            g_cfg.egress_loss_ppm = (uint32_t)(atof(argv[++i]) * 10000.0);
        else if (!strcmp(argv[i], "--congest-queue-kb") && i + 1 < argc)
            g_cfg.congest_q_bytes = (uint64_t)atoi(argv[++i]) * 1024;
        else if (!strcmp(argv[i], "--egress-queue-kb") && i + 1 < argc)
            g_cfg.egress_qcap_bytes = (uint64_t)atoi(argv[++i]) * 1024;
        else if (!strcmp(argv[i], "--seg-id") && i + 1 < argc)
            g_cfg.seg_id = (uint8_t)atoi(argv[++i]);
        /* signal toggles for A/B/ablation */
        else if (!strcmp(argv[i], "--no-cnp"))      g_cfg.cnp_on = 0;
        else if (!strcmp(argv[i], "--no-anticnp"))  g_cfg.anticnp_on = 0;
        else if (!strcmp(argv[i], "--signals-off")) { g_cfg.cnp_on = 0; g_cfg.anticnp_on = 0; }
        else if (!strcmp(argv[i], "--force-random")) g_cfg.force_random = 1;
    }

    g_tsc_hz = rte_get_tsc_hz();
    g_tsc_us = g_tsc_hz / 1000000; if (!g_tsc_us) g_tsc_us = 1;
    g_tsc_ms = g_tsc_hz / 1000;    if (!g_tsc_ms) g_tsc_ms = 1;
    g_cfg.egress_delay_tsc = (uint64_t)g_cfg.egress_delay_ms * g_tsc_ms;
    g_tok_last_tsc = now_tsc();

    if (rte_eth_dev_count_avail() == 0) rte_panic("no DPDK ports\n");

    g_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS, MEMPOOL_CACHE_SIZE,
        0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!g_pool) rte_panic("mbuf pool: %s\n", rte_strerror(rte_errno));

    g_port = 0;
    if (init_port(g_port) != 0) rte_panic("port init failed\n");

    main_loop(NULL);

    rte_eth_dev_stop(g_port);
    rte_eth_dev_close(g_port);
    return 0;
}
