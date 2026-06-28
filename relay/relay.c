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
#define CONGEST_HOLD_US      400000          /* keep CNPing 400ms past the last
                                              * CONGESTED detection, so a queue
                                              * that momentarily drains (BBR cycle)
                                              * doesn't let elephants re-ramp     */
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
    uint8_t  force_random;      /* ablation: force RELAX even when congested */
    uint8_t  cong_rate;         /* mode(b): CONGESTED beacon carries fair-share rate */
    uint8_t  seg_id;            /* this relay's segment id (diagnostics) */
    uint8_t  probe_next;        /* actively 4-timestamp-probe the next-hop (relay) */
    uint8_t  probe_congest;     /* also judge congestion from probe RTT inflation */
    uint32_t congest_qdelay_us; /* probe queueing-delay threshold => "congested"   */
    uint64_t congest_min_bps;   /* min forwarded rate to attribute congestion to me */

    /* Scheduled step event + ingress trace (control-loop-latency experiment).
     * At step_at_sec after boot, change the egress bottleneck to model a sudden
     * congestion onset, logging the apply time in relay-local ms. With
     * ingress_trace on, the C2S offered rate seen at this relay is printed every
     * ~100ms; the sender's reaction (rate falling to the new bottleneck) is then
     * measured ENTIRELY in this relay's clock -- no cross-host sync needed. */
    uint32_t step_at_sec;       /* 0 = disabled */
    int64_t  step_rate_bps;     /* new egress rate at step; <0 = leave unchanged */
    int64_t  step_loss_ppm;     /* new egress loss at step; <0 = leave unchanged */
    uint8_t  ingress_trace;     /* periodic C2S ingress-rate print (reaction series) */
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
    .congest_qdelay_us = 10000,                  /* 10ms probe queueing => congested */
    .congest_min_bps = (5ull * 1000 * 1000) / 8, /* >=5Mbit forwarded => could be me */
    .step_rate_bps = -1,                         /* no scheduled step by default */
    .step_loss_ppm = -1,
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

/* Single upstream neighbor (prev-hop) toward the client: in a chain all C2S
 * traffic arrives from one neighbor, so the relay needs only ONE return
 * address (no per-flow state) for S2C forwarding, CNP, and broadcast anti-CNP. */
static uint32_t  g_prev_ip = 0;      /* network order */
static uint16_t  g_prev_port = 0;    /* network order */
static uint8_t   g_prev_mac[6];
static uint8_t   g_prev_known = 0;
static uint64_t  g_bcast_last_tsc = 0;   /* last healthy-broadcast anti-CNP */
static uint64_t  g_bcast_count = 0;

/* Control-loop-latency experiment state (scheduled step + ingress trace). */
static uint64_t  g_boot_tsc = 0;          /* main-loop start, for step timing */
static uint8_t   g_step_done = 0;         /* step already applied (timer or ctl)? */
static uint64_t  g_ingress_bytes = 0;     /* C2S DATA bytes since last itrace */
static uint64_t  g_itrace_last_tsc = 0;
static char      g_step_ctl[256] = {0};   /* --step-ctl path: trigger step on demand */

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

/* ----------------------------- 4-timestamp PROBE --------------------- */
/*
 * This relay actively probes its next-hop segment with the classic 4-timestamp
 * exchange (no clock sync needed): PROBE carries t1 (our tsc); the next hop
 * stamps t2 on receive, t3 on echo, and returns t1 + (t3-t2 as microseconds in
 * ITS clock); we take t4 on receive and compute
 *   RTT_us = (t4 - t1)/our_tsc_us  -  echo_delay_us.
 * The probe traverses our egress shaper (so it sees the emulated segment delay
 * and any standing queue) but is exempt from random loss. RTprop = min RTT
 * (propagation); RttRecent - RTprop = queueing delay on the segment.
 */
#define PROBE_BOOT_INTERVAL_US 10000        /* before RTprop is known */
#define PROBE_RTPROP_WIN_US    2000000      /* refresh the RTprop floor every 2s */
static uint64_t g_seg_rtprop_us = UINT64_MAX;
static uint64_t g_seg_rtt_us    = 0;        /* EWMA recent RTT (for logging)        */
static uint64_t g_seg_rtprop_stamp = 0;     /* tsc of last RTprop refresh           */
static uint64_t g_probe_last_tsc = 0;
static uint64_t g_probe_count = 0;
/* Windowed-MIN RTT = the STANDING (persistent) queue, CoDel-style. Probe-RTT
 * jitter (netem timer quantization on the VMs swings a "5ms" delay 4-9ms) and
 * transient BBR ProbeBW spikes ride ABOVE this; only a queue that never drains
 * within the window lifts the min. The phase classifier reads this, not the
 * jittery EWMA, so a clean-but-noisy segment reads qdelay~0 instead of flapping. */
#define SEG_WMIN_WINDOW_US 200000           /* 200ms standing-queue window          */
static uint64_t g_seg_rtt_wmin   = UINT64_MAX;  /* published min over last window   */
static uint64_t g_rtt_wmin_cur   = UINT64_MAX;  /* min accumulator, current window  */
static uint64_t g_rtt_wmin_stamp = 0;           /* current window start (tsc)       */

/* Segment-phase classifier state (BBR-native RTT-vs-bandwidth diagram). The
 * thresholds are DIMENSIONLESS fractions of the measured RTprop -- no absolute
 * ms/Mbps magic numbers. RELAX when the segment RTT sits at its propagation
 * floor (empty pipe); CONGESTED when RTT is inflated AND my forwarded rate has
 * plateaued (I push more but deliver no more = hitting the bottleneck, it's
 * mine); NEUTRAL otherwise. Only a small probe-jitter floor stays absolute. */
#define SEG_RELAX_NUM    1   /* qdelay <= RTprop * 1/8  -> pipe empty  -> RELAX     */
#define SEG_RELAX_DEN    8
#define SEG_CONG_NUM     1   /* qdelay >= RTprop * 1/4  -> inflated    -> CONGESTED */
#define SEG_CONG_DEN     4
#define SEG_QD_JITTER_US 1500                  /* probe-jitter noise floor for RELAX */
#define SEG_BW_GROW_NUM  1   /* fwd rate grew > 1/8 since last tick = still climbing */
#define SEG_BW_GROW_DEN  8   /* (so NOT plateaued -> not self-induced CONGESTED yet) */
#define SEG_BW_FLOOR_BPS ((1ull*1000*1000)/8)  /* <1Mbit fwd = no load (noise gate)  */
enum seg_phase { SEG_PH_RELAX = 0, SEG_PH_NEUTRAL = 1, SEG_PH_CONGESTED = 2 };
static int      g_bw_saturated = 0;  /* my forwarded rate has plateaued (set in detect) */
static uint64_t g_fwd_bps      = 0;  /* aggregate rate I forward into the segment        */
static uint64_t g_congest_hold_until = 0; /* CNP keeps firing until this tsc (hysteresis) */

static inline int shaper_enabled(void) {
    return g_cfg.egress_rate_bps || g_cfg.egress_delay_tsc || g_cfg.egress_loss_ppm;
}

/*
 * Congestion backlog = FIFO bytes beyond the in-flight propagation BDP
 * (rate * delay). A big propagation delay fills the FIFO with ~BDP bytes that
 * are NOT congestion (they're "on the wire"); only the excess above BDP is a
 * real standing queue. This is what separates "big RTT" from "congested" so
 * the classifier doesn't false-positive on a long-haul-but-uncongested segment.
 */
static inline uint64_t cong_backlog(void) {
    /* A standing queue only forms when a rate limit is in effect; without one
     * the FIFO holds only in-flight (propagation) bytes, which are NOT
     * congestion. So no rate limit => cong 0 (a long-haul-but-uncongested
     * segment must not read as congested). */
    if (!g_cfg.egress_rate_bps) return 0;
    uint64_t bdp = (g_cfg.egress_rate_bps * g_cfg.egress_delay_ms) / 1000;
    return (g_sq_bytes > bdp) ? (g_sq_bytes - bdp) : 0;
}

/* Probe-measured queueing delay = recent segment RTT above its propagation
 * floor (RTprop). Unlike cong_backlog (which reads this relay's OWN egress
 * FIFO), this detects congestion ANYWHERE on the segment -- including a real
 * bottleneck the relay does NOT own (the realistic deployment: the relay
 * forwards into a congested link rather than imposing the limit itself). Needs
 * the active 4-timestamp probe (--probe-next). */
static inline uint64_t probe_qdelay_us(void) {
    if (g_seg_rtprop_us == UINT64_MAX) return 0;
    /* Standing queue = (windowed-min RTT) - RTprop. Take the min of the published
     * window and the in-progress accumulator: responsive DOWNWARD (a fresh low
     * sample releases it at once) but smooth UPWARD (needs a whole window of
     * elevated samples to rise) -> jitter and transient spikes don't register. */
    uint64_t wmin = g_rtt_wmin_cur;
    if (g_seg_rtt_wmin < wmin) wmin = g_seg_rtt_wmin;
    if (wmin == UINT64_MAX || wmin <= g_seg_rtprop_us) return 0;
    return wmin - g_seg_rtprop_us;
}

/* Unified segment phase from the BBR-native RTT-vs-bandwidth diagram (and, when
 * this relay owns the bottleneck, its local egress backlog as ground truth):
 *   RELAX     : RTT at the propagation floor (qdelay ~ 0) -> empty pipe, so any
 *               loss here is random -> tell the sender to ignore it.
 *   CONGESTED : RTT inflated above the floor AND my forwarded rate has plateaued
 *               (deliver no more though I push more) -> I'm loading the bottleneck
 *               -> self-induced -> stay honest + throttle my elephant (CNP).
 *   NEUTRAL   : in between, OR RTT inflated but my rate is NOT saturated (someone
 *               else's congestion) -> stay honest (don't ignore loss) but do not
 *               throttle. The safe default == native loss-responsive BBR.
 * This is the ProbeBW signal per segment; the relax/congest thresholds are
 * fractions of the measured RTprop, so there are no absolute ms/Mbps knobs. */
static inline enum seg_phase seg_phase(void) {
    /* Ground truth when this relay IS the bottleneck owner. */
    if (shaper_enabled() && cong_backlog() > g_cfg.congest_q_bytes) return SEG_PH_CONGESTED;
    /* No congestion sensor for this segment (no active probe, and not locally
     * congested above) -> ABSTAIN with RELAX rather than vetoing. A tail segment
     * we don't measure (e.g. r3 -> server) must not broadcast a "don't ignore
     * loss" vote that the endpoint's barrel rule would treat as congestion; and a
     * known-but-shallow local queue is simply healthy. NEUTRAL is reserved for a
     * PROBING segment in the gray zone (below), where staying honest is right. */
    if (!g_cfg.probe_congest || g_seg_rtprop_us == UINT64_MAX) return SEG_PH_RELAX;
    uint64_t rtp = g_seg_rtprop_us;
    uint64_t qd  = probe_qdelay_us();
    uint64_t relax_th = rtp * SEG_RELAX_NUM / SEG_RELAX_DEN;
    if (relax_th < SEG_QD_JITTER_US) relax_th = SEG_QD_JITTER_US;     /* noise floor */
    uint64_t cong_th = rtp * SEG_CONG_NUM / SEG_CONG_DEN;
    if (cong_th < relax_th + SEG_QD_JITTER_US) cong_th = relax_th + SEG_QD_JITTER_US;
    if (qd <= relax_th) return SEG_PH_RELAX;
    if (qd >= cong_th && g_bw_saturated) return SEG_PH_CONGESTED;
    return SEG_PH_NEUTRAL;
}
/* Back-compat boolean (unused by the new signaling path, kept for clarity). */
static inline int seg_congested(void) { return seg_phase() == SEG_PH_CONGESTED; }

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
static void shaper_enqueue(struct rte_mbuf *m, uint64_t t, int allow_loss) {
    if (allow_loss && g_cfg.egress_loss_ppm) {
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
    if (via_shaper && shaper_enabled()) shaper_enqueue(m, t, 1 /* allow_loss */);
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
static void inject_cnp(struct flow *f, uint64_t t, uint64_t fair) {
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
        /* Cut toward the FAIR SHARE on this bottleneck (fair = aggregate/active),
         * not an absolute rate: keep% = fair/rate, so a 4x-over-fair elephant
         * keeps ~25% while a barely-over-fair flow keeps ~80%. Pulling every
         * above-fair flow down to ~fair drops the aggregate below capacity and
         * drains the standing queue (so mice get through) -- a single mild 50%
         * nudge, scaled against an absolute threshold, did neither. */
        uint64_t rate = f->bytes_per_sec ? f->bytes_per_sec : 1;
        uint64_t keep = fair ? (fair * 100 / rate) : 50;   /* % of window to keep */
        if (keep < 15) keep = 15;                          /* never throttle to ~0 */
        if (keep > 80) keep = 80;                          /* always a real cut    */
        severity = (uint8_t)(100 - keep);
    }
    uint8_t buf[CNP_MAX_LEN];
    int cnp_len = cnp_build(buf, NULL, 0, CNP_SUPPRESS_MS, severity, (uint32_t)fair);
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
    int acn_len = acn_build(buf, NULL, 0, ANTICNP_WINDOW_MS, 0 /* default relax */,
                            ACN_STATE_RELAX, 0, g_cfg.seg_id);
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

/* ----------------------------- broadcast anti-CNP --------------------- */
/*
 * Segment-level state beacon: every period the relay sends ONE anti-CNP toward
 * the upstream gateway with flow_id=0 (broadcast marker), carrying this
 * segment's state (RELAX when healthy, CONGESTED when it is a real bottleneck;
 * with the fair-share rate in mode (b)). It propagates S2C hop-by-hop to the
 * client-shim, which fans it out to EVERY local flow. This puts the decision
 * at the segment's ground-truth owner and gives every flow/gateway the same
 * view (one packet per gateway per period, no per-flow loss detection).
 */
static void inject_anticnp_broadcast(uint64_t t, uint32_t window_ms,
                                     uint8_t seg_state, uint32_t rate_bps) {
    if (!g_prev_known) return;
    uint8_t buf[ACN_MAX_LEN];
    int acn_len = acn_build(buf, NULL, 0, window_ms, 0, seg_state, rate_bps, g_cfg.seg_id);
    if (acn_len < 0) return;

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
    th->type        = TUNNEL_TYPE_ANTICNP;
    th->direction   = TUNNEL_DIR_S2C;
    th->flow_id     = 0;                         /* 0 = broadcast to all flows */
    th->payload_len = rte_cpu_to_be_16((uint16_t)acn_len);
    memcpy(body, buf, acn_len);

    uint16_t udp_len = sizeof(*udp) + sizeof(*th) + acn_len;
    uint16_t ip_len  = sizeof(*ip) + udp_len;
    rte_ether_addr_copy(&g_relay_mac, &eth->src_addr);
    memcpy(eth->dst_addr.addr_bytes, g_prev_mac, 6);
    eth->ether_type     = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    ip->version_ihl     = 0x45;
    ip->type_of_service = 0;
    ip->total_length    = rte_cpu_to_be_16(ip_len);
    ip->packet_id       = 0;
    ip->fragment_offset = 0;
    ip->time_to_live    = 64;
    ip->next_proto_id   = IPPROTO_UDP;
    ip->src_addr        = rte_cpu_to_be_32(g_cfg.relay_ip);
    ip->dst_addr        = g_prev_ip;
    udp->src_port  = rte_cpu_to_be_16(g_cfg.relay_port);
    udp->dst_port  = g_prev_port;
    udp->dgram_len = rte_cpu_to_be_16(udp_len);
    uint16_t total = sizeof(*eth) + ip_len;
    m->data_len = total; m->pkt_len = total;
    fix_l3l4(ip, udp);
    tx_enqueue(m);
    g_bcast_last_tsc = t;
    g_bcast_count++;
}

/* ----------------------------- PROBE send / echo / RTT ---------------- */
/* Send a PROBE to the next-hop, carrying t1 (our tsc) in the payload. Goes
 * through the egress shaper (sees the emulated segment delay+queue) but is
 * exempt from random loss. */
static void inject_probe(uint64_t t) {
    if (!g_cfg.next_hop_ip) return;
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
    th->type        = TUNNEL_TYPE_PROBE;
    th->direction   = TUNNEL_DIR_C2S;
    th->payload_len = rte_cpu_to_be_16(8);
    memcpy(body, &t, 8);                       /* t1 (our tsc, verbatim) */

    uint16_t udp_len = sizeof(*udp) + sizeof(*th) + 8;
    uint16_t ip_len  = sizeof(*ip) + udp_len;
    rte_ether_addr_copy(&g_relay_mac, &eth->src_addr);
    memcpy(eth->dst_addr.addr_bytes,
           g_cfg.have_next_hop_mac ? g_cfg.next_hop_mac : g_gw_mac.addr_bytes, 6);
    eth->ether_type     = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    ip->version_ihl     = 0x45;
    ip->type_of_service = 0;
    ip->total_length    = rte_cpu_to_be_16(ip_len);
    ip->packet_id       = 0;
    ip->fragment_offset = 0;
    ip->time_to_live    = 64;
    ip->next_proto_id   = IPPROTO_UDP;
    ip->src_addr        = rte_cpu_to_be_32(g_cfg.relay_ip);
    ip->dst_addr        = rte_cpu_to_be_32(g_cfg.next_hop_ip);
    udp->src_port  = rte_cpu_to_be_16(g_cfg.relay_port);
    udp->dst_port  = rte_cpu_to_be_16(g_cfg.next_hop_port);
    udp->dgram_len = rte_cpu_to_be_16(udp_len);
    uint16_t total = sizeof(*eth) + ip_len;
    m->data_len = total; m->pkt_len = total;
    fix_l3l4(ip, udp);
    shaper_enqueue(m, t, 0 /* no loss for probes */);
    g_probe_last_tsc = t;
}

/* Handle a received PROBE (echo it back) or PROBE_ECHO (compute segment RTT). */
static void process_probe(struct rte_mbuf *m, struct rte_ether_hdr *eth,
                          struct rte_ipv4_hdr *ip, struct rte_udp_hdr *udp,
                          struct tunnel_header *th, uint64_t t) {
    uint8_t *body = (uint8_t *)(th + 1);
    if (th->type == TUNNEL_TYPE_PROBE) {
        /* We are the next-hop: t2 = recv (t), t3 = now; echo t1 + echo_delay. */
        uint64_t t1; memcpy(&t1, body, 8);
        uint64_t echo_delay_us = (now_tsc() - t) / g_tsc_us;
        th->type        = TUNNEL_TYPE_PROBE_ECHO;
        th->payload_len = rte_cpu_to_be_16(16);
        memcpy(body, &t1, 8);
        memcpy(body + 8, &echo_delay_us, 8);
        /* Send back to the prober (received outer src), unshaped (reverse dir). */
        uint32_t src_ip = ip->src_addr; uint16_t src_port = udp->src_port;
        uint8_t src_mac[6]; memcpy(src_mac, eth->src_addr.addr_bytes, 6);
        uint16_t udp_len = sizeof(*udp) + sizeof(*th) + 16;
        uint16_t ip_len  = sizeof(*ip) + udp_len;
        rte_ether_addr_copy(&g_relay_mac, &eth->src_addr);
        memcpy(eth->dst_addr.addr_bytes, src_mac, 6);
        ip->src_addr = rte_cpu_to_be_32(g_cfg.relay_ip);
        ip->dst_addr = src_ip;
        ip->total_length = rte_cpu_to_be_16(ip_len);
        udp->src_port = rte_cpu_to_be_16(g_cfg.relay_port);
        udp->dst_port = src_port;
        udp->dgram_len = rte_cpu_to_be_16(udp_len);
        uint16_t total = sizeof(*eth) + ip_len;
        m->data_len = total; m->pkt_len = total;
        fix_l3l4(ip, udp);
        tx_enqueue(m);
    } else { /* TUNNEL_TYPE_PROBE_ECHO: we are the prober, t4 = now */
        uint64_t t1, echo_delay_us;
        memcpy(&t1, body, 8); memcpy(&echo_delay_us, body + 8, 8);
        uint64_t rtt_us = (t - t1) / g_tsc_us;
        rtt_us = (rtt_us > echo_delay_us) ? rtt_us - echo_delay_us : 0;
        /* RTprop = propagation floor = running MINIMUM of probe RTT. Update only
         * DOWNWARD: a queue-inflated sample must never raise the floor (the old
         * "re-baseline to the current sample every 2s" poisoned RTprop under
         * sustained congestion -> qdelay collapsed). The segment's propagation is
         * ~static; a production deployment would re-baseline on BBR-ProbeRTT-style
         * periodic drains for route changes, but for these controlled segments the
         * running min (measured before/between bursts) is the true floor. */
        if (rtt_us < g_seg_rtprop_us) { g_seg_rtprop_us = rtt_us; g_seg_rtprop_stamp = t; }
        g_seg_rtt_us = g_seg_rtt_us ? (g_seg_rtt_us * 7 + rtt_us) / 8 : rtt_us;
        /* Maintain the windowed-min RTT (standing queue). Accumulate the min of
         * this window; every SEG_WMIN_WINDOW_US publish it and restart -- so a
         * queue that drains to the floor in any window resets the standing queue
         * to ~0, while a persistent queue keeps every window's min elevated. */
        if (g_rtt_wmin_stamp == 0) g_rtt_wmin_stamp = t;
        if (rtt_us < g_rtt_wmin_cur) g_rtt_wmin_cur = rtt_us;
        if (t - g_rtt_wmin_stamp > (uint64_t)SEG_WMIN_WINDOW_US * g_tsc_us) {
            g_seg_rtt_wmin = g_rtt_wmin_cur;
            g_rtt_wmin_cur = rtt_us;
            g_rtt_wmin_stamp = t;
        }
        g_probe_count++;
        rte_pktmbuf_free(m);
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

    /* Broadcast anti-CNP (flow_id=0) passing upstream: forward to the single
     * prev-hop without touching the flow table, until it reaches the gateway. */
    if (dir == TUNNEL_DIR_S2C && th->type == TUNNEL_TYPE_ANTICNP && flow_id == 0) {
        if (!g_prev_known) { rte_pktmbuf_free(m); return; }
        forward_to(m, eth, ip, udp, g_prev_ip, g_prev_port, g_prev_mac, t, 0);
        return;
    }

    struct flow *f = flow_find(flow_id);
    if (!f) f = flow_create(flow_id, t);
    if (!f) { rte_pktmbuf_free(m); return; }

    flow_account(f, plen, t);

    if (dir == TUNNEL_DIR_C2S) {
        /* Learn the upstream neighbor's outer address (prev-hop = where return
         * traffic and CNP/anti-CNP go). In a chain this is the previous relay;
         * it is a SINGLE neighbor, cached globally for broadcast/return. */
        f->client_ip   = ip->src_addr;        /* network order */
        f->client_port = udp->src_port;       /* network order */
        memcpy(f->client_mac, eth->src_addr.addr_bytes, 6);
        f->have_client = 1;
        g_prev_ip = ip->src_addr; g_prev_port = udp->src_port;
        memcpy(g_prev_mac, eth->src_addr.addr_bytes, 6); g_prev_known = 1;

        if (th->type == TUNNEL_TYPE_DATA) {
            ingress_track(f, th, t);
            g_ingress_bytes += plen;   /* offered rate seen at this relay (itrace) */
        }

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

    /* Aggregate rate I'm forwarding into my downstream segment, and active count. */
    uint64_t fwd_bps = 0; uint32_t nf = 0;
    for (uint32_t i = 0; i < g_active_cnt; i++) {
        struct flow *f = &g_flows[g_active_idx[i]];
        if (!f->used) continue;
        fwd_bps += f->bytes_per_sec; nf++;
    }

    /* BBR-native saturation test feeding seg_phase(): has my forwarded rate
     * plateaued? If it grew appreciably since the last tick I'm still ramping
     * (NOT at the ceiling); if it's flat/falling while the probe RTT is inflated,
     * I can't deliver more = I'm pushing against the bottleneck = self-induced.
     * A small floor gates out trickle traffic (no load to attribute a queue to). */
    static uint64_t prev_fwd_bps = 0;
    int growing = fwd_bps > prev_fwd_bps + prev_fwd_bps * SEG_BW_GROW_NUM / SEG_BW_GROW_DEN;
    g_bw_saturated = (fwd_bps >= SEG_BW_FLOOR_BPS) && !growing;
    g_fwd_bps = fwd_bps;
    prev_fwd_bps = fwd_bps;

    /* CNP fires only when the segment phase is CONGESTED: RTT inflated above the
     * propagation floor AND my rate plateaued (I'm loading the bottleneck), or I
     * locally own a deep egress backlog. RTT rising with my rate still climbing
     * or low (background traffic / a re-route) is NEUTRAL and never fires CNP. */
    /* Hysteresis: a real bottleneck's queue momentarily drains every BBR cycle,
     * which would blip seg_phase back to NEUTRAL and let the elephants re-ramp
     * between CNPs. Latch CONGESTED for CONGEST_HOLD_US past the last detection so
     * CNP fires continuously while the segment is loaded, keeping the aggregate
     * pinned below capacity (the suppression is fully reversible once it lapses). */
    if (g_cfg.cnp_on && seg_phase() == SEG_PH_CONGESTED)
        g_congest_hold_until = t + (uint64_t)CONGEST_HOLD_US * g_tsc_us;

    uint64_t fair = nf ? (fwd_bps / nf) : 0;
    if (g_cfg.cnp_on && fair > 0 && t <= g_congest_hold_until) {
        /* Trim EVERY flow above its fair share (= aggregate / active), not just a
         * single largest -- if two elephants are 5 and 4.9, hitting only the 5
         * lets the 4.9 backfill and the queue never drains. CNP_TOP_K bounds the
         * batch; the K largest above-fair flows are chosen. */
        struct flow *top[CNP_TOP_K];
        int n = 0;
        for (uint32_t i = 0; i < g_active_cnt; i++) {
            struct flow *f = &g_flows[g_active_idx[i]];
            if (!f->used || f->bytes_per_sec <= fair) continue;   /* only above fair share */
            if (n < CNP_TOP_K) {
                top[n++] = f;
            } else {
                int min = 0;
                for (int k = 1; k < CNP_TOP_K; k++)
                    if (top[k]->bytes_per_sec < top[min]->bytes_per_sec) min = k;
                if (f->bytes_per_sec > top[min]->bytes_per_sec) top[min] = f;
            }
        }
        for (int i = 0; i < n; i++) inject_cnp(top[i], t, fair);
    }

    /* anti-CNP is now a segment-level HEALTHY broadcast, driven from main_loop
     * (finer cadence than this 200ms scan); see anticnp_broadcast_tick(). */
}

/* Segment-state beacon tick: every period (adaptive to RTprop) emit ONE
 * broadcast anti-CNP toward the gateway carrying this segment's state.
 *   healthy   -> RELAX     (sender ignores random loss)
 *   congested -> CONGESTED. mode(b) (--cong-rate) attaches the fair-share rate
 *                = egress_rate / active_flows (sender ignores random loss but
 *                caps to its share); mode(a) attaches rate=0 (sender runs
 *                honest, loss-responsive BBR).
 * Ablation --force-random forces RELAX even when congested (no discrimination
 * -> sender ignores the real bottleneck's loss -> should overrun and hurt). */
static void anticnp_broadcast_tick(uint64_t t) {
    if (!g_cfg.anticnp_on || !g_prev_known) return;
    uint64_t period_us = (g_seg_rtprop_us != UINT64_MAX) ? g_seg_rtprop_us : 50000;
    if (period_us < 20000)  period_us = 20000;   /* >=20ms */
    if (period_us > 200000) period_us = 200000;  /* <=200ms */
    if (t - g_bcast_last_tsc < period_us * g_tsc_us) return;

    /* The beacon is binary on the wire (RELAX vs honest); the sender ignores loss
     * only when EVERY fresh segment says RELAX (barrel rule). So NEUTRAL and
     * CONGESTED both map to the honest (ACN_STATE_CONGESTED) "don't ignore loss"
     * vote; only RELAX (RTT at the floor) lets the sender ignore loss. A
     * fair-share rate cap (mode b) is attached only on a true CONGESTED phase. */
    enum seg_phase ph = seg_phase();
    uint8_t  seg_state = ACN_STATE_RELAX;
    uint32_t rate_bps  = 0;
    if (ph != SEG_PH_RELAX && !g_cfg.force_random) {
        seg_state = ACN_STATE_CONGESTED;
        if (g_cfg.cong_rate && ph == SEG_PH_CONGESTED) {  /* mode(b): fair-share cap */
            uint32_t n = g_active_cnt ? g_active_cnt : 1;
            rate_bps = (uint32_t)(g_cfg.egress_rate_bps / n);
        }
    }
    inject_anticnp_broadcast(t, (uint32_t)(3 * period_us / 1000), seg_state, rate_bps);

    static uint64_t last_log = 0;
    if (t - last_log > g_tsc_hz) {       /* at most ~1 beacon log/sec */
        const char *phn = ph == SEG_PH_RELAX ? "RELAX"
                        : ph == SEG_PH_CONGESTED ? "CONGESTED" : "NEUTRAL";
        printf("[relay] seg%u beacon %s cong=%" PRIu64 "B q=%" PRIu64 "B qdelay=%" PRIu64
               "us rtprop=%" PRIu64 "us fwd=%.1fMbit sat=%d n=%u rate=%.1fMbit\n",
               g_cfg.seg_id, phn, cong_backlog(), g_sq_bytes, probe_qdelay_us(),
               (g_seg_rtprop_us == UINT64_MAX) ? 0 : g_seg_rtprop_us,
               (double)(g_fwd_bps * 8) / 1e6, g_bw_saturated, g_active_cnt,
               (double)((uint64_t)rate_bps * 8) / 1e6);
        last_log = t;
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
    enum seg_phase ph = seg_phase();
    const char *label = (ph == SEG_PH_CONGESTED) ? "CONGESTED"
                      : (ph == SEG_PH_NEUTRAL)   ? "NEUTRAL"
                      : (loss > 0)               ? "LOSSY" : "HEALTHY";
    uint64_t rtprop = (g_seg_rtprop_us == UINT64_MAX) ? 0 : g_seg_rtprop_us;
    printf("[relay] seg%u %s flows=%u big=%u total=%.1fMbit cong=%" PRIu64
           "B q=%" PRIu64 "B loss=%" PRIu64 " drops=%" PRIu64 "/%" PRIu64
           " probe rtprop=%" PRIu64 "us rtt=%" PRIu64 "us qdelay=%" PRIu64 "us n=%" PRIu64 "\n",
           g_cfg.seg_id, label, g_active_cnt, big, (double)(total * 8) / 1e6,
           cong_backlog(), g_sq_bytes, loss, g_egress_loss_drops, g_egress_full_drops,
           rtprop, g_seg_rtt_us, probe_qdelay_us(), g_probe_count);
}

/* Control-loop-latency experiment: a one-shot scheduled bottleneck step plus a
 * fine-grained ingress-rate trace, both stamped in relay-local ms. The step
 * models a sudden congestion onset; the sender's reaction (offered rate falling
 * to the new bottleneck) is then read off the itrace series against the APPLY
 * timestamp -- entirely in this relay's clock, so no cross-host sync is needed.
 * overlay-on (CNP closes the loop over sender<->relay) reacts in ~segA RTT;
 * overlay-off (end-to-end BBR) reacts in ~full RTT, growing with downstream
 * delay -- that gap, swept over downstream delay, is the loop-shortening proof. */
static void step_and_trace_tick(uint64_t t) {
    /* timer-driven step (boot-relative) */
    if (g_cfg.step_at_sec && !g_step_done &&
        (t - g_boot_tsc) >= (uint64_t)g_cfg.step_at_sec * g_tsc_hz) {
        if (g_cfg.step_rate_bps >= 0) g_cfg.egress_rate_bps = (uint64_t)g_cfg.step_rate_bps;
        if (g_cfg.step_loss_ppm >= 0) g_cfg.egress_loss_ppm = (uint32_t)g_cfg.step_loss_ppm;
        g_step_done = 1;
        printf("[ctl] tms=%" PRIu64 " APPLY rate=%.1fMbit loss=%.2f%%\n",
               t / g_tsc_ms, (double)(g_cfg.egress_rate_bps * 8) / 1e6,
               (double)g_cfg.egress_loss_ppm / 10000.0);
    }
    /* control-file step (on demand): the harness writes the new rate (Mbps) once
     * the flow is steady, so the step is timed to actual load rather than boot.
     * The apply time is stamped here in relay-local ms regardless of the trigger. */
    if (g_step_ctl[0] && !g_step_done) {
        static uint64_t last_chk = 0;
        if (t - last_chk >= g_tsc_hz / 5) {          /* poll ~5x/sec */
            last_chk = t;
            FILE *fp = fopen(g_step_ctl, "r");
            if (fp) {
                int rate = -1;
                if (fscanf(fp, "%d", &rate) == 1 && rate >= 0) {
                    g_cfg.egress_rate_bps = ((uint64_t)rate * 1000 * 1000) / 8;
                    g_step_done = 1;
                    printf("[ctl] tms=%" PRIu64 " APPLY rate=%.1fMbit loss=%.2f%% (ctl)\n",
                           t / g_tsc_ms, (double)(g_cfg.egress_rate_bps * 8) / 1e6,
                           (double)g_cfg.egress_loss_ppm / 10000.0);
                }
                fclose(fp);
            }
        }
    }
    if (g_cfg.ingress_trace) {
        uint64_t win = t - g_itrace_last_tsc;
        if (win >= g_tsc_hz / 10) {                  /* ~100ms sample */
            double mbit = (double)g_ingress_bytes * 8.0 * g_tsc_hz / (double)win / 1e6;
            printf("[itrace] tms=%" PRIu64 " in=%.2fMbit cong=%" PRIu64 "B\n",
                   t / g_tsc_ms, mbit, cong_backlog());
            g_ingress_bytes = 0;
            g_itrace_last_tsc = t;
        }
    }
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

    g_boot_tsc = now_tsc();
    g_itrace_last_tsc = g_boot_tsc;

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
                    if (th->type == TUNNEL_TYPE_PROBE ||
                        th->type == TUNNEL_TYPE_PROBE_ECHO) {
                        process_probe(m, eth, ip, udp, th, t);
                    } else {
                        process_tunnel(m, eth, ip, udp, th, t);
                    }
                    continue;
                }
            }
            rte_pktmbuf_free(m);   /* not ours */
        }

        /* Active 4-timestamp probe of the next-hop segment, cadence adaptive to
         * the measured RTprop (probe ~RTprop/4, clamped 1..50ms). */
        if (g_cfg.probe_next && g_cfg.next_hop_ip) {
            uint64_t interval_us = PROBE_BOOT_INTERVAL_US;
            if (g_seg_rtprop_us != UINT64_MAX) {
                interval_us = g_seg_rtprop_us / 4;
                if (interval_us < 1000)  interval_us = 1000;   /* >=1ms  */
                if (interval_us > 50000) interval_us = 50000;  /* <=50ms */
            }
            if (t - g_probe_last_tsc >= interval_us * g_tsc_us) inject_probe(t);
        }

        detect_and_inject(t);        /* updates bandwidth saturation, fires CNP   */
        anticnp_broadcast_tick(t);   /* segment-state beacon (reads saturation)   */
        shaper_drain(t);       /* release egress-shaped packets */
        reap_idle(t);
        print_stats(t);
        step_and_trace_tick(t);   /* scheduled bottleneck step + ingress trace */
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
        else if (!strcmp(argv[i], "--probe-next"))
            g_cfg.probe_next = 1;
        else if (!strcmp(argv[i], "--probe-congest"))
            g_cfg.probe_congest = 1;
        else if (!strcmp(argv[i], "--congest-qdelay-ms") && i + 1 < argc)
            g_cfg.congest_qdelay_us = (uint32_t)(atof(argv[++i]) * 1000.0);
        else if (!strcmp(argv[i], "--congest-min-mbps") && i + 1 < argc)
            g_cfg.congest_min_bps = ((uint64_t)atoi(argv[++i]) * 1000 * 1000) / 8;
        /* signal toggles for A/B/ablation */
        else if (!strcmp(argv[i], "--no-cnp"))      g_cfg.cnp_on = 0;
        else if (!strcmp(argv[i], "--no-anticnp"))  g_cfg.anticnp_on = 0;
        else if (!strcmp(argv[i], "--signals-off")) { g_cfg.cnp_on = 0; g_cfg.anticnp_on = 0; }
        else if (!strcmp(argv[i], "--force-random")) g_cfg.force_random = 1;
        /* mode(b): CONGESTED beacon carries the per-flow fair-share rate cap */
        else if (!strcmp(argv[i], "--cong-rate"))   g_cfg.cong_rate = 1;
        /* control-loop-latency experiment: scheduled step + ingress trace */
        else if (!strcmp(argv[i], "--step-at-sec") && i + 1 < argc)
            g_cfg.step_at_sec = (uint32_t)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--step-rate-mbps") && i + 1 < argc)
            g_cfg.step_rate_bps = ((int64_t)atoi(argv[++i]) * 1000 * 1000) / 8;
        else if (!strcmp(argv[i], "--step-loss-pct") && i + 1 < argc)
            g_cfg.step_loss_ppm = (int64_t)(atof(argv[++i]) * 10000.0);
        else if (!strcmp(argv[i], "--ingress-trace")) g_cfg.ingress_trace = 1;
        else if (!strcmp(argv[i], "--step-ctl") && i + 1 < argc) {
            strncpy(g_step_ctl, argv[++i], sizeof(g_step_ctl) - 1);
            g_step_ctl[sizeof(g_step_ctl) - 1] = '\0';
        }
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
