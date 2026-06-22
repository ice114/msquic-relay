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

#include "tunnel_protocol.h"

/* ----------------------------- tunables ------------------------------- */
#define MAX_PKT_BURST        32
#define MEMPOOL_CACHE_SIZE   256
#define RX_RING_SIZE         1024
#define TX_RING_SIZE         1024
#define NUM_MBUFS            8191
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

/* ----------------------------- config --------------------------------- */
struct relay_cfg {
    uint32_t relay_ip;        /* host order */
    uint16_t relay_port;      /* host order */
    uint64_t threshold_bps;   /* single-flow elephant threshold, bytes/sec */
    uint8_t  cid_len;         /* client local CID length (msquic CidTotalLength) */
};
static struct relay_cfg g_cfg = {
    .relay_ip      = 0,                 /* set in main (default 10.103.238.111) */
    .relay_port    = 4433,
    .threshold_bps = (10ull * 1000 * 1000) / 8,  /* 10 Mbit/s */
    .cid_len       = CLIENT_CID_LEN,             /* 9 (load balancing off) */
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
static uint64_t                   g_tsc_hz = 0, g_tsc_us = 1;

static uint64_t now_tsc(void) { return rte_rdtsc(); }

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

/* ----------------------------- forwarding ----------------------------- */
/*
 * Forward a tunnel datagram in place: keep the tunnel header + inner payload,
 * rewrite only the outer L2/L3/L4 toward `dst_ip:dst_port` via `dst_mac`.
 */
static void forward_to(struct rte_mbuf *m, struct rte_ether_hdr *eth,
                       struct rte_ipv4_hdr *ip, struct rte_udp_hdr *udp,
                       uint32_t dst_ip_net, uint16_t dst_port_net,
                       const uint8_t *dst_mac) {
    rte_ether_addr_copy(&g_relay_mac, &eth->src_addr);
    memcpy(eth->dst_addr.addr_bytes, dst_mac, 6);

    ip->src_addr = rte_cpu_to_be_32(g_cfg.relay_ip);
    ip->dst_addr = dst_ip_net;            /* already network order */

    udp->src_port = rte_cpu_to_be_16(g_cfg.relay_port);
    udp->dst_port = dst_port_net;         /* already network order */

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

    struct rte_mbuf *m = rte_pktmbuf_alloc(g_pool);
    if (!m) return;

    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct rte_ipv4_hdr  *ip  = (struct rte_ipv4_hdr *)(eth + 1);
    struct rte_udp_hdr   *udp = (struct rte_udp_hdr *)(ip + 1);
    struct tunnel_header *th  = (struct tunnel_header *)(udp + 1);
    uint8_t              *cnp = (uint8_t *)(th + 1);

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
    int cnp_len = cnp_build(cnp, NULL, 0, CNP_SUPPRESS_MS, severity);
    if (cnp_len < 0) { rte_pktmbuf_free(m); return; }

    /* tunnel header: tell the client shim "deliver this CNP to flow X". */
    memset(th, 0, sizeof(*th));
    th->magic       = rte_cpu_to_be_32(TUNNEL_MAGIC);
    th->version     = TUNNEL_VERSION;
    th->type        = TUNNEL_TYPE_CNP;
    th->direction   = TUNNEL_DIR_S2C;
    th->flow_id     = rte_cpu_to_be_32(f->flow_id);
    th->payload_len = rte_cpu_to_be_16((uint16_t)cnp_len);

    uint16_t udp_len = sizeof(*udp) + sizeof(*th) + cnp_len;
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
    ip->dst_addr        = f->client_ip;          /* network order */

    udp->src_port  = rte_cpu_to_be_16(g_cfg.relay_port);
    udp->dst_port  = f->client_port;             /* network order */
    udp->dgram_len = rte_cpu_to_be_16(udp_len);

    uint16_t total = sizeof(*eth) + ip_len;
    m->data_len = total;
    m->pkt_len  = total;
    fix_l3l4(ip, udp);

    tx_enqueue(m);
    f->last_cnp_tsc = t;
    f->cnp_count++;

    static uint64_t last_log = 0;
    if (t - last_log > g_tsc_hz) {       /* at most ~1 log line/sec */
        printf("[relay] CNP -> flow 0x%08x bps=%.1fMbit cid_len=%u count=%u\n",
               f->flow_id, (double)(f->bytes_per_sec * 8) / 1e6,
               f->client_cid_len, f->cnp_count);
        last_log = t;
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
    uint8_t *inner    = (uint8_t *)(th + 1);

    struct flow *f = flow_find(flow_id);
    if (!f) f = flow_create(flow_id, t);
    if (!f) { rte_pktmbuf_free(m); return; }

    flow_account(f, plen, t);

    if (dir == TUNNEL_DIR_C2S) {
        /* Learn the client's outer address (for return + CNP). */
        f->client_ip   = ip->src_addr;        /* network order */
        f->client_port = udp->src_port;       /* network order */
        memcpy(f->client_mac, eth->src_addr.addr_bytes, 6);
        f->have_client = 1;
        /* Forward to the server shim (tunnel header carries its addr). */
        forward_to(m, eth, ip, udp,
                   th->orig_dst_ip, th->orig_dst_port, g_gw_mac.addr_bytes);
    } else { /* TUNNEL_DIR_S2C */
        //
        // CNP is addressed by tunnel flow_id, not by QUIC CID (clients use a
        // zero-length source CID), so no inner-header CID sniffing is needed.
        //
        (void)inner;
        if (!f->have_client) { rte_pktmbuf_free(m); return; }
        /* Forward back to the client. */
        forward_to(m, eth, ip, udp,
                   f->client_ip, f->client_port, f->client_mac);
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

/* ----------------------------- detection ------------------------------ */
static void detect_and_inject(uint64_t t) {
    static uint64_t last = 0;
    if (t - last < (uint64_t)DETECT_INTERVAL_US * g_tsc_us) return;
    last = t;

    /* Collect flows over the elephant threshold, keep the Top-K largest. */
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
    uint64_t total = 0; uint32_t big = 0;
    for (uint32_t i = 0; i < g_active_cnt; i++) {
        struct flow *f = &g_flows[g_active_idx[i]];
        if (!f->used) continue;
        total += f->bytes_per_sec;
        if (f->bytes_per_sec > g_cfg.threshold_bps) big++;
    }
    printf("[relay] flows=%u big=%u total=%.1fMbit\n",
           g_active_cnt, big, (double)(total * 8) / 1e6);
}

/* ----------------------------- main loop ------------------------------ */
static int main_loop(__rte_unused void *arg) {
    printf("[relay] loop on lcore %u, relay=%u.%u.%u.%u:%u thresh=%.1fMbit\n",
           rte_lcore_id(),
           (g_cfg.relay_ip >> 24) & 0xFF, (g_cfg.relay_ip >> 16) & 0xFF,
           (g_cfg.relay_ip >> 8) & 0xFF, g_cfg.relay_ip & 0xFF, g_cfg.relay_port,
           (double)(g_cfg.threshold_bps * 8) / 1e6);

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
    }

    g_tsc_hz = rte_get_tsc_hz();
    g_tsc_us = g_tsc_hz / 1000000; if (!g_tsc_us) g_tsc_us = 1;

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
