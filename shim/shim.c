/*
 * shim.c — 端侧网关 (端 side gateway) for the CNP relay experiment.
 *
 * A small, portable (macOS + Linux) UDP proxy that runs ON THE SAME HOST as an
 * unmodified-but-CNP-patched msquic endpoint. It tunnels the endpoint's QUIC
 * traffic through the DPDK relay so the relay can observe flows and inject
 * Congestion Notification Packets — without touching msquic's datapath.
 *
 *   ── client host (e.g. the Mac) ──            ── server host (10.29.75.103) ──
 *   msquic client                                msquic server (127.0.0.1:4444)
 *     | target 127.0.0.1:5000                       ^ 127.0.0.1:4444
 *     v                                             | per-flow local socket
 *   shim --role client                            shim --role server
 *     sockA  127.0.0.1:5000  (faces msquic)          local_fd (faces msquic)
 *     sockB  ephemeral       (faces relay) ---.   .--- sockB bind (faces relay)
 *                                              v   |
 *                                      relay 10.103.238.111:4433
 *
 * Forward (upload): msquic client -> sockA -> [TUNL|QUIC] -> relay -> server
 * shim sockB -> local_fd -> msquic server. Return path is the mirror. When the
 * relay decides the client is an elephant flow it sends a TUNL(type=CNP) packet
 * back to the client shim, which strips the header and delivers the inner
 * "CNP1" bytes to the local msquic from sockA — msquic does not check the CNP
 * source address, so this just works and no IP spoofing is needed.
 *
 * Build:  cc -O2 -I../include -o shim shim.c
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <poll.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "tunnel_protocol.h"

/* ----------------------------------------------------------------------- */
/* Config                                                                  */
/* ----------------------------------------------------------------------- */

enum role { ROLE_CLIENT, ROLE_SERVER };

#define MAX_FLOWS     256
#define BUF_SIZE      65535
#define FLOW_IDLE_SEC 120

struct config {
    enum role role;
    struct sockaddr_in listen_addr; /* client: sockA bind (msquic targets this) */
    struct sockaddr_in bind_addr;   /* server: sockB bind (faces relay)         */
    struct sockaddr_in relay_addr;  /* both: where tunnel packets go            */
    struct sockaddr_in peer_addr;   /* client: server-shim addr (tunnel orig_dst)*/
    struct sockaddr_in msquic_addr; /* server: local msquic server addr         */
    int verbose;
};

/* ----------------------------------------------------------------------- */
/* Flow table                                                              */
/* ----------------------------------------------------------------------- */

struct flow {
    int                used;
    uint32_t           flow_id;          /* host order */
    struct sockaddr_in msquic_addr;      /* client: msquic ephemeral src;
                                            server: local msquic server addr  */
    int                local_fd;         /* server: per-flow socket to msquic;
                                            client: -1 (uses sockA)           */
    /* identity to stamp on outgoing tunnel headers (network order) */
    uint32_t           orig_src_ip, orig_dst_ip;
    uint16_t           orig_src_port, orig_dst_port;
    time_t             last_seen;
};

static struct flow g_flows[MAX_FLOWS];

static struct flow *flow_by_id(uint32_t flow_id) {
    for (int i = 0; i < MAX_FLOWS; i++)
        if (g_flows[i].used && g_flows[i].flow_id == flow_id)
            return &g_flows[i];
    return NULL;
}

static struct flow *flow_by_msquic(const struct sockaddr_in *a) {
    for (int i = 0; i < MAX_FLOWS; i++)
        if (g_flows[i].used &&
            g_flows[i].msquic_addr.sin_addr.s_addr == a->sin_addr.s_addr &&
            g_flows[i].msquic_addr.sin_port == a->sin_port)
            return &g_flows[i];
    return NULL;
}

static struct flow *flow_alloc(void) {
    for (int i = 0; i < MAX_FLOWS; i++)
        if (!g_flows[i].used) {
            memset(&g_flows[i], 0, sizeof(g_flows[i]));
            g_flows[i].used = 1;
            g_flows[i].local_fd = -1;
            return &g_flows[i];
        }
    return NULL;
}

/* ----------------------------------------------------------------------- */
/* Helpers                                                                 */
/* ----------------------------------------------------------------------- */

static void die(const char *msg) { perror(msg); exit(1); }

/* Parse "ip:port" into a sockaddr_in. Returns 0 on success. */
static int parse_addr(const char *s, struct sockaddr_in *out) {
    char tmp[128];
    strncpy(tmp, s, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = 0;
    char *colon = strrchr(tmp, ':');
    if (!colon) return -1;
    *colon = 0;
    memset(out, 0, sizeof(*out));
    out->sin_family = AF_INET;
    if (inet_pton(AF_INET, tmp, &out->sin_addr) != 1) return -1;
    out->sin_port = htons((uint16_t)atoi(colon + 1));
    return 0;
}

static const char *astr(const struct sockaddr_in *a, char *buf, size_t n) {
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &a->sin_addr, ip, sizeof(ip));
    snprintf(buf, n, "%s:%u", ip, ntohs(a->sin_port));
    return buf;
}

static int udp_socket_bound(const struct sockaddr_in *addr) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) die("socket");
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (bind(fd, (struct sockaddr *)addr, sizeof(*addr)) < 0) die("bind");
    return fd;
}

/* ----------------------------------------------------------------------- */
/* Tunnel encap / decap                                                    */
/* ----------------------------------------------------------------------- */

/*
 * Prepend a tunnel header to `payload` (len bytes) in `out`. Returns total
 * length (TUNNEL_HDR_LEN + len). Caller guarantees out has room.
 */
static int tunnel_encap(uint8_t *out, const struct flow *f, uint8_t type,
                        uint8_t dir, const uint8_t *payload, int len) {
    struct tunnel_header *h = (struct tunnel_header *)out;
    memset(h, 0, sizeof(*h));
    h->magic         = htonl(TUNNEL_MAGIC);
    h->version       = TUNNEL_VERSION;
    h->type          = type;
    h->direction     = dir;
    h->flow_id       = htonl(f->flow_id);
    h->payload_len   = htons((uint16_t)len);
    h->orig_src_ip   = f->orig_src_ip;
    h->orig_dst_ip   = f->orig_dst_ip;
    h->orig_src_port = f->orig_src_port;
    h->orig_dst_port = f->orig_dst_port;
    memcpy(out + TUNNEL_HDR_LEN, payload, len);
    return TUNNEL_HDR_LEN + len;
}

/* ----------------------------------------------------------------------- */
/* Client mode                                                             */
/* ----------------------------------------------------------------------- */

static void run_client(struct config *cfg) {
    char b1[64], b2[64], b3[64];
    int sockA = udp_socket_bound(&cfg->listen_addr);   /* faces msquic */
    struct sockaddr_in any = { .sin_family = AF_INET,
                               .sin_addr.s_addr = htonl(INADDR_ANY), .sin_port = 0 };
    int sockB = udp_socket_bound(&any);                /* faces relay  */

    fprintf(stderr,
        "[shim/client] msquic-facing %s | relay %s | server-shim %s\n",
        astr(&cfg->listen_addr, b1, 64),
        astr(&cfg->relay_addr, b2, 64),
        astr(&cfg->peer_addr, b3, 64));

    uint8_t in[BUF_SIZE], out[BUF_SIZE];
    struct pollfd pfds[2] = {
        { .fd = sockA, .events = POLLIN },
        { .fd = sockB, .events = POLLIN },
    };

    for (;;) {
        if (poll(pfds, 2, -1) < 0) {
            if (errno == EINTR) continue;
            die("poll");
        }

        /* msquic -> relay (forward, DIR_C2S) */
        if (pfds[0].revents & POLLIN) {
            struct sockaddr_in src;
            socklen_t sl = sizeof(src);
            ssize_t n = recvfrom(sockA, in, sizeof(in), 0,
                                 (struct sockaddr *)&src, &sl);
            if (n > 0) {
                struct flow *f = flow_by_msquic(&src);
                if (!f) {
                    f = flow_alloc();
                    if (f) {
                        f->msquic_addr   = src;
                        f->orig_src_ip   = src.sin_addr.s_addr;
                        f->orig_src_port = src.sin_port;
                        f->orig_dst_ip   = cfg->peer_addr.sin_addr.s_addr;
                        f->orig_dst_port = cfg->peer_addr.sin_port;
                        f->flow_id = tunnel_flow_id(
                            ntohl(src.sin_addr.s_addr), ntohs(src.sin_port),
                            ntohl(cfg->peer_addr.sin_addr.s_addr),
                            ntohs(cfg->peer_addr.sin_port));
                        if (cfg->verbose)
                            fprintf(stderr, "[shim/client] new flow 0x%08x from %s\n",
                                    f->flow_id, astr(&src, b1, 64));
                    }
                }
                if (f) {
                    f->last_seen = time(NULL);
                    int olen = tunnel_encap(out, f, TUNNEL_TYPE_DATA,
                                            TUNNEL_DIR_C2S, in, (int)n);
                    sendto(sockB, out, olen, 0,
                           (struct sockaddr *)&cfg->relay_addr,
                           sizeof(cfg->relay_addr));
                }
            }
        }

        /* relay -> msquic (return DATA, or relay-injected CNP) */
        if (pfds[1].revents & POLLIN) {
            ssize_t n = recvfrom(sockB, in, sizeof(in), 0, NULL, NULL);
            if (n >= TUNNEL_HDR_LEN) {
                struct tunnel_header *h = (struct tunnel_header *)in;
                if (tunnel_is(h, htonl(TUNNEL_MAGIC))) {
                    uint32_t fid = ntohl(h->flow_id);
                    int plen = ntohs(h->payload_len);
                    uint8_t *payload = in + TUNNEL_HDR_LEN;
                    if (plen > (int)n - TUNNEL_HDR_LEN)
                        plen = (int)n - TUNNEL_HDR_LEN;
                    struct flow *f = flow_by_id(fid);
                    if (f && plen > 0) {
                        f->last_seen = time(NULL);
                        /* DATA and CNP are both just delivered verbatim to the
                         * local msquic from the listen address. */
                        sendto(sockA, payload, plen, 0,
                               (struct sockaddr *)&f->msquic_addr,
                               sizeof(f->msquic_addr));
                        if (cfg->verbose && h->type == TUNNEL_TYPE_CNP)
                            fprintf(stderr, "[shim/client] delivered CNP (%d B) "
                                    "to msquic flow 0x%08x\n", plen, fid);
                    }
                }
            }
        }
    }
}

/* ----------------------------------------------------------------------- */
/* Server mode                                                             */
/* ----------------------------------------------------------------------- */

static void run_server(struct config *cfg) {
    char b1[64], b2[64];
    int sockB = udp_socket_bound(&cfg->bind_addr);     /* faces relay */

    fprintf(stderr, "[shim/server] relay-facing %s | local msquic %s\n",
            astr(&cfg->bind_addr, b1, 64), astr(&cfg->msquic_addr, b2, 64));

    uint8_t in[BUF_SIZE], out[BUF_SIZE];

    for (;;) {
        /* Rebuild poll set: sockB plus each flow's local msquic-facing fd. */
        struct pollfd pfds[1 + MAX_FLOWS];
        struct flow  *pf[1 + MAX_FLOWS];
        int nfds = 0;
        pfds[nfds].fd = sockB; pfds[nfds].events = POLLIN; pf[nfds] = NULL; nfds++;
        for (int i = 0; i < MAX_FLOWS; i++) {
            if (g_flows[i].used && g_flows[i].local_fd >= 0) {
                pfds[nfds].fd = g_flows[i].local_fd;
                pfds[nfds].events = POLLIN;
                pf[nfds] = &g_flows[i];
                nfds++;
            }
        }

        if (poll(pfds, nfds, -1) < 0) {
            if (errno == EINTR) continue;
            die("poll");
        }

        /* relay -> local msquic (forward DATA, or future CNP for server) */
        if (pfds[0].revents & POLLIN) {
            ssize_t n = recvfrom(sockB, in, sizeof(in), 0, NULL, NULL);
            if (n >= TUNNEL_HDR_LEN) {
                struct tunnel_header *h = (struct tunnel_header *)in;
                if (tunnel_is(h, htonl(TUNNEL_MAGIC))) {
                    uint32_t fid  = ntohl(h->flow_id);
                    int      plen = ntohs(h->payload_len);
                    uint8_t *payload = in + TUNNEL_HDR_LEN;
                    if (plen > (int)n - TUNNEL_HDR_LEN)
                        plen = (int)n - TUNNEL_HDR_LEN;

                    struct flow *f = flow_by_id(fid);
                    if (!f) {
                        f = flow_alloc();
                        if (f) {
                            f->flow_id     = fid;
                            f->msquic_addr = cfg->msquic_addr;
                            /* Return identity = forward identity, swapped. */
                            f->orig_src_ip   = h->orig_dst_ip;
                            f->orig_src_port = h->orig_dst_port;
                            f->orig_dst_ip   = h->orig_src_ip;
                            f->orig_dst_port = h->orig_src_port;
                            /* Per-flow ephemeral socket connected to msquic so
                             * its replies are distinguishable per client. */
                            struct sockaddr_in any = { .sin_family = AF_INET,
                                .sin_addr.s_addr = htonl(INADDR_ANY), .sin_port = 0 };
                            f->local_fd = udp_socket_bound(&any);
                            connect(f->local_fd,
                                    (struct sockaddr *)&cfg->msquic_addr,
                                    sizeof(cfg->msquic_addr));
                            if (cfg->verbose)
                                fprintf(stderr, "[shim/server] new flow 0x%08x\n", fid);
                        }
                    }
                    if (f && plen > 0) {
                        f->last_seen = time(NULL);
                        send(f->local_fd, payload, plen, 0);
                    }
                }
            }
        }

        /* local msquic -> relay (return, DIR_S2C) */
        for (int i = 1; i < nfds; i++) {
            if (!(pfds[i].revents & POLLIN)) continue;
            struct flow *f = pf[i];
            ssize_t n = recv(pfds[i].fd, in, sizeof(in), 0);
            if (n > 0 && f) {
                f->last_seen = time(NULL);
                int olen = tunnel_encap(out, f, TUNNEL_TYPE_DATA,
                                        TUNNEL_DIR_S2C, in, (int)n);
                sendto(sockB, out, olen, 0,
                       (struct sockaddr *)&cfg->relay_addr,
                       sizeof(cfg->relay_addr));
            }
        }
    }
}

/* ----------------------------------------------------------------------- */
/* main                                                                    */
/* ----------------------------------------------------------------------- */

static void usage(const char *p) {
    fprintf(stderr,
"usage:\n"
"  client: %s --role client --listen 127.0.0.1:5000 \\\n"
"             --relay 10.103.238.111:4433 --peer 10.29.75.103:4433 [-v]\n"
"  server: %s --role server --bind 10.29.75.103:4433 \\\n"
"             --msquic 127.0.0.1:4444 --relay 10.103.238.111:4433 [-v]\n",
        p, p);
    exit(2);
}

int main(int argc, char **argv) {
    struct config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = -1;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--role") && i + 1 < argc) {
            const char *r = argv[++i];
            if (!strcmp(r, "client")) cfg.role = ROLE_CLIENT;
            else if (!strcmp(r, "server")) cfg.role = ROLE_SERVER;
            else usage(argv[0]);
        } else if (!strcmp(argv[i], "--listen") && i + 1 < argc) {
            if (parse_addr(argv[++i], &cfg.listen_addr)) usage(argv[0]);
        } else if (!strcmp(argv[i], "--bind") && i + 1 < argc) {
            if (parse_addr(argv[++i], &cfg.bind_addr)) usage(argv[0]);
        } else if (!strcmp(argv[i], "--relay") && i + 1 < argc) {
            if (parse_addr(argv[++i], &cfg.relay_addr)) usage(argv[0]);
        } else if (!strcmp(argv[i], "--peer") && i + 1 < argc) {
            if (parse_addr(argv[++i], &cfg.peer_addr)) usage(argv[0]);
        } else if (!strcmp(argv[i], "--msquic") && i + 1 < argc) {
            if (parse_addr(argv[++i], &cfg.msquic_addr)) usage(argv[0]);
        } else if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose")) {
            cfg.verbose = 1;
        } else {
            usage(argv[0]);
        }
    }

    if (cfg.role == ROLE_CLIENT) {
        if (!cfg.listen_addr.sin_port || !cfg.relay_addr.sin_port ||
            !cfg.peer_addr.sin_port) usage(argv[0]);
        run_client(&cfg);
    } else if (cfg.role == ROLE_SERVER) {
        if (!cfg.bind_addr.sin_port || !cfg.relay_addr.sin_port ||
            !cfg.msquic_addr.sin_port) usage(argv[0]);
        run_server(&cfg);
    } else {
        usage(argv[0]);
    }
    return 0;
}
