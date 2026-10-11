#include "protocols.h"
#include "queue.h"
#include "lib.h"
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* ===== Config knobs ======================================================= */
#ifndef ROUTER_NUM_INTERFACES
#define ROUTER_NUM_INTERFACES 4
#endif

/* Fallback netmask for directly-connected routes if your framework
 * doesn't expose a get_interface_netmask(i). Adjust to your lab topology. */
#define DEFAULT_IFACE_MASK "255.255.255.0"

/* Initial capacities (will grow dynamically) */
#define RT_INIT_CAP   64
#define ARP_INIT_CAP  64

/* ===== Data structures ==================================================== */

struct pending_pkt {
    size_t len;
    int out_iface;
    uint32_t next_hop_ip;
    uint8_t buf[MAX_PACKET_LEN];
};

static queue pending_q;

/* Dynamic ARP table (learned only, no files) */
struct arp_dyn_table {
    struct arp_table_entry *v;
    int len;
    int cap;
} g_arp = {NULL, 0, 0};

/* Dynamic route table (self-built from interfaces, plus optional default) */
struct route_dyn_table {
    struct route_table_entry *v;
    int len;
    int cap;
} g_rtbl = {NULL, 0, 0};

/* ===== Utilities ========================================================== */

static uint32_t str_ip(const char *s) {
    return inet_addr(s);
}

static void die_alloc(void *p) {
    if (!p) { perror("malloc/realloc"); exit(1); }
}

static void arp_reserve(int need) {
    if (g_arp.cap >= need) return;
    int ncap = g_arp.cap ? g_arp.cap * 2 : ARP_INIT_CAP;
    while (ncap < need) ncap *= 2;
    g_arp.v = (struct arp_table_entry*)realloc(g_arp.v, ncap * sizeof(*g_arp.v));
    die_alloc(g_arp.v);
    g_arp.cap = ncap;
}

static void rt_reserve(int need) {
    if (g_rtbl.cap >= need) return;
    int ncap = g_rtbl.cap ? g_rtbl.cap * 2 : RT_INIT_CAP;
    while (ncap < need) ncap *= 2;
    g_rtbl.v = (struct route_table_entry*)realloc(g_rtbl.v, ncap * sizeof(*g_rtbl.v));
    die_alloc(g_rtbl.v);
    g_rtbl.cap = ncap;
}

/* ===== Route table: compare + LPM ======================================== */

/* Sort by mask (ascending host order), then prefix (ascending host order) */
int compareRoutes(const void *a, const void *b) {
    const struct route_table_entry *ra = (const struct route_table_entry *)a;
    const struct route_table_entry *rb = (const struct route_table_entry *)b;

    uint32_t maskA = ntohl(ra->mask);
    uint32_t maskB = ntohl(rb->mask);

    if (maskA > maskB) return 1;
    if (maskA < maskB) return -1;

    uint32_t prefixA = ntohl(ra->prefix);
    uint32_t prefixB = ntohl(rb->prefix);

    if (prefixA > prefixB) return 1;
    if (prefixA < prefixB) return -1;
    return 0;
}

/* Correct LPM via linear scan (keeps your original function signature/comment) */
struct route_table_entry *getBestRoute(uint32_t ipDest,
                                       struct route_table_entry *rtable,
                                       int rtableLen) {
    struct route_table_entry *best = NULL;
    uint32_t bestMaskHost = 0;

    for (int i = 0; i < rtableLen; i++) {
        if ((ipDest & rtable[i].mask) == rtable[i].prefix) {
            uint32_t m = ntohl(rtable[i].mask);
            if (m > bestMaskHost) {
                bestMaskHost = m;
                best = &rtable[i];
            }
        }
    }
    return best;
}

/* ===== Router interface helpers ========================================== */

/* Checks if dest equals any interface IP of the router */
int isRouteAddress(uint32_t dest) {
    for (int i = 0; i < ROUTER_NUM_INTERFACES; i++) {
        const char *ipStr = get_interface_ip(i);
        if (!ipStr) continue;
        uint32_t ipAddr = inet_addr(ipStr);
        if (dest == ipAddr) return 1;
    }
    return 0;
}

/* ===== ICMP builders ====================================================== */

static void prepareIcmpPacket(uint8_t *buf, uint8_t *origPayload,
                              int iface, uint16_t totalIcmpLen) {
    struct ether_hdr *ethHdrOrig = (struct ether_hdr *)origPayload;
    struct ip_hdr *ipHdrOrig = (struct ip_hdr *)(origPayload + sizeof(struct ether_hdr));

    struct ether_hdr *ethHdr = (struct ether_hdr *)buf;
    memcpy(ethHdr->ethr_dhost, ethHdrOrig->ethr_shost, 6);
    get_interface_mac(iface, ethHdr->ethr_shost);
    ethHdr->ethr_type = htons(0x0800);

    struct ip_hdr *ipHdr = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
    ipHdr->ver = 4;
    ipHdr->ihl = 5;
    ipHdr->tos = 0;
    ipHdr->id = htons(0);
    ipHdr->frag = 0;
    ipHdr->ttl = 64;
    ipHdr->proto = 1; /* ICMP */
    ipHdr->source_addr = inet_addr(get_interface_ip(iface));
    ipHdr->dest_addr = ipHdrOrig->source_addr;
    ipHdr->tot_len = htons(sizeof(struct ip_hdr) + totalIcmpLen);
    ipHdr->checksum = 0;
    ipHdr->checksum = htons(checksum((uint16_t *)ipHdr, sizeof(struct ip_hdr)));
}

static void sendIcmpEchoReply(uint8_t *origPayload, int iface) {
    uint8_t buf[MAX_PACKET_LEN] = {0};

    struct ip_hdr *ipHdrOrig = (struct ip_hdr *)(origPayload + sizeof(struct ether_hdr));
    int ipHdrLen = ipHdrOrig->ihl * 4;
    int icmpDataLen = ntohs(ipHdrOrig->tot_len) - ipHdrLen;
    if (icmpDataLen <= 0) return;

    prepareIcmpPacket(buf, origPayload, iface, icmpDataLen);

    struct icmp_hdr *icmpHdrReply = (struct icmp_hdr *)(buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
    struct icmp_hdr *icmpHdrOrig2 = (struct icmp_hdr *)(origPayload + sizeof(struct ether_hdr) + ipHdrLen);
    memcpy(icmpHdrReply, icmpHdrOrig2, icmpDataLen);
    icmpHdrReply->mtype = 0; /* Echo Reply */
    icmpHdrReply->check = 0;
    icmpHdrReply->check = htons(checksum((uint16_t *)icmpHdrReply, icmpDataLen));

    int totalLen = sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + icmpDataLen;
    send_to_link(totalLen, (char *)buf, iface);
}

static void sendIcmpTimeExceeded(uint8_t *origPayload, size_t origLen, int iface) {
    uint8_t buf[MAX_PACKET_LEN] = {0};

    struct ip_hdr *ipHdrOrig = (struct ip_hdr *)(origPayload + sizeof(struct ether_hdr));
    size_t copyLen = sizeof(struct ip_hdr) + 8;
    if (origLen - sizeof(struct ether_hdr) < copyLen)
        copyLen = origLen - sizeof(struct ether_hdr);

    prepareIcmpPacket(buf, origPayload, iface, sizeof(struct icmp_hdr) + copyLen);

    struct icmp_hdr *icmpHdr = (struct icmp_hdr *)(buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
    icmpHdr->mtype = 11; /* Time Exceeded */
    icmpHdr->mcode = 0;
    icmpHdr->check = 0;

    uint8_t *icmpData = (uint8_t *)icmpHdr + sizeof(struct icmp_hdr);
    memcpy(icmpData, ipHdrOrig, copyLen);
    int icmpLen = sizeof(struct icmp_hdr) + copyLen;
    icmpHdr->check = htons(checksum((uint16_t *)icmpHdr, icmpLen));

    send_to_link(sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + icmpLen, (char *)buf, iface);
}

static void sendIcmpDestUnreachable(uint8_t *origPayload, size_t origLen, int iface) {
    uint8_t buf[MAX_PACKET_LEN] = {0};

    struct ip_hdr *ipHdrOrig = (struct ip_hdr *)(origPayload + sizeof(struct ether_hdr));
    size_t copyLen = sizeof(struct ip_hdr) + 8;
    if (origLen - sizeof(struct ether_hdr) < copyLen)
        copyLen = origLen - sizeof(struct ether_hdr);

    prepareIcmpPacket(buf, origPayload, iface, sizeof(struct icmp_hdr) + copyLen);

    struct icmp_hdr *icmpHdr = (struct icmp_hdr *)(buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
    icmpHdr->mtype = 3; /* Dest Unreachable */
    icmpHdr->mcode = 0;
    icmpHdr->check = 0;

    uint8_t *icmpData = (uint8_t *)icmpHdr + sizeof(struct icmp_hdr);
    memcpy(icmpData, ipHdrOrig, copyLen);
    int icmpLen = sizeof(struct icmp_hdr) + copyLen;
    icmpHdr->check = htons(checksum((uint16_t *)icmpHdr, icmpLen));

    send_to_link(sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + icmpLen, (char *)buf, iface);
}

void icmp(uint8_t *payload, size_t len, int iface) {
    struct ip_hdr *ipHdr = (struct ip_hdr *)(payload + sizeof(struct ether_hdr));
    int ipHdrLen = ipHdr->ihl * 4;

    if (len < sizeof(struct ether_hdr) + ipHdrLen + sizeof(struct icmp_hdr))
        return;

    struct icmp_hdr *icmpHdr = (struct icmp_hdr *)(payload + sizeof(struct ether_hdr) + ipHdrLen);
    if (icmpHdr->mtype == 8 && icmpHdr->mcode == 0) /* Echo Request */
        sendIcmpEchoReply(payload, iface);
}

/* ===== ARP cache (learned dynamically) ==================================== */

static struct arp_table_entry *getMacEntry(uint32_t ip) {
    for (int i = 0; i < g_arp.len; i++) {
        if (g_arp.v[i].ip == ip)
            return &g_arp.v[i];
    }
    return NULL;
}

static void add_or_update_arp(uint32_t ip, const uint8_t mac[6]) {
    for (int i = 0; i < g_arp.len; i++) {
        if (g_arp.v[i].ip == ip) {
            memcpy(g_arp.v[i].mac, mac, 6);
            return;
        }
    }
    arp_reserve(g_arp.len + 1);
    g_arp.v[g_arp.len].ip = ip;
    memcpy(g_arp.v[g_arp.len].mac, mac, 6);
    g_arp.len++;
}

static void send_arp_request(uint32_t target_ip, int out_iface) {
    uint8_t buf[MAX_PACKET_LEN] = {0};

    struct ether_hdr *eth = (struct ether_hdr *)buf;
    memset(eth->ethr_dhost, 0xFF, 6);
    get_interface_mac(out_iface, eth->ethr_shost);
    eth->ethr_type = htons(0x0806);

    struct arp_hdr *arp = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));
    arp->hw_type    = htons(1);
    arp->proto_type = htons(0x0800);
    arp->hw_len     = 6;
    arp->proto_len  = 4;
    arp->opcode     = htons(1); /* request */
    get_interface_mac(out_iface, arp->shwa);
    arp->sprotoa    = inet_addr(get_interface_ip(out_iface));
    memset(arp->thwa, 0x00, 6);
    arp->tprotoa    = target_ip;

    send_to_link(sizeof(struct ether_hdr) + sizeof(struct arp_hdr), (char *)buf, out_iface);
}

static void flush_pending_for_ip(uint32_t ip, const uint8_t mac[6]) {
    if (!pending_q) return;

    queue new_q = create_queue();
    while (!queue_empty(pending_q)) {
        struct pending_pkt *pk = (struct pending_pkt *)queue_deq(pending_q);
        if (pk->next_hop_ip == ip) {
            struct ether_hdr *eth = (struct ether_hdr *)pk->buf;
            memcpy(eth->ethr_dhost, mac, 6);
            get_interface_mac(pk->out_iface, eth->ethr_shost);
            send_to_link(pk->len, (char *)pk->buf, pk->out_iface);
            free(pk);
        } else {
            queue_enq(new_q, pk);
        }
    }
    pending_q = new_q;
}

/* ===== IPv4 forwarding ==================================================== */

void ipv4(uint8_t *payload, size_t len,
          struct route_table_entry *rtable, int rtableLen,
          int iface) {
    if (len < sizeof(struct ether_hdr) + sizeof(struct ip_hdr)) return;

    struct ip_hdr *ipHdr = (struct ip_hdr *)(payload + sizeof(struct ether_hdr));

    /* Validate checksum */
    uint16_t checksumOrg = ipHdr->checksum;
    ipHdr->checksum = 0;
    uint16_t checksumAfter = checksum((uint16_t *)ipHdr, sizeof(struct ip_hdr));
    if (checksumAfter != ntohs(checksumOrg)) {
        ipHdr->checksum = checksumOrg;
        return;
    }
    ipHdr->checksum = checksumOrg;

    /* TTL */
    if (ipHdr->ttl <= 1) {
        sendIcmpTimeExceeded(payload, len, iface);
        return;
    }

    ipHdr->ttl -= 1;
    ipHdr->checksum = 0;
    ipHdr->checksum = htons(checksum((uint16_t *)ipHdr, sizeof(struct ip_hdr)));

    /* Local delivery (ICMP only) */
    if (isRouteAddress(ipHdr->dest_addr)) {
        if (ipHdr->proto == IPPROTO_ICMP) {
            icmp(payload, len, iface);
        }
        return;
    }

    /* LPM lookup */
    struct route_table_entry *bestRoute = getBestRoute(ipHdr->dest_addr, rtable, rtableLen);
    if (!bestRoute) {
        sendIcmpDestUnreachable(payload, len, iface);
        return;
    }

    /* ARP resolution */
    uint32_t arpIp = bestRoute->next_hop ? bestRoute->next_hop : ipHdr->dest_addr;
    struct arp_table_entry *arpEntry = getMacEntry(arpIp);
    if (!arpEntry) {
        struct pending_pkt *pk = (struct pending_pkt *)malloc(sizeof(struct pending_pkt));
        die_alloc(pk);
        pk->len = len;
        pk->out_iface = bestRoute->interface;
        pk->next_hop_ip = arpIp;
        memcpy(pk->buf, payload, len);
        queue_enq(pending_q, pk);

        send_arp_request(arpIp, bestRoute->interface);
        return;
    }

    /* Fill Ethernet and forward */
    struct ether_hdr *etherHdr = (struct ether_hdr *)payload;
    memcpy(etherHdr->ethr_dhost, arpEntry->mac, 6);
    get_interface_mac(bestRoute->interface, etherHdr->ethr_shost);

    send_to_link(len, (char *)payload, bestRoute->interface);
}

/* ===== ARP processing ===================================================== */

void arp(uint8_t *payload, size_t len, int in_iface) {
    if (len < sizeof(struct ether_hdr) + sizeof(struct arp_hdr)) return;

    struct arp_hdr *arph = (struct arp_hdr *)(payload + sizeof(struct ether_hdr));

    if (ntohs(arph->hw_type)    != 1      ||
        ntohs(arph->proto_type) != 0x0800 ||
        arph->hw_len            != 6      ||
        arph->proto_len         != 4)
        return;

    uint16_t op = ntohs(arph->opcode);

    /* Learn sender */
    add_or_update_arp(arph->sprotoa, arph->shwa);

    if (op == 1) { /* request */
        uint32_t my_ip = inet_addr(get_interface_ip(in_iface));
        if (arph->tprotoa != my_ip) return;

        uint8_t rbuf[MAX_PACKET_LEN] = {0};

        struct ether_hdr *reth = (struct ether_hdr *)rbuf;
        memcpy(reth->ethr_dhost, arph->shwa, 6);
        get_interface_mac(in_iface, reth->ethr_shost);
        reth->ethr_type = htons(0x0806);

        struct arp_hdr *rarp = (struct arp_hdr *)(rbuf + sizeof(struct ether_hdr));
        rarp->hw_type    = htons(1);
        rarp->proto_type = htons(0x0800);
        rarp->hw_len     = 6;
        rarp->proto_len  = 4;
        rarp->opcode     = htons(2); /* reply */
        get_interface_mac(in_iface, rarp->shwa);
        rarp->sprotoa = my_ip;
        memcpy(rarp->thwa, arph->shwa, 6);
        rarp->tprotoa = arph->sprotoa;

        send_to_link(sizeof(struct ether_hdr) + sizeof(struct arp_hdr), (char *)rbuf, in_iface);
        return;
    }

    if (op == 2) { /* reply */
        flush_pending_for_ip(arph->sprotoa, arph->shwa);
        return;
    }
}

/* ===== Self-building route table ========================================= */

/* Helper to push a route entry */
static void rt_push(uint32_t prefix, uint32_t mask, uint32_t next_hop, int iface) {
    rt_reserve(g_rtbl.len + 1);
    g_rtbl.v[g_rtbl.len].prefix    = prefix;
    g_rtbl.v[g_rtbl.len].mask      = mask;
    g_rtbl.v[g_rtbl.len].next_hop  = next_hop; /* 0 means directly-connected */
    g_rtbl.v[g_rtbl.len].interface = iface;
    g_rtbl.len++;
}

/* Build directly-connected routes from router interfaces.
 * If your framework provides get_interface_netmask(i), use it.
 * Otherwise falls back to DEFAULT_IFACE_MASK. */
static void build_connected_routes(void) {
    for (int i = 0; i < ROUTER_NUM_INTERFACES; i++) {
        const char *ip_s = get_interface_ip(i);
        if (!ip_s) continue;

        const char *mask_s =
#ifdef get_interface_netmask
            get_interface_netmask(i);
#else
            DEFAULT_IFACE_MASK;
#endif
        uint32_t ip = str_ip(ip_s);
        uint32_t mask = str_ip(mask_s);
        uint32_t prefix = ip & mask;

        rt_push(prefix, mask, 0 /* directly-connected */, i);
    }
}

/* Optional: add a default route (0.0.0.0/0) if user provides CLI flags:
 *   -d <next_hop_ip> <iface_index>
 */
static void maybe_add_default_route(int argc, char **argv) {
    for (int k = 1; k + 2 < argc; k++) {
        if (strcmp(argv[k], "-d") == 0) {
            uint32_t nh = str_ip(argv[k+1]);
            int iface = atoi(argv[k+2]);
            rt_push(0 /* 0.0.0.0 */, 0 /* /0 */, nh, iface);
            break;
        }
    }
}

/* ===== Main loop ========================================================= */

int main(int argc, char *argv[]) {
    char buf[MAX_PACKET_LEN];

    /* Init with all interfaces passed on CLI (no rtable/arp files needed).
     * Your lab's init usually expects a list of interface names:
     *   ./router iface0 iface1 ...
     * If your original init expected argv+2, adjust here accordingly. */
    init(argv + 1, argc - 1);

    /* Init dynamic tables & queues */
    arp_reserve(ARP_INIT_CAP);
    rt_reserve(RT_INIT_CAP);
    pending_q = create_queue();

    /* Build route table automatically */
    build_connected_routes();
    maybe_add_default_route(argc, argv);
    qsort(g_rtbl.v, g_rtbl.len, sizeof(struct route_table_entry), compareRoutes);

    while (1) {
        size_t interface;
        size_t len;

        interface = recv_from_any_link(buf, &len);
        DIE(interface < 0, "recv_from_any_links");

        /* Accept frames addressed to us or broadcast */
        uint8_t macAddr[6];
        struct ether_hdr *ethernetHdr = (struct ether_hdr *)buf;
        uint16_t ethernetType = ntohs(ethernetHdr->ethr_type);
        get_interface_mac(interface, macAddr);

        if (memcmp(ethernetHdr->ethr_dhost, macAddr, 6) != 0 &&
            memcmp(ethernetHdr->ethr_dhost, "\xFF\xFF\xFF\xFF\xFF\xFF", 6) != 0)
            continue;

        switch (ethernetType) {
            case 0x0800: /* IPv4 */
                ipv4((uint8_t *)buf, len, g_rtbl.v, g_rtbl.len, (int)interface);
                break;
            case 0x0806: /* ARP  */
                arp((uint8_t *)buf, len, (int)interface);
                break;
            default:
                /* ignore others */
                continue;
        }
    }
    return 0;
}
