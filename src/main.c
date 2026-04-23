#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <time.h>
#include <arpa/inet.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_malloc.h>
#include <rte_lcore.h>
#include <rte_lpm.h>
#include <rte_lpm6.h>
#include <rte_ring.h>
#include <rte_errno.h>
#include <rte_cycles.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include "local.h"

struct rte_hash_parameters hash_params = {
    .name = "ip_hash",
    .entries = MAX_IP_ENTRIES,
    .key_len = sizeof(uint32_t),
    .hash_func = rte_jhash,
    .hash_func_init_val = 0
};


struct sovereignty_audit_entry {
    char dst_ip[INET_ADDRSTRLEN];
    uint64_t total_bytes;   // Total volume for this session/packet
    char org_name[64];      // Identity (from your Top 1000/rDNS table)
    uint64_t timestamp;
};

struct audit_ctx {
    struct rte_ring *audit_ring;
    struct rte_mempool *log_pool;
    uint64_t start_cycles;
    time_t start_time;
    uint64_t hz;
    uint64_t timestamp;
    const char *output_file;
};

struct rte_lpm_config config = {
    .max_rules = 1024,
    .number_tbl8s = 256,
    .flags = 0
};

static const struct rte_eth_conf port_conf_default = {
    .rxmode = {
        /* Enable Multi-Queue to separate ARP (Queue 1) from NAT (Queue 0) */
        .mq_mode = RTE_ETH_MQ_RX_RSS,
        //.offloads = 0,                   // adjust RX offloads if neededx
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key = NULL,
            //.rss_hf = RTE_ETH_RSS_IP, // Default hashing for IP traffic for later
        },
    },
    .txmode = {
        .mq_mode = RTE_ETH_MQ_RX_NONE,
        .offloads = RTE_ETH_TX_OFFLOAD_IPV4_CKSUM |
                    RTE_ETH_TX_OFFLOAD_UDP_CKSUM  |
                    RTE_ETH_TX_OFFLOAD_TCP_CKSUM
    },
    /* CRITICAL: Enable the Link Status Change interrupt */
    .intr_conf = {
        .lsc = 1,
    },
};


int main(int argc, char **argv)
{
    int ret;
    uint16_t port_id;
    uint16_t port_ids[RTE_MAX_ETHPORTS];
    int socket_ids[RTE_MAX_ETHPORTS];
    int socket_id;
    uint16_t nb_ports;
    struct rte_eth_dev_info dev_info[RTE_MAX_ETHPORTS];
    struct rte_mempool *mbuf_pool, *log_pool;
    struct rte_eth_txconf txq_conf;
    struct rte_eth_conf port_conf = port_conf_default;
    struct rte_mbuf *bufs[BURST_SIZE];
    struct rte_eth_stats stats;
    uint64_t last_stat_print = 0;
    struct port_config net_port[RTE_MAX_ETHPORTS];
    struct rte_eth_link link;
    struct sovereignty_log *entry = malloc(sizeof(*entry));
    uint64_t clock_rate = rte_get_tsc_hz();
    struct rte_lpm *lpmv4, *lpmv6;
    struct rte_ring *audit_ring;
    struct audit_ctx *ctx = malloc(sizeof(*ctx));
    ctx->start_cycles = rte_get_timer_cycles();
    ctx->start_time = time(NULL);
    ctx->hz = rte_get_timer_hz();
    struct rte_hash *ip_hash = rte_hash_create(&hash_params);

    const char *v4filename = "afrinic-gh-ipv4-cidr.txt";
    const char *v6filename = "afrinic-gh-ipv6-cidr.txt";

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // 1. Initialize EAL
    ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    }

    // 2. Check available ports
    nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0) {
        rte_exit(EXIT_FAILURE, "No available DPDK ports\n");
    }

    printf("Available ports: %u\n", nb_ports);

    for (port_id = 0; port_id < nb_ports; port_id++) {

        if (rte_eth_dev_info_get(port_id, &(dev_info[port_id])))
            rte_exit(EXIT_FAILURE, "couldn't get attribute of port %d driver %s\n", port_id, dev_info[port_id].driver_name);

        if (rte_eth_macaddr_get(port_id, &(my_local_mac[port_id])))
            rte_exit(EXIT_FAILURE, "couldn't get mac address of port %d driver %s\n", port_id, dev_info[port_id].driver_name);

        socket_id = rte_eth_dev_socket_id(port_id);
        if (socket_id == SOCKET_ID_ANY)
            socket_id = 0;

        hash_params.socket_id = socket_id;

        socket_ids[port_id] = socket_id; // keep track of a port => socket id map

        printf("started pool\n");
        // create mempool for packets
        mbuf_pool = create_memory_pool(
            "NAT_MBUF_POOL_",
            NUM_MBUFS,
            MBUF_CACHE_SIZE,
            0,
            RTE_MBUF_DEFAULT_BUF_SIZE,
            socket_id
        );

        if (mbuf_pool == NULL) {
            printf("Mempool Creation Failed:  %s\n", rte_strerror(rte_errno));
            rte_exit(EXIT_FAILURE, "Cannot create NAT mbuf pool on socket id %d\n", socket_id);
        }
         printf("created memory pool\n");

        // create mempool for logging
        log_pool = create_memory_pool(
            "LOG_POOL_",
            LOG_MBUFS,
            LOG_MBUF_CACHE_SIZE,
            0,
            RTE_MBUF_DEFAULT_BUF_SIZE,
            socket_id
        );

        if (log_pool == NULL) {
            printf("Mempool Creation Failed:  %s\n", rte_strerror(rte_errno));
            rte_exit(EXIT_FAILURE, "Cannot create log mbuf pool on socket id %d\n", socket_id);
        }

        printf("created log pool\n");

        ret = rte_eth_dev_configure(port_id, 1, 1, &port_conf);
        if (ret < 0) {
            rte_exit(EXIT_FAILURE, "Cannot configure device on port %d\n", port_id);
        }

        // Setup sensor RX queue
        ret = rte_eth_rx_queue_setup(
            port_id,
            0,
            RX_NAT_RING_SIZE,
            socket_id,
            NULL,
            mbuf_pool
        );
        if (ret < 0) {
            rte_exit(EXIT_FAILURE, "NAT RX queue setup failed\n");
        }

        printf("rx queue setup\n");

        ret = rte_eth_dev_start(port_id);
        if (ret < 0) {
            rte_exit(EXIT_FAILURE, "Device %d start failed on err=%d\n", port_id, ret );
        }

        printf("device started\n");

        // 9. Enable promiscuous mode
        ret = rte_eth_promiscuous_enable(port_id);
        if (ret < 0) {
            rte_exit(EXIT_FAILURE, "promiscuous mode on device %d failed on err=%d\n", port_id, ret);
        }

        port_ids[port_id] = port_id;
        lpmv4 = rte_lpm_create("ghana_lpm_v4", socket_id, &config);
        if (lpmv4 == NULL) {
            rte_exit(EXIT_FAILURE, "Failed to create LPM table for ipv4\n");
        }
        load_ipv4_cidrs(lpmv4, v4filename); //load addresses into memory

        /*lpmv6 = rte_lpm_create("ghana_lpm_v6", socket_id, &config);
        if (lpmv6 == NULL) {
            rte_exit(EXIT_FAILURE, "Failed to create LPM table for ipv6\n");
        }
        load_ipv4_cidrs(lpmv6, v6filename); // ditto for v6
        */

        audit_ring = rte_ring_create(
            "AUDIT_RING",           // Unique name for the ring
            AUDIT_RING_SIZE,              // Number of slots (must be power of 2)
            socket_id,        // Allocate on the same NUMA node as the NIC
            RING_F_SP_ENQ | RING_F_SC_DEQ // Single-Producer, Single-Consumer optimization
        );

        if (audit_ring == NULL) {
            rte_exit(EXIT_FAILURE, "Failed to create Audit Ring: %s\n", rte_strerror(rte_errno));
        }
        ctx->audit_ring = audit_ring;
        ctx->log_pool = log_pool;
        rte_eal_remote_launch(audit_consumer, ctx, 1);

    }

    printf("Initialization complete. Receiving packets...\n");


    while (!force_quit) {

        uint64_t now = rte_get_timer_cycles();
        uint16_t nb_rx = rte_eth_rx_burst(0, 0, bufs, BURST_SIZE);

        if (nb_rx == 0)
            continue;

        entry->timestamp = now;

        printf("Received %" PRIu16 " packets\n", nb_rx);
        int i;

        for (i = 0; i < nb_rx; i++) {
            printf("prefetchign\n");
            rte_prefetch0(rte_pktmbuf_mtod(bufs[i], void *));

            // future: prefetch NAT entry too
            // If you have a huge NAT table, prefetch the hash entry too
            // rte_prefetch0(lookup_table_entry_for_this_packet);
        }


        for (i = 0; i < nb_rx; i++) {
            printf("starting loop\n");
            struct rte_mbuf *m = bufs[i];


            // 2. MTOD: Get the pointer to the start of the Ethernet Header.
            // This triggers the 64-byte fetch into one of your 512 L1 slots.
            struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
            struct rte_ipv4_hdr  *ipv4;
            struct rte_tcp_hdr   *tcp;
            struct rte_udp_hdr   *udp;
            uint32_t next_hop;
            const char *sniptr;


            uint16_t eth_type = eth_hdr->ether_type; // Already in Big Endian from wire

            if (likely(eth_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))) {
                printf("IP\n");

                struct rte_ipv4_hdr *ipv4 = (struct rte_ipv4_hdr *)(eth_hdr + 1);
                uint8_t proto = ipv4->next_proto_id;
                uint32_t src_ip = rte_cpu_to_be_32(ipv4->src_addr);
                uint32_t dst_ip = rte_cpu_to_be_32(ipv4->dst_addr);
                uint16_t d_port, s_port;


                if (rte_lpm_lookup(lpmv4, dst_ip, &next_hop) == 0) {
                    // Ghana IP, continue;
                    continue;
                }

                memset(entry, 0, sizeof(*entry));

                /* not ghana IP, flagged */



                if (proto == IPPROTO_TCP) {

                    tcp = (struct rte_tcp_hdr *)((unsigned char *)ipv4 +
                    (ipv4->ihl * 4));
                    d_port = rte_cpu_to_be_16(tcp->dst_port);
                    s_port = rte_cpu_to_be_16(tcp->src_port);
                    const uint8_t *data = (uint8_t *)tcp + ((tcp->data_off >> 4) * 4);
                    uint16_t tcp_payload_len = rte_be_to_cpu_16(ipv4->total_length)
                        - ((ipv4->ihl * 4) + ((tcp->data_off >> 4) * 4));
                    size_t sni_len;
                    check_tcp_payload_encryption(data, tcp_payload_len, entry);
                    if (entry->is_tls_ech_handshake) {
                        static const char *unk = "ECH ENCRYPTED";
                        rte_memcpy(entry->sni, unk, 14);
                    }
                    else {
                        if ((sniptr = extract_sni(data, tcp_payload_len, &sni_len)) != NULL) {
                            rte_memcpy(entry->sni, sniptr, sni_len);
                            entry->sni[sni_len] = '\0';
                        }
                        else {
                            static const char *unk = "UNKNOWN";
                            rte_memcpy(entry->sni, unk, 8);
                        }
                    }

                } else if (proto == IPPROTO_UDP) {
                    udp = (struct rte_udp_hdr *)((unsigned char *)ipv4 +
                    (ipv4->ihl * 4));
                    const uint8_t *payload = (const uint8_t *)(udp + 1);
                    uint16_t payload_len = rte_be_to_cpu_16(ipv4->total_length) - (ipv4->ihl * 4) - sizeof(struct rte_udp_hdr);
                    d_port = rte_cpu_to_be_16(udp->dst_port);
                    s_port = rte_cpu_to_be_16(udp->src_port);
                    check_udp_payload_encryption(payload, payload_len, entry);
                    if (entry->is_tls_ech_handshake) {
                        static const char *unk = "ECH ENCRYPTED";
                        rte_memcpy(entry->sni, unk, 14);
                    }
                }

                if (rte_mempool_get(log_pool, (void **)&entry) == 0) {
                    entry->d_ip = dst_ip;
                    entry->s_ip = src_ip;
                    entry->src_port = s_port;
                    entry->dst_port = d_port;
                    entry->timestamp = now; // High-precision cycle count
                    entry->service = port_to_service(ntohs(s_port));
                    entry->protocol = protocol_to_str(ntohs(proto));

                    /* 3. Hand over to the logging ring */
                    if (rte_ring_enqueue(audit_ring, entry) < 0) {
                        rte_mempool_put(log_pool, entry); // Drop if ring is full
                    }
                }

                printf("IPv4 received\n");
                continue;
            }
            else if (unlikely(eth_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6))) {

                    continue;
                // The CPU prepares for this to be false

            }
            else {
                printf("drop\n");
                // The "Trash Can" for everything else
                rte_pktmbuf_free(m);
                continue;
            }

            // 4. FREE: Once done, the cache line is marked as 'dirty' or 'freeable'
            rte_pktmbuf_free(m);

            printf("  Packet length: %u bytes\n",
                    rte_pktmbuf_pkt_len(bufs[i]));
        }

        if (now - last_stat_print > rte_get_timer_hz()) {
            rte_eth_stats_get(0, &stats);

            printf("=== NIC stats ===\n");
            printf("RX packets: %" PRIu64 "\n", stats.ipackets);
            printf("RX dropped: %" PRIu64 "\n", stats.imissed);
            printf("=================\n");

            last_stat_print = now;
        }
    }

    rte_eth_dev_stop(0);
    rte_eth_dev_close(0);

    printf("Bye!\n");
    return 0;
}

struct rte_mempool *
create_memory_pool(const char *sig, uint16_t cnt, uint16_t cache_size,
        uint16_t priv_size, uint16_t data_room_size, int sock_id)
{
    char pool_name[32];
    struct rte_mempool *mp;

    /* 1. Append the socket_id to the base name */
    /* Result will be "NAT_MBUF_POOL_0", "NAT_MBUF_POOL_1", etc. */
    snprintf(pool_name, sizeof(pool_name), "%s%u", sig, sock_id);

    /* 2. Try to find if it already exists (from another port on same socket) */
    mp = rte_mempool_lookup(pool_name);

    if (mp != NULL) {
        printf("Found existing pool: %s\n", pool_name); /* don't create */
        return mp;
    }

    // Create mempool
    mp = rte_pktmbuf_pool_create(
        pool_name,
        cnt,
        cache_size,
        priv_size,
        data_room_size,
        sock_id
    );

    return mp;
}

static inline void
signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\nSignal received, preparing to exit...\n");
        force_quit = true;
    }
}


#define TLS_CLIENT_HELLO 1
#define TLS_EXT_SNI 0x0000

static inline const char *
extract_sni(const uint8_t *data, size_t len, size_t *sni_len)
{
    const uint8_t *p = data;
    const uint8_t *end = data + len;

    // ---- TLS record header (5 bytes) ----
    if (p + 5 > end)
        return NULL;

    if (p[0] != TLS_HANDSHAKE)
        return NULL;

    uint16_t record_len = (p[3] << 8) | p[4];
    p += 5;

    if (p + record_len > end)
        return NULL;

    // ---- Handshake header ----
    if (p + 4 > end)
        return NULL;

    if (p[0] != TLS_CLIENT_HELLO)
        return NULL;

    uint32_t hs_len = (p[1] << 16) | (p[2] << 8) | p[3];
    p += 4;

    if (p + hs_len > end)
        return NULL;

    // ---- Skip:
    // version (2) + random (32)
    if (p + 34 > end)
        return NULL;
    p += 34;

    // session ID
    if (p + 1 > end)
        return NULL;
    uint8_t sid_len = p[0];
    p += 1 + sid_len;

    // cipher suites
    if (p + 2 > end)
        return NULL;
    uint16_t cs_len = (p[0] << 8) | p[1];
    p += 2 + cs_len;

    // compression methods
    if (p + 1 > end)
        return NULL;
    uint8_t comp_len = p[0];
    p += 1 + comp_len;

    // ---- Extensions ----
    if (p + 2 > end)
        return NULL;
    uint16_t ext_len = (p[0] << 8) | p[1];
    p += 2;

    const uint8_t *ext_end = p + ext_len;

    while (p + 4 <= ext_end) {
        uint16_t ext_type = (p[0] << 8) | p[1];
        uint16_t ext_size = (p[2] << 8) | p[3];
        p += 4;

        if (p + ext_size > ext_end)
            return NULL;

        if (ext_type == TLS_EXT_SNI) {
            const uint8_t *sni = p;

            // SNI list length
            if (sni + 2 > p + ext_size)
                return NULL;

            uint16_t list_len = (sni[0] << 8) | sni[1];
            sni += 2;

            // Only first entry
            if (sni + 3 > p + ext_size)
                return NULL;

            uint8_t name_type = sni[0];
            uint16_t name_len = (sni[1] << 8) | sni[2];
            sni += 3;

            if (name_type != 0)
                return NULL;

            if (sni + name_len > p + ext_size)
                return NULL;

            *sni_len = strlen(sni);

            return (const char *)sni; // NOT null-terminated!
        }

        p += ext_size;
    }

    return NULL;
}

static inline int
load_ipv4_cidrs(struct rte_lpm *lpm, const char *filename)
{
    int fd = open(filename, O_RDONLY);
    if (fd < 0)
        rte_exit(EXIT_FAILURE, "cannot open file %s\n", filename);

    struct stat st;
    fstat(fd, &st);

    char *data = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (data == MAP_FAILED)
        rte_exit(EXIT_FAILURE, "failed to map file %s to memory\n", filename);

    char *p = data;
    char *end = data + st.st_size;

    int count = 0;

    while (p < end) {
        char *line_end = memchr(p, '\n', end - p);
        if (!line_end) break;

        *line_end = '\0';

        // parse "IP/PREFIX"
        char *slash = strchr(p, '/');
        if (slash) {
            *slash = '\0';

            const char *ip_str = p;
            int prefix = atoi(slash + 1);

            struct in_addr addr;
            if (inet_pton(AF_INET, ip_str, &addr) == 1) {
                uint32_t ip = rte_be_to_cpu_32(addr.s_addr);

                rte_lpm_add(lpm, ip, prefix, 1);
                count++;
            }
        }

        p = line_end + 1;
    }

    munmap(data, st.st_size);
    close(fd);

    printf("Loaded %d IPv4 prefixes into LPM\n", count);
    return 0;
}

/*
static inline int
load_ipv6_cidrs(struct rte_lpm6 *lpm6, const char *filename)
{
    int fd = open(filename, O_RDONLY);
    if (fd < 0)
        rte_exit(EXIT_FAILURE, "cannot open file %s\n", filename);

    struct stat st;
    fstat(fd, &st);

    char *data = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (data == MAP_FAILED)
        rte_exit(EXIT_FAILURE, "failed to map file %s to memory\n", filename);

    char *p = data;
    char *end = data + st.st_size;

    int count = 0;

    while (p < end) {
        char *line_end = memchr(p, '\n', end - p);
        if (!line_end) break;

        *line_end = '\0';

        // parse "IPv6/PREFIX"
        char *slash = strchr(p, '/');
        if (slash) {
            *slash = '\0';

            const char *ip_str = p;
            int prefix = atoi(slash + 1);

            uint8_t ip[16];

            if (inet_pton(AF_INET6, ip_str, ip) == 1) {
                if (rte_lpm6_add(lpm6, ip, prefix, 1) == 0) {
                    count++;
                }
            }
        }

        p = line_end + 1;
    }

    munmap(data, st.st_size);
    close(fd);

    printf("Loaded %d IPv6 prefixes into LPM6\n", count);
    return 0;
}
*/

static inline int
audit_consumer(void *arg)
{
    struct audit_ctx *ctx = arg;
    struct sovereignty_log *entries[BURST_SIZE];

    uint64_t start_cycles = ctx->start_cycles;
    time_t start_time = ctx->start_time;
    uint64_t hz = ctx->hz;

    // Bank of Ghana requires restricted access to audit trails
    // 0600: Only the application owner can read/write.
    int fd = open("audit.csv", O_WRONLY | O_APPEND | O_CREAT, 0600);

    if (fd < 0) {
        rte_exit(EXIT_FAILURE, "CRITICAL: Audit log inaccessible. System must halt.\n");
    }
    if (lseek(fd, 0, SEEK_END) == 0) {
        const char *header = "Time,Source (Bank),Destination,Service,SNI state, protocol\n";
        write(fd, header, strlen(header));
    }

    while (1) {

        // Inside your audit_consumer loop
        unsigned int n = rte_ring_dequeue_burst(ctx->audit_ring, (void **)entries, BURST_SIZE, NULL);

        if (unlikely(n == 0)) {
            rte_pause();
            continue;
        }

        for (unsigned int i = 0; i < n; i++) {
            char buf[1024];
            struct sovereignty_log *entry = entries[i];
            char s_ip_str[INET_ADDRSTRLEN];
            char d_ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &entry->s_ip, s_ip_str, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &entry->d_ip, d_ip_str, INET_ADDRSTRLEN);

            // 2. Format Timestamp to HH:MM:SS
            time_t pkt_time = start_time + ((entry->timestamp - start_cycles) / hz);
            struct tm *tm_info = localtime(&pkt_time);
            char time_str[9];
            strftime(time_str, sizeof(time_str), "%H:%M:%S", tm_info);

            // 3. Generate CSV Row
            int len = snprintf(buf, sizeof(buf),
                "%s,%s,%s,%s,%s,%s\n",
                time_str,             // Time
                s_ip_str,          // Source (Bank)
                d_ip_str,    // Destination (SNI or IP)
                entry->service,         // Service (SWIFT/GIP/Update)
                entry->sni,             // SNI
                entry->protocol);       // protocol

            if (unlikely(write(fd, buf, len) < 0)) {
                // Fintechs must "Fail-Closed" if logging fails
                rte_exit(EXIT_FAILURE, "Storage Failure: Ghana Cyber Act Compliance Breach.\n");
            }

            rte_mempool_put(ctx->log_pool, entry);
        }

        // Immediate consistency for financial records
        fdatasync(fd);
    }

    close(fd);
    return 0;
}

static inline const char*
port_to_service(uint16_t port)
{
    switch (port) {
        case 21:   return "ftp";
        case 22:   return "ssh";
        case 80:   return "http";
        case 443:  return "https";
        case 1433: return "mssql";
        case 1521: return "oracle";
        case 3306: return "mysql";
        case 5432: return "postgres";
        case 6379: return "redis";
        default:   return "unassigned";
    }
}

static inline const char*
protocol_to_str(uint8_t proto)
{
    switch (proto) {
        case 1:   return "ICMP";
        case 2:   return "IGMP";
        case 6:   return "TCP";
        case 17:  return "UDP";
        case 47:  return "GRE";
        case 50:  return "ESP";   // IPsec
        case 51:  return "AH";    // IPsec
        case 58:  return "ICMPv6";
        case 115: return "L2TP";
        case 132: return "SCTP";
        default:  return "UNKNOWN";
    }
}

/*
static inline struct ip_entry *
lookup_ip(uint32_t dst_ip)
{
    int ret = rte_hash_lookup(ip_hash, &dst_ip);

    if (likely(ret >= 0)) {
        return &entries[ret];
    }

    return NULL;
}



static inline struct ip_entry *
create_ip_entry(uint32_t dst_ip, uint64_t now, char *ip)
{
    int ret = rte_hash_add_key(ip_hash, &dst_ip);

    if (unlikely(ret < 0)) {
        return NULL; // table full or error
    }

    struct sovereignty_audit_entry *entry = &entries[ret];

    memset(entry, 0, sizeof(entry));
    inet_ntop(AF_INET, &dst_ip, entry->ip, INET_ADDRSTRLEN);
    entry->window_start_tsc = now;

    return entry;
}

static inline struct ip_entry *
get_entry(uint32_t dst_ip, uint64_t now, uint64_t cyc)
{
    struct ip_entry *entry = lookup_ip(dst_ip);
    if (entry == NULL) {
        entry = create_ip_entry(dst_ip, now, cyc);
        if (unlikely(entry == NULL)) {
            printf("entry table full\n");
            return NULL;
        }
    }

    /*if (now - entry->window_start_tsc > WINDOW_CYCLES) {

        // only reset
        memset(entry, 0, sizeof(entry));
        entry->window_start_tsc = now;
    }
    return entry;
}

*/

static inline void
check_tcp_payload_encryption(const uint8_t *payload, uint16_t len, struct sovereignty_log *entry)
{
    if (len < 16) return; // Too small to reliably judge

    // 1. Protocol-Level Check: TLS Application Data
    // 0x17 is the ContentType for "Application Data" in TLS 1.2 and 1.3
    if (payload[0] == 0x17 && payload[1] == 0x03) {
        entry->is_data_encrypted = true;
        return;
    }

    if(payload[0] == 0x16 && payload[1] == 0x03) {
        entry->is_tls_ech_handshake = true;
        return;
    }

    // 2. Statistical Heuristic (The "Randomness" Test)
    // We sample 4 specific offsets to see if they fall into common ASCII ranges.
    // If they look like "GET ", "POST", or "HTTP", it's plaintext.
    int non_ascii_count = 0;
    uint16_t samples[4] = { len/4, len/2, (3*len)/4, len-1 };

    for (int i = 0; i < 4; i++) {
        uint8_t b = payload[samples[i]];
        // If byte is outside standard printable ASCII (32-126)
        // or common whitespace, it's likely part of an encrypted stream.
        if (b < 32 || b > 126) {
            non_ascii_count++;
        }
    }

    // If 3 out of 4 samples are non-printable, we treat it as encrypted
    entry->is_data_encrypted = (non_ascii_count >= 3);
}

/**
 * Returns 1 if the UDP payload is likely encrypted (DTLS or QUIC),
 * 0 if it appears to be plaintext (DNS, NTP, etc.)
 */
static inline void
check_udp_payload_encryption(const uint8_t *payload, uint16_t len, struct sovereignty_log *entry)
{
    if (len < 8)
        return;

    // 1. DTLS Check
    // DTLS uses the same ContentTypes as TLS.
    // 0x16 = Handshake, 0x17 = Application Data
    // DTLS Version 1.2 is 0xfe fd
    if (payload[0] == 0x16 && payload[1] == 0xfe) {
        entry->is_tls_ech_handshake = true;
        return;
    }

    if (payload[0] == 0x17 && payload[1] == 0xfe) {
        entry->is_data_encrypted = true;
        return;
    }

    // 2. QUIC Check
    // QUIC Long Header starts with 0x80 or higher (bit 7 set)
    // QUIC Short Header (1-RTT) has bit 6 set and bit 7 unset (0x40-0x7f)
    // This is a common heuristic for HTTP/3 traffic
    if ((payload[0] & 0x80) || (payload[0] & 0x40)) {
        // Statistical check: Since QUIC is fully encrypted (even headers),
        // the entropy will be very high.
        int non_ascii = 0;
        for(int i = 1; i < 5; i++) {
            if (payload[i] < 32 || payload[i] > 126) non_ascii++;
        }
        if (non_ascii >= 3)
            entry->is_data_encrypted = true;
    }

    return;// Likely Plaintext (e.g., DNS)
}
