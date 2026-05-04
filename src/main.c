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



struct flow_key {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;
} __attribute__((__packed__));

struct flow_audit_entry {
    struct flow_key flow;     // flow
    uint64_t byte_count;      // Total bytes moved
    uint64_t packet_count;    // Total packets
    uint64_t no_encrypted;      // number of encrypted packets in flow
    uint64_t entry_start_tsc;   // first time the flow was init
    uint64_t last_seen;     // time the flow communiction ended
    uint64_t asn;   // ASN number of dest IP
    char country[8];  // country of dest IP
    char owner[128];     // owner of dest IP
    char protocol[16];
    char log_state[16];
    char bank_name[128];
} __rte_cache_aligned;

struct asn_range {
    uint32_t start_ip;
    uint32_t end_ip;
    uint32_t asn;
    char country[8];
    char owner[128];
};


struct rte_hash_parameters params = {
    .name = "flow_audit_table",
    .entries = 262144,               // Table size
    .key_len = sizeof(struct flow_key),
    .hash_func = rte_jhash,          // Jenkins Hash (standard/fast)
    .hash_func_init_val = 0,
    .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY, // Safe for multiple cores
};

struct audit_ctx {
    struct rte_ring *audit_ring;
    struct rte_mempool *log_pool;
    uint64_t start_cycles;
    time_t start_time;
    uint64_t hz;
    uint64_t timestamp;
    const char *output_file;
    uint64_t audit_dropped;
};

struct rte_lpm_config config = {
    .max_rules = 1024,
    .number_tbl8s = 256,
    .flags = 0
};

static const struct rte_eth_conf port_conf_default = {
    .rxmode = {
        /* Enable Multi-Queue*/
        .mq_mode = RTE_ETH_MQ_RX_NONE,
        .max_lro_pkt_size = RTE_ETHER_MAX_LEN,
        .offloads = 0,
    },
    /* CRITICAL: Enable the Link Status Change interrupt */
    .intr_conf = {
        .lsc = 1,
    },
};

struct rte_hash *flow_table = NULL;
struct flow_audit_entry *entries;

struct asn_range *asn_db = NULL;
uint32_t total_asn_entries = 0;
uint64_t current_scan_idx;

#include "local.h"

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
    //struct port_config net_port[RTE_MAX_ETHPORTS];
    struct flow_audit_entry *entry = malloc(sizeof(*entry));
    struct rte_lpm *lpmv4, *lpmv6;
    struct rte_ring *audit_ring;
    uint64_t clock_rate, timeout;
    struct audit_ctx *ctx = malloc(sizeof(*ctx));
    ctx->start_cycles = rte_get_timer_cycles();
    ctx->start_time = time(NULL);

    const char *v4filename = "afrinic-gh-ipv4-cidr.txt";
    const char *v6filename = "afrinic-gh-ipv6-cidr.txt";
    const char *asn_country = "ip2asn-v4-u32.tsv";

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // 1. Initialize EAL
    ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    }

    clock_rate = rte_get_tsc_hz();
    if (clock_rate == 0) {
        rte_exit(EXIT_FAILURE, "CRITICAL: CPU frequency is 0. Timestamping impossible.\n");
    }
    ctx->hz = clock_rate;
    timeout = clock_rate * 10; // 10-second timeout

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

        init_flow_table(socket_id);

        printf("started pool\n");
        // create mempool for packets
        mbuf_pool = create_memory_pool(
            "MBUF_POOL_",
            NUM_MBUFS,
            MBUF_CACHE_SIZE,
            0,
            RTE_MBUF_DEFAULT_BUF_SIZE,
            socket_id
        );

        if (mbuf_pool == NULL) {
            printf("Mempool Creation Failed:  %s\n", rte_strerror(rte_errno));
            rte_exit(EXIT_FAILURE, "Cannot create mbuf pool on socket id %d\n", socket_id);
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

        ret = rte_eth_dev_configure(port_id, 1, 0, &port_conf);
        if (ret < 0) {
            rte_exit(EXIT_FAILURE, "Cannot configure device on port %d\n", port_id);
        }

        // Setup sensor RX queue
        ret = rte_eth_rx_queue_setup(
            port_id,
            0,
            RX_RING_SIZE,
            socket_id,
            NULL,
            mbuf_pool
        );
        if (ret < 0) {
            rte_exit(EXIT_FAILURE, " RX queue setup failed\n");
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
        load_asn_db(asn_country); // load ip to  asntocountry into memory

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

        scan_for_logging(ctx, timeout, now);// scan and send a few logs

        printf("Received %" PRIu16 " packets\n", nb_rx);
        int i;

        for (i = 0; i < nb_rx; i++) {
            printf("prefetchign\n");
            rte_prefetch0(rte_pktmbuf_mtod(bufs[i], void *));
        }

        for (i = 0; i < nb_rx; i++) {
            printf("starting loop\n");
            struct rte_mbuf *m = bufs[i];


            // mtod
            struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
            struct rte_ipv4_hdr  *ipv4;
            struct rte_tcp_hdr   *tcp;
            struct rte_udp_hdr   *udp;
            uint32_t next_hop;
            const char *sniptr;


            uint16_t eth_type = eth_hdr->ether_type;

            if (likely(eth_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))) {
                printf("IP\n");
                struct flow_key flow;
                struct rte_ipv4_hdr *ipv4 = (struct rte_ipv4_hdr *)(eth_hdr + 1);
                flow.proto = ipv4->next_proto_id;
                flow.src_ip = rte_cpu_to_be_32(ipv4->src_addr);
                flow.dst_ip = rte_cpu_to_be_32(ipv4->dst_addr);

                uint32_t bytes = m->pkt_len;


                if (rte_lpm_lookup(lpmv4, flow.dst_ip, &next_hop) == 0) {
                    // Ghana IP, continue;
                    continue;
                }

                /* not ghana IP, flagged */

                if (flow.proto == IPPROTO_TCP) {

                    tcp = (struct rte_tcp_hdr *)((unsigned char *)ipv4 +
                    (ipv4->ihl * 4));
                    flow.dst_port = rte_cpu_to_be_16(tcp->dst_port);
                    flow.src_port = rte_cpu_to_be_16(tcp->src_port);
                    const uint8_t *data = (uint8_t *)tcp + ((tcp->data_off >> 4) * 4);
                    uint16_t tcp_payload_len = rte_be_to_cpu_16(ipv4->total_length)
                        - ((ipv4->ihl * 4) + ((tcp->data_off >> 4) * 4));
                    check_tcp_payload_encryption(data, tcp_payload_len, entry);

                } else if (flow.proto == IPPROTO_UDP) {

                    udp = (struct rte_udp_hdr *)((unsigned char *)ipv4 +
                    (ipv4->ihl * 4));
                    const uint8_t *payload = (const uint8_t *)(udp + 1);
                    uint16_t payload_len = rte_be_to_cpu_16(ipv4->total_length) - (ipv4->ihl * 4) - sizeof(struct rte_udp_hdr);
                    flow.dst_port = rte_cpu_to_be_16(udp->dst_port);
                    flow.src_port = rte_cpu_to_be_16(udp->src_port);
                    check_udp_payload_encryption(payload, payload_len, entry);
                }

                entry = get_flow_entry(flow_table, &flow, now, timeout, bytes);

                // If the flow has moved > 10MB (High Value), log it faster
                if (entry->byte_count > 10000000) {
                    move_to_audit_ring(ctx, entry);
                    entry->last_seen = now;
                    entry->packet_count = 0;
                    entry->no_encrypted = 0;
                    rte_strscpy(entry->log_state, "IN PROGRESS", 16);
                }

                printf("IPv4 received\n");
                continue;
            }
            else if (unlikely(eth_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6))) {
                    continue;

            }
            else {
                printf("drop\n");
                // free
                rte_pktmbuf_free(m);
                continue;
            }

            // 4. FREE
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

static inline struct rte_mempool *
create_memory_pool(const char *sig, uint16_t cnt, uint16_t cache_size,
        uint16_t priv_size, uint16_t data_room_size, int sock_id)
{
    char pool_name[32];
    struct rte_mempool *mp;

    /* 1. Append the socket_id to the base name */
    /* Result will be "MBUF_POOL_0", "MBUF_POOL_1", etc. */
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

static inline void
init_flow_table(int socket_id) {
    struct rte_hash_parameters params = {
        .name = "flow_audit_table",
        .entries = MAX_HASH_ENTRY,
        .key_len = sizeof(struct flow_key),
        .hash_func = rte_jhash,        // Standard Jenkins hash for DPDK
        .hash_func_init_val = 0,
        .socket_id = socket_id,  // Current NUMA node
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF, // Lock-free read/write
    };

    flow_table = rte_hash_create(&params);
    if (flow_table == NULL) {
        rte_exit(EXIT_FAILURE, "Unable to create flow hash table\n");
    }

    size_t total_size = sizeof(struct flow_audit_entry) * MAX_HASH_ENTRY;

    // 3. Allocate from Hugepages
    // zero out memory
    entries = rte_zmalloc_socket(
        "FLOW_AUDIT_ENTRIES",      // Name for debugging
        total_size,                // Total bytes
        RTE_CACHE_LINE_SIZE,       // Align to cache line for speed
        socket_id            // Allocate on the local CPU's memory
    );

    if (entries == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot allocate memory for flow entries\n");
    }
}

static inline struct flow_audit_entry *
get_flow_entry(struct rte_hash *flow_table, struct flow_key *key, uint64_t now,
                uint64_t timeout, uint32_t bytes)
{
    struct flow_audit_entry *entry;
    int ret = rte_hash_lookup(flow_table, key);

    if (likely(ret >= 0)) {
        entry = &entries[ret];

        if (now - entry->last_seen > timeout) { // 60 seconds = new timestamp

            // kill association, log and reset
            memset((struct flow_key *)entry + 1, 0, sizeof(*entry) - sizeof(*key)); // reset all but leave the flow
        }
    } else {
        // new flow
        ret = rte_hash_add_key(flow_table, key);
        if (unlikely(ret < 0)) {
            printf("entry table full: size is %zu\n", rte_hash_count(flow_table));
            return NULL; // table full or error
        }
        entry = &entries[ret];
        entry->entry_start_tsc = now;
    }

    entry->packet_count++;
    entry->last_seen = now; // update last seen
    entry->byte_count += bytes;
    rte_strscpy(entry->protocol, protocol_to_str(ntohs(entry->flow.proto)), 16);
    return entry;
}





static inline int
load_asn_db(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    struct stat st;
    fstat(fd, &st);

    // Map file to memory for fast parsing
    char *map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        close(fd);
        return -1;
    }

    // Count lines to allocate exact memory
    for (long i = 0; i < st.st_size; i++) {
        if (map[i] == '\n')
            total_asn_entries++;
    }

    // Allocate in Hugepages for the Logger Core
    asn_db = rte_zmalloc("ASN_DATABASE", sizeof(struct asn_range) * total_asn_entries, 0);
    if (!asn_db) {
        munmap(map, st.st_size);
        close(fd);
        rte_exit(EXIT_FAILURE, "failed to allocate for ASN database\n");
        return -1;
    }

    char *line = map;
    for (uint32_t i = 0; i < total_asn_entries; i++) {
        // %u\t%u\t%u -> Start, End, ASN
        // %s\t -> Country code (stops at tab)
        // %[^\n] -> Owner (reads everything until the newline, including spaces)
        sscanf(line, "%u\t%u\t%u\t%8s\t%127[^\n]",
               &asn_db[i].start_ip, &asn_db[i].end_ip, &asn_db[i].asn,
               asn_db[i].country, asn_db[i].owner);

        char *next = strchr(line, '\n');
        if (!next) break;
        line = next + 1;
    }

    munmap(map, st.st_size);
    close(fd);
    return 0;
}

static inline struct asn_range*
lookup_ip_metadata(uint32_t ip) {
    if (unlikely(!asn_db)) return NULL;

    uint32_t low = 0;
    uint32_t high = total_asn_entries - 1;

    while (low <= high) {
        uint32_t mid = low + (high - low) / 2;
        struct asn_range *entry = &asn_db[mid];

        // Check if IP is within this range [Start, End]
        if (ip >= entry->start_ip && ip <= entry->end_ip) {
            return entry;
        }

        if (ip < entry->start_ip) {
            high = mid - 1;
        } else {
            low = mid + 1;
        }
    }
    return NULL; // Not found
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

static inline int
audit_consumer(void *arg)
{
    struct audit_ctx *ctx = arg;
    struct flow_audit_entry *entries[BURST_SIZE];
    struct asn_range *asn_info;
    double encryption_ratio;

    uint64_t start_cycles = ctx->start_cycles;
    time_t start_time = ctx->start_time;
    uint64_t hz = ctx->hz;

    /* SECURE FILE ACCESS */
    int fd = open("audit.csv", O_WRONLY | O_APPEND | O_CREAT, 0666);
    if (fd < 0) {
        rte_exit(EXIT_FAILURE, "CRITICAL: Audit log inaccessible. System must halt.\n");
    }

    // Write CSV Header if file is new
    if (lseek(fd, 0, SEEK_END) == 0) {
        const char *header = "Bank_Name,Time,Source_IP,Dest_IP,Encryption_Ratio,Protocol,Source_Port, Dest_Port,Bytes,ASN,Owner,Country, State\n";
        if (write(fd, header, strlen(header)) < 0) {
            rte_exit(EXIT_FAILURE, "Failed to write CSV header.\n");
        }
    }

    printf("[Audit] Logger Core started. Writing to audit.csv\n");

    while (1) {
        unsigned int n = rte_ring_dequeue_burst(ctx->audit_ring, (void **)entries, BURST_SIZE, NULL);

        if (unlikely(n == 0)) {
            rte_pause();
            continue;
        }

        for (unsigned int i = 0; i < n; i++) {
            struct flow_audit_entry *entry = entries[i];
            char buf[2048];
            char s_ip_str[INET_ADDRSTRLEN];
            char d_ip_str[INET_ADDRSTRLEN];
            char time_str[9];
            struct tm tm_res;
            /* we need them back to host order for inet_ntop */
            uint32_t src = rte_cpu_to_be_32(entry->flow.src_ip);
            uint32_t dst = rte_cpu_to_be_32(entry->flow.dst_ip);

            // 2. CONVERT IP TO STRINGS
            inet_ntop(AF_INET, &src, s_ip_str, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &dst, d_ip_str, INET_ADDRSTRLEN);

            // 3. GENERATE TIMESTAMP (HH:MM:SS)
            double diff_sec = (double)(entry->entry_start_tsc - start_cycles) / hz;
            time_t pkt_time = start_time + (time_t)diff_sec;

            // localtime_r is thread-safe and requires the &tm_res pointer
            localtime_r(&pkt_time, &tm_res);
            strftime(time_str, sizeof(time_str), "%H:%M:%S", &tm_res);

            // 4. ENRICH WITH ASN DATA
            // Convert to Host Byte Order for the binary search database
            asn_info = lookup_ip_metadata(entry->flow.dst_ip);

            if (asn_info) {
                entry->asn = asn_info->asn;
                rte_strscpy(entry->country, asn_info->country, sizeof(entry->country));
                rte_strscpy(entry->owner, asn_info->owner, sizeof(entry->owner));
            } else {
                entry->asn = 0;
                rte_strscpy(entry->country, "??", sizeof(entry->country));
                rte_strscpy(entry->owner, "UNKNOWN_NET", sizeof(entry->owner));
            }

            if (entry->packet_count > 0) {
                encryption_ratio = (double)(entry->no_encrypted / entry->packet_count);
            }

            // CEF Formatting Logic
            char cef_buf[2048];
            int len = snprintf(cef_buf, sizeof(cef_buf),
                "CEF:0|%s|Sovereignty-Probe|1.0|100|High Value Flow|3|"
                "rt=%s src=%s dst=%s spt=%u dpt=%u app=%s out=%lu cs1Label=CryptoRatio cs1=%.2f cn1Label=ASN cn1=%u sntdom=%s cs2Label=Country cs2=%s msg=%s\n",
                entry->bank_name,     // Vendor
                time_str,           // Receipt Time
                s_ip_str,           // Source IP
                d_ip_str,           // Dest IP
                entry->flow.src_port,           // Source Port
                entry->flow.dst_port,           // Dest Port
                entry->protocol,    // Protocol
                entry->byte_count,  // Bytes
                encryption_ratio,   // Custom String 1 (Ratio)
                entry->asn,         // Custom Number 1 (ASN)
                entry->owner,       // Network Owner
                entry->country,     // Country Code
                entry->log_state    // Status Message
            );

            // 5. GENERATE CSV ROW (Fintech Standard)
            /*int len = snprintf(buf, sizeof(buf),
                "%s,%s,%s,%s,%.2f,%s,%u,%u,%lu,%u,\"%s\",%s,%s\n",
                time_str,           // Time
                s_ip_str,           // Source
                d_ip_str,           // Destination
                encryption_ratio,    // crypto state
                entry->protocol,    // Protocol ()
                entry->flow.src_port, // source port
                entry->flow.dst_port, // destination port
                entry->byte_count,  // Volume
                entry->asn,         // ASN
                entry->owner,       // Network Owner (quoted for CSV safety)
                entry->country,      // Country Code
                entry->log_state    // log state, partial or complete
            );*/

            if (unlikely(write(fd, buf, len) < 0)) {
                rte_exit(EXIT_FAILURE, "Storage Failure: Ghana Cyber Act Compliance Breach.\n");
            }

            // Return entry to the pool for reuse
            rte_mempool_put(ctx->log_pool, entry);
        }

        // Ensure data is physically on disk before next burst
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
