#define RX_RING_SIZE 1024
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 256
#define BURST_SIZE 32

#define LOG_MBUFS 8191
#define LOG_MBUF_CACHE_SIZE 256

#define AUDIT_RING_SIZE 65536

#define ENTRIES_PER_SCAN 64


#define TLS_HANDSHAKE 22
#define TLS_EXT_ECH 0xfe0d


#define MYSQL_MARIADB 3306

#define POSTGRESQL 5432

#define MSSQL 1433

#define ORACLE 1521

#define MONGODB 27017

#define REDIS 6379

#define MAX_HASH_ENTRY 2097152

static volatile bool force_quit = false;

static struct rte_ether_addr my_local_mac[RTE_MAX_ETHPORTS];


//static inline int link_status_callback(uint16_t, enum rte_eth_event_type, void *, void *);
static inline void signal_handler(int);
struct rte_mempool * create_memory_pool(const char *, uint16_t, uint16_t,
        uint16_t, uint16_t, int);
static inline int audit_consumer(void *arg);
static inline const char* port_to_service(uint16_t);
static inline const char* protocol_to_str(uint8_t);

static inline int load_ipv4_cidrs(struct rte_lpm *, const char *);
static inline int load_ipv6_cidrs(struct rte_lpm6 *, const char *);

static inline struct asn_range* lookup_ip_metadata(uint32_t);
static inline int load_asn_db(const char *);

static inline struct flow_audit_entry *get_flow_entry(struct rte_hash *, struct flow_key *, uint64_t,
                uint64_t, uint32_t);
static inline void init_flow_table(int);

//static inline void scan_for_logging(struct audit_ctx *ctx, uint32_t, uint64_t);
static inline void
scan_for_logging(struct audit_ctx *ctx, uint32_t timeout, uint64_t now) {

    for (int j = 0; j < ENTRIES_PER_SCAN; j++) {
        struct flow_audit_entry *e = &entries[current_scan_idx];

        if (now - e->last_seen > timeout) {
            if (e->packet_count > 0)
                move_to_audit_ring(ctx, e);

            rte_strscpy(e->log_state, "CLOSED", 16);

            // CRITICAL: Remove from hash table so the index can be reused
            // Note: We use the key stored inside the entry itself
            rte_hash_del_key(flow_table, &e->flow);

            // Clear the entry in the hugepage array
            memset(e, 0, sizeof(struct flow_audit_entry));
        }

        // Increment and wrap around the global array
        current_scan_idx++;
        if (unlikely(current_scan_idx >= MAX_HASH_ENTRY)) {
            current_scan_idx = 0;
        }
    }
}
//static inline void move_to_audit_ring(struct audit_ctx *ctx, struct flow_audit_entry *);
static inline void
move_to_audit_ring(struct audit_ctx *ctx, struct flow_audit_entry *entry) {

    struct flow_audit_entry *log_msg;

    // Get a clean buffer from the log mempool
    if (rte_mempool_get(ctx->log_pool, (void **)&log_msg) == 0) {
        // Deep copy the snapshot
        rte_memcpy(log_msg, entry, sizeof(*log_msg));

        // Push to the ring for the background logger lcore
        if (rte_ring_enqueue(ctx->audit_ring, log_msg) < 0) {
            rte_mempool_put(ctx->log_pool, log_msg); // Drop if ring full

        }
    }
}

//static inline void check_udp_payload_encryption(const uint8_t *, uint16_t, struct flow_audit_entry *);
/**
 * Returns 1 if the UDP payload is likely encrypted (DTLS or QUIC),
 * 0 if it appears to be plaintext (DNS, NTP, etc.)
 */
static inline void
check_udp_payload_encryption(const uint8_t *payload, uint16_t len, struct flow_audit_entry *entry)
{
    if (len < 8)
        return;

    // 1. DTLS Check
    // DTLS uses the same ContentTypes as TLS.
    // 0x16 = Handshake, 0x17 = Application Data
    // DTLS Version 1.2 is 0xfe fd
    if (payload[0] == 0x16 && payload[1] == 0xfe) {
        entry->no_encrypted++;
        return;
    }

    if (payload[0] == 0x17 && payload[1] == 0xfe) {
        entry->no_encrypted++;
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
            entry->no_encrypted++;
    }

    return;
}


//static inline void check_tcp_payload_encryption(const uint8_t *, uint16_t, struct flow_audit_entry *);
static inline void
check_tcp_payload_encryption(const uint8_t *payload, uint16_t len, struct flow_audit_entry *entry)
{
    if (len < 16) return; // Too small to reliably judge

    // 1. Protocol-Level Check: TLS Application Data
    // 0x17 is the ContentType for "Application Data" in TLS 1.2 and 1.3
    if (payload[0] == 0x17 && payload[1] == 0x03) {
        entry->no_encrypted++;
        return;
    }

    if(payload[0] == 0x16 && payload[1] == 0x03) {
        entry->no_encrypted++;
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
    if (non_ascii_count >= 3)
         entry->no_encrypted++;

}
