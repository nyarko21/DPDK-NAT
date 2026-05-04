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
static inline void check_udp_payload_encryption(const uint8_t *, uint16_t, struct flow_audit_entry *);
static inline void check_tcp_payload_encryption(const uint8_t *, uint16_t, struct flow_audit_entry *);

static inline int load_ipv4_cidrs(struct rte_lpm *, const char *);
static inline int load_ipv6_cidrs(struct rte_lpm6 *, const char *);

static inline struct asn_range* lookup_ip_metadata(uint32_t);
static inline int load_asn_db(const char *);
static inline void scan_for_logging(struct audit_ctx *ctx, uint32_t, uint64_t);
static inline void move_to_audit_ring(struct audit_ctx *ctx, struct flow_audit_entry *);
static inline struct flow_audit_entry *get_flow_entry(struct rte_hash *, struct flow_key *, uint64_t,
                uint64_t, uint32_t);
static inline void init_flow_table(int);