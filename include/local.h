#define RX_NAT_RING_SIZE 1024
#define TX_NAT_RING_SIZE 1024
#define RX_ARP_RING_SIZE 64
#define TX_ARP_RING_SIZE 64
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 256
#define BURST_SIZE 32

#define LOG_MBUFS 8191
#define LOG_MBUF_CACHE_SIZE 256

#define AUDIT_RING_SIZE 65536


#define TLS_HANDSHAKE 22
#define TLS_EXT_ECH 0xfe0d


#define MYSQL_MARIADB 3306

#define POSTGRESQL 5432

#define MSSQL 1433

#define ORACLE 1521

#define MONGODB 27017

#define REDIS 6379


typedef uint32_t ip_addr_t;


static volatile bool force_quit = false;

#define MAX_IP_ENTRIES 65536

struct ip_stats {
    uint64_t syn;      // SYN packets seen
    uint64_t syn_ack;   // SYN-ACK acknowledgments
    uint64_t ack;      // ACK packets seen
    uint64_t rst;      // optional: TCP resets
    uint64_t fin;       // FIN packets

    uint64_t udp;       // udp packets
    uint64_t icmp;      // icmp

    uint64_t bytes;     // bytes
} __attribute__((aligned(64)));

struct ip_entry {
    ip_addr_t ip;
    struct ip_stats stats;
    uint64_t window_start_tsc;
    uint16_t count;
};

struct sovereignty_log {
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    char sni[256];
    const char *service;
    const char *protocol;
    uint32_t s_ip;
    uint32_t d_ip;
    uint64_t timestamp;
    uint32_t bytes;
    uint16_t dst_port;
    uint16_t src_port;
    bool is_data_encrypted;
    bool is_tls_ech_handshake;
};

struct ip_entry entries[MAX_IP_ENTRIES];
struct rte_hash *ip_hash;

static struct rte_ether_addr my_local_mac[RTE_MAX_ETHPORTS];

/* custom port structure for port on network */
struct port_config {
    struct rte_ether_addr mac;  /* Port MAC address */
    struct rte_mempool *arp_pool;   /* Socket-local arp memory pool */
    struct rte_mempool *nat_pool;   /* socket-local NAT memory pool */
    uint32_t gateway_ip;        /* NAT Gateway IP */
    uint32_t net_addr;          /* Network IP address on link */
    uint16_t port_id;
    int socket_id;              /* NUMA Socket ID */
} __attribute__((packed));

//static inline int link_status_callback(uint16_t, enum rte_eth_event_type, void *, void *);
static inline void signal_handler(int);
struct rte_mempool * create_memory_pool(const char *, uint16_t, uint16_t,
        uint16_t, uint16_t, int);
static inline const char *extract_sni(const uint8_t *, size_t, size_t*);
static inline int audit_consumer(void *arg);
static inline const char* port_to_service(uint16_t);
static inline const char* protocol_to_str(uint8_t);
static inline void check_udp_payload_encryption(const uint8_t *, uint16_t, struct sovereignty_log *);
static inline void check_tcp_payload_encryption(const uint8_t *, uint16_t, struct sovereignty_log *);

static inline int load_ipv4_cidrs(struct rte_lpm *, const char *);
static inline int load_ipv6_cidrs(struct rte_lpm6 *, const char *);
static inline const char *map_file(const char*);
static inline struct ip_entry *lookup_ip(uint32_t);
static inline struct ip_entry *create_ip_entry(uint32_t);

static inline bool  is_allowed_udp_port(uint16_t) ;
