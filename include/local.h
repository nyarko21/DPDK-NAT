#define RX_NAT_RING_SIZE 1024
#define TX_NAT_RING_SIZE 1024
#define RX_ARP_RING_SIZE 64
#define TX_ARP_RING_SIZE 64
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 256
#define BURST_SIZE 32

/* ARP/Management Pool Constants */
#define NUM_MBUFS_ARP          1023    /* Sufficient for control plane bursts */
#define MBUF_CACHE_SIZE_ARP    32      /* Small cache for a single service core */
#define ARP_MBUF_DATA_SIZE     512     /* ARP packets are ~64 bytes; no need for 2KB */

struct arp_cache_entry {
    uint8_t mac[6];          // The resolved MAC (e.g., the ISP Router)
    uint32_t ip;             // The Target IP we are looking for
    volatile uint8_t valid;  // 1 if resolved, 0 if unknown
} __attribute__((aligned(64)));


static volatile bool force_quit = false;
static volatile uint8_t port_needs_arp_announcement[RTE_MAX_ETHPORTS] = {0};

static struct arp_cache_entry gateway_arp;
static struct rte_ether_addr my_local_mac[RTE_MAX_ETHPORTS];
