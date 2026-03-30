#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

#define RX_RING_SIZE 1024
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 256
#define BURST_SIZE 32

static volatile bool force_quit = false;

struct arp_cache_entry {
    uint8_t mac[6];          // The resolved MAC (e.g., the ISP Router)
    uint32_t ip;             // The Target IP we are looking for
    volatile uint8_t valid;  // 1 if resolved, 0 if unknown
} __attribute__((aligned(64)));

struct arp_cache_entry gateway_arp;
struct rte_ether_addr my_local_mac;

static inline void
signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\nSignal received, preparing to exit...\n");
        force_quit = true;
    }
}

static const struct rte_eth_conf port_conf_default = {
    .rxmode = {
        .mq_mode = RTE_ETH_MQ_RX_NONE,       // single queue
        .offloads = 0,                   // adjust RX offloads if needed
        .max_lro_pkt_size = 0,           // only relevant for LRO
    },
    .txmode = {
        .mq_mode = RTE_ETH_MQ_RX_NONE
    }
};

int main(int argc, char **argv)
{
    int ret;
    uint16_t port_id = 0;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // 1. Initialize EAL
    ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    }

    // 2. Check available ports
    uint16_t nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0) {
        rte_exit(EXIT_FAILURE, "No available DPDK ports\n");
    }

    printf("Available ports: %u\n", nb_ports);

    struct rte_eth_dev_info dev_info;
    if (rte_eth_dev_info_get(port_id, &dev_info))
        rte_exit(EXIT_FAILURE, "couldn't get attribute\n");

    printf("using Port %u driver: %s\n", port_id, dev_info.driver_name);

    rte_eth_macaddr_get(port_id, &my_local_mac);

    // 4. NUMA-aware socket
    int socket_id = rte_eth_dev_socket_id(port_id);
    if (socket_id < 0)
        socket_id = 0;

    // 5. Create mempool
    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create(
        "MBUF_POOL",
        NUM_MBUFS,
        MBUF_CACHE_SIZE,
        0,
        RTE_MBUF_DEFAULT_BUF_SIZE,
        socket_id
    );

    if (mbuf_pool == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
    }

    // 6. Configure device
    struct rte_eth_conf port_conf = port_conf_default;
    ret = rte_eth_dev_configure(port_id, 1, 0, &port_conf);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Cannot configure device\n");
    }

    // 7. Setup RX queue
    ret = rte_eth_rx_queue_setup(
        port_id,
        0,
        RX_RING_SIZE,
        socket_id,
        NULL,
        mbuf_pool
    );
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "RX queue setup failed\n");
    }

    // 8. Start device
    ret = rte_eth_dev_start(port_id);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Device start failed\n");
    }

    // 9. Enable promiscuous mode
    rte_eth_promiscuous_enable(port_id);

    printf("Initialization complete. Receiving packets...\n");

    struct rte_mbuf *bufs[BURST_SIZE];
    struct rte_eth_stats stats;

    uint64_t last_stat_print = 0;

    while (!force_quit) {
        uint16_t nb_rx = rte_eth_rx_burst(port_id, 0, bufs, BURST_SIZE);

        if (nb_rx > 0) {
            printf("Received %" PRIu16 " packets\n", nb_rx);
            int i;

            for (i = 0; i < nb_rx; i++) {
                rte_prefetch0(rte_pktmbuf_mtod(bufs[i], void *));

                // future: prefetch NAT entry too
                // If you have a huge NAT table, prefetch the hash entry too
                // rte_prefetch0(lookup_table_entry_for_this_packet);
            }


            for (int i = 0; i < nb_rx; i++) {
                struct rte_mbuf *m = bufs[i];

                // 2. MTOD: Get the pointer to the start of the Ethernet Header.
                // This triggers the 64-byte fetch into one of your 512 L1 slots.
                struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

                uint16_t eth_type = eth_hdr->ether_type; // Already in Big Endian from wire

                if (likely(eth_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))) {
                    struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
                    // This is the "Straight Track" - No braking
                    //do_nat_surgery();
                    //rte_eth_tx_burst(WAN_PORT, 0, &m, 1);
                    printf("IPv4 received\n");
                    continue;
                }
                else if (unlikely(eth_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP))) {

                    struct rte_arp_hdr *arp = rte_pktmbuf_mtod_offset(m, struct rte_arp_hdr *, sizeof(struct rte_ether_hdr));

                    // CASE A: Someone is asking for OUR MAC (ARP Request)
                    if (arp->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST)) {
                        // "Recycle" the packet: Swap MACs and IPs in place
                        // Swap Ethernet Addresses
                        rte_ether_addr_copy(&eth_hdr->src_addr, &eth_hdr->dst_addr);
                        rte_ether_addr_copy(&my_local_mac, &eth_hdr->src_addr);

                        // Swap ARP Data
                        arp->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
                        rte_ether_addr_copy(&arp->arp_data.arp_sha, &arp->arp_data.arp_tha); // Target becomes old Sender
                        rte_ether_addr_copy(&my_local_mac, &arp->arp_data.arp_sha);         // Sender becomes Us

                        uint32_t temp_ip = arp->arp_data.arp_sip;
                        arp->arp_data.arp_sip = arp->arp_data.arp_tip;
                        arp->arp_data.arp_tip = temp_ip;

                        // Send it right back out the port it came from
                        rte_eth_tx_burst(port_id, 0, &m, 1);
                        printf("ARP reply sent\n");
                        continue;
                    // The CPU prepares for this to be false
                    }

                    // CASE B: The Router is giving us ITS MAC (ARP Reply)
                    if (arp->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REPLY)) {
                        // Update our Shadow Table so the NAT cores can see it
                        if (arp->arp_data.arp_sip == gateway_arp.ip) {
                            rte_memcpy(gateway_arp.mac, &arp->arp_data.arp_sha, 6);
                            gateway_arp.valid = 1;
                        }
                        rte_pktmbuf_free(m);
                        continue;
                    }
                }
                else {
                    // The "Trash Can" for everything else
                    rte_pktmbuf_free(m);
                    continue;
                }

                // 4. FREE: Once done, the cache line is marked as 'dirty' or 'freeable'
                rte_pktmbuf_free(m);

                printf("  Packet length: %u bytes\n",
                       rte_pktmbuf_pkt_len(bufs[i]));
            }
        }

        // Print stats periodically
        uint64_t now = rte_get_timer_cycles();
        if (now - last_stat_print > rte_get_timer_hz()) {
            rte_eth_stats_get(port_id, &stats);

            printf("=== NIC stats ===\n");
            printf("RX packets: %" PRIu64 "\n", stats.ipackets);
            printf("RX dropped: %" PRIu64 "\n", stats.imissed);
            printf("=================\n");

            last_stat_print = now;
        }
    }

    rte_eth_dev_stop(port_id);
    rte_eth_dev_close(port_id);

    printf("Bye!\n");
    return 0;
}