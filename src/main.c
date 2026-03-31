#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include "local.h"

/* custom port structure for port on network */
struct port_config {
    uint16_t port_id;
    uint32_t gateway_ip;        /* NAT Gateway IP */
    uint32_t net_addr;          /* Network IP address on link */
    struct rte_ether_addr mac;  /* Port MAC address */
    struct rte_mempool *arp_pool;   /* Socket-local arp memory pool */
    struct rte_mempool *nat_pool;   /* socket-local NAT memory pool */
    int socket_id;              /* NUMA Socket ID */
};

static inline int link_status_callback(uint16_t, enum rte_eth_event_type, void *, void *);
static inline void signal_handler(int);
struct rte_mempool * create_memory_pool(const char *, uint16_t, uint16_t,
        uint16_t, uint16_t, int);
static inline void send_announce_arp(uint16_t, struct port_config *);

static const struct rte_eth_conf port_conf_default = {
    .rxmode = {
        /* Enable Multi-Queue to separate ARP (Queue 1) from NAT (Queue 0) */
        .mq_mode = RTE_ETH_MQ_RX_RSS,
        .offloads = 0,                   // adjust RX offloads if needed
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key = NULL,
            .rss_hf = RTE_ETH_RSS_IP, // Default hashing for IP traffic
        },
    },
    .txmode = {
        .mq_mode = RTE_ETH_MQ_RX_NONE
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
    uint16_t socket_ids[RTE_MAX_ETHPORTS];
    uint16_t socket_id;
    uint16_t nb_ports[RTE_MAX_ETHPORTS];
    struct rte_eth_dev_info dev_info[RTE_MAX_ETHPORTS];
    struct rte_mempool *mbuf_nat_pool, *mbuf_arp_pool;
    struct rte_eth_txconf txq_conf;
    struct rte_eth_conf port_conf = port_conf_default;
    struct rte_mbuf *bufs[BURST_SIZE];
    struct rte_eth_stats stats;
    uint64_t last_stat_print = 0;
    struct port_config net_port[RTE_MAX_ETHPORTS];


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

    for (int port_id = 0; port_id < nb_ports; port_id++) {

        if (rte_eth_dev_info_get(i, &(dev_info[port_id])))
            rte_exit(EXIT_FAILURE, "couldn't get attribute of port %d driver %s\n", port_id, dev_info[i].driver_name);

        if (rte_eth_macaddr_get(i, &(my_local_mac[port_id])))
            rte_exit(EXIT_FAILURE, "couldn't get mac address of port %d driver %s\n", port_id, dev_info[i].driver_name);

        socket_id = rte_eth_dev_socket_id(port_id);
        if (socket_id == SOCKET_ID_ANY)
            socket_id = 0;

        socket_ids[port_id] = socket_id; // keep track of a port => socket id map

        // create mempool for NAT
        mbuf_nat_pool = create_memory_pool(
            "NAT_MBUF_POOL_",
            NUM_MBUFS,
            MBUF_CACHE_SIZE,
            0,
            RTE_MBUF_DEFAULT_BUF_SIZE,
            socket_id
        );

        if (mbuf_nat_pool == NULL) {
            rte_exit(EXIT_FAILURE, "Cannot create NAT mbuf pool\n");
        }

        mbuf_arp_pool = create_memory_pool(
            "ARP_MBUF_POOL_",
            NUM_MBUFS_ARP,
            MBUF_CACHE_SIZE_ARP,
            0,
            ARP_MBUF_DATA_SIZE,
            socket_id
        );

        if (mbuf_arp_pool == NULL) {
            rte_exit(EXIT_FAILURE, "Cannot create ARP mbuf pool\n");
        }

        ret = rte_eth_dev_configure(port_id, 2, 2, &port_conf);
        if (ret < 0) {
            rte_exit(EXIT_FAILURE, "Cannot configure device on port %d\n", port_id);
        }

        // Setup NAT RX queue
        ret = rte_eth_rx_queue_setup(
            port_id,
            0,
            RX_NAT_RING_SIZE,
            socket_id,
            NULL,
            mbuf_nat_pool
        );
        if (ret < 0) {
            rte_exit(EXIT_FAILURE, "NAT RX queue setup failed\n");
        }

        // setup RX queue for ARP
        ret = rte_eth_rx_queue_setup(
            port_id,
            1,
            RX_ARP_RING_SIZE,
            socket_id,
            NULL,
            mbuf_arp_pool
        );
        if (ret < 0) {
            rte_exit(EXIT_FAILURE, "ARP RX queue setup failed\n");
        }

        /* setup TX queue */
        txq_conf = dev_info.default_txconf;
        txq_conf.offloads = port_conf.txmode.offloads;

        // NAT
        ret = rte_eth_tx_queue_setup(
            port_id,
            0,           // Queue index 0
            TX_NAT_RING_SIZE,
            socket_id,
            &txq_conf
        );
        if (ret < 0) {
            rte_exit(EXIT_FAILURE, "NAT TX queue setup failed: err=%d, port=%u\n", ret, port_id);
        }

        // ARP
        ret = rte_eth_tx_queue_setup(
            port_id,
            1,           // Queue index 0
            TX_ARP_RING_SIZE,
            socket_id,
            &txq_conf
        );
        if (ret < 0) {
            rte_exit(EXIT_FAILURE, "ARP TX queue setup failed: err=%d, port=%u\n", ret, port_id);
        }

        net_port[port_id].port_id = port_id;
        net_port[port_id].gateway_ip = rte_cpu_to_be_32(RTE_IPV4(192, 168, 100, 1));
        net_port[port_id].net_addr = rte_cpu_to_be_32(RTE_IPV4(192, 168, 100, 67));
        net_port[port_id].mac = my_local_mac[port_id];
        net_port[port_id].arp_pool = mbuf_arp_pool;
        net_port[port_id].nat_pool = mbuf_nat_pool;
        net_port[port_id].socket_id = socket_id;

        ret = rte_eth_dev_callback_register(port_id, RTE_ETH_EVENT_INTR_LSC, link_status_callback, &net_port[i]);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "callback registering failed: err=%d, port=%u\n", ret, port_id);

        ret = rte_eth_dev_start(port_id);
        if (ret < 0) {
            rte_exit(EXIT_FAILURE, "Device %d start failed on err=%d\n", port_id, ret );
        }

        // 9. Enable promiscuous mode
        ret = rte_eth_promiscuous_enable(port_id);
        if (ret < 0) {
            rte_exit(EXIT_FAILURE, "promiscuous mode on device %d failed on err=%d\n", port_id, ret);
        }

    }

    printf("Initialization complete. Receiving packets...\n");

    while (!force_quit) {
        uint16_t nb_rx = rte_eth_rx_burst(0, 0, bufs, BURST_SIZE);

        if (nb_rx > 0) {
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

                uint16_t eth_type = eth_hdr->ether_type; // Already in Big Endian from wire

                if (likely(eth_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))) {
                    printf("IP\n");
                    struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
                    // This is the "Straight Track" - No braking
                    //do_nat_surgery();
                    //rte_eth_tx_burst(WAN_PORT, 0, &m, 1);
                    printf("IPv4 received\n");
                    continue;
                }
                else if (unlikely(eth_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP))) {
                    printf("ARP\n");

                    struct rte_arp_hdr *arp = rte_pktmbuf_mtod_offset(m, struct rte_arp_hdr *, sizeof(struct rte_ether_hdr));
                    uint32_t target_ip = rte_be_to_cpu_32(arp->arp_data.arp_tip);

                    // CASE A: Someone is asking for OUR MAC (ARP Request), reply if ours
                    if (arp->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST) && (target_ip == net_port[0].net_addr)) {
                        printf("REQUEST\n");
                        // "Recycle" the packet: Swap MACs and IPs in place
                        // Swap Ethernet Addresses
                        rte_ether_addr_copy(&eth_hdr->src_addr, &eth_hdr->dst_addr);
                        rte_ether_addr_copy(&my_local_mac[0], &eth_hdr->src_addr);

                        printf("one?\n");
                        // Swap ARP Data
                        arp->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
                        rte_ether_addr_copy(&arp->arp_data.arp_sha, &arp->arp_data.arp_tha); // Target becomes old Sender
                        rte_ether_addr_copy(&my_local_mac[0], &arp->arp_data.arp_sha);         // Sender becomes Us

                        printf("two?\n");

                        uint32_t temp_ip = arp->arp_data.arp_sip;
                        arp->arp_data.arp_sip = arp->arp_data.arp_tip;
                        arp->arp_data.arp_tip = temp_ip;

                        printf("three?\n");

                        // Send it right back out the port it came from
                        rte_eth_tx_burst(0, 1, &m, 1);
                        printf("ARP reply sent\n");
                        continue;
                    // The CPU prepares for this to be false
                    }
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

struct rte_mempool *
create_memory_pool(const char *sig, uint16_t cnt, uint16_t cache_size,
        uint16_t priv_size, uint16_t data_room_size, int sock_id)
{
    char pool_name[32];
    struct rte_mempool *mp;
    int ret;

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

static inline int
link_status_callback(uint16_t port_id, enum rte_eth_event_type type, void *param, void *ret_param)
{
    struct rte_eth_link link;
    struct port_config *conf = (struct port_config *)param;
    int ret;

    /* Check the link state without blocking the interrupt thread */
    ret = rte_eth_link_get_nowait(port_id, &link);
    if (ret < 0) {
        printf("Port %u: Failed to get link (error %d)\n", port_id, ret);
        return ret;
    }

    if (link.link_status == RTE_ETH_LINK_UP) {
        printf("Port %u Link Up - speed %u Mbps - %s\n",
               port_id, link.link_speed,
               (link.link_duplex == RTE_ETH_LINK_FULL_DUPLEX) ? "full-duplex" : "half-duplex");

        /* send ARPs to announce presence */
        send_announce_arp(port_id, conf);
    } else {
        printf("Port %u Link Down\n", port_id);
    }
    return 0;
}

static inline void
send_announce_arp(uint16_t port_id, struct port_config *conf) {
    struct rte_mbuf *m = rte_pktmbuf_alloc(conf->arp_pool);
    if (!m) return;

    /* 1. Ethernet Header */
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    rte_eth_macaddr_get(port_id, &eth_hdr->src_addr);
    memset(&eth_hdr->dst_addr, 0xFF, 6); // Broadcast
    eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);

    /* 2. ARP Header */
    struct rte_arp_hdr *arp_hdr = (struct rte_arp_hdr *)(eth_hdr + 1);
    arp_hdr->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
    arp_hdr->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    arp_hdr->arp_hlen = 6;
    arp_hdr->arp_plen = 4;
    arp_hdr->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY); // "I am..."

    /* Sender: My MAC / My IP */
    rte_eth_macaddr_get(port_id, &arp_hdr->arp_data.arp_sha);
    arp_hdr->arp_data.arp_sip = conf->net_addr;

    /* Target: Broadcast / My IP (Gratuitous style) */
    memset(&arp_hdr->arp_data.arp_tha, 0, 6);
    arp_hdr->arp_data.arp_tip = conf->gateway_ip;

    /* 3. Set Packet Length and Send */
    m->pkt_len = m->data_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
    rte_eth_tx_burst(port_id, 1, &m, 1);
}

static inline void
signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\nSignal received, preparing to exit...\n");
        force_quit = true;
    }
}
