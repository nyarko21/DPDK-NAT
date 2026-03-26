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

static void
signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\nSignal received, preparing to exit...\n");
        force_quit = true;
    }
}

static const struct rte_eth_conf port_conf_default = {
    .rxmode = {
        .mq_mode = ETH_MQ_RX_NONE,       // single queue
        .offloads = 0,                   // adjust RX offloads if needed
        .max_lro_pkt_size = 0,           // only relevant for LRO
    },
    .txmode = {
        .mq_mode = ETH_MQ_TX_NONE
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

            for (int i = 0; i < nb_rx; i++) {
                printf("  Packet length: %u bytes\n",
                       rte_pktmbuf_pkt_len(bufs[i]));

                rte_pktmbuf_free(bufs[i]);
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

    // Cleanup
    printf("Stopping port...\n");
    rte_eth_dev_stop(port_id);
    rte_eth_dev_close(port_id);

    printf("Bye!\n");
    return 0;
}