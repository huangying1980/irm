/* huangying */
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>

#include "irm_socket.h"
#include "irm_error.h"
#include "irm_sockopt.h"
#include "test_msg.h"
#include "test_time_clock.h"

#define PONG_PORT 8887


struct ping_packet {
    size_t      size;
    char*       data;
};
struct latency {
    uint64_t    start;
    uint64_t    end;
};
struct latency* latency = NULL;
static void ping_usage(void)
{
    fprintf(stderr, "test_ping usage:\n");
    fprintf(stderr, "-t | --type        0:efvi, 1:native. default: 0\n");
    fprintf(stderr, "-p | --pub_cpu     core for pub event loop thread. default: -1\n");
    fprintf(stderr, "-s | --sub_cpu     core for sub event loop thread. default: -1\n");
    fprintf(stderr, "-C | --CPU         core for main. default: -1\n");
    fprintf(stderr, "-n | --count       total of packet\n");
    fprintf(stderr, "-n | --warm        warm of packet\n");
    fprintf(stderr, "-d | --delay       delay of per packet. default: 0\n");
    fprintf(stderr, "-g | --mc_ip       multicase ip of pub\n");
    fprintf(stderr, "-l | --local_ip    local ip\n");
    fprintf(stderr, "-h | --help        usage\n");
} 

static void init_ping_msg(struct ping_msg* msg, uint64_t id)
{
    msg->id = id;
    msg->size = 256;
    memset(msg->data, 'p', PING_MSG_DATA_SIZE);
}

static IRM_PUBHANDLE ping_init(int type, int core_id, const char* local_ip)
{
    IRM_PUBHANDLE                handle;
    struct irm_config_cpu        cpu;
    struct irm_config_tx         tx;
    int                          ret;

    handle = irm_pub_socket(type, NULL);
    if (!handle) {
        fprintf(stderr, "ping_init failed, irm_pubsocket error %d\n",
            irm_errno);
        return handle;
    }

    irm_pub_getsockopt(handle, IRM_CONFIG_TYPE_CPU, &cpu, sizeof(cpu));
    cpu.cpu_id = core_id;
    cpu.rt = 0;
    ret = irm_pub_setsockopt(handle, IRM_CONFIG_TYPE_CPU, &cpu, sizeof(cpu));
    if (ret < 0) {
        fprintf(stderr, "irm_pub_setsockopt cpu failed, error %d\n", ret);
        irm_pub_close(handle, IRM_CLOSE_TYPE_GRACE);
        return 0;
    }

    irm_pub_getsockopt(handle, IRM_CONFIG_TYPE_TX, &tx, sizeof(tx));
    tx.mbuf_count = 1U << 14;
    ret = irm_pub_setsockopt(handle, IRM_CONFIG_TYPE_TX, &tx, sizeof(tx));
    if (ret < 0) {
        fprintf(stderr, "irm_pub_setsockopt tx failed, error %d\n", ret);
        irm_pub_close(handle, IRM_CLOSE_TYPE_GRACE);
        return 0;
    }

    ret = irm_pub_bind(handle, local_ip);
    if (ret != IRM_OK) {
        fprintf(stderr, "irm_pubbind failed, error %d", ret);
        irm_pub_close(handle, IRM_CLOSE_TYPE_GRACE);
        return 0;
    }

    return handle;
}

static IRM_SUBHANDLE pong_init(int type, int core_id, const char* local_ip,
    const char* mc_ip)
{
    IRM_SUBHANDLE                handle;
    struct irm_config_cpu        cpu;
    struct irm_config_addr       addr;
    struct irm_config_rx         rx;
    int                          ret;

    handle = irm_sub_socket(type, NULL);
    if (!handle) {
        fprintf(stderr, "pong_init failed, irm_subsocket error %d\n",
            irm_errno);
        return handle;
    }

    irm_sub_getsockopt(handle, IRM_CONFIG_TYPE_CPU, &cpu, sizeof(cpu));
    cpu.cpu_id = core_id;
    cpu.rt = 0;
    ret = irm_sub_setsockopt(handle, IRM_CONFIG_TYPE_CPU, &cpu, sizeof(cpu));
    if (ret < 0) {
        fprintf(stderr, "irm_subsetsockopt cpu failed, error %d\n", ret);
        irm_sub_close(handle, IRM_CLOSE_TYPE_GRACE);
        return 0;
    }
    
    irm_sub_getsockopt(handle, IRM_CONFIG_TYPE_ADDR, &addr, sizeof(addr));
    addr.local_port = PONG_PORT;
    memcpy(addr.mcgroup_ip, mc_ip, strlen(mc_ip));  
    ret = irm_sub_setsockopt(handle, IRM_CONFIG_TYPE_ADDR, &addr, sizeof(addr));
    if (ret < 0) {
        fprintf(stderr, "irm_subsetsocket addr failed, error %d\n", ret);
        irm_sub_close(handle, IRM_CLOSE_TYPE_GRACE);
        return 0;
    }

    irm_sub_getsockopt(handle, IRM_CONFIG_TYPE_RX, &rx, sizeof(rx));
    rx.mbuf_count = 1U << 14;
    ret = irm_sub_setsockopt(handle, IRM_CONFIG_TYPE_RX, &rx, sizeof(rx));
    if (ret < 0) {
        fprintf(stderr, "irm_subsetsocket rx failed, error %d\n", ret);
        irm_sub_close(handle, IRM_CLOSE_TYPE_GRACE);
        return 0;
    }

    ret = irm_sub_bind(handle, local_ip);
    if (ret != IRM_OK) {
        fprintf(stderr, "irm_subbind failed, error %d", ret);
        irm_sub_close(handle, IRM_CLOSE_TYPE_GRACE);
        return 0;
    }

    return handle;
}

static struct ping_packet* init_pkts(IRM_PUBHANDLE handle, int count)
{
    struct ping_packet* pkts;
    int                 i;
    pkts = (struct ping_packet *)calloc(count, sizeof(struct ping_packet));
    for (i = 0; i < count; ++i) {
        pkts[i].data = (char *)irm_pub_alloc(handle, &pkts[i].size);
        if (!pkts[i].data) {
            fprintf(stderr, "irm_pub_alloc failed error %d\n", irm_errno);
            return NULL;
        }
        init_ping_msg((struct ping_msg *)pkts[i].data, i);
    } 

    return pkts;
}

int test_ping(int argc, char* argv[])
{
    IRM_PUBHANDLE  pub_handle = 0;
    IRM_SUBHANDLE  sub_handle = 0;

    uint64_t       last_ts = 0;
    uint64_t       curr_ts = 0;
    uint64_t       cycle = 0;
    
    size_t         data_len;

    int            ret;
    int            i;
    int            c;
    int            index = 0;

    char           local_ip[16] = {0};
    char           mc_ip[16] = {0};
    int            pub_cpu = -1;
    int            sub_cpu = -1;
    int            cpu = -1;
    int            count = 0;
    int            warm = 0;
    int            total;
    int            type = IRM_SOCKET_TYPE_NATIVE;
    uint64_t       delay = 0;
    uint64_t       ping_ts;
    uint64_t       pong_ts;

    struct ping_packet*      pkts = NULL;
    struct pong_msg*         pong_msg;
    struct ping_msg*         ping_msg;
    struct test_time_clock   tc;
    

    static struct option long_options[] = {
        {"type", required_argument, 0, 't'},
        {"pub_cpu", required_argument, 0, 'p'},
        {"sub_cpu", required_argument, 0, 's'},
        {"CPU", required_argument, 0, 'C'},
        {"delay", required_argument, 0, 'd'},
        {"count", required_argument, 0, 'n'},
        {"mc_ip", required_argument, 0, 'g'},
        {"local_ip", required_argument, 0, 'l'},
        {"warm", required_argument, 0, 'w'},
        {"help", no_argument, 0, 'h'},
        {NULL, 0, 0, 0},
    }; 

    while (1) {
        c = getopt_long(argc, argv, "t:p:s:C:d:n:g:l:w:h", long_options, &index);
        if (c == -1) {
            break;
        }
        switch (c) {
            case 't':
                type = atoi(optarg);
                break;
            case 'p':
                pub_cpu = atoi(optarg);
                break;
            case 's':
                sub_cpu = atoi(optarg);
                break;
            case 'C':
                cpu = atoi(optarg);
                break;
            case 'd':
                delay = atol(optarg);                
                break;
            case 'n':
                count = atoi(optarg);
                break;
            case 'w':
                warm = atoi(optarg);
                break;
            case 'g':
                snprintf(mc_ip, 16, "%s", optarg);
                break;
            case 'l':
                snprintf(local_ip, 16, "%s", optarg);
                break;
            case 'h':
            default:
                ping_usage();
                exit(0);
        }
    }

    if (count <= 0 || !mc_ip[0] || !local_ip[0]) {
        ping_usage();
        exit(-1);
    }
    fprintf(stderr, "ping %d packets\n", count);

    ret = test_set_core(cpu);
    if (ret < 0) {
        goto TEST_OUT;
    }

    test_time_clock_init(&tc, 0.0);
    
    if (delay) {
        cycle = test_time_clock_us2cycle(&tc, delay);
    } else {
        cycle = 0;
    }
    
    pub_handle = ping_init(type, pub_cpu, local_ip); 
    if (!pub_handle) {
        fprintf(stderr, "pub_handle init failed\n");
        goto TEST_OUT;
    }

    sub_handle = pong_init(type, sub_cpu, local_ip, mc_ip);
    if (!sub_handle) {
        fprintf(stderr, "sub_handle init failed\n");
        goto TEST_OUT;
    }

    total = count + warm;
    pkts = init_pkts(pub_handle, total);
    if (!pkts) {
        fprintf(stderr, "init_pkts failed\n");
        goto TEST_OUT;
    }
    latency = (struct latency *)malloc(sizeof(struct latency) * total);
    memset(latency, 0, sizeof(struct latency) * total);
    
    sleep(5);
    for (i = 0; i < total; ++i) {
        latency[i].start = test_get_cycle();
        do {
            ping_msg = (struct ping_msg *)pkts[i].data,
            ret = irm_pub_send(pub_handle, ping_msg, ping_msg->size);
        } while (ret != IRM_OK);
        //fprintf(stderr, "irm_pub_send ping msg %lu, %u\n", ping_msg->id, i);

        do {
            pong_msg = (struct pong_msg *)irm_sub_recv(sub_handle, &data_len);
        } while (!pong_msg);

        //fprintf(stderr, "irm_sub_recv pong msg %lu, %u\n", pong_msg->id, i);
        //latency[pong_msg->id].end = test_get_cycle();
        latency[i].end = test_get_cycle();
        irm_sub_free(sub_handle, pong_msg);
        
        last_ts = curr_ts = test_get_cycle();
        while (curr_ts - last_ts < cycle) {
            curr_ts = test_get_cycle();
        }
        
    }

    for (i = warm; i < total; ++i) {
        ping_ts = test_time_clock_cycle2ns(&tc, latency[i].start);
        pong_ts = test_time_clock_cycle2ns(&tc, latency[i].end);
        printf("ping_ts %lu, pong_ts %lu, %d,%lu\n", ping_ts, pong_ts, i - warm, pong_ts - ping_ts);
    }

TEST_OUT:
    if (pub_handle) {
        fprintf(stderr, "close pub_handle\n");
        irm_pub_close(pub_handle, IRM_CLOSE_TYPE_GRACE);
    }
    if (sub_handle) {
        fprintf(stderr, "close sub_handle\n");
        irm_sub_close(sub_handle, IRM_CLOSE_TYPE_GRACE);
    }
    if (pkts) {
        fprintf(stderr, "free pkts\n");
        free(pkts);
    }

    return 0;
}
