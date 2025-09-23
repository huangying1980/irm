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

#define PING_PORT 8887

struct pong_packet {
    size_t      size;
    char*       data;
};

static void pong_usage(void)
{
    fprintf(stderr, "test_pong usage:\n");
    fprintf(stderr, "-t | --type        0:efvi, 1:native. default: 0\n");
    fprintf(stderr, "-p | --pub_cpu     core for pub event loop thread. default: -1\n");
    fprintf(stderr, "-s | --sub_cpu     core for sub event loop thread. default: -1\n");
    fprintf(stderr, "-C | --CPU         core for main. default: -1\n");
    fprintf(stderr, "-n | --count       total of packet\n");
    fprintf(stderr, "-w | --warm        warm of packet\n");
    fprintf(stderr, "-g | --mc_ip       multicase ip of pub\n");
    fprintf(stderr, "-l | --local_ip    local ip\n");
    fprintf(stderr, "-h | --help        usage\n");
    exit(-1);
}

static struct pong_packet* init_pong_pkts(IRM_PUBHANDLE handle, int count)
{
    struct pong_packet* pkts;
    struct pong_msg*    msg;
    int    i;
    
    pkts = (struct pong_packet *)calloc(count, sizeof(struct pong_packet));
    for (i = 0; i < count; ++i) {
        msg = (struct pong_msg *)irm_pub_alloc(handle, &pkts[i].size);        
        if (!msg) {
            fprintf(stderr, "irm_puballoc failed, error %d\n", irm_errno);
            return NULL;
        }
        msg->id = i;
        pkts[i].data = (char *)msg;
    }
    return pkts;    
}

static IRM_PUBHANDLE ping_init(int type, int core_id, const char* mc_ip,
    const char* local_ip)
{
    IRM_PUBHANDLE                handle;
    struct irm_config_cpu        cpu;
    struct irm_config_addr       addr;
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
        fprintf(stderr, "irm_pubsetsockopt cpu failed, error %d\n", ret);
        irm_pub_close(handle, IRM_CLOSE_TYPE_GRACE);
        return 0;
    }

    irm_pub_getsockopt(handle, IRM_CONFIG_TYPE_ADDR, &addr, sizeof(addr));
    addr.local_port = PING_PORT;
    memcpy(addr.mcgroup_ip, mc_ip, strlen(mc_ip));  
    ret = irm_pub_setsockopt(handle, IRM_CONFIG_TYPE_ADDR, &addr, sizeof(addr));
    if (ret < 0) {
        fprintf(stderr, "irm_pubsetsocket addr failed, error %d\n", ret);
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

int test_pong(int argc, char* argv[])
{
    IRM_PUBHANDLE  pub_handle = 0;
    IRM_SUBHANDLE  sub_handle = 0;

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
    int            total_count = 0;
    int            type = IRM_SOCKET_TYPE_NATIVE;

    struct pong_packet* pkts = NULL;
    struct ping_msg*    ping_msg;
    struct pong_msg*    pong_msg;
    
    static struct option long_options[] = {
        {"type", required_argument, 0, 't'},
        {"pub_cpu", required_argument, 0, 'p'},
        {"sub_cpu", required_argument, 0, 's'},
        {"CPU", required_argument, 0, 'C'},
        {"delay", required_argument, 0, 'd'},
        {"count", required_argument, 0, 'n'},
        {"warm", required_argument, 0, 'w'},
        {"mc_ip", required_argument, 0, 'g'},
        {"local_ip", required_argument, 0, 'i'},
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
                fprintf(stderr, "argument error\n");
                pong_usage();
        }
    }

    if (count <= 0 || !mc_ip[0] || !local_ip[0]) {
        pong_usage();
        exit(-1);
    }

    fprintf(stderr, "pong %d packets\n", count);

    ret = test_set_core(cpu);
    if (ret < 0) {
        goto TEST_OUT;
    }

    pub_handle = ping_init(type, pub_cpu, mc_ip, local_ip); 
    if (!pub_handle) {
        goto TEST_OUT;
    }

    sub_handle = pong_init(type, sub_cpu, local_ip, mc_ip);
    if (!sub_handle) {
        goto TEST_OUT;
    }

    total_count = count + warm;
    pkts = init_pong_pkts(pub_handle, total_count);
    if (!pkts) {
        goto TEST_OUT;
    }

    for (i = 0; i < total_count; ++i) {
        do {
            ping_msg = (struct ping_msg *)irm_sub_recv(sub_handle, &data_len);
        } while (!ping_msg);
        //fprintf(stderr, "irm_sub_recv ping msg %lu, %u\n", ping_msg->id, i);

        pong_msg = (struct pong_msg *)pkts[i].data;
        pong_msg->id = ping_msg->id;

        do {
            ret = irm_pub_send(pub_handle, pkts[i].data, sizeof(struct pong_msg));
        } while (ret != IRM_OK);
        //fprintf(stderr, "irm_pub_send pong msg %lu, %u\n", pong_msg->id, i);
        irm_sub_free(sub_handle, ping_msg);
        
    }

    while (1) {
        usleep(500);
    }
TEST_OUT:
    if (pub_handle) {
        irm_pub_close(pub_handle, IRM_CLOSE_TYPE_GRACE);
    }
    if (sub_handle) {
        irm_sub_close(sub_handle, IRM_CLOSE_TYPE_GRACE);
    }
    if (pkts) {
        free(pkts);
    }

    return 0;
}
