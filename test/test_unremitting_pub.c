/* huangying */
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#include "irm_socket.h"
#include "irm_sockopt.h"
#include "irm_error.h"
#include "test_msg.h"
#include "test_time_clock.h"

struct packet {
    size_t  size;
    char* data;
};

int sent = 0;

void sig_handle(int sig)
{
    printf("sent %d\n", sent);
    exit(0);
}

int test_unremitting_pub(int argc, char* argv[])
{
    IRM_PUBHANDLE  handle;
    int            count;
    uint64_t       delay;
    uint64_t       last_ts = 0;
    uint64_t       alloc_failed_n = 0;
    
    int            ret;
    int            i;
    struct packet* packets;
    struct test_time_clock tc;
    struct irm_config_tx tx;
    //struct irm_config_storage st;

    signal(SIGINT, sig_handle);
    printf("%s start\n", argv[0]);
    handle = irm_pub_socket(IRM_SOCKET_TYPE_NATIVE, NULL);    
    //handle = irm_pub_socket(IRM_SOCKET_TYPE_EFVI, NULL);    
    if (!handle) {
        fprintf(stderr, "irm_pubsocket failed, error %d\n", irm_errno);
        return -1;
    }
    /* 
    irm_pub_getsockopt(handle, IRM_CONFIG_TYPE_STORAGE, &st, sizeof(st));
    st.enable = 1;
    irm_pub_setsockopt(handle, IRM_CONFIG_TYPE_STORAGE, &st, sizeof(st));
    */ 
    irm_pub_getsockopt(handle, IRM_CONFIG_TYPE_TX, &tx, sizeof(tx));
    tx.mbuf_count = 4096;
    irm_pub_setsockopt(handle, IRM_CONFIG_TYPE_TX, &tx, sizeof(tx));
    
    ret = irm_pub_bind(handle, argv[1]);
    if (ret != IRM_OK) {
        irm_pub_close(handle, IRM_CLOSE_TYPE_GRACE);
        fprintf(stderr, "irm_pubbind failed, ret %d, error %d\n", ret, irm_errno);
        return -1;
    }
    count = atoi(argv[2]);
    test_time_clock_init(&tc, 0.0);
    delay = test_time_clock_us2cycle(&tc, (uint64_t)atol(argv[3]));
    packets = (struct packet *)calloc(count, sizeof(struct packet));

    for (i = 0; i < count; ++i) {
        do {
            packets[i].data = (char *)irm_pub_alloc(handle, &packets[i].size);
            if (!packets[i].data) {
                ++alloc_failed_n;
                usleep(10);
            }
        } while (!packets[i].data);
        //fprintf(stderr, "packet[%d].size %lu\n", i, packets[i].size);
        printf("alloc failed times %lu\n", alloc_failed_n);
        alloc_failed_n = 0;
        init_msg((struct test_msg *)packets[i].data, i, &packets[i].size);
        printf("send %d packets\n", i);
        
        do {
            ret = irm_pub_send(handle, packets[i].data, packets[i].size);
            if (ret != IRM_OK) {
                printf("irm_pubput failed ret %d, error %d\n",
                    ret, irm_errno);
                usleep(5 * 1000000);
                continue;
            }
            break;
        } while (1);
        ++sent;
        //usleep(delay);
        
        last_ts = test_get_cycle();
        while (test_get_cycle() - last_ts < delay);
        
    }
    while (1) {
        usleep(50 * 1000);
    }

    free(packets);
    irm_pub_close(handle, IRM_CLOSE_TYPE_GRACE);
    return 0;
}
