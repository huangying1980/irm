/* huangying */
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

#include "irm_socket.h"
#include "irm_error.h"
#include "test_msg.h"
#include "test_time_clock.h"

struct packet {
    size_t  size;
    char*   data;
};

int test_pub(int argc, char* argv[])
{
    IRM_PUBHANDLE  handle;
    int            count;
    uint64_t       delay;
    uint64_t       last_ts = 0;
    
    int            ret;
    int            i;
    struct packet* packets;
    struct test_time_clock tc;

    handle = irm_pub_socket(IRM_SOCKET_TYPE_NATIVE, NULL);    
    //handle = irm_pub_socket(IRM_SOCKET_TYPE_EFVI, NULL);    
    if (!handle) {
        fprintf(stderr, "irm_pubsocket failed, error %d\n", irm_errno);
        return -1;
    }
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
    //memset(packets, 0, sizeof(packet) * count);
    sleep(20);

    for (i = 0; i < count; ++i) {
        packets[i].data = (char *)irm_pub_alloc(handle, &packets[i].size);
        //packets[i].data = (char *)irm_pub_alloc(handle, &size);
        if (!packets[i].data) {
            fprintf(stderr, "irm_pubget failed error %d\n", irm_errno);
            irm_pub_close(handle, IRM_CLOSE_TYPE_GRACE); 
            free(packets);
            return -1;
        }
        //fprintf(stderr, "packet[%d].size %lu\n", i, packets[i].size);
        //packets[i].size = size;
        init_msg((struct test_msg *)packets[i].data, i, &packets[i].size);
    } 
    fprintf(stderr, "sent %d packets\n", i);
    #if 1 
    for (i = 0; i < count; ++i) {
        
        do {
            ret = irm_pub_send(handle, packets[i].data, packets[i].size);
            if (ret != IRM_OK) {
                /*
                fprintf(stderr, "irm_pubput failed ret %d, error %d\n",
                    ret, irm_errno);
                */
                //usleep(5 * 1000000);
                continue;
            }
            break;
        } while (1);
        
        last_ts = test_get_cycle();
        while (test_get_cycle() - last_ts < delay);
    }
    #endif
    /*
    while (1) {
        usleep(50 * 1000);
    }
    */
    sleep(2);
    printf("pub close\n");
    irm_pub_close(handle, IRM_CLOSE_TYPE_GRACE);
    free(packets);
    return 0;
}
