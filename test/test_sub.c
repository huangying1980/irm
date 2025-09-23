/* huangying */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "irm_socket.h"
#include "irm_error.h"

#include "test_msg.h"


int test_sub(int argc, char* argv[])
{
    IRM_SUBHANDLE    handle;
    void*            data;
    size_t           data_len;
    int              ret;
    int              count;

    handle = irm_sub_socket(IRM_SOCKET_TYPE_NATIVE, NULL);
    if (!handle) {
        fprintf(stderr, "irm_subsocket failed, err %d\n", irm_errno);
        return -1;
    }
    ret = irm_sub_bind(handle, argv[1]); 
    if (ret != IRM_OK) {
        irm_sub_close(handle, IRM_CLOSE_TYPE_GRACE);
        fprintf(stderr, "irm_subbind failed, ret %d, err %d\n", ret, irm_errno);
        return -1;
    }
    count = atoi(argv[2]);
    while (count) {
        data = irm_sub_recv(handle, &data_len);
        if (!data) {
            //fprintf(stderr, "irm_subget no data\n");
            usleep(50 * 1000);
            continue;
        }
        print_msg((struct test_msg *)data);
        irm_sub_free(handle, data);
        --count;
    } 
    irm_sub_close(handle, IRM_CLOSE_TYPE_GRACE);
    return 0;
}
    
