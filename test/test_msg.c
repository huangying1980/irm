/* huangying */
#include <string.h>
#include <stdio.h>

#include "test_msg.h"

void init_msg(struct test_msg* msg, uint64_t id, size_t* size)
{
    const char* str = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    size_t i;
    int len = strlen(str);

    msg->id = id;
    msg->key = 122;   
    msg->val = 456;
    for (i = 0; i < TEST_MSG_DATA_SIZE - 1 && i <* size - 1; ++i) {
        msg->data[i] = str[i % len];    
    }
    msg->data[i] = 0;
    msg->size = i + 1;
    *size = msg->size + sizeof(struct test_msg);
}

void print_msg(struct test_msg* msg)
{
    printf("msg id %lu\n", msg->id);    
    printf("msg key %u\n", msg->key);    
    printf("msg val %u\n", msg->val);    
    printf("msg data size %lu\n", msg->size);    
    printf("msg data %s\n", msg->data);
}

int test_set_core(int core_id)
{
    cpu_set_t   cpuset;
    pid_t       tid;
    int         ret;


    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);

    tid = syscall(SYS_gettid);

    ret = sched_setaffinity(tid, sizeof(cpuset), &cpuset);
    if(ret != 0) {
        fprintf(stderr, "set_core failed, core_id %d, tid %d, error %s",
            core_id, tid, strerror(errno));
        return -1;
    }
    return 0;
}
