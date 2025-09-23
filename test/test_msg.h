/* huangying */
#ifndef TEST_MSG_H
#define TEST_MSG_H

#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <sys/syscall.h>

#define TEST_MSG_DATA_SIZE (256 - sizeof(struct test_msg))
struct test_msg {
    uint64_t    id;
    uint16_t    key; 
    uint32_t    val;
    size_t      size;
    char        data[0];
}__attribute__((packed));

#define PING_MSG_DATA_SIZE (256 - sizeof(struct ping_msg))
struct ping_msg {
    uint64_t    id;
    uint64_t    size;
    char        data[0]; 
}__attribute__((packed));

struct pong_msg {
    uint64_t    id;
}__attribute__((packed));

void print_msg(struct test_msg* msg);
void init_msg(struct test_msg* msg, uint64_t id, size_t* size);
int test_pub(int argc, char* argv[]);
int test_unremitting_pub(int argc, char* argv[]);
int test_sub(int argc, char* argv[]);
int test_set_core(int core_id);

int test_ping(int argc, char* argv[]);
int test_pong(int argc, char* argv[]);
#endif
