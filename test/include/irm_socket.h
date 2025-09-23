/* huangying */
#ifndef IRM_SOCKET_H
#define IRM_SOCKET_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus 
extern "C" {
#endif

#ifdef IRM_SOCK_DISABLE_HOT_CALL
#define IRM_SOCK_HOT_CALL
#else
#define IRM_SOCK_HOT_CALL __attribute__((hot))
#endif

#ifndef IRM_IFNAME_MAX_LEN
#define IRM_IFNAME_MAX_LEN (32)
#endif

#ifndef IRM_IP_MAX_LEN
#define IRM_IP_MAX_LEN (16)
#endif

#ifndef IRM_NAME_MAX_LEN
#define IRM_NAME_MAX_LEN (8)
#endif

enum {
    IRM_SOCKET_TYPE_NATIVE = 0,

#ifdef IRM_ENABLE_EFVI
    IRM_SOCKET_TYPE_EFVI,
#endif

#ifdef IRM_ENABLE_DPDK
    IRM_SOCKET_TYPE_DPDK,
#endif

#ifdef IRM_ENABLE_XDP
    IRM_SOCKET_TYPE_XDP,
#endif

    IRM_SOCKET_TYPE_MAX
};

enum {
    IRM_CLOSE_TYPE_NOW = 0,
    IRM_CLOSE_TYPE_WAIT,
    IRM_CLOSE_TYPE_GRACE
};


typedef unsigned long IRM_SUBHANDLE;
typedef unsigned long IRM_PUBHANDLE;

/*
 * set environment IRM_HUGEPAGE_HOME for hugepage
 * example:
 * IRM_HUGEPAGE_HOME=${hugepage_mount_point_path}
 */

IRM_PUBHANDLE irm_pub_socket(int type, const char* path);
int irm_pub_bind(IRM_PUBHANDLE handle, const char* local_ip);
int irm_pub_close(IRM_PUBHANDLE handle, int flags);
IRM_SOCK_HOT_CALL void* irm_pub_alloc(IRM_PUBHANDLE handle,
    size_t* const max_size);
IRM_SOCK_HOT_CALL int irm_pub_send(IRM_PUBHANDLE handle, void* data, size_t data_len);
IRM_SOCK_HOT_CALL int irm_pub_free(IRM_PUBHANDLE handle, void* data);
uint8_t irm_pub_getalivedsubs(IRM_PUBHANDLE handle);

IRM_SUBHANDLE irm_sub_socket(int type, const char* path);
int irm_sub_bind(IRM_SUBHANDLE handle, const char* local_ip);
int irm_sub_close(IRM_SUBHANDLE handle, int flags);
IRM_SOCK_HOT_CALL void* const irm_sub_recv(IRM_SUBHANDLE handle,
    size_t* const data_len);
IRM_SOCK_HOT_CALL int irm_sub_free(IRM_SUBHANDLE handle, void* data);
uint8_t irm_sub_getalivedpubs(IRM_SUBHANDLE handle);

#ifdef __cplusplus 
}
#endif

#endif
