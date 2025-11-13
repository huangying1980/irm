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
#define IRM_DEFAULT_ARGS(_1,  _2, NAME, ...) NAME
#define irm_pub_socket(...) IRM_DEFAULT_ARGS(__VA_ARGS__, \
    irm_pub_socket2, irm_pub_socket1) (__VA_ARGS__)
#define irm_pub_socket1(_type) irm_pub_socket_impl(_type, NULL)
#define irm_pub_socket2(_type, _path) irm_pub_socket_impl(_type, _path)

#define irm_pub_close(...) IRM_DEFAULT_ARGS(__VA_ARGS__, \
    irm_pub_close2, irm_pub_close1) (__VA_ARGS__)
#define irm_pub_close1(_handle) irm_pub_close_impl(_handle, IRM_CLOSE_TYPE_GRACE)
#define irm_pub_close2(_handle, _flag) irm_pub_close_impl(_handle, _flag)

#define irm_sub_socket(...) IRM_DEFAULT_ARGS(__VA_ARGS__, \
    irm_sub_socket2, irm_sub_socket1) (__VA_ARGS__)
#define irm_sub_socket1(_type) irm_sub_socket_impl(_type, NULL)
#define irm_sub_socket2(_type, _path) irm_sub_socket_impl(_type, _path)

#define irm_sub_close(...) IRM_DEFAULT_ARGS(__VA_ARGS__, \
    irm_sub_close2, irm_sub_close1) (__VA_ARGS__)
#define irm_sub_close1(_handle) irm_sub_close_impl(_handle, IRM_CLOSE_TYPE_GRACE)
#define irm_sub_close2(_handle, _flag) irm_sub_close_impl(_handle, _flag)

IRM_PUBHANDLE irm_pub_socket_impl(int type, const char* path);
int irm_pub_bind(IRM_PUBHANDLE handle, const char* local_ip);
int irm_pub_close_impl(IRM_PUBHANDLE handle, int flags);
IRM_SOCK_HOT_CALL void* irm_pub_alloc(IRM_PUBHANDLE handle,
    size_t* const max_size);
IRM_SOCK_HOT_CALL int irm_pub_send(IRM_PUBHANDLE handle, void* data, size_t data_len);
IRM_SOCK_HOT_CALL int irm_pub_free(IRM_PUBHANDLE handle, void* data);
uint8_t irm_pub_getalivedsubs(IRM_PUBHANDLE handle);

IRM_SUBHANDLE irm_sub_socket_impl(int type, const char* path);
int irm_sub_bind(IRM_SUBHANDLE handle, const char* local_ip);
int irm_sub_close_impl(IRM_SUBHANDLE handle, int flags);
IRM_SOCK_HOT_CALL void* const irm_sub_recv(IRM_SUBHANDLE handle,
    size_t* const data_len);
IRM_SOCK_HOT_CALL int irm_sub_free(IRM_SUBHANDLE handle, void* data);
uint8_t irm_sub_getalivedpubs(IRM_SUBHANDLE handle);

#ifdef __cplusplus 
}
#endif

#endif
