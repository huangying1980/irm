/* huangying */
#include "irm_socket.h"

#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "irm_sockopt.h"
#include "irm_config.h"
#include "irm_error.h"
#include "irm_log.h"
#include "irm_common.h"
#include "irm_buffer.h"
#include "irm_pub_context.h"
#include "irm_sub_context.h"


IRM_C_BEGIN

#ifndef IRM_MAJOR
#define IRM_MAJOR 1
#endif

#ifndef IRM_MINOR
#define IRM_MINOR 0
#endif

#ifndef IRM_SMALL
#define IRM_SMALL 0
#endif

#define IRM_CHECK_CONFIG(_cfg, _type) \
if (!_cfg || !val || size != sizeof(_type)) {\
    return IRM_ERR_CONFIG;\
}

static void irm_cfg_pub_init(struct irm_config* cfg);
static void irm_cfg_sub_init(struct irm_config* cfg);

static int irm_config_set_addr(struct irm_config* cfg, void* val, size_t size);
static int irm_config_set_retry(struct irm_config* cfg, void* val, size_t size);
static int irm_config_set_io_mode(struct irm_config* cfg, void* val, size_t size);
static int irm_config_set_cpu(struct irm_config* cfg, void* val, size_t size);
static int irm_config_set_timeout(struct irm_config* cfg, void* val, size_t size);
static int irm_config_set_tx(struct irm_config* cfg, void* val, size_t size);
static int irm_config_set_rx(struct irm_config* cfg, void* val, size_t size);
static int irm_config_set_memory(struct irm_config* cfg, void* val, size_t size);
static int irm_config_set_invitation(struct irm_config* cfg, void* val,
    size_t size);
static int irm_config_set_heartbeat(struct irm_config* cfg, void* val,
    size_t size);
static int irm_config_set_hugepage(struct irm_config* cfg, void* val,
    size_t size);
static int irm_config_set_storage(struct irm_config* cfg, void* val,
    size_t size);
static int irm_config_set_name(struct irm_config* cfg, void* val,
    size_t size);
static int irm_config_set_skbuf(struct irm_config* cfg, void* val,
    size_t size);

static int irm_config_get_addr(struct irm_config* cfg, void* val, size_t size);
static int irm_config_get_retry(struct irm_config* cfg, void* val, size_t size);
static int irm_config_get_io_mode(struct irm_config* cfg, void* val, size_t size);
static int irm_config_get_cpu(struct irm_config* cfg, void* val, size_t size);
static int irm_config_get_timeout(struct irm_config* cfg, void* val, size_t size);
static int irm_config_get_tx(struct irm_config* cfg, void* val, size_t size);
static int irm_config_get_rx(struct irm_config* cfg, void* val, size_t size);
static int irm_config_get_memory(struct irm_config* cfg, void* val, size_t size);
static int irm_config_get_invitation(struct irm_config* cfg, void* val,
    size_t size);
static int irm_config_get_heartbeat(struct irm_config* cfg, void* val,
    size_t size);
static int irm_config_get_hugepage(struct irm_config* cfg, void* val,
    size_t size);
static int irm_config_get_storage(struct irm_config* cfg, void* val,
    size_t size);
static int irm_config_get_name(struct irm_config* cfg, void* val,
    size_t size);
static int irm_config_get_skbuf(struct irm_config* cfg, void* val,
    size_t size);

static struct irm_config_option {
    int (*set) (struct irm_config* cfg, void* val, size_t size);
    int (*get) (struct irm_config* cfg, void* val, size_t size);
} irm_config_opts[] = {
    {irm_config_set_retry,      irm_config_get_retry},
    {irm_config_set_addr,       irm_config_get_addr},
    {irm_config_set_io_mode,    irm_config_get_io_mode},
    {irm_config_set_cpu,        irm_config_get_cpu},
    {irm_config_set_timeout,    irm_config_get_timeout},
    {irm_config_set_tx,         irm_config_get_tx},
    {irm_config_set_rx,         irm_config_get_rx},
    {irm_config_set_memory,     irm_config_get_memory},
    {irm_config_set_hugepage,   irm_config_get_hugepage},
    {irm_config_set_invitation, irm_config_get_invitation},
    {irm_config_set_heartbeat,  irm_config_get_heartbeat},
    {irm_config_set_storage,    irm_config_get_storage},
    {irm_config_set_name,       irm_config_get_name},
    {irm_config_set_skbuf,      irm_config_get_skbuf},
    {NULL, NULL}
};

IRM_C_END

IRM_PUBHANDLE irm_pub_socket_impl(int type, const char* path)
{
    struct irm_pub_context* ctx;
    size_t path_len;

    printf("[IRM_INFO]IRM_PUB_VERSION %d.%d.%d, ONLOAD 7.1.3.202\n",
        IRM_MAJOR, IRM_MINOR, IRM_SMALL);
    ctx = irm_pub_context_create();
    if (!ctx) {
        return (IRM_PUBHANDLE)0;
    }
    irm_cfg_pub_init(&ctx->cfg);
    if (!path || !path[0]) {
        ctx->cfg.path[0] = 0;
        ctx->cfg.path_len = 0;
    } else {
        path_len = strnlen(path, IRM_CONFIG_PATH_MAX - 1);
        irm_memcpy(ctx->cfg.path, path, path_len);
        ctx->cfg.path[path_len + 1] = 0;
        ctx->cfg.path_len = path_len;
    }
    ctx->cfg.io_mode = type;
    if (type == IRM_SOCKET_TYPE_NATIVE) {
        ctx->cfg.tx.mbuf_count = IRM_CONFIG_PUB_TX_MBUF_COUNT_NATIVE_DEFAULT;
        ctx->cfg.tx.mbuf_size = IRM_CONFIG_MBUF_SIZE_NATIVE_DEFAULT;
    }
    return (IRM_PUBHANDLE)ctx;
}

int irm_pub_bind(IRM_PUBHANDLE handle, const char* local_ip)
{
    struct irm_pub_context* ctx = IRM_PUB_CTX(handle);
    int                     len;
    int                     ret;
    uint32_t                ip_be32;

    
    if (!ctx) {
        return -IRM_ERR_HANDLE;
    }
    if (local_ip && local_ip[0]) {
        len = strnlen(local_ip, IRM_IP_MAX_LEN - 1);
        irm_memcpy(ctx->cfg.addr.local_ip, local_ip, len);
        ctx->cfg.addr.local_ip[len] = 0;
    }
    if (!ctx->cfg.addr.local_ip[0]) {
        return -IRM_ERR_CONFIG_LOCAL_IP;
    }
    ip_be32 = inet_addr(ctx->cfg.addr.local_ip);
    ret = irm_get_ifname_ip(ip_be32, ctx->cfg.addr.ifname);
    if (ret != IRM_OK) {
        return ret;
    } 
    return irm_pub_context_init(ctx);
}

int irm_pub_close_impl(IRM_PUBHANDLE handle, int flags)
{
    struct irm_pub_context*  ctx = IRM_PUB_CTX(handle);
    int                      i = IRM_WAIT_RETRY;
    int                      ret = IRM_OK;
    
    if (flags == IRM_CLOSE_TYPE_NOW || !ctx->tx_buffer) {
        irm_pub_context_release(ctx);        
        return ret;
    }
    while (irm_txbuffer_available(ctx->tx_buffer)) {
        if (i-- && flags == IRM_CLOSE_TYPE_WAIT) {
            break;
        } 
        usleep(IRM_WAIT_US);
    }
    if (irm_txbuffer_available(ctx->tx_buffer)) {
        ret = -IRM_ERR_CLOSE_DATA;
    }
    irm_pub_context_release(ctx);
    return ret;
}

IRM_HOT_CALL
void* irm_pub_alloc(IRM_PUBHANDLE handle, size_t* max_size)
{
    struct irm_pub_context*  ctx = IRM_PUB_CTX(handle);
    struct irm_mbuf*         mbuf;
    struct irm_msg_data*     msg;

    IRM_DBG("pub_alloc");
    mbuf = irm_mbuf_get(&ctx->netio->tx_pool);
    if (IRM_UNLIKELY(!mbuf)) {
        return NULL;
    }
    msg = IRM_MBUF_MSG(irm_msg_data, mbuf, ctx->netops.payload_offset);
    *max_size = ctx->netops.max_payload_size;
    //*max_size = 2048;
    return IRM_MSG_PAYLOAD(msg);
}

IRM_HOT_CALL
int irm_pub_free(IRM_PUBHANDLE handle, void* data)
{
    struct irm_pub_context*  ctx = IRM_PUB_CTX(handle);
    struct irm_mbuf*         mbuf;
    struct irm_msg_data*     data_msg;

    IRM_DBG("pub_free");
    data_msg = IRM_MSG_D2M(irm_msg_data, data); 
    mbuf = IRM_MBUF_D2M((char *)data_msg - ctx->netops.payload_offset);
    return irm_mbuf_put(&ctx->netio->tx_pool, mbuf);
}

IRM_HOT_CALL
int irm_pub_send(IRM_PUBHANDLE handle, void* data, size_t data_size)
{
    struct irm_pub_context*  ctx = IRM_PUB_CTX(handle);
    struct irm_mbuf*         mbuf;
    struct irm_msg_data*     data_msg;
    const uint32_t           offset = ctx->netops.payload_offset; 
    
    IRM_DBG("pub_send");
    data_msg = IRM_MSG_D2M(irm_msg_data, data); 
    data_msg->header.size = data_size;
    mbuf = IRM_MBUF_D2M((char *)data_msg - offset);
    mbuf->size = data_size + sizeof(struct irm_msg_data);
    return irm_buffer_put_sequence(ctx->tx_buffer, mbuf, &data_msg->header.seq);
}

int irm_pub_setsockopt(IRM_PUBHANDLE handle, int type, void* val, size_t val_len)
{
    struct irm_pub_context* pub_ctx = IRM_PUB_CTX(handle);
    struct irm_config* cfg = &pub_ctx->cfg;
    return irm_config_opts[type].set(cfg, val, val_len);
}

int irm_pub_getsockopt(IRM_PUBHANDLE handle, int type, void* val, size_t val_len)
{
    struct irm_pub_context* pub_ctx = IRM_PUB_CTX(handle);
    struct irm_config* cfg = &pub_ctx->cfg;
    return irm_config_opts[type].get(cfg, val, val_len);
}

uint8_t irm_pub_getalivedsubs(IRM_PUBHANDLE handle)
{
    return IRM_PUB_ALIVE_SUB_COUNT(IRM_PUB_CTX(handle));
}

IRM_SUBHANDLE irm_sub_socket_impl(int type, const char* path)
{
    struct irm_sub_context* ctx;
    size_t  path_len;

    printf("[IRM_INFO]IRM_SUB_VERSION %d.%d.%d, ONLOAD 7.1.3.202\n",
        IRM_MAJOR, IRM_MINOR, IRM_SMALL);
    ctx = irm_sub_context_create();
    if (!ctx) {
        return (IRM_SUBHANDLE)0;
    }
    irm_cfg_sub_init(&ctx->cfg);
    if (!path || !path[0]) {
        ctx->cfg.path[0] = 0;
        ctx->cfg.path_len = 0;
    } else {
        path_len = strnlen(path, IRM_CONFIG_PATH_MAX - 1);
        irm_memcpy(ctx->cfg.path, path, path_len);
        ctx->cfg.path[path_len + 1] = 0;
        ctx->cfg.path_len = path_len;
    }
    ctx->cfg.io_mode = type;
    if (type == IRM_SOCKET_TYPE_NATIVE) {
        ctx->cfg.rx.mbuf_count = IRM_CONFIG_SUB_RX_MBUF_COUNT_NATIVE_DEFAULT;
        ctx->cfg.rx.mbuf_size = IRM_CONFIG_MBUF_SIZE_NATIVE_DEFAULT;
    }
    return (IRM_SUBHANDLE)ctx;
}

int irm_sub_bind(IRM_SUBHANDLE handle, const char* local_ip)
{
    struct irm_sub_context* ctx = IRM_SUB_CTX(handle);
    int                     len;
    int                     ret;
    uint32_t                ip_be32;

    if (!ctx) {
        return -IRM_ERR_HANDLE;
    }
    if (local_ip && local_ip[0]) {
        len = strnlen(local_ip, IRM_IP_MAX_LEN - 1);
        irm_memcpy(ctx->cfg.addr.local_ip, local_ip, len);
        ctx->cfg.addr.local_ip[len] = 0;
    }
    if (!ctx->cfg.addr.local_ip[0]) {
        return -IRM_ERR_CONFIG_LOCAL_IP;
    }
    ip_be32 = inet_addr(ctx->cfg.addr.local_ip);
    ret = irm_get_ifname_ip(ip_be32, ctx->cfg.addr.ifname);
    if (ret != IRM_OK) {
        return ret;
    } 
    return irm_sub_context_init(ctx);
}

int irm_sub_close_impl(IRM_SUBHANDLE handle, int flags)
{
    struct irm_sub_context* ctx = IRM_SUB_CTX(handle);
    int                     ret = IRM_OK;
    int                     i = IRM_WAIT_RETRY;
   
    if (flags == IRM_CLOSE_TYPE_NOW || !ctx->rx_buffer) {
        irm_sub_context_release(ctx);        
        return ret;
    } 
    while (irm_rxbuffer_available(ctx->rx_buffer)) {
        if (i-- && flags == IRM_CLOSE_TYPE_WAIT) {
            break;
        } 
        usleep(IRM_WAIT_US);
    }

    if (irm_rxbuffer_available(ctx->rx_buffer)) {
        ret = -IRM_ERR_CLOSE_DATA;
    }

    irm_sub_context_release(ctx);        
    return ret;
}

IRM_HOT_CALL void* 
const irm_sub_recv(IRM_SUBHANDLE handle, size_t* const data_size)
{
    struct irm_sub_context*  ctx = IRM_SUB_CTX(handle);
    struct irm_mbuf*         mbuf;
    struct irm_msg_data*     msg;

    mbuf = (struct irm_mbuf *)irm_buffer_pop(ctx->rx_buffer);
    if (IRM_UNLIKELY(!mbuf)) {
        return NULL;
    }
    msg = IRM_MBUF_MSG(irm_msg_data, mbuf, ctx->netops.payload_offset);
    *data_size = (size_t)IRM_MSG_PAYLOAD_SIZE(msg);
    return IRM_MSG_PAYLOAD(msg);
}

IRM_HOT_CALL
int irm_sub_free(IRM_SUBHANDLE handle, void* data)
{
    struct irm_sub_context* ctx = IRM_SUB_CTX(handle);
    struct irm_mbuf*        mbuf;
    struct irm_msg_data*    data_msg;

    data_msg = IRM_MSG_D2M(irm_msg_data, data); 
    mbuf = IRM_MBUF_D2M((char *)data_msg - ctx->netops.payload_offset);
    return irm_mbuf_put(&ctx->netio->rx_pool, mbuf);
}

int irm_sub_setsockopt(IRM_SUBHANDLE handle, int type, void* val, size_t val_len)
{
    struct irm_sub_context* sub_ctx = IRM_SUB_CTX(handle);
    struct irm_config* cfg = &sub_ctx->cfg;
    return irm_config_opts[type].set(cfg, val, val_len);
}

int irm_sub_getsockopt(IRM_SUBHANDLE handle, int type, void* val, size_t val_len)
{
    struct irm_sub_context* sub_ctx = IRM_SUB_CTX(handle);
    struct irm_config* cfg = &sub_ctx->cfg;
    return irm_config_opts[type].get(cfg, val, val_len);
}

uint8_t irm_sub_getalivedpubs(IRM_SUBHANDLE handle)
{
    return IRM_SUB_ALIVE_PUB_COUNT(IRM_SUB_CTX(handle));
}

static int irm_config_set_addr(struct irm_config* cfg, void* val, size_t size)
{
    struct irm_config_addr* addr = (struct irm_config_addr *)val;
    IRM_CHECK_CONFIG(cfg, struct irm_config_addr);
    if (!addr) {
        return -IRM_ERR_CONFIG_ADDR;
    }
    memcpy(&cfg->addr, addr, sizeof(struct irm_config_addr));
    return IRM_OK;
}

static int irm_config_get_addr(struct irm_config* cfg, void* val, size_t size)
{
    struct irm_config_addr* addr = (struct irm_config_addr *)val;
    IRM_CHECK_CONFIG(cfg, struct irm_config_addr);
    if (!addr) {
        return -IRM_ERR_CONFIG_ADDR;
    }
    memset(addr, 0, sizeof(struct irm_config_addr));
    memcpy(addr, &cfg->addr, sizeof(struct irm_config_addr));
    return IRM_OK;
}

static int irm_config_set_retry(struct irm_config* cfg, void* val, size_t size)
{
    IRM_CHECK_CONFIG(cfg, uint8_t);
    cfg->retry = *(uint8_t *)val;
    return IRM_OK;
}

static int irm_config_get_retry(struct irm_config* cfg, void* val, size_t size)
{
    IRM_CHECK_CONFIG(cfg, uint8_t);
    *(uint8_t *)val = cfg->retry;
    return IRM_OK;
}

static int irm_config_set_io_mode(struct irm_config* cfg, void* val, size_t size)
{
    int mode = *(int *)val;
    IRM_CHECK_CONFIG(cfg, int);
    
    if (mode < IRM_SOCKET_TYPE_NATIVE
        || mode >= IRM_SOCKET_TYPE_MAX) {
        return -IRM_ERR_CONFIG_IO_MODE;
    }
    cfg->io_mode = mode;
    return IRM_OK;
}

static int irm_config_get_io_mode(struct irm_config* cfg, void* val, size_t size)
{
    IRM_CHECK_CONFIG(cfg, int);
    *(int *)val = cfg->io_mode;
    return IRM_OK;
}

static int irm_config_set_cpu(struct irm_config* cfg, void* val, size_t size)
{
    struct irm_config_cpu* cpu = (struct irm_config_cpu *)val;    
    IRM_CHECK_CONFIG(cfg, struct irm_config_cpu);
    cfg->cpu = *cpu;
    return IRM_OK;
}

static int irm_config_get_cpu(struct irm_config* cfg, void* val, size_t size)
{
    struct irm_config_cpu* cpu = (struct irm_config_cpu *)val;    
    IRM_CHECK_CONFIG(cfg, struct irm_config_cpu);
    *cpu = cfg->cpu;
    return IRM_OK;
}

static int irm_config_set_timeout(struct irm_config* cfg, void* val, size_t size)
{
    struct irm_config_timeout* timeout = (struct irm_config_timeout *)val;
    IRM_CHECK_CONFIG(cfg, struct irm_config_timeout);
    cfg->timeout = *timeout;
    return IRM_OK;
}

static int irm_config_get_timeout(struct irm_config* cfg, void* val, size_t size)
{
    struct irm_config_timeout* timeout = (struct irm_config_timeout *)val;
    IRM_CHECK_CONFIG(cfg, struct irm_config_timeout);
    *timeout = cfg->timeout;
    return IRM_OK;
}

static int irm_config_set_tx(struct irm_config* cfg, void* val, size_t size)
{
    struct irm_config_tx* tx = (struct irm_config_tx *)val;
    IRM_CHECK_CONFIG(cfg, struct irm_config_tx);
    cfg->tx = *tx;
    return IRM_OK;
}

static int irm_config_get_tx(struct irm_config* cfg, void* val, size_t size)
{
    struct irm_config_tx* tx = (struct irm_config_tx *)val;
    IRM_CHECK_CONFIG(cfg, struct irm_config_tx);
    *tx = cfg->tx;
    return IRM_OK;
}

static int irm_config_set_rx(struct irm_config* cfg, void* val, size_t size)
{
    struct irm_config_rx* rx = (struct irm_config_rx *)val;
    IRM_CHECK_CONFIG(cfg, struct irm_config_rx);
    cfg->rx = *rx;
    if (cfg->rx.recycle == IRM_CONFIG_SUB_RX_MBUF_COUNT_DEFAULT
        && cfg->rx.mbuf_count != IRM_CONFIG_SUB_RX_MBUF_COUNT_DEFAULT) {
        cfg->rx.recycle = cfg->rx.mbuf_count;
    }
    if (cfg->rx.mbuf_count < cfg->rx.recycle) {
        return -IRM_ERR_CONFIG;
    }
    return IRM_OK;
}

static int irm_config_get_rx(struct irm_config* cfg, void* val, size_t size)
{
    struct irm_config_rx* rx = (struct irm_config_rx *)val;
    IRM_CHECK_CONFIG(cfg, struct irm_config_rx);
    *rx = cfg->rx;
    return IRM_OK;
}

static int irm_config_set_memory(struct irm_config* cfg, void* val, size_t size)
{
    struct irm_config_memory* memory = (struct irm_config_memory *)val;
    IRM_CHECK_CONFIG(cfg, struct irm_config_memory);
    cfg->memory = *memory;
    return IRM_OK;
}

static int irm_config_get_memory(struct irm_config* cfg, void* val, size_t size)
{
    struct irm_config_memory* memory = (struct irm_config_memory *)val;
    IRM_CHECK_CONFIG(cfg, struct irm_config_memory);
    *memory = cfg->memory;
    return IRM_OK;
}

static int
irm_config_set_invitation(struct irm_config* cfg, void* val, size_t size)
{
    struct irm_config_invitation* invitation;
    invitation = (struct irm_config_invitation *)val;
    IRM_CHECK_CONFIG(cfg, struct irm_config_invitation);
    cfg->invitation = *invitation;
    return IRM_OK;
}

static int
irm_config_get_invitation(struct irm_config* cfg, void* val, size_t size)
{
    struct irm_config_invitation* invitation;
    invitation = (struct irm_config_invitation *)val;
    IRM_CHECK_CONFIG(cfg, struct irm_config_invitation);
    *invitation = cfg->invitation;
    return IRM_OK;
}

static int
irm_config_set_heartbeat(struct irm_config* cfg, void* val, size_t size)
{
    struct irm_config_heartbeat* heartbeat;
    heartbeat = (struct irm_config_heartbeat *)val;
    IRM_CHECK_CONFIG(cfg, struct irm_config_heartbeat);
    cfg->heartbeat = *heartbeat;
    return IRM_OK;
}

static int
irm_config_get_heartbeat(struct irm_config* cfg, void* val, size_t size)
{
    struct irm_config_heartbeat* heartbeat;
    heartbeat = (struct irm_config_heartbeat *)val;
    IRM_CHECK_CONFIG(cfg, struct irm_config_heartbeat);
    *heartbeat = cfg->heartbeat;
    return IRM_OK;
}

static int
irm_config_set_hugepage(struct irm_config* cfg, void* val, size_t size)
{
    uint32_t* page_size;
    page_size = (uint32_t *)val;
    IRM_CHECK_CONFIG(cfg, uint32_t);
    if (*page_size != 4096 && *page_size != 1 << 21 && *page_size != 1 << 30) {
        return -IRM_ERR_CONFIG_HUGEPAGE;
    }
    cfg->hugepage_size = *page_size;
    return IRM_OK;
}

static int
irm_config_get_hugepage(struct irm_config* cfg, void* val, size_t size)
{
    IRM_CHECK_CONFIG(cfg, uint32_t);
    *(uint32_t *)val = cfg->hugepage_size;
    return IRM_OK;
}

static int
irm_config_set_storage(struct irm_config* cfg, void* val, size_t size)
{
    struct irm_config_storage* storage;
    storage = (struct irm_config_storage *)val;
    IRM_CHECK_CONFIG(cfg, struct irm_config_storage);
    cfg->storage = *storage;
    return IRM_OK;
}

static int
irm_config_get_storage(struct irm_config* cfg, void* val, size_t size)
{
    struct irm_config_storage* storage;
    storage = (struct irm_config_storage *)val;
    IRM_CHECK_CONFIG(cfg, struct irm_config_storage);
    *storage = cfg->storage;
    return IRM_OK;
}

static int
irm_config_set_name(struct irm_config* cfg, void* val, size_t size)
{
    int len;
    struct irm_config_name* name;
    name = (struct irm_config_name *)val;
    IRM_CHECK_CONFIG(cfg, struct irm_config_name);
    if (name->pub[0]) {
        len = strnlen(name->pub, IRM_NAME_MAX_LEN);
        memcpy(cfg->name.pub, name->pub, len);    
        cfg->name.pub[len] = 0;
    }
    if (name->sub[0]) {
        len = strnlen(name->sub, IRM_NAME_MAX_LEN);
        memcpy(cfg->name.sub, name->sub, len);
        cfg->name.sub[len] = 0;
    }
    return IRM_OK;
}

static int
irm_config_get_name(struct irm_config* cfg, void* val, size_t size)
{
    struct irm_config_name* name;
    int                     len;
    name = (struct irm_config_name *)val;
    IRM_CHECK_CONFIG(cfg, struct irm_config_name);
    memset(name, 0, sizeof(struct irm_config_name));
    if (cfg->name.pub[0]) {
        len = strlen(cfg->name.pub); 
        memcpy(name->pub, cfg->name.pub, strlen(cfg->name.pub));
        name->pub[len] = 0;
    }
    if (cfg->name.sub[0]) {
        len = strlen(cfg->name.sub); 
        memcpy(name->sub, cfg->name.sub, strlen(cfg->name.sub));
        name->sub[len] = 0;
    }
    return IRM_OK;
}

static int
irm_config_set_skbuf(struct irm_config* cfg, void* val, size_t size)
{
    struct irm_config_skbuf* skbuf;

    skbuf = (struct irm_config_skbuf *)val;
    IRM_CHECK_CONFIG(cfg, struct irm_config_skbuf);
    cfg->skbuf = *skbuf;
    return IRM_OK;
}

static int
irm_config_get_skbuf(struct irm_config* cfg, void* val, size_t size)
{
    struct irm_config_skbuf* skbuf;
    skbuf = (struct irm_config_skbuf *)val;
    IRM_CHECK_CONFIG(cfg, struct irm_config_storage);
    *skbuf = cfg->skbuf;
    return IRM_OK;
}

static void irm_cfg_pub_init(struct irm_config* cfg)
{
    cfg->io_mode = IRM_SOCKET_TYPE_NATIVE;
    cfg->retry = IRM_CONFIG_RETRY_DEFAULT;
    cfg->hugepage_size = 4096U;
    memset(cfg->path, 0, IRM_CONFIG_PATH_MAX);
    cfg->path_len = 0;
    irm_memcpy(cfg->addr.mcgroup_ip, IRM_CONFIG_MCGROUP_IP_DEFAULT,
        sizeof(IRM_CONFIG_MCGROUP_IP_DEFAULT) - 1);
    cfg->addr.mcgroup_port = IRM_CONFIG_MCGROUP_PORT_DEFAULT;
    cfg->addr.local_ip[0] = 0;
    cfg->addr.local_port = IRM_CONFIG_LOCAL_PORT_DEFAULT; 
    cfg->addr.ifname[0] = 0;

    cfg->cpu.cpu_id = -1;
    cfg->cpu.rt = IRM_FALSE;
    cfg->cpu.priority = 99;
    
    cfg->timeout.span_us = IRM_CONFIG_TIMEOUT_SPAN_DEFAULT;
    cfg->timeout.times = IRM_CONFIG_TIMEOUT_TIMES_DEFAULT;
    cfg->timeout.nack_timeout = IRM_CONFIG_TIMEOUT_RENACK;
    cfg->timeout.breakpoint_timeout = IRM_CONFIG_TIMEOUT_BREAKPOINT;
    
    cfg->tx.mbuf_count = IRM_CONFIG_PUB_TX_MBUF_COUNT_DEFAULT;
    cfg->tx.mbuf_size = IRM_CONFIG_MBUF_SIZE_DEFAULT;
    cfg->tx.fifo_timeout = IRM_CONFIG_PUB_FIFO_TIMEOUT;
    cfg->tx.fifo_threshold = IRM_CONFIG_PUB_FIFO_THRESHOLD;

    cfg->tx.ctpio = IRM_TRUE;
    cfg->tx.ctpio_no_poison = IRM_TRUE;

    cfg->rx.mbuf_count = IRM_CONFIG_PUB_RX_MBUF_COUNT_DEFAULT;
    cfg->rx.mbuf_size = IRM_CONFIG_MBUF_SIZE_DEFAULT;
    
    cfg->memory.rank = 0;
    cfg->memory.channel = 0;
    cfg->memory.pool_size = IRM_CONFIG_MEMORY_POOL_SIZE;

    cfg->invitation.times = IRM_CONFIG_INVITATION_TIMES;
    cfg->invitation.retry = IRM_CONFIG_INVITATION_RETRY;
    cfg->invitation.wait_sub_count = IRM_CONFIG_INVITATION_WAIT_SUB_COUNT;

    cfg->heartbeat.send_timeout = IRM_CONFIG_HEARTBEAT_SEND_TIMEOUT;
    cfg->heartbeat.alive_timeout = IRM_CONFIG_HEARTBEAT_ALIVE_TIMEOUT;

    cfg->storage.enable = IRM_FALSE;
    cfg->storage.sobj_size = cfg->tx.mbuf_size;
    cfg->storage.sobj_count = cfg->tx.mbuf_count << 1;
    cfg->storage.task_count = cfg->storage.sobj_count;
    cfg->storage.cpu_id = -1;
    cfg->storage.rt = IRM_FALSE;
    cfg->storage.priority = 99;

    cfg->weight.tx = IRM_CONFIG_TX_WEIGHT;
    cfg->weight.rx = 0;

    cfg->skbuf.rd = IRM_CONFIG_SKBUF_RD;
    cfg->skbuf.wr = IRM_CONFIG_SKBUF_WR;

    memset(cfg->name.pub, 0, IRM_NAME_MAX_LEN);
}

static void irm_cfg_sub_init(struct irm_config* cfg)
{
    cfg->io_mode = IRM_SOCKET_TYPE_NATIVE;
    cfg->retry = IRM_CONFIG_RETRY_DEFAULT;
    cfg->hugepage_size = 4096U;
    memset(cfg->path, 0, IRM_CONFIG_PATH_MAX);
    cfg->path_len = 0;
    irm_memcpy(cfg->addr.mcgroup_ip, IRM_CONFIG_MCGROUP_IP_DEFAULT,
        sizeof(IRM_CONFIG_MCGROUP_IP_DEFAULT) - 1);
    cfg->addr.mcgroup_port = IRM_CONFIG_MCGROUP_PORT_DEFAULT;
    cfg->addr.local_ip[0] = 0;
    cfg->addr.local_port = IRM_CONFIG_LOCAL_PORT_DEFAULT; 
    cfg->addr.ifname[0] = 0;

    cfg->cpu.cpu_id = -1;
    cfg->cpu.priority = IRM_CONFIG_CPU_PRIORITY_DEFAULT;
    cfg->cpu.rt = IRM_FALSE;
    
    cfg->timeout.span_us = IRM_CONFIG_TIMEOUT_SPAN_DEFAULT;
    cfg->timeout.times = IRM_CONFIG_TIMEOUT_TIMES_DEFAULT;
    cfg->timeout.nack_timeout = IRM_CONFIG_TIMEOUT_RENACK;
    cfg->timeout.breakpoint_timeout = IRM_CONFIG_TIMEOUT_BREAKPOINT;
    
    cfg->tx.mbuf_count = IRM_CONFIG_SUB_TX_MBUF_COUNT_DEFAULT;
    cfg->tx.mbuf_size = IRM_CONFIG_MBUF_SIZE_DEFAULT;
    cfg->tx.ctpio = IRM_TRUE;
    cfg->tx.ctpio_no_poison = IRM_TRUE;

    cfg->rx.mbuf_count = IRM_CONFIG_SUB_RX_MBUF_COUNT_DEFAULT;
    cfg->rx.mbuf_size = IRM_CONFIG_MBUF_SIZE_DEFAULT;
    cfg->rx.recycle = IRM_CONFIG_SUB_RX_MBUF_COUNT_DEFAULT;

    cfg->memory.rank = 0;
    cfg->memory.channel = 0;
    cfg->memory.pool_size = IRM_CONFIG_MEMORY_POOL_SIZE;

    cfg->invitation.times = IRM_CONFIG_INVITATION_TIMES;
    cfg->invitation.retry = IRM_CONFIG_INVITATION_RETRY;

    cfg->heartbeat.send_timeout = IRM_CONFIG_HEARTBEAT_SEND_TIMEOUT;
    cfg->heartbeat.alive_timeout = IRM_CONFIG_HEARTBEAT_ALIVE_TIMEOUT;

    cfg->skbuf.rd = IRM_CONFIG_SKBUF_RD;
    cfg->skbuf.wr = IRM_CONFIG_SKBUF_WR;

    memset(cfg->name.sub, 0, IRM_NAME_MAX_LEN);
}
