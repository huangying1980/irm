/* huangying */
#include "irm_netio.h"

#include <unistd.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include "irm_utils.h"
#include "irm_error.h"
#include "irm_log.h"

#ifndef IRM_NETIO_IP_MULTICAST_LOOP
#define IRM_NETIO_IP_MULTICAST_LOOP 0
#endif

#ifndef IRM_NETIO_IP_MULTICAST_TTL
#define IRM_NETIO_IP_MULTICAST_TTL 64
#endif

static int irm_netio_add_mcgroup(const uint32_t local_ip_be32,
    const uint32_t mcgroup_ip_be32, const uint16_t mcgroup_port_be16);
static int irm_netio_create_local(const uint32_t local_ip_be32,
    const uint16_t local_port_be16);

int irm_netio_init(struct irm_netio* netio)
{
    struct irm_config* cfg = netio->cfg;
    netio->local_ip_be32 = inet_addr(cfg->addr.local_ip);
    netio->mcgroup_ip_be32 = inet_addr(cfg->addr.mcgroup_ip);
    netio->mcgroup_port_be16 = irm_htons(cfg->addr.mcgroup_port);
    netio->local_port_be16 = irm_htons(cfg->addr.local_port);
    netio->last_send_seq = -1;
     
    netio->gfd = irm_netio_add_mcgroup(netio->local_ip_be32,
        netio->mcgroup_ip_be32, netio->mcgroup_port_be16);
    if (netio->gfd < 0) {
        IRM_ERR("netio add multicast group failed, err %d", irm_errno);
        return irm_errno;
    }
    
    netio->lfd = irm_netio_create_local(netio->local_ip_be32,
        netio->local_port_be16);
    if (netio->lfd < 0) {
        IRM_ERR("create local fd failed, err %d", irm_errno);
        return irm_errno;
    }
   
    IRM_DBG("ifname %s, mcgroup %s:%u, local %u.%u.%u.%u:%u",
        cfg->addr.ifname, cfg->addr.mcgroup_ip, cfg->addr.mcgroup_port,
        IRM_IP_N2S(&netio->local_ip_be32), cfg->addr.local_port);

    return IRM_OK;
}

void irm_netio_deinit(struct irm_netio* netio)
{
    struct ip_mreq  mreq; 

    if (netio->gfd > 0) {
        memset(&mreq, 0, sizeof(struct ip_mreq));
        mreq.imr_multiaddr.s_addr = netio->mcgroup_ip_be32;
        mreq.imr_interface.s_addr = netio->local_ip_be32;
        setsockopt(netio->gfd, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq,
            sizeof(struct ip_mreq));
        close(netio->gfd);
        netio->gfd = IRM_INVALID_FD;
    }
    if (netio->lfd > 0) {
        close(netio->lfd);
        netio->lfd = IRM_INVALID_FD;
    }
}

static int irm_netio_add_mcgroup(const uint32_t local_ip_be32,
    const uint32_t mcgroup_ip_be32, const uint16_t mcgroup_port_be16)
{
    int                 fd;
    int                 ret = IRM_OK;
    int                 reuse_addr = 1;
    struct sockaddr_in  sock_addr;
    struct ip_mreq      mreq;

    fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) {
        IRM_ERR("create socket failed, error %s", strerror(errno));
        ret = -IRM_ERR_NETIO_ADD_MCGROUP_SOCKET;
        goto IRM_ERR_OUT;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse_addr,
        sizeof (reuse_addr)) < 0) {
        IRM_ERR("setsockopt SO_REUSEADDR failed, error %s", strerror(errno));
        ret = -IRM_ERR_NETIO_ADD_MCGROUP_SETSOCKOPT;
        goto IRM_ERR_OUT;
    }

    memset(&sock_addr, 0, sizeof(sock_addr));
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_port = mcgroup_port_be16;
    sock_addr.sin_addr.s_addr = mcgroup_ip_be32;

    if (bind(fd, (struct sockaddr *)&sock_addr, sizeof (sock_addr)) < 0) {
        IRM_ERR("bind address %u.%u.%u.%u:%u failed, error %s",
            IRM_IP_N2S(&mcgroup_ip_be32), irm_ntohs(mcgroup_port_be16),
            strerror(errno));
        ret = -IRM_ERR_NETIO_ADD_MCGROUP_BIND;
        goto IRM_ERR_OUT;
    } 

    IRM_DBG("bind mcgroup addr %u.%u.%u.%u:%u", IRM_IP_N2S(&mcgroup_ip_be32),
        irm_ntohs(mcgroup_port_be16));

    IRM_DBG("local addr %u.%u.%u.%u", IRM_IP_N2S(&local_ip_be32));
    memset(&mreq, 0, sizeof(struct ip_mreq));
    mreq.imr_multiaddr.s_addr = mcgroup_ip_be32;
    mreq.imr_interface.s_addr = local_ip_be32;
    if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq,
        sizeof(struct ip_mreq)) < 0) {
        IRM_ERR("setsockopt IP_ADD_MEMBERSHIP failed, error %s", strerror(errno));
        ret = -IRM_ERR_NETIO_ADD_MCGROUP_ADD_MEMBERSHIP;
    }

IRM_ERR_OUT:
    if (ret != IRM_OK) {
        if (fd > 0) {
            close(fd);
        }
        irm_errno = ret;
        fd = IRM_INVALID_FD;
    }
    return fd;

}

static int irm_netio_create_local(const uint32_t local_ip_be32,
    const uint16_t local_port_be16)
{
    int fd;
    int ret = IRM_OK;
    int loop = IRM_NETIO_IP_MULTICAST_LOOP;
    int ttl = IRM_NETIO_IP_MULTICAST_TTL;
    unsigned char tos = IPTOS_LOWDELAY;
    struct sockaddr_in sockaddr;
    int                 reuse_addr = 1;
    
    fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) {
        IRM_ERR("irm_native_netio_create_local error, "
            "socket failed, error %s", strerror(errno));
        ret = -IRM_ERR_NATIVE_CREATE_LOCAL_SOCKET;
        goto IRM_ERR_OUT; 
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse_addr,
        sizeof (reuse_addr)) < 0) {
        IRM_ERR("setsockopt SO_REUSEADDR failed, error %s", strerror(errno));
        ret = -IRM_ERR_NETIO_ADD_MCGROUP_SETSOCKOPT;
        goto IRM_ERR_OUT;
    }

    memset(&sockaddr, 0, sizeof(sockaddr));
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = local_port_be16;
    sockaddr.sin_addr.s_addr = local_ip_be32;

    if (bind(fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0) {
        ret = -IRM_ERR_NATIVE_CREATE_LOCAL_BIND;
        IRM_ERR("bind address %u.%u.%u.%u:%u failed, error %s\n",
            IRM_IP_N2S(&local_ip_be32), irm_ntohs(local_port_be16),
            strerror(errno));
        goto IRM_ERR_OUT;
    }
    
    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof (ttl)) < 0) {
        IRM_ERR("setsockopt IP_MULTICAST_TTL failed, error %s", strerror(errno));
        ret = -IRM_ERR_NATIVE_CREATE_LOCAL_MC_TTL;
        goto IRM_ERR_OUT;
    }

    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop)) < 0) {
        IRM_ERR("setosockopt IP_MULTICAST_LOOP error %s", strerror(errno));
        ret = -IRM_ERR_NATIVE_CREATE_LOCAL_MC_LOOP;
        goto IRM_ERR_OUT;
    }

    if (setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)) < 0) {
        IRM_ERR("setsockopt IP_TOS error %s", strerror(errno));
        ret = -IRM_ERR_NATIVE_CREATE_LOCAL_TOS;
        goto IRM_ERR_OUT;
    }

IRM_ERR_OUT: 
    if (ret != IRM_OK) {
        if (fd > 0) {
            close(fd);
        }
        irm_errno = ret;
        fd = IRM_INVALID_FD;
    }
    return fd;
}

int irm_netio_set_option(struct irm_netio* netio, uint32_t type,
    void* val, size_t val_len)
{
    switch (type) {
        case IRM_NETIO_OPTION_MBUF_RX_POOL:
            if (sizeof(uint32_t) != val_len) {
                return -IRM_ERR_NETIO_SET_OPTION;
            }
            IRM_POOL_MGR_SET_FLAGS(&netio->rx_pool, *(uint32_t *)val);
            break;
        case IRM_NETIO_OPTION_MBUF_TX_POOL:
            if (sizeof(uint32_t) != val_len) {
                return -IRM_ERR_NETIO_SET_OPTION;
            }
            IRM_POOL_MGR_SET_FLAGS(&netio->tx_pool, *(uint32_t *)val);
            break;
        case IRM_NETIO_OPTION_MBUF_RV_POOL:
            if (sizeof(uint32_t) != val_len) {
                return -IRM_ERR_NETIO_SET_OPTION;
            }
            IRM_POOL_MGR_SET_FLAGS(&netio->rv_pool, *(uint32_t *)val);
            break;
        default:
            return -IRM_ERR_NETIO_SET_OPTION;
    }
    
    return IRM_OK;
}

