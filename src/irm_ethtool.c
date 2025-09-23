/* huangying */
#include "irm_ethtool.h"

#include <sys/types.h>
#include <sys/ioctl.h>
#include <string.h>
#include <errno.h>

#include "irm_error.h"
#include "irm_log.h"

#ifndef SIOCETHTOOL
#define SIOCETHTOOL     0x8946
#endif

#define IRM_ETHTOOL_GRINGPARAM  0x00000010 
#define IRM_ETHTOOL_SRINGPARAM  0x00000011

static int irm_ethtool_ring_get(int fd, struct ifreq* ifr,
    struct irm_ethtool_ringparam* ering);
static int irm_ethtool_ring_set(int fd, struct ifreq* ifr,
    struct irm_ethtool_ringparam* ering);
int irm_ethtool_ring_set_max(const char* ifname, int rx, int tx)
{
    struct irm_ethtool_ringparam ering;
    struct ifreq                 ifr;
    int                          fd;
    int                          ret;

    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, ifname);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        IRM_ERR("ring set max error, socket failed %s", strerror(errno));
        return -IRM_ERR_RING_SET_MAX_SOCKET;
    }
    ret = irm_ethtool_ring_get(fd, &ifr, &ering);
    if (ret != IRM_OK) {
        return ret;
    }
    if (rx == -1) {
        ering.rx_pending = ering.rx_max_pending;
    } else if (rx > 0) {
        ering.rx_pending = (uint32_t)rx;
    }
    if (rx == -1) {
        ering.tx_pending = ering.tx_max_pending;
    } else if (tx > 0) {
        ering.tx_pending = (uint32_t)tx;
    }
    return irm_ethtool_ring_set(fd, &ifr, &ering); 
}

static int irm_ethtool_ring_get(int fd, struct ifreq* ifr,
    struct irm_ethtool_ringparam* ering)
{
    int ret;
    ering->cmd = IRM_ETHTOOL_GRINGPARAM;
    ifr->ifr_data = (caddr_t)ering;
    ret = ioctl(fd, SIOCETHTOOL, ifr);
    if (ret < 0) {
        IRM_ERR("get ring failed %s", strerror(errno));
        return -IRM_ERR_ETHTOOL_GET_RING_IOCTL;
    }
    
    return IRM_OK;
}

static int irm_ethtool_ring_set(int fd, struct ifreq* ifr,
    struct irm_ethtool_ringparam* ering)
{
    int    ret;

    ering->cmd = IRM_ETHTOOL_SRINGPARAM;
    ifr->ifr_data = (caddr_t)ering;
    ret = ioctl(fd, SIOCETHTOOL, ifr);
    if (ret < 0) {
        IRM_ERR("set ring failed %s", strerror(errno));
        return -IRM_ERR_ETHTOOL_SET_RING_IOCTL;
    }

    return IRM_OK;
}
