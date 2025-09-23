/* huangying */
#ifndef IRM_INET_H
#define IRM_INET_H

#include "irm_decls.h"
#include "irm_common.h"

IRM_C_BEGIN

#define IRM_ETH_ALEN (6)
#define IRM_ETH_TYPE_IP (0x0800)

#define IRM_INET_HEADER_SIZE \
        (sizeof(struct irm_eth_hdr) + sizeof(struct irm_ip4_hdr) + sizeof(struct irm_udp_hdr))

#pragma pack(push, 1)

struct irm_eth_hdr {
    uint8_t   dst_host[IRM_ETH_ALEN];
    uint8_t   src_host[IRM_ETH_ALEN];  
    uint16_t  eth_type;
};

struct irm_ip4_hdr {
    union {
        uint8_t   ip_ihl_version;
        struct { 
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
            uint8_t   ihl:4;
            uint8_t   version:4; 
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
            uint8_t   version:4; 
            uint8_t   ihl:4;
#else
# error "Fix your compiler's __BYTE_ORDER__?!"
#endif
        };
    };
    uint8_t   ip_tos;
    uint16_t  ip_tot_len_be16;
    uint16_t  ip_id_be16;
    uint16_t  ip_frag_off_be16;
    uint8_t   ip_ttl;
    uint8_t   ip_protocol;
    uint16_t  ip_check_be16;
    uint32_t  ip_saddr_be32;
    uint32_t  ip_daddr_be32;
};

struct irm_ip4_pseudo_hdr{
        uint32_t  ip_saddr_be32;
        uint32_t  ip_daddr_be32;
        uint8_t   zero;
        uint8_t   ip_protocol;
        uint16_t  length_be16;
};

struct irm_udp_hdr {
        uint16_t  udp_source_be16;
        uint16_t  udp_dest_be16;
        uint16_t  udp_len_be16;
        uint16_t  udp_check_be16;
};
#pragma pack(pop)

IRM_HOT_CALL static IRM_ALWAYS_INLINE
uint32_t irm_ip_hdr_csum32_finish(uint32_t csum32)
{
    unsigned sum =  (csum32 >> 16u) + (csum32 & 0xffff);
    sum += (sum >> 16u);
    return ~sum & 0xffff;
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE
uint32_t irm_ip_checksum(const struct irm_ip4_hdr* ip)
{
    const uint16_t*__restrict__ p = (const uint16_t*) ip;
    uint32_t csum32;
    int bytes;

    csum32  = p[0];
    csum32 += p[1];
    csum32 += p[2];
    csum32 += p[3];
    csum32 += p[4];
        /* omit ip_check_be16 */
    csum32 += p[6];
    csum32 += p[7];
    csum32 += p[8];
    csum32 += p[9];

    bytes = ip->ihl << 2;
    if(IRM_UNLIKELY(bytes > 20)) {
        p += 10; 
        bytes -= 20;
        do {
            csum32 += *p++;
            bytes -= 2;
        } while(bytes);
    }

    return irm_ip_hdr_csum32_finish(csum32);
}

IRM_C_END

#endif
