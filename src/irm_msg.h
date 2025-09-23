/* huangying */
#ifndef IRM_MSG_H
#define IRM_MSG_H

#include <stdint.h>

#include "irm_decls.h"

IRM_C_BEGIN

enum {
    IRM_MSG_TYPE_DATA = 0,
    IRM_MSG_TYPE_INVITATION = 1,
    IRM_MSG_TYPE_ASK = 2,
    IRM_MSG_TYPE_NACK = 3,
    IRM_MSG_TYPE_HEARTBEAT = 4,
    IRM_MSG_TYPE_LOST_DATA = 5,
    IRM_MSG_TYPE_BREAKPOINT = 6,
    IRM_MSG_TYPE_CLOSE = 7
};

enum {
    IRM_ROLE_TYPE_PUB = 0x0,
    IRM_ROLE_TYPE_SUB = 0x1
};

#pragma pack(push, 1)

struct irm_msg_header {
    uint8_t                 msg_type:6;
    uint8_t                 role:2;
    uint8_t                 sender_id;
    uint8_t                 target_id;
    uint8_t                 source_id;
    uint32_t                seq;
    uint32_t                size;
    uint32_t                ip_be32;
    uint32_t                token;
};

struct irm_msg_invitation_body {
    uint8_t                         empty;
};

struct irm_msg_invitation {
    struct irm_msg_header           header;
    struct irm_msg_invitation_body  body;
};

struct irm_msg_close_body {
    uint8_t                         empty;
};

struct irm_msg_close {
    struct irm_msg_header           header;
    struct irm_msg_close_body       body;
};

struct irm_msg_ask_body {
    uint32_t                       last_seq;
};

struct irm_msg_ask {
    struct irm_msg_header           header;
    struct irm_msg_ask_body         body;
};

struct irm_msg_data {
    struct irm_msg_header           header;
    char                            data[0];
};

struct irm_msg_nack_body {
    uint32_t                        start;
    uint32_t                        end;
};

struct irm_msg_nack {
    struct irm_msg_header           header;
    struct irm_msg_nack_body        body;
};

struct irm_msg_heartbeat_body {
    uint8_t                         empty;
};

struct irm_msg_heartbeat {
    struct irm_msg_header           header;
    struct irm_msg_heartbeat_body   body;
};

struct irm_msg_lost_data_body {
    uint32_t                        old_start;
    uint32_t                        current_start;
    uint32_t                        old_end;
    uint32_t                        current_end;
    uint32_t                        count;
};

struct irm_msg_lost_data {
    struct irm_msg_header           header;
    struct irm_msg_lost_data_body   body;
};

struct irm_msg_breakpoint_body {
    uint32_t                        last_send_seq;
    uint8_t                         heartbeat;                        
};

struct irm_msg_breakpoint {
    struct irm_msg_header           header;
    struct irm_msg_breakpoint_body  body;
};

#pragma pack(pop)

#define IRM_MSG_HEADER(_hdr) ((struct irm_msg_header *)(_hdr))
#define IRM_MSG_PAYLOAD(_msg) ((_msg)->data)
#define IRM_MSG_PAYLOAD_SIZE(_msg) ((_msg)->header.size)

#define IRM_MSG_D2M(_type, _data) (&(((struct _type *)(_data))[-1]))

IRM_C_END

#endif
