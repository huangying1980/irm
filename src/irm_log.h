/* huangying */
#ifndef IRM_LOG_H
#define IRM_LOG_H

#include <stdio.h>
#include <stdlib.h>

#if defined(IRM_DEBUG_VERBOSE) || defined(IRM_ERROR_VERBOSE) || defined(IRM_TRACE)
#include <sys/time.h> 
#include <pthread.h>
#endif

#include "irm_decls.h"
#include "irm_socket.h"

#ifndef IRM_LOG_BUF_SIZE
#define IRM_LOG_BUF_SIZE    (2048)
#endif

IRM_C_BEGIN

struct irm_log {
    log_handle   handle;        
    int          level;
};

extern struct irm_log irm_global_log;

#define IRM_LOG_TIME \
({\
    struct timeval tv;\
    gettimeofday(&tv, NULL);\
    tv.tv_sec * 1000000 + tv.tv_usec;\
})

#define IRM_LOG_TID pthread_self()

#ifdef IRM_TRACE
#define IRM_TRC(format, args...) \
do {\
    fprintf(stderr, "[%s:%d %s IRM_DEBUG %lu tid=%lu] ", __FILE__, __LINE__, __func__,\
        IRM_LOG_TIME, IRM_LOG_TID); \
        fprintf(stderr, format, ##args);\
        fprintf(stderr, "\n");\
} while (0)
#else
#define IRM_TRC(format, args...) do{}while(0)
#endif

#if defined IRM_DEBUG

#define IRM_DBG(format, args...) \
do {\
    if (irm_global_log.handle && IRM_LOG_LEVEL_DEBUG <= irm_global_log.level) {\
        char buf[IRM_LOG_BUF_SIZE];\
        int  n = 0;\
        n = snprintf(buf, IRM_LOG_BUF_SIZE, "[IRM_DEBUG] "); \
        n += snprintf(buf, IRM_LOG_BUF_SIZE - n, format, ##args); \
        n += snprintf(buf, IRM_LOG_BUF_SIZE, "\n"); \
        irm_global_log.handle(IRM_LOG_LEVEL_DEBUG, buf, n);\
    } else {\
        fprintf(stderr, "[IRM_DEBUG] ");  \
        fprintf(stderr, format, ##args); \
        fprintf(stderr, "\n");\
    }\
} while (0)

#define IRM_DBG_POOL(_p)\
    for (uint32_t i = 0; i < (_p)->count; ++i) {\
        IRM_DBG("i %u, mbuf %p, id %u", i, (_p)->ring[i], (_p)->ring[i]->id);\
    }

#define IRM_DBG_IP_PORT(_addr) \
do {  \
  unsigned char *p = (unsigned char *)&_addr.sin_addr.s_addr;       \
  IRM_DBG("%d.%d.%d.%d:%d\n", p[0], p[1], p[2], p[3], irm_htons(_addr.sin_port));\
} while (0)

#elif defined IRM_DEBUG_VERBOSE


#define IRM_DBG(format, args...) \
do {\
    if (irm_global_log.handle && IRM_LOG_LEVEL_DEBUG <= irm_global_log.level) {\
        char buf[IRM_LOG_BUF_SIZE];\
        int  n = 0;\
        n = snprintf(buf, IRM_LOG_BUF_SIZE, "[%s:%d %s IRM_DEBUG %lu tid=%lu] ",\
            __FILE__, __LINE__, __func__, IRM_LOG_TIME, IRM_LOG_TID); \
        n += snprintf(buf + n, IRM_LOG_BUF_SIZE - n, format, ##args);\
        n += snprintf(buf + n, IRM_LOG_BUF_SIZE - n, "\n");\
        irm_global_log.handle(IRM_LOG_LEVEL_DEBUG, buf, n);\
    } else  {\
        fprintf(stderr, "[%s:%d %s IRM_DEBUG %lu tid=%lu] ", __FILE__, __LINE__, __func__,\
           IRM_LOG_TIME, IRM_LOG_TID); \
        fprintf(stderr, format, ##args);\
        fprintf(stderr, "\n");\
    }\
} while (0)

#define IRM_DBG_POOL(_p)\
    for (uint32_t i = 0; i < (_p)->count; ++i) {\
        IRM_DBG("i %u, mbuf %p, id %u", i, (_p)->ring[i], (_p)->ring[i]->id);\
    }

#define IRM_DBG_IP_PORT(_addr) \
do {  \
    unsigned char *p = (unsigned char *)&_addr.sin_addr.s_addr;\
    IRM_DBG("%d.%d.%d.%d:%d\n", p[0], p[1], p[2], p[3], irm_htons(_addr.sin_port));\
} while (0)

#else

#define IRM_DBG(format, args...) do{}while(0)
#define IRM_DBG_IP_PORT(_ip) do{}while(0)
#define IRM_DBG_POOL(_p) do{}while(0)
#endif

#ifdef IRM_ERROR_VERBOSE

#define IRM_ERR(format, args...) \
do {\
    if (irm_global_log.handle && IRM_LOG_LEVEL_ERROR <= irm_global_log.level) {\
        char buf[IRM_LOG_BUF_SIZE];\
        int  n = 0;\
        n = snprintf(buf, IRM_LOG_BUF_SIZE, "[%s:%d %s IRM_ERR %lu tid=%lu] ",\
            __FILE__, __LINE__, __func__, IRM_LOG_TIME, IRM_LOG_TID); \
        n += snprintf(buf + n, IRM_LOG_BUF_SIZE - n, format, ##args);\
        n += snprintf(buf + n, IRM_LOG_BUF_SIZE - n, "\n");\
        irm_global_log.handle(IRM_LOG_LEVEL_ERROR, buf, n);\
    } else  {\
        fprintf(stderr, "[%s:%d %s IRM_ERR %lu tid=%lu] ", __FILE__, __LINE__, __func__,\
           IRM_LOG_TIME, IRM_LOG_TID); \
        fprintf(stderr, format, ##args);\
        fprintf(stderr, "\n");\
    }\
} while (0)

#define IRM_WARN(format, args...) \
do {\
    if (irm_global_log.handle && IRM_LOG_LEVEL_WARN <= irm_global_log.level) {\
        char buf[IRM_LOG_BUF_SIZE];\
        int  n = 0;\
        n = snprintf(buf, IRM_LOG_BUF_SIZE, "[%s:%d %s IRM_WARN %lu tid=%lu] ",\
            __FILE__, __LINE__, __func__, IRM_LOG_TIME, IRM_LOG_TID); \
        n += snprintf(buf + n, IRM_LOG_BUF_SIZE - n, format, ##args);\
        n += snprintf(buf + n, IRM_LOG_BUF_SIZE - n, "\n");\
        irm_global_log.handle(IRM_LOG_LEVEL_WARN, buf, n);\
    } else {\
        fprintf(stderr, "[%s:%d %s IRM_WARN %lu tid=%lu] ", __FILE__, __LINE__, __func__,\
           IRM_LOG_TIME, IRM_LOG_TID); \
        fprintf(stderr, format, ##args);\
        fprintf(stderr, "\n");\
    }\
} while (0)

#define IRM_INFO(format, args...) \
do {\
    if (irm_global_log.handle && IRM_LOG_LEVEL_INFO <= irm_global_log.level) {\
        char buf[IRM_LOG_BUF_SIZE];\
        int  n = 0;\
        n = snprintf(buf, IRM_LOG_BUF_SIZE, "[%s:%d %s IRM_INFO %lu tid=%lu] ",\
            __FILE__, __LINE__, __func__, IRM_LOG_TIME, IRM_LOG_TID); \
        n += snprintf(buf + n, IRM_LOG_BUF_SIZE - n, format, ##args);\
        n += snprintf(buf + n, IRM_LOG_BUF_SIZE - n, "\n");\
        irm_global_log.handle(IRM_LOG_LEVEL_INFO, buf, n);\
    } else {\
        fprintf(stderr, "[%s:%d %s IRM_INFO %lu tid=%lu] ", __FILE__, __LINE__, __func__,\
           IRM_LOG_TIME, IRM_LOG_TID); \
        fprintf(stderr, format, ##args);\
        fprintf(stderr, "\n");\
    }\
} while (0)

#define IRM_PANIC(format, args...) \
fprintf(stderr, "[%s:%d %s IRM_OOPS] ", __FILE__, __LINE__, __func__); \
fprintf(stderr, format, ##args);\
fprintf(stderr, "\n"); \
abort()

#else

#define IRM_ERR(format, args...) \
do {\
    if (irm_global_log.handle && IRM_LOG_LEVEL_ERROR <= irm_global_log.level) {\
        char buf[IRM_LOG_BUF_SIZE];\
        int  n = 0;\
        n = snprintf(buf, IRM_LOG_BUF_SIZE, "[IRM_ERR] ");\
        n += snprintf(buf + n, IRM_LOG_BUF_SIZE - n, format, ##args);\
        n += snprintf(buf + n, IRM_LOG_BUF_SIZE - n, "\n");\
        irm_global_log.handle(IRM_LOG_LEVEL_ERROR, buf, n);\
    } else  {\
        fprintf(stderr, "[IRM_ERR] ");  \
        fprintf(stderr, format, ##args); \
        fprintf(stderr, "\n");\
    }\
} while (0)

#define IRM_WARN(format, args...) \
do {\
    if (irm_global_log.handle && IRM_LOG_LEVEL_WARN <= irm_global_log.level) {\
        char buf[IRM_LOG_BUF_SIZE];\
        int  n = 0;\
        n = snprintf(buf, IRM_LOG_BUF_SIZE, "[IRM_WARN] ");\
        n += snprintf(buf + n, IRM_LOG_BUF_SIZE - n, format, ##args);\
        n += snprintf(buf + n, IRM_LOG_BUF_SIZE - n, "\n");\
        irm_global_log.handle(IRM_LOG_LEVEL_WARN, buf, n);\
    } else  {\
        fprintf(stderr, "[IRM_WARN] ");  \
        fprintf(stderr, format, ##args); \
        fprintf(stderr, "\n");\
    }\
} while (0)

#define IRM_INFO(format, args...) \
do {\
    if (irm_global_log.handle && IRM_LOG_LEVEL_INFO <= irm_global_log.level) {\
        char buf[IRM_LOG_BUF_SIZE];\
        int  n = 0;\
        n = snprintf(buf, IRM_LOG_BUF_SIZE, "[IRM_INFO] ");\
        n += snprintf(buf + n, IRM_LOG_BUF_SIZE - n, format, ##args);\
        n += snprintf(buf + n, IRM_LOG_BUF_SIZE - n, "\n");\
        irm_global_log.handle(IRM_LOG_LEVEL_INFO, buf, n);\
    } else  {\
        fprintf(stderr, "[IRM_INFO] ");  \
        fprintf(stderr, format, ##args); \
        fprintf(stderr, "\n");\
    }\
} while (0)

#define IRM_PANIC(format, args...) \
fprintf(stderr, "[IRM_OOPS] "); \
fprintf(stderr, format, ##args); \
fprintf(stderr, "\n");\
abort()

#endif

IRM_C_END
#endif
