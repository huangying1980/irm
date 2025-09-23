/* huangying */
#include "irm_utils.h"

#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/statfs.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <netdb.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <ifaddrs.h>

#include "irm_common.h"
#include "irm_error.h"
#include "irm_log.h"

#ifndef IRM_IPV4_MAX_LEN
#define IRM_IPV4_MAX_LEN 16
#endif

IRM_C_BEGIN
static int irm_mkdir(const char* path, size_t len);
static int irm_make_path(const char* path, size_t path_len);
static int irm_format(int fd, size_t size);
static int irm_load_version(int fd, uint32_t magic, uint32_t version);
static int irm_file_ready(int fd, size_t size, uint32_t magic,
    uint32_t version);
IRM_C_END

int irm_set_skbuf(int fd, uint32_t rd, uint32_t wr)
{
    int     ret;
    int     bytes;

    if (rd != 0) {
        bytes = (int)rd;
        ret = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bytes, sizeof(bytes));
        if (ret < 0) {
            IRM_ERR("set socket SO_RCVBUF to %d failed", bytes);
            return -IRM_ERR_SET_RCVBUF;
        }
    }
    if (wr != 0) {
        bytes = (int)wr;
        ret = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bytes, sizeof(bytes));
        if (ret < 0) {
            IRM_ERR("set socket SO_SNDBUF to %d failed", bytes);
            return -IRM_ERR_SET_SNDBUF;
        }
    }

    return IRM_OK;
}

int irm_get_ifname_ip(uint32_t ip_be32, char* const ifname)
{
    struct ifaddrs* ifaddr;        
    struct ifaddrs* p = NULL;
    
    if (getifaddrs(&ifaddr) < 0) {
        IRM_ERR("getifaddr failed, error %s", strerror(errno));
        return -IRM_ERR_IFNAME_IP_GETIFADDRS;
    }

    for (p = ifaddr; p; p = p->ifa_next) {
        if (! (p->ifa_flags & IFF_UP)) {
            continue;
        }
        if (p->ifa_flags & IFF_LOOPBACK) {
            continue;
        }
        if (p->ifa_addr->sa_family != AF_INET) {
            continue;
        }
        if (((struct sockaddr_in *)p->ifa_addr)->sin_addr.s_addr == ip_be32) {
            snprintf(ifname, IRM_IPV4_MAX_LEN, "%s", p->ifa_name);
            free(ifaddr);
            return IRM_OK;
        }
    }
    free(ifaddr);
    return -IRM_ERR_IFNAME_IP_MATCH;
}

int irm_prepare_hugepage(size_t* size)
{
    char            path[IRM_PATH_MAX];
    char*           env;
    int             fd = IRM_INVALID_FD;
    size_t          page_size = 0;
    struct statfs   sfs;

    env = getenv(IRM_HUGEPAGE_ENV);
    if (!env) {
        IRM_WARN("env %s is not set", IRM_HUGEPAGE_ENV);
        return -IRM_ERR_HUGEPAGE_ENV;
    }

    snprintf(path, IRM_PATH_MAX, "%s/%s.XXXXXX", env, IRM_HUGEPAGE_FILE); 
    fd = mkstemp(path);
    if (fd < 0) {
        IRM_ERR("mkstemp %s failed, error %s", path, strerror(errno));
        return -IRM_ERR_MKSTEMP;
    }

    if (unlink(path) < 0) {
        IRM_WARN("unlink %s failed, error %s", path, strerror(errno));
    }
    
    if (fstatfs(fd, &sfs) < 0) {
        IRM_ERR("fstatfs %s failed, error %s", path, strerror(errno));
        close(fd);
        return -IRM_ERR_FSTATFS;
    }
    page_size = (size_t)sfs.f_bsize;
    *size = IRM_SIZE_ALIGN(*size, page_size);
    IRM_DBG("path %s size %lu, page_size %lu", path, *size, page_size);
    if (ftruncate(fd, *size) < 0) {
        IRM_ERR("ftruncate %s failed, error %s", path, strerror(errno));
        close(fd);
        return -IRM_ERR_FTRUNCATE;
    }
    
    return fd;
}

int irm_set_core(pid_t tid, int core_id)
{
    cpu_set_t   cpuset;
    int         ret;

    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
    ret = sched_setaffinity(tid, sizeof(cpuset), &cpuset);
    if(ret != 0) {
        IRM_ERR("irm_set_core failed, core_id %d, tid %d, error %s",
            core_id, tid, strerror(errno));
        return -IRM_ERR_SET_CORE;
    }
    return IRM_OK;
}

int irm_set_thread_name(pid_t tid, const char* name, const char* suffix)
{
    char str[32] = {0};
    int  ret;

    if (suffix && suffix[0]) {
        snprintf(str, 32, "%s.%s", name, suffix);
    } else {
        snprintf(str, 32, "%s", name);
    }
    ret = prctl(PR_SET_NAME, str, 0, 0, 0);
    if (ret < 0) {
        IRM_ERR("set tid %d name to %s failed, error %s", tid, str,
            strerror(errno));
        return -IRM_ERR_SET_THREAD_NAME;
    } 
    return IRM_OK;
}

int irm_set_fifo(pid_t tid, int priority)
{
    struct sched_param param;
    int                ret;

    memset(&param, 0, sizeof(struct sched_param));
    param.sched_priority = priority;
    ret = sched_setscheduler(tid, SCHED_FIFO, &param);
    if (ret < 0) {
        IRM_ERR("set tid %d to SCHED_FIFO and priority %d failed, error %s\n",
            tid, priority, strerror(errno));
        return -IRM_ERR_SET_FIFO;
    }

    return IRM_OK;
}

void* irm_load_state(const char* path, size_t path_len, size_t size,
    uint32_t magic, uint32_t version)
{
    size_t          i;
    int             ret;
    int             ready;
    int             fd = IRM_INVALID_FD;
    void*           addr = NULL;

    ret = irm_make_path(path, path_len);
    if (ret != IRM_OK) {
        goto IRM_LOAD_STATE_OUT;
    }

    fd = open(path, O_CREAT | O_RDWR, 0666);
    if (fd < 0) {
        IRM_ERR("load state error, open file %s failed, error %s",
            path, strerror(errno));
        irm_errno = -IRM_ERR_LOAD_STATE_OPEN;
        goto IRM_LOAD_STATE_OUT;
    }

    ready = irm_file_ready(fd, size, magic, version); 
    if (!ready) {
        ret = irm_format(fd, size);
        if (ret != IRM_OK) {
            goto IRM_LOAD_STATE_OUT;
        }
    }

    addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (!addr || addr == MAP_FAILED) {
        IRM_ERR("mmap failed, err %s", strerror(errno));
        irm_errno = -IRM_ERR_LOAD_STATE_MMAP;
        addr = NULL;
        goto IRM_LOAD_STATE_OUT;
    }
    
    if (!ready) {
        memset(addr, 0, size);
    } else {
        for (i = 0; i < size; i += IRM_PAGE_SIZE) {
            (void)(((volatile char *)addr)[i]);
        }
    }

IRM_LOAD_STATE_OUT:
    if (fd != IRM_INVALID_FD) {
        close(fd);
    }

    return addr;
}

static int irm_mkdir(const char* path, size_t len)
{
    size_t i = 0;
    char   tmp_path[PATH_MAX];
    size_t path_len;
    char   bak;

    if (!path || !path[0] || !len || len > PATH_MAX - 2) {
      IRM_ERR("irm mkdir failed path len %lu", len);
      return -IRM_ERR_MKDIR_PATH;
    }

    path_len = len < PATH_MAX - 2 ? len : PATH_MAX - 2;
    memcpy(tmp_path, path, path_len);
    if (tmp_path[path_len - 1] != '/') {
      tmp_path[path_len++] = '/';
    }
    tmp_path[path_len] = 0;

    if (tmp_path[0] == '/') {
        ++i;
    }

    for (; i < path_len; ++i) {
        if (tmp_path[i] != '/') {
            continue;
        }
        bak = tmp_path[i];
        tmp_path[i] = 0;
        if (mkdir(tmp_path, 0777) < 0) {
            switch (errno) {
                case EEXIST:
                    IRM_DBG("mkdir failed, %s already existed", tmp_path);
                    break;
                default:
                    IRM_ERR("mkdir failed, %s error %s", tmp_path,
                        strerror(errno));
                    return -IRM_ERR_SYS_MKDIR;
            }
        }
        tmp_path[i] = bak;
    }

    return IRM_OK;
}

static int irm_make_path(const char* path, size_t path_len)
{
    struct stat st;
    int         ret;

    if (!path || !path[0]) {
        IRM_ERR("make path failed, path error");
        irm_errno = -IRM_ERR_MAKE_PATH;
        goto IRM_MAKE_PATH_OUT;
    }
    if (!stat(path, &st)) {
        if ((st.st_mode & S_IFMT) == S_IFDIR) {
            irm_errno = -IRM_ERR_PATH_EXISTED;
            goto IRM_MAKE_PATH_OUT;
        }
        irm_errno = -IRM_ERR_MAKE_PATH_NAME;
        goto IRM_MAKE_PATH_OUT;
    }
    if (errno != ENOENT) {
        IRM_ERR("make path failed, stat err %s", strerror(errno));
        irm_errno = -IRM_ERR_MAKE_PATH_STAT;
        goto IRM_MAKE_PATH_OUT;
    }
    ret = irm_mkdir(path, path_len);
    if (ret != IRM_OK) { 
        IRM_ERR("mkdir %s failed, err %s", path, strerror(errno));
        irm_errno = ret;
    }

IRM_MAKE_PATH_OUT: 
    return irm_errno;
}

static int irm_format(int fd, size_t size)
{
    if (ftruncate(fd, 0) < 0) {
        IRM_ERR("Init failed, ftruncate err %s", strerror(errno));
        irm_errno = -IRM_ERR_FORMAT_FTRUNCATE;
        return irm_errno;
    }
    if (ftruncate(fd, size) < 0) {
        IRM_ERR("Init failed, ftruncate err %s", strerror(errno));
        irm_errno = -IRM_ERR_FORMAT_FTRUNCATE_SIZE;
        return irm_errno;
    }
    return IRM_OK;
}

static int irm_load_version(int fd, uint32_t magic, uint32_t version)
{
    struct {
      uint32_t magic;
      uint32_t version;
    } meta = {0, 0};
    ssize_t ret;

    ret = pread(fd, &meta, sizeof(meta), 0);
    if (!ret) {
        irm_errno = -IRM_ERR_LOAD_VERSION_PREAD;
        return irm_errno;
    }

    if (ret < 0) {
        IRM_ERR("load version failed, pread error %s", strerror(errno));
        irm_errno = -IRM_ERR_LOAD_META;
        return irm_errno;
    }
    if (ret < (ssize_t)sizeof(meta)) {
        IRM_ERR("load version failed, ret %ld", ret);
        irm_errno = -IRM_ERR_LOAD_META_SIZE;
        return irm_errno;
    }

    if (magic != meta.magic || version != meta.version) {
        IRM_ERR("load version failed, magic %x, version %x",
            meta.magic, meta.version);
        irm_errno = -IRM_ERR_LOAD_VERSION;
        return irm_errno;
    }

    return IRM_OK;
}

static int irm_file_ready(int fd, size_t size, uint32_t magic,
    uint32_t version)
{
    struct stat st;
    if (irm_load_version(fd, magic, version) != IRM_OK) {
        return IRM_FALSE;
    } 

    if (fstat(fd, &st) < 0) {
        IRM_ERR("Init failed, fstat err %s", strerror(errno));
        irm_errno = -IRM_ERR_FILE_READY_FSTAT;
        return IRM_FALSE;
    }
    if ((size_t)st.st_size != size) {
      IRM_PANIC("size error, file %lu, buf size %lu", st.st_size, size);
    }
    return IRM_TRUE;
}

    
