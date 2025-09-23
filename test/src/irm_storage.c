/* huangying */

#include "irm_storage.h"

#include <pthread.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "irm_msg.h"
#include "irm_error.h"

#ifndef IRM_STORAGE_IDLE_TIMES
#define IRM_STORAGE_IDLE_TIMES (4095)
#endif

#ifndef IRM_STORAGE_WORKER_NAME
#define IRM_STORAGE_WORKER_NAME "irmstore"
#endif

IRM_C_BEGIN
static void* irm_storage_event_loop(void* arg);
IRM_C_END

int irm_storage_init(void* mpool,
    struct irm_storage* storage, struct irm_netio* netio,
    uint32_t payload_offset, struct irm_config* cfg)
{
    uint32_t              count;
    uint32_t              elt_size;
    uint32_t              task_count;
    int                   ret;


    memset(storage, 0, sizeof(struct irm_storage));

    storage->cfg = cfg;
    storage->netio = netio;
    storage->payload_offset = payload_offset;
    count = cfg->storage.sobj_count;
    elt_size = cfg->storage.sobj_size;
    task_count = cfg->storage.task_count;

    
    storage->lock = IRM_STORAGE_LOCK_OFF;
    storage->ht = irm_hashtable_create(mpool, count);
    if (!storage->ht) {
        IRM_ERR("hashtable create failed, error %d", irm_errno);
        goto IRM_STORAGE_ERR;
    }
    
    IRM_QUEUE_INIT(&storage->lru);
    storage->pool = irm_sobj_pool_create(mpool, elt_size, count, 0, 0);
    if (!storage->pool) {
        IRM_ERR("sobj pool create failed, error %d", irm_errno);
        goto IRM_STORAGE_ERR;
    }
 
    storage->taskqueue = irm_taskqueue_create(mpool, task_count);
    if (!storage->taskqueue) {
        IRM_ERR("taskqueue create failed, error %d", irm_errno);
        goto IRM_STORAGE_ERR;
    }
    ret = pthread_create(&storage->tid, NULL, irm_storage_event_loop, storage);
    if (ret) {
        IRM_ERR("storage thread create failed, err %s", strerror(ret));
        goto IRM_STORAGE_ERR;
    }
    irm_errno = IRM_OK; 
    storage->inited = IRM_TRUE;

IRM_STORAGE_ERR: 
    if (irm_errno != IRM_OK) {
        irm_storage_deinit(storage);
    }
    return irm_errno;
}

void irm_storage_deinit(struct irm_storage* storage)
{
    if (!storage || !storage->inited) {
        return;
    }

    IRM_RMB();
    storage->quit = IRM_TRUE;
    if (storage->tid) {
        pthread_join(storage->tid, NULL);
    }
    storage->ht = NULL;
    storage->pool = NULL;
    storage->taskqueue = NULL;
    storage->inited = IRM_FALSE;
}


static void* irm_storage_event_loop(void* arg)
{
    struct irm_storage*      storage = (struct irm_storage *)arg;
    struct irm_config*       cfg = storage->cfg;
    struct irm_msg_header*   header;
    struct irm_sobj*         sobj = NULL;
    struct irm_mbuf*         mbuf;
    struct irm_queue*       iter = NULL;
    struct irm_hashtable_ln* ln = NULL;
    uint32_t                 idle = 0;
    uint32_t                 empty = 0;
    uint32_t                 key = 0;
    const uint32_t           offset = storage->payload_offset;
    pid_t                    tid = -1;

    tid = syscall(SYS_gettid);
    if (cfg->storage.cpu_id > 0) {
        irm_set_core(tid, cfg->storage.cpu_id);
    }

    if (cfg->storage.rt && cfg->storage.priority >= 0) {
        irm_set_fifo(tid, cfg->storage.priority);    
    }
    irm_set_thread_name(tid, IRM_STORAGE_WORKER_NAME, cfg->name.pub);

    while (!storage->quit) {
        mbuf = (struct irm_mbuf *)irm_taskqueue_pop(storage->taskqueue);
        if (!mbuf) {
            if (!(idle++ & IRM_STORAGE_IDLE_TIMES)) {
                usleep(10);
            }
            continue;
        }
        idle = 0;
        sobj = irm_sobj_get(storage->pool);
        while (!sobj) {
            if (!(empty++ & IRM_STORAGE_IDLE_TIMES)) {
                usleep(10);
            }
            empty = 0;

            IRM_STORAGE_LOCK(storage->lock);

#if defined(IRM_DEBUG) || defined(IRM_DEBUG_VERBOSE)
            if (IRM_QUEUE_EMPTY(&storage->lru)) {
                IRM_DBG("storage pool and lru all empty");
            }
#endif
            IRM_QUEUE_FOREACH(iter, &storage->lru) {
                key = IRM_QUEUE_DATA(iter, struct irm_sobj, lru)->ln.key;
                ln = irm_hashtable_del(storage->ht, key);
                if (ln) {
                    sobj = IRM_CONTAINER_OF(ln, struct irm_sobj, ln);
#if defined(IRM_DEBUG) || defined(IRM_DEBUG_VERBOSE)
                    {
                        struct irm_msg_header* h; 
                        h = (struct irm_msg_header *)sobj->data;
                        IRM_DBG("lru sobj seq %u, size %u, msg type %u, sender_id %u",
                            h->seq, h->size, h->msg_type, h->sender_id);
                    }
#endif
                    IRM_QUEUE_REMOVE(iter);
                    break;
                }
                IRM_ERR("sobj key %u not in hashtable", key);
            }

            IRM_STORAGE_UNLOCK(storage->lock);
        }

        sobj->data_size = mbuf->size; 
        IRM_DBG("mbuf->size %u, offset %u, sobj->data_size %u, sobj->size %u",
            mbuf->size, offset, sobj->data_size, sobj->size);
        if (sobj->data_size > sobj->size) {
            sobj->data_size = sobj->size;
        }
        irm_memcpy(sobj->data, IRM_MBUF_M2D(mbuf) + offset, sobj->data_size);
#if defined IRM_DEBUG || defined IRM_DEBUG_VERBOSE
        {
            struct irm_msg_header* h; 
            h = (struct irm_msg_header *)sobj->data;
            IRM_DBG("insert sobj seq %u, size %u, msg type %u, sender_id %u",
                h->seq, h->size, h->msg_type, h->sender_id);
        }
#endif
        header = IRM_MBUF_MSG(irm_msg_header, mbuf, offset);
        sobj->ln.key = header->seq;

        IRM_STORAGE_LOCK(storage->lock);
        irm_hashtable_insert(storage->ht, &sobj->ln);
        IRM_QUEUE_INSERT_TAIL(&storage->lru, &sobj->lru);
        IRM_STORAGE_UNLOCK(storage->lock);

        IRM_DBG("mbuf %p, mbuf->size %u", mbuf, mbuf->size);
        irm_mbuf_put(&storage->netio->tx_pool, mbuf);
        IRM_DBG("mbuf %p, mbuf->size %u", mbuf, mbuf->size);
    }

    IRM_INFO("storage event loop exit");

    return NULL;
}
