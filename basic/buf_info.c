#include "tunnel_priv.h"

#include "coroutine.h"
#include "list.h"
#include "balloc.h"
#include "khash.h"
#include "common.h"

#define BUF_ITEM_MAX 64

/* 因为想数据报文要处理得更快，弄了一个cache加快内存的分配 */
void buf_caches_init(tunnel_mgr* pmgr) {
    INIT_LIST_HEAD(&pmgr->buf_list);
    pmgr->buf_list_len = 0;
}

void buf_caches_release(tunnel_mgr* pmgr) {
    buf_info *b_to_del = NULL, *n;

    list_for_each_entry_safe(b_to_del, n, &pmgr->buf_list, node) {
        list_del(&b_to_del->node);
        free(b_to_del);
    }
}

/* 分配内存 */
buf_info* buf_alloc(void) {
    buf_info *b = NULL;
    tunnel_mgr* pmgr = get_mgr();

    if(pmgr->buf_list_len > 0) {
        //如果有数据，则直接分配最近使用的buf_info
        // got first entry
        list_for_each_entry(b, &pmgr->buf_list, node) {
            break;
        }
        list_del_init(&b->node);
        pmgr->buf_list_len--;
    } else {
        //否则重新malloc一个新的buf_info
        b = (buf_info*)malloc(sizeof(buf_info));
        if(NULL == b) {
            return b;
        }
        INIT_LIST_HEAD(&b->node);
    }
    b->start = 0;
    b->len = 0;
    b->total_len = 0;

    //printf("alloc len=%d\n", pmgr->buf_list_len);

    return b;
}

void buf_del_free(buf_info* b) {
    list_del_init(&b->node);
    buf_free(b);
}

int len_of_list(void);

void buf_free(buf_info* b) {
    tunnel_mgr* pmgr = get_mgr();
    buf_info *b_to_del = NULL;

    if(pmgr->buf_list_len >= BUF_ITEM_MAX) {
        //Remote tail and add to first. better for cache
        list_add(&b->node, &pmgr->buf_list);

        list_for_each_entry_reverse(b_to_del, &pmgr->buf_list, node) {
            break;
        }
        list_del(&b_to_del->node);
        free(b_to_del);
        b_to_del = NULL;
    } else {
        //Add to first
        list_add(&b->node, &pmgr->buf_list);
        pmgr->buf_list_len++;
    }

    //printf("free len=%d real_len=%d\n", pmgr->buf_list_len, len_of_list());
}

int len_of_list(void) {
    int n = 0;
    tunnel_mgr* pmgr = get_mgr();
    buf_info *b_to_del = NULL;

    list_for_each_entry(b_to_del, &pmgr->buf_list, node) {
        n++;
    }

    return n;
}

void buf_block_init(buf_block* b) {
    memset(b, 0, sizeof(buf_block));
    INIT_LIST_HEAD(&b->list_todo);
}

void buf_block_release(buf_block* b) {
    buf_info *pos, *n;
    if(NULL != b->curr) {
        //Maybe the b->curr is in b->list_doto
        buf_del_free(b->curr);
        b->curr = NULL;
    }

    list_for_each_entry_safe(pos, n, &b->list_todo, node) {
        list_del(&pos->node);

        buf_free(pos);
    }

    //reset to empty
    INIT_LIST_HEAD(&b->list_todo);
}

buf_info* next_buf_info(struct list_head* list)
{
    buf_info *n, *buf = NULL;

    if(!list_empty(list))
    {
        list_for_each_entry_safe(buf, n, list, node) {
            break;
        }
        //list_del(&buf_info->node);
    }

    return buf;
}
