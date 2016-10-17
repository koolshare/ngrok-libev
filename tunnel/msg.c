#include "tunnel_priv.h"
#include "tunnel_priv.h"
#include "utils.h"
#include "list.h"
#include "khash.h"
#include "cJSON.h"
#include "common.h"

int pack_auth(main_conn *main_sock, char* clientId, char* user, char* auth)
{
    uint64_t pack_len;
    buf_info* b = buf_alloc();
    if(NULL == b) {
        tunnel_log(TUNNEL_DEBUG, "%s buf is null\n", __FUNCTION__);
        return -1;
    }

    b->len = snprintf((char*)b->buf + 8, TUNNEL_BUF_SIZE - 8, "{\"Type\":\"Auth\",\"Payload\":{\"Version\":\"2\",\"MmVersion\":\"1.7\",\"User\":\"%s\",\"Password\": \"%s\",\"OS\":\"darwin\",\"Arch\":\"amd64\",\"ClientId\":\"%s\"}}"
            , user, auth, clientId);
    pack_len = (uint64_t)b->len;
    b->total_len = b->len =  b->len + 8;
    pack_len = TO_LITTLE(pack_len);
    memcpy(b->buf, &pack_len, 8);
    b->start = 0;
    list_add_tail(&b->node, &main_sock->block_write.list_todo);

    return 0;
}

int pack_ping(main_conn *main_sock) {
    uint64_t pack_len;
    buf_info* b = buf_alloc();
    if(NULL == b) {
        tunnel_log(TUNNEL_DEBUG, "%s buf is null\n", __FUNCTION__);
        return -1;
    }
    b->len = snprintf((char*)b->buf + 8, TUNNEL_BUF_SIZE - 8, "{\"Type\":\"Ping\",\"Payload\":{}}");
    pack_len = (uint64_t)b->len;
    b->total_len = b->len =  b->len + 8;
    pack_len = TO_LITTLE(pack_len);
    memcpy(b->buf, &pack_len, 8);
    b->start = 0;
    list_add_tail(&b->node, &main_sock->block_write.list_todo);

    return 0;
}

int pack_tunnel(main_conn* main_sock, char* guid_str, char* proto, char* hostname, char* subdomain, int remote_port) {
    uint64_t pack_len;
    buf_info* b = buf_alloc();
    if(NULL == b) {
        tunnel_log(TUNNEL_DEBUG, "%s buf is null\n", __FUNCTION__);
        return -1;
    }
    //fprintf(stderr, "reqId %s\n", guid_str);
    b->len = snprintf((char*)b->buf+8, TUNNEL_BUF_SIZE-8, "{\"Type\":\"ReqTunnel\",\"Payload\":{\"Protocol\":\"%s\",\"ReqId\":\"%s\",\"Hostname\": \"%s\",\"Subdomain\":\"%s\",\"HttpAuth\":\"\",\"RemotePort\":%d}}"
            , proto, guid_str, hostname, subdomain, remote_port);
    pack_len = (uint64_t)b->len;
    b->total_len = b->len =  b->len + 8;
    pack_len = TO_LITTLE(pack_len);
    memcpy(b->buf, &pack_len, 8);
    b->start = 0;
    list_add_tail(&b->node, &main_sock->block_write.list_todo);

    return 0;
}

int pack_reg_proxy(proxy_conn* proxy_sock, char* clientId) {
    uint64_t pack_len;
    buf_info* b = buf_alloc();
    if(NULL == b) {
        tunnel_log(TUNNEL_DEBUG, "%s buf is null\n", __FUNCTION__);
        return -1;
    }
    b->len = snprintf((char*)b->buf + 8, TUNNEL_BUF_SIZE - 8, "{\"Type\":\"RegProxy\",\"Payload\":{\"ClientId\":\"%s\"}}", clientId);
    pack_len = (uint64_t)b->len;
    b->total_len = b->len =  b->len + 8;
    pack_len = TO_LITTLE(pack_len);
    memcpy(b->buf, &pack_len, 8);
    b->start = 0;
    list_add_tail(&b->node, &proxy_sock->block_write.list_todo);

    return 0;
}

