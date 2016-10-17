#include "tunnel_priv.h"
#include "utils.h"
#include "list.h"
#include "khash.h"
#include "cJSON.h"
#include "common.h"

//TODO CFLAGS+= -g3 -fno-inline -O0 -fexceptions -DOPENSSL=1

static int proxy_conn_release(EV_P_ proxy_conn* proxy_sock);

void proxy_conn_switch(EV_P_ proxy_conn* proxy_sock, int w)
{
    if(w) {
        //switch to write
        ev_io_stop(EV_A_ &proxy_sock->io);
        ev_io_set(&proxy_sock->io, proxy_sock->sock_fd, EV_WRITE);
        ev_io_start(EV_A_ &proxy_sock->io);
        proxy_sock->conn_state = conn_state_write;
    } else {
        //switch to read
        ev_io_stop(EV_A_ &proxy_sock->io);
        ev_io_set(&proxy_sock->io, proxy_sock->sock_fd, EV_READ);
        ev_io_start(EV_A_ &proxy_sock->io);
        proxy_sock->conn_state = conn_state_read;
    }
}

static ccr_break_state proxy_conn_read_util(proxy_conn *proxy_sock, buf_info* buf, int read_len) {
    int rsize;

    if(0 == buf->total_len) {
        buf->total_len = read_len;
    }

    rsize = SSL_read(proxy_sock->sslinfo->ssl, buf->buf + buf->start, buf->total_len - buf->start);

    if(0 == rsize) {
        tunnel_log(TUNNEL_DEBUG, "remote closed\n");
        goto closing;
    } else if(rsize < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            //rewait for read
            return ccr_break_all;
        } else {
            tunnel_log(TUNNEL_DEBUG, "proxy remote recv error\n");
            goto closing;
        }
    }

    buf->start += rsize;
    if(buf->start < buf->total_len) {
        //wait for next read
        return ccr_break_all;
    } else {
        buf->len = buf->start;
        buf->start = 0;
        return ccr_break_none;
    }

closing:
    return ccr_break_killed;
}

static int proxy_conn_ccr_json(EV_P_ proxy_conn* proxy_sock)
{
    uint64_t pack_len = 0;
    int status;
    buf_info* buf;
    tunnel_mgr *pmgr = get_mgr();
    tunnel_info* ptunnel;
    ccrContext* ctx = &proxy_sock->ccr_read;
    cJSON *json = NULL, *jType, *jPayload;
    char url_str[HOST_BUF_LEN];
    khiter_t k = {0};

    buf = proxy_sock->block_read.curr;

    ccrBegin(ctx);
    if(NULL == buf) {
        buf = buf_alloc();
        proxy_sock->block_read.curr = buf;
    }

    buf->start = 0;
    buf->len = 0;
    buf->total_len = 8;
    for(;;) {
        status = proxy_conn_read_util(proxy_sock, buf, buf->total_len);
        if(status != ccr_break_none) {
            ccrReturn(ctx, status);
        } else {
            break;
        }
    }

    memcpy(&pack_len, buf->buf, 8);
    pack_len = TO_LITTLE(pack_len);
    buf->start = 0;
    buf->len = 0;
    buf->total_len = (int)pack_len;
    for(;;) {
        status = proxy_conn_read_util(proxy_sock, buf, pack_len);
        if(status != ccr_break_none) {
            ccrReturn(ctx, status);
        } else {
            break;
        }
    }

    buf->buf[buf->len] = '\0';
    //{"Type":"StartProxy","Payload":{"Url":"http://test.v-find.com:8000","ClientAddr":"127.0.0.1:41140"}}
    //fprintf(stderr, "proxy:%s\n", (char*)buf->buf);
    json = cJSON_Parse(buf->buf);
    jType = cJSON_GetObjectItem(json, "Type");
    if(0 == strcmp(jType->valuestring, "StartProxy")) {
        jPayload = cJSON_GetObjectItem(json, "Payload");
        strcpy(url_str, cJSON_GetObjectItem(jPayload, "Url")->valuestring);
        /* if(0 != url_parse(url_str, &proto, &remote_host, &remote_port)) {
            tunnel_error("cannot parse url\n");
            ccrReturn(ctx, ccr_break_killed);
        } */
        k = kh_get(hi, pmgr->tunnelmap, url_str);
        if(k == kh_end(pmgr->tunnelmap)) {
            tunnel_error("proto not found\n");
            ccrReturn(ctx, ccr_break_killed);
        }
        ptunnel = pmgr->tunnels[kh_value(pmgr->tunnelmap, k)];
        tunnel_error("creating priv\n");
        //start to join connection
        proxy_sock->started = 1;
        priv_conn_create(EV_A_ proxy_sock, ptunnel);
    }

    cJSON_Delete(json);
    json = NULL;
    if(NULL != proxy_sock->block_read.curr) {
        buf_del_free(proxy_sock->block_read.curr);
        proxy_sock->block_read.curr = NULL;
    }

    ccrFinish(ctx, ccr_break_all);
}

static int proxy_conn_ccr_join(EV_P_ proxy_conn* proxy_sock) {
    buf_info* buf;
    priv_conn* priv_sock = proxy_sock->priv_sock;
    int rsize;

    if(NULL == priv_sock) {
        return ccr_break_killed;
    }

    tunnel_error("proxy reading\n");
    buf = buf_alloc();
    rsize = SSL_read(proxy_sock->sslinfo->ssl, buf->buf, TUNNEL_BUF_SIZE);
    do {
        if(0 == rsize) {
            tunnel_error("priv sock closed\n");
            break;
        } else if(rsize < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                buf_del_free(buf);
                return ccr_break_all;
            } else {
                tunnel_error("proxy remote recv error\n");
                break;
            }
        }

        buf->start = 0;
        buf->len = rsize;
        buf->total_len = rsize;
        list_add_tail(&buf->node, &proxy_sock->block_read.list_todo);
        if((conn_state_connecting != priv_sock->conn_state)
                && (conn_state_write != priv_sock->conn_state)) {
            priv_conn_switch(EV_A_ priv_sock, TRUE);
        }

        return ccr_break_all;
    } while(0);

    //TODO closing
    if(NULL != buf) {
        buf_del_free(buf);
    }
    return ccr_break_killed;
}

static int proxy_conn_ccr_read(EV_P_ proxy_conn* proxy_sock)
{
    int state;

    //update time first
    proxy_sock->read_time = get_curr_time();

    if(proxy_sock->started) {
        return proxy_conn_ccr_join(EV_A_ proxy_sock);
    } else {
        state = proxy_conn_ccr_json(EV_A_ proxy_sock);
        if(proxy_sock->started) {
            memset(&proxy_sock->ccr_read, 0, sizeof(ccrContext));
        }

        return state;
    }
}

static int proxy_conn_ccr_write(proxy_conn* proxy_sock) {
    buf_info *buf;
    int n = 0;
    ccrContext* ctx = &proxy_sock->ccr_write;
    buf = proxy_sock->block_write.curr;

    ccrBegin(ctx);
    proxy_sock->block_write.curr = next_buf_info(&proxy_sock->block_write.list_todo);
    buf = proxy_sock->block_write.curr;

    if(NULL == buf) {
        //tunnel_log(TUNNEL_DEBUG, "proxy_sock write is null\n");
        ccrReturn(ctx, -1);//reset and write
    }

    //tunnel_log(TUNNEL_DEBUG, "proxy writing\n");
    while(NULL != buf) {
        //tunnel_error("start=%d len=%d\n", buf->start, buf->len);
        n = SSL_write(proxy_sock->sslinfo->ssl, buf->buf+buf->start, buf->len);
        if(n < 0) {
            if(errno == EINTR || errno == EAGAIN) {
                ccrReturn(ctx, 1);//continue for writing
            } else {
                tunnel_log(TUNNEL_DEBUG, "proxy_sock write error, line=%d\n", __LINE__);
                ccrReturn(ctx, -2);//killed
            }
        }

        buf->len -= n;
        if(buf->len > 0) {
            buf->start += n;
            ccrReturn(ctx, 2);//continue for writing
        } else {
            buf_del_free(buf);
            proxy_sock->block_write.curr = next_buf_info(&proxy_sock->block_write.list_todo);
            buf = proxy_sock->block_write.curr;
        }
    }

    ccrFinish(ctx, 0);//finished
}

//TODO how to support read/write
static void proxy_conn_proc(EV_P_ ev_io *io, int revents) {
    tunnel_mgr *pmgr = get_mgr();
    proxy_conn* proxy_sock = container_of(io, proxy_conn, io);
    ccr_break_state read_state;
    int err, err2;

    if(conn_state_connecting == proxy_sock->conn_state) {
        if(0 != (err = conn_check(proxy_sock->sock_fd))) {
            tunnel_log(TUNNEL_DEBUG, "proxy connection error:%d\n", err);
            return;
        }
        proxy_sock->conn_state = conn_state_tls;
        tunnel_log(TUNNEL_DEBUG, "proxy socket ok\n");
    }

    if(conn_state_tls == proxy_sock->conn_state) {
        if(NULL == proxy_sock->sslinfo) {
            proxy_sock->sslinfo = (openssl_info*)calloc(1, sizeof(openssl_info));
            if(NULL == proxy_sock->sslinfo) {
                tunnel_log(TUNNEL_DEBUG, "proxy ssl alloc error\n");
                return;
            }
            if(0 != openssl_init_info(pmgr, proxy_sock->sock_fd, proxy_sock->sslinfo)) {
                tunnel_log(TUNNEL_DEBUG, "proxy failed init openssl\n");
                //TODO release
                return;
            }
        }
        err = SSL_connect(proxy_sock->sslinfo->ssl);
        if(1 == err) {
            tunnel_log(TUNNEL_DEBUG, "proxy tls ok\n");
            pack_reg_proxy(proxy_sock, pmgr->clientId);
            proxy_conn_switch(EV_A_ proxy_sock, TRUE);
        } else {
            err2 = SSL_get_error(proxy_sock->sslinfo->ssl, err);
            switch(err2)
            {
                case SSL_ERROR_WANT_WRITE:
                case SSL_ERROR_WANT_READ:
                    break;
                default:
                    //TODO
                    tunnel_log(TUNNEL_DEBUG, "proxy tls error, err=%d err2=%d\n", err, err2);
                    proxy_sock->conn_state = conn_state_connecting;
                    proxy_conn_release(EV_A_ proxy_sock);
                    proxy_sock->ccr_state = ccr_break_killed;
                    pmgr->program_exit = PROGRAM_EXIT_NORMAL;
                    return;
            }
        }
    } else if(conn_state_read == proxy_sock->conn_state) {
        //read
        for(;;) {
            read_state = proxy_conn_ccr_read(EV_A_ proxy_sock);
            if(ccr_break_none == read_state) {
                continue;
            } else if(ccr_break_all == read_state) {
                break;
            } else {
                //Switch to write then kill itself
                //proxy_conn_release(EV_A_ proxy_sock);
                proxy_conn_switch(EV_A_ proxy_sock, TRUE);
                proxy_sock->ccr_state = ccr_break_killed;
                break;
            }
        }
    } else {
        //write or killed state
        err = proxy_conn_ccr_write(proxy_sock);
        if(-2 == err) {
            proxy_conn_release(EV_A_ proxy_sock);
        } else if(err <= 0) {
            //Finished or error
            if((ccr_break_killed == proxy_sock->ccr_state)
                    || (proxy_sock->started && (NULL == proxy_sock->priv_sock))) {
                proxy_conn_release(EV_A_ proxy_sock);
            } else {
                memset(&proxy_sock->ccr_write, 0, sizeof(ccrContext));
                //switch to read
                proxy_conn_switch(EV_A_ proxy_sock, FALSE);
            }
        }
    }
}

static void proxy_conn_timeout(EV_P_ ev_timer *watcher, int revents) {
    int now = get_curr_time();
    proxy_conn* proxy_sock = container_of(watcher, proxy_conn, watcher);
    if((0 == proxy_sock->read_time) || ((now - proxy_sock->read_time) >= 10*60)) {
        tunnel_log(TUNNEL_DEBUG, "proxy_conn_timeout\n");
        proxy_conn_release(EV_A_ proxy_sock);
    }
    ev_timer_again(EV_A_ watcher);
}

static int proxy_conn_release(EV_P_ proxy_conn* proxy_sock) {
    tunnel_mgr *pmgr = get_mgr();

    //close priv_conn first
    if(NULL != proxy_sock->priv_sock) {
        priv_conn_release(EV_A_ proxy_sock->priv_sock);
    }

    ev_timer_stop(EV_A_ &proxy_sock->watcher);
    ev_io_stop(EV_A_ &proxy_sock->io);
    buf_block_release(&proxy_sock->block_read);
    buf_block_release(&proxy_sock->block_write);

    if(NULL != proxy_sock->sslinfo) {
        openssl_free_info(proxy_sock->sslinfo);
        free(proxy_sock->sslinfo);
        proxy_sock->sslinfo = NULL;
    }

    if(-1 != proxy_sock->sock_fd) {
        close(proxy_sock->sock_fd);
    }

    //free myself
    free(proxy_sock);
    pmgr->proxy_alloc--;

    tunnel_log(TUNNEL_DEBUG, "proxy release\n");
    return 0;
}

proxy_conn* proxy_conn_create(EV_P_ tunnel_mgr* pmgr)
{
    int optval = 0;

    //First log for alloc buf
    tunnel_log(TUNNEL_DEBUG, "proxy alloc=%d\n", pmgr->proxy_alloc);

    proxy_conn* proxy_sock = (proxy_conn*)malloc(sizeof(proxy_conn));
    pmgr->proxy_alloc++;

    do {
        if(NULL == proxy_sock) {
            tunnel_log(TUNNEL_DEBUG, "alloc proxy sock error\n");
            break;
        }
        memset(proxy_sock, 0, sizeof(proxy_conn));

        if(-1 == (proxy_sock->sock_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP))) {
            tunnel_log(TUNNEL_DEBUG, "create proxy sock error\n");
            break;
        }

        //setsockopt(proxy_sock->sock_fd, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval));
        setsockopt(proxy_sock->sock_fd, IPPROTO_TCP, TCP_NODELAY
            , (const void *)&optval, sizeof(optval));
        if(-1 == setnonblock(proxy_sock->sock_fd)) {
            tunnel_log(TUNNEL_DEBUG, "setnonblock error\n");
            break;
        }

        buf_block_init(&proxy_sock->block_read);
        buf_block_init(&proxy_sock->block_write);
        proxy_sock->conn_state = conn_state_connecting;
        ev_io_init(&proxy_sock->io, &proxy_conn_proc, proxy_sock->sock_fd, EV_READ|EV_WRITE);
        //10 minutes
        ev_timer_init(&proxy_sock->watcher, &proxy_conn_timeout, 5*60, 0);
        ev_io_start(EV_A_ &proxy_sock->io);
        ev_timer_start(EV_A_ &proxy_sock->watcher);

        //the server_addr is inited by main_conn_init
        connect(proxy_sock->sock_fd, (struct sockaddr*) &pmgr->server_addr, sizeof(struct sockaddr));
        return proxy_sock;
    } while(0);

    if(NULL != proxy_sock) {
        pmgr->proxy_alloc--;
        if(-1 != proxy_sock->sock_fd) {
            close(proxy_sock->sock_fd);
        }
        free(proxy_sock);
    }

    return NULL;
}

