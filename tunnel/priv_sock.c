#include "tunnel_priv.h"
#include "utils.h"
#include "list.h"
#include "khash.h"
#include "cJSON.h"
#include "common.h"

int priv_conn_release(EV_P_ priv_conn* priv_sock) {
    tunnel_mgr *pmgr = get_mgr();

    ev_timer_stop(EV_A_ &priv_sock->watcher);
    ev_io_stop(EV_A_ &priv_sock->io);
    //buf_block_release(&priv_sock->block_read);
    //buf_block_release(&priv_sock->block_write);

    if(NULL != priv_sock->sslinfo) {
        openssl_free_info(priv_sock->sslinfo);
        free(priv_sock->sslinfo);
        priv_sock->sslinfo = NULL;
    }

    if(-1 != priv_sock->sock_fd) {
        close(priv_sock->sock_fd);
    }

    priv_sock->proxy->priv_sock = NULL;
    tunnel_error("priv release\n");
    free(priv_sock);
    pmgr->priv_alloc--;

    return 0;
}

void priv_conn_switch(EV_P_ priv_conn* priv_sock, int w)
{
    if(w) {
        //switch to write
        ev_io_stop(EV_A_ &priv_sock->io);
        ev_io_set(&priv_sock->io, priv_sock->sock_fd, EV_WRITE);
        ev_io_start(EV_A_ &priv_sock->io);
        priv_sock->conn_state = conn_state_write;
    } else {
        //switch to read
        ev_io_stop(EV_A_ &priv_sock->io);
        ev_io_set(&priv_sock->io, priv_sock->sock_fd, EV_READ);
        ev_io_start(EV_A_ &priv_sock->io);
        priv_sock->conn_state = conn_state_read;
    }
}

static int priv_conn_ccr_read(EV_P_ priv_conn* priv_sock) {
    buf_info* buf;
    //ccrContext* ctx = &priv_sock->ccr_read;
    proxy_conn* proxy_sock = priv_sock->proxy;
    int rsize;

    buf = buf_alloc();
    rsize = recv(priv_sock->sock_fd, buf->buf, TUNNEL_BUF_SIZE, 0);
    if(0 == rsize) {
        tunnel_error("priv sock closed\n");
        goto error_reading;
    } else if(rsize < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            buf_del_free(buf);
            return ccr_break_all;
        } else {
            tunnel_error("priv remote recv error\n");
            goto error_reading;
        }
    }

    //tunnel_error("priv reading rsize=%d\n", rsize);
    buf->start = 0;
    buf->len = rsize;
    buf->total_len = rsize;
    list_add_tail(&buf->node, &proxy_sock->block_write.list_todo);
    if(conn_state_write != proxy_sock->conn_state) {
        proxy_conn_switch(EV_A_ proxy_sock, TRUE);
    }

    //wait for next read
    return ccr_break_all;

error_reading:
    if(NULL != buf) {
        buf_del_free(buf);
    }
    return ccr_break_killed;
}

static int priv_conn_ccr_write(priv_conn* priv_sock) {
    buf_info* buf;
    int n = 0;
    ccrContext* ctx = &priv_sock->ccr_write;
    proxy_conn* proxy_sock = priv_sock->proxy;
    buf_block* block = &proxy_sock->block_read;
    buf = block->curr;

    ccrBegin(ctx);
    block->curr = next_buf_info(&block->list_todo);
    buf = block->curr;

    if(NULL == buf) {
        tunnel_error("priv_sock write is null\n");
        ccrReturn(ctx, -1);
    }
    tunnel_error("priv writing\n");
    while(NULL != buf) {
        n = write(priv_sock->sock_fd, buf->buf + buf->start, buf->len);
        if(n < 0) {
            if(errno == EINTR || errno == EAGAIN) {
                ccrReturn(ctx, 1);
            } else {
                tunnel_error("priv write error\n");
                ccrReturn(ctx, -2);
            }
        }
        buf->len -= n;
        if(buf->len > 0) {
            buf->start += n;
            ccrReturn(ctx, 2);
        } else {
            //Finished write, look again
            buf_del_free(buf);
            block->curr = next_buf_info(&block->list_todo);
            buf = block->curr;
        }
    }

    ccrFinish(ctx, 0);
}

static void priv_conn_proc(EV_P_ ev_io *io, int revents) {
    priv_conn* priv_sock = container_of(io, priv_conn, io);
    proxy_conn* proxy_sock = priv_sock->proxy;
    ccr_break_state read_state;
    int err;

    if(conn_state_connecting == priv_sock->conn_state) {
        if(0 != (err = conn_check(priv_sock->sock_fd))) {
            return;
        }
        tunnel_error("priv ok\n");
        if(list_empty(&proxy_sock->block_read.list_todo)) {
            priv_sock->conn_state = conn_state_read;
        } else {
            priv_sock->conn_state = conn_state_write;
            priv_conn_switch(EV_A_ priv_sock, TRUE);
            return;
        }
    }
    if(conn_state_read == priv_sock->conn_state) {
        for(;;) {
            read_state = priv_conn_ccr_read(EV_A_ priv_sock);
            if(ccr_break_none == read_state) {
                continue;
            } else if(ccr_break_all == read_state) {
                break;
            } else {
                priv_conn_release(EV_A_ priv_sock);

                //Notify proxy_conn to kill itself
                //Now priv_sock == NULL
                if(conn_state_write != proxy_sock->conn_state) {
                    proxy_conn_switch(EV_A_ proxy_sock, TRUE);
                }
                break;
            }
        }
    } else {
        //write or killed
        err = priv_conn_ccr_write(priv_sock);
        if(-2 == err) {
            priv_conn_release(EV_A_ priv_sock);
            if(conn_state_write != proxy_sock->conn_state) {
                proxy_conn_switch(EV_A_ proxy_sock, TRUE);
            }
        } else if(err <= 0) {
            memset(&priv_sock->ccr_write, 0, sizeof(ccrContext));
            priv_conn_switch(EV_A_ priv_sock, FALSE);
        }
    }
}

static void priv_conn_timeout(EV_P_ ev_timer *watcher, int revents) {
    priv_conn* priv_sock = container_of(watcher, priv_conn, watcher);
    proxy_conn* proxy_sock = priv_sock->proxy;
    if(conn_state_connecting == priv_sock->conn_state) {
        tunnel_error("priv timeout\n");
        priv_conn_release(EV_A_ priv_sock);
        if(conn_state_write != proxy_sock->conn_state) {
            proxy_conn_switch(EV_A_ proxy_sock, TRUE);
        }
    }
}

priv_conn* priv_conn_create(EV_P_ proxy_conn* proxy_sock, tunnel_info* ptunnel)
{
    int optval = 0;
    struct sockaddr_in server_addr_o = {0};
    struct sockaddr_in *server_addr = &server_addr_o;
    tunnel_mgr *pmgr = get_mgr();

    //First log for alloc buf
    tunnel_log(TUNNEL_DEBUG, "priv alloc=%d\n", pmgr->priv_alloc);

    priv_conn* priv_sock = (priv_conn*)calloc(1, sizeof(priv_conn));
    pmgr->priv_alloc++;

    do {
        if(NULL == priv_sock) {
            tunnel_error("alloc priv sock error\n");
            break;
        }
        priv_sock->sock_fd = socket(AF_INET, SOCK_STREAM, 0);
        if(-1 == priv_sock->sock_fd) {
            tunnel_error("create priv sock error\n");
            break;
        }

        //setsockopt(priv_sock->sock_fd, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval));
        setsockopt(priv_sock->sock_fd, IPPROTO_TCP, TCP_NODELAY
                , (const void*)&optval, sizeof(optval));
        if(-1 == setnonblock(priv_sock->sock_fd)) {
            tunnel_error("setnonblock error\n");
            break;
        }
        priv_sock->proxy = proxy_sock;
        proxy_sock->priv_sock = priv_sock;
        priv_sock->ptunnel = ptunnel;
        //TODO for proto, use http for default
        priv_sock->proto_type = proto_type_http;
        if(0 == ptunnel->local_addr) {
            ptunnel->local_addr = name_resolve(ptunnel->localhost);
        }

        //buf_block_init(&priv_sock->block_read);
        //buf_block_init(&priv_sock->block_write);
        priv_sock->conn_state = conn_state_connecting;
        //TODO for tls, use EV_READ
        ev_io_init(&priv_sock->io, &priv_conn_proc, priv_sock->sock_fd, EV_READ|EV_WRITE);
        ev_timer_init(&priv_sock->watcher, &priv_conn_timeout, MAX_CONNECT_TIMEOUT, 0);
        ev_io_start(EV_A_ &priv_sock->io);
        ev_timer_start(EV_A_ &priv_sock->watcher);

        server_addr->sin_family = AF_INET;
        server_addr->sin_port = htons(ptunnel->local_port);
        server_addr->sin_addr.s_addr = ptunnel->local_addr;
        connect(priv_sock->sock_fd, (struct sockaddr*)server_addr, sizeof(struct sockaddr));

        tunnel_error("connecting to %s:%d\n", ptunnel->localhost, ptunnel->local_port);
        return priv_sock;
    } while(0);

    if(NULL != priv_sock) {
        if(-1 != priv_sock->sock_fd) {
            close(priv_sock->sock_fd);
        }
        free(priv_sock);
        pmgr->priv_alloc--;
    }

    return NULL;
}

