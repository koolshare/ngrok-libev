#include "tunnel_priv.h"
#include "balloc.h"
#include "utils.h"
#include "list.h"
#include "khash.h"
#include "cJSON.h"
#include "common.h"

static void main_conn_switch(EV_P_ main_conn* mani_sock, int w);

void main_conn_release(EV_P_ main_conn* main_sock) {
    tunnel_mgr *pmgr = get_mgr();

    ev_timer_stop(EV_A_ &main_sock->watcher);
    ev_io_stop(EV_A_ &main_sock->io);

    buf_block_release(&main_sock->block_write);
    if(NULL != main_sock->curr_read) {
        buf_del_free(main_sock->curr_read);
        main_sock->curr_read = NULL;
    }

    if(NULL != main_sock->sslinfo) {
        openssl_free_info(main_sock->sslinfo);
        bfree(B_ARGS, main_sock->sslinfo);
        main_sock->sslinfo = NULL;
    }
    if(-1 != main_sock->sock_fd) {
        close(main_sock->sock_fd);
        main_sock->sock_fd = -1;
    }
    //reset all params
    main_sock->conn_state = conn_state_connecting;
    main_sock->ccr_state = ccr_break_none;
    main_sock->tick_cnt = 0;
    main_sock->to_ping = 0;
    main_sock->pong_time = 0;
    memset(&main_sock->ccr_read, 0, sizeof(ccrContext));
    memset(&main_sock->ccr_write, 0, sizeof(ccrContext));

    //released
    pmgr->main_created = 0;

    tunnel_log(TUNNEL_DEBUG, "releaseed and reconnecting %d\n", pmgr->program_exit);
    if(!pmgr->program_exit) {
        //not exit but reconnect only, wait 30s and reconnect
        sleep(30);
    }

    if(pmgr->program_exit || (0 != main_sock_init(EV_A_ pmgr))) {
        //program exit or main_sock init failed!, break all
        tunnel_error("main_sock reconnect failed or program error, exting\n");
        ev_break(EV_A_ EVBREAK_ALL);
    }
}

static int main_conn_ccr_write(main_conn* main_sock) {
    buf_info* buf;
    int n = 0;
    ccrContext* ctx = &main_sock->ccr_write;
    buf = main_sock->block_write.curr;

    ccrBegin(ctx);
    main_sock->block_write.curr = next_buf_info(&main_sock->block_write.list_todo);
    buf = main_sock->block_write.curr;

    if(NULL == buf) {
        tunnel_log(TUNNEL_DEBUG, "main_sock write is null\n");
        ccrReturn(ctx, -1);
    }

    //tunnel_log(TUNNEL_DEBUG, "writing\n");

    while(NULL != buf) {
        n = SSL_write(main_sock->sslinfo->ssl, buf->buf+buf->start, buf->len);
        if(n < 0) {
            if(errno == EINTR || errno == EAGAIN) {
                ccrReturn(ctx, 1);
            } else {
                tunnel_log(TUNNEL_DEBUG, "main_sock write error, line=%d\n", __LINE__);
                ccrReturn(ctx, -2);
            }
        }

        buf->start += n;
        if((buf->len -= n) > 0) {
            ccrReturn(ctx, 2);
        } else {
            //Finished write
            buf_del_free(buf);
            main_sock->block_write.curr = next_buf_info(&main_sock->block_write.list_todo);
            buf = main_sock->block_write.curr;
        }
    }

    if(main_sock->to_ping) {
        //tunnel_log(TUNNEL_DEBUG, "ping in write ...\n");
        pack_ping(main_sock);
        main_sock->to_ping = 0;
        ccrReturn(ctx, 2);
    }
    ccrFinish(ctx, 0);
}

static ccr_break_state main_conn_read_util(main_conn *main_sock, buf_info* buf, int read_len) {
    int rsize;

    if(0 == buf->total_len) {
        buf->total_len = read_len;
    }

    //rsize = recv(main_sock->sock_fd, buf->buf + buf->start, buf->total_len - buf->start, 0);
    rsize = SSL_read(main_sock->sslinfo->ssl, buf->buf + buf->start, buf->total_len - buf->start);

    if(0 == rsize) {
        tunnel_log(TUNNEL_DEBUG, "remote closed\n");
        goto closing;
    } else if(rsize < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            //rewait for read
            return ccr_break_all;
        } else {
            tunnel_log(TUNNEL_DEBUG, "remote recv error\n");
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

//TODO better
static void save_tunnel(tunnel_info* ptunnel) {
    FILE* f = fopen("/tmp/tunnel.log", "a");
    if(NULL == f) {
        tunnel_error("Canot write log file\n");
        return;
    }
    fprintf(f, "id:%s remote_url:%s local_url:%s//%s:%d\n"
            , ptunnel->reqId, ptunnel->url, ptunnel->protocol, ptunnel->localhost, ptunnel->local_port);
    fclose(f);
}

/* 为了更方便处理socket的请求，程序当中多次依赖于C语言的假协程的处理
 * 具体代码在coroutine.h里面
 * 原理就是一个死循环，当需要等待事情时，从死循环里通过switch跳出等待事件
 * 否则一直往下处理
 * 当有等待的事件进入时，从上一个跳出的位置的下一行开始运行。这样就像真实的协程一样
 * 主动让出控制权，若有新事情的时候重新得到控制权处理等待得到数据之后的任务 */
static int main_conn_ccr_read(EV_P_ main_conn* main_sock)
{
    uint64_t pack_len;
    int i, status, ret;
    buf_info* buf;
    tunnel_info *ptunnel;
    khiter_t k;
    tunnel_mgr *pmgr = get_mgr();
    ccrContext* ctx = &main_sock->ccr_read;

    cJSON *json = NULL, *jType, *jPayload;
    char *cid, *error, *tmpc;

    //ccrBeginContext
    //ccrEndContext(ctx);

    //Must set hear to init before coroutine
    buf = main_sock->curr_read;

    ccrBegin(ctx);
    //最初初始化协程的时候
    if(NULL == buf) {
        buf = buf_alloc();
        main_sock->curr_read = buf;
    }

    //tunnel_log(TUNNEL_DEBUG, "begin to read\n");
    buf->start = 0;
    buf->len = 0;
    buf->total_len = 8;
    for(;;) {
        status = main_conn_read_util(main_sock, buf, buf->total_len);
        if(status != ccr_break_none) {
            //让出控制权，一直等待到新事情并读取到buf->total_len的数据之后进行break
            ccrReturn(ctx, status);
        } else {
            break;
        }
    }

    //MUST reset it to 0
    memcpy(&pack_len, buf->buf, 8);
    pack_len = TO_LITTLE(pack_len);

    buf->start = 0;
    buf->len = 0;
    buf->total_len = (int)pack_len;
    //tunnel_log(TUNNEL_DEBUG, "\ngot pack_len is %d\n", buf->total_len);
    for(;;) {
        //Got read len
        status = main_conn_read_util(main_sock, buf, pack_len);
        if(status != ccr_break_none) {
            ccrReturn(ctx, status);
        } else {
            //读取一个报文。ngrokd的报文协议是：报文长度(little endian)，报文内容
            //通过这次循环已经得到足够长度的报文内容
            break;
        }
    }

    //Read all ok
    buf->buf[buf->len] = '\0';
    //fprintf(stderr, "%s\n", (char*)buf->buf);
    json = cJSON_Parse(buf->buf);
    if(NULL == json) {
        tunnel_error("parse json error\n");
        pmgr->program_exit = PROGRAM_EXIT_NORMAL;
        ccrReturn(ctx, ccr_break_killed);
    }

    //处理具体的json报文内容
    jType = cJSON_GetObjectItem(json, "Type");
    if(0 == strcmp(jType->valuestring, "ReqProxy")) {
        if(NULL == proxy_conn_create(EV_A_ pmgr)) {
            //alloc proxy conn error, restart the program
            pmgr->program_exit = PROGRAM_EXIT_RESTART;
            ccrReturn(ctx, ccr_break_killed);
        }
    } else if(0 == strcmp(jType->valuestring, "Pong")) {
        main_sock->pong_time = get_curr_time();
    } else if(0 == strcmp(jType->valuestring, "Ping")) {
        pack_ping(main_sock);
        main_conn_switch(EV_A_ main_sock, TRUE);
    } else if(0 == strcmp(jType->valuestring, "NewTunnel")) {
        jPayload = cJSON_GetObjectItem(json, "Payload");

        error = cJSON_GetObjectItem(jPayload, "Error")->valuestring;
        if((NULL != error) && (0 != strcmp(error, ""))) {
            //Found error
            tunnel_error("error msg:%s\n", error);
            cJSON_Delete(json);
            pmgr->program_exit = PROGRAM_EXIT_NORMAL;
            ccrReturn(ctx, ccr_break_killed);
        }

        tmpc = cJSON_GetObjectItem(jPayload, "ReqId")->valuestring;
        if(NULL != tmpc) {
            k = kh_get(hi, pmgr->tunnelmap, tmpc);
            if(k == kh_end(pmgr->tunnelmap)) {
                tunnel_error("reqId=%s not found, buf=%s\n", tmpc, buf->buf);
                pmgr->program_exit = PROGRAM_EXIT_NORMAL;
            } else {
                i = kh_value(pmgr->tunnelmap, k);
                ptunnel = pmgr->tunnels[i];
                strcpy(ptunnel->url, cJSON_GetObjectItem(jPayload, "Url")->valuestring);
                k = kh_put(hi, pmgr->tunnelmap, ptunnel->url, &ret);
                kh_value(pmgr->tunnelmap, k) = i;
                ptunnel->remote_ok = 1;

                //append to run
                save_tunnel(ptunnel);
            }
        }
    } else if(0 == strcmp(jType->valuestring, "AuthResp")) {
        jPayload = cJSON_GetObjectItem(json, "Payload");
        cid = cJSON_GetObjectItem(jPayload, "ClientId")->valuestring;
        strcpy(pmgr->clientId, cid);
        error = cJSON_GetObjectItem(jPayload, "Error")->valuestring;
        if(0 == strcmp(error, "")) {
            //tunnel_log(TUNNEL_DEBUG, "auth ping...\n");
            //TODO for check
            pack_ping(main_sock);
            //Switch to write
            main_conn_switch(EV_A_ main_sock, TRUE);

            //Delete the json object and return
            cJSON_Delete(json);
            json = NULL;
            ccrReturn(ctx, ccr_break_all);

            for(i = 0; i < pmgr->tunnel_len; i++) {
                ptunnel = pmgr->tunnels[i];
                rand_string(ptunnel->reqId, REQ_ID_LEN);
                k = kh_put(hi, pmgr->tunnelmap, ptunnel->reqId, &ret);
                kh_value(pmgr->tunnelmap, k) = i;
                pack_tunnel(main_sock, ptunnel->reqId, ptunnel->protocol, ptunnel->hostname
                        , ptunnel->subdomain, ptunnel->remote_port);
            }
            main_conn_switch(EV_A_ main_sock, TRUE);

            //The json object is deleted, return now
            ccrReturn(ctx, ccr_break_all);
        } else {
            //TODO for auth failed
            cJSON_Delete(json);
            json = NULL;
            tunnel_log(TUNNEL_DEBUG, "Auth failed for authtoken.\n");
            pmgr->program_exit = PROGRAM_EXIT_NORMAL;
            ccrReturn(ctx, ccr_break_killed);
            break;
        }
    }

    if(json != NULL) {
        cJSON_Delete(json);
    }
    ccrFinish(ctx, ccr_break_all);
}

//libev读写状态转换
static void main_conn_switch(EV_P_ main_conn* main_sock, int w) {
    if(w) {
        //switch to write
        ev_io_stop(EV_A_ &main_sock->io);
        ev_io_set(&main_sock->io, main_sock->sock_fd, EV_WRITE);
        ev_io_start(EV_A_ &main_sock->io);
        main_sock->conn_state = conn_state_write;
    } else {
        //switch to read
        ev_io_stop(EV_A_ &main_sock->io);
        ev_io_set(&main_sock->io, main_sock->sock_fd, EV_READ);
        ev_io_start(EV_A_ &main_sock->io);
        main_sock->conn_state = conn_state_read;
    }
}

static void main_conn_proc(EV_P_ ev_io *io, int revents) {
    tunnel_mgr *pmgr = get_mgr();
    main_conn* main_sock = container_of(io, main_conn, io);
    ccr_break_state read_state;
    int err, err2;
    //char bufp[256];

    if(conn_state_connecting == main_sock->conn_state) {
        //check if the connection is ok?
        if(0 != (err = conn_check(main_sock->sock_fd))) {
            //wait for next time
            tunnel_log(TUNNEL_DEBUG, "connection error:%d\n", err);
            return;
        }
        main_sock->conn_state = conn_state_tls;
        tunnel_log(TUNNEL_DEBUG, "socket ok\n");

        //TODO https://groups.google.com/forum/#!topic/mailing.openssl.users/si5VbiL9x0c

    }

    /* 把连接升级为tls连接，main_conn都使用tls进行连接 */
    if(conn_state_tls == main_sock->conn_state) {
        if(NULL == main_sock->sslinfo) {
            main_sock->sslinfo = (openssl_info*)balloc(B_ARGS, sizeof(openssl_info));
            if(NULL == main_sock->sslinfo) {
                tunnel_log(TUNNEL_DEBUG, "sslinfo alloc error\n");
                //TODO release main_sock
                return;
            }
            if(0 != openssl_init_info(pmgr, main_sock->sock_fd, main_sock->sslinfo)) {
                tunnel_log(TUNNEL_DEBUG, "fail init openssl\n");
                //TODO release main_sock
                return;
            }
        }

        //此处可能会被运行多次。
        err = SSL_connect(main_sock->sslinfo->ssl);
        if(1 == err) {
            tunnel_log(TUNNEL_DEBUG, "tls ok\n");

            //send message to server
            pack_auth(main_sock, pmgr->clientId, pmgr->user, pmgr->auth_token);

            //switch to write
            main_conn_switch(EV_A_ main_sock, TRUE);
            /* ev_io_stop(EV_A_ &main_sock->io);
            ev_io_set(&main_sock->io, main_sock->sock_fd, EV_WRITE);
            ev_io_start(EV_A_ &main_sock->io);
            main_sock->conn_state = conn_state_write; */
        } else {
            err2 = SSL_get_error(main_sock->sslinfo->ssl, err);
            switch(err2)
            {
                case SSL_ERROR_WANT_WRITE:
                case SSL_ERROR_WANT_READ:
                    //tunnel_log(TUNNEL_DEBUG, "tls going\n");
                    break;
                default:
                    //tunnel_log(TUNNEL_DEBUG, "tls error, err=%d err2=%d\n", err, err2);
                    //ERR_error_string_n(err2, bufp, sizeof(bufp));
                    //fprintf(stderr, bufp);
                    break;
            }
        }
    } else if(conn_state_read == main_sock->conn_state) {
        //read
        for(;;) {
            //进入协程处理
            read_state = main_conn_ccr_read(EV_A_ main_sock);
            //tunnel_log(TUNNEL_DEBUG, "read_state=%d\n", read_state);
            if(ccr_break_none == read_state) {
                continue;
            } else if(ccr_break_all == read_state) {
                break;
            } else {
                //TODO switch to write and killed
                main_conn_release(EV_A_ main_sock);
                break;
            }
        }
    } else {
        //write
        if(main_conn_ccr_write(main_sock) <= 0) {
            //Finish or error
            memset(&main_sock->ccr_write, 0, sizeof(ccrContext));

            //switch to read
            main_conn_switch(EV_A_ main_sock, FALSE);
            /* ev_io_stop(EV_A_ &main_sock->io);
            ev_io_set(&main_sock->io, main_sock->sock_fd, EV_READ);
            ev_io_start(EV_A_ &main_sock->io);
            main_sock->conn_state = conn_state_read; */
        }
    }
}

static void main_conn_timeout(EV_P_ ev_timer *watcher, int revents) {
    int now = get_curr_time();
    //tunnel_mgr *pmgr = get_mgr();
    main_conn* main_sock = container_of(watcher, main_conn, watcher);

    main_sock->tick_cnt++;
    if(conn_state_read == main_sock->conn_state) {
        //tunnel_log(TUNNEL_DEBUG, "ping...\n");
        //switch to write
        pack_ping(main_sock);
        main_conn_switch(EV_A_ main_sock, TRUE);
    } else if(conn_state_write == main_sock->conn_state) {
        main_sock->to_ping++;
    } else if((conn_state_connecting == main_sock->conn_state)
           || (conn_state_tls == main_sock->conn_state)) {
        if(main_sock->tick_cnt > 3) {
            //main_sock timeout, retry ?
            main_conn_release(EV_A_ main_sock);
            //Not exit but retry
            //ev_break(EV_A_ EVBREAK_ALL);
            return;
        }
    }

    //Only warning hear
    if((0 != main_sock->pong_time) && (now-main_sock->pong_time) > 100) {
        tunnel_error("pong time not recv\n");

        //main_conn_release(EV_A_ main_sock);
    }

    ev_timer_again(EV_A_ watcher);
}

/* 用于控制报文与保持心跳的连接 */
int main_sock_init(EV_P_ tunnel_mgr* pmgr) {
    int optval = 0;
    struct sockaddr_in *server_addr = &pmgr->server_addr;
    main_conn* main_sock = &pmgr->main_sock;

    if(-1 == (main_sock->sock_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP))) {
        tunnel_log(TUNNEL_DEBUG, "create main sock error\n");
        return -1;
    }

    setsockopt(main_sock->sock_fd, IPPROTO_TCP, TCP_NODELAY
            , (const void *)&optval, sizeof(optval));
    if(-1 == setnonblock(main_sock->sock_fd)) {
        tunnel_log(TUNNEL_DEBUG, "setnonblock error\n");
        close(main_sock->sock_fd);
        main_sock->sock_fd = -1;
        return -1;
    }

    buf_block_init(&main_sock->block_write);

    main_sock->conn_state = conn_state_connecting;
    //Use read/write for tls connection
    ev_io_init(&main_sock->io, &main_conn_proc, main_sock->sock_fd, EV_READ|EV_WRITE);
    ev_timer_init(&main_sock->watcher, &main_conn_timeout, MAX_PING_TIMEOUT, MAX_PING_TIMEOUT);
    ev_io_start(EV_A_ &main_sock->io);
    ev_timer_start(EV_A_ &main_sock->watcher);

    server_addr->sin_family = AF_INET;
    server_addr->sin_port = htons((uint16_t)pmgr->server_port);
    server_addr->sin_addr.s_addr = name_resolve(pmgr->server_name);
    tunnel_log(TUNNEL_DEBUG, "before connect host=%s port=%d\n"
            , pmgr->server_name, pmgr->server_port);
    connect(main_sock->sock_fd, (struct sockaddr*) server_addr, sizeof(struct sockaddr));

    //already released
    pmgr->main_created = 1;
    //tunnel_log(TUNNEL_DEBUG, "%d", conn_check(main_sock->sock_fd));

    return 0;
}

