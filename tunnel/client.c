#define _XOPEN_SOURCE

#include "tunnel_priv.h"

#include "utils.h"
#include "list.h"
#include "khash.h"
#include "cJSON.h"
#include "common.h"

tunnel_mgr global_mgr;
ev_signal signal_watcher;
ev_signal signal_watcher2;
int log_level = LOG_ERR;

/* 用于获取全局的唯一对象 */
tunnel_mgr* get_mgr(void) {
    return &global_mgr;
}

/* 打印日志，如果在路由器里，请使用syslog来打印日志 */
void emit_log(int level, char* line) {
    //TODO for level
    int syslog_level = LOG_ERR;
    //syslog(syslog_level, "%s", line);
    fprintf(stderr, "%s", line);
}

/* 日志打印，目前只能打印256字节一行的日志 */
void _tunnel_logv(int filter, const char *format, va_list vl)
{
    char buf[256];
    vsnprintf(buf, sizeof(buf), format, vl);
    buf[sizeof(buf) - 1] = '\0';

    emit_log(filter, buf);
}

/* 日志打印接口，目前没有分日志等级 */
void tunnel_log(int filter, const char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    _tunnel_logv(filter, format, ap);
    va_end(ap);
}

void tunnel_error(const char *format, ...) {
    va_list ap;

    va_start(ap, format);
    _tunnel_logv(TUNNEL_DEBUG, format, ap);
    va_end(ap);
}

/* 使用libev接口处理 CTRL+C 信号量处理函数 */
static void sigint_cb (EV_P_ ev_signal *w, int revents) {
    ev_signal_stop (EV_A_ w);
    ev_break(EV_A_ EVBREAK_ALL);
}

//Just test restart
/* static void sigint_cb2 (EV_P_ ev_signal *w, int revents) {
    tunnel_mgr *pmgr = get_mgr();
    pmgr->program_exit = PROGRAM_EXIT_RESTART;

    ev_signal_stop (EV_A_ w);
    ev_break(EV_A_ EVBREAK_ALL);
} */

/* 读取与解析配置文件函数，可以参考default.json文件，这个文件记录了域名与端口转发的规则 */
static int read_config(tunnel_mgr* pmgr, char* config_path) {
#define GETCONFIG(j,k,buf,tmpj,tmpc,msg) do {\
        tmpj = cJSON_GetObjectItem(j, k);\
        if(NULL == tmpj) {\
            fprintf(stderr, msg);\
            return -1;\
        }\
        tmpc = tmpj->valuestring;\
        if(NULL == tmpc) {\
            fprintf(stderr, msg);\
            return -1;\
        }\
        strcpy(buf, tmpc);\
    }while(0)

#define GETCONFIGINT(j,k,num,tmpj,msg) do {\
        tmpj = cJSON_GetObjectItem(j, k);\
        if(NULL == tmpj) {\
            fprintf(stderr, msg);\
            return -1;\
        }\
        num = tmpj->valueint;\
    }while(0)

#define GETCONFIGINT_DEF(j,k,num,tmpj,def) do {\
        tmpj = cJSON_GetObjectItem(j, k);\
        if(NULL == tmpj) {\
            num = def;\
        } else {\
            num = tmpj->valueint;\
        }\
    }while(0)

    char buf[8196];
    long fsize;
    cJSON *json = NULL, *jtunnel, *tmpj, *subj;
    tunnel_info* ptunnel;
    char* tmpc;
    int i, tunnel_len;
    FILE *f = fopen(config_path, "r");
    if (NULL == f) {
        fprintf(stderr, "Invalid config file\n");
        return -1;
    }
    fseek(f, 0, SEEK_END);
    fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if(fsize > (sizeof(buf)-1)) {
        fprintf(stderr, "Config file too big\n");
        return -1;
    }

    fread(buf, fsize, 1, f);
    fclose(f);
    buf[fsize] = '\0';

    //Read from json
    json = cJSON_Parse(buf);
    if(NULL == json) {
        fprintf(stderr, "Parse json failed\n");
        return -1;
    }

    GETCONFIG(json, "server", pmgr->server_name, tmpj, tmpc, "server config error\n");
    GETCONFIG(json, "user", pmgr->user, tmpj, tmpc, "user config error\n");
    GETCONFIG(json, "auth", pmgr->auth_token, tmpj, tmpc, "password config error\n");
    GETCONFIGINT(json, "port", pmgr->server_port, tmpj, "port config error\n");
    jtunnel = cJSON_GetObjectItem(json, "tunnels");
    if(NULL == jtunnel) {
        fprintf(stderr, "No tunnels\n");
        return -1;
    }
    tunnel_len = cJSON_GetArraySize(jtunnel);
    if(tunnel_len > pmgr->tunnel_cap) {
        fprintf(stderr, "tunnels is too much len=%d\n", tunnel_len);
        return -1;
    }
    for(i = 0; i < tunnel_len; i++) {
        subj = cJSON_GetArrayItem(jtunnel, i);
        ptunnel = (tunnel_info*)calloc(1, sizeof(tunnel_info));
        GETCONFIG(subj, "proto", ptunnel->protocol, tmpj, tmpc, "proto error\n");
        strcpy(ptunnel->hostname, "");
        GETCONFIG(subj, "subdomain", ptunnel->subdomain, tmpj, tmpc, "subdomain error\n");
        GETCONFIG(subj, "localhost", ptunnel->localhost, tmpj, tmpc, "localhost error\n");
        GETCONFIGINT(subj, "localport", ptunnel->local_port, tmpj, "local port error\n");
        GETCONFIGINT_DEF(subj, "remoteport", ptunnel->remote_port, tmpj, 0);
        ptunnel->local_addr = name_resolve(ptunnel->localhost);
        pmgr->tunnels[i] = ptunnel;
    }
    pmgr->tunnel_len = tunnel_len;
    cJSON_Delete(json);
    return 0;
}

/* 全局对象初始化函数 */
static int tunnel_mgr_init(tunnel_mgr* pmgr)
{
    buf_caches_init(pmgr);
    pmgr->default_ctx = (SSL_CTX*)SSL_CTX_new(SSLv3_method());
    //pmgr->default_ctx = (SSL_CTX*)SSL_CTX_new(SSLv23_client_method());
    if(NULL == pmgr->default_ctx) {
        tunnel_log(TUNNEL_DEBUG, "initial context error\n");
        return -1;
    }

    //Init 32
    pmgr->tunnelmap = kh_init(hi);
    kh_resize(hi, pmgr->tunnelmap, 32);

    return 0;
}

int server_init(EV_P_ tunnel_mgr* pmgr) {
    OpenSSL_add_all_algorithms();
    SSL_library_init();
    SSL_load_error_strings();

    //初始化一些基础数据，并从配置文件读取配置信息
    tunnel_mgr_init(pmgr);

    //初始化main_conn并连接服务器，接受服务器的各项配置信息
    main_sock_init(EV_A_ pmgr);
    return 0;
}

extern void base64_cleanup(void);
static void mgr_release(EV_P_ tunnel_mgr* pmgr) {
    //first release main_sock
    if(pmgr->main_created) {
        //avoid main_conn for reconnect
        if(!pmgr->program_exit) {
            pmgr->program_exit = PROGRAM_EXIT_NORMAL;
        }
        main_conn_release(EV_A_ &pmgr->main_sock);
    }

    if(NULL != pmgr->default_ctx) {
        SSL_CTX_free(pmgr->default_ctx);
    }

    buf_caches_release(pmgr);

    base64_cleanup();
}

static struct option options[] = {
    { "help",	no_argument,    NULL, 'h' },
    { "debug",	no_argument,  NULL, 'd' },
    { "path", required_argument, NULL, 'p' },
    { "config", required_argument, NULL, 'c' },
    { NULL, 0, 0, 0 }
};

/*
 * tunnel的最简单理解的原理是
 * ngrokd服务器接受一个新的连接
 * 新连接传入服务器的数据，ngrokd都原样从proxy_conn连接交给tunnel
 * tunnel从本地的配置以及端口转发的信息得到新的连接所实际连接的本地主机名，端口
 * tunnel创建一个新的priv_conn去连接真实的本地主机名端口，并把从proxy_conn得到的
 * 数据从priv_conn发出。从priv_conn得到的数据也原样从proxy_conn发回到ngrokd服务器。
 * 此时穿透完成内网主机端口，与外网连接的映射。proxy_conn/priv_conn的作用就是这样
 * 更详细的源码可看：http://tonybai.com/2015/05/14/ngrok-source-intro/
 * 没时间可以不看，因为理解tunnel程序比上文的链接简单 */
int main(int argc, char **argv)
{
    int n = 0, debug = 0, daemon = 0;
    char *config_path = NULL;
    int syslog_options = LOG_PID | LOG_PERROR | LOG_DEBUG;
    tunnel_mgr* pmgr = &global_mgr;
    EV_P  = ev_default_loop(0);

    srand((unsigned) time(NULL));
    memset(pmgr, 0, sizeof(tunnel_mgr));

    while (n >= 0) {
        n = getopt_long(argc, argv, "hdp:c:", options, NULL);
        if (n < 0) {
            continue;
        }
        switch(n) {
            case 'd':
                debug = 1;
                break;
            case 'c':
                config_path = optarg;
                break;
            case 'p':
                strcpy(pmgr->pid_path, optarg);
                daemon = 1;
                break;
            case 'h':
                fprintf(stderr, "Libev version of ngrok by Xiaobao, running more effective.\nUsage: tunnel -c config_path -p pid_path -d\n");
                exit(1);
        }
    }

    if(NULL == config_path) {
        fprintf(stderr, "config_path error \nUsage: tunnel -c config_path -p path -d\n");
        exit(1);
    }

    //Read configs
    pmgr->tunnel_cap = TUNNEL_CAP;
    if(0 != read_config(pmgr, config_path)) {
        exit(1);
    }

    if(daemon) {
        //before daemonize, wait 5s for creator's pid for exit
        sleep(5);

        //转入后台运行
        daemonize(pmgr->pid_path);
    }

    setlogmask(LOG_UPTO (LOG_DEBUG));
    openlog("tunnel", syslog_options, LOG_DAEMON);

    //kill -SIGUSR2 22459
    signal(SIGPIPE, SIG_IGN);
    signal(SIGABRT, SIG_IGN);
    ev_signal_init (&signal_watcher, sigint_cb, SIGINT);
    ev_signal_start (EV_A_ &signal_watcher);
    ev_signal_init (&signal_watcher2, sigint_cb, SIGUSR2);
    ev_signal_start (EV_A_ &signal_watcher2);

    server_init(EV_A_ pmgr);

    //进入libev的事情循环
    ev_loop(EV_A_ 0);

    //Now release mgr
    mgr_release(EV_A_ pmgr);
    tunnel_error("exit\n");

#if 0
    //please use perp to monitor it
    //Restart myself support
    if(PROGRAM_EXIT_RESTART == pmgr->program_exit) {
        char* nargs[7];
        nargs[0] = argv[0];
        nargs[1] = "-c";
        nargs[2] = config_path;
        nargs[3] = "-p";
        nargs[4] = pmgr->pid_path;
        nargs[5] = "-d";
        nargs[6] = NULL;

        tunnel_error("restarting for some error\n");
        if (execv(argv[0], nargs)) {
            tunnel_error("restart failed\n");
        }
    }
#endif

    closelog();
    return 0;
}

