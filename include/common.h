#ifndef __COMMON_H_
#define __COMMON_H_

#define talloc(size) malloc(size)
#define tfree(p) free(p)
#define trealloc(p, size) realloc(p, size)

#define TUNNEL_BUF_SIZE 2048
#define HOST_BUF_LEN 255
#define TUNNEL_DEBUG 1
#define MAX_CONNECT_TIMEOUT 18
#define MAX_PING_TIMEOUT 6
#define REQ_ID_LEN 10
#define TUNNEL_CAP 20

#define PROGRAM_EXIT_NORMAL 1
#define PROGRAM_EXIT_RESTART 2

//buf_list
typedef struct _buf_info {
    struct list_head    node;

    int                 start;
    int                 len;
    int                 total_len;
    char               buf[TUNNEL_BUF_SIZE];
} buf_info;

/* How to use
typedef struct _tunnel_info
{
    char localhost[HOST_BUF_LEN];
    char subdomain[HOST_BUF_LEN];
    char hostname[HOST_BUF_LEN];
    char httpauth[HOST_BUF_LEN];
    int localport;
    uint32_t local_addr;
    int remote_port;
} tunnel_info; */

/* 记录转发相关的信息 */
typedef struct _tunnel_info {
    char protocol[HOST_BUF_LEN];
    char hostname[HOST_BUF_LEN];
    char subdomain[HOST_BUF_LEN];
    int remote_port;

    char localhost[HOST_BUF_LEN];
    int local_port;
    uint32_t local_addr;

    //char keyMap[HOST_BUF_LEN];
    char reqId[REQ_ID_LEN];
    char url[HOST_BUF_LEN];
    int remote_ok;
} tunnel_info;

/* 用于通信的数据块，通过链表把数据块连接起来 */
typedef struct _buf_block {
    struct list_head    list_todo;
    buf_info*           curr;       //The current node is always in list_todo
    int                 len;
    int                 total_len;
    int                 type;
    unsigned short      seq;
} buf_block;

//typedef *tunnel_info ptunnel_info;
//KHASH_MAP_INIT_INT(ts, ptunnel_info)
KHASH_MAP_INIT_STR(hi, int)

/* 协程的处理状态，killed表示当前协程已死，要处理死亡之后的事情了
 * all表示当前协程要等待新的事情到来，要从最里面一层跳到最外面一层
 * none表示当前路程没有要等待的事情，可以接着干下面的活 */
typedef enum _ccr_break_state {
    ccr_break_none = 0,
    ccr_break_all,
    ccr_break_killed
} ccr_break_state;

typedef enum _conn_state {
    conn_state_connecting = 0,
    conn_state_tls,
    conn_state_read,
    conn_state_write,
    conn_state_count
} conn_state;

typedef enum _proto_type {
    proto_type_http = 0,
    proto_type_tcp,
    proto_type_count
} proto_type;

struct _proxy_conn;

/* priv_conn处理本地网络数据的请求，从内网穿透的角度，它将处理tunnel具体连接到内网的哪个主机，
 * 得到数据之后再交由proxy_conn传给ngrokd服务器 */
typedef struct _priv_conn {
    ev_io io;
    ev_timer watcher;

    int sock_fd;
    openssl_info *sslinfo;

    ccrContext ccr_read;
    ccrContext ccr_write;
    ccr_break_state ccr_state;
    conn_state conn_state;

    //buf_block block_read;
    //buf_block block_write;

    int proto_type;
    uint32_t local_addr;
    int port;
    tunnel_info* ptunnel;
    struct _proxy_conn* proxy;
} priv_conn;

/* main_conn与ngrokd连接，处理控制报文，所有控制信息都基于main_conn进行交互
 * 协程相关请参考函数 main_conn_ccr_read */
typedef struct _main_conn {
    ev_io io;
    ev_timer watcher;

    int sock_fd;
    openssl_info *sslinfo;

    ccrContext ccr_read;
    ccrContext ccr_write;
    ccr_break_state ccr_state;
    conn_state conn_state;

    buf_info* curr_read;
    buf_block block_write;

    int tick_cnt;
    int to_ping;
    int pong_time;
} main_conn;

/* Proxy连接与ngrokd服务器连接，与ngrokd服务器之间的负载数据都借助proxy_conn进行 */
typedef struct _proxy_conn {
    ev_io io;
    ev_timer watcher;

    int sock_fd;
    openssl_info *sslinfo;

    ccrContext ccr_read;
    ccrContext ccr_write;
    ccr_break_state ccr_state;
    conn_state conn_state;

    //check for exit
    int read_time;

    //For priv_sock to write
    buf_block block_read;
    buf_block block_write;

    priv_conn* priv_sock;
    int started;
} proxy_conn;

/* 存放全局相关对象 */
typedef struct _tunnel_mgr
{
    /* buf_list链表用于存放未使用的buf_info列表
     * 当网络有数据，或准备发送数据的时候，数据的存放
     * 都通过buf_info，相关代码在buf_info.c */
    struct list_head    buf_list;
    int buf_list_len;

    /* 指示程序是否因为一些原因导致退出，如果非退出，将自动重新连接 */
    int program_exit;
    /* main_sock proxy_sock priv_sock的概念可在main函数头部看到说明 */
    main_conn main_sock;
    int main_created;

    /* 服务器地址，端口，加密密码等 */
    struct sockaddr_in server_addr;
    int server_port;
    char server_name[HOST_BUF_LEN];
    char auth_token[HOST_BUF_LEN];

    /* ngrok 协议当中用于，代码在msg.c 里可以看到 */
    char clientId[HOST_BUF_LEN];
    char user[HOST_BUF_LEN];

    char pid_path[HOST_BUF_LEN];

    //TODO for cap
    //域名或端口转发相关的配置项记录
    tunnel_info *tunnels[TUNNEL_CAP];
    int tunnel_len;
    int tunnel_cap;
    khash_t(hi) *tunnelmap;

    //统计
    int proxy_alloc;
    int priv_alloc;

    //SSL 相关的context
    SSL_CTX* default_ctx;
} tunnel_mgr;

int main_sock_init(EV_P_ tunnel_mgr* pmgr);
void tunnel_log(int filter, const char *format, ...);
void tunnel_error(const char *format, ...);
tunnel_mgr* get_mgr(void);

//main_conn
void main_conn_release(EV_P_ main_conn* main_sock);

//proxy_conn
proxy_conn* proxy_conn_create(EV_P_ tunnel_mgr*);
priv_conn* priv_conn_create(EV_P_ proxy_conn* proxy_sock, tunnel_info* ptunnel);
int priv_conn_release(EV_P_ priv_conn* priv_sock);
void proxy_conn_switch(EV_P_ proxy_conn* proxy_sock, int w);
void priv_conn_switch(EV_P_ priv_conn* priv_sock, int w);

//buf_info
void buf_caches_init(tunnel_mgr*);
void buf_caches_release(tunnel_mgr* pmgr);
buf_info* buf_alloc(void);
void buf_block_init(buf_block* b);
void buf_block_release(buf_block* b);
buf_info* next_buf_info(struct list_head* list);
void buf_free(buf_info* b);
void buf_del_free(buf_info* b);

//msg
int pack_auth(main_conn *main_sock, char* clientId, char* user, char* auth);
int pack_ping(main_conn *main_sock);
int pack_reg_proxy(proxy_conn* proxy_sock, char* clientId);
int pack_tunnel(main_conn* main_sock, char* guid_str, char* proto, char* hostname, char* subdomain, int remote_port);
#endif

