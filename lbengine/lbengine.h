#ifndef __LBENGINE_INVOKE__
#define __LBENGINE_INVOKE__

#define _GNU_SOURCE
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/event.h>
#include <event2/thread.h>
#include <glib-2.0/gmodule.h>
#include <libconfig.h>

#include <http_comm.h>

#ifdef LOG_LIB
#include <loglib.h>
#elif LOG_APP
#include <appLog.h>
#endif

#define MAX_IOV_CNT 3 // header + vheader + body
#define MAX_IOV_PUSH 256

typedef struct iovec_item {
    void *sender_tcp_ctx;                   /* sender tcp context */

    char dest_ip[46];                       /* want to send to */
    struct iovec iov[MAX_IOV_CNT];          /* send to push chunk (header + vheader + body) */
    int iov_cnt;                            /* chunk count */
    int next_start_pos;                     /* if retry after partial sended */
    int remain_bytes;                       /* info remain byte to send */

    char *ctx_unset_ptr;                     /* if all item sended, unset this value (ctx free) */
	void (*unset_cb_func)();                /* if need, unset func() */
	void *unset_cb_arg;                     /* if need, unset func(arg) */
} iovec_item_t;

typedef struct write_item {
    struct write_item *prev, *next;         /* linked */
    iovec_item_t *iovec_item;               /* item */
} write_item_t;

typedef struct write_list {
    write_item_t *root;                     /* first item */
    write_item_t *last;                     /* last item */

    int item_cnt;                           /* match with {bundle_cnt} */
    ssize_t item_bytes;                     /* match with {bundle_bytes} */
} write_list_t;

#define MAX_RCV_BUFF_LEN 1024 * 1024 // 1MB
typedef struct sock_ctx {
    time_t create_time;

	time_t last_hb_recv_time;
	AhifHttpCSMsgHeadType hb_pkt_hdr;
	iovec_item_t push_req; // for hearbeat send

    struct event *event_flush_cb;
    struct event *event_send_hb;
    struct event *event_chk_hb;

    struct bufferevent *bev;
    write_list_t push_items;

    char client_ip[46];
    int client_port;
    int client_fd;
	int connected;

    char buff[MAX_RCV_BUFF_LEN];
    int rcv_len;

    void *lb_ctx;
	void *tcp_ctx;

    GNode *my_conn;

} sock_ctx_t;

typedef enum svc_type {
    TT_NONE = 0,
    TT_RX_ONLY,
    TT_TX_ONLY,
    TT_PEER_RECV,
    TT_PEER_SEND 
} svc_type_t;

typedef struct tcp_stat {
	int send_bytes;
	int recv_bytes;
	int tps;
	int send_to_remote_called;
	int send_to_remote_success;
	int send_to_peer;
	int send_to_fep;
	int ctx_assign_fail;
} tcp_stat_t;

typedef enum select_node_depth {
    SN_TYPE = 0,
    SN_HOST,
    SN_IP,
    SN_PORT,
    SN_CONN_ID,
    SN_MAX
} select_node_depth_t;

typedef int (*FUNC_PTR)(void *, void *);

typedef struct select_node {
    int depth;
    int select_vector;
    int last_selected;

    char name[1024];
    int val;

    GNode *node_ptr;        // my gnode pointer
    FUNC_PTR func_ptr;      // compare function
    void *leaf_ptr;
} select_node_t;

typedef struct tcp_ctx {
    pthread_t thread_id;

	int fep_tag;			// fep index
	int buff_exist;			// buffer_exist or not
	void *httpcs_ctx_buff;	// if receiver thread,  malloc & use own buffer
	int context_num;

    struct event_base *evbase;
    struct evconnlistener *listener;

    /* used by listen thread */
    int svc_type;
    int listen_port;
    int connect_type;
    /* used by connect thread */
    int peer_listen_port;
	char peer_ip_addr[46];

	int heartbeat_enable;
	int flush_tmval;

	/* use by HTTPS for RR request */
	int round_robin_index[MAX_THRD_NUM];

    void *lb_ctx;
    GNode *root_conn;

	/* for stat */
	tcp_stat_t tcp_stat;

	/* for dest selection */
	select_node_t root_select;

	/* for check active / standby */
	int received_fep_status;
} tcp_ctx_t;

typedef struct lb_ctx {
	GNode *fep_rx_thrd;
	GNode *fep_tx_thrd;
	GNode *peer_rx_thrd;
	GNode *peer_tx_thrd;

	pthread_t stat_thrd_id;
} lb_ctx_t;


/***************************************************************/
/******* caller must implement this function !!! ***************/
/* ------------------------- from another.c ------------------ */
void    lb_buff_readcb(struct bufferevent *bev, void *arg);
void    iovec_push_req(tcp_ctx_t *dest_tcp_ctx, iovec_item_t *push_req);
/***************************************************************/


/* ------------------------- iolist.c --------------------------- */
write_item_t    *create_write_item(write_list_t *write_list, iovec_item_t *iovec_item);
void    print_write_item(write_list_t *write_list);
ssize_t push_write_item(int fd, write_list_t *write_list, int bundle_cnt, int bundle_bytes);
//void    unset_pushed_item(write_list_t *write_list, ssize_t nwritten);
void unset_pushed_item(write_list_t *write_list, ssize_t nwritten, const char *caller);

/* ------------------------- util.c --------------------------- */
char    *util_get_ip_from_sa(struct sockaddr *sa);
int     util_get_port_from_sa(struct sockaddr *sa);
int     util_set_linger(int fd, int onoff, int linger);
int     util_set_rcvbuffsize(int fd, int byte);
int     util_set_sndbuffsize(int fd, int byte);
int     util_set_keepalive(int fd, int keepalive, int cnt, int idle, int intvl);
pid_t   util_gettid(void);
void    util_dumphex(FILE *out, const void* data, size_t size);
char    *measure_print(int bytes, char *return_str);
void    printf_config_list_int(char *annotation, config_setting_t *int_list);

/* ------------------------- tcp.c --------------------------- */
GNode   *new_node_conn(sock_ctx_t *sock_ctx);
GNode   *add_node(GNode *parent, GNode *child, GNode *looser_brother);
void    remove_node(GNode *node);
GNode   *new_tcp_ctx(tcp_ctx_t *tcp_ctx);
void    add_tcp_ctx_to_main(tcp_ctx_t *tcp_ctx, GNode *where_to_add);
sock_ctx_t      *search_node_by_ip(tcp_ctx_t *tcp_ctx, const char *ipaddr);
sock_ctx_t      *get_last_conn_sock(tcp_ctx_t *tcp_ctx);
sock_ctx_t      *return_nth_sock(tcp_ctx_t *tcp_ctx, int idx);
int     return_sock_num(tcp_ctx_t *tcp_ctx);
int     is_host_if_cnvt(char *host_or_addr, char *cnvt_to_buff);
int     check_conf_via_sock(tcp_ctx_t *tcp_ctx, sock_ctx_t *sock_ctx);
void    unexpect_readcb(struct bufferevent *bev, void *arg);
void    release_conncb(sock_ctx_t *sock_ctx);
void    svr_sock_eventcb(struct bufferevent *bev, short events, void *user_data);
void    packet_process_res(sock_ctx_t *sock_ctx, char *process_ptr, size_t processed_len);
void    create_heartbeat_msg(sock_ctx_t *sock_ctx);
sock_ctx_t      *assign_sock_ctx(tcp_ctx_t *tcp_ctx, evutil_socket_t fd, struct sockaddr *sa);
void    sock_hb_send_cb(evutil_socket_t fd, short what, void *arg);
int     sock_add_heartbeatcb(tcp_ctx_t *tcp_ctx, sock_ctx_t *sock_ctx);
void    release_conn_by_hb(lb_ctx_t *lb_ctx, tcp_ctx_t *tcp_ctx, sock_ctx_t *sock_ctx);
void    sock_hb_chk_cb(evutil_socket_t fd, short what, void *arg);
int     sock_chk_heartbeatcb(tcp_ctx_t *tcp_ctx, sock_ctx_t *sock_ctx);
void    sock_flush_callback(evutil_socket_t fd, short what, void *arg);
int     sock_add_flushcb(tcp_ctx_t *tcp_ctx, sock_ctx_t *sock_ctx);
void    release_older_sock(tcp_ctx_t *tcp_ctx);
char    *svc_type_to_str(int svc_type);
void    *fep_conn_thread(void *arg);
void    cli_sock_eventcb(struct bufferevent *bev, short events, void *user_data);
sock_ctx_t      *create_new_peer_sock(tcp_ctx_t *tcp_ctx, const char *peer_addr);
void    check_peer_conn(evutil_socket_t fd, short what, void *arg);
void    *fep_peer_thread(void *arg);
void    CREATE_LB_THREAD(GNode *root_node, size_t context_size, int context_num);
#endif

