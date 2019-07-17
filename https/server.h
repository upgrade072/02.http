#include <libs.h>
#include <libconfig.h>

#include <http_comm.h>
#include <http_vhdr.h>

#include <shmQueue.h>
#include <commlib.h>
#include <ahif_msgtypes.h>
#include <sfm_msgtypes.h>
#ifdef LOG_LIB
#include <loglib.h>
#elif LOG_APP
#include <appLog.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <err.h>
#include <string.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <event.h>
#include <event2/event.h>
#include <event2/bufferevent_ssl.h>
#include <event2/listener.h>
#include <event2/thread.h>
#include <nghttp2/nghttp2.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <pthread.h>
/* OAuth 2.0 / JWT */
#include <jwt.h>
/* for lb */
#include <lbengine.h>

#include <nghttp2_session.h>

#ifdef OVLD_API /* nssf ovld ctrl */
#include <api_overload.h>
#endif

#define OUTPUT_WOULDBLOCK_THRESHOLD (1 << 16)

/* For LOG */
extern char lOG_PATH[64];

#define TM_INTERVAL     20000  // every 20ms
#define TMOUT_VECTOR    50    // SERVER_CONF.tmout_sec * TMOUT_VECTOR = N sec

#define MAX_PORT_NUM	12
typedef struct server_conf {
	int debug_mode;
	int log_level;
	int https_listen_port[MAX_PORT_NUM];
	int http_listen_port[MAX_PORT_NUM];
	int worker_num;
	int worker_shmkey;
	int timeout_sec;
	int ping_interval;
	int ping_timeout;
	int pkt_log;

	char cert_file[128];
	char key_file[128];
	char credential[MAX_ACC_TOKEN_LEN];

	/* for direct relay to fep */
	int	dr_enabled;							// 0 (not) 1 (true)
	const char *callback_ip;				// for callback uri ipaddr 
	int callback_port_tls[MAX_PORT_NUM];	// for callback uri port
	int callback_port_tcp[MAX_PORT_NUM];	// for callback uri port

    config_setting_t *lb_config;
} server_conf;

typedef struct conn_client {
	int occupied;
	int thrd_idx;
	int sess_idx;
	int session_id;
} conn_client_t;

typedef struct allow_list {
	int index;
	int used;
	int list_index;
	int item_index;

	char host[AHIF_MAX_DESTHOST_LEN];
	char type[AHIF_COMM_NAME_LEN];
	char ip[INET6_ADDRSTRLEN];
	int act;
	int max;
	int curr;

	conn_client_t client[MAX_SVR_NUM];

	int auth_act;
} allow_list_t;

typedef enum conn_status {
    CN_NOT_CONNECTED = 0,
    CN_CONNECTING,
    CN_CONNECTED
} conn_status_t;

typedef struct app_context {
	SSL_CTX *ssl_ctx;
	struct event_base *evbase;

	// for fep direct relay
	int is_direct_sock;
	int relay_fep_tag;
} app_context;

typedef struct thrd_context {
	pthread_t thrd_id;
	struct event_base *evbase;
	unsigned int time_index;
	int client_num;

	int msg_id;
    int running_index;
    int checked_index;
    int hang_counter;
} thrd_context;

typedef struct http2_stream_data {
	struct http2_stream_data *prev, *next;
	int32_t stream_id;
	int ctx_id;
} http2_stream_data;

typedef struct http2_session_data {
	nghttp2_session *session;
	http2_stream_data root;
	struct bufferevent *bev;

	char *client_addr;
	int client_port;

	char scheme[12]; 
	char type[AHIF_COMM_NAME_LEN];
	char hostname[AHIF_MAX_DESTHOST_LEN];

	int list_index;		// hostname index
	int thrd_index;
	int session_index;
	int	allowlist_index;
	int session_id; // unique id
	int used; // 1 : used, 0 : free

	int connected;
	int ping_cnt;
	struct timespec ping_rcv_time;

#ifdef OAUTH
	int auth_act;
#endif
	// for direct relay
	int is_direct_session;
	int relay_fep_tag;
} http2_session_data;

typedef struct https_ctx {
	AhifHttpCSMsgType user_ctx;

    /* for timeout case */
    int thrd_idx;
    int sess_idx;
    int session_id;
	int inflight_ref_cnt;

	char occupied;
	int  recv_time_index;

#ifdef OAUTH
	char access_token[MAX_ACC_TOKEN_LEN];
#endif
    iovec_item_t push_req;

	int fep_tag;
	//pthread_t recv_thread_id;

	int is_direct_ctx;
	int relay_fep_tag;

	// if iovec pushed into tcp queue, worker can't cancel this
	char tcp_wait;

	/* for recv log */
	FILE *recv_log_file;
	size_t file_size;
	char *log_ptr;
} https_ctx_t;

typedef enum intl_req_mtype {
    HTTP_INTL_SND_REQ = 0,
    HTTP_INTL_TIME_OUT,
	HTTP_INTL_SESSION_DEL, 
	HTTP_INTL_SEND_PING,
	HTTP_INTL_OVLD
} intl_req_mtype_t;

typedef struct intl_req {
	long msgq_index;

	int intl_msg_type;
	HttpCSAhifTagType tag;
} intl_req_t;

typedef struct lb_global {
    int bundle_bytes;
    int bundle_count;
    int flush_tmval;
	int heartbeat_enable;

    int total_fep_num;
    int context_num;
    config_setting_t *cf_fep_rx_listen_port;
    config_setting_t *cf_fep_tx_listen_port;
} lb_global_t;

/* ------------------------- config.c --------------------------- */
int     init_cfg();
int     destroy_cfg();
int     config_load_just_log();
int     config_load();
int     addcfg_client_hostname(char *hostname, char *type);
int     addcfg_client_ipaddr(int id, char *ipaddr, int max);
int     actcfg_http_client(int id, int ip_exist, char *ipaddr, int change_to_act);
int     chgcfg_client_max_cnt(int id, char *ipaddr, int max);
int     delcfg_client_ipaddr(int id, char *ipaddr);
int     delcfg_client_hostname(int id);

/* ------------------------- list.c --------------------------- */
https_ctx_t     *get_context(int thrd_idx, int ctx_idx, int used);
void    clear_new_ctx(https_ctx_t *https_ctx);
void    assign_new_ctx_info(https_ctx_t *https_ctx, http2_session_data *session_data, http2_stream_data *stream_data);
void    assign_rcv_ctx_info(https_ctx_t *https_ctx, AhifHttpCSMsgType *ResMsg);
void    clear_and_free_ctx(https_ctx_t *https_ctx);
void    set_intl_req_msg(intl_req_t *intl_req, int thrd_idx, int ctx_idx, int sess_idx, int session_id, int stream_id, int msg_type);
http2_session_data      *get_session(int thrd_idx, int sess_idx, int session_id);
void    save_session_info(https_ctx_t *https_ctx, int thrd_idx, int sess_idx, int session_id, char *ipaddr);
int     check_allow(char *ip);
int     add_to_allowlist(int list_idx, int thrd_idx, int sess_idx, int session_id);
int     del_from_allowlist(int list_idx, int thrd_idx, int sess_idx);
void    print_list();
void    write_list(char *buff);
void    log_pkt_send(char *prefix, nghttp2_nv *hdrs, int hdrs_len, char *body, int body_len);
void    log_pkt_head_recv(https_ctx_t *https_ctx, const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen);
void    log_pkt_end_stream(int stream_id, https_ctx_t *https_ctx);

/* ------------------------- main.c --------------------------- */
int     get_in_port(struct sockaddr *sa);
int     find_least_conn_worker();
int     check_access_token(char *token);
void    check_thread();
void    monitor_worker();
void    main_tick_callback(evutil_socket_t fd, short what, void *arg);
void    recv_msgq_callback(evutil_socket_t fd, short what, void *arg);
void    thrd_tick_callback(evutil_socket_t fd, short what, void *arg);
void    chk_tmout_callback(evutil_socket_t fd, short what, void *arg);
void    send_ping_callback(evutil_socket_t fd, short what, void *arg);
void    send_status_to_omp(evutil_socket_t fd, short what, void *arg);
void	initialize_nghttp2_session(http2_session_data *session_data);
void    *workerThread(void *arg);
void    create_https_worker();
int     initialize();
int     main(int argc, char **argv);

/* ------------------------- command.c --------------------------- */
void    message_handle(evutil_socket_t fd, short what, void *arg);
void    mml_function(IxpcQMsgType *rxIxpcMsg);
int     func_dis_http_client(IxpcQMsgType *rxIxpcMsg);
int     func_add_http_client(IxpcQMsgType *rxIxpcMsg);
int     func_add_http_cli_ip(IxpcQMsgType *rxIxpcMsg);
int     func_act_http_client(IxpcQMsgType *rxIxpcMsg);
int     func_dact_http_client(IxpcQMsgType *rxIxpcMsg);
int     func_chg_http_client_act(IxpcQMsgType *rxIxpcMsg, int change_to_act);
int     func_chg_http_client(IxpcQMsgType *rxIxpcMsg);
int     func_del_http_cli_ip(IxpcQMsgType *rxIxpcMsg);
int     func_del_http_client(IxpcQMsgType *rxIxpcMsg);

/* ------------------------- lb.c --------------------------- */
https_ctx_t     *get_null_recv_ctx(tcp_ctx_t *tcp_ctx);
https_ctx_t     *get_assembled_ctx(tcp_ctx_t *tcp_ctx, char *ptr);
void    set_iovec(tcp_ctx_t *dest_tcp_ctx, https_ctx_t *https_ctx, const char *dest_ip, iovec_item_t *push_req, void (*cbfunc)(), void *cbarg);
void    push_callback(evutil_socket_t fd, short what, void *arg);
void    iovec_push_req(tcp_ctx_t *dest_tcp_ctx, iovec_item_t *push_req);
tcp_ctx_t       *get_loadshare_turn(https_ctx_t *https_ctx);
tcp_ctx_t       *get_direct_dest(https_ctx_t *https_ctx);
void    gb_clean_ctx(https_ctx_t *https_ctx);
void    set_callback_tag(https_ctx_t *https_ctx, tcp_ctx_t *fep_tcp_ctx);
int     send_request_to_fep(https_ctx_t *https_ctx);
void    send_to_worker(tcp_ctx_t *tcp_ctx, https_ctx_t *recv_ctx, int intl_msg_type);
void    heartbeat_process(https_ctx_t *recv_ctx, tcp_ctx_t *tcp_ctx, sock_ctx_t *sock_ctx, int staCause);
void    check_and_send(tcp_ctx_t *tcp_ctx, sock_ctx_t *sock_ctx);
void    lb_buff_readcb(struct bufferevent *bev, void *arg);
int     get_httpcs_buff_used(tcp_ctx_t *tcp_ctx);
void    clear_context_stat(tcp_ctx_t *tcp_ctx);
void    fep_stat_print(evutil_socket_t fd, short what, void *arg);
void    *fep_stat_thread(void *arg);
void    load_lb_config(server_conf *svr_conf, lb_global_t *lb_conf);
void    attach_lb_thread(lb_global_t *lb_conf, lb_ctx_t *lb_ctx);
int     create_lb_thread();
