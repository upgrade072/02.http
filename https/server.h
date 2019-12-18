#ifndef __HTTPS_H__
#define __HTTPS_H__

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
#include <jansson.h>
#include <jwt.h>
/* for lb */
#include <lbengine.h>

#include <libfort.h>

#include <nghttp2_session.h>

#ifdef OVLD_API /* nssf ovld ctrl */
#include <api_noverload.h>
#endif

#define OUTPUT_WOULDBLOCK_THRESHOLD (1 << 16)

/* CONFIG */
#define CF_SERVER_CONF      "server.cfg"
#define CF_LOG_LEVEL        "server_cfg.sys_config.log_level"
#define CF_DEBUG_MODE       "server_cfg.sys_config.debug_mode"
#define CF_WORKER_SHMKEY    "server_cfg.sys_config.worker_shmkey_base"
#define CF_TLS_LISTEN_PORT  "server_cfg.http_config.listen_port_tls"
#define CF_TCP_LISTEN_PORT  "server_cfg.http_config.listen_port_tcp"
#define CF_MAX_WORKER_NUM   "server_cfg.http_config.worker_num"
#define CF_TIMEOUT_SEC      "server_cfg.http_config.timeout_sec"
#define CF_PING_INTERVAL    "server_cfg.http_config.ping_interval"
#define CF_PING_TIMEOUT     "server_cfg.http_config.ping_timeout"
#define CF_PING_EVENT_MS    "server_cfg.http_config.ping_event_ms"
#define CF_PING_EVENT_CODE  "server_cfg.http_config.ping_event_code"
#define CF_CERT_EVENT_CODE  "server_cfg.http_config.cert_event_code"
#define CF_DEF_OVLD_LIMIT   "server_cfg.http_config.def_ovld_limit"
#define CF_OVLD_EVENT_CODE  "server_cfg.http_config.ovld_event_code"
#define CF_ALLOW_ANY_CLIENT "server_cfg.http_config.allow_any_client"
#define CF_ANY_CLIENT_DEFAULT_MAX   "server_cfg.http_config.any_cli_def_max"
#define CF_HTTP_OPT_HDR_TABLE_SIZE  "server_cfg.http_option.setting_header_table_size"
#define CF_PKT_LOG          "server_cfg.http_config.pkt_log"
#define CF_CERT_FILE        "server_cfg.oauth_config.cert_file"
#define CF_KEY_FILE         "server_cfg.oauth_config.key_file"
#define CF_CREDENTIAL       "server_cfg.oauth_config.credential"
//#define CF_UUID_FILE        "server_cfg.oauth_config.uuid_file"
#define CF_LB_CONFIG        "server_cfg.lb_config"
#define CF_DRELAY_CONFIG    "server_cfg.direct_relay"
#define CF_DRELAY_ENABLE    "server_cfg.direct_relay.enable"
#define CF_CALLBACK_IP      "server_cfg.direct_relay.callback_ip"
#define CF_CALLBACK_TLS_PORT    "server_cfg.direct_relay.callback_port_tls"
#define CF_CALLBACK_TCP_PORT    "server_cfg.direct_relay.callback_port_tcp"
#define CF_ALLOW_LIST       "allow_list"

/* For LOG */
extern char lOG_PATH[64];

#define TM_INTERVAL     20000  // every 20ms
#define TMOUT_VECTOR    50    // SERVER_CONF.tmout_sec * TMOUT_VECTOR = N sec

#define MAX_PEER_NF_NUM 12      // associate_conf. peer (sameType)
typedef struct uuid_list {
    int peer_nfs_num;
    char uuid[MAX_PEER_NF_NUM][128];
} uuid_list_t;

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
	int ping_event_ms;
	int ping_event_code;
	int cert_event_code;
	int pkt_log;
    config_setting_t *lb_config;

	int http_opt_header_table_size;
	nghttp2_option *nghttp2_option;

	/* for OAUTH 2.0 */
	char cert_file[128];
	char key_file[128];
	char credential[512];
#if 0
	char uuid_file[12][128];
#else
    /* uuid(s) from ~/associate_conf by type */
    uuid_list_t uuid_list;
#endif

	/* for direct relay to fep */
	int	dr_enabled;							// 0 (not) 1 (true)
	const char *callback_ip;				// for callback uri ipaddr 
	int callback_port_tls[MAX_PORT_NUM];	// for callback uri port
	int callback_port_tcp[MAX_PORT_NUM];	// for callback uri port

	/* for overload ctrl */
	int def_ovld_limit;
	int ovld_event_code;

    /* for NRF import NF Client */
    int allow_any_client;
    int any_client_default_max;

    /* for WEIGHT balance */
    int weight[MAX_THRD_NUM];
    int size;
} server_conf;

#define MAX_OVLD_POS 3
typedef struct peer_ovld {
	int curr_tps[MAX_LIST_NUM];
	int drop_tps[MAX_LIST_NUM];
} peer_ovld_t;

typedef struct ovld_state {
	int curr_pos;
	peer_ovld_t peer_ovld[MAX_OVLD_POS][MAX_THRD_NUM];
} ovld_state_t;

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

typedef struct load_weight {
    /* footstep */
    int pointer;
    int counter;
} load_weight_t;

typedef struct thrd_context {
	pthread_t thrd_id;
	struct event_base *evbase;
	unsigned int time_index;
	int client_num;

	int msg_id;
    int running_index;
    int checked_index;
    int hang_counter;

    /* for weight balance */
    load_weight_t weight;
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
	struct timeval ping_snd_time;
	struct timeval ping_rcv_time;
	int event_occured;

    /* oauth 2.0 */
	int auth_act;

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

	char access_token[512];

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

	/* for NRFM CTX (notify from NRF) */
	char for_nrfm_ctx;
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
    config_setting_t *cf_fep_weight_balance;
} lb_global_t;


/* ------------------------- config.c --------------------------- */
int     init_cfg();
int     config_load_just_log();
int     config_load();
int     addcfg_client_hostname(char *hostname, char *type);
int     addcfg_client_ipaddr(int id, char *ipaddr, int max, int auth_act);
int     actcfg_http_client(int id, int ip_exist, char *ipaddr, int change_to_act);
int     chgcfg_client_max_cnt_with_auth_act_and_limit(int id, char *ipaddr, int max, int auth_act, int limit);
int     delcfg_client_ipaddr(int id, char *ipaddr);
int     delcfg_client_hostname(int id);
int     chgcfg_client_ping(int interval, int timeout, int ms);

/* ------------------------- list.c --------------------------- */
https_ctx_t     *get_context(int thrd_idx, int ctx_idx, int used);
void    clear_new_ctx(https_ctx_t *https_ctx);
void    assign_new_ctx_info(https_ctx_t *https_ctx, http2_session_data *session_data, http2_stream_data *stream_data);
void    assign_rcv_ctx_info(https_ctx_t *https_ctx, AhifHttpCSMsgType *ResMsg);
void    clear_and_free_ctx(https_ctx_t *https_ctx);
void    set_intl_req_msg(intl_req_t *intl_req, int thrd_idx, int ctx_idx, int sess_idx, int session_id, int stream_id, int msg_type);
http2_session_data      *get_session(int thrd_idx, int sess_idx, int session_id);
void    save_session_info(https_ctx_t *https_ctx, int thrd_idx, int sess_idx, int session_id, char *ipaddr);
int     check_allow(char *ip, int allow_any_client);
int     add_to_allowlist(int list_idx, int thrd_idx, int sess_idx, int session_id);
int     del_from_allowlist(int list_idx, int thrd_idx, int sess_idx);
void    disconnect_all_client_in_allow_list(allow_list_t *allow_list);
void    print_list();
void    write_list(char *buff);
void    log_pkt_send(char *prefix, nghttp2_nv *hdrs, int hdrs_len, char *body, int body_len);
void    log_pkt_head_recv(https_ctx_t *https_ctx, const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen);
void    log_pkt_end_stream(int stream_id, https_ctx_t *https_ctx);
int     get_uuid_from_associate(uuid_list_t *uuid_list);

/* ------------------------- main.c --------------------------- */
int     get_in_port(struct sockaddr *sa);
int     find_least_conn_worker();
int     check_access_token(char *token, char *oauth_scope);
void    check_thread();
void    monitor_worker();
void    main_tick_callback(evutil_socket_t fd, short what, void *arg);
void    https_shm_callback(evutil_socket_t fd, short what, void *arg);
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
void    handle_nrfm_request(GeneralQMsgType *msg);
void    handle_nrfm_response(GeneralQMsgType *msg);
void    adjust_loglevel(TrcLibSetPrintMsgType *trcMsg);
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
int     func_dis_https_config(IxpcQMsgType *rxIxpcMsg);
void    relaod_http_config(char *conf_name, int conf_val);
int     func_chg_https_config(IxpcQMsgType *rxIxpcMsg);
int     func_https_weight_conf(IxpcQMsgType *rxIxpcMsg);

/* ------------------------- lb.c --------------------------- */
https_ctx_t     *get_null_recv_ctx(tcp_ctx_t *tcp_ctx);
https_ctx_t     *get_assembled_ctx(tcp_ctx_t *tcp_ctx, char *ptr);
void    set_iovec(tcp_ctx_t *dest_tcp_ctx, https_ctx_t *https_ctx, const char *dest_ip, iovec_item_t *push_req, void (*cbfunc)(), void *cbarg);
void    push_callback(evutil_socket_t fd, short what, void *arg);
void    iovec_push_req(tcp_ctx_t *dest_tcp_ctx, iovec_item_t *push_req);
tcp_ctx_t       *get_loadshare_turn(https_ctx_t *https_ctx);
tcp_ctx_t       *thread_conn_status(GNode *root_node, int pos);
tcp_ctx_t       *get_weight_balance_turn(https_ctx_t *https_ctx);
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
void    send_fep_conn_status(evutil_socket_t fd, short what, void *arg);
void    nrfm_send_conn_status_callback(tcp_ctx_t *tcp_ctx);
int     create_lb_thread();

/* ------------------------- cert.c --------------------------- */
X509    *load_cert(const char *file);
void    check_cert(const char *cert_file);

/* ------------------------- ovld.c --------------------------- */
int     ovld_calc_check(http2_session_data *session_data);
void    ovld_step_forward();

#endif /* __HTTPS_H__ */
