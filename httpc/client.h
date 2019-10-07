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

#include <ctype.h>
#include <event2/thread.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <err.h>
#include <signal.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <event.h>
#include <event2/event.h>
#include <event2/bufferevent_ssl.h>
#include <event2/dns.h>
#include <nghttp2/nghttp2.h>
#include <http_parser.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
/* for single request */
#include <libreq.h>
/* for lb */
#include <lbengine.h>

#ifdef OVLD_API /* nssf ovld ctrl */
#include <api_noverload.h>
#endif

#define TM_INTERVAL		20000   // every 20 ms check, 
#define TMOUT_VECTOR    50      // CLIENT_CONF.tmout_sec * TMOUT_VECTOR = N sec

/* For LOG */
extern char lOG_PATH[64];

typedef struct client_conf {
	int debug_mode;
	int log_level;
    int worker_num;
    int worker_shmkey;
    int httpc_status_shmkey;
    int timeout_sec;
	int ping_interval;
	int ping_timeout;
	int ping_event_ms;
	int ping_event_code;
	int pkt_log;
	config_setting_t *lb_config;

	int http_opt_header_table_size;
	int prepare_close_stream_limit;
	nghttp2_option *nghttp2_option;
} client_conf_t;

typedef struct thrd_context {
	pthread_t thrd_id;
	struct event_base *evbase;
	unsigned int time_index;
	int server_num;

	int msg_id;			// internal msgq id
    int running_index;
    int checked_index;
    int hang_counter;
} thrd_context_t ;


typedef enum loadshare_mode {
	LSMODE_RR = 0,		// round robin
	LSMODE_LS			// least send
} loadshare_mode_t;

#ifdef OAUTH		/* OAuth define from here */
typedef struct nrf_worker {
	pthread_t thrd_id;
	struct event_base *evbase;
} nrf_worker_t;

#define CONTENT_TYPE_OAUTH_REQ "application/x-www-form-urlencoded"

#define HBODY_ACCESS_TOKEN_REQ_FOR_TYPE "\
grant_type=client_credentials&\
nfInstanceId=%s&\
nfType=%s&\
targetNfType=%s&\
scope=%s"

#define HBODY_ACCESS_TOKEN_REQ_FOR_INSTANCE "\
grant_type=client_credentials&\
nfInstanceId=%s&\
nfType=%s&\
targetNfType=%s&\
scope=%s&\
targetNfInstanceId=%s"

typedef enum nrf_acc_type {
	AT_SVC = 0,			// token for SVC
	AT_INST				// token for specific {Instance}
} nrf_acc_type_t;

typedef enum token_acuire_status {
	TA_INIT = 0,		// not any action
	TA_FAILED,			// requested but failed
	TA_TRYING,			// trying to get token
	TA_ACCUIRED			// token accuired
} token_acuire_status_t;

#define MAX_NRF_TYPE_LEN	24
#define MAX_NRF_INST_LEN	24
#define MAX_NRF_SCOPE_LEN	256
//#define MAX_ACC_TOKEN_NUM	128
//#define MAX_ACC_TOKEN_LEN	1024
typedef struct acc_token_list {
	/* used */
	int occupied;

	/* table view */
	int token_id;
	char nrf_addr[INET6_ADDRSTRLEN + 12];
	int acc_type;
	char nf_type[MAX_NRF_TYPE_LEN];
	char nf_instance_id[MAX_NRF_INST_LEN];
	char scope[MAX_NRF_SCOPE_LEN];
	int status;
	time_t due_date;

	/* internal use */
	int inet_type;
	struct sockaddr_in sa;
	struct sockaddr_in6 sa6;
	int port;

	int token_pos;
	char access_token[2][MAX_ACC_TOKEN_LEN];
	time_t last_request_time;
} acc_token_list_t;


typedef struct access_token_res {
	char *access_token;
	char *token_type;
	int expire_in;
} access_token_res_t;
#endif		/* OAuth define to here */

typedef struct conn_list {
	int index;	// 0, 1, 2, 3, ....
	int used;	// if 1 : conn retry, 0 : don't do anything
	int conn;	// if 0 : disconnected, 1 : connected
	int act;	// 1: act, 0: deact

	char scheme[12];					// https (over TLS) | http (over TCP)
	char type[AHIF_COMM_NAME_LEN];		// UDM | PCF | ...
	char host[AHIF_MAX_DESTHOST_LEN];	// udm_fep_01 
	char ip[INET6_ADDRSTRLEN];			// 192.168.100.100
	int	port;							// 8888

	int list_index;
	int item_index;

	int thrd_index;
	int session_index;
	int session_id;

	int token_id;

	int reconn_candidate;				// stream_id is full, trigger reconnect
} conn_list_t;

typedef enum conn_status {
	CN_NOT_CONNECTED = 0,
	CN_CONNECTING,
	CN_CONNECTED
} conn_status_t;

typedef struct {
	int32_t stream_id;
	int ctx_id;
} http2_stream_data;

typedef struct httpc_ctx {
	AhifHttpCSMsgType user_ctx;
	
	/* for timeout case */
	int thrd_idx;
	int sess_idx;
	int session_id;
	int ctx_idx;
	int inflight_ref_cnt;

	char occupied;
	int	 recv_time_index;
	http2_stream_data stream;

#ifdef OAUTH
	char access_token[MAX_ACC_TOKEN_LEN];
#endif
	iovec_item_t push_req;

	/* for lb-fep-peer */
	int fep_tag;				// index of thread (fep 1 / 2 / 3)
	
	// if iovec pushed into tcp queue, worker can't cancel this
	char tcp_wait;

	/* for recv log */
	FILE *recv_log_file;
	size_t file_size;
	char *log_ptr;

	/* for NRFM CTX */
	char for_nrfm_ctx;
} httpc_ctx_t;

typedef enum intl_req_mtype {
	HTTP_INTL_SND_REQ = 0,
	HTTP_INTL_TIME_OUT,
	HTTP_INTL_SESSION_DEL,
	HTTP_INTL_SEND_PING
} intl_req_mtype_t;

typedef struct intl_req {
	long msgq_index;

	int intl_msg_type;
	HttpCSAhifTagType tag;
} intl_req_t;

typedef struct http2_session_data {
	nghttp2_session *session;
	//struct evdns_base *dnsbase;
	struct bufferevent *bev;

	char scheme[12];
	char authority[128];
	int authority_len;

	int list_index;		// hostname index

	int conn_index;
	int thrd_index;
	int session_index; 
	int session_id;		// unique id
	int used;			// 1 : used, 0 : free
	int connected;

	int ping_cnt;
	struct timeval ping_snd_time;
	struct timeval ping_rcv_time;
	int event_occured;
} http2_session_data_t;

typedef struct lb_global {
    int bundle_bytes;
    int bundle_count;
	int flush_tmval;
	int heartbeat_enable;

	int total_fep_num;
	int context_num;
	config_setting_t *cf_fep_rx_listen_port;
	config_setting_t *cf_fep_tx_listen_port;
	config_setting_t *cf_peer_listen_port;
	config_setting_t *cf_peer_connect_port;
	const char *peer_lb_address;
} lb_global_t;

typedef struct compare_input {
    char *type;
    char *host;
    char *ip;
    int port;
    int index;
} compare_input_t;

#if 0
// move to lbengine/tcp_ctx_t
typedef int (*FUNC_PTR)(void *, void *);

typedef struct select_node {
    int depth;
    int select_vector;
    int last_selected;

    char name[1024];
    int val;

    GNode *node_ptr;        // my gnode pointer
    FUNC_PTR func_ptr;      // compare function
    conn_list_t *leaf_ptr;
} select_node_t;

typedef enum select_node_depth {
    SN_TYPE = 0,
    SN_HOST,
    SN_IP,
    SN_PORT,
    SN_CONN_ID,
    SN_MAX
} select_node_depth_t;
#endif

/* ------------------------- config.c --------------------------- */
int     init_cfg();
int     config_load_just_log();
int     config_load();
int     addcfg_server_hostname(char *hostname, char *type);
int     addcfg_server_ipaddr(int id, char *scheme, char *ipaddr, int port, int conn_cnt, int token_id);
int     actcfg_http_server(int id, int ip_exist, char *ipaddr, int port, int change_to_act);
int     chgcfg_server_conn_cnt(int id, char *scheme, char *ipaddr, int port, int conn_cnt, int token_id);
int     delcfg_server_ipaddr(int id, char *ipaddr, int port);
int     delcfg_server_hostname(int id);
int     chgcfg_server_ping(int interval, int timeout, int ms);

/* ------------------------- list.c --------------------------- */
httpc_ctx_t     *get_context(int thrd_idx, int ctx_idx, int used);
void    clear_send_ctx(httpc_ctx_t *httpc_ctx);
void    clear_and_free_ctx(httpc_ctx_t *httpc_ctx);
void    set_intl_req_msg(intl_req_t *intl_req, int thrd_idx, int ctx_idx, int sess_idx, int session_id, int stream_id, int msg_type);
http2_session_data_t      *get_session(int thrd_idx, int sess_idx, int session_id);
void    save_session_info(httpc_ctx_t *httpc_ctx, int thrd_idx, int sess_idx, int session_id, int ctx_idx, conn_list_t *conn_list);
int		find_least_conn_worker();
void    print_list(conn_list_status_t conn_status[]);
void    print_raw_list();
void    write_list(conn_list_status_t CONN_STATUS[], char *buff);
void    gather_list(conn_list_status_t CONN_STATUS[]);
void    prepare_order(int list_index);
void    order_list();
#ifdef OAUTH
acc_token_list_t *get_token_list(int id, int used);
void print_token_list_raw(acc_token_list_t input_token_list[]);
#endif
void    log_pkt_send(char *prefix, nghttp2_nv *hdrs, int hdrs_len, char *body, int body_len);
void    log_pkt_head_recv(httpc_ctx_t *httpc_ctx, const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen);
void    log_pkt_end_stream(int stream_id, httpc_ctx_t *httpc_ctx);
void	log_pkt_httpc_error_reply(httpc_ctx_t *httpc_ctx, int resp_code);

/* ------------------------- client.c --------------------------- */
int     send_request(http2_session_data_t *session_data, int thrd_index, int ctx_id);
void    thrd_tick_callback(evutil_socket_t fd, short what, void *arg);
void    chk_tmout_callback(evutil_socket_t fd, short what, void *arg);
void    send_ping_callback(evutil_socket_t fd, short what, void *arg);
void    pub_conn_callback(evutil_socket_t fd, short what, void *arg);
void    send_status_to_omp(evutil_socket_t fd, short what, void *arg);
void    recv_msgq_callback(evutil_socket_t fd, short what, void *arg);
void    *workerThread(void *arg);
void    *receiverThread(void *arg);
void    create_httpc_worker();
void    conn_func(evutil_socket_t fd, short what, void *arg);
void    check_thread();
void    monitor_worker();
void    main_tick_callback(evutil_socket_t fd, short what, void *arg);
void    main_loop();
int     initialize();
int     main(int argc, char **argv);


/* ------------------------- command.c --------------------------- */
void    handle_nrfm_request(GeneralQMsgType *msg);
int     set_nrfm_response_msg(int ahif_msg_type) ;
void    message_handle(evutil_socket_t fd, short what, void *arg);
void    mml_function(IxpcQMsgType *rxIxpcMsg);
int     func_dis_http_server(IxpcQMsgType *rxIxpcMsg);
int     func_add_http_server(IxpcQMsgType *rxIxpcMsg);
int     func_add_http_svr_ip(IxpcQMsgType *rxIxpcMsg);
int     func_act_http_server(IxpcQMsgType *rxIxpcMsg);
int     func_dact_http_server(IxpcQMsgType *rxIxpcMsg);
int     func_chg_http_server_act(IxpcQMsgType *rxIxpcMsg, int change_to_act);
int     func_chg_http_server(IxpcQMsgType *rxIxpcMsg);
int     func_del_http_svr_ip(IxpcQMsgType *rxIxpcMsg);
int     func_del_http_server(IxpcQMsgType *rxIxpcMsg);
int		func_dis_http_svr_ping(IxpcQMsgType *rxIxpcMsg);
int		func_chg_http_svr_ping(IxpcQMsgType *rxIxpcMsg);


/* ------------------------- nrf.c --------------------------- */
#ifdef OAUTH
void    print_oauth_response(access_token_res_t *response);
void    parse_oauth_response(char *body, access_token_res_t *response);
void    accuire_token(acc_token_list_t *token_list);
void    chk_and_accuire_token(acc_token_list_t *token_list);
void    nrf_get_token_cb(evutil_socket_t fd, short what, void *arg);
void    *nrf_access_thread(void *arg);
char    *get_access_token(int token_id);
#endif

/* ------------------------- lb.c --------------------------- */
httpc_ctx_t     *get_null_recv_ctx(tcp_ctx_t *tcp_ctx);
httpc_ctx_t     *get_assembled_ctx(tcp_ctx_t *tcp_ctx, char *ptr);
void    send_to_worker(tcp_ctx_t *tcp_ctx, conn_list_t *httpc_conn, httpc_ctx_t *recv_ctx);
void    set_iovec(tcp_ctx_t *dest_tcp_ctx, httpc_ctx_t *recv_ctx, const char *dest_ip, iovec_item_t *push_req, void (*cbfunc)(), void *cbarg);
void    push_callback(evutil_socket_t fd, short what, void *arg);
void    iovec_push_req(tcp_ctx_t *dest_tcp_ctx, iovec_item_t *push_req);
void    stp_err_to_fep(tcp_ctx_t *fep_tcp_ctx, httpc_ctx_t *recv_ctx);
void    stp_snd_to_peer(tcp_ctx_t *peer_tcp_ctx, httpc_ctx_t *recv_ctx);
void    free_ctx_with_httpc_ctx(httpc_ctx_t *httpc_ctx);
tcp_ctx_t       *search_dest_via_tag(httpc_ctx_t *httpc_ctx, GNode *root_node);
void    send_response_to_fep(httpc_ctx_t *httpc_ctx);
void    send_to_peerlb(sock_ctx_t *sock_ctx, httpc_ctx_t *recv_ctx);
void    send_to_remote(sock_ctx_t *sock_ctx, httpc_ctx_t *recv_ctx);
void    heartbeat_process(httpc_ctx_t *recv_ctx, tcp_ctx_t *tcp_ctx, sock_ctx_t *sock_ctx);
void    check_and_send(tcp_ctx_t *tcp_ctx, sock_ctx_t *sock_ctx);
void    lb_buff_readcb(struct bufferevent *bev, void *arg);
void    load_lb_config(client_conf_t *cli_conf, lb_global_t *lb_conf);
int     get_httpcs_buff_used(tcp_ctx_t *tcp_ctx);
void    clear_context_stat(tcp_ctx_t *tcp_ctx);
void    fep_stat_print(evutil_socket_t fd, short what, void *arg);
void    *fep_stat_thread(void *arg);
void    attach_lb_thread(lb_global_t *lb_conf, lb_ctx_t *lb_ctx);
int     create_lb_thread();

/* ------------------------- select.c --------------------------- */
conn_list_t     *find_nrfm_inf_dest(AhifHttpCSMsgType *ahifPkt);
int     sn_cmp_type(void *input, void *compare);
int     sn_cmp_host(void *input, void *compare);
int     sn_cmp_ip(void *input, void *compare);
int     sn_cmp_port(void *input, void *compare);
int     sn_cmp_conn_id(void *input, void *compare);
char    *depth_to_str(int depth);
GNode   *new_select_data(compare_input_t *comm_input, int depth, conn_list_t *conn_list);
int     depth_compare(int depth, select_node_t *select_node, compare_input_t *comm_input);
select_node_t   *search_select_node(GNode *parent_node, compare_input_t *comm_input, int depth);
select_node_t   *add_select_node(GNode *parent_node, compare_input_t *comm_input, int depth, conn_list_t *conn_list);
void    create_compare_data_with_list(conn_list_t *conn_list, compare_input_t *comm_input);
void    create_compare_data_with_pkt(AhifHttpCSMsgHeadType *pkt_head, compare_input_t *comm_input);
void    reorder_select_node(select_node_t *root_node);
gboolean        traverse_memset(GNode *node, gpointer data);
conn_list_t     *search_conn_list(GNode *curr_node, compare_input_t *comm_input, select_node_t *root_node);
conn_list_t     *find_packet_index(select_node_t *root_select, AhifHttpCSMsgHeadType *pkt_head);
void    create_select_node(select_node_t *root_node);
void    destroy_select_node(select_node_t *root_node);
void    rebuild_select_node(select_node_t *root_node);
void    refresh_select_node(evutil_socket_t fd, short what, void *arg);
void    set_refresh_select_node(GNode *root_node);
void    init_refresh_select_node(lb_ctx_t *lb_ctx);
void    once_refresh_select_node(GNode *root_node);
void    trig_refresh_select_node(lb_ctx_t *lb_ctx);
