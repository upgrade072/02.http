#include <libs.h>
#include <libconfig.h>

#include <http_comm.h>
#include <shmQueue.h>
#include <commlib.h>
#include <ahif_msgtypes.h>
#include <sfm_msgtypes.h>
#ifdef UDMR
#include <appLog.h>
#endif

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
#include <pthread.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#define TM_INTERVAL		20000   // every 20 ms check, 
#if 0
#define TMOUT_NORSP		200     // 20ms * 200 = 4 sec timeout
#else
#define TMOUT_VECTOR    50      // CLIENT_CONF.tmout_sec * TMOUT_VECTOR = N sec
#endif

/* For LOG */
extern char lOG_PATH[64];

typedef struct client_conf {
	int log_level;
    int worker_num;
    int timeout_sec;
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

#define MAX_COUNT_NUM	1024
typedef struct conn_list {
	int index; // 0, 1, 2, 3, ....
	int used; // if 1 : conn retry, 0 : don't do anything
	int conn; // if 0 : disconnected, 1 : connected

//  char schema[MAX_SCHEMA_NAME];	// https, http
	char host[AHIF_MAX_DESTHOST_LEN];	// localhost, 127.0.0.1, 192.168.8.1 ...
	char type[AHIF_COMM_NAME_LEN];
	int list_index;
	int item_index;

	char ip[INET6_ADDRSTRLEN];
	int	port;		// 8888
	int act;		// 1: act, 0: deact

	int next_hop;
	int max_hop;
	int curr_idx;	// 
	int counter;	// sended packet num

	int thrd_index;
	int session_index;
	int session_id;
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
	int inflight_ref_cnt;

	char occupied;
	int	 recv_time_index;
	http2_stream_data stream;

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

	char authority[128];
	int authority_len;

	int list_index;		// hostname index

	int conn_index;
	int thrd_index;
	int session_index; 
	int session_id;		// unique id
	int used;			// 1 : used, 0 : free

	int connected;
	int ping_snd;
} http2_session_data;

/* ------------------------- config.c --------------------------- */
int     init_cfg();
int     destroy_cfg();
int     config_load_just_log();
int     config_load();
int     addcfg_server_hostname(char *hostname, char *type);
int     addcfg_server_ipaddr(int id, char *ipaddr, int port, int conn_cnt);
int     actcfg_http_server(int id, int ip_exist, char *ipaddr, int port, int change_to_act);
int     chgcfg_server_conn_cnt(int id, char *ipaddr, int port, int conn_cnt);
int     delcfg_server_ipaddr(int id, char *ipaddr, int port);
int     delcfg_server_hostname(int id);

/* ------------------------- list.c --------------------------- */
httpc_ctx_t     *get_context(int thrd_idx, int ctx_idx, int used);
void    clear_send_ctx(httpc_ctx_t *httpc_ctx);
void    clear_and_free_ctx(httpc_ctx_t *httpc_ctx);
void    set_intl_req_msg(intl_req_t *intl_req, int thrd_idx, int ctx_idx, int sess_idx, int session_id, int stream_id, int msg_type);
http2_session_data      *get_session(int thrd_idx, int sess_idx, int session_id);
void    save_session_info(httpc_ctx_t *httpc_ctx, int thrd_idx, int sess_idx, int session_id);
int     find_least_conn_worker();
void    print_list(conn_list_status_t conn_status[]);
void    print_raw_list();
void    write_list(conn_list_status_t CONN_STATUS[], char *buff);
void    gather_list(conn_list_status_t CONN_STATUS[]);
void    prepare_order(int list_index);
void    order_list();
int     find_packet_index(char *host, int ls_mode);

/* ------------------------- client.c --------------------------- */
int     send_request(struct http2_session_data *session_data, int thrd_index, int ctx_id);
void    thrd_tick_callback(evutil_socket_t fd, short what, void *arg);
void    chk_tmout_callback(evutil_socket_t fd, short what, void *arg);
void    send_ping_callback(evutil_socket_t fd, short what, void *arg);
void    pub_conn_callback(evutil_socket_t fd, short what, void *arg);
void    send_status_to_omp(evutil_socket_t fd, short what, void *arg);
void    recv_msgq_callback(evutil_socket_t fd, short what, void *arg);
void    *workerThread(void *arg);
void    *receiverThread(void *arg);
void    thrd_initialize();
void    conn_func(evutil_socket_t fd, short what, void *arg);
void    check_thread();
void    monitor_worker();
void    main_tick_callback(evutil_socket_t fd, short what, void *arg);
void    main_loop();
int     initialize();
int     main(int argc, char **argv);

/* ------------------------- command.c --------------------------- */
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
