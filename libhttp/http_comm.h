#ifndef __HTTP_COMMON_H__
#define __HTTP_COMMON_H__

#include <ahif_msgtypes.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/shm.h>

#ifdef LOG_LIB
#include <loglib.h>
#elif LOG_APP
#include <appLog.h>
#elif LOG_PRINT
#endif

// if stream id reach to 1073741823, no more assign ascend stream id
// so prepare reconnect when stream id reach HTTP_PREPARE_STREAM_LIMIT
#if 0
#define HTTP_PREPARE_STREAM_LIMIT 1000000000
#endif

#ifdef LOG_LIB
int *lOG_FLAG;
#define APPLOG_NONE   LL0
#define APPLOG_ERR    LL1
#define APPLOG_SIMPLE LL2
#define APPLOG_DETAIL LL3
#define APPLOG_DEBUG  LL4
#define APPLOG(level, fmt, ...); {if (level <= *lOG_FLAG) logPrint(ELI, FL, fmt "\n", ##__VA_ARGS__);}
#elif LOG_APP
#elif LOG_PRINT
#define APPLOG(level, fmt, ...) fprintf(stderr, fmt "\n", ##__VA_ARGS__)
#endif


typedef enum http_encode_scheme {
	HTTP_EN_RFC3986 = 0,
	HTTP_EN_HTML5,
	HTTP_EN_XWWW
} http_encode_scheme_t;

// for AHIF special purpose
/* exception header : start with semi-colon */
#define HDR_METHOD					":method"
#define HDR_SCHEME					":scheme"
#define HDR_AUTHORITY				":authority"
#define HDR_PATH					":path"
#define HDR_STATUS					":status"
/* virtual header : non semi-colon start */
#define HDR_AUTHORIZATION			"authorization"		// authorization: Bearer token_raw
#define HDR_CONTENT_TYPE			"content-type"		// it used by NRF (http) request lib
#if 0 // move to vhdr use
#define HDR_CONTENT_ENCODING		"content-encoding"
#endif

typedef struct HttpCSAhifTagType {
	int thrd_index;
	int session_index;
	int session_id;
	int stream_id;
	int ctx_id;
} HttpCSAhifTagType;
#define HTTPCS_AHIF_MSG_TAG_LEN   sizeof(HttpCSAhifTagType)

#define ARRLEN(x) (sizeof(x) / sizeof(x[0]))

#define MAKE_NV(NAME, VALUE, VALUELEN)                                         \
  {                                                                            \
    (uint8_t *)NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, VALUELEN,             \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }

#define MAKE_NV2(NAME, VALUE)                                                  \
  {                                                                            \
    (uint8_t *)NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, sizeof(VALUE) - 1,    \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }

#define MAKE_NV_STR(NAME, VALUE)                                                  \
  {                                                                            \
    (uint8_t *)NAME, (uint8_t *)VALUE, strlen(NAME), strlen(VALUE),            \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }

#define HTTP_MAX_HOST	(512)
#define HTTP_MAX_ADDR	(4)
#define HTTP_MAX_CONN	(4)

#define MAX_SVR_NUM		(HTTP_MAX_HOST * HTTP_MAX_ADDR * HTTP_MAX_CONN)
#define MAX_CON_NUM		(HTTP_MAX_HOST * HTTP_MAX_ADDR)
#define MAX_LIST_NUM	(HTTP_MAX_HOST)
#define MAX_ITEM_NUM	(HTTP_MAX_ADDR + 1)

typedef struct item_index {
	int occupied;
	char itemname[INET6_ADDRSTRLEN];
	int port;
} item_index_t;
typedef struct index {
	char occupied;
	char listname[AHIF_MAX_DESTHOST_LEN];
	item_index_t item_idx[MAX_ITEM_NUM];
} index_t;

/* for context */
#define MAX_THRD_NUM (12)
#define MAXMSG   (10000)
#define STARTID  (1)
#define SIZEID   (10000+1)

/* for ping recv */
#define MAX_PING_WAIT 5 // (sec)

/* httpc connection status */
typedef struct conn_list_status {
	int list_index;
	int item_index;
	char scheme[12];
	char host[AHIF_MAX_DESTHOST_LEN];
	char type[AHIF_COMM_NAME_LEN];
	char ip[INET6_ADDRSTRLEN];
	int port;
	int sess_cnt;
	int conn_cnt;
	int act;
	int occupied;

	/* for OAuth 2.0 */
	int token_id;
	int token_acquired;
    int nrfm_auto_added;
} conn_list_status_t;

/* https connection status */
typedef struct conn_client {
    int occupied;
    int thrd_idx;
    int sess_idx;
    int session_id;
} conn_client_t;

typedef struct allow_list {
    int auto_added; // from allow any client action
    time_t tombstone_date; // last disconnect time

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

    /* peer overload */
    int limit_tps;
    int last_curr_tps;
    int last_drop_tps;
    int ovld_alrm_sts;
} allow_list_t;

typedef struct nrfm_https_remove_conn {
    int list_index;
    int item_index;
    char host[AHIF_MAX_DESTHOST_LEN];
} nrfm_https_remove_conn_t;

/* for statistics */
/* find current --> find thread --> find host --> write pos */
typedef enum http_statistic_enum {
	HTTP_TX_REQ = 0,
	HTTP_RX_RSP,
	HTTP_RX_REQ,
	HTTP_TX_RSP,
	HTTP_CONN,
	HTTP_DISCONN,
	HTTP_TIMEOUT,	/* send rst msg to peer */
	HTTP_RX_RST,	/* recv rst msg from peer */
	HTTP_PRE_END,	/* ahif cancel https ctx */
	HTTP_STRM_N_FOUND,
	HTTP_DEST_N_AVAIL,
	HTTP_S_INVLD_API,				/* 400 bad request */
	HTTP_S_INVLD_MSG_FORMAT,		/* 400 bad request */
	HTTP_S_MANDATORY_IE_INCORRECT,	/* 400 bad reqeust */
	HTTP_S_INSUFFICIENT_RESOURCES,	/* 500 internal server error */
	HTTP_S_SYSTEM_FAILURE,			/* 500 internal server error */
	HTTP_S_NF_CONGESTION,			/* 503 service unavailable */
	HTTP_STAT_MAX
} http_statistic_enum_t;
typedef struct http_statistic {
	int http_stat_host[HTTP_MAX_HOST][HTTP_STAT_MAX];
} http_statistic_t;
typedef struct http_stat_thrd {
	http_statistic_t http_stat_thrd[MAX_THRD_NUM];
} http_stat_thrd_t;
#define HTTP_STAT_CHAIN 2
typedef struct http_stat {
	int current;
	http_stat_thrd_t stat[HTTP_STAT_CHAIN];
} http_stat_t;

#define HTTP_STATUS_CHAIN 2
typedef struct shm_http {
	int current;
	conn_list_status_t connlist[HTTP_STATUS_CHAIN][MAX_CON_NUM];
} shm_http_t;
#define SHM_HTTP_SIZE sizeof(shm_http_t)

/* function proto type */

/* ------------------------- libshm.c --------------------------- */
int     get_http_shm(int httpc_status_shmkey);
void    set_httpc_status(conn_list_status_t conn_status[]);
int     select_next_httpc_conn(char *type, char *host, char *ip, int port, int last_selected_index, conn_list_status_t *find_raw);
int     get_shm_comm_key(char *fname, char *proc_name, int shm_mode);

/* ------------------------- libvhdr.c --------------------------- */
int     set_relay_vhdr(hdr_index_t hdr_index[], int array_size);
int     print_relay_vhdr(hdr_index_t hdr_index[], int array_size);
int     sort_relay_vhdr(hdr_index_t hdr_index[], int array_size);
hdr_index_t     *search_vhdr(hdr_index_t hdr_index[], int array_size, char *vhdr_name);

/* ------------------------- libhutil.c --------------------------- */
int     parse_ipv4(char *temp_str, struct sockaddr_in *sa, int *port);
int     parse_ipv6(char *temp_str, struct sockaddr_in6 *sa6, int *port);
int     parse_http_addr(char *temp_str, struct sockaddr_in *sa, struct sockaddr_in6 *sa6, int *port);
int		divide_string(char *input, int delim, char *head, ssize_t head_size, char *tail, ssize_t tail_size);

#endif /* __HTTP_COMMON_H__ */
