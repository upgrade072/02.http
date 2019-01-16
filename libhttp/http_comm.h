#ifndef __HTTP_COMMON_H__
#define __HTTP_COMMON_H__

#include <ahif_msgtypes.h>
#include <arpa/inet.h>

/* HTTPCS STACK VALUE */
#ifndef TEST
//#define HTTPC_SEMAPHORE_NAME		"httpc_sem_status"
#define HTTPC_SHM_MEM_KEY			0x00520000
#define HTTPC_INTL_MSG_KEY_BASE		0x00520100 // ~ 0x00520111
#define HTTPS_INTL_MSG_KEY_BASE		0x00520200 // ~ 0x00520211
#else
//#define HTTPC_SEMAPHORE_NAME		"httpc_sem_status_test"
#define HTTPC_SHM_MEM_KEY			0x00620000
#define HTTPC_INTL_MSG_KEY_BASE		0x00620100 // ~ 0x00620111
#define HTTPS_INTL_MSG_KEY_BASE		0x00620200 // ~ 0x00620211
#endif

#define AHIF_HTTPC_SEND_SIZE(a) AHIF_HTTPCS_MSG_HEAD_LEN + a.head.bodyLen
#define HTTPC_AHIF_SEND_SIZE(a) AHIF_HTTPCS_MSG_HEAD_LEN + a.head.bodyLen
#define HTTPS_AHIF_SEND_SIZE	HTTPC_AHIF_SEND_SIZE
#define AHIF_HTTPS_SEND_SIZE	AHIF_HTTPC_SEND_SIZE

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


#define HTTP_MAX_HOST		128
#define HTTP_MAX_ADDR		4
#define HTTP_MAX_CONN		4

#define MAX_SVR_NUM		HTTP_MAX_HOST * HTTP_MAX_ADDR * HTTP_MAX_CONN
#define MAX_CON_NUM		HTTP_MAX_HOST * HTTP_MAX_ADDR
#define MAX_LIST_NUM	HTTP_MAX_HOST
#define MAX_ITEM_NUM	HTTP_MAX_ADDR + 1

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
#define MAX_THRD_NUM 12
#define MAXMSG   10000
#define STARTID  1
#define SIZEID 10000+1 

/* for ping recv */
#define MAX_PING_WAIT 5 // (sec)

/* connection status */
typedef struct conn_list_status {
	int list_index;
	int item_index;
	char host[AHIF_MAX_DESTHOST_LEN];
	char type[AHIF_COMM_NAME_LEN];
	char ip[INET6_ADDRSTRLEN];
	int port;
	int sess_cnt;
	int conn_cnt;
	int act;
	int occupied;
} conn_list_status_t;

/* for statistics */
/* find current --> find thread --> find host --> write pos */
typedef enum http_statistic_enum {
	HTTP_TX_REQ = 0,
	HTTP_RX_RSP,
	HTTP_RX_REQ,
	HTTP_TX_RSP,
	HTTP_CONN,
	HTTP_DISCONN,
	HTTP_TIMEOUT,
	HTTP_STRM_N_FOUND,
	HTTP_DEST_N_AVAIL,
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
int     get_http_shm(void);
void    set_httpc_status(conn_list_status_t conn_status[]);
#endif /* __HTTP_COMMON_H__ */
