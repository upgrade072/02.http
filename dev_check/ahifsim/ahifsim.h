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

#include <libconfig.h>
#include <event.h>
#include <event2/event.h>
#include <event2/thread.h>

#include <ahif_msgtypes.h>

#define CONFIG_PATH "./ahifsim.cfg"

#define MAX_IOV_CNT 3
#define MAX_IOV_PUSH 256
#define MAX_RCV_BUFF_LEN 1024 * 1024 // 1MB

#define MAX_TEST_CTX_NUM 100000

#define TEST_URI "/test_uri/ctx_id/"

typedef enum conn_type {
	TT_HTTPC_TX = 0,
	TT_HTTPC_RX,
	TT_HTTPS_TX,
	TT_HTTPS_RX,
	TT_NUMOF
} conn_type_t;

typedef struct iovec_item {
	struct iovec iov[MAX_IOV_CNT];
	int iov_cnt;
	int next_start_pos;
	int remain_bytes;

	char *ctx_unset_ptr;
	void *sender_thrd_ctx;
	config_t *CFG;
} iovec_item_t;

typedef struct write_item {
	struct write_item *prev, *next;         /* linked */
	iovec_item_t *iovec_item;               /* item */
} write_item_t;

typedef struct write_list {
	write_item_t *root;                     /* first item */
	write_item_t *last;                     /* last item */

	int item_cnt;                           /* match with {bundle_cnt} */
	int item_bytes;                         /* match with {bundle_bytes} */
} write_list_t;

typedef struct thrd_ctx {
	int my_conn_type;
	const char *ipaddr;
	int port;
	int fd;
	int connected;

	struct event_base *evbase;
	struct bufferevent *bev;

	write_list_t push_items;

	char buff[MAX_RCV_BUFF_LEN];
	int rcv_len;

	void *MAIN_CTX;

	/* stat */
	int send_bytes;
	int recv_bytes;
} thrd_ctx_t;

typedef struct ahif_ctx {
	char occupied;
	int ctxId;
	AhifHttpCSMsgType ahif_pkt;
	iovec_item_t push_req;
} ahif_ctx_t;

typedef struct main_ctx {
	config_t CFG;

	/* with CFG R.R */
	int dest_hosts_pos;
	int vheader_cnts_pos;
	int body_lens_pos;

	/* context */
	ahif_ctx_t *ahif_ctx;

	thrd_ctx_t httpc_tx_ctx;
	thrd_ctx_t httpc_rx_ctx;
	thrd_ctx_t https_tx_ctx;
	thrd_ctx_t https_rx_ctx;

	/* stat */
	int httpc_send_cnt;
	int https_recv_cnt;
	int https_send_cnt;
	int httpc_recv_cnt;
} main_ctx_t;


/* ------------------------- pkt.c --------------------------- */
ahif_ctx_t      *get_null_ctx(main_ctx_t *MAIN_CTX);
void    set_ahif_ctx(main_ctx_t *MAIN_CTX, ahif_ctx_t *ahif_ctx);
void    set_iovec(ahif_ctx_t *ahif_ctx, iovec_item_t *push_req, char *ctx_unset_ptr);
void    push_callback(evutil_socket_t fd, short what, void *arg);
void    iovec_push_req(main_ctx_t *MAIN_CTX, thrd_ctx_t *tx_thread_ctx, iovec_item_t *push_req);
void    snd_ahif_pkt(main_ctx_t *MAIN_CTX);
void    https_echo_rx_to_tx(main_ctx_t *MAIN_CTX, ahif_ctx_t *ahif_ctx);
void    httpc_remove_ctx(main_ctx_t *MAIN_CTX, ahif_ctx_t *ahif_ctx);
void    rx_handle_func(thrd_ctx_t *thrd_ctx, void (*handle_func)());

/* ------------------------- main.c --------------------------- */
int     init_cfg(main_ctx_t *MAIN_CTX);
thrd_ctx_t      *read_thread_conf(main_ctx_t *MAIN_CTX, config_setting_t *setting, char conn_type);
double  commlib_getCurrTime_double (void);
int     util_set_linger(int fd, int onoff, int linger);
int     util_set_rcvbuffsize(int fd, int byte);
int     util_set_sndbuffsize(int fd, int byte);
int     crt_new_conn(thrd_ctx_t *thrd_ctx, bufferevent_data_cb readcb, bufferevent_data_cb writecb, bufferevent_event_cb eventcb);
void    *perf_thread(void *arg);
int     create_thread(thrd_ctx_t *thrd_ctx);
int     init_thread(main_ctx_t *MAIN_CTX);
void    end_perf();
void    perf_gen(main_ctx_t *MAIN_CTX);
int     main();

/* ------------------------- list.c --------------------------- */
write_item_t    *create_write_item(write_list_t *write_list, iovec_item_t *iovec_item);
ssize_t push_write_item(int fd, write_list_t *write_list, int bundle_cnt, int bundle_bytes);
void    unset_pushed_item(write_list_t *write_list, ssize_t nwritten);

/* ------------------------- util.c --------------------------- */
void    util_dumphex(const void* data, size_t size);

/* ------------------------- cb.c --------------------------- */
void    sock_eventcb(struct bufferevent *bev, short events, void *user_data);
void    packet_process_res(thrd_ctx_t *thrd_ctx, char *process_ptr, size_t processed_len);
ahif_ctx_t      *get_sended_ctx(main_ctx_t *MAIN_CTX, char *ctxIdStr);
ahif_ctx_t      *get_assembled_ctx(main_ctx_t *MAIN_CTX, char *ptr);
void    https_read_cb(struct bufferevent *bev, void *arg);
void    httpc_read_cb(struct bufferevent *bev, void *arg);
