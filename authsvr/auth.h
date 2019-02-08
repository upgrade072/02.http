#include <sys/types.h>
#include <sys/socket.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
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

#include <nghttp2/nghttp2.h>
#include <jwt.h>

#include <libconfig.h>

#include <libs.h>

#define OUTPUT_WOULDBLOCK_THRESHOLD (1 << 16)

/* -------------------------------------------------------------- */

#define NRF_UUID "Nnrf-UUID-1234-ABCD"
#define NRF_TOKEN_EXPIRE "3600" /* 1 hour */

#define MAX_SCOPE_NUM 24
typedef struct access_token_req {
    char *grant_type;
    char *nfInstanceId;
    char *nfType;
    char *targetNfType;
	char scope_raw[1024];
    char *scope[MAX_SCOPE_NUM];
    char *targetNfInstanceId;
} access_token_req_t;

#define MAX_BODY_LEN 1024
typedef struct http2_stream_data {
	struct http2_stream_data *prev, *next;
	char *request_path;
	int32_t stream_id;
	int fd;

	char method[12];
	char content_type[42];

	char body[MAX_BODY_LEN];
	int body_len;
} http2_stream_data;

typedef struct app_context {
	SSL_CTX *ssl_ctx;
	struct event_base *evbase;
} app_context_t;

typedef struct http2_session_data {
	struct http2_stream_data root;
	struct bufferevent *bev;
	app_context_t *app_ctx;
	nghttp2_session *session;
	char *client_addr;
} http2_session_data;

/* ------------------------- http.c --------------------------- */
void	run(const char *service, const char *key_file, const char *cert_file);
void    print_stream_data(http2_stream_data *stream_data);
int 	send_response(nghttp2_session *session, int32_t stream_id, nghttp2_nv *nva, size_t nvlen, void *ptr);

/* ------------------------- main.c --------------------------- */
int     main(int argc, char **argv);

/* ------------------------- config.c --------------------------- */
void    print_nf_list(config_setting_t *elem);
config_setting_t        *search_nf_by_value(const char *name, char *find_value);
config_setting_t        *search_nf_by_auth_info(access_token_req_t *auth_req);
int     get_hash_alg();
int     init_cfg();

/* ------------------------- nrf.c --------------------------- */
void    parse_oauth_request(char *body, access_token_req_t *request);
void    print_oauth_request(access_token_req_t *request);
int     check_scope_mismatch(access_token_req_t *req, config_setting_t *scope);
int     issue_access_token(access_token_req_t *auth_req, config_setting_t *conf, char *token_buff);
int		on_request_recv_nrf(nghttp2_session *session, http2_session_data *session_data, http2_stream_data *stream_data);
