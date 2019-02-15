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
#include <http_comm.h>
#include <http_parser.h>
#include <libs.h>

typedef struct libhttp_single_sndreq {
	char *uri;					/* request uri https:// { ip | [ipv6] } : port / api */
	char *method;				/* GET POST PUT DEL ... */
	char *content_type;			/* ex) application/x-www-form-urlencoded | application/json */
	void *body;					/* ptr where to request body */
	size_t body_size;			/* sizeof body pointed (send length) */
} libhttp_single_sndreq_t;

typedef struct libhttp_single_rcvres {
	int res_code;				/* http response code */
	char *body;					/* ptr where to save response */
	size_t body_size;			/* maximum recv size (sizeof body pointed) */
	int	body_len;				/* received length */
} libhttp_single_rcvres_t;

typedef struct libhttp_stream_data {
	const char *uri;			/* The NULL-terminated URI string to retrieve. */
	struct http_parser_url *u;	/* Parsed result of the |uri| */
	char *authority;			/* The authority portion of the |uri|, not NULL-terminated */
	char *path;					/* The path portion of the |uri|, including query, not NULL-terminated */
	size_t authoritylen;		/* The length of the |authority| */
	size_t pathlen;				/* The length of the |path| */
	int32_t stream_id;			/* The stream ID of this stream */

	libhttp_single_sndreq_t *sndreq;
	libhttp_single_rcvres_t *rcvres;
} libhttp_stream_data_t;

typedef struct libhttp_session_data {
	nghttp2_session *session;

	struct evdns_base *dnsbase;
	struct bufferevent *bev;

	libhttp_stream_data_t *stream_data;
} libhttp_session_data_t;

/* ------------------------- request.c --------------------------- */
void    single_run(libhttp_single_sndreq_t *sndreq, libhttp_single_rcvres_t *rcvres);
