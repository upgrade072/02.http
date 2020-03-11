#include "server.h"

char mySysName[COMM_MAX_NAME_LEN];
char myProcName[COMM_MAX_NAME_LEN];

//#ifdef LOG_APP
int logLevel = APPLOG_DEBUG;
int *lOG_FLAG = &logLevel;
//#endif

int httpsQid, ixpcQid, nrfmQid;

int THREAD_NO[MAX_THRD_NUM] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
int SESSION_ID;
int SESS_IDX;
server_conf SERVER_CONF;

thrd_context THRD_WORKER[MAX_THRD_NUM];
http2_session_data SESS[MAX_THRD_NUM][MAX_SVR_NUM];
https_ctx_t *HttpsCtx[MAX_THRD_NUM];
allow_list_t ALLOW_LIST[MAX_LIST_NUM];
allow_list_t *ALLOW_LIST_SHM;
http_stat_t HTTP_STAT;
ovld_state_t OVLD_STATE;
extern lb_global_t LB_CONF; 

hdr_index_t VHDR_INDEX[2][MAX_HDR_RELAY_CNT];

#ifdef OVLD_API
extern int lb_api_ovld_is_ctrl(int trid, int proto, char *host, char *err_str);
#endif

// for lb ctx print
extern lb_global_t LB_CONF;
extern lb_ctx_t LB_CTX;

static unsigned char next_proto_list[256];
static size_t next_proto_list_len;

static void readcb(struct bufferevent *bev, void *ptr); // TODO, remove this define to .h
static void writecb(struct bufferevent *bev, void *ptr);
static void eventcb(struct bufferevent *bev, short events, void *ptr);

static int next_proto_cb(SSL *ssl, const unsigned char **data,
		unsigned int *len, void *arg) {
	(void)ssl;
	(void)arg;

	*data = next_proto_list;
	*len = (unsigned int)next_proto_list_len;
	return SSL_TLSEXT_ERR_OK;
}

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
static int alpn_select_proto_cb(SSL *ssl, const unsigned char **out,
		unsigned char *outlen, const unsigned char *in,
		unsigned int inlen, void *arg) {
	int rv;
	(void)ssl;
	(void)arg;

	rv = nghttp2_select_next_protocol((unsigned char **)out, outlen, in, inlen);

	if (rv != 1) {
		return SSL_TLSEXT_ERR_NOACK;
	}

	return SSL_TLSEXT_ERR_OK;
}
#endif // OPENSSL_VERSION_NUMBER >= 0x10002000L

/* Create SSL_CTX. */
static SSL_CTX *create_ssl_ctx(const char *key_file, const char *cert_file) {
	SSL_CTX *ssl_ctx;
	EC_KEY *ecdh;

	ssl_ctx = SSL_CTX_new(SSLv23_server_method());
	if (!ssl_ctx) {
		APPLOG(APPLOG_ERR, "%s(), Could not create SSL/TLS context: %s",
				__func__, ERR_error_string(ERR_get_error(), NULL));
	}
	SSL_CTX_set_options(ssl_ctx,
			SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
			SSL_OP_NO_COMPRESSION |
			SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);

	ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if (!ecdh) {
		APPLOG(APPLOG_ERR, "%s() EC_KEY_new_by_curv_name failed: %s",
				__func__, ERR_error_string(ERR_get_error(), NULL));
	}
	SSL_CTX_set_tmp_ecdh(ssl_ctx, ecdh);
	EC_KEY_free(ecdh);

	if (SSL_CTX_use_PrivateKey_file(ssl_ctx, key_file, SSL_FILETYPE_PEM) != 1) {
		APPLOG(APPLOG_ERR, "%s() Could not read private key file %s", __func__, key_file);
	}
	if (SSL_CTX_use_certificate_chain_file(ssl_ctx, cert_file) != 1) {
		APPLOG(APPLOG_ERR, "%s() Could not read certificate file %s", __func__, cert_file);
	}

	next_proto_list[0] = NGHTTP2_PROTO_VERSION_ID_LEN;
	memcpy(&next_proto_list[1], NGHTTP2_PROTO_VERSION_ID,
			NGHTTP2_PROTO_VERSION_ID_LEN);
	next_proto_list_len = 1 + NGHTTP2_PROTO_VERSION_ID_LEN;

	SSL_CTX_set_next_protos_advertised_cb(ssl_ctx, next_proto_cb, NULL);

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
	SSL_CTX_set_alpn_select_cb(ssl_ctx, alpn_select_proto_cb, NULL);
#endif // OPENSSL_VERSION_NUMBER >= 0x10002000L

	return ssl_ctx;
}

/* Create SSL object */
static SSL *create_ssl(SSL_CTX *ssl_ctx) {
	SSL *ssl;
	ssl = SSL_new(ssl_ctx);
	if (!ssl) {
		APPLOG(APPLOG_ERR, "%s() Could not create SSL/TLS session object: %s",
				__func__, ERR_error_string(ERR_get_error(), NULL));
	}
	return ssl;
}

static void add_stream(http2_session_data *session_data,
		http2_stream_data *stream_data) {
	stream_data->next = session_data->root.next;
	session_data->root.next = stream_data;
	stream_data->prev = &session_data->root;
	if (stream_data->next) {
		stream_data->next->prev = stream_data;
	}
}

static void remove_stream(http2_session_data *session_data,
		http2_stream_data *stream_data) {
	(void)session_data;

	stream_data->prev->next = stream_data->next;
	if (stream_data->next) {
		stream_data->next->prev = stream_data->prev;
	}
}

static http2_stream_data *
create_http2_stream_data(http2_session_data *session_data, int32_t stream_id) {
	http2_stream_data *stream_data;
	stream_data = malloc(sizeof(http2_stream_data));
	memset(stream_data, 0, sizeof(http2_stream_data));
	stream_data->stream_id = stream_id;

	add_stream(session_data, stream_data);
	return stream_data;
}

static void delete_http2_stream_data(http2_stream_data *stream_data) {
	free(stream_data);
}

int get_in_port(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return (((struct sockaddr_in*)sa)->sin_port);
    }

    return (((struct sockaddr_in6*)sa)->sin6_port);
}

int find_least_conn_worker()
{
	int i, thrd_id = 0, ls_cnt = 0;

	ls_cnt = THRD_WORKER[0].client_num;
	for (i = 0; i < SERVER_CONF.worker_num; i++) {
		if (THRD_WORKER[i].client_num < ls_cnt) {
			thrd_id = i;
			ls_cnt = THRD_WORKER[i].client_num;
		}
	}

	return thrd_id;
}

static http2_session_data *create_http2_session_data(app_context *app_ctx,
		int fd,
		struct sockaddr *addr,
		int addrlen) {
	int rv;
	http2_session_data *session_data;
	SSL *ssl;
	char host[NI_MAXHOST];
	int val = 1;
	int index = 0;
	int i, found = 0, sess_idx = 0;
	int allowlist_index;

	if ((rv = getnameinfo(addr, (socklen_t)addrlen, host, sizeof(host), NULL, 0, 
					NI_NUMERICHOST)) != 0) {
        APPLOG(APPLOG_DEBUG, "%s():%d (%s) getnameinfo fail", __func__, __LINE__, host);
		return NULL;
    }

	if ((allowlist_index = check_allow(host, SERVER_CONF.allow_any_client)) < 0) {
        APPLOG(APPLOG_DETAIL, "%s():%d (conn from: %s) allow list fail to find (or connection full)", __func__, __LINE__, host);
		return NULL;
    }

	/*
	 * 세션 인덱스를 항상 전진시켜, 
	 * 종료 시 해당 세션의 ctx 수집 과정에서 신규 생성된 세션과의 충돌이 생기지 않도록 한다 
	 */
	index = find_least_conn_worker();
    for (i = 0 ; i < MAX_SVR_NUM; i++) {
        int pos = (SESS_IDX + i) % MAX_SVR_NUM;
        if (SESS[index][pos].used == 0) {
            found = 1;
            SESS_IDX = sess_idx = pos;
            break;
        }
    }
	if (!found) {
		return NULL; // 중요!!! 호출 함수의 예외처리 
	}

	session_data = &SESS[index][sess_idx];
	memset(session_data, 0, sizeof(http2_session_data));
	session_data->session_index = sess_idx;
	session_data->session_id = ++SESSION_ID;
	SESSION_ID = SESSION_ID % 65535 + 1;
	session_data->used = 1;
	session_data->connected = CN_CONNECTING;
	session_data->allowlist_index = allowlist_index;
	sprintf(session_data->hostname, "%s", ALLOW_LIST[allowlist_index].host);
	sprintf(session_data->type, "%s", ALLOW_LIST[allowlist_index].type);
	session_data->list_index = ALLOW_LIST[allowlist_index].list_index;
	session_data->auth_act = ALLOW_LIST[allowlist_index].auth_act;

	/* use when session DACT */
	add_to_allowlist(allowlist_index, index, sess_idx, session_data->session_id);

	if (app_ctx->ssl_ctx != NULL) {
		ssl = create_ssl(app_ctx->ssl_ctx);
		APPLOG(APPLOG_DETAIL, "TLS] %s() thread [%d], accept new client, session id (%d)", 
				__func__, index, session_data->session_id);
	} else {
		APPLOG(APPLOG_DETAIL, "TCP] %s() thread [%d], accept new client, session id (%d)", 
				__func__, index, session_data->session_id);
	}

	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&val, sizeof(val));
	session_data->thrd_index = index;
	if (app_ctx->ssl_ctx != NULL) {
		APPLOG(APPLOG_DETAIL, "DBG}}} SSL CONNECTED !");
		sprintf(session_data->scheme, "%s", "https");
		session_data->bev = bufferevent_openssl_socket_new(
				THRD_WORKER[index].evbase, fd, ssl, BUFFEREVENT_SSL_ACCEPTING,
				BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	} else {
		APPLOG(APPLOG_DETAIL, "DBG}}} TCP CONNECTED !");
		sprintf(session_data->scheme, "%s", "http");
		session_data->bev = bufferevent_socket_new(
				THRD_WORKER[index].evbase, fd,
				BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	}

	session_data->client_addr = strdup(host);
	session_data->client_port = ntohs(get_in_port(addr));

	/* for direct relay */
	if (app_ctx->is_direct_sock) {
		session_data->is_direct_session = 1;
		session_data->relay_fep_tag = app_ctx->relay_fep_tag;
	}

	/* schlee, if tcp connection, never happen EVENT_CONNECTED */
	if (app_ctx->ssl_ctx == NULL) {
		eventcb(session_data->bev, BEV_EVENT_CONNECTED, session_data);
	}

    /* schlee, if evhandler not assigned, it cause send_ping core error */
    bufferevent_setcb(session_data->bev, readcb, writecb, eventcb, session_data);
	bufferevent_enable(session_data->bev, EV_READ | EV_WRITE);

	return session_data;
}

/* caution!!! this func must called by worker */
static void delete_http2_session_data(http2_session_data *session_data) {
	http2_stream_data *stream_data;

	session_data->connected = 0;

	/* stat HTTP_DISCONN */
	http_stat_inc(session_data->thrd_index, session_data->list_index, HTTP_DISCONN);

	APPLOG(APPLOG_DETAIL, "%s() peer %s disconnected", __func__, session_data->client_addr);
	THRD_WORKER[session_data->thrd_index].client_num --;
	ALLOW_LIST[session_data->allowlist_index].curr --;
    ALLOW_LIST[session_data->allowlist_index].tombstone_date = time(NULL);
#if 0
    // this code might be useless 2019.12.09
	del_from_allowlist(session_data->allowlist_index, session_data->thrd_index, session_data->session_index);
#endif

	if (!strcmp(session_data->scheme, "https")) {
		SSL *ssl = bufferevent_openssl_get_ssl(session_data->bev);
		if (ssl) {
			SSL_shutdown(ssl);
		}
	}
	bufferevent_free(session_data->bev);
	nghttp2_session_del(session_data->session);

	for (stream_data = session_data->root.next; stream_data;) {
		http2_stream_data *next = stream_data->next;
		delete_http2_stream_data(stream_data);
		stream_data = next;
	}
	free(session_data->client_addr);
	session_data->session_index = 0;
	session_data->session_id = 0;
	session_data->used = 0;
}

/* Serialize the frame and send (or buffer) the data to
   bufferevent. */
static int session_send(http2_session_data *session_data) {
	int rv;
	rv = nghttp2_session_send(session_data->session);
	if (rv != 0) {
		APPLOG(APPLOG_ERR, "Fatal error: %s", nghttp2_strerror(rv));
		return (-1);
	}
	return 0;
}

/* Read the data in the bufferevent and feed them into nghttp2 library
   function. Invocation of nghttp2_session_mem_recv() may make
   additional pending frames, so call session_send() at the end of the
   function. */
static int session_recv(http2_session_data *session_data) {
	ssize_t readlen;
	struct evbuffer *input = bufferevent_get_input(session_data->bev);
	size_t datalen = evbuffer_get_length(input);
	unsigned char *data = evbuffer_pullup(input, -1);

	if (session_data->session == NULL) {
		APPLOG(APPLOG_ERR, "Fatal error: session_data->session is NULL!");
		return (-1);
	}
	readlen = nghttp2_session_mem_recv(session_data->session, data, datalen);
	if (readlen < 0) {
		APPLOG(APPLOG_ERR, "Fatal error: %s", nghttp2_strerror((int)readlen));
		return (-1);
	}
	if (evbuffer_drain(input, (size_t)readlen) != 0) {
		APPLOG(APPLOG_ERR, "Fatal error: evbuffer_drain failed");
		return (-1);
	}
	if (session_send(session_data) != 0) {
		return (-1);
	}
	return 0;
}

static ssize_t send_callback(nghttp2_session *session, const uint8_t *data,
		size_t length, int flags, void *user_data) {
	http2_session_data *session_data = (http2_session_data *)user_data;
	struct bufferevent *bev = session_data->bev;
	(void)session;
	(void)flags;

	/* Avoid excessive buffering in server side. */
	if (evbuffer_get_length(bufferevent_get_output(session_data->bev)) >=
			OUTPUT_WOULDBLOCK_THRESHOLD) {
		return NGHTTP2_ERR_WOULDBLOCK;
	}
	bufferevent_write(bev, data, length);
	return (ssize_t)length;
}

static ssize_t ptr_read_callback(nghttp2_session *session, int32_t stream_id,
		uint8_t *buf, size_t length,
		uint32_t *data_flags,
		nghttp2_data_source *source,
		void *user_data) {
    int len = strlen(source->ptr);
    strncpy((char *)buf, source->ptr, len);
    *data_flags |= NGHTTP2_DATA_FLAG_EOF;

    return len;
}

static int send_response(nghttp2_session *session, int32_t stream_id,
		nghttp2_nv *nva, size_t nvlen, void *ptr) {
	int rv;
	nghttp2_data_provider data_prd;
	data_prd.source.ptr = ptr;
	data_prd.read_callback = ptr_read_callback;

	rv = nghttp2_submit_response(session, stream_id, nva, nvlen, &data_prd);
	if (rv != 0) {
		APPLOG(APPLOG_ERR, "Fatal error: %s", nghttp2_strerror(rv));
		return (-1);
	}

	// Send Response header (this func used in only error case

	return 0;
}
static ssize_t ptr_read_callback_ctx(nghttp2_session *session, int32_t stream_id,
		uint8_t *buf, size_t length,
		uint32_t *data_flags,
		nghttp2_data_source *source,
		void *user_data) {
	https_ctx_t *https_ctx = (https_ctx_t *)source->ptr;
	int len = https_ctx->user_ctx.head.bodyLen;

    if (len >= length) {
        APPLOG(APPLOG_ERR, "%s() body_len(%d) exceed maximum data_prd_len(%zu)!",
                __func__, len, length);
        len = length;
    }
	// ahif.data [query|body|...] this callback only want body
    memcpy(buf, https_ctx->user_ctx.data + https_ctx->user_ctx.head.queryLen, len);
    *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    return len;
}
static int send_response_by_ctx(nghttp2_session *session, int32_t stream_id,
		nghttp2_nv *nva, size_t nvlen, https_ctx_t *https_ctx) {
	int rv;
	nghttp2_data_provider data_prd;
	data_prd.source.ptr = https_ctx;
	data_prd.read_callback = ptr_read_callback_ctx;

	rv = nghttp2_submit_response(session, stream_id, nva, nvlen, &data_prd);

	char log_pfx[1024] = {0,};
	sprintf(log_pfx, "HTTPS ctx(%d:%d) http sess/stream(%d:%d) ahifCid(%d)",
			https_ctx->user_ctx.head.thrd_index,
			https_ctx->user_ctx.head.ctx_id,
			https_ctx->session_id,
			stream_id,
			https_ctx->user_ctx.head.ahifCid);
	log_pkt_send(log_pfx, nva, nvlen, 
			https_ctx->user_ctx.data + https_ctx->user_ctx.head.queryLen, 
			https_ctx->user_ctx.head.bodyLen);

	if (rv != 0) {
		APPLOG(APPLOG_ERR, "Fatal error: %s", nghttp2_strerror(rv));
		return (-1);
	}

	return 0;
}

/* CAUTION!!! : data_prd only ref pointer(not copyed), must use under static values */
static const char ERROR_NULLBODY[] = "";
static const char ERROR_HTTP_S_INVLD_API[]              /* 400 bad request */ = "\
{\
  \"title\" : \"receive wrong uri\",\
  \"status\" : 400,\
  \"detail\" : \"The HTTP request contains an unsupported API name or API version in the URI.\"\
}";
static const char ERROR_HTTP_S_INVLD_MSG_FORMAT[]       /* 400 bad request */ = "\
{\
  \"title\" : \"fail to decoding\",\
  \"status\" : 400,\
  \"detail\" : \"The HTTP request has an invalid format.\"\
}";
static const char ERROR_HTTP_S_MANDATORY_IE_INCORRECT[] /* 400 bad reqeust */ = "\
{\
  \"title\" : \"oauth fail\",\
  \"status\" : 400,\
  \"detail\" : \"A mandatory IE or conditional IE in data structure, but mandatory required, for an HTTP method was received with a semantically incorrect value.\"\
}";
static const char ERROR_HTTP_S_INSUFFICIENT_RESOURCES[] /* 500 internal server error */ = "\
{\
  \"title\" : \"fail to assign context\",\
  \"status\" : 500,\
  \"detail\" : \"The request is rejected due to insufficient resources.\"\
}"; 
static const char ERROR_HTTP_S_SYSTEM_FAILURE[]         /* 500 internal server error */ = "\
{\
  \"title\" : \"internal tcp error\",\
  \"status\" : 500,\
  \"detail\" : \"The request is rejected due to generic error condition in the NF.\"\
}"; 
static const char ERROR_HTTP_S_NF_CONGESTION[]          /* 503 service unavailable */ = "\
{\
  \"title\" : \"ovld ctrl occured\",\
  \"status\" : 503,\
  \"detail\" : \"The NF experiences congestion and performs overload control, which does not allow the request to be processed.\"\
}";
static int error_reply(http2_session_data *session_data, nghttp2_session *session, http2_stream_data *stream_data,
		int error_code, const char *error_body, int stat_enum)
{
	char err_code_str[128] = {0,};
	sprintf(err_code_str, "%d", error_code);

#if 0
	nghttp2_nv hdrs[] = { MAKE_NV(":status", err_code_str, strlen(err_code_str)) };
#else
	nghttp2_nv hdrs[2] = { MAKE_NV(":status", err_code_str, strlen(err_code_str)),
		MAKE_NV("content-type", "application/problem+json", strlen("application/problem+json")) };
#endif

#ifdef OVLD_API
	/* for nssf overload control */
	// api_ovld_add_fail(session_data->thrd_index, API_PROTO_HTTPS, 0, error_code);
	api_ovld_add_fail(session_data->thrd_index, API_PROTO_HTTPS, 0);
#endif

	char log_pfx[1024] = {0,};
	sprintf(log_pfx, "HTTPS ctx(N/A) http sess/stream(-:%d) [internal error]",
			stream_data->stream_id);
	log_pkt_send(log_pfx, hdrs, 2, error_body, strlen(error_body));

	switch (stat_enum) {
		case HTTP_S_INVLD_API:
		case HTTP_S_INVLD_MSG_FORMAT:
		case HTTP_S_MANDATORY_IE_INCORRECT:
		case HTTP_S_INSUFFICIENT_RESOURCES:
		case HTTP_S_SYSTEM_FAILURE:
		case HTTP_S_NF_CONGESTION:
			http_stat_inc(session_data->thrd_index, session_data->list_index, stat_enum);
			break;
	}

	if (send_response(session, stream_data->stream_id, hdrs, ARRLEN(hdrs),
				(void *)error_body) != 0) {
		return (-1);
	}
	return 0;
}

/* nghttp2_on_header_callback: Called when nghttp2 library emits
   single header name/value pair. */
static int on_header_callback(nghttp2_session *session,
		const nghttp2_frame *frame, const uint8_t *name,
		size_t namelen, const uint8_t *value,
		size_t valuelen, uint8_t flags, void *user_data) {
	http2_session_data *session_data = (http2_session_data *)user_data;
	http2_stream_data *stream_data;
	int stream_id, thrd_idx, idx;
	https_ctx_t *https_ctx = NULL;
	(void)flags;
	(void)user_data;

	// schlee, nghttp gurantee null ternimation in this function
	char *header_name = (char *)name;
	char *header_value = (char *)value;

	switch (frame->hd.type) {
		case NGHTTP2_HEADERS:
			if (frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
				break;
			}
			// Partial http2 header received

			stream_id = frame->hd.stream_id;
			stream_data = nghttp2_session_get_stream_user_data(session, stream_id);
			if (!stream_data) {
				break;
			}

			thrd_idx = session_data->thrd_index;
			idx = stream_data->ctx_id;
			if ((https_ctx = get_context(thrd_idx, idx, 1)) == NULL) {
				APPLOG(APPLOG_DEBUG, "%s() get_context fail", __func__);
				break;
			}

			log_pkt_head_recv(https_ctx, name, namelen, value, valuelen);

			if (!strcmp(header_name, HDR_PATH)) {
				https_ctx->user_ctx.head.queryLen = divide_string(header_value, '?', 
						https_ctx->user_ctx.head.rsrcUri,
						sizeof(https_ctx->user_ctx.head.rsrcUri),
						https_ctx->user_ctx.data,
						sizeof(https_ctx->user_ctx.data));
			} else if (!strcmp(header_name, HDR_SCHEME)) {
				sprintf(https_ctx->user_ctx.head.scheme, "%s", header_value);
			} else if (!strcmp(header_name, HDR_AUTHORITY)) {
				sprintf(https_ctx->user_ctx.head.authority, "%s", header_value);
			} else if (!strcmp(header_name, HDR_METHOD)) {
				sprintf(https_ctx->user_ctx.head.httpMethod, "%s", header_value);
			} else if (!strcmp(header_name, HDR_AUTHORIZATION)) {
				sprintf(https_ctx->access_token, "%s", header_value); // Bearer token_raw
			} else {
				/* vHeader relay */
				if (set_defined_header(VHDR_INDEX[1], header_name, header_value, &https_ctx->user_ctx) != -1) {
					https_ctx->user_ctx.head.vheaderCnt ++;
				}
			}
			break;
	}
	return 0;
}

static int on_begin_headers_callback(nghttp2_session *session,
		const nghttp2_frame *frame,
		void *user_data) {
	http2_session_data *session_data = (http2_session_data *)user_data;
	http2_stream_data *stream_data;
	int idx;
	https_ctx_t *https_ctx = NULL;

	/* this func normally handle data recv */
	if (frame->hd.type != NGHTTP2_HEADERS || frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
		return 0;
	}

	/* get stream data */
	stream_data = create_http2_stream_data(session_data, frame->hd.stream_id);
	nghttp2_session_set_stream_user_data(session, frame->hd.stream_id,
			stream_data);

	/* stat HTTP_RX_REQ */
	http_stat_inc(session_data->thrd_index, session_data->list_index, HTTP_RX_REQ);
#if 0
#ifdef OVLD_API
	/* for nssf overload control */
	char *error_str = NULL;
	int ovld_reason_code = lb_api_ovld_is_ctrl(session_data->thrd_index, API_PROTO_HTTPS, 
			session_data->hostname, error_str); 
	if (ovld_reason_code == API_ACTION_DROP) {
		// TODO LIKE PREARRANGE SOMETHING ...
	} else if (ovld_reason_code > 299) {
		int res = error_reply(session_data, session, stream_data, ovld_reason_code, 
				error_str != NULL ? error_str : ERROR_NULLBODY, HTTP_S_NF_CONGESTION);

		return res == 0 ? 0 : NGHTTP2_ERR_CALLBACK_FAILURE;
	}
#endif
#endif

	/* assign context when receive begin-header, remove it when remove_http2_stream_data() called */
	idx = Get_CtxId(session_data->thrd_index);

	if (idx < 0) {
		APPLOG(APPLOG_ERR, "%s() Assign Context fail thrd[%d]!", __func__, session_data->thrd_index);
		if (error_reply(session_data, session, stream_data, 500, 
					ERROR_HTTP_S_INSUFFICIENT_RESOURCES, HTTP_S_INSUFFICIENT_RESOURCES) != 0) {
			return NGHTTP2_ERR_CALLBACK_FAILURE;
		}
	} else {
		if ((https_ctx = get_context(session_data->thrd_index, idx, 0)) == NULL) {
			APPLOG(APPLOG_ERR, "%s() get_context fail!", __func__);
			return NGHTTP2_ERR_CALLBACK_FAILURE;
		}
		clear_new_ctx(https_ctx);

		/* caution, set occupied after save timer_index */
		https_ctx->recv_time_index = THRD_WORKER[session_data->thrd_index].time_index;
		https_ctx->occupied = 1;
		https_ctx->user_ctx.head.ctx_id = idx;
		stream_data->ctx_id = idx;
		sprintf(https_ctx->user_ctx.head.magicByte, "%s", AHIF_MAGIC_BYTE);

		assign_new_ctx_info(https_ctx, session_data, stream_data);
		save_session_info(https_ctx, session_data->thrd_index, session_data->session_index, session_data->session_id, session_data->client_addr);
	}

	// Request header started from here

	return 0;
}

int check_token_uuid(const char *audience)
{
    for (int i = 0; i < SERVER_CONF.uuid_list.peer_nfs_num; i++) {
        if (!strcmp(audience, SERVER_CONF.uuid_list.uuid[i]))
            return (1);
    }

    return (-1);
}

/* oauth 2.0 */
/*
{
    "alg": "HS256", // algo
    "typ": "JWT"
}
.
{
    "audience": "NF producer UUID",
    "expiration": 1649949847,       // expire time
    "issuer": "NF Consumer UUID",
    "scope": "namf-loc namf-evts namf-loc namf-mt", // service scope
    "subject": "NRF UUID"
}
*/
int check_access_token(char *token, char *oauth_scope)
{
	jwt_t *jwt = NULL;
	int ret = 0;

	char *key = SERVER_CONF.credential;
	int key_len = strlen(key);

	ret = jwt_decode(&jwt, token, (const unsigned char *)key, key_len);

	if (ret != 0 || jwt == NULL) {
		APPLOG(APPLOG_DETAIL, "{{{JWT}}} jwt parse fail!");
		return (-1);
	}

	char *out = jwt_dump_str(jwt, 1);
	APPLOG(APPLOG_DEBUG, "{{{JWT}}} recv token (pretty)\n%s", out);
	free(out);

	long double expiration = jwt_get_grant_int(jwt, "expiration");
	time_t current = time(NULL);
	if (expiration == 0 || expiration < current) {
		APPLOG(APPLOG_DETAIL, "{{{JWT}}} wrong expiration! [%Lf]", expiration);
		jwt_free(jwt);
		return (-1);
	}

	const char *audience = jwt_get_grant(jwt, "audience");
	if (audience == NULL || check_token_uuid(audience) < 0) {
		APPLOG(APPLOG_DETAIL, "{{{JWT}}} wrong audience! [%s]", audience);
		jwt_free(jwt);
		return (-1);
	}

    const char *scope = jwt_get_grant(jwt, "scope");
    if (scope != NULL) {
		APPLOG(APPLOG_DEBUG, "{{{JWT}}} {{{TEST}}} recv scope [%s]", scope);
        sprintf(oauth_scope, "%.255s", scope);
    }

	// TODO!!! more check, subject / issuer / scope  ...

	jwt_free(jwt);

	return (0); // success
}

/* HTTPS --> NRFM direct channel */
int send_request_to_nrfm(https_ctx_t *https_ctx, int ahif_mtype)
{
	https_ctx->for_nrfm_ctx = 1; // this ctx relayed to NRFM

	char msgBuff[sizeof(GeneralQMsgType)] = {0,};

	GeneralQMsgType *msg = (GeneralQMsgType *)msgBuff;
	msg->mtype = (long)MSGID_HTTPS_NRFM_REQUEST;

	AhifHttpCSMsgType *ahifPkt_recv = &https_ctx->user_ctx;
	AhifHttpCSMsgType *ahifPkt_send = (AhifHttpCSMsgType *)msg->body;

	size_t shmqlen = AHIF_APP_MSG_HEAD_LEN + AHIF_VHDR_LEN + ahifPkt_recv->head.queryLen + ahifPkt_recv->head.bodyLen;
	memcpy(ahifPkt_send, ahifPkt_recv, shmqlen);

	ahifPkt_send->head.mtype = ahif_mtype;

	int res = -1;
	if (nrfmQid > 0) {
		res = msgsnd(nrfmQid, msg, shmqlen, IPC_NOWAIT);
		if (res < 0) {
			APPLOG(APPLOG_ERR, "%s(), fail to send resp to NRFM! (res:%d)", __func__, res);
		}
	}

	return res;
}

static int on_request_recv(nghttp2_session *session,
		http2_session_data *session_data,
		http2_stream_data *stream_data) {
	char *rel_path;
	https_ctx_t *https_ctx = NULL;
	int thrd_idx = session_data->thrd_index;
	int ctx_id = stream_data->ctx_id;

	if ((https_ctx = get_context(thrd_idx, ctx_id, 1)) == NULL) {
		APPLOG(APPLOG_ERR, "%s() get_context fail", __func__);
		return 0;
	}

	// Whole http body received

	log_pkt_end_stream(stream_data->stream_id, https_ctx);

	/* 2019.10.16 peer ovld sts test*/
	if (ovld_calc_check(session_data)) {
		/* silence discard stream */
		nghttp2_session_close_stream(session_data->session, stream_data->stream_id, NGHTTP2_INTERNAL_ERROR);
		clear_and_free_ctx(https_ctx);
		Free_CtxId(thrd_idx, ctx_id);
		http_stat_inc(session_data->thrd_index, session_data->list_index, HTTP_PRE_END);
		return 0;
	}

#ifdef OVLD_API
	char *error_str = NULL;
	//int ovld_reason_code = lb_api_ovld_is_ctrl(session_data->thrd_index, API_PROTO_HTTPS, 
	//		session_data->hostname, error_str); 
	int ovld_reason_code = api_ovld_is_ctrl_by_uri(session_data->thrd_index, 
			API_PROTO_HTTPS, 
			session_data->hostname, 
			https_ctx->user_ctx.head.httpMethod,
			https_ctx->user_ctx.head.rsrcUri,
			https_ctx->user_ctx.data,
			error_str); 
	if (ovld_reason_code == API_ACTION_DROP) {
		/* silence discard stream */
		nghttp2_session_close_stream(session_data->session, stream_data->stream_id, NGHTTP2_INTERNAL_ERROR);
		clear_and_free_ctx(https_ctx);
		Free_CtxId(thrd_idx, ctx_id);
		http_stat_inc(session_data->thrd_index, session_data->list_index, HTTP_PRE_END);
		return 0;
	} else if (ovld_reason_code > 299) {
		int res = error_reply(session_data, session, stream_data, ovld_reason_code, 
				error_str != NULL ? error_str : ERROR_NULLBODY, HTTP_S_NF_CONGESTION);

		clear_and_free_ctx(https_ctx);
		Free_CtxId(thrd_idx, ctx_id);
		return res == 0;
	}
#endif

	if (!https_ctx->user_ctx.head.rsrcUri[0]) {
		if (error_reply(session_data, session, stream_data, 400, 
					ERROR_HTTP_S_INVLD_API, HTTP_S_INVLD_API) != 0)
			return NGHTTP2_ERR_CALLBACK_FAILURE;
		return 0;
	}

	/* check OAuth 2.0 access token */
	if (session_data->auth_act > 0) {
		if (https_ctx->access_token == NULL) {
			if (error_reply(session_data, session, stream_data, 400, 
						ERROR_HTTP_S_MANDATORY_IE_INCORRECT, HTTP_S_MANDATORY_IE_INCORRECT) != 0) 
				return NGHTTP2_ERR_CALLBACK_FAILURE;
			return 0;
		}
		int token_len = strlen(https_ctx->access_token);
		if (token_len <= 7 || strncmp(https_ctx->access_token, "Bearer ", 7)) {
			if (error_reply(session_data, session, stream_data, 400, 
						ERROR_HTTP_S_MANDATORY_IE_INCORRECT, HTTP_S_MANDATORY_IE_INCORRECT) != 0) 
				return NGHTTP2_ERR_CALLBACK_FAILURE;
			return 0;
		}
		if (check_access_token(https_ctx->access_token + 7, https_ctx->user_ctx.head.oauthScope) < 0) {
			if (error_reply(session_data, session, stream_data, 400, 
						ERROR_HTTP_S_MANDATORY_IE_INCORRECT, HTTP_S_MANDATORY_IE_INCORRECT) != 0) 
				return NGHTTP2_ERR_CALLBACK_FAILURE;
			return 0;
		}
	}

	// TODO!!! recheck this logic
	for (rel_path = https_ctx->user_ctx.head.rsrcUri; *rel_path == '/'; ++rel_path)
		;

	int relay_result = 0;

	if (!strcmp(https_ctx->user_ctx.head.rsrcUri, "/notifyForLb")) {
		relay_result = send_request_to_nrfm(https_ctx, MTYPE_NRFM_NOTIFY_REQUEST);
	} else {
		relay_result = send_request_to_fep(https_ctx);
	}

	if (relay_result < 0) {
		/* all context will release in stream close state */
		if (error_reply(session_data, session, stream_data, 500, 
					ERROR_HTTP_S_SYSTEM_FAILURE, HTTP_S_SYSTEM_FAILURE) != 0) {
			APPLOG(APPLOG_ERR, "%s() send error_reply fail!", __func__);
		} 
	}

	return 0;
}

void ping_latency_alarm(http2_session_data *session_data, struct timeval *send_tm, struct timeval *recv_tm)
{
	char alarm_info[1024] = {0,};
	char alarm_desc[1024] = {0,};

	// don't make alarm event
	if (SERVER_CONF.ping_event_ms <= 0)
		return;

	long long tv_send = send_tm->tv_sec * 1000LL + (send_tm->tv_usec / 1000LL);
	long long tv_recv = recv_tm->tv_sec * 1000LL + (recv_tm->tv_usec / 1000LL);
	long long ping_latency = tv_recv - tv_send;

	if (ping_latency >= SERVER_CONF.ping_event_ms && session_data->event_occured == 0) {
		if (SERVER_CONF.ping_event_code > 0) {
			sprintf(alarm_info, "HTTPS-%s:%d",  session_data->client_addr, session_data->client_port);
			sprintf(alarm_desc, "%lld-ms", ping_latency);
			reportAlarm("HTTPS", SERVER_CONF.ping_event_code, SFM_ALM_MAJOR, alarm_info, alarm_desc);
		}
		session_data->event_occured = 1;
		APPLOG(APPLOG_DEBUG, "%s() session (id:%d) alarm status (%s) [%s:%s]",
				__func__, session_data->session_id,
				SERVER_CONF.ping_event_code > 0 ? "sended" : "silence discarded",
				alarm_info, alarm_desc);
	} else if (ping_latency < SERVER_CONF.ping_event_ms && session_data->event_occured == 1) {
		if (SERVER_CONF.ping_event_code > 0) {
			sprintf(alarm_info, "HTTPS-%s:%d",  session_data->client_addr, session_data->client_port);
			sprintf(alarm_desc, "%lld-ms", ping_latency);
			reportAlarm("HTTPS", SERVER_CONF.ping_event_code, SFM_ALM_NORMAL, alarm_info, alarm_desc);
		}
		session_data->event_occured = 0;
		APPLOG(APPLOG_DEBUG, "%s() session (id:%d) alarm status (%s) [%s:%s]",
				__func__, session_data->session_id,
				SERVER_CONF.ping_event_code > 0 ? "cleared" : "silence discarded",
				alarm_info, alarm_desc);
	}
}

static int on_frame_recv_callback(nghttp2_session *session,
		const nghttp2_frame *frame, void *user_data) {
	http2_session_data *session_data = (http2_session_data *)user_data;

	switch (frame->hd.type) {
		/* for RCV RST STAT */
		case NGHTTP2_RST_STREAM:
			http_stat_inc(session_data->thrd_index, session_data->list_index, HTTP_RX_RST);
			break;
		case NGHTTP2_PING:
			if (frame->hd.flags & NGHTTP2_FLAG_ACK) {
				gettimeofday(&session_data->ping_rcv_time, NULL);
				ping_latency_alarm(session_data, &session_data->ping_snd_time, &session_data->ping_rcv_time);
			}
			break;
		case NGHTTP2_DATA:
		case NGHTTP2_HEADERS:
			/* Check that the client request has finished */
			if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
				http2_stream_data *stream_data = 
					nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
				/* For DATA and HEADERS frame, this callback may be called after
				   on_stream_close_callback. Check that stream still alive. */
				if (!stream_data) {
					return 0;
				}
				return on_request_recv(session, session_data, stream_data);
			}
			break;
		default:
			break;
	}
	return 0;
}

static int on_data_chunk_recv_callback(nghttp2_session *session, uint8_t flags,
		int32_t stream_id, const uint8_t *data,
		size_t len, void *user_data) {
	http2_session_data *session_data = (http2_session_data *)user_data;
	(void)session;
	(void)flags;
	http2_stream_data *stream_data = NULL;
	https_ctx_t *https_ctx = NULL;

	/* no data, do nothing */
	if (len == 0) return 0;

	/* re-assemble */
	stream_data = nghttp2_session_get_stream_user_data(session, stream_id);
	if (stream_data) {
        int thrd_idx = session_data->thrd_index;
        int idx = stream_data->ctx_id;

		if ((https_ctx = get_context(thrd_idx, idx, 1)) == NULL) {
			APPLOG(APPLOG_ERR, "%s() get_context fail!", __func__);
			return 0;
		}

		/* volatile issue */
		char *ptr = https_ctx->user_ctx.data + https_ctx->user_ctx.head.queryLen; // ahif.data [query|data|...]
		volatile int curr_len = https_ctx->user_ctx.head.bodyLen;
		ptr += curr_len;
		memcpy(ptr, data, len);
		https_ctx->user_ctx.head.bodyLen += len;

		// Partial http2 body received
	} else {
		APPLOG(APPLOG_DEBUG, "%s() h2 get stream fail!", __func__);
	}

	return 0;
}

static int on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
		uint32_t error_code, void *user_data) {
	http2_session_data *session_data = (http2_session_data *)user_data;
	http2_stream_data *stream_data = NULL;
	https_ctx_t *https_ctx;
	int thrd_idx, idx;
	(void)error_code;

	if ((stream_data = nghttp2_session_get_stream_user_data(session, stream_id)) == NULL) {
		return 0;
	}
	thrd_idx = session_data->thrd_index;
	idx = stream_data->ctx_id;
	if ((https_ctx = get_context(thrd_idx, idx, 1)) != NULL) {
		clear_and_free_ctx(https_ctx);
		Free_CtxId(thrd_idx, idx);
	}
	remove_stream(session_data, stream_data);
	delete_http2_stream_data(stream_data);

	return 0;
}

void initialize_nghttp2_session(http2_session_data *session_data) {
	nghttp2_session_callbacks *callbacks;

	nghttp2_session_callbacks_new(&callbacks);

	nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);

	nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks,
			on_frame_recv_callback);

	nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
			callbacks, on_data_chunk_recv_callback);

	nghttp2_session_callbacks_set_on_stream_close_callback(
			callbacks, on_stream_close_callback);

	nghttp2_session_callbacks_set_on_header_callback(callbacks,
			on_header_callback);

	nghttp2_session_callbacks_set_on_begin_headers_callback(
			callbacks, on_begin_headers_callback);

#if 0
	nghttp2_session_server_new(&session_data->session, callbacks, session_data);
#else
	// U+ requirement, dynamic table size 0
	nghttp2_session_server_new2(&session_data->session, callbacks, session_data, SERVER_CONF.nghttp2_option);
#endif

	// schlee test code, set session buff 10MB
	nghttp2_session_set_local_window_size(session_data->session, NGHTTP2_FLAG_NONE, 0, 1 << 30);

	nghttp2_session_callbacks_del(callbacks);
}

/* Send HTTP/2 client connection header, which includes 24 bytes
   magic octets and SETTINGS frame */
static int send_server_connection_header(http2_session_data *session_data) {
	/* TODO!!! tuning param */
	nghttp2_settings_entry iv[5] = {
		{NGHTTP2_SETTINGS_HEADER_TABLE_SIZE, 65535},
		{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 65535},
		{NGHTTP2_SETTINGS_MAX_FRAME_SIZE, 65535},
		{NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 65535},
		{NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE, 65535}};
	int rv;

	rv = nghttp2_submit_settings(session_data->session, NGHTTP2_FLAG_NONE, iv,
			ARRLEN(iv));
	if (rv != 0) {
		APPLOG(APPLOG_ERR, "Fatal error: %s", nghttp2_strerror(rv));
		return (-1);
	}
	return 0;
}

/* readcb for bufferevent after client connection header was
   checked. */
static void readcb(struct bufferevent *bev, void *ptr) {
	http2_session_data *session_data = (http2_session_data *)ptr;
	(void)bev;

	if (session_recv(session_data) != 0) {
		delete_http2_session_data(session_data);
		return;
	}
}

/* writecb for bufferevent. To greaceful shutdown after sending or
   receiving GOAWAY, we check the some conditions on the nghttp2
   library and output buffer of bufferevent. If it indicates we have
   no business to this session, tear down the connection. If the
   connection is not going to shutdown, we call session_send() to
   process pending data in the output buffer. This is necessary
   because we have a threshold on the buffer size to avoid too much
   buffering. See send_callback(). */
static void writecb(struct bufferevent *bev, void *ptr) {
	http2_session_data *session_data = (http2_session_data *)ptr;

	if (evbuffer_get_length(bufferevent_get_output(bev)) > 0) {
		return;
	}
	if (nghttp2_session_want_read(session_data->session) == 0 &&
			nghttp2_session_want_write(session_data->session) == 0) {
#ifndef HOLDSESS 
		/* schlee, don't close session, hold it */
		delete_http2_session_data(session_data);
#endif
		return;
	}
	if (session_send(session_data) != 0) {
		delete_http2_session_data(session_data);
		return;
	}
}

/* eventcb for bufferevent */
static void eventcb(struct bufferevent *bev, short events, void *ptr) {
	http2_session_data *session_data = (http2_session_data *)ptr;
	if (events & BEV_EVENT_CONNECTED) {
		const unsigned char *alpn = NULL;
		unsigned int alpnlen = 0;
		(void)bev;

		APPLOG(APPLOG_DETAIL, "%s() %s:%d Connected", __func__, session_data->client_addr, session_data->client_port);

		if (!strcmp(session_data->scheme, "https")) {
			SSL *ssl = bufferevent_openssl_get_ssl(session_data->bev);

			SSL_get0_next_proto_negotiated(ssl, &alpn, &alpnlen);
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
			if (alpn == NULL) {
				SSL_get0_alpn_selected(ssl, &alpn, &alpnlen);
			}
#endif // OPENSSL_VERSION_NUMBER >= 0x10002000L

			if (alpn == NULL || alpnlen != 2 || memcmp("h2", alpn, 2) != 0) {
				APPLOG(APPLOG_ERR, "%s() %s h2 is not negotiated", __func__, session_data->client_addr);
				delete_http2_session_data(session_data);
				return;
			}

		}

		initialize_nghttp2_session(session_data);

		if (send_server_connection_header(session_data) != 0 ||
				session_send(session_data) != 0) {
			delete_http2_session_data(session_data);
			return;
		}

		// schlee, ok let's send ping 
		session_data->connected = CN_CONNECTED;
		gettimeofday(&session_data->ping_rcv_time, NULL);
		return;
	}
	if (events & BEV_EVENT_EOF) {
		APPLOG(APPLOG_DETAIL, "%s() %s EOF", __func__, session_data->client_addr);
	} else if (events & BEV_EVENT_ERROR) {
		APPLOG(APPLOG_DETAIL, "%s() %s network error", __func__, session_data->client_addr);
	} else if (events & BEV_EVENT_TIMEOUT) {
		APPLOG(APPLOG_DETAIL, "%s() %s timeout", __func__, session_data->client_addr);
	}
	delete_http2_session_data(session_data);
}

/* callback for evconnlistener */
static void acceptcb(struct evconnlistener *listener, int fd,
		struct sockaddr *addr, int addrlen, void *arg) {
	app_context *app_ctx = (app_context *)arg;
	http2_session_data *session_data;
	(void)listener;

	session_data = create_http2_session_data(app_ctx, fd, addr, addrlen);

	if (session_data == NULL) {
		char host[NI_MAXHOST] = {0,};
		int rv = getnameinfo(addr, (socklen_t)addrlen, host, sizeof(host), NULL, 0, NI_NUMERICHOST);
		if (rv != 0) {
			APPLOG(APPLOG_ERR, "%s() create session failed (unknown)!", __func__);
		} else {
			APPLOG(APPLOG_ERR, "%s() create session failed %s!", __func__, host);
		}
		/* stat HTTP_DISCONN */
		http_stat_inc(0, 0, HTTP_CONN);
		http_stat_inc(0, 0, HTTP_DISCONN);

		close(fd);
		return; // don't do anything!
	}
	/* stat HTTP_CONN */
	http_stat_inc(session_data->thrd_index, session_data->list_index, HTTP_CONN);

	THRD_WORKER[session_data->thrd_index].client_num ++;

}

static void start_listen(struct event_base *evbase, const char *service,
		app_context *app_ctx) {
	int rv;
	struct addrinfo hints;
	struct addrinfo *res, *rp;

	memset(&hints, 0, sizeof(hints));
	//hints.ai_family = AF_UNSPEC;
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	hints.ai_flags |= AI_ADDRCONFIG;

	rv = getaddrinfo(NULL, service, &hints, &res);
	if (rv != 0) {
		APPLOG(APPLOG_ERR, "%s() Could not resolve server address", __func__);
	}

	for (rp = res; rp; rp = rp->ai_next) {
		struct evconnlistener *listener;
		// TODO!!! more opt check like LEV_OPT_THREADSAFE
		listener = evconnlistener_new_bind(
				evbase, acceptcb, app_ctx, LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE | LEV_OPT_THREADSAFE,
				16, rp->ai_addr, (int)rp->ai_addrlen);
		if (listener) {
			freeaddrinfo(res);

			return;
		}
	}
	APPLOG(APPLOG_ERR, "%s() Could not start listener", __func__);
}

static void initialize_app_context(app_context *app_ctx, SSL_CTX *ssl_ctx,
		struct event_base *evbase, int is_direct_sock, int relay_fep_tag) {
	memset(app_ctx, 0, sizeof(app_context));
	app_ctx->ssl_ctx = ssl_ctx;
	app_ctx->evbase = evbase;

	app_ctx->is_direct_sock = is_direct_sock;
	app_ctx->relay_fep_tag = relay_fep_tag;
}

#define MAX_THRD_WAIT_NUM 5
void check_thread()
{
    int index = 0;

    /* check worker thread hang */
    for (index = 0; index < SERVER_CONF.worker_num; index++) {
        if (THRD_WORKER[index].running_index == THRD_WORKER[index].checked_index) {
            THRD_WORKER[index].hang_counter ++;
        } else {
            THRD_WORKER[index].checked_index = THRD_WORKER[index].running_index;
            THRD_WORKER[index].hang_counter = 0;
        }
        if (THRD_WORKER[index].hang_counter >= MAX_THRD_WAIT_NUM) {
            APPLOG(APPLOG_ERR, "WORKER[%2d] hang detected, restart program!!!", index);
            exit(0);
        }
    }
}
void monitor_worker()
{   
    int i, index;
    https_ctx_t *https_ctx; 
    int free_num, used_num, tmout_num;
    char buff[1024 * MAX_THRD_NUM] = {0, };

    /* check thread status */
    check_thread();
    
    for (index = 0; index < SERVER_CONF.worker_num; index++) {
        for (i = STARTID, free_num = 0, used_num = 0, tmout_num = 0; i < SIZEID; i++) {
            if ((https_ctx = get_context(index, i, 1)) == NULL) {
                free_num++;
                continue;
            }
            used_num++;
            if (https_ctx->inflight_ref_cnt)
                tmout_num ++;
        }
        sprintf(buff + strlen(buff), "WORKER[%2d] used[%5d] free[%5d] tmout[%5d]\n",
                index, used_num, free_num, tmout_num);
    }
    APPLOG(APPLOG_ERR, "\n\n%s\n", buff);
}

void main_tick_callback(evutil_socket_t fd, short what, void *arg)
{
	keepalivelib_increase();

	if (SERVER_CONF.debug_mode == 1) {
		IxpcQMsgType Ixpc = {0,};

		/* log worker ctx status */
		monitor_worker();
		/* log https status */
		stat_function(&Ixpc, SERVER_CONF.worker_num, 0, 1, MSGID_HTTPS_STATISTICS_REPORT);
	}

	/* https peer ovld */
	ovld_step_forward();
}

void https_shm_callback(evutil_socket_t fd, short what, void *arg)
{
	for (int i = 0; i < MAX_LIST_NUM; i++) {
		if (ALLOW_LIST[i].used == 0) {
            ALLOW_LIST_SHM[i].used = 0;
        } else {
            memcpy(&ALLOW_LIST_SHM[i], &ALLOW_LIST[i], sizeof(allow_list_t));
        }
	}
}

void recv_msgq_callback(evutil_socket_t fd, short what, void *arg)
{
	int read_index = *(int *)arg;
	intl_req_t intl_req;

	struct http2_session_data *session_data = NULL;
	https_ctx_t *https_ctx = NULL;

	int thrd_index, session_index, stream_id, session_id, ctx_id;
	int msg_type;
	char result_code[128] = {0,};

	while(1)
	{
		memset(&intl_req, 0x00, sizeof(intl_req));
		/* get first msg (Arg 4) */
		int res = msgrcv(THRD_WORKER[read_index].msg_id, &intl_req, sizeof(intl_req) - sizeof(long), 0, IPC_NOWAIT|MSG_NOERROR); 
		if (res < 0) {
			if (errno != ENOMSG) {
				APPLOG(APPLOG_ERR,"%s() msgrcv fail; err=%d(%s)", __func__, errno, strerror(errno));
			}
			return;
		} else {
			msg_type = intl_req.intl_msg_type;
			thrd_index = intl_req.tag.thrd_index;
			session_index = intl_req.tag.session_index;
			session_id = intl_req.tag.session_id;
			stream_id = intl_req.tag.stream_id;
			ctx_id = intl_req.tag.ctx_id;
		} 

		/* it can be NULL */
		session_data = get_session(thrd_index, session_index, session_id);
		https_ctx = get_context(thrd_index, ctx_id, 1);

		switch(msg_type) {
			case HTTP_INTL_SND_REQ:
				if (session_data == NULL) {
					/* legacy session expired and new one already created case */
					APPLOG(APPLOG_DEBUG, "%s():%d get_session fail", __func__, __LINE__);
					continue;
				}
				if (https_ctx == NULL) {
					APPLOG(APPLOG_DEBUG, "%s():%d get_context fail TH %d CTX %d", __func__, __LINE__, 
							thrd_index, ctx_id);
					continue;
				}

				/* assign more virtual header */
				sprintf(result_code, "%d", https_ctx->user_ctx.head.respCode);
#ifdef OVLD_API
				/* for nssf overload control */
				if (https_ctx->user_ctx.head.respCode > 299) {
					// api_ovld_add_fail(thrd_index, API_PROTO_HTTPS, 0, https_ctx->user_ctx.head.respCode);
					api_ovld_add_fail(thrd_index, API_PROTO_HTTPS, 0);
				}
#endif
				nghttp2_nv hdrs[MAX_HDR_RELAY_CNT + 2] = { MAKE_NV(":status", result_code, strlen(result_code))};
				int hdrs_len = 1; /* :status */

				hdrs_len = assign_more_headers(VHDR_INDEX[0], &hdrs[0], MAX_HDR_RELAY_CNT + 2, hdrs_len, &https_ctx->user_ctx);
				if (send_response_by_ctx(session_data->session, stream_id, hdrs, hdrs_len, https_ctx) == 0) {
					/* submit success */
					if (session_send(session_data) != 0) {
						// err
					} else {
						// success stat inc
						/* stat HTTP_TX_RSP */
						http_stat_inc(session_data->thrd_index, session_data->list_index, HTTP_TX_RSP);
					}
				}
				break;
			case HTTP_INTL_TIME_OUT:
				if (https_ctx  == NULL) {
					APPLOG(APPLOG_DEBUG, "%s():%d get_context fail", __func__, __LINE__);
					continue;
				}
				if (session_data == NULL) {
					/* legacy session expired and new one already created case */
					APPLOG(APPLOG_DEBUG, "%s():%d get_session fail", __func__, __LINE__);
				} else {
					/* it's same session and alive, send reset */
					nghttp2_submit_rst_stream(session_data->session, NGHTTP2_FLAG_NONE,
							https_ctx->user_ctx.head.stream_id,
							NGHTTP2_INTERNAL_ERROR);
				}
				clear_and_free_ctx(https_ctx);
				Free_CtxId(thrd_index, ctx_id);
				
				/* stat HTTP_TIMEOUT */
				if (session_data != NULL) 
					http_stat_inc(session_data->thrd_index, session_data->list_index, HTTP_TIMEOUT);
				else
					http_stat_inc(0, 0, HTTP_TIMEOUT);

				break;
			case HTTP_INTL_SESSION_DEL:
				if (session_data  == NULL) {
					/* legacy session expired and new one already created case */
					APPLOG(APPLOG_DEBUG, "%s():%d get_session fail", __func__, __LINE__);
					continue;
				}
				delete_http2_session_data(session_data);
				break;
			case HTTP_INTL_SEND_PING:
				if (session_data  == NULL) {
					/* legacy session expired and new one already created case */
					APPLOG(APPLOG_DEBUG, "%s():%d get_session fail", __func__, __LINE__);
					continue;
				}
				/* don't use FLAG_ACK (FLAG_NONE : request, FLAG_ACK : response) */
				gettimeofday(&session_data->ping_snd_time, NULL);
				if (nghttp2_submit_ping(session_data->session, NGHTTP2_FLAG_NONE, NULL) != 0) {
					/* legacy session expired and new one already created case */
					APPLOG(APPLOG_DEBUG, "%s():%d h2 submit_ping fail", __func__, __LINE__);
					continue;
				}
				if (session_send(session_data) != 0) {
					APPLOG(APPLOG_DEBUG, "%s():%d session_send fail", __func__, __LINE__);
					continue;
				}
				break;
			case HTTP_INTL_OVLD:
				if (https_ctx  == NULL) {
					APPLOG(APPLOG_DEBUG, "%s():%d get_context fail", __func__, __LINE__);
					continue;
				}
				if (session_data == NULL) {
					/* legacy session expired and new one already created case */
					APPLOG(APPLOG_DEBUG, "%s():%d get_session fail", __func__, __LINE__);
				} else {
					/* silence discard stream */
					nghttp2_session_close_stream(session_data->session, stream_id, NGHTTP2_INTERNAL_ERROR);
				}
				clear_and_free_ctx(https_ctx);
				Free_CtxId(thrd_index, ctx_id);

				/* TODO!! STAT!!! */
				if (session_data != NULL) 
					http_stat_inc(session_data->thrd_index, session_data->list_index, HTTP_PRE_END);
				else
					http_stat_inc(0, 0, HTTP_PRE_END);

				break;
			default:
				break;
		}   
	}  
}

void thrd_tick_callback(evutil_socket_t fd, short what, void *arg)
{
	int index = *(int *)arg;

    THRD_WORKER[index].time_index++;    // use for context timer
    THRD_WORKER[index].running_index++; // use for check thread hang
}

#define MAX_TMOUT_SEND (SIZEID / 10)
void chk_tmout_callback(evutil_socket_t fd, short what, void *arg)
{
    int i, snd;
	int index;
	https_ctx_t *https_ctx = NULL;
	intl_req_t intl_req;

	for (index = 0; index < SERVER_CONF.worker_num; index ++) {
		for (i = STARTID, snd = 0; i < SIZEID; i++) {

			/* normal case */
			if ((https_ctx = get_context(index, i, 1)) == NULL) 
				continue;
			/* this ctx queued in tcp, don't release this */
			if (https_ctx->tcp_wait == 1)
				continue;

			/* timeout case */
            if ((THRD_WORKER[index].time_index - https_ctx->recv_time_index) >=
                    ((SERVER_CONF.timeout_sec * TMOUT_VECTOR) + 1)) {
				/* already sended, wait next 10th order */
				if ((https_ctx->inflight_ref_cnt) && (https_ctx->inflight_ref_cnt++ % 10 != 0)) {
					continue;
				} else {
					https_ctx->inflight_ref_cnt++;
				}
				set_intl_req_msg(&intl_req, index, i, https_ctx->sess_idx, https_ctx->session_id, 0, HTTP_INTL_TIME_OUT);
                if (-1 == msgsnd(THRD_WORKER[index].msg_id, &intl_req, sizeof(intl_req) - sizeof(long), IPC_NOWAIT)) {
					APPLOG(APPLOG_DEBUG, "%s() msgsnd fail!!!", __func__);
                }
				/* if tmout sended num exceed 1/10 total ctx, wait to next turn */
				if (snd ++ > MAX_TMOUT_SEND) break;
			}
		}
	}
}

void send_ping_callback(evutil_socket_t fd, short what, void *arg)
{
    int thrd_idx, sess_idx;
	http2_session_data *session_data = NULL;
	intl_req_t intl_req;
	struct timespec tm_curr = {0,};

	clock_gettime(CLOCK_REALTIME, &tm_curr);

	for (thrd_idx = 0; thrd_idx < SERVER_CONF.worker_num; thrd_idx++) {
		for (sess_idx = 0; sess_idx < MAX_SVR_NUM; sess_idx++) {
			session_data = &SESS[thrd_idx][sess_idx];
			if (session_data->used != 1)
				continue;
			if (session_data->connected != CN_CONNECTED)
				continue;
			/* if (5sec:  send - ack > 5 ) delete sess */
			if ((tm_curr.tv_sec - session_data->ping_rcv_time.tv_sec) > SERVER_CONF.ping_timeout) {
				APPLOG(APPLOG_ERR, "%s() session (id: %d) goaway~!", __func__, session_data->session_id);
				set_intl_req_msg(&intl_req, thrd_idx, 0, sess_idx, session_data->session_id, 0, HTTP_INTL_SESSION_DEL);
                if (-1 == msgsnd(THRD_WORKER[thrd_idx].msg_id, &intl_req, sizeof(intl_req) - sizeof(long), IPC_NOWAIT)) {
					APPLOG(APPLOG_ERR, "%s():%d msgsnd fail", __func__, __LINE__);
                }
				continue;
			} 
			if (session_data->ping_cnt ++ % SERVER_CONF.ping_interval == 0) {
				set_intl_req_msg(&intl_req, thrd_idx, 0, sess_idx, session_data->session_id, 0, HTTP_INTL_SEND_PING);
				if (-1 == msgsnd(THRD_WORKER[thrd_idx].msg_id, &intl_req, sizeof(intl_req) - sizeof(long), IPC_NOWAIT)) {
					APPLOG(APPLOG_ERR, "%s():%d msgsnd fail", __func__, __LINE__);
				}
			}
		}
	}
}

void send_status_to_omp(evutil_socket_t fd, short what, void *arg)
{
	int i, index = 0;
	SFM_HttpConnStatusList conn_list;
	allow_list_t *allow_status;

	memset(&conn_list, 0x00, sizeof(SFM_HttpConnStatusList));
	for (i = 0; i < MAX_LIST_NUM; i++) {
		if (ALLOW_LIST[i].used != 1 || ALLOW_LIST[i].item_index == -1)
			continue;
		else
			allow_status = &ALLOW_LIST[i];

        index = conn_list.cnt++;
        conn_list.conn[index].id = allow_status->list_index;
        snprintf(conn_list.conn[index].host, sizeof(conn_list.conn[index].host), "%s", allow_status->host);
        snprintf(conn_list.conn[index].type, sizeof(conn_list.conn[index].type), "%s", allow_status->type);
        snprintf(conn_list.conn[index].ip, sizeof(conn_list.conn[index].ip), "%s", allow_status->ip);
        conn_list.conn[index].port = 0;
        conn_list.conn[index].max = allow_status->max;
        conn_list.conn[index].curr = allow_status->curr;
	}

	http_report_status(&conn_list, MSGID_HTTP_CLIENT_STATUS_REPORT);
}

void *workerThread(void *arg)
{
	int index = *(int *)arg;
	struct event_base *evbase;

	evbase = event_base_new();
	THRD_WORKER[index].evbase = evbase;

	/* this event ++ timer index, for timeout check func() */
	struct timeval tm_interval = {0, TM_INTERVAL};
	struct event *ev_tmr;
	ev_tmr = event_new(evbase, -1, EV_PERSIST, thrd_tick_callback, (void *)&index);
	event_add(ev_tmr, &tm_interval);

	/* this event check msgq to find sendmsg exist */
	struct timeval one_u_sec = {0, 1};
	struct event *ev_msg;
	ev_msg = event_new(evbase, -1, EV_PERSIST, recv_msgq_callback, &index); // thread index == msgq data_type 
	event_add(ev_msg, &one_u_sec);

	/* if flag == 0 and no event pending, loop just exited */
	event_base_loop(evbase, EVLOOP_NO_EXIT_ON_EMPTY);

	event_base_free(evbase);

	APPLOG(APPLOG_ERR, "%s():%d reach here!!!", __func__, __LINE__);

	return NULL;
}

void create_https_worker()
{
	for (int i = 0; i < SERVER_CONF.worker_num; i++) {
		int res = pthread_create(&THRD_WORKER[i].thrd_id, NULL, &workerThread, (void *)&THREAD_NO[i]);
		if (res != 0) {
			APPLOG(APPLOG_ERR, "%s() Thread Create Fail (Worker:%2dth)", __func__, i);
			exit(0);
		} else {
			pthread_detach(THRD_WORKER[i].thrd_id);
		}
	}
}

int set_http2_option(server_conf *SERVER_CONF)
{
	/* create nghttp2 option */
	if (nghttp2_option_new(&SERVER_CONF->nghttp2_option) < 0) {
		APPLOG(APPLOG_ERR, "{{{INIT}}} %s fail to create nghttp2 option!", __func__);
		return -1;
	}

	/* set setting_header_table_size */
	nghttp2_option_set_max_deflate_dynamic_table_size(SERVER_CONF->nghttp2_option, SERVER_CONF->http_opt_header_table_size);
	APPLOG(APPLOG_ERR, "{{{INIT}}} %s set setting_header_table_size to [%d]", __func__, SERVER_CONF->http_opt_header_table_size);

	return 0;
}

int initialize()
{
	char fname[64] = { 0, }; 
	char tmp[64] = { 0, };
	int  key, i, j;
    char *env, *ptrStr;

	/*  get env */
    if ((env = getenv(IV_HOME)) == NULL) {
        fprintf(stderr,"{{{INIT}}} [%s] not found %s environment name!\n", __func__, IV_HOME);
        return (-1);
    }
    /* my proc name ... */
    sprintf(myProcName, "%s", "HTTPS");
    /* my sys name ... */
    if( (ptrStr=getenv(MY_SYS_NAME))==NULL ) {
        fprintf (stderr, "{{{INIT}}} [%s] ERROR getenv %s fail!\n", __func__, MY_SYS_NAME);
        return -1;
    }
    strcpy(mySysName, ptrStr);

    /* libevent, multi-thread safe code (always locked) */
    evthread_use_pthreads();

	/* local config loading */
    if (init_cfg() < 0) {
        fprintf(stderr, "{{{INIT}}} fail to init config!\n");
        return (-1);
    }
#ifdef LOG_LIB
	char log_path[1024] = {0,};
	sprintf(log_path, "%s/log/STACK/%s", getenv(IV_HOME), myProcName);
	initlog_for_loglib(myProcName, log_path);
#elif LOG_APP
    sprintf(fname, "%s/log/STACK", getenv(IV_HOME));
    LogInit(myProcName, fname);
#endif
    if (config_load_just_log() < 0) {
        fprintf(stderr, "{{{INIT}}} fail to read config file (log)!\n");
        return (-1);
    }
    *lOG_FLAG = SERVER_CONF.log_level;
	APPLOG(APPLOG_ERR, "\n\n[[[[[ Welcome Process Started ]]]]]");

	if (config_load() < 0) {
		APPLOG(APPLOG_ERR, "{{{INIT}}} fail to read config file!");
		return (-1);
	} else {
		print_list();
	}

	for ( i = 0; i < SERVER_CONF.worker_num; i++) {
		if (-1 == (THRD_WORKER[i].msg_id = msgget((key_t)(SERVER_CONF.worker_shmkey + i), IPC_CREAT | 0666))) {
			APPLOG(APPLOG_ERR, "{{{INIT}}} fail to create internal msgq id!");
			exit( 1);
		}
		/* & flushing it & remake */
		msgctl(THRD_WORKER[i].msg_id, IPC_RMID, NULL);
		if (-1 == (THRD_WORKER[i].msg_id = msgget((key_t)(SERVER_CONF.worker_shmkey + i), IPC_CREAT | 0666))) {
			APPLOG(APPLOG_ERR, "{{{INIT}}} fail to create internal msgq id!");
			exit( 1);
		}
	}

    /* oauth 2.0 */
#if 0
	if (!strlen(SERVER_CONF.uuid_file)) {
		APPLOG(APPLOG_ERR, "{{{INIT}}} SERVER_CONF.uuid file is NULL!\n");
		return -1;
	} else {
		json_t *json = NULL;
		json_error_t error = {0,};
		json_t *uuid = NULL; 
		json = json_load_file((SERVER_CONF.uuid_file), 0, &error);
		if (!json) {
			APPLOG(APPLOG_ERR, "{{{INIT}}} fail to json-read from (%s)!", SERVER_CONF.uuid_file);
			return -1;
		} else if ((uuid = json_object_get(json, "VNF_INSTANCE_ID")) == NULL) {
			APPLOG(APPLOG_ERR, "{{{INIT}}} fail to (%s) doesn't include key (%s)!", SERVER_CONF.uuid_file, "VNF_INSTANCE_ID");
			return -1;
		} else {
			sprintf(myUUID, "%s", json_string_value(uuid));
			/* success */
			APPLOG(APPLOG_ERR, "{{{INIT}}} mySvr UUID is (%s) check from (%s)", myUUID, SERVER_CONF.uuid_file);
		}
	}
#else
    if (get_uuid_from_associate(&SERVER_CONF.uuid_list) <= 0) {
        APPLOG(APPLOG_ERR, "{{{INIT}}} fail to get uuids from ~/associate_config");
        return -1;
    } else {
        for (int i = 0; i < SERVER_CONF.uuid_list.peer_nfs_num; i++) {
            APPLOG(APPLOG_ERR, "{{{INIT}}} find same type uuid [%02d : %s]", i, SERVER_CONF.uuid_list.uuid[i]);
        }
    }
#endif

    /* allow list shm */
    sprintf(fname,"%s/%s", env, SYSCONF_FILE);

    if (conflib_getNthTokenInFileSection (fname, "SHARED_MEMORY_KEY", "SHM_HTTPS_CONN", 1, tmp) < 0 )
        return -1;
    int shm_https_conn_key = strtol(tmp,(char**)0,0);

    int shm_https_conn_id = 0;
    if ((shm_https_conn_id = (int)shmget (shm_https_conn_key, sizeof(allow_list_t) * MAX_LIST_NUM, 0644|IPC_CREAT)) < 0) {
        APPLOG(APPLOG_ERR,"[%s] SHM_HTTTPS_CONN shmget fail; err=%d(%s)", __func__, errno, strerror(errno));
        return -1;
    }
    if ((void*)(ALLOW_LIST_SHM = (allow_list_t *)shmat(shm_https_conn_id,0,0)) == (void*)-1) {
        APPLOG(APPLOG_ERR,"[%s] SHM_HTTPS_CONN shmat fail; err=%d(%s)", __func__, errno, strerror(errno));
        return -1;
    }

#ifdef SYSCONF_LEGACY
    int PROC_NAME_LOC = 1; // some old sysconf : eir ...
#else
    int PROC_NAME_LOC = 3;
#endif

	/* create recv-mq */
    sprintf(fname,"%s/%s", env, SYSCONF_FILE);
    if (conflib_getNthTokenInFileSection (fname, "APPLICATIONS", myProcName, PROC_NAME_LOC, tmp) < 0)
        return (-1);
    key = strtol(tmp,0,0);
    if ((httpsQid = msgget(key,IPC_CREAT|0666)) < 0) {
        APPLOG(APPLOG_ERR, "{{{INIT}}} [%s] msgget fail; key=0x%x,err=%d(%s)!", __func__, key, errno, strerror(errno));
        return (-1);
    } else {
        APPLOG(APPLOG_ERR, "{{{INIT}}} [%s] msgget success; key=0x%x,httpsQid=(%d)!", __func__, key, httpsQid);
    }

    /* create send-(ixpc) mq */
    if (conflib_getNthTokenInFileSection (fname, "APPLICATIONS", "IXPC", PROC_NAME_LOC, tmp) < 0)
        return -1;
    key = strtol(tmp,0,0);
    if ((ixpcQid = msgget(key,IPC_CREAT|0666)) < 0) {
        APPLOG(APPLOG_ERR, "{{{INIT}}} [%s] msgget fail; key=0x%x,err=%d(%s)!", __func__, key, errno, strerror(errno));
        return -1;
    }

    /* create send-(nrfm) mq */
    if (conflib_getNthTokenInFileSection (fname, "APPLICATIONS", "NRFM", PROC_NAME_LOC, tmp) >= 0) {
		key = strtol(tmp,0,0);
		if ((nrfmQid = msgget(key,IPC_CREAT|0666)) < 0) {
			APPLOG(APPLOG_ERR, "{{{INIT}}} [%s] msgget fail; key=0x%x,err=%d(%s)! NRFM QID will 0", __func__, key, errno, strerror(errno));
		}
	} else {
		APPLOG(APPLOG_ERR, "{{{INIT}}} can't find NRFM info in sysconfig APPLITION!, NRFM QID will 0");
	}

	/* alloc context memory */
	for ( i = 0; i < SERVER_CONF.worker_num; i++) {
		HttpsCtx[i] = calloc (SIZEID, sizeof(https_ctx_t));
	}
	/* &initialize */
	for (i = 0; i < SERVER_CONF.worker_num; i++) {
		Init_CtxId(i);
		for (j = 0; j < SIZEID; j++) {
			HttpsCtx[i][j].occupied = 0;
		}
	}

    /* create header enum:string list for bsearch and relay */
    if (set_relay_vhdr(VHDR_INDEX[0], VH_END) < 0) {
		APPLOG(APPLOG_ERR, "{{{INIT}}} relay vhdr set fail!");
        return -1;
	} else {
        print_relay_vhdr(VHDR_INDEX[0], VH_END);
	}
	memcpy(VHDR_INDEX[1], VHDR_INDEX[0], sizeof(hdr_index_t) * MAX_HDR_RELAY_CNT);


    if (sort_relay_vhdr(VHDR_INDEX[1], VH_END) < 0)
        return -1;
    else
        print_relay_vhdr(VHDR_INDEX[1], VH_END);

	/*  http/2 option load */
	if (set_http2_option(&SERVER_CONF) < 0) {
		APPLOG(APPLOG_ERR, "{{{INIT}}} set http/2 option fail!");
		return -1;
	}

	/* process start run */
    if (keepalivelib_init (myProcName) < 0)
        return (-1);

	/* check cert once */
	check_cert(SERVER_CONF.cert_file);

#ifdef OVLD_API
	/* for nssf overload control */
	// if (api_ovld_init(myProcName, API_PROTO_HTTPS, SERVER_CONF.worker_num) < 0) {
	if (api_ovld_init(myProcName) < 0) {
		APPLOG(APPLOG_ERR, "{{{INIT}}} ovldctrl init fail!");
	} else {
		APPLOG(APPLOG_ERR, "{{{INIT}}} ovldctrl init success!");
	}
#endif

	return 0;
}

void check_cert_cb(evutil_socket_t fd, short what, void *arg)
{
	check_cert(SERVER_CONF.cert_file);
}

static void main_loop(const char *key_file, const char *cert_file) {
	SSL_CTX *ssl_ctx = NULL;
	app_context comm_app_ctx_tls = {0,};
	app_context comm_app_ctx_tcp = {0,};
	app_context direct_app_ctx_tls[MAX_PORT_NUM];
	app_context direct_app_ctx_tcp[MAX_PORT_NUM];
	struct event_base *evbase;
	char port_str[12] = {0,};
	int i;

	ssl_ctx = create_ssl_ctx(key_file, cert_file);

	/* create event base */
	evbase = event_base_new();

	/* initialize https (over tls) listen ports */
	initialize_app_context(&comm_app_ctx_tls, ssl_ctx, evbase, 0, 0);
	for (i = 0; i < MAX_PORT_NUM; i++) {
		if (SERVER_CONF.https_listen_port[i]) {
			sprintf(port_str, "%d", SERVER_CONF.https_listen_port[i]);
			start_listen(evbase, port_str, &comm_app_ctx_tls);
		}
	}
	/* initialize http (over tcp) listen ports */
	initialize_app_context(&comm_app_ctx_tcp, NULL, evbase, 0, 0);
	for (i = 0; i < MAX_PORT_NUM; i++) {
		if (SERVER_CONF.http_listen_port[i]) {
			sprintf(port_str, "%d", SERVER_CONF.http_listen_port[i]);
			start_listen(evbase, port_str, &comm_app_ctx_tcp);
		}
	}

	/* if enabled, initial direct relay listen ports, it only https (over tls) support now */
	if (SERVER_CONF.dr_enabled) {
		for (i = 0; i < MAX_PORT_NUM; i++) {
			initialize_app_context(&direct_app_ctx_tls[i], ssl_ctx, evbase, 1, i);
			if (SERVER_CONF.callback_port_tls[i]) {
				sprintf(port_str, "%d", SERVER_CONF.callback_port_tls[i]);
				start_listen(evbase, port_str, &direct_app_ctx_tls[i]);
			}
		}
		for (i = 0; i < MAX_PORT_NUM; i++) {
			initialize_app_context(&direct_app_ctx_tcp[i], NULL, evbase, 1, i);
			if (SERVER_CONF.callback_port_tcp[i]) {
				sprintf(port_str, "%d", SERVER_CONF.callback_port_tcp[i]);
				start_listen(evbase, port_str, &direct_app_ctx_tcp[i]);
			}
		}
	}

	/* tick function */
	struct timeval tic_sec = {1, 0};
	struct event *ev_tick;
	ev_tick = event_new(evbase, -1, EV_PERSIST, main_tick_callback, NULL);
	event_add(ev_tick, &tic_sec);

    /* publish allow list to shm */
	struct event *ev_https_shm;
    ev_https_shm = event_new(evbase, -1, EV_PERSIST, https_shm_callback, NULL);
	event_add(ev_https_shm, &tic_sec);

	/* check context timeout */
    struct timeval tm_interval = {0, TM_INTERVAL * 5};
    struct event *ev_timeout;
    ev_timeout = event_new(evbase, -1, EV_PERSIST, chk_tmout_callback, NULL);
    event_add(ev_timeout, &tm_interval);

	/* send ping & delete goaway session */
	struct timeval tm_ping = {1, 0};
	struct event *ev_ping;
	ev_ping = event_new(evbase, -1, EV_PERSIST, send_ping_callback, NULL);
	event_add(ev_ping, &tm_ping);

    /* send conn status to OMP FIMD */
    struct timeval tm_status = {5, 0};
    struct event *ev_status;
    ev_status = event_new(evbase, -1, EV_PERSIST, send_status_to_omp, NULL);
    event_add(ev_status, &tm_status);

	/* system message handle */
    //struct timeval tm_milisec = {0, 100000}; // 100 ms
    struct timeval tm_milisec = {0, 1000}; // 1 ms
    struct event *ev_msg_handle;
    ev_msg_handle = event_new(evbase, -1, EV_PERSIST, message_handle, NULL);
    event_add(ev_msg_handle, &tm_milisec);

    /* LB stat print */
    struct timeval lbctx_print_interval = {1, 0};
    struct event *ev_lbctx_print;
    ev_lbctx_print = event_new(evbase, -1, EV_PERSIST, fep_stat_print, NULL);
    event_add(ev_lbctx_print, &lbctx_print_interval);

	/* check cert expire */
	struct timeval check_cert_interval = { 60 * 60 * 12, 0}; // every 12 hour
	struct event *ev_cert_check;
	ev_cert_check = event_new(evbase, -1, EV_PERSIST, check_cert_cb, NULL); 
	event_add(ev_cert_check, &check_cert_interval);

	/* start loop */
	event_base_loop(evbase, EVLOOP_NO_EXIT_ON_EMPTY);


	/* never reach here */
	event_base_free(evbase);
	SSL_CTX_free(ssl_ctx);
}

#if 0
// nghttp2 --enable-debug 와 함께 사용
- 성능 저하 발생함
- library 전체 로그 출력/저장으로 분석 어려움 
void test_debug_func(const char *fmt, va_list args)
{
	logPrint(ELI, FL, fmt, args);
	fprintf(stderr, fmt, args);
}
...
nghttp2_set_debug_vprintf_callback(test_debug_func);
#endif

int main(int argc, char **argv) {
	struct sigaction act;

	memset(&act, 0, sizeof(struct sigaction));
	act.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &act, NULL);

	if (initialize() < 0) {
		fprintf(stderr,"{{{INIT}}} https_initial fail!!!\n");
		return (-1);
	}

	SSL_load_error_strings();
	SSL_library_init();

    /* create ahif conn --> https recv */
	create_lb_thread();
	create_https_worker();

	sleep(3);

	main_loop(SERVER_CONF.key_file, SERVER_CONF.cert_file);

	return 0;
}
