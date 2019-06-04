
#include "libreq.h"

static libhttp_stream_data_t *lib_create_stream_data(const char *uri, struct http_parser_url *u, 
		libhttp_single_sndreq_t *sndreq, libhttp_single_rcvres_t *rcvres)
{
	/* MAX 5 digits (max 65535) + 1 ':' + 1 NULL (because of snprintf) */
	size_t extra = 7;
	libhttp_stream_data_t *stream_data = malloc(sizeof(libhttp_stream_data_t));
	memset(stream_data, 0x00, sizeof(libhttp_stream_data_t));

	stream_data->uri = uri;
	stream_data->u = u;
	stream_data->stream_id = -1;

	stream_data->authoritylen = u->field_data[UF_HOST].len;
	stream_data->authority = malloc(stream_data->authoritylen + extra);
	memcpy(stream_data->authority, &uri[u->field_data[UF_HOST].off],
			u->field_data[UF_HOST].len);
	if (u->field_set & (1 << UF_PORT)) {
		stream_data->authoritylen +=
			(size_t)snprintf(stream_data->authority + u->field_data[UF_HOST].len,
					extra, ":%u", u->port);
	}

	/* If we don't have path in URI, we use "/" as path. */
	stream_data->pathlen = 1;
	if (u->field_set & (1 << UF_PATH)) {
		stream_data->pathlen = u->field_data[UF_PATH].len;
	}
	if (u->field_set & (1 << UF_QUERY)) {
		/* +1 for '?' character */
		stream_data->pathlen += (size_t)(u->field_data[UF_QUERY].len + 1);
	}

	stream_data->path = malloc(stream_data->pathlen);
	if (u->field_set & (1 << UF_PATH)) {
		memcpy(stream_data->path, &uri[u->field_data[UF_PATH].off],
				u->field_data[UF_PATH].len);
	} else {
		stream_data->path[0] = '/';
	}
	if (u->field_set & (1 << UF_QUERY)) {
		stream_data->path[stream_data->pathlen - u->field_data[UF_QUERY].len - 1] =
			'?';
		memcpy(stream_data->path + stream_data->pathlen -
				u->field_data[UF_QUERY].len,
				&uri[u->field_data[UF_QUERY].off], u->field_data[UF_QUERY].len);
	}

	/* schlee, set request info : caution!!! NOT deep copy, caller MUST hold context */
	stream_data->sndreq = sndreq;
	stream_data->rcvres = rcvres;

	return stream_data;
}

static void lib_delete_stream_data(libhttp_stream_data_t *stream_data) {
	free(stream_data->path);
	free(stream_data->authority);
	free(stream_data);
}

static libhttp_session_data_t *lib_create_session_data(struct event_base *evbase) {
	libhttp_session_data_t *session_data = malloc(sizeof(libhttp_session_data_t));

	memset(session_data, 0, sizeof(libhttp_session_data_t));
	session_data->dnsbase = evdns_base_new(evbase, 1);
	return session_data;
}

static void lib_delete_session_data(libhttp_session_data_t *session_data) {
	SSL *ssl = bufferevent_openssl_get_ssl(session_data->bev);

	if (ssl) {
		SSL_shutdown(ssl);
	}
	bufferevent_free(session_data->bev);
	session_data->bev = NULL;
	evdns_base_free(session_data->dnsbase, 1);
	session_data->dnsbase = NULL;
	nghttp2_session_del(session_data->session);
	session_data->session = NULL;
	if (session_data->stream_data) {
		lib_delete_stream_data(session_data->stream_data);
		session_data->stream_data = NULL;
	}
	free(session_data);
}

static ssize_t lib_send_callback(nghttp2_session *session, const uint8_t *data,
		size_t length, int flags, void *user_data) {
	libhttp_session_data_t *session_data = (libhttp_session_data_t *)user_data;
	struct bufferevent *bev = session_data->bev;
	(void)session;
	(void)flags;

	bufferevent_write(bev, data, length);
	return (ssize_t)length;
}

static int lib_on_header_callback(nghttp2_session *session,
		const nghttp2_frame *frame, const uint8_t *name,
		size_t namelen, const uint8_t *value,
		size_t valuelen, uint8_t flags, void *user_data) {
	libhttp_session_data_t *session_data = (libhttp_session_data_t *)user_data;
	(void)session;
	(void)flags;

	char *header_name = (char *)name;
	char *header_value = (char *)value;

	switch (frame->hd.type) {
		case NGHTTP2_HEADERS:
			if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE &&
					session_data->stream_data->stream_id == frame->hd.stream_id) {
				/* Print response headers for the initiated request. */
				print_header(stderr, name, namelen, value, valuelen);
				/* schlee, we need to do some more */
				//break;
			}
			if (!strcmp(header_name, HDR_STATUS)) {
				libhttp_single_rcvres_t *rcvres = session_data->stream_data->rcvres;
				rcvres->res_code = atoi(header_value);
			}
	}
	return 0;
}

static int lib_on_begin_headers_callback(nghttp2_session *session,
		const nghttp2_frame *frame,
		void *user_data) {
	libhttp_session_data_t *session_data = (libhttp_session_data_t *)user_data;
	(void)session;

	switch (frame->hd.type) {
		case NGHTTP2_HEADERS:
			if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE &&
					session_data->stream_data->stream_id == frame->hd.stream_id) {
				APPLOG(APPLOG_DETAIL, "{{{HLIB}}} Response headers for stream ID=%d",
						frame->hd.stream_id);
			}
			break;
	}
	return 0;
}

static int lib_on_frame_recv_callback(nghttp2_session *session,
		const nghttp2_frame *frame, void *user_data) {
	libhttp_session_data_t *session_data = (libhttp_session_data_t *)user_data;
	(void)session;

	switch (frame->hd.type) {
		case NGHTTP2_HEADERS:
			if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE &&
					session_data->stream_data->stream_id == frame->hd.stream_id) {
				APPLOG(APPLOG_DETAIL, "{{{HLIB}}} All headers received");
			}
			break;
	}
	return 0;
}

static int lib_on_data_chunk_recv_callback(nghttp2_session *session, uint8_t flags,
		int32_t stream_id, const uint8_t *data,
		size_t len, void *user_data) {
	libhttp_session_data_t *session_data = (libhttp_session_data_t *)user_data;
	(void)session;
	(void)flags;

	if (len == 0) return 0;
	if (session_data->stream_data->stream_id == stream_id) {
		/* data received */
		// schlee, this code have only 1 session & 1 stream. and can receive 65535 byte once
		libhttp_single_rcvres_t *rcvres = session_data->stream_data->rcvres;
		if ((rcvres->body_len + len) > rcvres->body_size)
			return -1;
		memcpy(rcvres->body + rcvres->body_len, data, len);
		rcvres->body_len = rcvres->body_len + len;
		//DumpHex(data, len);
	}
	return 0;
}

static int lib_on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
		uint32_t error_code, void *user_data) {
	libhttp_session_data_t *session_data = (libhttp_session_data_t *)user_data;
	int rv;

	if (session_data->stream_data->stream_id == stream_id) {
		APPLOG(APPLOG_DETAIL, "{{{HLIB}}} Stream %d closed with error_code=%u", stream_id,
				error_code);
		rv = nghttp2_session_terminate_session(session, NGHTTP2_NO_ERROR);
		if (rv != 0) {
			return NGHTTP2_ERR_CALLBACK_FAILURE;
		}
	}
	return 0;
}

static int lib_select_next_proto_cb(SSL *ssl, unsigned char **out,
		unsigned char *outlen, const unsigned char *in,
		unsigned int inlen, void *arg) {
	(void)ssl;
	(void)arg;

	if (nghttp2_select_next_protocol(out, outlen, in, inlen) <= 0) {
		APPLOG(APPLOG_ERR, "{{{HLIB}}} Server did not advertise" NGHTTP2_PROTO_VERSION_ID);
		return (-1);
	}
	return SSL_TLSEXT_ERR_OK;
}

static SSL_CTX *lib_create_ssl_ctx(void) {
	SSL_CTX *ssl_ctx;
	ssl_ctx = SSL_CTX_new(SSLv23_client_method());
	if (!ssl_ctx) {
		// TODO!!! fail exit
		APPLOG(APPLOG_ERR, "{{{HLIB}}} Could not create SSL/TLS context: %s",
				ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}
	SSL_CTX_set_options(ssl_ctx,
			SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
			SSL_OP_NO_COMPRESSION |
			SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
	SSL_CTX_set_next_proto_select_cb(ssl_ctx, lib_select_next_proto_cb, NULL);

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
	SSL_CTX_set_alpn_protos(ssl_ctx, (const unsigned char *)"\x02h2", 3);
#endif // OPENSSL_VERSION_NUMBER >= 0x10002000L

	return ssl_ctx;
}

static SSL *lib_create_ssl(SSL_CTX *ssl_ctx) {
	SSL *ssl;
	ssl = SSL_new(ssl_ctx);
	if (!ssl) {
		// TODO!!! fail exit
		APPLOG(APPLOG_ERR, "{{{HLIB}}} Could not create SSL/TLS session object: %s",
				ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}
	return ssl;
}

static void lib_initialize_http2_session(libhttp_session_data_t *session_data) {
	nghttp2_session_callbacks *callbacks;

	nghttp2_session_callbacks_new(&callbacks);

	nghttp2_session_callbacks_set_send_callback(callbacks, lib_send_callback);

	nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks,
			lib_on_frame_recv_callback);

	nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
			callbacks, lib_on_data_chunk_recv_callback);

	nghttp2_session_callbacks_set_on_stream_close_callback(
			callbacks, lib_on_stream_close_callback);

	nghttp2_session_callbacks_set_on_header_callback(callbacks,
			lib_on_header_callback);

	nghttp2_session_callbacks_set_on_begin_headers_callback(
			callbacks, lib_on_begin_headers_callback);

	nghttp2_session_client_new(&session_data->session, callbacks, session_data);

	nghttp2_session_callbacks_del(callbacks);
}

static void lib_send_client_connection_header(libhttp_session_data_t *session_data) {
	/* schlee, IMPORTANT, thease means MAX SND/RCV SIZE & MAX CURR STREAM */
	nghttp2_settings_entry iv[5] = {
		{NGHTTP2_SETTINGS_HEADER_TABLE_SIZE, 65535},
		{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 1024},
		{NGHTTP2_SETTINGS_MAX_FRAME_SIZE, 65535},
		{NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 65535},
		{NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE, 65535}};

	/* client 24 bytes magic string will be sent by nghttp2 library */
	int rv = nghttp2_submit_settings(session_data->session, NGHTTP2_FLAG_NONE, iv,
			ARRLEN(iv));
	if (rv != 0) {
		APPLOG(APPLOG_ERR, "{{{{HLIB}}} Could not submit SETTINGS: %s", nghttp2_strerror(rv));
	}
}

static ssize_t lib_ptr_read_callback(nghttp2_session *session, int32_t stream_id,
        uint8_t *buf, size_t length,
        uint32_t *data_flags,
        nghttp2_data_source *source,
        void *user_data) {
	libhttp_stream_data_t *stream_data = (libhttp_stream_data_t *)source->ptr;
	void *data = stream_data->sndreq->body;
    int len = stream_data->sndreq->body_size;

    if (len >= length) {
        APPLOG(APPLOG_ERR, "{{{HLIB}}} %s() length(%d) exceed maximum val(%zu)",
                __func__, len, length);
        return 0;
    }
    memcpy(buf, data, len);

    *data_flags |= NGHTTP2_DATA_FLAG_EOF;

    return len;
}

static void lib_submit_request(libhttp_session_data_t *session_data) {
	int32_t stream_id;
	libhttp_stream_data_t *stream_data = session_data->stream_data;
	const char *uri = stream_data->uri;
	const struct http_parser_url *u = stream_data->u;
	nghttp2_data_provider data_prd;

	/* make normal header */
	nghttp2_nv hdrs[4 + 1 /*if content type exist */] = {
		MAKE_NV(":method", stream_data->sndreq->method, strlen(stream_data->sndreq->method)),
		MAKE_NV(":scheme", &uri[u->field_data[UF_SCHEMA].off],
				u->field_data[UF_SCHEMA].len),
		MAKE_NV(":authority", stream_data->authority, stream_data->authoritylen), /* TODO!!!! check authority!!!! */
		MAKE_NV(":path", stream_data->path, stream_data->pathlen)};
	int hdrs_len = 4;

	/* additional header */
	if (stream_data->sndreq->content_type != NULL) {
		nghttp2_nv more_hdr[1] = {
			MAKE_NV(HDR_CONTENT_TYPE, stream_data->sndreq->content_type, strlen(stream_data->sndreq->content_type))
		};
		memcpy(&hdrs[4], more_hdr, sizeof(nghttp2_nv));
		hdrs_len ++;
	}

	APPLOG(APPLOG_DETAIL, "Request headers:");
	APPLOG(APPLOG_DETAIL, "hdrs len %d", hdrs_len);
	print_headers(stderr, hdrs, hdrs_len);

	if (stream_data->sndreq->body_size > 0) {
		data_prd.source.ptr = stream_data;
		data_prd.read_callback = lib_ptr_read_callback;
	}
	stream_id = nghttp2_submit_request(session_data->session, NULL, hdrs, hdrs_len, 
		(stream_data->sndreq->body_size > 0) ? &data_prd : NULL, stream_data);
	if (stream_id < 0) {
		APPLOG(APPLOG_ERR, "{{{HLIB}}} Could not submit HTTP request: %s", nghttp2_strerror(stream_id));
		/* schlee, stream_id (-) setted, will error handle */
	}

	stream_data->stream_id = stream_id;
}

static int lib_session_send(libhttp_session_data_t *session_data) {
	int rv;

	rv = nghttp2_session_send(session_data->session);
	if (rv != 0) {
		APPLOG(APPLOG_ERR, "{{{HLIB}}} %s() Fatal error: %s", __func__, nghttp2_strerror(rv));
		return -1;
	}
	return 0;
}

static void lib_readcb(struct bufferevent *bev, void *ptr) {
	libhttp_session_data_t *session_data = (libhttp_session_data_t *)ptr;
	ssize_t readlen;
	struct evbuffer *input = bufferevent_get_input(bev);
	size_t datalen = evbuffer_get_length(input);
	unsigned char *data = evbuffer_pullup(input, -1);

	readlen = nghttp2_session_mem_recv(session_data->session, data, datalen);
	if (readlen < 0) {
		APPLOG(APPLOG_ERR, "{{{HLIB}}} %s() Fatal error: %s", __func__, nghttp2_strerror((int)readlen));
		lib_delete_session_data(session_data);
		return;
	}
	if (evbuffer_drain(input, (size_t)readlen) != 0) {
		APPLOG(APPLOG_ERR, "{{{HLIB}}} %s() Fatal error: evbuffer_drain failed", __func__);
		lib_delete_session_data(session_data);
		return;
	}
	if (lib_session_send(session_data) != 0) {
		lib_delete_session_data(session_data);
		return;
	}
}

static void lib_writecb(struct bufferevent *bev, void *ptr) {
	libhttp_session_data_t *session_data = (libhttp_session_data_t *)ptr;
	(void)bev;

	if (nghttp2_session_want_read(session_data->session) == 0 &&
			nghttp2_session_want_write(session_data->session) == 0 &&
			evbuffer_get_length(bufferevent_get_output(session_data->bev)) == 0) {
		lib_delete_session_data(session_data);
	}
}

static void lib_eventcb(struct bufferevent *bev, short events, void *ptr) {
	libhttp_session_data_t *session_data = (libhttp_session_data_t *)ptr;
	if (events & BEV_EVENT_CONNECTED) {
		int fd = bufferevent_getfd(bev);
		int val = 1;
		const unsigned char *alpn = NULL;
		unsigned int alpnlen = 0;
		SSL *ssl;

		APPLOG(APPLOG_DETAIL, "{{{HLIB}}} %s() Connected!!!", __func__);

		ssl = bufferevent_openssl_get_ssl(session_data->bev);

		SSL_get0_next_proto_negotiated(ssl, &alpn, &alpnlen);
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
		if (alpn == NULL) {
			SSL_get0_alpn_selected(ssl, &alpn, &alpnlen);
		}
#endif // OPENSSL_VERSION_NUMBER >= 0x10002000L

		if (alpn == NULL || alpnlen != 2 || memcmp("h2", alpn, 2) != 0) {
			APPLOG(APPLOG_ERR, "{{{HLIB}}} h2 is not negotiated");
			lib_delete_session_data(session_data);
			return;
		}

		setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&val, sizeof(val));
		lib_initialize_http2_session(session_data);
		lib_send_client_connection_header(session_data);
		lib_submit_request(session_data);
		if (lib_session_send(session_data) != 0) {
			lib_delete_session_data(session_data);
		}
		return;
	}
	if (events & BEV_EVENT_EOF) {
		APPLOG(APPLOG_DETAIL, "{{{HLIB}}} %s() Disconnected from the remote host", __func__);
	} else if (events & BEV_EVENT_ERROR) {
		APPLOG(APPLOG_DETAIL, "{{{HLIB}}} %s() Network error", __func__);
	} else if (events & BEV_EVENT_TIMEOUT) {
		APPLOG(APPLOG_DETAIL, "{{{HLIB}}} %s() Timeout", __func__);
	}
	lib_delete_session_data(session_data);
}

static struct timeval TM_SYN_TIMEOUT = {3, 0};
static void lib_initiate_connection(struct event_base *evbase, SSL_CTX *ssl_ctx,
		const char *host, uint16_t port,
		libhttp_session_data_t *session_data) {
	int rv;
	struct bufferevent *bev;
	SSL *ssl;

	ssl = lib_create_ssl(ssl_ctx);
	bev = bufferevent_openssl_socket_new(
			evbase, -1, ssl, BUFFEREVENT_SSL_CONNECTING,
			BEV_OPT_DEFER_CALLBACKS | BEV_OPT_CLOSE_ON_FREE);
	bufferevent_enable(bev, EV_READ | EV_WRITE);
	bufferevent_setcb(bev, lib_readcb, lib_writecb, lib_eventcb, session_data);
	bufferevent_set_timeouts(bev, &TM_SYN_TIMEOUT, &TM_SYN_TIMEOUT);
	rv = bufferevent_socket_connect_hostname(bev, session_data->dnsbase,
			AF_UNSPEC, host, port);

	if (rv != 0) {
		APPLOG(APPLOG_ERR, "{{{HLIB}}} Could not connect to the remote host %s", host);
		// TODO!!! let's see what happen
	}
	session_data->bev = bev;
}

void single_run(libhttp_single_sndreq_t *sndreq, libhttp_single_rcvres_t *rcvres)
{
	struct http_parser_url u;
	char *host;
	uint16_t port;
	int rv;
	SSL_CTX *ssl_ctx;
	struct event_base *evbase;
	libhttp_session_data_t *session_data;
	char *uri = sndreq->uri;

	/* Parse the |uri| and stores its components in |u| */
	rv = http_parser_parse_url(uri, strlen(uri), 0, &u);
	if (rv != 0) {
		APPLOG(APPLOG_ERR, "{{{HLIB}}} Could not parse URI %s", uri);
		return;
	}

	host = strndup(&uri[u.field_data[UF_HOST].off], u.field_data[UF_HOST].len);
	if (!(u.field_set & (1 << UF_PORT))) {
		port = 443;
	} else {
		port = u.port;
	}

	ssl_ctx = lib_create_ssl_ctx();

	evbase = event_base_new();

	session_data = lib_create_session_data(evbase);
	session_data->stream_data = lib_create_stream_data(uri, &u, sndreq, rcvres);

	lib_initiate_connection(evbase, ssl_ctx, host, port, session_data);
	free(host);
	host = NULL;

	event_base_loop(evbase, 0);

	event_base_free(evbase);
	SSL_CTX_free(ssl_ctx);

	APPLOG(APPLOG_DETAIL, "{{{HLIB}}} all RESOURCE cleared !!!");

	return;
}
