
#include <restcli.h>

config_t MAIN_CFG; /* ~.cfg */

typedef struct {
  /* The NULL-terminated URI string to retrieve. */
  const char *uri;
  /* Parsed result of the |uri| */
  struct http_parser_url *u;
  /* The authority portion of the |uri|, not NULL-terminated */
  char *authority;
  /* The path portion of the |uri|, including query, not
     NULL-terminated */
  char *path;
  /* The length of the |authority| */
  size_t authoritylen;
  /* The length of the |path| */
  size_t pathlen;
  /* The stream ID of this stream */
  int32_t stream_id;

  int from_file;
  const char *body_ptr;
  int fd;
} http2_stream_data;

typedef struct {
  nghttp2_session *session;
  struct evdns_base *dnsbase;
  struct bufferevent *bev;
  http2_stream_data *stream_data;

  char scheme[128];
} http2_session_data;

static http2_stream_data *create_http2_stream_data(const char *uri,
                                                   struct http_parser_url *u) {
  /* MAX 5 digits (max 65535) + 1 ':' + 1 NULL (because of snprintf) */
  size_t extra = 7;
  http2_stream_data *stream_data = malloc(sizeof(http2_stream_data));

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

  return stream_data;
}

static void delete_http2_stream_data(http2_stream_data *stream_data) {
  free(stream_data->path);
  free(stream_data->authority);
  free(stream_data);
}

/* Initializes |session_data| */
static http2_session_data *
create_http2_session_data(struct event_base *evbase) {
  http2_session_data *session_data = malloc(sizeof(http2_session_data));

  memset(session_data, 0, sizeof(http2_session_data));
  session_data->dnsbase = evdns_base_new(evbase, 1);
  return session_data;
}

static void delete_http2_session_data(http2_session_data *session_data) {
	if (!strcmp(session_data->scheme, "https")) {
		SSL *ssl = bufferevent_openssl_get_ssl(session_data->bev);
		if (ssl) {
			SSL_shutdown(ssl);
		}
	}

  bufferevent_free(session_data->bev);
  session_data->bev = NULL;
  evdns_base_free(session_data->dnsbase, 1);
  session_data->dnsbase = NULL;
  nghttp2_session_del(session_data->session);
  session_data->session = NULL;
  if (session_data->stream_data) {
    delete_http2_stream_data(session_data->stream_data);
    session_data->stream_data = NULL;
  }
  free(session_data);
}

static void print_header(FILE *f, const uint8_t *name, size_t namelen,
                         const uint8_t *value, size_t valuelen) {
  fwrite(name, 1, namelen, f);
  fprintf(f, ": ");
  fwrite(value, 1, valuelen, f);
  fprintf(f, "\n");
}

/* Print HTTP headers to |f|. Please note that this function does not
   take into account that header name and value are sequence of
   octets, therefore they may contain non-printable characters. */
static void print_headers(FILE *f, nghttp2_nv *nva, size_t nvlen) {
  size_t i;
  for (i = 0; i < nvlen; ++i) {
    print_header(f, nva[i].name, nva[i].namelen, nva[i].value, nva[i].valuelen);
  }
  fprintf(f, "\n");
}

/* nghttp2_send_callback. Here we transmit the |data|, |length| bytes,
   to the network. Because we are using libevent bufferevent, we just
   write those bytes into bufferevent buffer. */
static ssize_t send_callback(nghttp2_session *session, const uint8_t *data,
                             size_t length, int flags, void *user_data) {
  http2_session_data *session_data = (http2_session_data *)user_data;
  struct bufferevent *bev = session_data->bev;
  (void)session;
  (void)flags;

  bufferevent_write(bev, data, length);
  return (ssize_t)length;
}

/* nghttp2_on_header_callback: Called when nghttp2 library emits
   single header name/value pair. */
static int on_header_callback(nghttp2_session *session,
                              const nghttp2_frame *frame, const uint8_t *name,
                              size_t namelen, const uint8_t *value,
                              size_t valuelen, uint8_t flags, void *user_data) {
  http2_session_data *session_data = (http2_session_data *)user_data;
  (void)session;
  (void)flags;

  switch (frame->hd.type) {
  case NGHTTP2_HEADERS:
    if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE &&
        session_data->stream_data->stream_id == frame->hd.stream_id) {
      /* Print response headers for the initiated request. */
      print_header(stderr, name, namelen, value, valuelen);
      break;
    }
  }
  return 0;
}

/* nghttp2_on_begin_headers_callback: Called when nghttp2 library gets
   started to receive header block. */
static int on_begin_headers_callback(nghttp2_session *session,
                                     const nghttp2_frame *frame,
                                     void *user_data) {
  http2_session_data *session_data = (http2_session_data *)user_data;
  (void)session;

  switch (frame->hd.type) {
  case NGHTTP2_HEADERS:
    if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE &&
        session_data->stream_data->stream_id == frame->hd.stream_id) {
      fprintf(stderr, "\nResponse headers for stream ID=%d:\n",
              frame->hd.stream_id);
    }
    break;
  }
  return 0;
}

/* nghttp2_on_frame_recv_callback: Called when nghttp2 library
   received a complete frame from the remote peer. */
static int on_frame_recv_callback(nghttp2_session *session,
                                  const nghttp2_frame *frame, void *user_data) {
  http2_session_data *session_data = (http2_session_data *)user_data;
  (void)session;

  switch (frame->hd.type) {
  case NGHTTP2_HEADERS:
    if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE &&
        session_data->stream_data->stream_id == frame->hd.stream_id) {
      fprintf(stderr, "All headers received\n\n");
    }
    break;
  }
  return 0;
}

/* nghttp2_on_data_chunk_recv_callback: Called when DATA frame is
   received from the remote peer. In this implementation, if the frame
   is meant to the stream we initiated, print the received data in
   stdout, so that the user can redirect its output to the file
   easily. */
static int on_data_chunk_recv_callback(nghttp2_session *session, uint8_t flags,
                                       int32_t stream_id, const uint8_t *data,
                                       size_t len, void *user_data) {
  http2_session_data *session_data = (http2_session_data *)user_data;
  (void)session;
  (void)flags;

  if (session_data->stream_data->stream_id == stream_id) {
	  fwrite(data, 1, len, stderr);
	  fprintf(stderr, "\n\n");
  }
  return 0;
}

/* nghttp2_on_stream_close_callback: Called when a stream is about to
   closed. This example program only deals with 1 HTTP request (1
   stream), if it is closed, we send GOAWAY and tear down the
   session */
static int on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
                                    uint32_t error_code, void *user_data) {
  http2_session_data *session_data = (http2_session_data *)user_data;
  int rv;

  if (session_data->stream_data->stream_id == stream_id) {
    fprintf(stderr, "Stream %d closed with error_code=%u\n", stream_id,
            error_code);
    rv = nghttp2_session_terminate_session(session, NGHTTP2_NO_ERROR);
    if (rv != 0) {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }
  return 0;
}

/* NPN TLS extension client callback. We check that server advertised
   the HTTP/2 protocol the nghttp2 library supports. If not, exit
   the program. */
static int select_next_proto_cb(SSL *ssl, unsigned char **out,
                                unsigned char *outlen, const unsigned char *in,
                                unsigned int inlen, void *arg) {
  (void)ssl;
  (void)arg;

  if (nghttp2_select_next_protocol(out, outlen, in, inlen) <= 0) {
    errx(1, "Server did not advertise " NGHTTP2_PROTO_VERSION_ID);
  }
  return SSL_TLSEXT_ERR_OK;
}

/* Create SSL_CTX. */
static SSL_CTX *create_ssl_ctx(void) {
  SSL_CTX *ssl_ctx;
  ssl_ctx = SSL_CTX_new(SSLv23_client_method());
  if (!ssl_ctx) {
    errx(1, "Could not create SSL/TLS context: %s",
         ERR_error_string(ERR_get_error(), NULL));
  }
  SSL_CTX_set_options(ssl_ctx,
                      SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
                          SSL_OP_NO_COMPRESSION |
                          SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
  SSL_CTX_set_next_proto_select_cb(ssl_ctx, select_next_proto_cb, NULL);

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
  SSL_CTX_set_alpn_protos(ssl_ctx, (const unsigned char *)"\x02h2", 3);
#endif // OPENSSL_VERSION_NUMBER >= 0x10002000L

  return ssl_ctx;
}

/* Create SSL object */
static SSL *create_ssl(SSL_CTX *ssl_ctx) {
  SSL *ssl;
  ssl = SSL_new(ssl_ctx);
  if (!ssl) {
    errx(1, "Could not create SSL/TLS session object: %s",
         ERR_error_string(ERR_get_error(), NULL));
  }
  return ssl;
}

static void initialize_nghttp2_session(http2_session_data *session_data) {
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

  nghttp2_session_client_new(&session_data->session, callbacks, session_data);

  nghttp2_session_callbacks_del(callbacks);
}

static void send_client_connection_header(http2_session_data *session_data) {
  nghttp2_settings_entry iv[1] = {
      {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}};
  int rv;

  /* client 24 bytes magic string will be sent by nghttp2 library */
  rv = nghttp2_submit_settings(session_data->session, NGHTTP2_FLAG_NONE, iv,
                               ARRLEN(iv));
  if (rv != 0) {
    errx(1, "Could not submit SETTINGS: %s", nghttp2_strerror(rv));
  }
}


static ssize_t ptr_read_callback(nghttp2_session *session, int32_t stream_id,
        uint8_t *buf, size_t length,
        uint32_t *data_flags,
        nghttp2_data_source *source,
        void *user_data) {
    int len = 0;
    ssize_t r = 0;
    http2_stream_data *stream_data = (http2_stream_data *)source->ptr;

	if (stream_data->from_file) {
		char temp_buff[8192] = {0,};
		while ((r = read(stream_data->fd, temp_buff, length)) == -1 && errno == EINTR)
			;
		if (r == -1) {
			fprintf(stderr, "error r is (-1)\n");
			return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
		}
		len = r;
		memcpy(buf, temp_buff, len);
	} else {
		if (stream_data->body_ptr != NULL) {
			len = strlen(stream_data->body_ptr);
			memcpy(buf, stream_data->body_ptr, len);
		}
	}
	*data_flags |= NGHTTP2_DATA_FLAG_EOF;
	fwrite(buf, len, 1, stderr);
	fprintf(stderr, "\n");
	return len;
}

/* Send HTTP request to the remote peer */
static void submit_request(http2_session_data *session_data) {
  int32_t stream_id;
  http2_stream_data *stream_data = session_data->stream_data;
  const char *uri = stream_data->uri;
  const struct http_parser_url *u = stream_data->u;

  config_setting_t *cf_method = config_lookup(&MAIN_CFG, "api.method");
  config_setting_t *cf_hdrs = config_lookup(&MAIN_CFG, "api.request_hdrs");

  if (cf_method == NULL || cf_hdrs == NULL) {
	  fprintf(stderr, "can't find member [api.method | api.request_hdrs] from CFG\n");
	  return;
  }

  int hdrs_num = config_setting_length(cf_hdrs) + 4 /*static*/;
  int hdrs_pos = 0;
  nghttp2_nv *hdrs = malloc(sizeof(nghttp2_nv) * hdrs_num);

  nghttp2_nv temp_hdr0[] = {MAKE_NV_STR(":method", config_setting_get_string(cf_method))};
  memcpy(&hdrs[hdrs_pos++], temp_hdr0, sizeof(nghttp2_nv));

  nghttp2_nv temp_hdr1[] = {MAKE_NV(":scheme", &uri[u->field_data[UF_SCHEMA].off],u->field_data[UF_SCHEMA].len)};
  memcpy(&hdrs[hdrs_pos++], temp_hdr1, sizeof(nghttp2_nv));

  nghttp2_nv temp_hdr2[] = {MAKE_NV(":authority", stream_data->authority, stream_data->authoritylen)};
  memcpy(&hdrs[hdrs_pos++], temp_hdr2, sizeof(nghttp2_nv));

  nghttp2_nv temp_hdr3[] = {MAKE_NV(":path", stream_data->path, stream_data->pathlen)};
  memcpy(&hdrs[hdrs_pos++], temp_hdr3, sizeof(nghttp2_nv));

  for (int i = 0; i < config_setting_length(cf_hdrs); i++) {
	  config_setting_t *cf_header = config_setting_get_elem(cf_hdrs, i);
	  const char *name = NULL;
	  config_setting_lookup_string(cf_header, "name", &name);
	  const char *value = NULL;
	  config_setting_lookup_string(cf_header, "value", &value);

	  nghttp2_nv temp_hdr[] = {MAKE_NV_STR(name, value) };
	  memcpy(&hdrs[hdrs_pos++], temp_hdr, sizeof(nghttp2_nv));
  }

  fprintf(stderr, "\nRequest headers (%d):\n", hdrs_num);
  print_headers(stderr, hdrs, hdrs_num);

  const char *body_path = NULL;

  config_setting_t *cf_bodys = config_lookup(&MAIN_CFG, "api.request_body");
  if (cf_bodys == NULL) {
	  fprintf(stderr, "can't find member [api.request_body]!\n");
	  free(hdrs);
	  return;
  }

  config_setting_lookup_bool(cf_bodys, "from_file", &stream_data->from_file);
  if (stream_data->from_file) {
	  config_setting_lookup_string(cf_bodys, "body_ref", &body_path);
	  stream_data->fd = open(body_path, O_RDONLY);
	  if (stream_data->fd == -1) {
		  errx(1, "Could not read file: %s", body_path);
	  }
  } else {
	  config_setting_lookup_string(cf_bodys, "body_ref", &stream_data->body_ptr);
  }

  nghttp2_data_provider data_prd = {0,};
  data_prd.source.ptr = stream_data;
  data_prd.read_callback = ptr_read_callback;

  stream_id = nghttp2_submit_request(session_data->session, NULL, hdrs,
                                     hdrs_num, &data_prd, stream_data);
  if (stream_id < 0) {
    errx(1, "Could not submit HTTP request: %s", nghttp2_strerror(stream_id));
  }

  stream_data->stream_id = stream_id;
  free(hdrs);
}

/* Serialize the frame and send (or buffer) the data to
   bufferevent. */
static int session_send(http2_session_data *session_data) {
  int rv;

  rv = nghttp2_session_send(session_data->session);
  if (rv != 0) {
    warnx("Fatal error: %s", nghttp2_strerror(rv));
    return -1;
  }
  return 0;
}

/* readcb for bufferevent. Here we get the data from the input buffer
   of bufferevent and feed them to nghttp2 library. This may invoke
   nghttp2 callbacks. It may also queues the frame in nghttp2 session
   context. To send them, we call session_send() in the end. */
static void readcb(struct bufferevent *bev, void *ptr) {
  http2_session_data *session_data = (http2_session_data *)ptr;
  ssize_t readlen;
  struct evbuffer *input = bufferevent_get_input(bev);
  size_t datalen = evbuffer_get_length(input);
  unsigned char *data = evbuffer_pullup(input, -1);

  readlen = nghttp2_session_mem_recv(session_data->session, data, datalen);
  if (readlen < 0) {
    warnx("Fatal error: %s", nghttp2_strerror((int)readlen));
    delete_http2_session_data(session_data);
    return;
  }
  if (evbuffer_drain(input, (size_t)readlen) != 0) {
    warnx("Fatal error: evbuffer_drain failed");
    delete_http2_session_data(session_data);
    return;
  }
  if (session_send(session_data) != 0) {
    delete_http2_session_data(session_data);
    return;
  }
}

/* writecb for bufferevent. To greaceful shutdown after sending or
   receiving GOAWAY, we check the some conditions on the nghttp2
   library and output buffer of bufferevent. If it indicates we have
   no business to this session, tear down the connection. */
static void writecb(struct bufferevent *bev, void *ptr) {
  http2_session_data *session_data = (http2_session_data *)ptr;
  (void)bev;

  if (nghttp2_session_want_read(session_data->session) == 0 &&
      nghttp2_session_want_write(session_data->session) == 0 &&
      evbuffer_get_length(bufferevent_get_output(session_data->bev)) == 0) {
    delete_http2_session_data(session_data);
  }
}

/* eventcb for bufferevent. For the purpose of simplicity and
   readability of the example program, we omitted the certificate and
   peer verification. After SSL/TLS handshake is over, initialize
   nghttp2 library session, and send client connection header. Then
   send HTTP request. */
static void eventcb(struct bufferevent *bev, short events, void *ptr) {
  http2_session_data *session_data = (http2_session_data *)ptr;
  if (events & BEV_EVENT_CONNECTED) {
    int fd = bufferevent_getfd(bev);
    int val = 1;
    const unsigned char *alpn = NULL;
    unsigned int alpnlen = 0;
    SSL *ssl;

    fprintf(stderr, "Connected\n");

	if (!strcmp(session_data->scheme, "https")) {
		ssl = bufferevent_openssl_get_ssl(session_data->bev);

		SSL_get0_next_proto_negotiated(ssl, &alpn, &alpnlen);
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
		if (alpn == NULL) {
			SSL_get0_alpn_selected(ssl, &alpn, &alpnlen);
		}
#endif // OPENSSL_VERSION_NUMBER >= 0x10002000L

		if (alpn == NULL || alpnlen != 2 || memcmp("h2", alpn, 2) != 0) {
			fprintf(stderr, "h2 is not negotiated\n");
			delete_http2_session_data(session_data);
			return;
		}
	}

    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&val, sizeof(val));
    initialize_nghttp2_session(session_data);
    send_client_connection_header(session_data);
    submit_request(session_data);
    if (session_send(session_data) != 0) {
      delete_http2_session_data(session_data);
    }
    return;
  }
  if (events & BEV_EVENT_EOF) {
    warnx("Disconnected from the remote host");
  } else if (events & BEV_EVENT_ERROR) {
    warnx("Network error");
  } else if (events & BEV_EVENT_TIMEOUT) {
    warnx("Timeout");
  }
  delete_http2_session_data(session_data);
}

/* Start connecting to the remote peer |host:port| */
static void initiate_connection(struct event_base *evbase, SSL_CTX *ssl_ctx,
                                const char *host, uint16_t port,
                                http2_session_data *session_data) {
  int rv;
  struct bufferevent *bev;
  SSL *ssl = NULL;

  if (!strcmp(session_data->scheme, "https")) {
	  ssl = create_ssl(ssl_ctx);
	  bev = bufferevent_openssl_socket_new(
			  evbase, -1, ssl, BUFFEREVENT_SSL_CONNECTING,
			  BEV_OPT_DEFER_CALLBACKS | BEV_OPT_CLOSE_ON_FREE);
  } else {
	  bev = bufferevent_socket_new(
			  evbase, -1, 
			  BEV_OPT_DEFER_CALLBACKS | BEV_OPT_CLOSE_ON_FREE);
  }
  bufferevent_enable(bev, EV_READ | EV_WRITE);
  bufferevent_setcb(bev, readcb, writecb, eventcb, session_data);
  rv = bufferevent_socket_connect_hostname(bev, session_data->dnsbase,
                                           AF_UNSPEC, host, port);

  if (rv != 0) {
    errx(1, "Could not connect to the remote host %s", host);
  }
  session_data->bev = bev;
}

/* Get resource denoted by the |uri|. The debug and error messages are
   printed in stderr, while the response body is printed in stdout. */
static void run() {
  struct http_parser_url u;
  char *host;
  uint16_t port;
  int rv;
  SSL_CTX *ssl_ctx;
  struct event_base *evbase;
  http2_session_data *session_data;
  const char *uri = NULL;

  config_lookup_string(&MAIN_CFG, "restcli_cfg.uri", &uri);

  /* Parse the |uri| and stores its components in |u| */
  rv = http_parser_parse_url(uri, strlen(uri), 0, &u);
  if (rv != 0) {
    errx(1, "Could not parse URI %s", uri);
  }
  host = strndup(&uri[u.field_data[UF_HOST].off], u.field_data[UF_HOST].len);
  if (!(u.field_set & (1 << UF_PORT))) {
    port = 443;
  } else {
    port = u.port;
  }

  /* check scheme */
  char scheme[128] = {0,};
  snprintf(scheme, u.field_data[UF_SCHEMA].len + 1, "%s", (char *)&uri[u.field_data[UF_SCHEMA].off]);

  fprintf(stderr, "INIT| host(%s) port(%d) scheme(%s)\n", host, port, scheme);

  ssl_ctx = create_ssl_ctx();

  evbase = event_base_new();

  session_data = create_http2_session_data(evbase);
  session_data->stream_data = create_http2_stream_data(uri, &u);

  /* save scheme */
  strcpy(session_data->scheme, scheme);

  initiate_connection(evbase, ssl_ctx, host, port, session_data);
  free(host);
  host = NULL;

  event_base_loop(evbase, 0);

  event_base_free(evbase);
  SSL_CTX_free(ssl_ctx);
}

int init_cfg(config_t *CFG)
{
	char conf_path[1024] = {0,};
	sprintf(conf_path,"%s/data/restcli.cfg", getenv("IV_HOME"));
	if (!config_read_file(CFG, conf_path)) {
		fprintf(stderr, "config read fail! (%s|%d - %s)\n",
				config_error_file(CFG),
				config_error_line(CFG),
				config_error_text(CFG));
		return (-1);
	} else {
		fprintf(stderr, "INIT| config read from ./restcli.cfg success!\n");
	}

	return 0;
}

int main(int argc, char **argv) {
  struct sigaction act;

  init_cfg(&MAIN_CFG);

  memset(&act, 0, sizeof(struct sigaction));
  act.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &act, NULL);

  SSL_load_error_strings();
  SSL_library_init();

  run();

  return 0;
}
