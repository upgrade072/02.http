
#include <restsvr.h>

/* my proc name : restsvr1.cfg restsvr2.cfg */
extern char *__progname;

/* log */
int logLevel = APPLOG_DEBUG;
int *lOG_FLAG = &logLevel;

config_t MAIN_CFG; /* ~.cfg */
char CONF_PATH[1024] = {0,};
int *INT_FOR_EACH_API;

#define TOKEN_MAX_NUM 12
#define TOKEN_MAX_LEN 128

typedef struct key_value {
	char key[TOKEN_MAX_LEN];
	char value[TOKEN_MAX_LEN];
} key_value_t;

struct app_context;
typedef struct app_context app_context;

typedef struct http2_stream_data {
  struct http2_stream_data *prev, *next;
  char method[128];
  char *request_path;
  char *query;
  key_value_t token[TOKEN_MAX_NUM];
  nghttp2_nv *resp_hdrs;

  int from_file;
  const char *body_ptr;
  GSList *cnvt_list;

  char *trace_ptr;
  FILE *trace_file;
  size_t trace_size;

  int32_t stream_id;
  int fd;
} http2_stream_data;

typedef struct http2_session_data {
  struct http2_stream_data root;
  struct bufferevent *bev;
  app_context *app_ctx;
  nghttp2_session *session;
  char *client_addr;

  char scheme[128];
} http2_session_data;

struct app_context {
  SSL_CTX *ssl_ctx;
  struct event_base *evbase;
};

static unsigned char next_proto_list[256];
static size_t next_proto_list_len;

/* proto */
char *replace_value_body(const char *value, http2_stream_data *stream_data, key_value_t token[TOKEN_MAX_NUM]);
static void eventcb(struct bufferevent *bev, short events, void *ptr);
int watch_directory_init(struct event_base *evbase, const char *path_name);
int keepalivelib_init(char *processName);
void keepalivelib_increase();

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
    APPLOG(APPLOG_ERR, "Could not create SSL/TLS context: %s",
         ERR_error_string(ERR_get_error(), NULL));
  }
  SSL_CTX_set_options(ssl_ctx,
                      SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
                          SSL_OP_NO_COMPRESSION |
                          SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);

  ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if (!ecdh) {
    APPLOG(APPLOG_ERR, "EC_KEY_new_by_curv_name failed: %s",
         ERR_error_string(ERR_get_error(), NULL));
  }
  SSL_CTX_set_tmp_ecdh(ssl_ctx, ecdh);
  EC_KEY_free(ecdh);

  if (SSL_CTX_use_PrivateKey_file(ssl_ctx, key_file, SSL_FILETYPE_PEM) != 1) {
    APPLOG(APPLOG_ERR, "Could not read private key file %s", key_file);
  }
  if (SSL_CTX_use_certificate_chain_file(ssl_ctx, cert_file) != 1) {
    APPLOG(APPLOG_ERR, "Could not read certificate file %s", cert_file);
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
    APPLOG(APPLOG_ERR, "Could not create SSL/TLS session object: %s",
         ERR_error_string(ERR_get_error(), NULL));
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
  stream_data->fd = -1;
  
  stream_data->trace_size = 0;
  stream_data->trace_file = open_memstream(&stream_data->trace_ptr, &stream_data->trace_size);

  add_stream(session_data, stream_data);
  return stream_data;
}

void free_char_ptr(char *ptr) {
	free(ptr);
}

static void delete_http2_stream_data(http2_stream_data *stream_data) {
  if (stream_data->fd != -1) {
    close(stream_data->fd);
  }

  g_slist_free_full(stream_data->cnvt_list, (GDestroyNotify)free_char_ptr);

  fclose(stream_data->trace_file);
  free(stream_data->trace_ptr);

  free(stream_data->request_path);
  free(stream_data->query);
  free(stream_data->resp_hdrs);
  free(stream_data);
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

  if (app_ctx->ssl_ctx != NULL)
	  ssl = create_ssl(app_ctx->ssl_ctx);

  session_data = malloc(sizeof(http2_session_data));
  memset(session_data, 0, sizeof(http2_session_data));
  session_data->app_ctx = app_ctx;
  setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&val, sizeof(val));
#if 0
  session_data->bev = bufferevent_openssl_socket_new(
      app_ctx->evbase, fd, ssl, BUFFEREVENT_SSL_ACCEPTING,
      BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
#else
  if (app_ctx->ssl_ctx != NULL) {
	  APPLOG(APPLOG_ERR, "CON| ssl connected!");
	  sprintf(session_data->scheme, "%s", "https");
	  session_data->bev = bufferevent_openssl_socket_new(
			  app_ctx->evbase, fd, ssl, BUFFEREVENT_SSL_ACCEPTING,
			  BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
  } else {
	  APPLOG(APPLOG_ERR, "CON| tcp connected!");
	  sprintf(session_data->scheme, "%s", "http");
	  session_data->bev = bufferevent_socket_new(
			  app_ctx->evbase, fd, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
  }
#endif
  bufferevent_enable(session_data->bev, EV_READ | EV_WRITE);
  rv = getnameinfo(addr, (socklen_t)addrlen, host, sizeof(host), NULL, 0,
                   NI_NUMERICHOST);
  if (rv != 0) {
    session_data->client_addr = strdup("(unknown)");
  } else {
    session_data->client_addr = strdup(host);
  }

  if (app_ctx->ssl_ctx == NULL) {
	  eventcb(session_data->bev, BEV_EVENT_CONNECTED, session_data);
  }

  return session_data;
}

static void delete_http2_session_data(http2_session_data *session_data) {
  http2_stream_data *stream_data;

  APPLOG(APPLOG_ERR, "%s disconnected", session_data->client_addr);

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
  free(session_data);
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

/* Read the data in the bufferevent and feed them into nghttp2 library
   function. Invocation of nghttp2_session_mem_recv() may make
   additional pending frames, so call session_send() at the end of the
   function. */
static int session_recv(http2_session_data *session_data) {
  ssize_t readlen;
  struct evbuffer *input = bufferevent_get_input(session_data->bev);
  size_t datalen = evbuffer_get_length(input);
  unsigned char *data = evbuffer_pullup(input, -1);

  readlen = nghttp2_session_mem_recv(session_data->session, data, datalen);
  if (readlen < 0) {
    warnx("Fatal error: %s", nghttp2_strerror((int)readlen));
    return -1;
  }
  if (evbuffer_drain(input, (size_t)readlen) != 0) {
    warnx("Fatal error: evbuffer_drain failed");
    return -1;
  }
  if (session_send(session_data) != 0) {
    return -1;
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

#if 0
/* Returns nonzero if the string |s| ends with the substring |sub| */
static int ends_with(const char *s, const char *sub) {
  size_t slen = strlen(s);
  size_t sublen = strlen(sub);
  if (slen < sublen) {
    return 0;
  }
  return memcmp(s + slen - sublen, sub, sublen) == 0;
}
#endif

/* Returns int value of hex string character |c| */
static uint8_t hex_to_uint(uint8_t c) {
  if ('0' <= c && c <= '9') {
    return (uint8_t)(c - '0');
  }
  if ('A' <= c && c <= 'F') {
    return (uint8_t)(c - 'A' + 10);
  }
  if ('a' <= c && c <= 'f') {
    return (uint8_t)(c - 'a' + 10);
  }
  return 0;
}

/* Decodes percent-encoded byte string |value| with length |valuelen|
   and returns the decoded byte string in allocated buffer. The return
   value is NULL terminated. The caller must free the returned
   string. */
static char *percent_decode(const uint8_t *value, size_t valuelen) {
  char *res;

  res = malloc(valuelen + 1);
  if (valuelen > 3) {
    size_t i, j;
    for (i = 0, j = 0; i < valuelen - 2;) {
      if (value[i] != '%' || !isxdigit(value[i + 1]) ||
          !isxdigit(value[i + 2])) {
        res[j++] = (char)value[i++];
        continue;
      }
      res[j++] =
          (char)((hex_to_uint(value[i + 1]) << 4) + hex_to_uint(value[i + 2]));
      i += 3;
    }
    memcpy(&res[j], &value[i], 2);
    res[j + 2] = '\0';
  } else {
    memcpy(res, value, valuelen);
    res[valuelen] = '\0';
  }
  return res;
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
		char temp_buff[1024 * 1024] = {0,};
		while ((r = read(stream_data->fd, temp_buff, length)) == -1 && errno == EINTR)
			;
		if (r == -1) {
			APPLOG(APPLOG_ERR, "error r is (-1)");
			return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
		}
		char *check_replace = replace_value_body((const char *)temp_buff, stream_data, stream_data->token);

		if (check_replace == NULL) {
			len = r;
			memcpy(buf, temp_buff, len);
		} else {
			len = strlen(check_replace);
			memcpy(buf, check_replace, len);
		}
		*data_flags |= NGHTTP2_DATA_FLAG_EOF;

#if 0
		fwrite(buf, len, 1, stderr);
#else
		buf[len] = '\0';
		APPLOG(APPLOG_DEBUG, "\n%s", buf);
#endif
		return len;
	} else {
		if (stream_data->body_ptr != NULL) {
			char *check_replace = replace_value_body((const char *)stream_data->body_ptr, stream_data, stream_data->token);
			if (check_replace == NULL) {
				len = strlen(stream_data->body_ptr);
				memcpy(buf, stream_data->body_ptr, len);
			} else {
				len = strlen(check_replace);
				memcpy(buf, check_replace, len);
			}
		}
		*data_flags |= NGHTTP2_DATA_FLAG_EOF;

#if 0
		fwrite(buf, len, 1, stderr);
#else
		buf[len] = '\0';
		APPLOG(APPLOG_DEBUG, "%s\n", buf);
#endif
		return len;
	}
}

static int send_response(nghttp2_session *session, int32_t stream_id,
                         nghttp2_nv *nva, size_t nvlen, http2_stream_data *stream_data) {
  int rv;
  nghttp2_data_provider data_prd;

  if (stream_data->from_file == 0) {
	  APPLOG(APPLOG_DEBUG, "response from ptr");
  } else {
	  APPLOG(APPLOG_DEBUG, "response from file");
  }
  data_prd.source.ptr = stream_data;
  data_prd.read_callback = ptr_read_callback;

  rv = nghttp2_submit_response(session, stream_id, nva, nvlen, &data_prd);
  if (rv != 0) {
    warnx("Fatal error: %s", nghttp2_strerror(rv));
    return -1;
  }
  return 0;
}

static const char ERROR_HTML[] = "{ \"problemDetail\" : \"can't find rest api\" }";

static int error_reply(nghttp2_session *session,
                       http2_stream_data *stream_data) {
  int rv;
  ssize_t writelen;
  int pipefd[2];
  nghttp2_nv hdrs[] = {MAKE_NV(":status", "404")};

  rv = pipe(pipefd);
  if (rv != 0) {
    warn("Could not create pipe");
    rv = nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                   stream_data->stream_id,
                                   NGHTTP2_INTERNAL_ERROR);
    if (rv != 0) {
      warnx("Fatal error: %s", nghttp2_strerror(rv));
      return -1;
    }
    return 0;
  }

  writelen = write(pipefd[1], ERROR_HTML, sizeof(ERROR_HTML) - 1);
  close(pipefd[1]);

  if (writelen != sizeof(ERROR_HTML) - 1) {
    close(pipefd[0]);
    return -1;
  }

  stream_data->fd = pipefd[0];

  stream_data->from_file = 1;
  if (send_response(session, stream_data->stream_id, hdrs, ARRLEN(hdrs), stream_data) != 0) {
    close(pipefd[0]);
    return -1;
  }
  return 0;
}

/* nghttp2_on_header_callback: Called when nghttp2 library emits
   single header name/value pair. */
static int on_header_callback(nghttp2_session *session,
                              const nghttp2_frame *frame, const uint8_t *name,
                              size_t namelen, const uint8_t *value,
                              size_t valuelen, uint8_t flags, void *user_data) {
  http2_stream_data *stream_data;
  const char PATH[] = ":path";
  const char METHOD[] = ":method";
  (void)flags;
  (void)user_data;

  switch (frame->hd.type) {
  case NGHTTP2_HEADERS:
    if (frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
      break;
    }
    stream_data =
        nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);

    if (!stream_data || stream_data->request_path) {
      break;
    }

	/* save header for trace */
	fprintf(stream_data->trace_file, "%s %s\n", name, value);

    if (namelen == sizeof(PATH) - 1 && memcmp(PATH, name, namelen) == 0) {
      size_t j;
      for (j = 0; j < valuelen && value[j] != '?'; ++j)
        ;
      stream_data->request_path = percent_decode(value, j);
	  /* schlee, if query exist */
	  if (j < valuelen) {
		  stream_data->query = percent_decode(value + j + 1, valuelen - j - 1);
	  }
    } else if (namelen == sizeof(METHOD) - 1 && memcmp(METHOD, name, namelen) == 0) {
		sprintf(stream_data->method, "%s", value);
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

  if (frame->hd.type != NGHTTP2_HEADERS ||
      frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
    return 0;
  }
  stream_data = create_http2_stream_data(session_data, frame->hd.stream_id);
  nghttp2_session_set_stream_user_data(session, frame->hd.stream_id,
                                       stream_data);
  return 0;
}

#if 0
/* Minimum check for directory traversal. Returns nonzero if it is
   safe. */
static int check_path(const char *path) {
  /* We don't like '\' in url. */
  return path[0] && path[0] == '/' && strchr(path, '\\') == NULL &&
         strstr(path, "/../") == NULL && strstr(path, "/./") == NULL &&
         !ends_with(path, "/..") && !ends_with(path, "/.");
}
#endif

int save_into_array(const char *api, char array[][TOKEN_MAX_LEN], int array_num)
{   
    char *copy_api = strdup(api);
    char *ptr = strtok(copy_api, "/");
    int token_num = 0; 
    while(ptr != NULL) {
        sprintf(array[token_num], "%s", ptr);
        token_num ++;
        ptr = strtok(NULL, "/");
        if (token_num >= array_num) {
            APPLOG(APPLOG_ERR, "%s() exceed max token_num[%d]", __func__, array_num);
            goto stop_and_return;
        }
    }

stop_and_return:
    free(copy_api); 
	/*
    fprintf(stderr, "token num is [%d]\n", token_num);
    for (int i = 0; i < token_num; i++) {
        fprintf(stderr, "%s ", array[i]);
    }
    fprintf(stderr, "\n");
	*/
    return token_num;
}

int comp_and_save(char input[][TOKEN_MAX_LEN], char comp[][TOKEN_MAX_LEN], key_value_t token[TOKEN_MAX_NUM], int array_num)
{   
    for (int i = 0, cnt = 0; i < array_num; i++) {
#if 0
        if (comp[i][0] == '$') {
            sprintf(token[cnt].key, "%s", comp[i]);
            sprintf(token[cnt].value, "%s", input[i]);
            cnt++;
#else
        char *ptr = strchr(comp[i], '$');
        if (ptr != NULL && !strncmp(input[i], comp[i], ptr - comp[i])) {
            sprintf(token[cnt].key, "%s", ptr);
            sprintf(token[cnt].value, "%s", input[i]);
            cnt++;
#endif
        } else if (strcmp(input[i], comp[i])) {
            return -1;
        }
    }
    return 0;
}

int find_from_cfg(config_setting_t *setting, http2_stream_data *stream_data, key_value_t token[TOKEN_MAX_NUM])
{
	char src_array[TOKEN_MAX_NUM][TOKEN_MAX_LEN] = {0,};
	char dst_array[TOKEN_MAX_NUM][TOKEN_MAX_LEN] = {0,};

	const char *cfg_method = NULL;
	if (config_setting_lookup_string(setting, "method", &cfg_method) <= 0)
		return -1;

	const char *api_path = NULL;
	if (config_setting_lookup_string(setting, "api_path", &api_path) <= 0)
		return -1;

	if (strcmp(cfg_method, stream_data->method))
		return -1;

	/* if query_param cfg exist, more matching */
	const char *query_param = NULL;
	if (config_setting_lookup_string(setting, "query_param", &query_param) > 0) {
		if (stream_data->query == NULL)
			return -1;
		if (strcmp(query_param, stream_data->query))
			return -1;
	}

	int src_num = save_into_array(stream_data->request_path, src_array, TOKEN_MAX_NUM);
	int dst_num = save_into_array(api_path, dst_array, TOKEN_MAX_NUM);

	if (src_num != dst_num) {
		return -1;
	} else if (comp_and_save(src_array, dst_array, token, src_num) < 0) {
		return -1;
	}

	const char *api_action = NULL;
	if (config_setting_lookup_string(setting, "response_action", &api_action) &&
			!strcmp(api_action, "noans"))
		return -2; // silence discard

	APPLOG(APPLOG_DEBUG, "matched with [%s] token is ...", setting->name);
	for (int i = 0; i < TOKEN_MAX_NUM; i++) {
		if (strlen(token[i].key) != 0) {
			APPLOG(APPLOG_DEBUG, "%s:%s", token[i].key, token[i].value);
		}
	}
	APPLOG(APPLOG_DEBUG, "------------------------------");
	return 0;
}

char *replace_all(const char *sentence, const char *olds, const char *news) {
    char *result, *ptr;
    size_t i, count = 0;
    size_t oldlen = strlen(olds); if (oldlen < 1) return NULL;
    size_t newlen = strlen(news);


    if (newlen != oldlen) {
        for (i = 0; sentence[i] != '\0';) {
            if (memcmp(&sentence[i], olds, oldlen) == 0) count++, i += oldlen;
            else i++;
        }
    } else i = strlen(sentence);

    if (count == 0)
        return NULL;

    result = (char *) malloc(i + 1 + count * (newlen - oldlen));
    if (result == NULL) return NULL;

    ptr = result;
    while (*sentence) {
        if (memcmp(sentence, olds, oldlen) == 0) {
            memcpy(ptr, news, newlen);
            ptr += newlen;
            sentence  += oldlen;
        } else *ptr++ = *sentence++;
    }
    *ptr = '\0';

    return result;
}

char *replace_value_header(const char *value, http2_stream_data *stream_data, key_value_t token[TOKEN_MAX_NUM])
{
	for (int i = 0; i < TOKEN_MAX_NUM; i++) {
		if (strstr(value, token[i].key)) {
			char *replace = NULL;
			if ((replace = replace_all(value, token[i].key, token[i].value)) != NULL) {
				//fprintf(stderr, "{{{dbg}}} malloc (%x)\n", replace);
#if 0
				GSList *res = g_slist_append(stream_data->cnvt_list, replace);
				if (res != NULL) {
					//fprintf(stderr, "dbg}}} list appended! replace [%s]\n", replace);
				}
#else
				stream_data->cnvt_list = g_slist_append(stream_data->cnvt_list, replace);
#endif
				return replace;
			}
		}
	}

	return NULL;
}
char *replace_value_body(const char *value, http2_stream_data *stream_data, key_value_t token[TOKEN_MAX_NUM])
{
	const char *body = value;
	char *last_replace = NULL;
	for (int i = 0; i < TOKEN_MAX_NUM; i++) {
		if (strstr(body, token[i].key)) {
			char *replace = NULL;
			if ((replace = replace_all(body, token[i].key, token[i].value)) != NULL) {
				//fprintf(stderr, "{{{dbg}}} malloc (%x)\n", replace);
#if 0
				GSList *res = g_slist_append(stream_data->cnvt_list, replace);
				if (res != NULL) {
					//fprintf(stderr, "dbg}}} list appended! replace(%d) [%s]\n", i, replace);
				}
#else
				stream_data->cnvt_list = g_slist_append(stream_data->cnvt_list, replace);
#endif
				last_replace = replace;
				body = replace;
			}
		}
	}
	return last_replace;
}

const char *config_get_body_by_order(config_setting_t *setting, config_setting_t *cf_body_ref)
{
	int my_index = config_setting_index(setting);
	int array_num = config_setting_length(cf_body_ref);
	int curr_pos = INT_FOR_EACH_API[my_index];
	INT_FOR_EACH_API[my_index] = (curr_pos + 1) % array_num;
	return config_setting_get_string_elem(cf_body_ref, curr_pos);
}

int resp_from_cfg(config_setting_t *setting,
						nghttp2_session *session,
						http2_session_data *session_data,
						http2_stream_data *stream_data,
						key_value_t token[TOKEN_MAX_NUM]) {
	config_setting_t *cf_hdrs = config_setting_get_member(setting, "response_hdrs");
	if (cf_hdrs == NULL) {
		APPLOG(APPLOG_ERR, "can't find member [response_hdrs] from [%s]", setting->name);
	}
	int hdrs_num = config_setting_length(cf_hdrs);
	APPLOG(APPLOG_DEBUG, "headers num [%d]", hdrs_num);

	stream_data->resp_hdrs = calloc(sizeof(nghttp2_nv), hdrs_num);

	for (int i = 0; i < hdrs_num; i++) {
		config_setting_t *cf_header = config_setting_get_elem(cf_hdrs, i);
		const char *name = NULL;
		config_setting_lookup_string(cf_header, "name", &name);

		const char *value = NULL;
		char *check_replace = NULL;
		config_setting_lookup_string(cf_header, "value", &value);
		check_replace = replace_value_header(value, stream_data, token);

		nghttp2_nv temp_hdr[] = {MAKE_NV_STR(name, check_replace == NULL ? value : check_replace)};
		memcpy(&stream_data->resp_hdrs[i], temp_hdr, sizeof(nghttp2_nv));
		APPLOG(APPLOG_DEBUG, "header] %s %s", name, check_replace == NULL ? value : check_replace);
	}

	const char *body_path = NULL;

	config_setting_t *cf_bodys = config_setting_get_member(setting, "response_bodys");
	if (cf_hdrs == NULL) {
		APPLOG(APPLOG_ERR, "can't find member [response_bodys] from [%s]", setting->name);
	}
	config_setting_lookup_bool(cf_bodys, "from_file", &stream_data->from_file);
	if (stream_data->from_file) {
		config_setting_t *cf_body_ref = config_setting_get_member(cf_bodys, "body_ref");
#if 0
		if (config_setting_type(cf_body_ref) == CONFIG_TYPE_ARRAY) {
			body_path = config_get_body_by_order(setting, cf_body_ref);
#else
		if (config_setting_type(cf_body_ref) == CONFIG_TYPE_ARRAY) {
			int select_mod = 0;
			if (config_setting_lookup_bool(cf_bodys, "rr_with_mod", &select_mod) && (select_mod > 0)) {
				int last_digit = stream_data->request_path[strlen(stream_data->request_path) - 1];
				int select_pos = last_digit % config_setting_length(cf_body_ref);
				APPLOG(APPLOG_DEBUG, "{{{DBG}}} %s api=(%s) <rr_with_mod> last_digit=(%d) \"%c\" pos=(%d)", __func__, stream_data->request_path, last_digit, last_digit, select_pos);
				body_path = config_setting_get_string_elem(cf_body_ref, select_pos);
			} else {
				body_path = config_get_body_by_order(setting, cf_body_ref);
			}
#endif
		} else {
			config_setting_lookup_string(cf_bodys, "body_ref", &body_path);
		}

		stream_data->fd = open(body_path, O_RDONLY);
		if (stream_data->fd == -1) {
			if (error_reply(session, stream_data) != 0) {
				return NGHTTP2_ERR_CALLBACK_FAILURE;
			}
		}
	} else {
		config_setting_t *cf_body_ref = config_setting_get_member(cf_bodys, "body_ref");
		if (config_setting_type(cf_body_ref) == CONFIG_TYPE_ARRAY) {
			stream_data->body_ptr = config_get_body_by_order(setting, cf_body_ref);
		} else {
			config_setting_lookup_string(cf_bodys, "body_ref", &stream_data->body_ptr);
		}
	}

	if (send_response(session, stream_data->stream_id, &stream_data->resp_hdrs[0], hdrs_num, 
			stream_data) != 0) {
		return NGHTTP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

int resp_action_noans(http2_session_data *session_data,
                           http2_stream_data *stream_data) {
	APPLOG(APPLOG_ERR, "* response_action is \"noans\", will silent discard");
	return nghttp2_session_close_stream(session_data->session, stream_data->stream_id, NGHTTP2_INTERNAL_ERROR);
}

int find_and_response(nghttp2_session *session,
                           http2_session_data *session_data,
                           http2_stream_data *stream_data) {

	config_setting_t *setting = config_lookup(&MAIN_CFG, "api_list");
	int num = config_setting_length(setting);
	for (int i = 0; i < num; i++) {
		config_setting_t *elem = config_setting_get_elem(setting, i);

		int res_action = find_from_cfg(elem, stream_data, stream_data->token);

		if (res_action == -2) {
			// response_action "noans"
			return resp_action_noans(session_data, stream_data);
		} else if (res_action >= 0) {
			// we find
			return resp_from_cfg(elem, session, session_data, stream_data, stream_data->token);
		}
		// keep find
	}

	/* schlee, can't find */
	APPLOG(APPLOG_ERR, "* can't find resp api [%s:%s(%s)]", stream_data->method, stream_data->request_path, stream_data->query);
    if (error_reply(session, stream_data) != 0) {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
}

static int on_request_recv(nghttp2_session *session,
                           http2_session_data *session_data,
                           http2_stream_data *stream_data) {
  APPLOG(APPLOG_DEBUG, "* request receive) mathod[%s] path[%s] query[%s]",
		  stream_data->method,
		  stream_data->request_path,
		  stream_data->query);

  fflush(stream_data->trace_file);
  APPLOG(APPLOG_DEBUG, "* received pkt (size:%ld)", stream_data->trace_size);
#if 0
  fwrite(stream_data->trace_ptr, stream_data->trace_size, 1, stderr);
#else
  APPLOG(APPLOG_DEBUG, "\n%s", stream_data->trace_ptr);
#endif
  APPLOG(APPLOG_DEBUG, "\n");

  if (!stream_data->request_path) {
    if (error_reply(session, stream_data) != 0) {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
  }
  return find_and_response(session, session_data, stream_data);
}

static int on_frame_recv_callback(nghttp2_session *session,
                                  const nghttp2_frame *frame, void *user_data) {
  http2_session_data *session_data = (http2_session_data *)user_data;
  http2_stream_data *stream_data;
  switch (frame->hd.type) {
  case NGHTTP2_DATA:
  case NGHTTP2_HEADERS:
    /* Check that the client request has finished */
    if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
      stream_data =
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
    (void)session;
    (void)flags;
    http2_stream_data *stream_data = NULL;

    /* no data, do nothing */
    if (len == 0) return 0;
    
    /* re-assemble */
    if ((stream_data = nghttp2_session_get_stream_user_data(session, stream_id)) != NULL) {
		fwrite(data, len, 1, stream_data->trace_file);
    }
    return 0;
}

static int on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
                                    uint32_t error_code, void *user_data) {
  http2_session_data *session_data = (http2_session_data *)user_data;
  http2_stream_data *stream_data;
  (void)error_code;

  stream_data = nghttp2_session_get_stream_user_data(session, stream_id);
  if (!stream_data) {
    return 0;
  }
  remove_stream(session_data, stream_data);
  delete_http2_stream_data(stream_data);
  return 0;
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

  nghttp2_session_server_new(&session_data->session, callbacks, session_data);

  nghttp2_session_callbacks_del(callbacks);
}

/* Send HTTP/2 client connection header, which includes 24 bytes
   magic octets and SETTINGS frame */
static int send_server_connection_header(http2_session_data *session_data) {
#if 0
  nghttp2_settings_entry iv[1] = {
      {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}};
#else
    nghttp2_settings_entry iv[5] = {
        {NGHTTP2_SETTINGS_HEADER_TABLE_SIZE, 65535},
        {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 65535},
        {NGHTTP2_SETTINGS_MAX_FRAME_SIZE, 65535},
        {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 65535},
        {NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE, 65535}};
#endif
  int rv;

  rv = nghttp2_submit_settings(session_data->session, NGHTTP2_FLAG_NONE, iv,
                               ARRLEN(iv));
  if (rv != 0) {
    warnx("Fatal error: %s", nghttp2_strerror(rv));
    return -1;
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
#if 0 // schlee, hold connection
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
    SSL *ssl;
    (void)bev;

    APPLOG(APPLOG_ERR, "%s connected", session_data->client_addr);

	if (!strcmp(session_data->scheme, "https")) {
		ssl = bufferevent_openssl_get_ssl(session_data->bev);

		SSL_get0_next_proto_negotiated(ssl, &alpn, &alpnlen);
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
		if (alpn == NULL) {
			SSL_get0_alpn_selected(ssl, &alpn, &alpnlen);
		}
#endif // OPENSSL_VERSION_NUMBER >= 0x10002000L
		if (alpn == NULL || alpnlen != 2 || memcmp("h2", alpn, 2) != 0) {
			APPLOG(APPLOG_ERR, "%s h2 is not negotiated", session_data->client_addr);
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

    return;
  }
  if (events & BEV_EVENT_EOF) {
    APPLOG(APPLOG_ERR, "%s EOF", session_data->client_addr);
  } else if (events & BEV_EVENT_ERROR) {
    APPLOG(APPLOG_ERR, "%s network error", session_data->client_addr);
  } else if (events & BEV_EVENT_TIMEOUT) {
    APPLOG(APPLOG_ERR, "%s timeout", session_data->client_addr);
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

  bufferevent_setcb(session_data->bev, readcb, writecb, eventcb, session_data);
}

static void start_listen(struct event_base *evbase, const char *service,
                         app_context *app_ctx) {
  int rv;
  struct addrinfo hints;
  struct addrinfo *res, *rp;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
#ifdef AI_ADDRCONFIG
  hints.ai_flags |= AI_ADDRCONFIG;
#endif /* AI_ADDRCONFIG */

  rv = getaddrinfo(NULL, service, &hints, &res);
  if (rv != 0) {
    errx(1, "Could not resolve server address");
  }
  for (rp = res; rp; rp = rp->ai_next) {
    struct evconnlistener *listener;
    listener = evconnlistener_new_bind(
        evbase, acceptcb, app_ctx, LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE,
        16, rp->ai_addr, (int)rp->ai_addrlen);
    if (listener) {
      freeaddrinfo(res);

      return;
    }
  }
  errx(1, "Could not start listener");
}

static void initialize_app_context(app_context *app_ctx, SSL_CTX *ssl_ctx,
                                   struct event_base *evbase) {
  memset(app_ctx, 0, sizeof(app_context));
  app_ctx->ssl_ctx = ssl_ctx;
  app_ctx->evbase = evbase;
}

void main_tick_callback(evutil_socket_t fd, short what, void *arg)
{
    keepalivelib_increase();
}

// service = port_string
static void run()
{
  SSL_CTX *ssl_ctx;
  app_context app_ctx_for_https = {0,};
  app_context app_ctx_for_http = {0,};
  struct event_base *evbase;

  const char *https_port = NULL;
  const char *http_port = NULL;
  const char *cert_file = NULL;
  const char *key_file = NULL;

  config_lookup_string(&MAIN_CFG, "restsvr_cfg.https_port", &https_port);
  config_lookup_string(&MAIN_CFG, "restsvr_cfg.http_port", &http_port);
  config_lookup_string(&MAIN_CFG, "restsvr_cfg.cert_file", &cert_file);
  config_lookup_string(&MAIN_CFG, "restsvr_cfg.key_file", &key_file);

  APPLOG(APPLOG_ERR, "INIT| https port[%s] http port[%s] cert_file[%s] key_file[%s]", 
		  https_port, http_port, cert_file, key_file);

  ssl_ctx = create_ssl_ctx(key_file, cert_file);
  evbase = event_base_new();

  // tick
  struct timeval tic_sec = {1,0};
  struct event *ev_tick = event_new(evbase, -1, EV_PERSIST, main_tick_callback, NULL);
  event_add(ev_tick, &tic_sec);

  // check config file changed
  char watch_directory[1024] = {0,};
  sprintf(watch_directory, "%s/data", getenv("IV_HOME"));
  watch_directory_init(evbase, watch_directory);

  // for https
  initialize_app_context(&app_ctx_for_https, ssl_ctx, evbase);
  start_listen(evbase, https_port, &app_ctx_for_https);

  // for http
  initialize_app_context(&app_ctx_for_http, NULL, evbase);
  start_listen(evbase, http_port, &app_ctx_for_http);

  event_base_loop(evbase, 0);

  event_base_free(evbase);
  SSL_CTX_free(ssl_ctx);
}

int init_cfg(config_t *CFG) 
{   
#if 0
    sprintf(CONF_PATH,"%s/data/restsvr.cfg", getenv("IV_HOME"));
#else
    sprintf(CONF_PATH,"%s/data/%s.cfg", getenv("IV_HOME"), __progname);
#endif
    if (!config_read_file(CFG, CONF_PATH)) {
        APPLOG(APPLOG_ERR, "config read fail! (%s|%d - %s)",
                config_error_file(CFG),
                config_error_line(CFG),
                config_error_text(CFG));
        return (-1);
    } else {
        APPLOG(APPLOG_ERR, "INIT| config read from ./restsvr.cfg success!");
    }

	config_setting_t *setting = config_lookup(CFG, "api_list");
	int api_num = config_setting_length(setting);
	APPLOG(APPLOG_ERR, "INIT| API num is [%d]", api_num);
	INT_FOR_EACH_API = malloc(sizeof(int) * api_num);
	memset(INT_FOR_EACH_API, 0x00, sizeof(int) * api_num);

	/* loglevel */
	config_setting_t *set_log = config_lookup(CFG, "restsvr_cfg.log_level");
	int log_level = config_setting_get_int(set_log);
	APPLOG(APPLOG_ERR, "INIT| log level adjust [%d]", log_level);
	*lOG_FLAG = log_level;
	// save with indent
#if 0
	config_set_tab_width(CFG, 4);
	config_write_file(CFG, CONF_PATH);
#endif
    
    return 0;
}   

void directory_watch_action(const char *file_name)
{
#if 0
	if (!strcmp(file_name, "restsvr.cfg")) {
		APPLOG(APPLOG_ERR, "CONF| main config changed, will reload it!");

		/* destroy */
		config_destroy(&MAIN_CFG);
		free(INT_FOR_EACH_API);

		/* reload */
		init_cfg(&MAIN_CFG);
		APPLOG(APPLOG_ERR, "--> done");
	}
#endif
}

void initialize()
{
    char myProcName[1024] = {0,};
    sprintf(myProcName, __progname);
    strupr(myProcName, strlen(myProcName));

	keepalivelib_init(myProcName);

#ifdef LOG_APP
    char log_path[1024] = {0,};
    sprintf(log_path, "%s/log", getenv(IV_HOME));
    LogInit(myProcName, log_path);
#endif
}

int main(int argc, char **argv) {
	struct sigaction act;

	initialize();
	init_cfg(&MAIN_CFG);

	memset(&act, 0, sizeof(struct sigaction));
	act.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &act, NULL);

	SSL_load_error_strings();
	SSL_library_init();

	run();

	return 0;
}
