#include "client.h"

// TODO : bundle in sys_conf. struct, someday
char mySysName[COMM_MAX_NAME_LEN];
char myProcName[COMM_MAX_NAME_LEN];

//#ifdef LOG_APP
int logLevel = APPLOG_DEBUG;
int *lOG_FLAG = &logLevel;
//#endif

int httpcQid, ixpcQid, nrfmQid;

int THREAD_NO[MAX_THRD_NUM] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
int SESSION_ID;
int SESS_IDX;

shm_http_t *SHM_HTTPC_PTR;
client_conf_t CLIENT_CONF;
thrd_context_t THRD_WORKER[MAX_THRD_NUM];
http2_session_data_t SESS[MAX_THRD_NUM][MAX_SVR_NUM];
pthread_mutex_t ONLY_CRT_SESS_LOCK = PTHREAD_MUTEX_INITIALIZER; // TODO!!! we want remove this 
pthread_mutex_t GET_INIT_CTX_LOCK = PTHREAD_MUTEX_INITIALIZER;	// schlee, LB thread VS MAIN(command)

httpc_ctx_t *HttpcCtx[MAX_THRD_NUM];

conn_list_t CONN_LIST[MAX_SVR_NUM];
conn_list_status_t CONN_STATUS[MAX_CON_NUM];
http_stat_t HTTP_STAT;

hdr_index_t VHDR_INDEX[2][MAX_HDR_RELAY_CNT];

// for lb ctx stat print
extern lb_ctx_t LB_CTX;
extern lb_global_t LB_CONF;

static http2_session_data_t * create_http2_session_data() 
{
	http2_session_data_t *session_data = NULL;
	int index, i, found = 0, sess_idx = 0;

	/* schlee, session index always forward, prevent conflict */
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
		return NULL; 
	}
	session_data = &SESS[index][sess_idx];
	memset(session_data, 0, sizeof(http2_session_data_t));
	session_data->session_index = sess_idx;
	session_data->session_id = ++SESSION_ID;
	SESSION_ID = SESSION_ID % 65535 + 1;
	session_data->used = 1;
	session_data->thrd_index = index;

	return session_data;
}

/* caution!!! this func must called by worker */
void delete_http2_session_data(http2_session_data_t *session_data) 
{
	pthread_mutex_lock(&ONLY_CRT_SESS_LOCK);

	session_data->connected = 0;

	/* stat HTTP_DISCONN */
	http_stat_inc(session_data->thrd_index, session_data->list_index, HTTP_DISCONN);

	if (!strcmp(session_data->scheme, "https")) {
		SSL *ssl = bufferevent_openssl_get_ssl(session_data->bev);
		if (ssl) {
			SSL_shutdown(ssl);
		}
	}
	THRD_WORKER[session_data->thrd_index].server_num--;

	bufferevent_free(session_data->bev);
	session_data->bev = NULL;

	if (CONN_LIST[session_data->conn_index].reconn_candidate) {
#if 0
		nghttp2_session_terminate_session(session_data->session, NGHTTP2_NO_ERROR);
#else
		// we immediately free session data, so can't do gracefully shutdown
		nghttp2_session_del(session_data->session);
#endif
	} else {
		nghttp2_session_del(session_data->session);
	}
	session_data->session = NULL;

	// caution! don't memset() we reuse .act and more field
	CONN_LIST[session_data->conn_index].thrd_index = 0;
	CONN_LIST[session_data->conn_index].session_index = 0;
	CONN_LIST[session_data->conn_index].session_id = 0;
	/* save last conn => disconn time */
	if (CONN_LIST[session_data->conn_index].conn == CN_CONNECTED)
		CONN_LIST[session_data->conn_index].tombstone_date = time(NULL);
	CONN_LIST[session_data->conn_index].conn = CN_NOT_CONNECTED;
	CONN_LIST[session_data->conn_index].reconn_candidate = 0;

	session_data->session_index = 0;
	session_data->session_id = 0;
	session_data->used = 0;

	pthread_mutex_unlock(&ONLY_CRT_SESS_LOCK);
}

/* nghttp2_send_callback. Here we transmit the |data|, |length| bytes,
   to the network. Because we are using libevent bufferevent, we just
   write those bytes into bufferevent buffer. */
static ssize_t send_callback(nghttp2_session *session, const uint8_t *data,
		size_t length, int flags, void *user_data) {
	http2_session_data_t *session_data = (http2_session_data_t *)user_data;
	struct bufferevent *bev = session_data->bev;
	(void)session;
	(void)flags;

	/* if already deleted */
	if (bev == NULL)
		return 0;

	bufferevent_write(bev, data, length);
	return (ssize_t)length;
}

/* nghttp2_on_header_callback: Called when nghttp2 library emits
   single header name/value pair. */
static int on_header_callback(nghttp2_session *session,
		const nghttp2_frame *frame, const uint8_t *name,
		size_t namelen, const uint8_t *value,
		size_t valuelen, uint8_t flags, void *user_data) {
	http2_session_data_t *session_data = (http2_session_data_t *)user_data;
	(void)session;
	(void)flags;
	http2_stream_data *stream_data = NULL;
	int stream_id, thrd_idx, idx;
	httpc_ctx_t *httpc_ctx;

	char *header_name = (char *)name;
	char *header_value = (char *)value;

	switch (frame->hd.type) {
		case NGHTTP2_HEADERS:
			if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
				/* Print response headers for the initiated request. */
			}
			stream_id = frame->hd.stream_id;
			stream_data = nghttp2_session_get_stream_user_data(session, stream_id);
			if (!stream_data)
				break;

			thrd_idx = session_data->thrd_index;
			idx = stream_data->ctx_id;

			if ((httpc_ctx = get_context(thrd_idx, idx, 1)) == NULL) {
				APPLOG(APPLOG_ERR, "%s() get_context fail!", __func__);
				break;
			}

			log_pkt_head_recv(httpc_ctx, name, namelen, value, valuelen);

			if (!strcmp(header_name, HDR_STATUS)) {
				httpc_ctx->user_ctx.head.respCode = atoi(header_value);
#ifdef OVLD_API
				/* for nssf overload control */
				if (httpc_ctx->user_ctx.head.respCode > 299) {
					//api_ovld_add_fail(thrd_idx, API_PROTO_HTTPC, 0, httpc_ctx->user_ctx.head.respCode);
					api_ovld_add_fail(thrd_idx, API_PROTO_HTTPC, 0);
				}
#endif
			} else {
				/* vHeader relay */
				if (set_defined_header(VHDR_INDEX[1], header_name, header_value, &httpc_ctx->user_ctx) != -1) {
					httpc_ctx->user_ctx.head.vheaderCnt ++;
				}
			}
			break;
	}
	return 0;
}

/* nghttp2_on_begin_headers_callback: Called when nghttp2 library gets
   started to receive header block. */
static int on_begin_headers_callback(nghttp2_session *session,
		const nghttp2_frame *frame,
		void *user_data) {
	(void)session;

	switch (frame->hd.type) {
		case NGHTTP2_HEADERS:
			if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
				// Response header for stream id %d (frame->hd.stream_id) receive/start
			}
			break;
	}
	return 0;
}

void ping_latency_alarm(http2_session_data_t *session_data, struct timeval *send_tm, struct timeval *recv_tm)
{
	char alarm_info[1024] = {0,};
	char alarm_desc[1024] = {0,};

	// don't make alarm event
	if (CLIENT_CONF.ping_event_ms <= 0)
		return;

	long long tv_send = send_tm->tv_sec * 1000LL + (send_tm->tv_usec / 1000LL);
	long long tv_recv = recv_tm->tv_sec * 1000LL + (recv_tm->tv_usec / 1000LL);
	long long ping_latency = tv_recv - tv_send;

	if (ping_latency >= CLIENT_CONF.ping_event_ms && session_data->event_occured == 0) {
		if (CLIENT_CONF.ping_event_code > 0) {
			sprintf(alarm_info, "HTTPC-%s",  session_data->authority);
			sprintf(alarm_desc, "%lld-ms", ping_latency);
			reportAlarm("HTTPC", CLIENT_CONF.ping_event_code, SFM_ALM_MAJOR, alarm_info, alarm_desc);
		}
		session_data->event_occured = 1;
		APPLOG(APPLOG_DEBUG, "%s() session (id:%d) alarm status (%s) [%s:%s]",
				__func__, session_data->session_id,
				CLIENT_CONF.ping_event_code > 0 ? "sended" : "silence discarded",
				alarm_info, alarm_desc);
	} else if (ping_latency < CLIENT_CONF.ping_event_ms && session_data->event_occured == 1) {
		if (CLIENT_CONF.ping_event_code > 0) {
			sprintf(alarm_info, "HTTPC-%s",  session_data->authority);
			sprintf(alarm_desc, "%lld-ms", ping_latency);
			reportAlarm("HTTPC", CLIENT_CONF.ping_event_code, SFM_ALM_NORMAL, alarm_info, alarm_desc);
		}
		session_data->event_occured = 0;
		APPLOG(APPLOG_DEBUG, "%s() session (id:%d) alarm status (%s) [%s:%s]",
				__func__, session_data->session_id,
				CLIENT_CONF.ping_event_code > 0 ? "cleared" : "silence discarded",
				alarm_info, alarm_desc);
	}
}

/* nghttp2_on_frame_recv_callback: Called when nghttp2 library
   received a complete frame from the remote peer. */
static int on_frame_recv_callback(nghttp2_session *session,
		const nghttp2_frame *frame, void *user_data) {
	http2_session_data_t *session_data = (http2_session_data_t *)user_data;
	(void)session;

	switch (frame->hd.type) {
		case NGHTTP2_RST_STREAM:
			http_stat_inc(session_data->thrd_index, session_data->list_index, HTTP_RX_RST);
			break;
		case NGHTTP2_PING:
			if (frame->hd.flags & NGHTTP2_FLAG_ACK) {
				gettimeofday(&session_data->ping_rcv_time, NULL);
				ping_latency_alarm(session_data, &session_data->ping_snd_time, &session_data->ping_rcv_time);
			}
			break;
		case NGHTTP2_HEADERS:
			if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
				/* stat HTTP_RX_RSP */
				http_stat_inc(session_data->thrd_index, session_data->list_index, HTTP_RX_RSP);
				// All header received
			}
			break;
	}
	return 0;
}

static ssize_t ptr_read_callback(nghttp2_session *session, int32_t stream_id,
		uint8_t *buf, size_t length,
		uint32_t *data_flags,
		nghttp2_data_source *source,
		void *user_data) {
	httpc_ctx_t *httpc_ctx = (httpc_ctx_t *)source->ptr;
	int len = httpc_ctx->user_ctx.head.bodyLen;

	if (len >= length) {
		APPLOG(APPLOG_ERR, "%s() ctx_id (%d) body_len(%d) exceed maximum data_prd_len(%zu)!",
				__func__, httpc_ctx->ctx_idx, len, length);
		len = length;
	}
	// ahif.data [query|body|...] this callback want body send
	memcpy(buf, httpc_ctx->user_ctx.data + httpc_ctx->user_ctx.head.queryLen, len);

	clear_send_ctx(httpc_ctx);
	*data_flags |= NGHTTP2_DATA_FLAG_EOF;
	return len;
}

static int submit_request(http2_session_data_t *session_data, httpc_ctx_t *httpc_ctx, http2_stream_data *stream_data) {
	int32_t stream_id;

    char request_path[8142] = {0,};

	if (strlen(httpc_ctx->user_ctx.head.rsrcUri) >= sizeof(request_path)) {
		APPLOG(APPLOG_ERR, "%s() request_path is null or too long!", __func__);
		clear_send_ctx(httpc_ctx); // clear now
		return -1;
	} else {
		sprintf(request_path, "%s", httpc_ctx->user_ctx.head.rsrcUri);
	}

	if ((strlen(request_path) + 1 + httpc_ctx->user_ctx.head.queryLen) >= sizeof(request_path)) {
		APPLOG(APPLOG_ERR, "%s() pathLen + queryLen exceed max request size!", __func__);
		clear_send_ctx(httpc_ctx); // clear now
		return -1;
	} else if (httpc_ctx->user_ctx.head.queryLen > 0) {
		sprintf(request_path + strlen(request_path), "%s", "?");
		memcpy(request_path + strlen(request_path), httpc_ctx->user_ctx.data, httpc_ctx->user_ctx.head.queryLen);
	}

	nghttp2_nv hdrs[MAX_HDR_RELAY_CNT + 5] = {
		MAKE_NV(HDR_METHOD, httpc_ctx->user_ctx.head.httpMethod, strlen(httpc_ctx->user_ctx.head.httpMethod)),
		MAKE_NV(HDR_SCHEME, session_data->scheme, strlen(session_data->scheme)),
		MAKE_NV(HDR_AUTHORITY, session_data->authority, session_data->authority_len),
		MAKE_NV(HDR_PATH, request_path, strlen(request_path))};
	int hdrs_len = 4; /* :method :scheme :authority :path */

    /* oauth 2.0 */
	if (httpc_ctx->access_token[0]) {
		char token_buffer[1024] = {0,};
		sprintf(token_buffer, "Bearer %s", httpc_ctx->access_token);
		nghttp2_nv auth_hdr[] = { MAKE_NV(HDR_AUTHORIZATION, token_buffer, strlen(token_buffer)) };
		memcpy(&hdrs[hdrs_len], &auth_hdr, sizeof(nghttp2_nv));
		hdrs_len ++;
	}

	hdrs_len = assign_more_headers(VHDR_INDEX[0], &hdrs[0], MAX_HDR_RELAY_CNT + 5, hdrs_len, &httpc_ctx->user_ctx);

	nghttp2_data_provider data_prd = {0,};
	char log_pfx[1024] = {0,};

	if (httpc_ctx->user_ctx.head.bodyLen > 0) {
		data_prd.source.ptr = httpc_ctx;
		data_prd.read_callback = ptr_read_callback; // clear ctx after body send
		stream_id = nghttp2_submit_request(session_data->session, NULL, hdrs, 
				hdrs_len, &data_prd, stream_data);
		sprintf(log_pfx, "HTTPC SEND ahifcid(%d) http sess/stream(%d:%d)]", 
				httpc_ctx->user_ctx.head.ahifCid, httpc_ctx->session_id, stream_id);
		log_pkt_send(log_pfx, hdrs, hdrs_len, 
				httpc_ctx->user_ctx.data + httpc_ctx->user_ctx.head.queryLen, 
				httpc_ctx->user_ctx.head.bodyLen);

	} else {
		stream_id = nghttp2_submit_request(session_data->session, NULL, hdrs, 
				hdrs_len, NULL, stream_data);
		sprintf(log_pfx, "HTTPC SEND ahifcid(%d) http sess/stream(%d:%d)]", 
				httpc_ctx->user_ctx.head.ahifCid, httpc_ctx->session_id, stream_id);
		log_pkt_send(log_pfx, hdrs, hdrs_len, 
				httpc_ctx->user_ctx.data + httpc_ctx->user_ctx.head.queryLen, 
				httpc_ctx->user_ctx.head.bodyLen);

		clear_send_ctx(httpc_ctx); // clear now
	}

	if (stream_id < 0) {
		APPLOG(APPLOG_ERR, "%s() Could not submit HTTP request: %s", __func__, nghttp2_strerror(stream_id));
	} 

	return stream_id;
}

/* Serialize the frame and send (or buffer) the data to
   bufferevent. */
static int session_send(http2_session_data_t *session_data) {
	int rv;

	rv = nghttp2_session_send(session_data->session);
	if (rv != 0) {
		APPLOG(APPLOG_ERR, "Fatal error: %s", nghttp2_strerror(rv));
		return -1;
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
	http2_session_data_t *session_data = (http2_session_data_t *)user_data;
	(void)session;
	(void)flags;
	/* get stream fron contex for defragment */
	http2_stream_data *stream_data = NULL;
	httpc_ctx_t *httpc_ctx = NULL;

	/* no data, do nothing */
	if (len == 0) return 0;

	/* re-assemble */
	stream_data = nghttp2_session_get_stream_user_data(session, stream_id);
	if (stream_data) {
		int thrd_idx = session_data->thrd_index;
		int idx = stream_data->ctx_id;

		if ((httpc_ctx = get_context(thrd_idx, idx, 1)) == NULL) {
			APPLOG(APPLOG_ERR, "%s() get_context fail! (thrd_idx:%d ctx_idx:%d)", __func__, thrd_idx, idx);
			return 0;
		}

		/* volatile issue */
		char *ptr = httpc_ctx->user_ctx.data + httpc_ctx->user_ctx.head.queryLen; // ahif.data [query|data|...]
		volatile int curr_len = httpc_ctx->user_ctx.head.bodyLen;
		ptr += curr_len;
		memcpy(ptr, data, len);
		httpc_ctx->user_ctx.head.bodyLen += len;

		// Http body received by len

	} else {
		APPLOG(APPLOG_ERR, "%s() h2 get stream fail!", __func__);
	}

	return 0;
}

void send_response_to_nrfm(httpc_ctx_t *httpc_ctx)
{
	int thrd_idx = httpc_ctx->thrd_idx;
	int ctx_idx = httpc_ctx->ctx_idx;

	char msgBuff[65535] = {0,};

	GeneralQMsgType *msg = (GeneralQMsgType *)msgBuff;
	msg->mtype = (long)MSGID_HTTPC_NRFM_RESPONSE;

	AhifHttpCSMsgType *ahifPkt_recv = &httpc_ctx->user_ctx;
	AhifHttpCSMsgType *ahifPkt_send = (AhifHttpCSMsgType *)msg->body;

	size_t shmqlen = AHIF_APP_MSG_HEAD_LEN + AHIF_VHDR_LEN + ahifPkt_recv->head.queryLen + ahifPkt_recv->head.bodyLen;
	memcpy(ahifPkt_send, ahifPkt_recv, shmqlen);

	int res = msgsnd(nrfmQid, msg, shmqlen, IPC_NOWAIT);
	if (res < 0) {
		APPLOG(APPLOG_ERR, "%s() msgsnd fail err=%d(%s)", __func__, errno, strerror(errno));
	}

	clear_and_free_ctx(httpc_ctx);
	Free_CtxId(thrd_idx, ctx_idx);
}

/* nghttp2_on_stream_close_callback: Called when a stream is about to
   closed. This example program only deals with 1 HTTP request (1
   stream), if it is closed, we send GOAWAY and tear down the
   session */
static int on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
		uint32_t error_code, void *user_data) {
	http2_session_data_t *session_data = (http2_session_data_t *)user_data;
	/* if recv EOF, send re-assembled data to upper */
	http2_stream_data *stream_data = NULL;
	httpc_ctx_t *httpc_ctx = NULL;
	int thrd_idx, idx;

	// Stream Closed

	if ((stream_data = nghttp2_session_get_stream_user_data(session, stream_id)) == NULL)
		return 0;

	/* get context */
	thrd_idx = session_data->thrd_index;
	idx = stream_data->ctx_id;

	if ((httpc_ctx = get_context(thrd_idx, idx, 1)) == NULL) {
		return 0;
	}

	// Whole data Reveived

	log_pkt_end_stream(stream_id, httpc_ctx);

	if (httpc_ctx->inflight_ref_cnt > 0) {
		/* timeout case */
		clear_and_free_ctx(httpc_ctx);
		Free_CtxId(thrd_idx, idx);
	} else if (httpc_ctx->for_nrfm_ctx) {
		/* response to NRFM */
		send_response_to_nrfm(httpc_ctx);
	} else {
		send_response_to_fep(httpc_ctx);
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
		APPLOG(APPLOG_ERR, "%s() Server did not advertise %s", __func__, NGHTTP2_PROTO_VERSION_ID);
	}
	return SSL_TLSEXT_ERR_OK;
}

#ifdef SSL_DEBUG
static BIO *bio_keylog = NULL;

static void keylog_callback(const SSL *ssl, const char *line)
{
    if (bio_keylog == NULL) {
        APPLOG(APPLOG_ERR, "%s() Keylog callback is invoked without valid file!", __func__);
        return;
    }

    /*
     * There might be concurrent writers to the keylog file, so we must ensure
     * that the given line is written at once.
     */
    BIO_printf(bio_keylog, "%s\n", line);
    (void)BIO_flush(bio_keylog);
}

int set_keylog_file(SSL_CTX *ctx, const char *keylog_file)
{
    /* Close any open files */
    BIO_free_all(bio_keylog);
    bio_keylog = NULL;

    if (ctx == NULL || keylog_file == NULL) {
        /* Keylogging is disabled, OK. */
        return 0;
    }

    /*
     * Append rather than write in order to allow concurrent modification.
     * Furthermore, this preserves existing keylog files which is useful when
     * the tool is run multiple times.
     */
    bio_keylog = BIO_new_file(keylog_file, "a");
    if (bio_keylog == NULL) {
        APPLOG(APPLOG_ERR, "%s() Error writing keylog file %s", __func__, keylog_file);
        return 1;
    }

    /* Write a header for seekable, empty files (this excludes pipes). */
    if (BIO_tell(bio_keylog) == 0) {
        BIO_puts(bio_keylog,
                 "# SSL/TLS secrets log file, generated by OpenSSL\n");
        (void)BIO_flush(bio_keylog);
    }
    SSL_CTX_set_keylog_callback(ctx, keylog_callback);
    return 0;
}
#endif

/* Create SSL_CTX. */
static SSL_CTX *create_ssl_ctx(void) {
	SSL_CTX *ssl_ctx;
	ssl_ctx = SSL_CTX_new(SSLv23_client_method());
#ifdef SSL_DEBUG
	set_keylog_file(ssl_ctx, "./ssl.log");
#endif
	if (!ssl_ctx) {
		APPLOG(APPLOG_ERR, "%s() Could not create SSL/TLS context: %s",
				__func__, ERR_error_string(ERR_get_error(), NULL));
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
		APPLOG(APPLOG_ERR, "%s() Could not create SSL/TLS session object: %s",
				__func__, ERR_error_string(ERR_get_error(), NULL));
	}
	return ssl;
}

static void initialize_nghttp2_session(http2_session_data_t *session_data) {
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
	nghttp2_session_client_new(&session_data->session, callbacks, session_data);
#else
	// U+ requirement, dynamic table size 0
	nghttp2_session_client_new2(&session_data->session, callbacks, session_data, CLIENT_CONF.nghttp2_option);
#endif

	// schlee test code, set session buff 10MB
	nghttp2_session_set_local_window_size(session_data->session, NGHTTP2_FLAG_NONE, 0, 1 << 30);

	nghttp2_session_callbacks_del(callbacks);
}

static void send_client_connection_header(http2_session_data_t *session_data) {
	/* schlee, IMPORTANT, this means MAX SND/RCV SIZE */
	nghttp2_settings_entry iv[5] = {
		{NGHTTP2_SETTINGS_HEADER_TABLE_SIZE, 65535},
		{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 65535},
		{NGHTTP2_SETTINGS_MAX_FRAME_SIZE, 65535},
		{NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 65535},
		{NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE, 65535}};

	/* client 24 bytes magic string will be sent by nghttp2 library */
	int rv = nghttp2_submit_settings(session_data->session, NGHTTP2_FLAG_NONE, iv,
			ARRLEN(iv));
	if (rv != 0) {
		APPLOG(APPLOG_ERR, "%s() Could not submit SETTINGS: %s", __func__, nghttp2_strerror(rv));
	}
}

/* readcb for bufferevent. Here we get the data from the input buffer
   of bufferevent and feed them to nghttp2 library. This may invoke
   nghttp2 callbacks. It may also queues the frame in nghttp2 session
   context. To send them, we call session_send() in the end. */
static void readcb(struct bufferevent *bev, void *ptr) {
	http2_session_data_t *session_data = (http2_session_data_t *)ptr;
	ssize_t readlen;
	struct evbuffer *input = bufferevent_get_input(bev);
	size_t datalen = evbuffer_get_length(input);
	unsigned char *data = evbuffer_pullup(input, -1);

	readlen = nghttp2_session_mem_recv(session_data->session, data, datalen);
	if (readlen < 0) {
		APPLOG(APPLOG_ERR, "Fatal error: %s", nghttp2_strerror((int)readlen));
		delete_http2_session_data(session_data);
		return;
	}
	if (evbuffer_drain(input, (size_t)readlen) != 0) {
		APPLOG(APPLOG_ERR, "Fatal error: evbuffer_drain failed");
		delete_http2_session_data(session_data);
		return;
	}
	if (session_send(session_data) != 0) {
		APPLOG(APPLOG_ERR,"DBG] %s schlee, session send failed", __func__);
		delete_http2_session_data(session_data);
		return;
	}
}

/* writecb for bufferevent. To greaceful shutdown after sending or
   receiving GOAWAY, we check the some conditions on the nghttp2
   library and output buffer of bufferevent. If it indicates we have
   no business to this session, tear down the connection. */
static void writecb(struct bufferevent *bev, void *ptr) {
	http2_session_data_t *session_data = (http2_session_data_t *)ptr;
	(void)bev;

	if (nghttp2_session_want_read(session_data->session) == 0 &&
			nghttp2_session_want_write(session_data->session) == 0 &&
			evbuffer_get_length(bufferevent_get_output(session_data->bev)) == 0) {
#ifndef HOLDSESS // schlee, don't close session, hold it, 아예 아무 처리도 안하는 방안
		delete_http2_session_data(session_data);
		return;
#endif
	}
}

/* eventcb for bufferevent. For the purpose of simplicity and
   readability of the example program, we omitted the certificate and
   peer verification. After SSL/TLS handshake is over, initialize
   nghttp2 library session, and send client connection header. Then
   send HTTP request. */
static void eventcb(struct bufferevent *bev, short events, void *ptr) {
	http2_session_data_t *session_data = (http2_session_data_t *)ptr;
	if (events & BEV_EVENT_CONNECTED) {
		int fd = bufferevent_getfd(bev);
		int val = 1;
		const unsigned char *alpn = NULL;
		unsigned int alpnlen = 0;

		if (!strcmp(session_data->scheme, "https")) {
			SSL *ssl = bufferevent_openssl_get_ssl(session_data->bev);

			SSL_get0_next_proto_negotiated(ssl, &alpn, &alpnlen);
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
			if (alpn == NULL) {
				SSL_get0_alpn_selected(ssl, &alpn, &alpnlen);
			}
#endif // OPENSSL_VERSION_NUMBER >= 0x10002000L

			if (alpn == NULL || alpnlen != 2 || memcmp("h2", alpn, 2) != 0) {
				APPLOG(APPLOG_ERR, "%s() h2 is not negotiated", __func__);
				delete_http2_session_data(session_data);
				return;
			}
		}

		setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&val, sizeof(val));
		// schlee test code  : from here
		if (util_set_linger(fd, 1, 0) != 0)
			APPLOG(APPLOG_ERR, "%s() fail to set SO_LINGER (ABORT) to fd", __func__);
		// schlee test code  : to here
		initialize_nghttp2_session(session_data);
		send_client_connection_header(session_data);
		if (session_send(session_data) != 0) {
			APPLOG(APPLOG_ERR, "%s() h2 nego send failed", __func__);
			delete_http2_session_data(session_data);
		}

		/* session connected */
		pthread_mutex_lock(&ONLY_CRT_SESS_LOCK);
		CONN_LIST[session_data->conn_index].conn = CN_CONNECTED;
		CONN_LIST[session_data->conn_index].tombstone_date = 0;
		session_data->connected = 1;
		gettimeofday(&session_data->ping_rcv_time, NULL);
		APPLOG(APPLOG_DETAIL, "%s() Connected conn_index %5d thrd_index %2d session_index %5d ip %s port %d",
				__func__,
				session_data->conn_index, 
				session_data->thrd_index, 
				session_data->session_index,
				CONN_LIST[session_data->conn_index].ip,
				CONN_LIST[session_data->conn_index].port);

		CONN_LIST[session_data->conn_index].thrd_index = session_data->thrd_index;
		CONN_LIST[session_data->conn_index].session_index = session_data->session_index;
		CONN_LIST[session_data->conn_index].session_id = session_data->session_id;
		pthread_mutex_unlock(&ONLY_CRT_SESS_LOCK);

		return;
	}

	if (events & BEV_EVENT_EOF) {
		APPLOG(APPLOG_DETAIL, "%s() Disconnect from remote ip index %d [%s:%s:%d]",
				__func__,
				session_data->conn_index, 
				CONN_LIST[session_data->conn_index].host,
				CONN_LIST[session_data->conn_index].ip,
				CONN_LIST[session_data->conn_index].port);
	} else if (events & BEV_EVENT_ERROR) {
		APPLOG(APPLOG_DETAIL, "%s() Network error index %d [%s:%s:%d]",
				__func__,
				session_data->conn_index, 
				CONN_LIST[session_data->conn_index].host,
				CONN_LIST[session_data->conn_index].ip,
				CONN_LIST[session_data->conn_index].port);
	} else if (events & BEV_EVENT_TIMEOUT) {
		APPLOG(APPLOG_DETAIL, "%s() Event Timeout index %d [%s:%s:%d]",
				__func__,
				session_data->conn_index, 
				CONN_LIST[session_data->conn_index].host,
				CONN_LIST[session_data->conn_index].ip,
				CONN_LIST[session_data->conn_index].port);
	}

	delete_http2_session_data(session_data);
}

/* Start connecting to the remote peer |ip:port| */
static void initiate_connection(struct event_base *evbase, SSL_CTX *ssl_ctx,
		const char *ip, uint16_t port,
		http2_session_data_t *session_data) {
	int rv = 0;
	struct bufferevent *bev = NULL;
	SSL *ssl = NULL;

	if (!strcmp(session_data->scheme, "https")) {
		ssl = create_ssl(ssl_ctx);
		bev = bufferevent_openssl_socket_new(
				evbase, -1, ssl, BUFFEREVENT_SSL_CONNECTING,
				BEV_OPT_DEFER_CALLBACKS | BEV_OPT_CLOSE_ON_FREE | BEV_OPT_THREADSAFE);
	} else {
		bev = bufferevent_socket_new(
				evbase, -1, BEV_OPT_DEFER_CALLBACKS | BEV_OPT_CLOSE_ON_FREE | BEV_OPT_THREADSAFE);
	}
	bufferevent_enable(bev, EV_READ | EV_WRITE);
	bufferevent_setcb(bev, readcb, writecb, eventcb, session_data);
	rv = bufferevent_socket_connect_hostname(bev, NULL,
			AF_UNSPEC, ip, port);

	if (rv != 0) {
		APPLOG(APPLOG_ERR, "%s() Could not connect to the remote ip %s", __func__, ip);
	}
	session_data->bev = bev;
}

int send_request(http2_session_data_t *session_data, int thrd_index, int ctx_id)
{
	int stream_id;

	httpc_ctx_t *httpc_ctx = NULL;

	if ((httpc_ctx = get_context(thrd_index, ctx_id, 1)) == NULL) {
		APPLOG(APPLOG_ERR, "%s() get_context fail", __func__);
		return (-1);
	}

	stream_id = submit_request(session_data, httpc_ctx, &httpc_ctx->stream);

	if (stream_id >= 0) {
		httpc_ctx->stream.stream_id = stream_id;
		httpc_ctx->stream.ctx_id = ctx_id;
	}

	return stream_id;
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
    httpc_ctx_t *httpc_ctx;
    intl_req_t intl_req;

    for (index = 0; index < CLIENT_CONF.worker_num; index ++) {
        for (i = STARTID, snd = 0; i < SIZEID; i++) {

            /* normal case */
            if ((httpc_ctx = get_context(index, i, 1)) == NULL) 
                continue;
			/* this ctx queued in tcp, don't release this */
			if (httpc_ctx->tcp_wait == 1)
				continue;

            /* timed out case */
            if ((THRD_WORKER[index].time_index - httpc_ctx->recv_time_index) >= 
                    ((CLIENT_CONF.timeout_sec * TMOUT_VECTOR) + 1)) {
				/* already sended, wait next 10th order */
				if ((httpc_ctx->inflight_ref_cnt) && (httpc_ctx->inflight_ref_cnt++ % 10 != 0)) {
					continue;
				} else {
					httpc_ctx->inflight_ref_cnt ++;
				}
                set_intl_req_msg(&intl_req, index, i, httpc_ctx->sess_idx, httpc_ctx->session_id, 0, HTTP_INTL_TIME_OUT);
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
    http2_session_data_t *session_data = NULL;
    intl_req_t intl_req;
	struct timespec tm_curr = {0,};

	clock_gettime(CLOCK_REALTIME, &tm_curr);

    for (thrd_idx = 0; thrd_idx < CLIENT_CONF.worker_num; thrd_idx++) {
        for (sess_idx = 0; sess_idx < MAX_SVR_NUM; sess_idx++) {
            session_data = &SESS[thrd_idx][sess_idx];
            if (session_data->used != 1)
                continue;
            if (session_data->connected != 1)
                continue;
            /* if 1sec * 5send = no response --> close session */
            if ((tm_curr.tv_sec - session_data->ping_rcv_time.tv_sec) > CLIENT_CONF.ping_timeout) {
                APPLOG(APPLOG_ERR, "%s() session (id: %d) goaway~!", __func__, session_data->session_id);
                set_intl_req_msg(&intl_req, thrd_idx, 0, sess_idx, session_data->session_id, 0, HTTP_INTL_SESSION_DEL);
                if (-1 == msgsnd(THRD_WORKER[thrd_idx].msg_id, &intl_req, sizeof(intl_req) - sizeof(long), IPC_NOWAIT)) {
					APPLOG(APPLOG_ERR, "%s():%d msgsnd fail!!!", __func__, __LINE__);
                }
				continue;
			}
			if (session_data->ping_cnt ++ % CLIENT_CONF.ping_interval == 0) { 
				set_intl_req_msg(&intl_req, thrd_idx, 0, sess_idx, session_data->session_id, 0, HTTP_INTL_SEND_PING);
				if (-1 == msgsnd(THRD_WORKER[thrd_idx].msg_id, &intl_req, sizeof(intl_req) - sizeof(long), IPC_NOWAIT)) {
					APPLOG(APPLOG_ERR, "%s():%d msgsnd fail!!!", __func__, __LINE__);
				}
			}
        }
    }
}

void pub_conn_callback(evutil_socket_t fd, short what, void *arg)
{
	memset(CONN_STATUS, 0x00, sizeof(CONN_STATUS));
	gather_list(CONN_STATUS);
	set_httpc_status(CONN_STATUS);
}

void send_status_to_omp(evutil_socket_t fd, short what, void *arg)
{
	int i, index = 0;
	SFM_HttpConnStatusList conn_list;
	conn_list_status_t *conn_status;

	memset(&conn_list, 0x00, sizeof(SFM_HttpConnStatusList));
	for (i = 0; i < MAX_CON_NUM; i++) {
		if (CONN_STATUS[i].occupied != 1 || CONN_STATUS[i].item_index == -1)
			continue;
		else
			conn_status = &CONN_STATUS[i];

		index = conn_list.cnt++;
		conn_list.conn[index].id = conn_status->list_index;
		snprintf(conn_list.conn[index].host, sizeof(conn_list.conn[index].host), "%s", conn_status->host);
		snprintf(conn_list.conn[index].type, sizeof(conn_list.conn[index].type), "%s", conn_status->type);
		snprintf(conn_list.conn[index].ip, sizeof(conn_list.conn[index].ip), "%s", conn_status->ip);
		conn_list.conn[index].port = conn_status->port;
		conn_list.conn[index].max = conn_status->sess_cnt;
		conn_list.conn[index].curr = conn_status->conn_cnt;
	}
	//DumpHex(&conn_list, MSGID_HTTP_SERVER_STATUS_REPORT);
	http_report_status(&conn_list, MSGID_HTTP_SERVER_STATUS_REPORT);
}

conn_list_t *check_sess_group_prepair_reconn(conn_list_t *conn_list)
{
	for (int i = 0; i < MAX_SVR_NUM; i++) {
		conn_list_t *compare_list =  &CONN_LIST[i];

		if (i == conn_list->index) continue; // it's me
		if (compare_list->used == 0) continue;
		if (compare_list->act == 0) continue;
		if (compare_list->conn != CN_CONNECTED) continue;

		if ((compare_list->reconn_candidate > 0) &&
				(compare_list->port == conn_list->port) &&
				!strcmp(compare_list->scheme, conn_list->scheme) &&
				!strcmp(compare_list->type, conn_list->type) &&
				!strcmp(compare_list->host, conn_list->host) &&
				!strcmp(compare_list->ip, conn_list->ip)) {
			return compare_list;
		}
	}

	return NULL;
}

void inspect_stream_id(int stream_id, http2_session_data_t *session_data)
{
#if 0
	if (stream_id >= HTTP_PREPARE_STREAM_LIMIT &&
			CONN_LIST[session_data->conn_index].reconn_candidate == 0) {
		conn_list_t *conn_list = &CONN_LIST[session_data->conn_index];
		APPLOG(APPLOG_ERR, "%s() SESSION[%d] (%s:%s:%s:%d) REACH TO STREAM_ID LIMIT[%d], PREPARE RECONNECT!!!",
				__func__, session_data->session_id, 
				conn_list->type, conn_list->host, conn_list->ip, conn_list->port, HTTP_PREPARE_STREAM_LIMIT);
		conn_list->reconn_candidate = 1;
#else
	if (stream_id >= CLIENT_CONF.prepare_close_stream_limit &&
			CONN_LIST[session_data->conn_index].reconn_candidate == 0) {
		conn_list_t *conn_list = &CONN_LIST[session_data->conn_index];
		conn_list_t *prepare_disconn_list = check_sess_group_prepair_reconn(conn_list);
		if (prepare_disconn_list == NULL) {
			APPLOG(APPLOG_ERR, "%s() SESSION[%d] (%s:%s:%s:%d) REACH TO STREAM_ID LIMIT[%d], PREPARE RECONNECT!!!",
					__func__, session_data->session_id, 
					conn_list->type, conn_list->host, conn_list->ip, conn_list->port, CLIENT_CONF.prepare_close_stream_limit);
			conn_list->reconn_candidate = 1;
		}
#endif
	}
}

void recv_msgq_callback(evutil_socket_t fd, short what, void *arg)
{
	int read_index = *(int *)arg;
	intl_req_t intl_req;

	http2_session_data_t *session_data = NULL;
	httpc_ctx_t *httpc_ctx = NULL;

	int thrd_index, session_index, ctx_id, session_id;
	int msg_type;

	while (1)
	{
		memset(&intl_req, 0x00, sizeof(intl_req));
		/* get first msg (Arg 4) */
		int res = msgrcv(THRD_WORKER[read_index].msg_id, &intl_req, sizeof(intl_req) - sizeof(long), 0, IPC_NOWAIT | MSG_NOERROR);
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
			ctx_id = intl_req.tag.ctx_id;

		}

		/* it can be NULL */
		session_data = get_session(thrd_index, session_index, session_id);
		httpc_ctx = get_context(thrd_index, ctx_id, 1);

		switch (msg_type) {
			case HTTP_INTL_SND_REQ:
				if (session_data  == NULL) {
					/* legacy session expired and new one already created case */
					APPLOG(APPLOG_DEBUG, "%s():%d send req case) get_session(id:%d) fail", __func__, __LINE__, session_id);
					continue;
				}
				int stream_id = send_request(session_data, thrd_index, ctx_id);
				if (stream_id < 0) {
					APPLOG(APPLOG_DEBUG, "%s():%d send_request fail", __func__, __LINE__);
					continue;
				}
				if (session_send(session_data) != 0) {
					APPLOG(APPLOG_DEBUG, "%s():%d session_send fail", __func__, __LINE__);
				} else {
					inspect_stream_id(stream_id, session_data);
				}

				/* stat HTTP_TX_REQ */
				http_stat_inc(session_data->thrd_index, session_data->list_index, HTTP_TX_REQ);
#ifdef OVLD_API
				/* for nssf overload control */
				api_ovld_is_ctrl(thrd_index,  API_PROTO_HTTPC, 0, NULL, NULL);
#endif
				break;
			case HTTP_INTL_TIME_OUT:
				if (httpc_ctx == NULL) {
					APPLOG(APPLOG_DEBUG, "%s():%d get_context fail", __func__, __LINE__);
					continue;
				}
				if (session_data == NULL) {
					/* legacy session expired and new one already created case */
					APPLOG(APPLOG_DEBUG, "%s():%d timeout case) get_session(id:%d) fail", __func__, __LINE__, session_id);
				} else {
                    log_pkt_httpc_reset(httpc_ctx);
					/* it's same session and alive, send reset */
					nghttp2_submit_rst_stream(session_data->session, NGHTTP2_FLAG_NONE,
							httpc_ctx->stream.stream_id,
							NGHTTP2_INTERNAL_ERROR);
				} 
				clear_and_free_ctx(httpc_ctx);
				Free_CtxId(thrd_index, ctx_id);

				/* stat HTTP_TIMEOUT */
				if (session_data != NULL) 
					http_stat_inc(session_data->thrd_index, session_data->list_index, HTTP_TIMEOUT);
				else
					http_stat_inc(0, 0, HTTP_TIMEOUT);

				break;
			case HTTP_INTL_SESSION_DEL:
				if (session_data == NULL) {
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
			default:
				break;
		}
	}
}

void *workerThread(void *arg)
{
	int index = *(int *)arg;
	struct event_base *evbase;

	evbase = event_base_new();
	THRD_WORKER[index].evbase = evbase;

	/* this event ++ timer index, for timeout check func() */
    /* INCREASE RUNNING INDEX IN HERE */
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

void create_httpc_worker()
{
	int res;

	for (int i = 0; i < CLIENT_CONF.worker_num; i++) {
		res = pthread_create(&THRD_WORKER[i].thrd_id, NULL, &workerThread, (void *)&THREAD_NO[i]);
		if (res != 0) {
			APPLOG(APPLOG_ERR, "%s() Thread Create Fail (Worker:%2dth)", __func__, i);
			exit(0);
		} else {
			pthread_detach(THRD_WORKER[i].thrd_id);
		}
	}
}

void conn_func(evutil_socket_t fd, short what, void *arg)
{
	SSL_CTX *ssl_ctx = (SSL_CTX *)arg;
	http2_session_data_t *session_data;
	int i;

	pthread_mutex_lock(&ONLY_CRT_SESS_LOCK);
	for (i = 0; i < MAX_SVR_NUM; i++) {
		if (CONN_LIST[i].used == 0 || CONN_LIST[i].act != 1 || CONN_LIST[i].conn > CN_NOT_CONNECTED)
			continue;

		session_data = create_http2_session_data();

		if (session_data == NULL) {
			continue;
		} else {
			CONN_LIST[i].conn = CN_CONNECTING;
		}
		THRD_WORKER[session_data->thrd_index].server_num++;
		session_data->list_index = CONN_LIST[i].list_index;
		session_data->conn_index = CONN_LIST[i].index;

		/* stat HTTP_CONN */
		http_stat_inc(session_data->thrd_index, session_data->list_index, HTTP_CONN);

		// schlee, create session authority data
		/* authority   = [ userinfo "@" ] host [ ":" port ] */
		sprintf(session_data->scheme, "%s", CONN_LIST[i].scheme);
		sprintf(session_data->authority, "%s", CONN_LIST[i].ip);
		sprintf(session_data->authority + strlen(session_data->authority), "%s", ":");
		sprintf(session_data->authority + strlen(session_data->authority), "%d", CONN_LIST[i].port);
		session_data->authority_len = strlen(session_data->authority);
		initiate_connection(THRD_WORKER[session_data->thrd_index].evbase, 
				ssl_ctx, CONN_LIST[i].ip, CONN_LIST[i].port, session_data);
	}
	pthread_mutex_unlock(&ONLY_CRT_SESS_LOCK);
}

void candidate_session_del(evutil_socket_t fd, short what, void *arg)
{
	pthread_mutex_lock(&ONLY_CRT_SESS_LOCK);
	for (int i = 0; i < MAX_SVR_NUM; i++) {
		if (CONN_LIST[i].used == 0 || CONN_LIST[i].conn != CN_CONNECTED)
			continue;

		/* del only 1 session by time (2sec) */
#if 0
		if (CONN_LIST[i].reconn_candidate) {
#else
		// wait 5 sec for outbound request response
		if ((CONN_LIST[i].reconn_candidate > 0) && (CONN_LIST[i].reconn_candidate++ >= 5)) {
#endif
			intl_req_t intl_req = {0,};
			int thrd_index = CONN_LIST[i].thrd_index;
			set_intl_req_msg(&intl_req, thrd_index, 0, CONN_LIST[i].session_index,
					CONN_LIST[i].session_id, 0, HTTP_INTL_SESSION_DEL);
			APPLOG(APPLOG_ERR, "%s() SESSION[%d] enough wait, now disconnect!",
					__func__, CONN_LIST[i].session_id);
			if (-1 == msgsnd(THRD_WORKER[thrd_index].msg_id, &intl_req, sizeof(intl_req) - sizeof(long), IPC_NOWAIT)) {
				APPLOG(APPLOG_DEBUG, "%s() msgsnd fail!!!", __func__);
			}
			goto CANDIDATE_RECONN_END_JOB;
		}
	}
CANDIDATE_RECONN_END_JOB:
	pthread_mutex_unlock(&ONLY_CRT_SESS_LOCK);
	return;
}

#define MAX_THRD_WAIT_NUM 5
void check_thread()
{
    //int index, res;
    int index;

    /* check worker thread hang */
    for (index = 0; index < CLIENT_CONF.worker_num; index++) {
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
	httpc_ctx_t *httpc_ctx;
	int free_num, used_num, tmout_num;
	char buff[1024 * MAX_THRD_NUM] = {0, };

    /* check thread status */
    check_thread();

    /* for log */
	for (index = 0; index < CLIENT_CONF.worker_num; index++) {
		for (i = STARTID, free_num = 0, used_num = 0, tmout_num = 0; i < SIZEID; i++) {
			if ((httpc_ctx = get_context(index, i, 1)) == NULL) {
				free_num++;
				continue;
			}
			used_num++;
			if (httpc_ctx->inflight_ref_cnt)
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

    /* if command changed */
	if (CLIENT_CONF.refresh_node_requested) {
        APPLOG(APPLOG_ERR, "%s() rebuild lb thread's select node, this trigger from command", __func__);
		once_refresh_select_node(LB_CTX.fep_rx_thrd);
		once_refresh_select_node(LB_CTX.peer_rx_thrd);
		CLIENT_CONF.refresh_node_requested = 0;
	}

	if (CLIENT_CONF.debug_mode == 1) {
		IxpcQMsgType Ixpc = {0,};

		/* log worker ctx status */
		monitor_worker();
		/* log http status */
		stat_function(&Ixpc, CLIENT_CONF.worker_num, 1, 0, MSGID_HTTPC_STATISTICS_REPORT);
	}
}

void send_nrfm_notify(evutil_socket_t fd, short what, void *arg)
{
	char msgBuff[sizeof(GeneralQMsgType)] = {0,};

	GeneralQMsgType *msg = (GeneralQMsgType *)msgBuff;
	nrfm_noti_t *httpc_noti = (nrfm_noti_t *)msg->body;

	msg->mtype = (long)MSGID_HTTPC_NRFM_IMALIVE_NOTI;
	httpc_noti->my_pid = getpid();

	/* if NRFM not exist, discard */
	if (nrfmQid > 0) {
		int res = msgsnd(nrfmQid, msg, sizeof(nrfm_noti_t), IPC_NOWAIT);
		if (res < 0) {
			APPLOG(APPLOG_ERR, "%s(), fail to send resp to NRFM! (res:%d)", __func__, res);
		}
	}
}

void main_loop()
{
	SSL_CTX *ssl_ctx;
	struct event_base *evbase;

	ssl_ctx = create_ssl_ctx();

	/* create event_base */
	evbase = event_base_new();

	/* tick function */
	struct timeval tic_sec = {1, 0};
	struct event *ev_tick;
    ev_tick = event_new(evbase, -1, EV_PERSIST, main_tick_callback, NULL);
    event_add(ev_tick, &tic_sec);

	/* check connection */
	struct timeval one_sec = {1, 0};
	struct event *ev;
	ev = event_new(evbase, -1, EV_PERSIST, conn_func, (void *)ssl_ctx);
	event_add(ev, &one_sec);

	/* check candidate reconnect (stream_id full) */
#if 0
	struct timeval tm_stream_id_inspect = {2, 0};
#else
	struct timeval tm_stream_id_inspect = {1, 0}; // check every 1sec, if 5 count (outbound no remain), delete session
#endif
	struct event *ev_candidate_session_del;
	ev_candidate_session_del = event_new(evbase, -1, EV_PERSIST, candidate_session_del, NULL);
	event_add(ev_candidate_session_del, &tm_stream_id_inspect);

	/* check context timeout */
	struct timeval tm_interval = {0, TM_INTERVAL * 5}; // every 100 ms
	struct event *ev_timeout;
	ev_timeout = event_new(evbase, -1, EV_PERSIST, chk_tmout_callback, NULL);
	event_add(ev_timeout, &tm_interval);

    /* send ping & delete goaway session */
    struct timeval tm_ping = {1, 0};
    struct event *ev_ping;
    ev_ping = event_new(evbase, -1, EV_PERSIST, send_ping_callback, NULL);
    event_add(ev_ping, &tm_ping);

	/* publish conn status to shm */
    struct timeval tm_conn = {1, 0};
    struct event *ev_conn;
    ev_conn = event_new(evbase, -1, EV_PERSIST, pub_conn_callback, NULL);
    event_add(ev_conn, &tm_conn);

	/* send conn status to OMP FIMD */
	struct timeval tm_status = {5, 0};
    struct event *ev_status;
    ev_status = event_new(evbase, -1, EV_PERSIST, send_status_to_omp, NULL);
    event_add(ev_status, &tm_status);

	/* system message handle */
	struct timeval tm_milisec = {0, 100000}; // 100 ms
	struct event *ev_msg_handle;
	ev_msg_handle = event_new(evbase, -1, EV_PERSIST, message_handle, NULL);
	event_add(ev_msg_handle, &tm_milisec);

	/* LB stat print */
	struct timeval lbctx_print_interval = {1, 0};
	struct event *ev_lbctx_print;
	ev_lbctx_print = event_new(evbase, -1, EV_PERSIST, fep_stat_print, NULL);
	event_add(ev_lbctx_print, &lbctx_print_interval);

	/* send to NRFM httpc still alive */
	struct timeval nrfm_notify_sec = {0, 300000}; // 300 ms
	struct event *ev_nrfm_notify;
	ev_nrfm_notify = event_new(evbase, -1, EV_PERSIST, send_nrfm_notify, NULL);
	event_add(ev_nrfm_notify, &nrfm_notify_sec);

	/* start loop */
	event_base_loop(evbase, EVLOOP_NO_EXIT_ON_EMPTY);

	/* never reach here */
	event_base_free(evbase);
	SSL_CTX_free(ssl_ctx);
}

int set_http2_option(client_conf_t *CLIENT_CONF)
{
	/* create nghttp2 option */
	if (nghttp2_option_new(&CLIENT_CONF->nghttp2_option) < 0) {
		APPLOG(APPLOG_ERR, "{{{INIT}}} %s fail to create nghttp2 option!", __func__);
		return -1;
	}

	/* set setting_header_table_size */
	nghttp2_option_set_max_deflate_dynamic_table_size(CLIENT_CONF->nghttp2_option, CLIENT_CONF->http_opt_header_table_size);
	APPLOG(APPLOG_ERR, "{{{INIT}}} %s set setting_header_table_size to [%d]", __func__, CLIENT_CONF->http_opt_header_table_size);

	return 0;
}

void directory_watch_action(const char *file_name) { } 

int get_acc_token_shm(client_conf_t *CLIENT_CONF)
{
    char fname[1024] = {0,};
    sprintf(fname,"%s/%s", getenv(IV_HOME), SYSCONF_FILE);

    char tmp[1024] = {0,};
    if (conflib_getNthTokenInFileSection (fname, "SHARED_MEMORY_KEY", "SHM_NRFM_ACC_TOKEN", 1, tmp) < 0 )
        return -1;
	int nrfm_acc_token_shm_key = strtol(tmp,(char**)0,0);

	int nrfm_acc_token_id = shmget((size_t)nrfm_acc_token_shm_key, SHM_ACC_TOKEN_TABLE_SIZE, IPC_CREAT|0666);
	if (nrfm_acc_token_id < 0) {
        fprintf(stderr, "TODO| fail to get (%s) shm id fail!\n", "SHM_NRFM_ACC_TOKEN");
		return (-1);
	}

	if ((CLIENT_CONF->ACC_TOKEN_LIST =
				(acc_token_shm_t *)shmat(nrfm_acc_token_id, NULL, 0)) == (acc_token_shm_t *)-1) {
        fprintf(stderr, "TODO| fail to attach to access token shm fail!\n");
		return (-1);
	}

	return 0;
}

int initialize()
{
	char fname[256] = { 0, };
	char tmp[64] = { 0, };
	int	 key, i, j;
	char *env, *ptrStr;

	/*  get env */
	if ((env = getenv(IV_HOME)) == NULL) {
		fprintf(stderr,"{{{INIT}}} [%s] not found %s environment name!\n", __func__, IV_HOME);
		return (-1);
	}
	/* my proc name ... */
	sprintf(myProcName, "%s", "HTTPC");
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
	sprintf(log_path, "%s/log/ERR_LOG/%s", getenv(IV_HOME), myProcName);
	initlog_for_loglib(myProcName, log_path);
#elif LOG_APP
	sprintf(fname, "%s/log", getenv(IV_HOME));
	LogInit(myProcName, fname);
#endif
    if (config_load_just_log() < 0) {
        fprintf(stderr, "{{{INIT}}}fail to read config file (log)!\n");
        return (-1);
	}
	*lOG_FLAG = CLIENT_CONF.log_level;
	APPLOG(APPLOG_ERR, "\n\n[[[[[ Welcome Process Started ]]]]]");

	/* create httpc conn status shm */
    sprintf(fname,"%s/%s", getenv(IV_HOME), SYSCONF_FILE);

    if (conflib_getNthTokenInFileSection (fname, "SHARED_MEMORY_KEY", "SHM_HTTPC_CONN", 1, tmp) < 0 )
        return -1;
    int shm_httpc_conn_key = strtol(tmp,(char**)0,0);

	if (get_http_shm(shm_httpc_conn_key) < 0) {
		fprintf(stderr,"{{{INIT}}} httpc conn status shm create fail!\n");
		return (-1);
	}

	/* get access token shm */
	if (get_acc_token_shm(&CLIENT_CONF) < 0) {
		fprintf(stderr,"{{{INIT}}} fail to get (nrfm) acc token shm!\n");
		return (-1);
	}

    if (config_load() < 0) {
        APPLOG(APPLOG_ERR, "{{{INIT}}} fail to read config file!");
        return (-1);
	} else {
		memset(CONN_STATUS, 0x00, sizeof(CONN_STATUS));

		gather_list(CONN_STATUS);
		print_list(CONN_STATUS);
	}

	for ( i = 0; i < CLIENT_CONF.worker_num; i++) {
		if ( -1 == (THRD_WORKER[i].msg_id = msgget((key_t)(CLIENT_CONF.worker_shmkey + i), IPC_CREAT | 0666))) {
			APPLOG(APPLOG_ERR, "{{{INIT}}} fail to create internal msgq id!");
			exit( 1);
		}
		/* & flughing it & remake */
		msgctl(THRD_WORKER[i].msg_id, IPC_RMID, NULL);
		if (-1 == (THRD_WORKER[i].msg_id = msgget((key_t)(CLIENT_CONF.worker_shmkey + i), IPC_CREAT | 0666))) {
			APPLOG(APPLOG_ERR, "{{{INIT}}} fail to create internal msgq id!");
			exit( 1);
		}
	}

#ifdef SYSCONF_LEGACY
    int PROC_NAME_LOC = 1; // some old sysconf : eir ...
#else
    int PROC_NAME_LOC = 3;
#endif

	/* create recv-mq */
	sprintf(fname,"%s/%s", env, SYSCONF_FILE);
	if (conflib_getNthTokenInFileSection (fname, "APPLICATIONS", myProcName, PROC_NAME_LOC, tmp) < 0) {
		APPLOG(APPLOG_ERR, "{{{INIT}}} configlib get token APPLICATIONS fail!");
		return -1;
	}
	key = strtol(tmp,0,0);
	if ((httpcQid = msgget(key,IPC_CREAT|0666)) < 0) {
		APPLOG(APPLOG_ERR,"{{{INIT}}} [%s] msgget fail; key=0x%x,err=%d(%s)!", __func__, key, errno, strerror(errno));
		return -1;
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
		APPLOG(APPLOG_ERR, "{{{INIT}}} can't find NRFM info in sysconfig APPLICATION!, NRFM QID will 0");
	}

	/* alloc context memory */
	for ( i = 0; i < CLIENT_CONF.worker_num; i++) {
		HttpcCtx[i] = calloc (SIZEID, sizeof(httpc_ctx_t));
	}
	/* & initialize */
	for (i = 0; i < CLIENT_CONF.worker_num; i++) {
		Init_CtxId(i);
		for (j = 0; j < SIZEID; j++) {
			HttpcCtx[i][j].occupied = 0;
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

	if (sort_relay_vhdr(VHDR_INDEX[1], VH_END) < 0) {
		APPLOG(APPLOG_ERR, "{{{INIT}}} sort vhdr set fail!");
		return -1;
	} else {
		print_relay_vhdr(VHDR_INDEX[1], VH_END);
	}

	/* http/2 option load */
	if (set_http2_option(&CLIENT_CONF) < 0) {
		APPLOG(APPLOG_ERR, "{{{INIT}}} set http/2 option fail!");
		return -1;
	}

	/* process start run */
	if (keepalivelib_init (myProcName) < 0) {
		APPLOG(APPLOG_ERR, "{{{INIT}}} keepalive init fail!");
		return -1;
	}

#ifdef OVLD_API
	/* for nssf overload control */
	if (api_ovld_init(myProcName) < 0) {
		APPLOG(APPLOG_ERR, "{{{INIT}}} ovldctrl init fail!");
	} else {
		APPLOG(APPLOG_ERR, "{{{INIT}}} ovldctrl init success!");
	}
#endif

	return 0;
}


int main(int argc, char **argv) 
{
	struct sigaction act;

	memset(&act, 0, sizeof(struct sigaction));
	act.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &act, NULL);

	if (initialize() < 0) {
		fprintf(stderr,"{{{INIT}}} httpc_initial fail!!!\n");
		return -1;
	}

	SSL_load_error_strings();
	SSL_library_init();

    /* create httpc send --> ahif conn */
	create_httpc_worker();
	create_lb_thread();

	sleep(3);

	main_loop();

	return 0;
}
