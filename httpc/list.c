#include "client.h"

extern client_conf_t CLIENT_CONF;
extern httpc_ctx_t *HttpcCtx[MAX_THRD_NUM];
extern conn_list_t CONN_LIST[MAX_SVR_NUM];
extern thrd_context_t THRD_WORKER[MAX_THRD_NUM];
extern http2_session_data_t SESS[MAX_THRD_NUM][MAX_SVR_NUM];

httpc_ctx_t *get_context(int thrd_idx, int ctx_idx, int used)
{
	if (thrd_idx < 0 || thrd_idx >= MAX_THRD_NUM)
		return NULL;
	if (ctx_idx < 0 || ctx_idx >= SIZEID)
		return NULL;

	if (used)
		if (HttpcCtx[thrd_idx][ctx_idx].occupied != 1)
			return NULL;

	return &HttpcCtx[thrd_idx][ctx_idx];
}
void clear_send_ctx(httpc_ctx_t *httpc_ctx)
{
	httpc_ctx->inflight_ref_cnt = 0;
	httpc_ctx->user_ctx.head.bodyLen = 0;
	httpc_ctx->user_ctx.head.queryLen = 0;
	httpc_ctx->user_ctx.head.vheaderCnt = 0;
	memset(httpc_ctx->user_ctx.vheader, 0x00, sizeof(hdr_relay) * MAX_HDR_RELAY_CNT);
}

void clear_and_free_ctx(httpc_ctx_t *httpc_ctx)
{
	httpc_ctx->tcp_wait = 0;
	httpc_ctx->inflight_ref_cnt = 0;
	httpc_ctx->user_ctx.head.bodyLen = 0;
	httpc_ctx->user_ctx.head.queryLen = 0;
	memset(httpc_ctx->user_ctx.vheader, 0x00, sizeof(hdr_relay) * MAX_HDR_RELAY_CNT);
	httpc_ctx->user_ctx.head.vheaderCnt = 0;
	httpc_ctx->for_nrfm_ctx = 0;
	httpc_ctx->occupied = 0;
}

void set_intl_req_msg(intl_req_t *intl_req, int thrd_idx, int ctx_idx, int sess_idx, int session_id, int stream_id, int msg_type)
{
	memset(intl_req, 0x00, sizeof(intl_req_t));
	intl_req->msgq_index = 1;					/* worker use personal msgq_id & type:0 */
	intl_req->tag.thrd_index = thrd_idx;
	intl_req->tag.ctx_id = ctx_idx;
	intl_req->tag.session_index = sess_idx;
	intl_req->tag.session_id = session_id;
	intl_req->tag.stream_id = stream_id;
	intl_req->intl_msg_type = msg_type;
}
http2_session_data_t *get_session(int thrd_idx, int sess_idx, int session_id)
{
	http2_session_data_t *session_data = NULL;

	if (thrd_idx < 0 || thrd_idx >= MAX_THRD_NUM)
		return NULL;
	if (sess_idx < 0 || sess_idx >= MAX_SVR_NUM)
		return NULL;

	session_data = &SESS[thrd_idx][sess_idx];

	if (session_data->used != 1)
		return NULL;
	if (session_data->session_id != session_id)
		return NULL;

	return session_data;
}
void save_session_info(httpc_ctx_t *httpc_ctx, int thrd_idx, int sess_idx, int session_id, int ctx_idx, conn_list_t *conn_list)
{
	httpc_ctx->thrd_idx = thrd_idx;
	httpc_ctx->sess_idx = sess_idx;
	httpc_ctx->session_id = session_id;
	httpc_ctx->ctx_idx = ctx_idx;
	sprintf(httpc_ctx->user_ctx.head.destType, "%s", conn_list->type);
	sprintf(httpc_ctx->user_ctx.head.destHost, "%s", conn_list->host);
	sprintf(httpc_ctx->user_ctx.head.destIp, "%s", conn_list->ip);
	httpc_ctx->user_ctx.head.destPort = conn_list->port;

    /* oauth 2.0 */
	char *token = NULL;
    if (conn_list->token_id > 0) {
        token = get_access_token(CLIENT_CONF.ACC_TOKEN_LIST, conn_list->token_id);
    }

	sprintf(httpc_ctx->access_token, "%s", token != NULL ? token : "");
}

int find_least_conn_worker()
{
    int i, thrd_id = 0, ls_cnt = 0;

    ls_cnt = THRD_WORKER[0].server_num;
    for (i = 0; i < CLIENT_CONF.worker_num; i++) {
        if (THRD_WORKER[i].server_num < ls_cnt) {
            thrd_id = i;
            ls_cnt = THRD_WORKER[i].server_num;
        }
    }

    return thrd_id;
}

// TODO!!! print NRF ref id 
void print_list(conn_list_status_t conn_status[]) {
    int i, j;

    APPLOG(APPLOG_ERR, "  ID HOSTNAME   TYPE       IP_ADDR                                         PORT CONN(max/curr)   ACT STATUS");
    APPLOG(APPLOG_ERR, "---------------------------------------------------------------------------------------------------------------");
    for ( i = 0; i < MAX_LIST_NUM; i++) {
        for ( j = 0; j < MAX_CON_NUM; j++) {
            if (conn_status[j].occupied != 1)	/* no occupied, just skip for save time */
                continue;
            if (conn_status[j].list_index != i) /* just for order result */
                continue;
            APPLOG(APPLOG_ERR, "%4d %-10s %-10s %-46s %5d (%4d  / %4d) %4d %s",
                    conn_status[j].list_index,	/* don't care */
                    conn_status[j].host,		/* udmbep, udmlb, ... */
                    conn_status[j].type,		/* udm, pcf, ... */
                    conn_status[j].ip,			/* 192.168.0.1 */
                    conn_status[j].port,		/* 7000 */
                    conn_status[j].sess_cnt,	/* don't care */
                    conn_status[j].conn_cnt,	/* if conn_cnt > 0 , ready to send */
                    conn_status[j].act,			/* don't care */
                    (conn_status[j].conn_cnt > 0) ?  "Connected" : (conn_status[j].act == 1) ? "Disconnect" : "Deact");
        }
    }
    APPLOG(APPLOG_ERR, "---------------------------------------------------------------------------------------------------------------");
}

/* watch out for buffer size */
void write_list(conn_list_status_t CONN_STATUS[], char *buff) {
	int i, j, resLen;

    resLen = sprintf(buff, "\n  ID HOSTNAME                                 TYPE   SCHEME   IP_ADDR                            PORT CONN(max/curr)    STATUS     TOKEN_ID  (AUTO_ADDED)\n");
    resLen += sprintf(buff + resLen, "----------------------------------------------------------------------------------------------------------------------------------------------------------\n");
	for ( i = 0; i < MAX_LIST_NUM; i++) {
		for ( j = 0; j < MAX_CON_NUM; j++) {
			if (CONN_STATUS[j].occupied != 1)
				continue;
			if (CONN_STATUS[j].list_index != i)
				continue;
			resLen += sprintf(buff + resLen, "%4d %-40s %-6s %-6s   %-33s %5d (%4d  / %4d)   %10s     %5d        %s\n",
					CONN_STATUS[j].list_index,
					CONN_STATUS[j].host,
					CONN_STATUS[j].type,
					CONN_STATUS[j].scheme,
					CONN_STATUS[j].ip,
					CONN_STATUS[j].port,
					CONN_STATUS[j].sess_cnt,
					CONN_STATUS[j].conn_cnt,
					(CONN_STATUS[j].conn_cnt > 0) ?  "Connected" : (CONN_STATUS[j].act == 1) ? "Disconnect" : "Deact",
					CONN_STATUS[j].token_id,
					(CONN_STATUS[j].nrfm_auto_added > NF_ADD_RAW) ? "O" : "X");
		}
	}
    sprintf(buff + resLen, "----------------------------------------------------------------------------------------------------------------------------------------------------------\n");
}

/* before gather, must be memset! */
void gather_list(conn_list_status_t CONN_STATUS[]) {
	int i, j, k, index = 0, find;

	/* item_index 가 -1 인 경우, hostname 만 있고 아직 ip 는 등록되지 않은 상태를 의미 */
	for (i = 0; i < MAX_SVR_NUM; i++) {
		if (CONN_LIST[i].used == 1 &&
				CONN_LIST[i].item_index == -1) {
			CONN_STATUS[index].list_index = CONN_LIST[i].list_index;
			CONN_STATUS[index].item_index = CONN_LIST[i].item_index;
			sprintf(CONN_STATUS[index].scheme, "%s", CONN_LIST[i].scheme);
			sprintf(CONN_STATUS[index].host, "%s", CONN_LIST[i].host);
			sprintf(CONN_STATUS[index].type, "%s", CONN_LIST[i].type);
			sprintf(CONN_STATUS[index].ip, "%s", "-");
			CONN_STATUS[index].port = 0;
			CONN_STATUS[index].act = 0;
			CONN_STATUS[index].occupied = 1;

            /* oauth 2.0 */
			int token_id = CONN_LIST[i].token_id;
			CONN_STATUS[index].token_id = token_id;

			if (token_id > 0) {
				char *access_token = get_access_token(CLIENT_CONF.ACC_TOKEN_LIST, CONN_LIST[i].token_id);
				CONN_STATUS[index].token_acquired = (access_token == NULL) ? 0 : 1;
			} else {
				CONN_STATUS[index].token_acquired = 1;
			}

			CONN_STATUS[index].nrfm_auto_added = CONN_LIST[i].nrfm_auto_added;
			index++;
		}
	}
	for (i = 0; i < MAX_LIST_NUM; i++) {
		for (j = 0; j < MAX_ITEM_NUM; j++) {
			for (k = 0, find = 0; k < MAX_SVR_NUM; k++) {
				if (CONN_LIST[k].used) {
					if (CONN_LIST[k].list_index == i && CONN_LIST[k].item_index == j) {
						if (find == 0) {
							index++; // it start from 1 ~
							find = 1;
							CONN_STATUS[index].list_index = i;
							CONN_STATUS[index].item_index = j;
							sprintf(CONN_STATUS[index].scheme, "%s", CONN_LIST[k].scheme);
							sprintf(CONN_STATUS[index].host, "%s", CONN_LIST[k].host);
							sprintf(CONN_STATUS[index].type, "%s", CONN_LIST[k].type);
							sprintf(CONN_STATUS[index].ip, "%s", CONN_LIST[k].ip);
							CONN_STATUS[index].port = CONN_LIST[k].port;
							CONN_STATUS[index].act = CONN_LIST[k].act;
							CONN_STATUS[index].occupied = 1;
						}
						CONN_STATUS[index].sess_cnt ++;
						if (CONN_LIST[k].conn == CN_CONNECTED) 
							CONN_STATUS[index].conn_cnt ++;

                        /* oauth 2.0 */
						int token_id = CONN_LIST[k].token_id;
						CONN_STATUS[index].token_id = token_id;

						if (token_id > 0) {
							char *access_token = get_access_token(CLIENT_CONF.ACC_TOKEN_LIST, CONN_LIST[k].token_id);
							CONN_STATUS[index].token_acquired = (access_token == NULL) ? 0 : 1;
						} else {
							CONN_STATUS[index].token_acquired = 1;
						}
						CONN_STATUS[index].nrfm_auto_added = CONN_LIST[k].nrfm_auto_added;
					}
				}
			}
		}
	}
}

// httpc outbound, log write with in 1step
void log_pkt_send(char *prefix, nghttp2_nv *hdrs, int hdrs_len, char *body, int body_len)
{
	FILE *temp_file = NULL;
	size_t file_size = 0;
	char *ptr = NULL;

	if (CLIENT_CONF.pkt_log != 1)
		return;

	temp_file = open_memstream(&ptr, &file_size); // buff size auto-grow
	if (temp_file == NULL) {
		APPLOG(APPLOG_ERR, "{{{PKT}}} in %s fail to call open_memstream!", __func__);
		return;
	}
	print_headers(temp_file, hdrs, hdrs_len);
	if (body_len > 0)
		util_dumphex(temp_file, body, body_len);

	// 1) close file
	fclose(temp_file);
	// 2) use ptr
	APPLOG(APPLOG_ERR, "{{{PKT}}} %s\n\
--------------------------------------------------------------------------------------------------\n\
%s\
==================================================================================================\n",
	prefix, ptr);
	// 3) free ptr
	free(ptr);
}

// httpc inbound, logwrite step 1 of 2 (headres receive)
void log_pkt_head_recv(httpc_ctx_t *httpc_ctx, const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen)
{
	if (CLIENT_CONF.pkt_log != 1)
		return;

	if (httpc_ctx->recv_log_file == NULL) {
		httpc_ctx->recv_log_file = open_memstream(&httpc_ctx->log_ptr, &httpc_ctx->file_size);
		if (httpc_ctx->recv_log_file == NULL) {
			APPLOG(APPLOG_ERR, "{{{PKT}}} in %s fail to call open_memstream!", __func__);
			// TODO fclose (*httpc/s ...)
			return;
		}
	}
	print_header(httpc_ctx->recv_log_file, name, namelen, value, valuelen);
}

// httpc inbound, logwrite step 2 of 2 (all of body received or stream closed)
void log_pkt_end_stream(int stream_id, httpc_ctx_t *httpc_ctx)
{
	if (CLIENT_CONF.pkt_log != 1)
		return;

	if (httpc_ctx->recv_log_file == NULL) {
		httpc_ctx->recv_log_file = open_memstream(&httpc_ctx->log_ptr, &httpc_ctx->file_size);
		if (httpc_ctx->recv_log_file == NULL) {
			APPLOG(APPLOG_ERR, "{{{PKT}}} in %s fail to call open_memstream!", __func__);
			return;
		}
	}
	// print body to log
	if (httpc_ctx->user_ctx.head.bodyLen > 0) {
#if 0
		util_dumphex(httpc_ctx->recv_log_file, httpc_ctx->user_ctx.body, httpc_ctx->user_ctx.head.bodyLen);
#else
		util_dumphex(httpc_ctx->recv_log_file, 
				httpc_ctx->user_ctx.data + httpc_ctx->user_ctx.head.queryLen,
				httpc_ctx->user_ctx.head.bodyLen);
#endif
	}

	// 1) close file
	fclose(httpc_ctx->recv_log_file);
	httpc_ctx->recv_log_file = NULL;
	// 2) use ptr
	APPLOG(APPLOG_ERR, "{{{PKT}}} HTTPC RECV http sess/stream(%d:%d) ahifCid(%d)]\n\
--------------------------------------------------------------------------------------------------\n\
%s\
==================================================================================================\n",
	httpc_ctx->session_id, 
	stream_id, 
	httpc_ctx->user_ctx.head.ahifCid,
	httpc_ctx->log_ptr);
	// 3) free ptr
	free(httpc_ctx->log_ptr);
	httpc_ctx->log_ptr = NULL;
}

void log_pkt_httpc_error_reply(httpc_ctx_t *httpc_ctx, int resp_code)
{
	if (CLIENT_CONF.pkt_log != 1)
		return;

	APPLOG(APPLOG_ERR, "{{{PKT}}} HTTPC INTERNAL ERROR http sess/stream(N/A:N/A) ahifCid(%d)]\n\
--------------------------------------------------------------------------------------------------\n\
:status:%d\n\
==================================================================================================\n",
	httpc_ctx->user_ctx.head.ahifCid, resp_code);
}
