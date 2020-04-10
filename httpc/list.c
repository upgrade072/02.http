#include "client.h"

extern int ixpcQid;
extern char mySysName[COMM_MAX_NAME_LEN];
extern char myProcName[COMM_MAX_NAME_LEN];

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

static void clear_trace_resource(httpc_ctx_t *httpc_ctx)
{
    if (httpc_ctx->send_log_file) {
        fclose(httpc_ctx->send_log_file);
        httpc_ctx->send_log_file = NULL;
    }
    if (httpc_ctx->recv_log_file) {
        fclose(httpc_ctx->recv_log_file);
        httpc_ctx->recv_log_file = NULL;
    }
    if (httpc_ctx->send_log_ptr) {
        free(httpc_ctx->send_log_ptr);
        httpc_ctx->send_log_ptr = NULL;
    }
    if (httpc_ctx->recv_log_ptr) {
        free(httpc_ctx->recv_log_ptr);
        httpc_ctx->recv_log_ptr = NULL;
    }
}

void clear_and_free_ctx(httpc_ctx_t *httpc_ctx)
{
    clear_trace_resource(httpc_ctx);
    httpc_ctx->user_ctx.head.subsTraceFlag = 0;
    memset(httpc_ctx->user_ctx.head.subsTraceId, 0x00, sizeof(httpc_ctx->user_ctx.head.subsTraceId));
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

void select_list(conn_list_status_t CONN_STATUS[], char *type) {
	for ( int i = 0; i < MAX_LIST_NUM; i++) {
        if (CONN_STATUS[i].occupied != 1)
            continue;
        if (strcmp(CONN_STATUS[i].type, type))
            CONN_STATUS[i].occupied = 0;
    }
}

/* watch out for buffer size */
void write_list(conn_list_status_t CONN_STATUS[], char *buff) {
	ft_table_t *table = ft_create_table();
	ft_set_border_style(table, FT_PLAIN_STYLE);

	/* head */
	ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);

	ft_write_ln(table, "ID", "HOSTNAME", "TYPE", "SCHEME", "IPADDR", "PORT", "CONN(max/curr)", "STATUS", "TOKEN_ID", "AUTO_ADDED", "TOMBSTONE_DATE");
	for ( int i = 0; i < MAX_LIST_NUM; i++) {
		for ( int j = 0; j < MAX_CON_NUM; j++) {
			if (CONN_STATUS[j].occupied != 1)
				continue;
			if (CONN_STATUS[j].list_index != i)
				continue;
			ft_printf_ln(table, "%d|%s|%s|%s|%s|%d|(%d/%d)|%s|%d|%s|%.24s",
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
				CONN_STATUS[j].nrfm_auto_added == NF_ADD_RAW ? " X " : 
				CONN_STATUS[j].nrfm_auto_added == NF_ADD_NRF ? "NRF" : "API",
				CONN_STATUS[j].tombstone_date != 0 ? ctime(&CONN_STATUS[j].tombstone_date) : "");
		}
	}
	ft_add_separator(table);
	sprintf(buff, "%s", ft_to_string(table));
	ft_destroy_table(table);
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
						if (CONN_LIST[k].conn == CN_CONNECTED) {
							CONN_STATUS[index].conn_cnt ++;
						} else {
							if (CONN_STATUS[index].conn_cnt == 0) { /* save last disconnected time */
								if (CONN_STATUS[index].tombstone_date <= CONN_LIST[k].tombstone_date) {
									CONN_STATUS[index].tombstone_date = CONN_LIST[k].tombstone_date;
								}
							}
						}

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
void log_pkt_send(httpc_ctx_t *httpc_ctx, nghttp2_nv *hdrs, int hdrs_len, const char *body, int body_len)
{
	if (CLIENT_CONF.pkt_log != 1 && CLIENT_CONF.trace_enable != 1)
		return;

    httpc_ctx->send_log_file = open_memstream(&httpc_ctx->send_log_ptr, &httpc_ctx->send_file_size);
    if (httpc_ctx->send_log_file == NULL) {
		APPLOG(APPLOG_ERR, "{{{PKT}}} in %s fail to call open_memstream!", __func__);
		return;
    } else {
        get_time_str(httpc_ctx->recv_time);
    }

	print_headers(httpc_ctx->send_log_file, hdrs, hdrs_len);
	if (body_len > 0) {
        fprintf(httpc_ctx->send_log_file, DUMPHEX_GUIDE_STR, httpc_ctx->user_ctx.head.bodyLen);
		util_dumphex(httpc_ctx->send_log_file, body, body_len);
    }
}

// httpc inbound, logwrite step 1 of 2 (headres receive)
void log_pkt_head_recv(httpc_ctx_t *httpc_ctx, const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen)
{
	if (CLIENT_CONF.pkt_log != 1 && CLIENT_CONF.trace_enable != 1)
		return;

	if (httpc_ctx->recv_log_file == NULL) {
		httpc_ctx->recv_log_file = open_memstream(&httpc_ctx->recv_log_ptr, &httpc_ctx->recv_file_size);
		if (httpc_ctx->recv_log_file == NULL) {
			APPLOG(APPLOG_ERR, "{{{PKT}}} in %s fail to call open_memstream!", __func__);
			return;
		} else {
            get_time_str(httpc_ctx->recv_time);
        }
    }
	print_header(httpc_ctx->recv_log_file, name, namelen, value, valuelen);
}

void send_trace_to_omp(httpc_ctx_t *httpc_ctx)
{
    int msg_len = 0;
    GeneralQMsgType GeneralMsg = {0,};

    IxpcQMsgType *ixpcMsg = (IxpcQMsgType *)&GeneralMsg.body;
    TraceMsgInfo *trcMsgInfo = (TraceMsgInfo *)(ixpcMsg->body);
    memset(trcMsgInfo, 0x00, sizeof(TraceMsgInfo) - TRC_MSG_BODY_MAX_LEN);

    GeneralMsg.mtype = MTYPE_TRACE_NOTIFICATION;
    strcpy(ixpcMsg->head.srcSysName, mySysName);
    strcpy(ixpcMsg->head.srcAppName, myProcName);
    strcpy(ixpcMsg->head.dstSysName, "OMP");
    strcpy(ixpcMsg->head.dstAppName, "COND");
    ixpcMsg->head.segFlag = 0;
    ixpcMsg->head.seqNo = 0;
    ixpcMsg->head.byteOrderFlag = 0x1234;

    // fflush
    if (httpc_ctx->send_log_file) {
        fflush(httpc_ctx->send_log_file);
    } else {
        httpc_ctx->send_log_ptr = NULL;
        httpc_ctx->send_time[0] = '\0';
    }
    if (httpc_ctx->recv_log_file) {
        fflush(httpc_ctx->recv_log_file);
    } else {
        httpc_ctx->recv_log_ptr = NULL;
        httpc_ctx->recv_time[0] = '\0';
    }

    // info
    char currTmStr[128] = {0,}; get_time_str(currTmStr);
    msg_len = sprintf(trcMsgInfo->trcMsg, "[%s] [%s]\n", mySysName, currTmStr);
    // ... //
    sprintf(trcMsgInfo->trcTime, "%s", currTmStr);
    trcMsgInfo->trcMsgType = TRCMSG_INIT_MSG;
    // ... //
    // slogan
    msg_len += sprintf(trcMsgInfo->trcMsg + strlen(trcMsgInfo->trcMsg), "S4000 HTTP/2 SEND-RECV PACKET\n");
    msg_len += sprintf(trcMsgInfo->trcMsg + strlen(trcMsgInfo->trcMsg), "  OPERATION        : HTTP/2 STACK Send Request / Recv Response\n");
    http2_session_data_t *session_data = get_session(httpc_ctx->thrd_idx, httpc_ctx->sess_idx, httpc_ctx->session_id);
    if (session_data != NULL) {
        msg_len += sprintf(trcMsgInfo->trcMsg + strlen(trcMsgInfo->trcMsg), "  SESS_INFO        : %s://%s (%s)\n",
                session_data->scheme, session_data->authority, session_data->host);
    }
    msg_len += sprintf(trcMsgInfo->trcMsg + strlen(trcMsgInfo->trcMsg), "  STRM_INFO        : SESS=(%d) STRM=(%d) ACID=(%d)\n",
            httpc_ctx->session_id, httpc_ctx->stream.stream_id, httpc_ctx->user_ctx.head.ahifCid);
    msg_len += sprintf(trcMsgInfo->trcMsg + strlen(trcMsgInfo->trcMsg), "  SND_TM           : %s\n", httpc_ctx->send_time);
    msg_len += sprintf(trcMsgInfo->trcMsg + strlen(trcMsgInfo->trcMsg), "  RCV_TM           : %s\n", httpc_ctx->recv_time);

    // check remain size
    int check_remain = sizeof(trcMsgInfo->trcMsg) - strlen(trcMsgInfo->trcMsg) 
        - strlen("[Send_Response]\n") 
        - strlen("[Recv_Request]\n") 
        - strlen("COMPLETE\n\n\n");
    int half_size = check_remain / 2;

    // snd msg trace
    msg_len += sprintf(trcMsgInfo->trcMsg + strlen(trcMsgInfo->trcMsg), "[Send_Response]\n");
    if (strlen(httpc_ctx->send_log_ptr) >= half_size) {
        msg_len += snprintf(trcMsgInfo->trcMsg + strlen(trcMsgInfo->trcMsg), half_size - 1, "%s", httpc_ctx->send_log_ptr);
        msg_len += sprintf(trcMsgInfo->trcMsg + strlen(trcMsgInfo->trcMsg), "\n");
    } else {
        msg_len += snprintf(trcMsgInfo->trcMsg + strlen(trcMsgInfo->trcMsg), half_size, "%s", httpc_ctx->send_log_ptr);
    }
    // rcv msg trace
    msg_len += sprintf(trcMsgInfo->trcMsg + strlen(trcMsgInfo->trcMsg), "[Recv_Request]\n");
    if (strlen(httpc_ctx->recv_log_ptr) >= half_size) {
        msg_len += snprintf(trcMsgInfo->trcMsg + strlen(trcMsgInfo->trcMsg), half_size - 1, "%s", httpc_ctx->recv_log_ptr);
        msg_len += sprintf(trcMsgInfo->trcMsg + strlen(trcMsgInfo->trcMsg), "\n");
    } else {
        msg_len += sprintf(trcMsgInfo->trcMsg + strlen(trcMsgInfo->trcMsg), "%s", httpc_ctx->recv_log_ptr);
    }
    // trace end
    msg_len += sprintf(trcMsgInfo->trcMsg + strlen(trcMsgInfo->trcMsg), "COMPLETE\n\n\n");

    //ixpcMsg->head.bodyLen = msg_len;
    ixpcMsg->head.bodyLen = sizeof(TraceMsgInfo)-TRC_MSG_BODY_MAX_LEN + msg_len + 8;

    if (CLIENT_CONF.pkt_log == 1) {
        APPLOG(APPLOG_ERR, "\n\n%s", trcMsgInfo->trcMsg);
    }
    if (CLIENT_CONF.trace_enable == 1 && httpc_ctx->user_ctx.head.subsTraceFlag == 1) {
        if (msgsnd(ixpcQid, (char *)&GeneralMsg, ixpcMsg->head.bodyLen + sizeof(long) + sizeof(ixpcMsg->head), IPC_NOWAIT) < 0) {
            APPLOG(APPLOG_ERR, "{{{DBG}}} %s fail to send send trace, errno(%d), (%s)", __func__, errno, strerror(errno));
        }
    }
}

// httpc inbound, logwrite step 2 of 2 (all of body received or stream closed)
void log_pkt_end_stream(httpc_ctx_t *httpc_ctx)
{
	if (CLIENT_CONF.pkt_log != 1 && CLIENT_CONF.trace_enable != 1) {
        return;
    }

	if (httpc_ctx->recv_log_file == NULL) {
		httpc_ctx->recv_log_file = open_memstream(&httpc_ctx->recv_log_ptr, &httpc_ctx->recv_file_size);
		if (httpc_ctx->recv_log_file == NULL) {
			APPLOG(APPLOG_ERR, "{{{PKT}}} in %s fail to call open_memstream!", __func__);
			return clear_trace_resource(httpc_ctx);
        } else {
            get_time_str(httpc_ctx->recv_time);
        }
	}

	// print body to log
	if (httpc_ctx->user_ctx.head.bodyLen > 0) {
        fprintf(httpc_ctx->recv_log_file, DUMPHEX_GUIDE_STR, httpc_ctx->user_ctx.head.bodyLen);
		util_dumphex(httpc_ctx->recv_log_file, 
				httpc_ctx->user_ctx.data + httpc_ctx->user_ctx.head.queryLen,
				httpc_ctx->user_ctx.head.bodyLen);
	}

    send_trace_to_omp(httpc_ctx);

    return;
}

void log_pkt_httpc_error_reply(httpc_ctx_t *httpc_ctx, int resp_code)
{
    if (CLIENT_CONF.pkt_log != 1)
        return;

    APPLOG(APPLOG_ERR, "{{{PKT}}} http/2 send request internal error(%d), ahifCid=(%d)", resp_code, httpc_ctx->user_ctx.head.ahifCid);
}

void log_pkt_httpc_reset(httpc_ctx_t *httpc_ctx)
{
    if (CLIENT_CONF.pkt_log != 1 && CLIENT_CONF.trace_enable != 1)
        return;

    APPLOG(APPLOG_ERR, "{{{PKT}}} http/2 send request / stream ressetted, ahifCid=(%d)", httpc_ctx->user_ctx.head.ahifCid);

    send_trace_to_omp(httpc_ctx);
}
