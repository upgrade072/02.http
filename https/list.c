#include "server.h"

extern int ixpcQid;
extern char mySysName[COMM_MAX_NAME_LEN];
extern char myProcName[COMM_MAX_NAME_LEN];

extern thrd_context THRD_WORKER[MAX_THRD_NUM];
extern allow_list_t  ALLOW_LIST[MAX_LIST_NUM];
extern https_ctx_t *HttpsCtx[MAX_THRD_NUM];
extern http2_session_data SESS[MAX_THRD_NUM][MAX_SVR_NUM];
extern server_conf SERVER_CONF;

https_ctx_t *get_context(int thrd_idx, int ctx_idx, int used)
{
    if (thrd_idx < 0 || thrd_idx >= MAX_THRD_NUM)
        return NULL;
    if (ctx_idx < 0 || ctx_idx >= SIZEID)
        return NULL;

    if (used)
        if (HttpsCtx[thrd_idx][ctx_idx].occupied != 1)
            return NULL;

    return &HttpsCtx[thrd_idx][ctx_idx];
}

/* if new context assigned, remove old info */
void clear_new_ctx(https_ctx_t *https_ctx)
{
	https_ctx->inflight_ref_cnt = 0;
    memset(&https_ctx->user_ctx.head, 0x00, AHIF_HTTPCS_MSG_HEAD_LEN);
	memset(https_ctx->user_ctx.vheader, 0x00, sizeof(hdr_relay) * MAX_HDR_RELAY_CNT);
}

void assign_new_ctx_info(https_ctx_t *https_ctx, http2_session_data *session_data, http2_stream_data *stream_data)
{
	https_ctx->user_ctx.head.mtype = MTYPE_HTTP2_REQUEST_HTTPS_TO_AHIF;
	https_ctx->user_ctx.head.thrd_index = session_data->thrd_index;
	https_ctx->user_ctx.head.session_index = session_data->session_index;
	https_ctx->user_ctx.head.session_id = session_data->session_id;
	https_ctx->user_ctx.head.stream_id = stream_data->stream_id;
	sprintf(https_ctx->user_ctx.head.destType, "%s", session_data->type);
	sprintf(https_ctx->user_ctx.head.destHost, "%s", session_data->hostname);

	if (session_data->is_direct_session) {
		https_ctx->is_direct_ctx = 1;
		https_ctx->relay_fep_tag = session_data->relay_fep_tag;
	} else {
		https_ctx->is_direct_ctx = 0;
		https_ctx->relay_fep_tag = 0;
	}
}

void assign_rcv_ctx_info(https_ctx_t *https_ctx, AhifHttpCSMsgType *ResMsg)
{
	https_ctx->user_ctx.head.subsTraceFlag = ResMsg->head.subsTraceFlag;
    memcpy(https_ctx->user_ctx.head.subsTraceId, ResMsg->head.subsTraceId, sizeof(https_ctx->user_ctx.head.subsTraceId));
	https_ctx->user_ctx.head.respCode = ResMsg->head.respCode;
	https_ctx->user_ctx.head.vheaderCnt = ResMsg->head.vheaderCnt;
	memcpy(&https_ctx->user_ctx.vheader, ResMsg->vheader, sizeof(hdr_relay) * ResMsg->head.vheaderCnt);
	https_ctx->user_ctx.head.queryLen = ResMsg->head.queryLen;
	https_ctx->user_ctx.head.bodyLen = ResMsg->head.bodyLen;
	memcpy(&https_ctx->user_ctx.data, ResMsg->data, 
			ResMsg->head.queryLen + ResMsg->head.bodyLen);
}

static void clear_trace_resource(https_ctx_t *https_ctx)
{
    if (https_ctx->recv_log_file) {
        fclose(https_ctx->recv_log_file);
        https_ctx->recv_log_file = NULL;
    }
    if (https_ctx->send_log_file) {
        fclose(https_ctx->send_log_file);
        https_ctx->send_log_file = NULL;
    }
    if (https_ctx->recv_log_ptr) {
        free(https_ctx->recv_log_ptr);
        https_ctx->recv_log_ptr = NULL;
    }
    if (https_ctx->send_log_ptr) {
        free(https_ctx->send_log_ptr);
        https_ctx->send_log_ptr = NULL;
    }
}

void clear_and_free_ctx(https_ctx_t *https_ctx)
{
    clear_trace_resource(https_ctx);
	https_ctx->user_ctx.head.subsTraceFlag = 0;
    memset(https_ctx->user_ctx.head.subsTraceId, 0x00, sizeof(https_ctx->user_ctx.head.subsTraceId));
	https_ctx->inflight_ref_cnt = 0;
	https_ctx->user_ctx.head.bodyLen = 0;
	https_ctx->user_ctx.head.queryLen = 0;
	https_ctx->user_ctx.head.vheaderCnt = 0;
	memset(https_ctx->user_ctx.vheader, 0x00, sizeof(hdr_relay) * MAX_HDR_RELAY_CNT);
	https_ctx->occupied = 0;
}
          
void set_intl_req_msg(intl_req_t *intl_req, int thrd_idx, int ctx_idx, int sess_idx, int session_id, int stream_id, int msg_type)
{         
    memset(intl_req, 0x00, sizeof(intl_req_t));
	intl_req->msgq_index = 1;					/* worker use personal msg_id & type:0 */
    intl_req->tag.thrd_index = thrd_idx;
    intl_req->tag.ctx_id = ctx_idx;
    intl_req->tag.session_index = sess_idx;
    intl_req->tag.session_id = session_id;
    intl_req->tag.stream_id = stream_id;
    intl_req->intl_msg_type = msg_type;
}   

http2_session_data *get_session(int thrd_idx, int sess_idx, int session_id)
{
    struct http2_session_data *session_data = NULL;

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
void save_session_info(https_ctx_t *https_ctx, int thrd_idx, int sess_idx, int session_id, char *ipaddr)
{
    https_ctx->thrd_idx = thrd_idx;
    https_ctx->sess_idx = sess_idx;
    https_ctx->session_id = session_id;
	sprintf(https_ctx->user_ctx.head.destIp, "%s", ipaddr);
}

int accept_with_anyclient(char *ip)
{
    // assign new index
    int list_index = new_list(ip);
    int item_index = list_index > 0 ? new_item(list_index, ip, 0) : -1;

    if (list_index < 0 || item_index < 0) {
        APPLOG(APPLOG_ERR, "%s() fail to add list-item index", __func__);
        if (list_index > 0)
            del_list(ip);
        if (item_index > 0)
            del_item(list_index, ip, 0);
        return (-1);
    }

    // find empty slot & new assign
    for (int i = 1; i < MAX_LIST_NUM; i++) {
        if (ALLOW_LIST[i].used == 0) {
            memset(&ALLOW_LIST[i], 0x00, sizeof(allow_list_t));
            ALLOW_LIST[i].index = i;
            ALLOW_LIST[i].used = 1;
            ALLOW_LIST[i].list_index = list_index;
            ALLOW_LIST[i].item_index = item_index;
            sprintf(ALLOW_LIST[i].type, "NF_AUTO_ADD");
            sprintf(ALLOW_LIST[i].host, ip);
            sprintf(ALLOW_LIST[i].ip, ip);
            ALLOW_LIST[i].act = 1;
            ALLOW_LIST[i].max = SERVER_CONF.any_client_default_max;
            ALLOW_LIST[i].curr++;
#if 0
            ALLOW_LIST[i].auth_act = 1;
#else
            ALLOW_LIST[i].auth_act = SERVER_CONF.any_client_oauth_check;
#endif
            ALLOW_LIST[i].auto_added = 1;
            return i;
        }
    }

    return (-1);
}

// schlee, if ip-match == allow, else, disconnect
int check_allow(char *ip, int allow_any_client)
{
	/* if ipv4 connected case */
	if (!strncmp(ip, "::ffff:", strlen("::ffff:")))
		ip += strlen("::ffff:");

    int its_blocked_address = 0;

    for (int i = 1; i < MAX_LIST_NUM; i++) {
        if (ALLOW_LIST[i].used != 1)
            continue;
        if (!strcmp(ip, ALLOW_LIST[i].ip)) {
            if ((ALLOW_LIST[i].act == 1) && (ALLOW_LIST[i].curr < ALLOW_LIST[i].max)) {
                ALLOW_LIST[i].curr++;
                return i;
            } if (ALLOW_LIST[i].act == 0) {
                its_blocked_address = 1;
            }
        }
    }

    if (allow_any_client && !its_blocked_address)
        return accept_with_anyclient(ip);
    else
        return (-1);
}

int add_to_allowlist(int list_idx, int thrd_idx, int sess_idx, int session_id)
{
    int i, found = -1;
    for (i = 0; i < MAX_SVR_NUM; i++) {
        if (ALLOW_LIST[list_idx].client[i].occupied)
            continue;
        ALLOW_LIST[list_idx].client[i].occupied = 1;
        ALLOW_LIST[list_idx].client[i].thrd_idx = thrd_idx;
        ALLOW_LIST[list_idx].client[i].sess_idx = sess_idx;
        ALLOW_LIST[list_idx].client[i].session_id = session_id;
		found = 1;
		break;
    }
    return found;
}
int del_from_allowlist(int list_idx, int thrd_idx, int sess_idx)
{
    int i, found = -1;
    for (i = 0; i < MAX_SVR_NUM; i++) {
        if (!ALLOW_LIST[list_idx].client[i].occupied)
            continue;
		if (ALLOW_LIST[list_idx].client[i].thrd_idx == thrd_idx &&
				ALLOW_LIST[list_idx].client[i].sess_idx == sess_idx) {
			ALLOW_LIST[list_idx].client[i].occupied = 0;
			found = 1;
			break;
		}
    }
    return found;
}

void disconnect_all_client_in_allow_list(allow_list_t *allow_list)
{
    intl_req_t intl_req = {0,};

    for (int k = 0; k < MAX_SVR_NUM; k++) {
        if (allow_list->client[k].occupied != 1)
            continue;
        conn_client_t *client_conn = &allow_list->client[k];
        int thrd_idx = client_conn->thrd_idx;

        APPLOG(APPLOG_DEBUG, "%s() delete thrd %d sess %d", __func__, client_conn->thrd_idx, client_conn->sess_idx);
        set_intl_req_msg(&intl_req, client_conn->thrd_idx, 0, client_conn->sess_idx, client_conn->session_id, 0, HTTP_INTL_SESSION_DEL);

        if (-1 == msgsnd(THRD_WORKER[thrd_idx].msg_id, &intl_req, sizeof(intl_req) - sizeof(long), IPC_NOWAIT)) {
            APPLOG(APPLOG_ERR, "%s() msg snd fail!!! (msgq_idx %ld thrd_idx %d session_idx %d)",
                    __func__, intl_req.msgq_index, intl_req.tag.thrd_index, intl_req.tag.session_index);
        }
        memset(&intl_req, 0x00, sizeof(intl_req_t));
    }
}

void print_list()
{
    int i, j;

    APPLOG(APPLOG_ERR, "  ID   HOSTNAME   TYPE       IP_ADDR                                    CONN(max/curr)         OAUTH    STATUS");
	APPLOG(APPLOG_ERR, "------------------------------------------------------------------------------------------------------------------");
    for ( i = 0; i < MAX_LIST_NUM; i++) {
        for ( j = 0; j < MAX_LIST_NUM; j++) {
            if (ALLOW_LIST[j].used != 1)
                continue;
            if (ALLOW_LIST[j].list_index != i)
                continue;
            APPLOG(APPLOG_ERR, "%4d   %-10s %-7s %-46s(%4d  / %4d)          %4s    %s",
                    ALLOW_LIST[j].list_index,
                    ALLOW_LIST[j].host,
                    ALLOW_LIST[j].type,
                    ALLOW_LIST[j].ip,
                    ALLOW_LIST[j].max,
                    ALLOW_LIST[j].curr,
                    (ALLOW_LIST[j].auth_act > 0) ?  "ACT" : "DACT",
                    (ALLOW_LIST[j].curr > 0) ?  "Connected" : (ALLOW_LIST[j].act == 1) ? "Disconnect" : "Deact");
        }
    }
	APPLOG(APPLOG_ERR, "------------------------------------------------------------------------------------------------------------------");
}

void write_list(char *buff) {
	ft_table_t *table = ft_create_table();
	ft_set_border_style(table, FT_PLAIN_STYLE);

	/* head */
	ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);

	/* TPS, CONN, OAUTH right align */
	ft_set_cell_prop(table, FT_ANY_ROW, 4, FT_CPROP_TEXT_ALIGN, FT_ALIGNED_RIGHT);
	ft_set_cell_prop(table, FT_ANY_ROW, 5, FT_CPROP_TEXT_ALIGN, FT_ALIGNED_RIGHT);
	ft_set_cell_prop(table, FT_ANY_ROW, 6, FT_CPROP_TEXT_ALIGN, FT_ALIGNED_RIGHT);
	ft_set_cell_prop(table, FT_ANY_ROW, 7, FT_CPROP_TEXT_ALIGN, FT_ALIGNED_CENTER);

	ft_write_ln(table, "ID", "HOSTNAME", "TYPE", "IPADDR", "TPS(limit/curr/drop)", "CONN(max/curr)", "OAUTH", "STATUS", "TOMBSTONE_DATE");
    for (int i = 0; i < MAX_LIST_NUM; i++) {
        for (int k = 0; k < MAX_LIST_NUM; k++) {
            if (ALLOW_LIST[k].used != 1)
                continue;
            if (ALLOW_LIST[k].list_index != i)
                continue;
            ft_printf_ln(table, "%d|%s|%s|%s|%d/%d/%d|%d/%d|%s|%s|%.24s",
                    ALLOW_LIST[k].list_index,
                    ALLOW_LIST[k].host,
                    ALLOW_LIST[k].type,
                    ALLOW_LIST[k].ip,
                    ALLOW_LIST[k].limit_tps,
                    ALLOW_LIST[k].last_curr_tps,
                    ALLOW_LIST[k].last_drop_tps,
                    ALLOW_LIST[k].max,
                    ALLOW_LIST[k].curr,
                    (ALLOW_LIST[k].auth_act > 0) ?  "ACT" : "DACT",
                    (ALLOW_LIST[k].curr > 0) ?  "Connected" : (ALLOW_LIST[k].act == 1) ? "Disconnect" : "Deact",
                    (ALLOW_LIST[k].auto_added == 1 && ALLOW_LIST[k].curr == 0) ? ctime(&ALLOW_LIST[k].tombstone_date) : ""); 
        }
    }
	ft_add_separator(table);
	sprintf(buff, "%s", ft_to_string(table));
	ft_destroy_table(table);
}

void send_trace_to_omp(https_ctx_t *https_ctx)
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
    if (https_ctx->recv_log_file) {
        fflush(https_ctx->recv_log_file);
    } else {
        https_ctx->recv_log_ptr = NULL;
        https_ctx->recv_time[0] = '\0';
    }
    if (https_ctx->send_log_file) {
        fflush(https_ctx->send_log_file);
    } else {
        https_ctx->send_log_ptr = NULL;
        https_ctx->send_time[0] = '\0';
    }

    // info
    char currTmStr[128] = {0,}; get_time_str(currTmStr);
    msg_len = sprintf(trcMsgInfo->trcMsg, "[%s] [%s]\n", mySysName, currTmStr);
    // ... //
    sprintf(trcMsgInfo->trcTime, "%s", currTmStr);
    trcMsgInfo->trcMsgType = TRCMSG_INIT_MSG;
    // ... //
    // slogan
    msg_len += sprintf(trcMsgInfo->trcMsg + strlen(trcMsgInfo->trcMsg), "S4000 HTTP/2 RECV SEND PACKET\n");
    msg_len += sprintf(trcMsgInfo->trcMsg + strlen(trcMsgInfo->trcMsg), "  OPERATION        : HTTP/2 STACK Recv Request / Send Response\n");
    // trace info
    if (https_ctx->user_ctx.head.subsTraceFlag) {
        msg_len += sprintf(trcMsgInfo->trcMsg + strlen(trcMsgInfo->trcMsg), "  TRACE_ID         : %s\n", https_ctx->user_ctx.head.subsTraceId);
    }
    http2_session_data *session_data = get_session(https_ctx->thrd_idx, https_ctx->sess_idx, https_ctx->session_id);
    if (session_data != NULL) {
        msg_len += sprintf(trcMsgInfo->trcMsg + strlen(trcMsgInfo->trcMsg), "  SESS_INFO        : %s://%s:%d (%s)\n",
                session_data->scheme, 
                !strncmp(session_data->client_addr, "::ffff:", strlen("::ffff:")) ? session_data->client_addr + strlen("::ffff:") : session_data->client_addr,
                session_data->client_port, 
                session_data->hostname); 
    }
    msg_len += sprintf(trcMsgInfo->trcMsg + strlen(trcMsgInfo->trcMsg), "  STRM_INFO        : SESS=(%d) STRM=(%d) ACID=(%d)\n", 
            https_ctx->session_id, https_ctx->user_ctx.head.stream_id, https_ctx->user_ctx.head.ahifCid);
    msg_len += sprintf(trcMsgInfo->trcMsg + strlen(trcMsgInfo->trcMsg), "  RCV_TM           : %s\n", https_ctx->recv_time);
    msg_len += sprintf(trcMsgInfo->trcMsg + strlen(trcMsgInfo->trcMsg), "  SND_TM           : %s\n", https_ctx->send_time);

    // check remain size
    int check_remain = sizeof(trcMsgInfo->trcMsg) - strlen(trcMsgInfo->trcMsg)
        - strlen("[Recv_Request]\n")
        - strlen("[Send_Response]\n")
        - strlen("COMPLETE\n\n\n");
    int half_size = check_remain / 2;

    // rcv msg trace
    msg_len += sprintf(trcMsgInfo->trcMsg + strlen(trcMsgInfo->trcMsg), "[Recv_Request]\n");
    if (https_ctx->recv_log_ptr != NULL && strlen(https_ctx->recv_log_ptr) >= half_size) {
        msg_len += snprintf(trcMsgInfo->trcMsg + strlen(trcMsgInfo->trcMsg), half_size - 1, "%s", https_ctx->recv_log_ptr);
        msg_len += sprintf(trcMsgInfo->trcMsg + strlen(trcMsgInfo->trcMsg), "\n");
    } else {
        msg_len += sprintf(trcMsgInfo->trcMsg + strlen(trcMsgInfo->trcMsg), "%s", https_ctx->recv_log_ptr);
    }
    // snd msg trace
    msg_len += sprintf(trcMsgInfo->trcMsg + strlen(trcMsgInfo->trcMsg), "[Send_Response]\n");
    if (https_ctx->send_log_ptr != NULL && strlen(https_ctx->send_log_ptr) >= half_size) {
        msg_len += snprintf(trcMsgInfo->trcMsg + strlen(trcMsgInfo->trcMsg), half_size - 1, "%s", https_ctx->send_log_ptr);
        msg_len += sprintf(trcMsgInfo->trcMsg + strlen(trcMsgInfo->trcMsg), "\n");
    } else {
        msg_len += sprintf(trcMsgInfo->trcMsg + strlen(trcMsgInfo->trcMsg), "%s", https_ctx->send_log_ptr);
    }
    // trace end
    msg_len += sprintf(trcMsgInfo->trcMsg + strlen(trcMsgInfo->trcMsg), "COMPLETE\n\n\n");

    //ixpcMsg->head.bodyLen = msg_len;
    ixpcMsg->head.bodyLen = sizeof(TraceMsgInfo)-TRC_MSG_BODY_MAX_LEN + msg_len + 8;
    if (SERVER_CONF.pkt_log == 1) {
        APPLOG(APPLOG_ERR, "\n\n%s", trcMsgInfo->trcMsg);
    }
    if (SERVER_CONF.trace_enable == 1 && https_ctx->user_ctx.head.subsTraceFlag == 1) {
        if (msgsnd(ixpcQid, (char *)&GeneralMsg, ixpcMsg->head.bodyLen + sizeof(long) + sizeof(ixpcMsg->head), IPC_NOWAIT) < 0) {
            APPLOG(APPLOG_ERR, "{{{DBG}}} %s fail to send send trace, errno(%d), (%s)", __func__, errno, strerror(errno));
        }
    }

}

// https outbound, log write with in 1step
void log_pkt_send(https_ctx_t *https_ctx, nghttp2_nv *hdrs, int hdrs_len, const char *body, int body_len)
{
    if (SERVER_CONF.pkt_log != 1 && SERVER_CONF.trace_enable != 1)
        return;

    https_ctx->send_log_file = open_memstream(&https_ctx->send_log_ptr, &https_ctx->send_file_size);
    if (https_ctx->send_log_file == NULL) {
        APPLOG(APPLOG_ERR, "{{{PKT}}} in %s fail to call open_memstream!", __func__);
        return;
    } else {
        get_time_str(https_ctx->send_time);
    }

    print_headers(https_ctx->send_log_file, hdrs, hdrs_len);
    if (body_len > 0) {
        fprintf(https_ctx->send_log_file, DUMPHEX_GUIDE_STR, body_len);
        util_dumphex(https_ctx->send_log_file, body, body_len);
    }

    send_trace_to_omp(https_ctx);

    return;
}

// https inbound, logwrite step 1 of 2 (headres receive)
void log_pkt_head_recv(https_ctx_t *https_ctx, const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen)
{
    if (SERVER_CONF.pkt_log != 1 && SERVER_CONF.trace_enable != 1)
        return;

    if (https_ctx->recv_log_file == NULL) {
        https_ctx->recv_log_file = open_memstream(&https_ctx->recv_log_ptr, &https_ctx->recv_file_size);
		if (https_ctx->recv_log_file == NULL) {
			APPLOG(APPLOG_ERR, "{{{PKT}}} in %s fail to call open_memstream!", __func__);
			return;
		} else {
            get_time_str(https_ctx->recv_time);
        }
    }
    print_header(https_ctx->recv_log_file, name, namelen, value, valuelen);
}

// https inbound, logwrite step 2 of 2 (all of body received or stream closed)
void log_pkt_end_stream(int stream_id, https_ctx_t *https_ctx)
{
    if (SERVER_CONF.pkt_log != 1)
        return;

    if (https_ctx->recv_log_file == NULL) {
        https_ctx->recv_log_file = open_memstream(&https_ctx->recv_log_ptr, &https_ctx->recv_file_size);
		if (https_ctx->recv_log_file == NULL) {
			APPLOG(APPLOG_ERR, "{{{PKT}}} in %s fail to call open_memstream!", __func__);
			return;
		} else {
            get_time_str(https_ctx->recv_time);
        }
    }
	if (https_ctx->user_ctx.head.bodyLen > 0) {
        fprintf(https_ctx->recv_log_file, DUMPHEX_GUIDE_STR, https_ctx->user_ctx.head.bodyLen);
		util_dumphex(https_ctx->recv_log_file, 
				https_ctx->user_ctx.data + https_ctx->user_ctx.head.queryLen,
				https_ctx->user_ctx.head.bodyLen);
	}
}

int get_uuid_from_associate(uuid_list_t *uuid_list)
{
    char fname[1024] = {0,};
    sprintf(fname, "%s/%s", getenv(IV_HOME), ASSOCONF_FILE);

    char syscmd[1024] = {0,}; // --> command
    char res_str[1024] = {0,}; // --> result

    /* GET MY TYPE */
    sprintf(syscmd, "grep %s %s | awk '{print $3}'", getenv(MY_SYS_NAME), fname);

    FILE *ptr_syscmd = popen(syscmd, "r");
    if (ptr_syscmd == NULL) {
        APPLOG(APPLOG_ERR, "{{{DBG}}} %s() fail to run syscmd [%s]", __func__, syscmd);
        return (-1);
    }

    char *result = fgets(res_str, 1024, ptr_syscmd);
    if (result == NULL || strlen(res_str) == 0) {
        APPLOG(APPLOG_ERR, "{{{DBG}}} %s() fail to find [MY_SYS_NAME:%s] from file [%s]",
                __func__, getenv(MY_SYS_NAME), fname);
        pclose(ptr_syscmd);
        return (-1);
    }
    res_str[strlen(res_str) -1] = '\0'; // remove newline
    pclose(ptr_syscmd);

    char my_type[1024] = {0,};
    sprintf(my_type, res_str);

    /* GET PEER UUIDS */
    sprintf(syscmd, "grep %s %s | awk '{print $11}'", my_type, fname);

    ptr_syscmd = popen(syscmd, "r");
    if (ptr_syscmd == NULL) {
        APPLOG(APPLOG_ERR, "{{{DBG}}} %s() fail to run syscmd [%s]", __func__, syscmd);
        return (-1);
    }

    int count = 0;
    while (fgets(res_str, 1024, ptr_syscmd) != NULL) {
        int current = count++;
        res_str[strlen(res_str) -1] = '\0';

        uuid_list->peer_nfs_num = count;
        sprintf(uuid_list->uuid[current], res_str);
    }
    pclose(ptr_syscmd);

    return uuid_list->peer_nfs_num;
}
