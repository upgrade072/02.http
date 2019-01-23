#include "server.h"

extern allow_list_t  ALLOW_LIST[MAX_LIST_NUM];
extern https_ctx_t *HttpsCtx[MAX_THRD_NUM];
extern http2_session_data SESS[MAX_THRD_NUM][MAX_SVR_NUM];

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
}

void assign_new_ctx_info(https_ctx_t *https_ctx, http2_session_data *session_data, http2_stream_data *stream_data)
{
	https_ctx->user_ctx.head.mtype = MTYPE_HTTP2_REQUEST_HTTPS_TO_AHIF;
	https_ctx->user_ctx.head.thrd_index = session_data->thrd_index;
	https_ctx->user_ctx.head.session_index = session_data->session_index;
	https_ctx->user_ctx.head.session_id = session_data->session_id;
	https_ctx->user_ctx.head.stream_id = stream_data->stream_id;
	sprintf(https_ctx->user_ctx.head.destHost, "%s", session_data->hostname);
	sprintf(https_ctx->user_ctx.head.destType, "%s", session_data->type);
}

void assign_rcv_ctx_info(https_ctx_t *https_ctx, AhifHttpCSMsgType *ResMsg)
{
	sprintf(https_ctx->user_ctx.head.contentEncoding, "%s", ResMsg->head.contentEncoding);
	https_ctx->user_ctx.head.respCode = ResMsg->head.respCode;
	https_ctx->user_ctx.head.bodyLen = ResMsg->head.bodyLen;
	memcpy(&https_ctx->user_ctx.body, ResMsg->body, ResMsg->head.bodyLen);
}

void clear_and_free_ctx(https_ctx_t *https_ctx)
{
	https_ctx->inflight_ref_cnt = 0;
	https_ctx->user_ctx.head.bodyLen = 0;
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

// schlee, if ip-match == allow, else, disconnect
int check_allow(char *ip)
{
    int i;

	/* if ipv4 connected case */
	if (!strncmp(ip, "::ffff:", strlen("::ffff:")))
		ip += strlen("::ffff:");

    for (i = 1; i < MAX_LIST_NUM; i++) {
        if (ALLOW_LIST[i].used != 1)
            continue;
        if (!strcmp(ip, ALLOW_LIST[i].ip) &&
                (ALLOW_LIST[i].act == 1) &&
                (ALLOW_LIST[i].curr < ALLOW_LIST[i].max)) {
            ALLOW_LIST[i].curr++;
            /*  return allow list index */
            return i;
        }
    }
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

void print_list()
{
    int i, j;

    APPLOG(APPLOG_ERR, "  ID   HOSTNAME   TYPE       IP_ADDR                                            CONN(max/curr)   ACT STATUS");
	APPLOG(APPLOG_ERR, "------------------------------------------------------------------------------------------------------------------");
    for ( i = 0; i < MAX_LIST_NUM; i++) {
        for ( j = 0; j < MAX_LIST_NUM; j++) {
            if (ALLOW_LIST[j].used != 1)
                continue;
            if (ALLOW_LIST[j].list_index != i)
                continue;
            APPLOG(APPLOG_ERR, "%4d   %-10s %-7s %-46s       (%4d  / %4d)  %4d %s",
                    ALLOW_LIST[j].list_index,
                    ALLOW_LIST[j].host,
                    ALLOW_LIST[j].type,
                    ALLOW_LIST[j].ip,
                    ALLOW_LIST[j].max,
                    ALLOW_LIST[j].curr,
                    ALLOW_LIST[j].act,
                    (ALLOW_LIST[j].curr > 0) ?  "Connected" : (ALLOW_LIST[j].act == 1) ? "Disconnect" : "Deact");
        }
    }
	APPLOG(APPLOG_ERR, "------------------------------------------------------------------------------------------------------------------");
}

void write_list(char *buff) {
    int i, j, resLen;

    resLen = sprintf(buff, "\n  ID   HOSTNAME   TYPE       IP_ADDR                                            CONN(max/curr)       STATUS\n");
	resLen += sprintf(buff + resLen, "------------------------------------------------------------------------------------------------------------------\n");
    for ( i = 0; i < MAX_LIST_NUM; i++) {
        for ( j = 0; j < MAX_LIST_NUM; j++) {
            if (ALLOW_LIST[j].used != 1)
                continue;
            if (ALLOW_LIST[j].list_index != i)
                continue;
            resLen += sprintf(buff + resLen, "%4d   %-10s %-7s %-46s       (%4d  / %4d)        %s\n",
                    ALLOW_LIST[j].list_index,
                    ALLOW_LIST[j].host,
                    ALLOW_LIST[j].type,
                    ALLOW_LIST[j].ip,
                    ALLOW_LIST[j].max,
                    ALLOW_LIST[j].curr,
                    (ALLOW_LIST[j].curr > 0) ?  "Connected" : (ALLOW_LIST[j].act == 1) ? "Disconnect" : "Deact");
        }
    }
	resLen += sprintf(buff + resLen, "------------------------------------------------------------------------------------------------------------------\n");
}
