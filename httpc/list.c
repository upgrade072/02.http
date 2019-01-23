#include "client.h"

extern client_conf_t CLIENT_CONF;
extern httpc_ctx_t *HttpcCtx[MAX_THRD_NUM];
extern conn_list_t CONN_LIST[MAX_SVR_NUM];
extern thrd_context_t THRD_WORKER[MAX_THRD_NUM];
extern http2_session_data SESS[MAX_THRD_NUM][MAX_SVR_NUM];

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
	memset(httpc_ctx->user_ctx.head.contentEncoding, 0x00, sizeof(httpc_ctx->user_ctx.head.contentEncoding));
}

void clear_and_free_ctx(httpc_ctx_t *httpc_ctx)
{
	httpc_ctx->inflight_ref_cnt = 0;
	httpc_ctx->user_ctx.head.bodyLen = 0;
	memset(httpc_ctx->user_ctx.head.contentEncoding, 0x00, sizeof(httpc_ctx->user_ctx.head.contentEncoding));
	httpc_ctx->occupied = 0;
}

void set_intl_req_msg(intl_req_t *intl_req, int thrd_idx, int ctx_idx, int sess_idx, int session_id, int stream_id, int msg_type)
{
	memset(intl_req, 0x00, sizeof(intl_req_t));
#if 0
	intl_req->msgq_index = thrd_idx + 1;		/* thrd use 1~12 msgqid */
#else
	intl_req->msgq_index = 1;					/* worker use personal msgq_id & type:0 */
#endif
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
void save_session_info(httpc_ctx_t *httpc_ctx, int thrd_idx, int sess_idx, int session_id, char *ipaddr)
{
	httpc_ctx->thrd_idx = thrd_idx;
	httpc_ctx->sess_idx = sess_idx;
	httpc_ctx->session_id = session_id;
	sprintf(httpc_ctx->user_ctx.head.destIp, "%s", ipaddr);
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

void print_raw_list() {
    int i;

    APPLOG(APPLOG_ERR, "- raw table ----------------------------------------------------------------------------------------------------------");
    APPLOG(APPLOG_ERR, " idx l-id i-id used  act conn host    type    ip                                             port next  max curr  num");
    for ( i = 0; i < MAX_SVR_NUM; i++) {
        if (CONN_LIST[i].used != 1)
            continue;
        APPLOG(APPLOG_ERR, "%4d %4d %4d %4d %4d %4d %-7s %-7s %-46s %4d %4d %4d %4d %4d",
                CONN_LIST[i].index,
                CONN_LIST[i].list_index,
                CONN_LIST[i].item_index,
                CONN_LIST[i].used,
                CONN_LIST[i].act,
                CONN_LIST[i].conn,
                CONN_LIST[i].host,
                CONN_LIST[i].type,
                CONN_LIST[i].ip,
                CONN_LIST[i].port,
                CONN_LIST[i].next_hop,
                CONN_LIST[i].max_hop,
                CONN_LIST[i].curr_idx,
                CONN_LIST[i].counter);
    }
    APPLOG(APPLOG_ERR, "----------------------------------------------------------------------------------------------------------------------");

}

/* watch out for buffer size */
void write_list(conn_list_status_t CONN_STATUS[], char *buff) {
	int i, j, resLen;

    resLen = sprintf(buff, "\n  ID HOSTNAME   TYPE       IP_ADDR                                         PORT CONN(max/curr)       STATUS\n");
    resLen += sprintf(buff + resLen, "---------------------------------------------------------------------------------------------------------------\n");
	for ( i = 0; i < MAX_LIST_NUM; i++) {
		for ( j = 0; j < MAX_CON_NUM; j++) {
			if (CONN_STATUS[j].occupied != 1)
				continue;
			if (CONN_STATUS[j].list_index != i)
				continue;
			resLen += sprintf(buff + resLen, "%4d %-10s %-10s %-46s %5d (%4d  / %4d)       %s\n",
					CONN_STATUS[j].list_index,
					CONN_STATUS[j].host,
					CONN_STATUS[j].type,
					CONN_STATUS[j].ip,
					CONN_STATUS[j].port,
					CONN_STATUS[j].sess_cnt,
					CONN_STATUS[j].conn_cnt,
					(CONN_STATUS[j].conn_cnt > 0) ?  "Connected" : (CONN_STATUS[j].act == 1) ? "Disconnect" : "Deact");
		}
	}
    resLen += sprintf(buff + resLen, "---------------------------------------------------------------------------------------------------------------\n");
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
			sprintf(CONN_STATUS[index].host, "%s", CONN_LIST[i].host);
			sprintf(CONN_STATUS[index].type, "%s", CONN_LIST[i].type);
			sprintf(CONN_STATUS[index].ip, "%s", "-");
			CONN_STATUS[index].port = 0;
			CONN_STATUS[index].act = 0;
			CONN_STATUS[index].occupied = 1;
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
					}
				}
			}
		}
	}
}

void prepare_order(int list_index)
{
    int i;

    for (i = 0; i < MAX_SVR_NUM; i++) {
        if (CONN_LIST[i].list_index == list_index) {
            CONN_LIST[i].next_hop = 0;
            CONN_LIST[i].max_hop = 0;
            CONN_LIST[i].curr_idx = 0;
            CONN_LIST[i].counter = 0;
        }
    }
}

void order_list() {
    conn_list_t *start = NULL, *curr = NULL, *prev = NULL;
    int i, j, found;

    for ( i = 0; i < MAX_SVR_NUM; i++) {
        if (CONN_LIST[i].used != 1)
            continue;
        if (CONN_LIST[i].next_hop == 0 ) {
            start = &CONN_LIST[i];
            start->max_hop = 1;
            prev = curr = start;

            found = 0;
            for (j = i + 1 ; j < MAX_SVR_NUM; j++) {
                curr = &CONN_LIST[j];

                if (CONN_LIST[j].used != 1)
                    continue;
                if (CONN_LIST[j].next_hop != 0 )
                    continue;

				if (!strcmp(curr->host, start->host)) {
                    curr->next_hop = start->index;
                    prev->next_hop = curr->index;
                    start->max_hop ++;

                    prev = curr;
                    found ++;
                }
            }
            if (found == 0) {
                start->next_hop = start->index;
            }
        }
    }
}

int find_packet_index(char *host, int ls_mode) {
    int i, found = 0, index;
    conn_list_t *curr = NULL, *start = NULL;
	int ls_index, ls_send_num;

	for ( i = 0; i < MAX_SVR_NUM; i++) {
		if (CONN_LIST[i].used != 1)
			continue;
		if(!strcmp(host, CONN_LIST[i].host)) {
			found = 1;
			break;
		}
	}
    if (!found) {
        APPLOG(APPLOG_DEBUG, "not found! (%s)", host);
        return (-1);
    }
    start = curr = &CONN_LIST[i];

	switch (ls_mode) {
		case LSMODE_RR:
			for (i = 0; i < start->curr_idx; i++) {
				index = curr->next_hop;
				curr = &CONN_LIST[index];
			}
			start->curr_idx = (start->curr_idx + 1) % start->max_hop;

			for (i = 0; i < start->max_hop; i++) {
				index = curr->next_hop;
				curr = &CONN_LIST[index];

				if (curr->conn == CN_CONNECTED) {
#ifndef PERFORM
					APPLOG(APPLOG_DEBUG, "packet sended via %d", curr->index);
#endif
					return (curr->index);
				}
			}
			break;

		case LSMODE_LS:
            ls_index = 0;
            ls_send_num = MAX_COUNT_NUM + 1;

            for (i = 0; i < start->max_hop; i++) {
                index = curr->next_hop;
                curr = &CONN_LIST[index];

                if (curr->conn == CN_CONNECTED) {
                    if (curr->counter <= ls_send_num) {
                        ls_index = curr->index;
                        ls_send_num = curr->counter;
                    }
                }
            }

            // HIT
            if (ls_index > 0) {
                curr = &CONN_LIST[ls_index];
#ifndef PERFORM
                APPLOG(APPLOG_DEBUG, "packet sended via %d (port %d)", curr->index, curr->port);
#endif
                if (curr->counter + 1 >= MAX_COUNT_NUM) {
#ifndef PERFORM
                    APPLOG(APPLOG_DEBUG, "clear counter");
#endif
                    for (i = 0; i < start->max_hop; i++) {
                        index = curr->next_hop;
                        curr = &CONN_LIST[index];
                        curr->counter = 0;
                    }
                } else {
                    curr->counter ++;
                }
                return curr->index;
            }
			break;
	}

    APPLOG(APPLOG_DEBUG, "fail to send");
    return (-1);
}
