#include "client.h"
#include <comm_msgtypes.h>

extern int httpcQid;
extern int ixpcQid;
extern client_conf_t CLIENT_CONF;
extern lb_ctx_t LB_CTX;    /* lb connection context */

extern pthread_mutex_t GET_INIT_CTX_LOCK;
extern int nrfmQid;
extern thrd_context_t THRD_WORKER[MAX_THRD_NUM];
extern int THREAD_NO[MAX_THRD_NUM];
extern conn_list_t CONN_LIST[MAX_SVR_NUM];
extern conn_list_status_t CONN_STATUS[MAX_CON_NUM];

char respMsg[MAX_MML_RESULT_LEN], respBuff[MAX_MML_RESULT_LEN];

typedef enum client_cmd {
	dis_http_server,
	add_http_server,
	add_http_svr_ip,
	act_http_server,
	dact_http_server,
	chg_http_server,
	del_http_svr_ip,
	del_http_server,
	dis_http_svr_ping,
	chg_http_svr_ping,
	MAX_CMD_NUM
} client_cmd_t;

MmcHdlrVector   mmcHdlrVecTbl[MAX_CMD_NUM] =
{
	{ "DIS-NF-SERVER",     func_dis_http_server},
	{ "ADD-NF-SERVER",     func_add_http_server},
	{ "ADD-NF-SVR-IP",     func_add_http_svr_ip},
	{ "ACT-NF-SERVER",     func_act_http_server},
	{ "DACT-NF-SERVER",    func_dact_http_server},
	{ "CHG-NF-SERVER",     func_chg_http_server},
	{ "DEL-NF-SVR-IP",     func_del_http_svr_ip},
	{ "DEL-NF-SERVER",     func_del_http_server},
	{ "DIS-NF-SVR-PING",   func_dis_http_svr_ping},
	{ "CHG-NF-SVR-PING",   func_chg_http_svr_ping}
};

void handle_nrfm_request(GeneralQMsgType *msg)
{
	AhifHttpCSMsgType *ahifPkt = (AhifHttpCSMsgType *)msg->body;
	httpc_ctx_t *httpc_ctx = NULL;
	intl_req_t intl_req = {0,};

	conn_list_t *httpc_conn = find_nrfm_inf_dest(ahifPkt);

	/* cant find connlist, error response */
	if (httpc_conn == NULL) {
		APPLOG(APPLOG_DETAIL, "%s() fail to find conn list for (%s)", __func__, ahifPkt->head.destType);
		goto HNR_ERROR_REPLY;
	}

	int thrd_idx = httpc_conn->thrd_index;
	int sess_idx = httpc_conn->session_index;
	int session_id = httpc_conn->session_id;

	pthread_mutex_lock(&GET_INIT_CTX_LOCK);
	int ctx_idx = Get_CtxId(thrd_idx);
	pthread_mutex_unlock(&GET_INIT_CTX_LOCK);

	if (ctx_idx < 0) {
		APPLOG(APPLOG_DETAIL, "%s() assign context fail in worker [%d]!", __func__, thrd_idx);
		goto HNR_ERROR_REPLY;
	}   
	if ((httpc_ctx = get_context(thrd_idx, ctx_idx, 0)) == NULL) {
		APPLOG(APPLOG_DETAIL, "%s() get context fail in worker [%d]!", __func__, thrd_idx);
		goto HNR_ERROR_REPLY;
	}

	httpc_ctx->recv_time_index = THRD_WORKER[thrd_idx].time_index;
	save_session_info(httpc_ctx, thrd_idx, sess_idx, session_id, ctx_idx, httpc_conn);
	httpc_ctx->for_nrfm_ctx = 1;
	httpc_ctx->occupied = 1; /* after time set */

	memcpy(&httpc_ctx->user_ctx.head, &ahifPkt->head, AHIF_HTTPCS_MSG_HEAD_LEN);
	memcpy(&httpc_ctx->user_ctx.vheader, &ahifPkt->vheader, sizeof(hdr_relay) * ahifPkt->head.vheaderCnt);
	memcpy(&httpc_ctx->user_ctx.data, &ahifPkt->data, 
			ahifPkt->head.queryLen + ahifPkt->head.bodyLen);
	int dataLen = ahifPkt->head.queryLen + ahifPkt->head.bodyLen;
	httpc_ctx->user_ctx.data[dataLen + 1] = '\0';

	httpc_ctx->user_ctx.head.mtype = set_nrfm_response_msg(httpc_ctx->user_ctx.head.mtype);    // in advance set

	set_intl_req_msg(&intl_req, thrd_idx, ctx_idx, sess_idx, session_id, 0, HTTP_INTL_SND_REQ);

	if (msgsnd(THRD_WORKER[thrd_idx].msg_id, &intl_req, sizeof(intl_req) - sizeof(long), 0) == -1) {
		APPLOG(APPLOG_ERR, "%s() internal msgsnd to worker [%d] failed!!!", __func__, thrd_idx);
		clear_and_free_ctx(httpc_ctx);
		Free_CtxId(thrd_idx, ctx_idx);
	}

	/* success */
	return;

	/* fail */
HNR_ERROR_REPLY:
	/* error response */
	ahifPkt->head.respCode = 500;
	msg->mtype = (long)MSGID_HTTPC_NRFM_RESPONSE;
	size_t shmqlen = AHIF_APP_MSG_HEAD_LEN + AHIF_VHDR_LEN + ahifPkt->head.queryLen + ahifPkt->head.bodyLen;

	int res = msgsnd(nrfmQid, msg, shmqlen, 0);
	if (res < 0) {
		APPLOG(APPLOG_ERR, "%s(), fail to send resp to NRFM! (res:%d)", __func__, res);
	}
}

void handle_nrfm_mmc(nrfm_mml_t *nrfm_cmd)
{
	APPLOG(APPLOG_ERR, "{{{DBG}}} %s called, cmdType(%d) [%s]",
			__func__, nrfm_cmd->command, get_nrfm_cmd_str(nrfm_cmd->command));
	print_nrfm_mml_raw(nrfm_cmd);

	switch (nrfm_cmd->command) {
		case NRFM_MML_HTTPC_ADD:
			nrfm_mmc_add_proc(nrfm_cmd);
			break;
		case NRFM_MML_HTTPC_ACT:
			nrfm_mmc_act_dact_proc(nrfm_cmd, 1);
			break;
		case NRFM_MML_HTTPC_DACT:
			nrfm_mmc_act_dact_proc(nrfm_cmd, 0);
			break;
		case NRFM_MML_HTTPC_DEL:
			nrfm_mmc_del_proc(nrfm_cmd);
			break;
		case NRFM_MML_HTTPC_CLEAR: /* NRFM restarted ! */
			nrfm_mmc_clear_proc();
			break;
	}
}

void nrfm_mmc_res_log()
{
	if (CLIENT_CONF.debug_mode != 1)
		return;

	conn_list_status_t temp_conn_status[MAX_CON_NUM] = {0,};
	char *resBuf = malloc(1024 * 1024);
	resBuf[0] = '\0';

	gather_list(temp_conn_status);
	write_list(temp_conn_status, resBuf);

	free(resBuf);
}

void nrfm_mmc_send_resp(nrfm_mml_t *nrfm_cmd_req)
{
    char msgBuff[sizeof(GeneralQMsgType)] = {0,};

    GeneralQMsgType *msg = (GeneralQMsgType *)msgBuff;
    nrfm_mml_t *httpc_cmd_res = (nrfm_mml_t *)msg->body;

    msg->mtype = (long)MSGID_HTTPC_NRFM_MMC_RESPONSE;
    memcpy(httpc_cmd_res, nrfm_cmd_req, sizeof(nrfm_mml_t));

	int res = msgsnd(nrfmQid, msg, sizeof(nrfm_mml_t), 0);
	if (res < 0) {
		APPLOG(APPLOG_ERR, "%s(), fail to send resp to NRFM! (res:%d)", __func__, res);
	} 
}

void nrfm_mmc_add_proc(nrfm_mml_t *nrfm_cmd)
{
	int list_index = new_list(nrfm_cmd->host);
	
#if 0
	for (int i = 0; i < nrfm_cmd->info_cnt; i++) {
#else
	for (int i = 0; (list_index > 0) && (i < nrfm_cmd->info_cnt); i++) {
#endif
		nf_conn_info_t *nf_conn = &nrfm_cmd->nf_conns[i];
		int item_index = new_item(list_index, nf_conn->ip, nf_conn->port);

		if (item_index < 0) {
			APPLOG(APPLOG_ERR, "{{{DBG}}} %s cause full of list[%d] or item[%d] skip", __func__, list_index, item_index);
			continue;
		}

		int added_cnt = 0;
		for (int k = 1; k < MAX_SVR_NUM ; k++) {
			if (CONN_LIST[k].used == 0) {
				CONN_LIST[k].index = k;
				CONN_LIST[k].list_index = list_index;
				CONN_LIST[k].item_index = item_index;
				CONN_LIST[k].used = 1;
				CONN_LIST[k].conn = 0;
				sprintf(CONN_LIST[k].host, "%s", nrfm_cmd->host);
				sprintf(CONN_LIST[k].type, "%s", nrfm_cmd->type);
				sprintf(CONN_LIST[k].scheme, "%s", nf_conn->scheme);
				sprintf(CONN_LIST[k].ip, "%s", nf_conn->ip);
				CONN_LIST[k].port = nf_conn->port;
				CONN_LIST[k].token_id = nrfm_cmd->token_id;
				CONN_LIST[k].act = 1;
				CONN_LIST[k].nrfm_auto_added = 1; /* this list is added by nrfm */
				APPLOG(APPLOG_ERR, "{{{DBG}}} [%s] [%s][%d] added cnt[%d] CONN_LIST[%d] INDEX[%d:%d]", 
						nrfm_cmd->host, nf_conn->ip, nf_conn->port, added_cnt, k, list_index, item_index);
				if (++added_cnt == nf_conn->cnt) break;
			}
		}
	}

	nrfm_mmc_res_log();
	nrfm_cmd->id = list_index; // replay added ID 
	nrfm_mmc_send_resp(nrfm_cmd);

	// node change, remake
	trig_refresh_select_node(&CLIENT_CONF);
}

void nrfm_mmc_act_dact_proc(nrfm_mml_t *nrfm_cmd, int act)
{
	int list_index = nrfm_cmd->id;

	for (int k = 1; k < MAX_SVR_NUM; k++) {
		if (CONN_LIST[k].used == 0)
			continue;
		if (CONN_LIST[k].nrfm_auto_added == 0)
			continue;
		if (CONN_LIST[k].list_index == list_index) {
			if (act) {
				CONN_LIST[k].act = 1;
			} else {
				/* hold connection */
				CONN_LIST[k].act = 0;

				http2_session_data_t *session_data = get_session(CONN_LIST[k].thrd_index,
						CONN_LIST[k].session_index, CONN_LIST[k].session_id);
				if (session_data != NULL) {
					delete_http2_session_data(session_data);
				}
			}
		}
	}

	nrfm_mmc_res_log();
	nrfm_cmd->id = list_index; // replay added ID 
	nrfm_mmc_send_resp(nrfm_cmd);

	// node change, remake
	trig_refresh_select_node(&CLIENT_CONF);
}

void nrfm_mmc_del_proc(nrfm_mml_t *nrfm_cmd)
{
	int list_index = nrfm_cmd->id;

	for (int k = 1; k < MAX_SVR_NUM; k++) {
		if (CONN_LIST[k].used == 0)
			continue;
		if (CONN_LIST[k].nrfm_auto_added == 0)
			continue;
		if (CONN_LIST[k].list_index == list_index) {
			http2_session_data_t *session_data = get_session(CONN_LIST[k].thrd_index,
					CONN_LIST[k].session_index, CONN_LIST[k].session_id);
			if (session_data != NULL) {
				delete_http2_session_data(session_data);
			}
			memset(&CONN_LIST[k], 0x00, sizeof(conn_list_t));
		}
	}
	/* clear list / item index */
	for (int i = 0; i < nrfm_cmd->info_cnt; i++) {
		nf_conn_info_t *nf_conn = &nrfm_cmd->nf_conns[i];
		del_item(list_index, nf_conn->ip, nf_conn->port);
	}
	del_list(nrfm_cmd->host);

	nrfm_mmc_res_log();
	nrfm_cmd->id = -1; // replay added ID 
	nrfm_mmc_send_resp(nrfm_cmd);

	// node change, remake
	trig_refresh_select_node(&CLIENT_CONF);
}

void nrfm_mmc_clear_proc()
{
	APPLOG(APPLOG_ERR, "{{{DBG}}} %s check NRFM restarted! clear all auto added conn", __func__);

	for (int k = 1; k < MAX_SVR_NUM; k++) {
		if (CONN_LIST[k].used == 0)
			continue;
		if (CONN_LIST[k].nrfm_auto_added == 0)
			continue;

		int list_index = get_list(CONN_LIST[k].host);
		del_item(list_index, CONN_LIST[k].ip, CONN_LIST[k].port);
		del_list(CONN_LIST[k].host);

		APPLOG(APPLOG_ERR, "{{{DBG}}} %s try to clear CONN_LIST[index:%d host:%s ip:%s port:%d]", 
				__func__, k, CONN_LIST[k].host, CONN_LIST[k].ip, CONN_LIST[k].port);

		http2_session_data_t *session_data = get_session(CONN_LIST[k].thrd_index,
				CONN_LIST[k].session_index, CONN_LIST[k].session_id);
		if (session_data != NULL) {
			/* disconnect must act in worker */
			intl_req_t intl_req = {0,};
			int thrd_index = session_data->thrd_index;
			set_intl_req_msg(&intl_req, thrd_index, 0, session_data->session_index,
					session_data->session_id, 0, HTTP_INTL_SESSION_DEL);
			if (-1 == msgsnd(THRD_WORKER[thrd_index].msg_id, &intl_req, sizeof(intl_req) - sizeof(long), 0)) {
				APPLOG(APPLOG_DEBUG, "%s() msgsnd fail!!!", __func__);
			}
		}
		/* for fast delete */
		memset(&CONN_LIST[k], 0x00, sizeof(conn_list_t));
	}
	nrfm_mmc_res_log();

	/* no response */

	// node change, remake
	trig_refresh_select_node(&CLIENT_CONF);
}

int set_nrfm_response_msg(int ahif_msg_type) 
{
	switch (ahif_msg_type) {
		case MTYPE_NRFM_REGI_REQUEST:
			return MTYPE_NRFM_REGI_RESPONSE;
		case MTYPE_NRFM_HEARTBEAT_REQUEST:
			return MTYPE_NRFM_HEARTBEAT_RESPONSE;
		case MTYPE_NRFM_RETRIEVE_REQUEST:
			return MTYPE_NRFM_RETRIEVE_RESPONSE;
		case MTYPE_NRFM_NF_PROFILE_REQUEST:
			return MTYPE_NRFM_NF_PROFILE_RESPONSE;
		case MTYPE_NRFM_SUBSCRIBE_REQUEST:
			return MTYPE_NRFM_SUBSCRIBE_RESPONSE;
		case MTYPE_NRFM_SUBSCR_PATCH_REQUEST:
			return MTYPE_NRFM_SUBSCR_PATCH_RESPONSE;
		case MTYPE_NRFM_TOKEN_REQUEST:
			return MTYPE_NRFM_TOKEN_RESPONSE;
		default:
			return -1;
	}
}

void adjust_loglevel(TrcLibSetPrintMsgType *trcMsg)
{
	if (trcMsg->trcLogFlag.pres) {
		if (trcMsg->trcLogFlag.octet == 9) {
			CLIENT_CONF.debug_mode = (CLIENT_CONF.debug_mode == 1 ? 0 : 1);
			APPLOG(APPLOG_ERR,"---- log level 9 (debug_mode on/off) now [%s]", CLIENT_CONF.debug_mode == 1 ? "ON" : "OFF");
		} else if (trcMsg->trcLogFlag.octet == 8) {
			CLIENT_CONF.pkt_log = (CLIENT_CONF.pkt_log == 1 ? 0 : 1);
			APPLOG(APPLOG_ERR,"---- log level 8 (pkg_log on/off) now [%s]", CLIENT_CONF.pkt_log == 1 ? "ON" : "OFF");
		} else {
			APPLOG(APPLOG_ERR,"---- log level change (%d -> %d)\n", *lOG_FLAG, trcMsg->trcLogFlag.octet);
			*lOG_FLAG = trcMsg->trcLogFlag.octet;
		}
	}
}

void message_handle(evutil_socket_t fd, short what, void *arg)
{
	char msgBuff[1024*64];
	GeneralQMsgType *msg = (GeneralQMsgType *)msgBuff;

	while (msgrcv(httpcQid, msg, sizeof(GeneralQMsgType), 0, IPC_NOWAIT) >= 0) {
		switch (msg->mtype) {
			case MTYPE_MMC_REQUEST:
				mml_function((IxpcQMsgType *)msg->body);
				continue;
			case MTYPE_STATISTICS_REQUEST:
				stat_function((IxpcQMsgType *)msg->body, CLIENT_CONF.worker_num, 1, 0, MSGID_HTTPC_STATISTICS_REPORT);
				continue;
			case MTYPE_SETPRINT:
				adjust_loglevel((TrcLibSetPrintMsgType *)msg);
				continue;
			/* NRF request from NRFM */
			case MSGID_NRFM_HTTPC_REQUEST:
				APPLOG(APPLOG_ERR, "%s() receive NRFM REQUEST (mtype:%ld)", __func__, (long)msg->mtype);
				handle_nrfm_request(msg);
				continue;
			case MSGID_NRFM_HTTPC_MMC_REQUEST:
				APPLOG(APPLOG_ERR, "%s() receive NRFM MMC (mtype:%ld)", __func__, (long)msg->mtype);
				handle_nrfm_mmc((nrfm_mml_t *)msg->body);
				continue;
			default:
				APPLOG(APPLOG_ERR, "%s() receive unknown msg (mtype:%ld)", __func__, (long)msg->mtype);
				continue;
		}
	}
	if (errno != ENOMSG) {
		APPLOG(APPLOG_ERR,"%s() msgrcv fail; err=%d(%s)", __func__, errno, strerror(errno));
	}

	return;
}

void mml_function(IxpcQMsgType *rxIxpcMsg)
{
	int i;
    MMLReqMsgType   *mmlReq=(MMLReqMsgType*)rxIxpcMsg->body;
    MmcHdlrVector	mmcHdlr;

	APPLOG(APPLOG_DEBUG, "%s() receive cmdName(%s)", __func__, mmlReq->head.cmdName);

	for (i = 0; i < MAX_CMD_NUM; i++) {
		if (!strcmp(mmlReq->head.cmdName, mmcHdlrVecTbl[i].cmdName)) {
			mmcHdlr.func = mmcHdlrVecTbl[i].func;
			break;
		}
	}

	if (i >= MAX_CMD_NUM) {
		APPLOG(APPLOG_ERR, "%s() not registered mml_cmd(%s) received!", __func__, mmlReq->head.cmdName);
	} else {
		respMsg[0]  = '\0';
		respBuff[0] = '\0';
		(int)(*(mmcHdlr.func)) (rxIxpcMsg);
	}
}

/*
1) gather connection status from raw-list
	- find hostname with no ipaddr (make text)
	- find ipaddr order by hostname id, sum conn count (make text)
	- return text
2) return ok
*/
int func_dis_http_server(IxpcQMsgType *rxIxpcMsg)
{
	APPLOG(APPLOG_DEBUG, "%s() called", __func__);

	char *resBuf = malloc(1024 * 1024);
	resBuf[0] = '\0';
	conn_list_status_t CONN_STATUS[MAX_CON_NUM];

	memset(CONN_STATUS, 0x00, sizeof(conn_list_status_t) * MAX_CON_NUM);

	gather_list(CONN_STATUS);
	write_list(CONN_STATUS, resBuf);

	print_list(CONN_STATUS);

	APPLOG(APPLOG_DETAIL, "%s() response is >>>\n%s", __func__, resBuf);
	int res = send_mml_res_succMsg(rxIxpcMsg, resBuf, FLAG_COMPLETE, 0, 0);

	free(resBuf);
	return res;
}

int func_add_http_server(IxpcQMsgType *rxIxpcMsg)
{
	APPLOG(APPLOG_DEBUG, "%s() called", __func__);

	MMLReqMsgType   *mmlReq=(MMLReqMsgType*)rxIxpcMsg->body;

	char HOSTNAME[64];
	char TYPE[64];
	conn_list_status_t CONN_STATUS[MAX_CON_NUM];

	memset(HOSTNAME, 0x00, sizeof(HOSTNAME));
	memset(TYPE, 0x00, sizeof(TYPE));
	memset(CONN_STATUS, 0x00, sizeof(conn_list_status_t) * MAX_CON_NUM);

	if (get_mml_para_str(mmlReq, "HOSTNAME", HOSTNAME) < 0)
		return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING(HOSTNAME)");
	if (get_mml_para_str(mmlReq, "TYPE", TYPE) < 0)
		return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING(TYPE)");

	if (addcfg_server_hostname(HOSTNAME, TYPE) < 0)
		return send_mml_res_failMsg(rxIxpcMsg, "HOSTNAME ADD FAIL");

	char *resBuf = malloc(1024 * 1024);
	resBuf[0] = '\0';

	// node change, remake
	trig_refresh_select_node(&CLIENT_CONF);

	gather_list(CONN_STATUS);

	write_list(CONN_STATUS, resBuf);

	APPLOG(APPLOG_DETAIL, "%s() response is >>>\n%s", __func__, resBuf);
	int res = send_mml_res_succMsg(rxIxpcMsg, resBuf, FLAG_COMPLETE, 0, 0);

	free(resBuf);
	return res;
}

int func_add_http_svr_ip(IxpcQMsgType *rxIxpcMsg)
{
	APPLOG(APPLOG_DEBUG, "%s() called", __func__);

	MMLReqMsgType   *mmlReq=(MMLReqMsgType*)rxIxpcMsg->body;

	int ID = -1;
	char SCHEME[64];
	char IPADDR[64];
	int PORT = -1;
	int CONN_CNT = -1;
	int TOKEN_ID = -1;
	struct sockaddr_in sa;
	struct sockaddr_in6 sa6;
	conn_list_status_t CONN_STATUS[MAX_CON_NUM];

	memset(IPADDR, 0x00, sizeof(IPADDR));
	memset(CONN_STATUS, 0x00, sizeof(conn_list_status_t) * MAX_CON_NUM);

	if ((ID = get_mml_para_int(mmlReq, "ID")) < 0)
		return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING(ID)");
	if (get_mml_para_str(mmlReq, "SCHEME", SCHEME) < 0)
		return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING(SCHEME)");
	if (get_mml_para_str(mmlReq, "IPADDR", IPADDR) < 0)
		return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING(IPADDR)");
	if ((PORT = get_mml_para_int(mmlReq, "PORT")) < 0)
		return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING(PORT)");
	if ((CONN_CNT = get_mml_para_int(mmlReq, "CONN_CNT")) < 0)
		return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING(CONN_CNT)");
	if ((TOKEN_ID = get_mml_para_int(mmlReq, "TOKEN_ID")) < 0)
		return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING(TOKEN_ID)");

	if (ID >= HTTP_MAX_HOST)
		return send_mml_res_failMsg(rxIxpcMsg, "INVALID ID");
	if (strcmp(SCHEME, "https") && strcmp(SCHEME, "http")) {
		return send_mml_res_failMsg(rxIxpcMsg, "INVALID SCHEME (https|http)");
	}
	if (inet_pton(AF_INET, IPADDR, &(sa.sin_addr))) {
	} else if (inet_pton(AF_INET6, IPADDR, &(sa6.sin6_addr))) {
	} else {
		return send_mml_res_failMsg(rxIxpcMsg, "INVALID IPADDR");
	}
	if (PORT <= 0 || PORT >= 65535)
		return send_mml_res_failMsg(rxIxpcMsg, "INVALID PORT");
	if (CONN_CNT <= 0 || CONN_CNT > HTTP_MAX_CONN)
		return send_mml_res_failMsg(rxIxpcMsg, "INVALID CONN_CNT");
	if (TOKEN_ID < 0 || TOKEN_ID >= MAX_ACC_TOKEN_NUM)
		return send_mml_res_failMsg(rxIxpcMsg, "INVALID TOKEN_ID");

	if (addcfg_server_ipaddr(ID, SCHEME, IPADDR, PORT, CONN_CNT, TOKEN_ID) < 0)
		return send_mml_res_failMsg(rxIxpcMsg, "IPADDR ADD FAIL");

	char *resBuf = malloc(1024 * 1024);
	resBuf[0] = '\0';

	// node change, remake
	trig_refresh_select_node(&CLIENT_CONF);

	gather_list(CONN_STATUS);

	write_list(CONN_STATUS, resBuf);

	APPLOG(APPLOG_DETAIL, "%s() response is >>>\n%s", __func__, resBuf);
	int res = send_mml_res_succMsg(rxIxpcMsg, resBuf, FLAG_COMPLETE, 0, 0);
	
	free(resBuf);
	return res;
}

int func_act_http_server(IxpcQMsgType *rxIxpcMsg)
{
	return func_chg_http_server_act(rxIxpcMsg, 1);
}

int func_dact_http_server(IxpcQMsgType *rxIxpcMsg)
{
	return func_chg_http_server_act(rxIxpcMsg, 0);
}

int func_chg_http_server_act(IxpcQMsgType *rxIxpcMsg, int change_to_act)
{
	APPLOG(APPLOG_DEBUG, "%s() called", __func__);

	MMLReqMsgType   *mmlReq=(MMLReqMsgType*)rxIxpcMsg->body;

	char *resBuf=respMsg;
	int ID = -1;
	char IPADDR[64];
	int ip_exist = -1;
	int PORT = -1;
	struct sockaddr_in sa;
	struct sockaddr_in6 sa6;

	memset(IPADDR, 0x00, sizeof(IPADDR));

	if ((ID = get_mml_para_int(mmlReq, "ID")) < 0)
		return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING(ID)");

	ip_exist = get_mml_para_str(mmlReq, "IPADDR", IPADDR);
	PORT = get_mml_para_int(mmlReq, "PORT");

	/* IPADDR(exist), PORT(not exist) or IPADDR(not exist), PORT(exist) case */
	if (ip_exist + PORT == 0)
		return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER IPADDR MUST USE WITH PORT");

	if (ID >= HTTP_MAX_HOST)
		return send_mml_res_failMsg(rxIxpcMsg, "INVALID ID");
	if (ip_exist > 0) {
		if (inet_pton(AF_INET, IPADDR, &(sa.sin_addr))) {
		} else if (inet_pton(AF_INET6, IPADDR, &(sa6.sin6_addr))) {
		} else {
			return send_mml_res_failMsg(rxIxpcMsg, "INVALID IPADDR");
		}
		if (PORT <= 0 || PORT >= 65535)
			return send_mml_res_failMsg(rxIxpcMsg, "INVALID PORT");
	}

	if (actcfg_http_server(ID, ip_exist, IPADDR, PORT, change_to_act) < 0)
		return send_mml_res_failMsg(rxIxpcMsg, "ACT HTTP SERVER FAIL");

	sprintf(resBuf, "\n[INPUT PARAM]\n\
			ID        : %d\n\
			IPADDR    : %s\n\
			PORT      : %d\n\
			ACT       : %s\n", ID, IPADDR, PORT, change_to_act == 1 ? "ACT":"DACT");

	APPLOG(APPLOG_DETAIL, "%s() response is >>>\n%s", __func__, resBuf);
	return send_mml_res_succMsg(rxIxpcMsg, resBuf, FLAG_COMPLETE, 0, 0);
}

int func_chg_http_server(IxpcQMsgType *rxIxpcMsg)
{
	APPLOG(APPLOG_DEBUG, "%s() called", __func__);

	MMLReqMsgType   *mmlReq=(MMLReqMsgType*)rxIxpcMsg->body;

	int ID = -1;
	char SCHEME[64];
	char IPADDR[64];
	int PORT = -1;
	int CONN_CNT = -1;
	int TOKEN_ID = -1;
	struct sockaddr_in sa;
	struct sockaddr_in6 sa6;
	conn_list_status_t CONN_STATUS[MAX_CON_NUM];

	memset(IPADDR, 0x00, sizeof(IPADDR));
	memset(CONN_STATUS, 0x00, sizeof(conn_list_status_t) * MAX_CON_NUM);

	if ((ID = get_mml_para_int(mmlReq, "ID")) < 0)
		return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING(ID)");
	if (get_mml_para_str(mmlReq, "IPADDR", IPADDR) < 0)
		return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING(IPADDR)");
	if (get_mml_para_str(mmlReq, "SCHEME", SCHEME) < 0)
		return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING(SCHEME)");
	if ((PORT = get_mml_para_int(mmlReq, "PORT")) < 0)
		return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING(PORT)");
	if ((CONN_CNT = get_mml_para_int(mmlReq, "CONN_CNT")) < 0)
		return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING(CONN_CNT)");
	if ((TOKEN_ID = get_mml_para_int(mmlReq, "TOKEN_ID")) < 0)
		return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING(TOKEN_ID)");

	if (ID >= HTTP_MAX_HOST)
		return send_mml_res_failMsg(rxIxpcMsg, "INVALID ID");
	if (strcmp(SCHEME, "https") && strcmp(SCHEME, "http")) {
		return send_mml_res_failMsg(rxIxpcMsg, "INVALID SCHEME (https|http)");
	}
	if (inet_pton(AF_INET, IPADDR, &(sa.sin_addr))) {
	} else if (inet_pton(AF_INET6, IPADDR, &(sa6.sin6_addr))) {
	} else {
		return send_mml_res_failMsg(rxIxpcMsg, "INVALID IPADDR");
	}
	if (PORT <= 0 || PORT >= 65535)
		return send_mml_res_failMsg(rxIxpcMsg, "INVALID PORT");
	if (CONN_CNT < 1 || CONN_CNT > HTTP_MAX_CONN) // 1~12 
		return send_mml_res_failMsg(rxIxpcMsg, "INVALID CONN_CNT");
	if (TOKEN_ID < 0 || TOKEN_ID >= MAX_ACC_TOKEN_NUM)
		return send_mml_res_failMsg(rxIxpcMsg, "INVALID TOKEN_ID");

	if (chgcfg_server_conn_cnt(ID, SCHEME, IPADDR, PORT, CONN_CNT, TOKEN_ID) < 0)
		return send_mml_res_failMsg(rxIxpcMsg, "CONN COUNT CHG FAIL");

	char *resBuf = malloc(1024 * 1024);
	resBuf[0] = '\0';

	// node change, remake
	trig_refresh_select_node(&CLIENT_CONF);

	gather_list(CONN_STATUS);

	write_list(CONN_STATUS, resBuf);

	APPLOG(APPLOG_DETAIL, "%s() response is >>>\n%s", __func__, resBuf);
	int res = send_mml_res_succMsg(rxIxpcMsg, resBuf, FLAG_COMPLETE, 0, 0);

	free(resBuf);
	return res;
}

int func_del_http_svr_ip(IxpcQMsgType *rxIxpcMsg)
{
	APPLOG(APPLOG_DEBUG, "%s() called", __func__);

	MMLReqMsgType   *mmlReq=(MMLReqMsgType*)rxIxpcMsg->body;

	int ID = -1;
	char IPADDR[64];
	int PORT = -1;
	struct sockaddr_in sa;
	struct sockaddr_in6 sa6;
	conn_list_status_t CONN_STATUS[MAX_CON_NUM];

	memset(IPADDR, 0x00, sizeof(IPADDR));
	memset(CONN_STATUS, 0x00, sizeof(conn_list_status_t) * MAX_CON_NUM);

	if ((ID = get_mml_para_int(mmlReq, "ID")) < 0)
		return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING(ID)");
	if (get_mml_para_str(mmlReq, "IPADDR", IPADDR) < 0)
		return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING(IPADDR)");
	if ((PORT = get_mml_para_int(mmlReq, "PORT")) < 0)
		return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING(PORT)");

	if (ID >= HTTP_MAX_HOST)
		return send_mml_res_failMsg(rxIxpcMsg, "INVALID ID");
	if (inet_pton(AF_INET, IPADDR, &(sa.sin_addr))) {
	} else if (inet_pton(AF_INET6, IPADDR, &(sa6.sin6_addr))) {
	} else {
		return send_mml_res_failMsg(rxIxpcMsg, "INVALID IPADDR");
	}
	if (PORT <= 0 || PORT >= 65535)
		return send_mml_res_failMsg(rxIxpcMsg, "INVALID PORT");

	if (delcfg_server_ipaddr(ID, IPADDR, PORT) < 0)
		return send_mml_res_failMsg(rxIxpcMsg, "IPADDR DEL FAIL");

	char *resBuf = malloc(1024 * 1024);
	resBuf[0] = '\0';

	// node change, remake
	trig_refresh_select_node(&CLIENT_CONF);

	gather_list(CONN_STATUS);

	write_list(CONN_STATUS, resBuf);

	APPLOG(APPLOG_DETAIL, "%s() response is >>>\n%s", __func__, resBuf);
	int res = send_mml_res_succMsg(rxIxpcMsg, resBuf, FLAG_COMPLETE, 0, 0);

	free(resBuf);
	return res;
}

int func_del_http_server(IxpcQMsgType *rxIxpcMsg)
{
	APPLOG(APPLOG_DEBUG, "%s() called", __func__);

	MMLReqMsgType   *mmlReq=(MMLReqMsgType*)rxIxpcMsg->body;

	int ID = -1;
	conn_list_status_t CONN_STATUS[MAX_CON_NUM];

	memset(CONN_STATUS, 0x00, sizeof(conn_list_status_t) * MAX_CON_NUM);

	if ((ID = get_mml_para_int(mmlReq, "ID")) < 0)
		return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING(ID)");

	if (ID >= HTTP_MAX_HOST)
		return send_mml_res_failMsg(rxIxpcMsg, "INVALID ID");

	if (delcfg_server_hostname(ID) < 0)
		return send_mml_res_failMsg(rxIxpcMsg, "HOSTNAME DEL FAIL");

	char *resBuf = malloc(1024 * 1024);
	resBuf[0] = '\0';

	// node change, remake
	trig_refresh_select_node(&CLIENT_CONF);

	gather_list(CONN_STATUS);

	write_list(CONN_STATUS, resBuf);

	APPLOG(APPLOG_DETAIL, "%s() response is >>>\n%s", __func__, resBuf);
	int res = send_mml_res_succMsg(rxIxpcMsg, resBuf, FLAG_COMPLETE, 0, 0);

	free(resBuf);
	return res;
}

int func_dis_http_svr_ping(IxpcQMsgType *rxIxpcMsg)
{
	APPLOG(APPLOG_DEBUG, "%s() called", __func__);

	char *resBuf=respMsg;

	sprintf(resBuf, "  PING INTERVAL (%d) sec\n", CLIENT_CONF.ping_interval);
	sprintf(resBuf + strlen(resBuf), "  PING TIMEOUT (%d) sec\n", CLIENT_CONF.ping_timeout);
	sprintf(resBuf + strlen(resBuf), "  PING ALARM LATENCY (%d) ms", CLIENT_CONF.ping_event_ms);

	APPLOG(APPLOG_DETAIL, "%s() response is >>>\n%s", __func__, resBuf);
	return send_mml_res_succMsg(rxIxpcMsg, resBuf, FLAG_COMPLETE, 0, 0);
}

int func_chg_http_svr_ping(IxpcQMsgType *rxIxpcMsg)
{
	APPLOG(APPLOG_DEBUG, "%s() called", __func__);

	MMLReqMsgType   *mmlReq=(MMLReqMsgType*)rxIxpcMsg->body;

	char *resBuf=respMsg;

	int interval = get_mml_para_int(mmlReq, "INTERVAL");
	int timeout = get_mml_para_int(mmlReq, "TIMEOUT");
	int ms = get_mml_para_int(mmlReq, "MS");

	int old_interval = CLIENT_CONF.ping_interval;
	int old_timeout = CLIENT_CONF.ping_timeout;
	int old_ms = CLIENT_CONF.ping_event_ms;

	if (chgcfg_server_ping(interval, timeout, ms) < 0)
		return send_mml_res_failMsg(rxIxpcMsg, "PING MS CHANGE FAIL");

	if (interval >= 0) CLIENT_CONF.ping_interval = interval;
	if (timeout >= 0) CLIENT_CONF.ping_timeout = timeout;
	if (ms >= 0) CLIENT_CONF.ping_event_ms = ms;

	sprintf(resBuf, "  PING INTERVAL (%d) --> (%d) sec\n", old_interval, CLIENT_CONF.ping_interval);
	sprintf(resBuf + strlen(resBuf), "  PING TIMEOUT (%d) --> (%d) sec\n", old_timeout, CLIENT_CONF.ping_timeout);
	sprintf(resBuf + strlen(resBuf), "  PING ALARM LATENCY (%d) --> (%d) ms\n", old_ms, CLIENT_CONF.ping_event_ms);

	APPLOG(APPLOG_DETAIL, "%s() response is >>>\n%s", __func__, resBuf);
	return send_mml_res_succMsg(rxIxpcMsg, resBuf, FLAG_COMPLETE, 0, 0);
}
