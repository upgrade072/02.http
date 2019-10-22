#include "server.h"
#include <comm_msgtypes.h>

#define MAX_LEN_RES_BUF 10000

extern int httpsQid;
extern int ixpcQid;
extern server_conf SERVER_CONF;
extern thrd_context THRD_WORKER[MAX_THRD_NUM];

char respMsg[MAX_MML_RESULT_LEN], respBuff[MAX_MML_RESULT_LEN];

typedef enum server_cmd {
	dis_http_client,
	add_http_client,
	add_http_cli_ip,
	act_http_client,
	dact_http_client,
	chg_http_client,
	del_http_cli_ip,
	del_http_client,
	dis_http_cli_ping,
	chg_http_cli_ping,
	MAX_CMD_NUM
} server_cmd_t;

MmcHdlrVector   mmcHdlrVecTbl[MAX_CMD_NUM] =
{
    { "DIS-NF-CLIENT",     func_dis_http_client},
    { "ADD-NF-CLIENT",     func_add_http_client},
    { "ADD-NF-CLI-IP",     func_add_http_cli_ip},
    { "ACT-NF-CLIENT",     func_act_http_client},
    { "DACT-NF-CLIENT",    func_dact_http_client},
    { "CHG-NF-CLIENT",     func_chg_http_client},
    { "DEL-NF-CLI-IP",     func_del_http_cli_ip},
    { "DEL-NF-CLIENT",     func_del_http_client},
	{ "DIS-NF-CLI-PING",   func_dis_http_cli_ping},
	{ "CHG-NF-CLI-PING",   func_chg_http_cli_ping}
};

void handle_nrfm_response(GeneralQMsgType *msg)
{
	AhifHttpCSMsgType *ahifPkt = (AhifHttpCSMsgType *)msg->body;
	AhifHttpCSMsgHeadType *head = &ahifPkt->head;

	https_ctx_t *https_ctx = NULL;
	http2_session_data *session_data = NULL;

	int thrd_index = head->thrd_index;
	int session_index = head->session_index;
	int session_id = head->session_id;
	int stream_id = head->stream_id;
	int ctx_id = head->ctx_id;

	if ((https_ctx = get_context(thrd_index, ctx_id, 1)) == NULL) {
		if ((session_data = get_session(thrd_index, session_index, session_id)) == NULL)
			http_stat_inc(0, 0, HTTP_STRM_N_FOUND);
		else
			http_stat_inc(session_data->thrd_index, session_data->list_index, HTTP_STRM_N_FOUND);
		APPLOG(APPLOG_ERR,"{{{NRF}}} %s() can't find https_ctx!", __func__);
		return;
	}

	if (https_ctx->for_nrfm_ctx != 1) {
		APPLOG(APPLOG_ERR,"{{{NRF}}} %s() mismatch type (not for nrfm)!", __func__);
		return;
	}

	intl_req_t intl_req = {0,};

	/* HTTP_INTL_SND_REQ || HTTP_INTL_OVLD */
	set_intl_req_msg(&intl_req, thrd_index, ctx_id, session_index, session_id, stream_id, HTTP_INTL_SND_REQ);

	assign_rcv_ctx_info(https_ctx, ahifPkt);

	if (msgsnd(THRD_WORKER[thrd_index].msg_id, &intl_req, sizeof(intl_req) - sizeof(long), 0) == -1) {
		APPLOG(APPLOG_ERR, "%s() internal msgsnd to worker [%d] failed!!!", __func__, thrd_index);
		clear_and_free_ctx(https_ctx);
		Free_CtxId(thrd_index, ctx_id);
	}
}

void adjust_loglevel(TrcLibSetPrintMsgType *trcMsg)
{
	if (trcMsg->trcLogFlag.pres) {
		if (trcMsg->trcLogFlag.octet == 9) {
			SERVER_CONF.debug_mode = (SERVER_CONF.debug_mode == 1 ? 0 : 1);
			APPLOG(APPLOG_ERR,"---- log level 9 (debug_mode on/off) now [%s]",
					SERVER_CONF.debug_mode == 1 ? "ON" : "OFF");
		} else if (trcMsg->trcLogFlag.octet == 8) {
			SERVER_CONF.pkt_log = (SERVER_CONF.pkt_log == 1 ? 0 : 1);
			APPLOG(APPLOG_ERR,"---- log level 8 (pkg_log on/off) now [%s]",
					SERVER_CONF.pkt_log == 1 ? "ON" : "OFF");
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

	while (msgrcv(httpsQid, msg, sizeof(GeneralQMsgType), 0, IPC_NOWAIT) >= 0) {
        switch (msg->mtype) {
            case MTYPE_MMC_REQUEST:
                mml_function((IxpcQMsgType *)msg->body);
                continue;
			case MTYPE_STATISTICS_REQUEST:
				stat_function((IxpcQMsgType *)msg->body, SERVER_CONF.worker_num, 0, 1, MSGID_HTTPS_STATISTICS_REPORT);
				continue;
			case MTYPE_SETPRINT:
				adjust_loglevel((TrcLibSetPrintMsgType *)msg);
				continue;
            /* NRF request from NRFM */
            case MSGID_NRFM_HTTPS_RESPONSE:
                APPLOG(APPLOG_ERR, "%s() receive NRFM Response (mtype:%ld)", __func__, (long)msg->mtype);
                handle_nrfm_response(msg);
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
    MmcHdlrVector   mmcHdlr;
    
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

int func_dis_http_client(IxpcQMsgType *rxIxpcMsg)
{
	APPLOG(APPLOG_DEBUG, "%s() called", __func__);

    char *resBuf=respMsg;

    write_list(resBuf);

	APPLOG(APPLOG_DETAIL, "%s() response is >>>\n%s", __func__, resBuf);
    return send_mml_res_succMsg(rxIxpcMsg, resBuf, FLAG_COMPLETE, 0, 0);
}
int func_add_http_client(IxpcQMsgType *rxIxpcMsg)
{
	APPLOG(APPLOG_DEBUG, "%s() called", __func__);

    MMLReqMsgType   *mmlReq=(MMLReqMsgType*)rxIxpcMsg->body;

    char *resBuf=respMsg;
    char HOSTNAME[64];
    char TYPE[64];

    memset(HOSTNAME, 0x00, sizeof(HOSTNAME));
    memset(TYPE, 0x00, sizeof(TYPE));

    if (get_mml_para_str(mmlReq, "HOSTNAME", HOSTNAME) < 0)
        return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING(HOSTNAME)");
    if (get_mml_para_str(mmlReq, "TYPE", TYPE) < 0)
        return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING(TYPE)");

    if (addcfg_client_hostname(HOSTNAME, TYPE) < 0)
        return send_mml_res_failMsg(rxIxpcMsg, "HOSTNAME ADD FAIL");

    write_list(resBuf);

	APPLOG(APPLOG_DETAIL, "%s() response is >>>\n%s", __func__, resBuf);
    return send_mml_res_succMsg(rxIxpcMsg, resBuf, FLAG_COMPLETE, 0, 0);
}
int func_add_http_cli_ip(IxpcQMsgType *rxIxpcMsg)
{
	APPLOG(APPLOG_DEBUG, "%s() called", __func__);
    
    MMLReqMsgType   *mmlReq=(MMLReqMsgType*)rxIxpcMsg->body;
    
    char *resBuf=respMsg;
    int ID = -1;
    char IPADDR[64];
    int MAX = -1; 
    struct sockaddr_in sa;
    struct sockaddr_in6 sa6;
    
    memset(IPADDR, 0x00, sizeof(IPADDR));
    
    if ((ID = get_mml_para_int(mmlReq, "ID")) < 0)
        return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING(ID)");
    if (get_mml_para_str(mmlReq, "IPADDR", IPADDR) < 0)
        return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING(IPADDR)");
    if ((MAX = get_mml_para_int(mmlReq, "MAX")) < 0)
        return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING(MAX)");
    
    if (ID >= HTTP_MAX_HOST)
        return send_mml_res_failMsg(rxIxpcMsg, "INVALID ID");
	if (inet_pton(AF_INET, IPADDR, &(sa.sin_addr))) {
	} else if (inet_pton(AF_INET6, IPADDR, &(sa6.sin6_addr))) {
	} else {
		return send_mml_res_failMsg(rxIxpcMsg, "INVALID IPADDR");
	}
    if (MAX <= 0 || MAX >= 65535)
        return send_mml_res_failMsg(rxIxpcMsg, "INVALID MAX");
    
    if (addcfg_client_ipaddr(ID, IPADDR, MAX) < 0)
        return send_mml_res_failMsg(rxIxpcMsg, "IPADDR ADD FAIL");
    
    write_list(resBuf);
    
	APPLOG(APPLOG_DETAIL, "%s() response is >>>\n%s", __func__, resBuf);
    return send_mml_res_succMsg(rxIxpcMsg, resBuf, FLAG_COMPLETE, 0, 0);
}
int func_act_http_client(IxpcQMsgType *rxIxpcMsg)
{
	return func_chg_http_client_act(rxIxpcMsg, 1);
}
int func_dact_http_client(IxpcQMsgType *rxIxpcMsg)
{
	return func_chg_http_client_act(rxIxpcMsg, 0);
}
int func_chg_http_client_act(IxpcQMsgType *rxIxpcMsg, int change_to_act)
{
	APPLOG(APPLOG_DEBUG, "%s() called", __func__);
    
    MMLReqMsgType   *mmlReq=(MMLReqMsgType*)rxIxpcMsg->body;
    
    char *resBuf=respMsg;
    int ID = -1;
    char IPADDR[64];
    int ip_exist = -1;
    struct sockaddr_in sa;
    struct sockaddr_in6 sa6;
    
    memset(IPADDR, 0x00, sizeof(IPADDR));
    
    if ((ID = get_mml_para_int(mmlReq, "ID")) < 0)
        return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING(ID)");
    
    ip_exist = get_mml_para_str(mmlReq, "IPADDR", IPADDR);
    
    if (ID >= HTTP_MAX_HOST)
        return send_mml_res_failMsg(rxIxpcMsg, "INVALID ID");
    if (ip_exist > 0) {
		if (inet_pton(AF_INET, IPADDR, &(sa.sin_addr))) {
		} else if (inet_pton(AF_INET6, IPADDR, &(sa6.sin6_addr))) {
		} else {
			return send_mml_res_failMsg(rxIxpcMsg, "INVALID IPADDR");
		}
    }
    
    if (actcfg_http_client(ID, ip_exist, IPADDR, change_to_act) < 0)
        return send_mml_res_failMsg(rxIxpcMsg, "ACT HTTP CLIENT FAIL");


	sprintf(resBuf, "\n[INPUT PARAM]\n\
			ID        : %d\n\
			IPADDR    : %s\n\
			ACT       : %s\n", ID, IPADDR, change_to_act == 1 ? "ACT":"DACT");

	APPLOG(APPLOG_DETAIL, "%s() response is >>>\n%s", __func__, resBuf);
    return send_mml_res_succMsg(rxIxpcMsg, resBuf, FLAG_COMPLETE, 0, 0);
}
int func_chg_http_client(IxpcQMsgType *rxIxpcMsg)
{
	APPLOG(APPLOG_DEBUG, "%s() called", __func__);

    MMLReqMsgType   *mmlReq=(MMLReqMsgType*)rxIxpcMsg->body;

    char *resBuf=respMsg;
    int ID = -1;
    char IPADDR[64];
    int MAX = -1;
	int LIMIT = -1;
	int AUTH_ACT = -1;
    struct sockaddr_in sa;
    struct sockaddr_in6 sa6;

    memset(IPADDR, 0x00, sizeof(IPADDR));

    if ((ID = get_mml_para_int(mmlReq, "ID")) < 0)
        return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING(ID)");
    if (get_mml_para_str(mmlReq, "IPADDR", IPADDR) < 0)
        return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING(IPADDR)");
    if ((MAX = get_mml_para_int(mmlReq, "MAX")) < 0)
        return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING(MAX)");
    if ((LIMIT = get_mml_para_int(mmlReq, "LIMIT")) < 0)
        return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING(LIMIT)");
    if ((AUTH_ACT = get_mml_para_int(mmlReq, "AUTH_ACT")) < 0)
        return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING(AUTH_ACT)");

    if (ID >= HTTP_MAX_HOST)
        return send_mml_res_failMsg(rxIxpcMsg, "INVALID ID");
	if (inet_pton(AF_INET, IPADDR, &(sa.sin_addr))) {
	} else if (inet_pton(AF_INET6, IPADDR, &(sa6.sin6_addr))) {
	} else {
		return send_mml_res_failMsg(rxIxpcMsg, "INVALID IPADDR");
	}
    if (MAX <= 0 || MAX >= 65535)
        return send_mml_res_failMsg(rxIxpcMsg, "INVALID MAX");
	if (LIMIT < 0)
        return send_mml_res_failMsg(rxIxpcMsg, "INVALID LIMIT");
	if (AUTH_ACT != 0 && AUTH_ACT != 1)
        return send_mml_res_failMsg(rxIxpcMsg, "INVALID AUTH_ACT");

    if (chgcfg_client_max_cnt_with_auth_act_and_limit(ID, IPADDR, MAX, AUTH_ACT, LIMIT) < 0)
        return send_mml_res_failMsg(rxIxpcMsg, "MAX CHG FAIL");

    write_list(resBuf);

	APPLOG(APPLOG_DETAIL, "%s() response is >>>\n%s", __func__, resBuf);
    return send_mml_res_succMsg(rxIxpcMsg, resBuf, FLAG_COMPLETE, 0, 0);
}
int func_del_http_cli_ip(IxpcQMsgType *rxIxpcMsg)
{
	APPLOG(APPLOG_DEBUG, "%s() called", __func__);

    MMLReqMsgType   *mmlReq=(MMLReqMsgType*)rxIxpcMsg->body;

    char *resBuf=respMsg;
    int ID = -1;
    char IPADDR[64];
    struct sockaddr_in sa;
    struct sockaddr_in6 sa6;

    memset(IPADDR, 0x00, sizeof(IPADDR));

    if ((ID = get_mml_para_int(mmlReq, "ID")) < 0)
        return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING(ID)");
    if (get_mml_para_str(mmlReq, "IPADDR", IPADDR) < 0)
        return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING(IPADDR)");

    if (ID >= HTTP_MAX_HOST)
        return send_mml_res_failMsg(rxIxpcMsg, "INVALID ID");
	if (inet_pton(AF_INET, IPADDR, &(sa.sin_addr))) {
	} else if (inet_pton(AF_INET6, IPADDR, &(sa6.sin6_addr))) {
	} else {
		return send_mml_res_failMsg(rxIxpcMsg, "INVALID IPADDR");
	}

    if (delcfg_client_ipaddr(ID, IPADDR) < 0)
        return send_mml_res_failMsg(rxIxpcMsg, "IPADDR DEL FAIL");

    write_list(resBuf);

	APPLOG(APPLOG_DETAIL, "%s() response is >>>\n%s", __func__, resBuf);
    return send_mml_res_succMsg(rxIxpcMsg, resBuf, FLAG_COMPLETE, 0, 0);
}
int func_del_http_client(IxpcQMsgType *rxIxpcMsg)
{
	APPLOG(APPLOG_DEBUG, "%s() called", __func__);

    MMLReqMsgType   *mmlReq=(MMLReqMsgType*)rxIxpcMsg->body;

    char *resBuf=respMsg;
    int ID = -1;

    if ((ID = get_mml_para_int(mmlReq, "ID")) < 0)
        return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING(ID)");

    if (ID >= HTTP_MAX_HOST)
        return send_mml_res_failMsg(rxIxpcMsg, "INVALID ID");

    if (delcfg_client_hostname(ID) < 0)
        return send_mml_res_failMsg(rxIxpcMsg, "HOSTNAME DEL FAIL");

    write_list(resBuf);

	APPLOG(APPLOG_DETAIL, "%s() response is >>>\n%s", __func__, resBuf);
    return send_mml_res_succMsg(rxIxpcMsg, resBuf, FLAG_COMPLETE, 0, 0);
}

int func_dis_http_cli_ping(IxpcQMsgType *rxIxpcMsg)
{
    APPLOG(APPLOG_DEBUG, "%s() called", __func__);

    char *resBuf=respMsg;

    sprintf(resBuf, "  PING INTERVAL (%d) sec\n", SERVER_CONF.ping_interval);
    sprintf(resBuf + strlen(resBuf), "  PING TIMEOUT (%d) sec\n", SERVER_CONF.ping_timeout);
    sprintf(resBuf + strlen(resBuf), "  PING ALARM LATENCY (%d) ms", SERVER_CONF.ping_event_ms);

    APPLOG(APPLOG_DETAIL, "%s() response is >>>\n%s", __func__, resBuf);
    return send_mml_res_succMsg(rxIxpcMsg, resBuf, FLAG_COMPLETE, 0, 0);
}

int func_chg_http_cli_ping(IxpcQMsgType *rxIxpcMsg)
{
    APPLOG(APPLOG_DEBUG, "%s() called", __func__);

    MMLReqMsgType   *mmlReq=(MMLReqMsgType*)rxIxpcMsg->body;

    char *resBuf=respMsg;

    int interval = get_mml_para_int(mmlReq, "INTERVAL");
    int timeout = get_mml_para_int(mmlReq, "TIMEOUT");
    int ms = get_mml_para_int(mmlReq, "MS");

    int old_interval = SERVER_CONF.ping_interval;
    int old_timeout = SERVER_CONF.ping_timeout;
    int old_ms = SERVER_CONF.ping_event_ms;

    if (chgcfg_client_ping(interval, timeout, ms) < 0)
        return send_mml_res_failMsg(rxIxpcMsg, "PING MS CHANGE FAIL");

    if (interval >= 0) SERVER_CONF.ping_interval = interval;
    if (timeout >= 0) SERVER_CONF.ping_timeout = timeout;
    if (ms >= 0) SERVER_CONF.ping_event_ms = ms;

    sprintf(resBuf, "  PING INTERVAL (%d) --> (%d) sec\n", old_interval, SERVER_CONF.ping_interval);
    sprintf(resBuf + strlen(resBuf), "  PING TIMEOUT (%d) --> (%d) sec\n", old_timeout, SERVER_CONF.ping_timeout);
    sprintf(resBuf + strlen(resBuf), "  PING ALARM LATENCY (%d) --> (%d) ms\n", old_ms, SERVER_CONF.ping_event_ms);

    APPLOG(APPLOG_DETAIL, "%s() response is >>>\n%s", __func__, resBuf);
    return send_mml_res_succMsg(rxIxpcMsg, resBuf, FLAG_COMPLETE, 0, 0);
}
