#include "server.h"
#include <comm_msgtypes.h>

#define MAX_LEN_RES_BUF 10000

extern int httpsQid;
extern int ixpcQid;
extern server_conf SERVER_CONF;
extern thrd_context THRD_WORKER[MAX_THRD_NUM];
extern allow_list_t ALLOW_LIST[MAX_LIST_NUM];
extern config_t CFG;
extern char CONFIG_PATH[256];
extern lb_global_t LB_CONF;

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
	dis_https_config,
    chg_https_config,
    dis_https_weight,
    chg_https_weight,
	MAX_CMD_NUM
} server_cmd_t;

MmcHdlrVector   mmcHdlrVecTbl[MAX_CMD_NUM] =
{
#ifdef EPCF
    { "PCF-DIS-NF-CLIENT",     func_dis_http_client},
    { "PCF-ADD-NF-CLIENT",     func_add_http_client},
    { "PCF-ADD-NF-CLI-IP",     func_add_http_cli_ip},
    { "PCF-ACT-NF-CLIENT",     func_act_http_client},
    { "PCF-DACT-NF-CLIENT",    func_dact_http_client},
    { "PCF-CHG-NF-CLIENT",     func_chg_http_client},
    { "PCF-DEL-NF-CLI-IP",     func_del_http_cli_ip},
    { "PCF-DEL-NF-CLIENT",     func_del_http_client},
	{ "PCF-DIS-HTTPS-CONFIG",  func_dis_https_config},
	{ "PCF-CHG-HTTPS-CONFIG",  func_chg_https_config},
	{ "PCF-DIS-HTTPS-WEIGHT",  func_https_weight_conf},
	{ "PCF-CHG-HTTPS-WEIGHT",  func_https_weight_conf}
#else
    { "DIS-NF-CLIENT",     func_dis_http_client},
    { "ADD-NF-CLIENT",     func_add_http_client},
    { "ADD-NF-CLI-IP",     func_add_http_cli_ip},
    { "ACT-NF-CLIENT",     func_act_http_client},
    { "DACT-NF-CLIENT",    func_dact_http_client},
    { "CHG-NF-CLIENT",     func_chg_http_client},
    { "DEL-NF-CLI-IP",     func_del_http_cli_ip},
    { "DEL-NF-CLIENT",     func_del_http_client},
	{ "DIS-HTTPS-CONFIG",  func_dis_https_config},
	{ "CHG-HTTPS-CONFIG",  func_chg_https_config},
	{ "DIS-HTTPS-WEIGHT",  func_https_weight_conf},
	{ "CHG-HTTPS-WEIGHT",  func_https_weight_conf}
#endif
};

void handle_nrfm_request(GeneralQMsgType *msg)
{
    nrfm_https_remove_conn_t *remove_direct = (nrfm_https_remove_conn_t *)msg->body;
    int list_index = remove_direct->list_index;
    int item_index = remove_direct->item_index;
    const char *ip = remove_direct->host;

    for (int i = 0; i < MAX_LIST_NUM; i++) {
        if (ALLOW_LIST[i].used == 0 || ALLOW_LIST[i].auto_added != 1 || ALLOW_LIST[i].curr > 0)
            continue;
        if (ALLOW_LIST[i].list_index == list_index && ALLOW_LIST[i].item_index == item_index) {
            if (!strcmp(ALLOW_LIST[i].ip, ip)) {
                APPLOG(APPLOG_ERR, "%s() remove old tombstone https conn host (%s)", __func__, ip);
                memset(&ALLOW_LIST[i], 0x00, sizeof(allow_list_t));
            }
        }
    }

    if (list_index > 0)
        del_list(ip);
    if (item_index > 0)
        del_item(list_index, ip, 0);
}

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

	if (msgsnd(THRD_WORKER[thrd_index].msg_id, &intl_req, sizeof(intl_req) - sizeof(long), IPC_NOWAIT) == -1) {
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

	while (msgrcv(httpsQid, msg, sizeof(GeneralQMsgType), 0, IPC_NOWAIT|MSG_NOERROR) >= 0) {
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
            case MSGID_NRFM_HTTPS_RESPONSE:
                handle_nrfm_response(msg);
                continue;
            case MSGID_NRFM_HTTPS_REQUEST:
                handle_nrfm_request(msg);
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
        if (!strcasecmp(mmlReq->head.cmdName, mmcHdlrVecTbl[i].cmdName)) {
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
    const char *error_reason = NULL;

    memset(HOSTNAME, 0x00, sizeof(HOSTNAME));
    memset(TYPE, 0x00, sizeof(TYPE));

    if (get_mml_para_str(mmlReq, "HOSTNAME", HOSTNAME) < 0)
        return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING [HOSTNAME]");
    if (get_mml_para_str(mmlReq, "TYPE", TYPE) < 0)
        return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING [TYPE]");

    if (addcfg_client_hostname(HOSTNAME, TYPE, &error_reason) < 0)
        return send_mml_res_failMsg(rxIxpcMsg, error_reason);

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
    int AUTH_ACT = -1;
    struct sockaddr_in sa;
    struct sockaddr_in6 sa6;
    const char *error_reason = NULL;
    
    memset(IPADDR, 0x00, sizeof(IPADDR));
    
    if ((ID = get_mml_para_int(mmlReq, "ID")) < 0)
        return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING [ID]");
    if (get_mml_para_str(mmlReq, "IPADDR", IPADDR) < 0)
        return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING [IPADDR]");
    if ((MAX = get_mml_para_int(mmlReq, "MAX")) < 0)
        return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING [MAX]");
    if ((AUTH_ACT = get_mml_para_int(mmlReq, "AUTH_ACT")) < 0)
        return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING [AUTH_ACT]");
    
    if (ID >= HTTP_MAX_HOST)
        return send_mml_res_failMsg(rxIxpcMsg, "INVALID ID");
	if (inet_pton(AF_INET, IPADDR, &(sa.sin_addr))) {
	} else if (inet_pton(AF_INET6, IPADDR, &(sa6.sin6_addr))) {
	} else {
		return send_mml_res_failMsg(rxIxpcMsg, "INVALID IPADDR");
	}
    if (MAX <= 0 || MAX >= 65535)
        return send_mml_res_failMsg(rxIxpcMsg, "INVALID MAX");
    if (AUTH_ACT != 0 && AUTH_ACT != 1)
        return send_mml_res_failMsg(rxIxpcMsg, "INVALID AUTH_ACT [0 or 1 avail]");
    
    if (addcfg_client_ipaddr(ID, IPADDR, MAX, AUTH_ACT, &error_reason) < 0)
        return send_mml_res_failMsg(rxIxpcMsg, error_reason);
    
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
    const char *error_reason = NULL;
    
    memset(IPADDR, 0x00, sizeof(IPADDR));
    
    if ((ID = get_mml_para_int(mmlReq, "ID")) < 0)
        return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING [ID]");
    
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
    
    if (actcfg_http_client(ID, ip_exist, IPADDR, change_to_act, &error_reason) < 0)
        return send_mml_res_failMsg(rxIxpcMsg, error_reason);


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
    const char *error_reason = NULL;

    memset(IPADDR, 0x00, sizeof(IPADDR));

    if ((ID = get_mml_para_int(mmlReq, "ID")) < 0)
        return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING [ID]");
    if (get_mml_para_str(mmlReq, "IPADDR", IPADDR) < 0)
        return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING [IPADDR]");
    if ((MAX = get_mml_para_int(mmlReq, "MAX")) < 0)
        return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING [MAX]");
    if ((LIMIT = get_mml_para_int(mmlReq, "LIMIT")) < 0)
        return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING [LIMIT]");
    if ((AUTH_ACT = get_mml_para_int(mmlReq, "AUTH_ACT")) < 0)
        return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING [AUTH_ACT]");

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

    if (chgcfg_client_max_cnt_with_auth_act_and_limit(ID, IPADDR, MAX, AUTH_ACT, LIMIT, &error_reason) < 0)
        return send_mml_res_failMsg(rxIxpcMsg, error_reason);

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
    const char *error_reason = NULL;

    memset(IPADDR, 0x00, sizeof(IPADDR));

    if ((ID = get_mml_para_int(mmlReq, "ID")) < 0)
        return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING [ID]");
    if (get_mml_para_str(mmlReq, "IPADDR", IPADDR) < 0)
        return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING [IPADDR]");

    if (ID >= HTTP_MAX_HOST)
        return send_mml_res_failMsg(rxIxpcMsg, "INVALID ID");
	if (inet_pton(AF_INET, IPADDR, &(sa.sin_addr))) {
	} else if (inet_pton(AF_INET6, IPADDR, &(sa6.sin6_addr))) {
	} else {
		return send_mml_res_failMsg(rxIxpcMsg, "INVALID IPADDR");
	}

    if (delcfg_client_ipaddr(ID, IPADDR, &error_reason) < 0)
        return send_mml_res_failMsg(rxIxpcMsg, error_reason);

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
    const char *error_reason = NULL;

    if ((ID = get_mml_para_int(mmlReq, "ID")) < 0)
        return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING [ID]");

    if (ID >= HTTP_MAX_HOST)
        return send_mml_res_failMsg(rxIxpcMsg, "INVALID ID");

    if (delcfg_client_hostname(ID, &error_reason) < 0)
        return send_mml_res_failMsg(rxIxpcMsg, error_reason);

    write_list(resBuf);

	APPLOG(APPLOG_DETAIL, "%s() response is >>>\n%s", __func__, resBuf);
    return send_mml_res_succMsg(rxIxpcMsg, resBuf, FLAG_COMPLETE, 0, 0);
}

int func_dis_https_config(IxpcQMsgType *rxIxpcMsg)
{
    APPLOG(APPLOG_DEBUG, "%s() called", __func__);

    char *resBuf=respMsg;

    int res = print_single_http_cfg(&CFG, "server_cfg.http_config", "http_config = ", "https - http/2 config", resBuf);
    
    if (res < 0)
        return send_mml_res_failMsg(rxIxpcMsg, ".CFG LOADING FAIL");
    else
        return send_mml_res_succMsg(rxIxpcMsg, resBuf, FLAG_COMPLETE, 0, 0);
}

void relaod_http_config(char *conf_name, int conf_val)
{
/* change config */
    if (!strcmp(conf_name, CF_TIMEOUT_SEC))
        SERVER_CONF.timeout_sec = conf_val;
    else if (!strcmp(conf_name, CF_PING_INTERVAL))
        SERVER_CONF.ping_interval = conf_val;
    else if (!strcmp(conf_name, CF_PING_TIMEOUT))
        SERVER_CONF.ping_timeout = conf_val;
    else if (!strcmp(conf_name, CF_PING_EVENT_MS))
        SERVER_CONF.ping_event_ms = conf_val;
    else if (!strcmp(conf_name, CF_DEF_OVLD_LIMIT))
        SERVER_CONF.def_ovld_limit = conf_val;
    else if (!strcmp(conf_name, CF_ALLOW_ANY_CLIENT))
        SERVER_CONF.allow_any_client = conf_val;
    else if (!strcmp(conf_name, CF_ANY_CLIENT_DEFAULT_MAX))
        SERVER_CONF.any_client_default_max = conf_val;
    else if (!strcmp(conf_name, CF_ANY_CLIENT_OAUTH_ENABLE))
        SERVER_CONF.any_client_oauth_enable = conf_val;
    else if (!strcmp(conf_name, CF_TRACE_ENABLE))
        SERVER_CONF.trace_enable = conf_val;

/* hook */
    if (!strcmp(conf_name, CF_ALLOW_ANY_CLIENT) && conf_val == 0 ) {
        for (int i = 1; i < MAX_LIST_NUM; i++) {
            allow_list_t *allow_row = &ALLOW_LIST[i];
            if (allow_row->used == 0 || allow_row->auto_added != 1 || allow_row->curr <= 0) {
                continue;
            } else {
                disconnect_all_client_in_allow_list(allow_row);
                memset(allow_row, 0x00, sizeof(allow_list_t));
            }
        }
    }
}

int func_chg_https_config(IxpcQMsgType *rxIxpcMsg)
{
    APPLOG(APPLOG_DEBUG, "%s() called", __func__);

    MMLReqMsgType   *mmlReq=(MMLReqMsgType*)rxIxpcMsg->body;
    char *resBuf=respMsg;

    char apply_config[1024] = {0,};
    config_setting_t *setting = NULL;
    char err_reply_text[1024] = {0,};

    char before_apply[10240] = {0,};
    print_single_http_cfg(&CFG, "server_cfg.http_config", "http_config = ", "https - http/2 config", before_apply);

    for(int i=0; i < mmlReq->head.paraCnt; i++ ) {
#ifdef MMLPARA_TYPESTR
        sprintf(apply_config, "server_cfg.http_config.%s",
                strlwr(mmlReq->head.para[i].typeStr, strlen(mmlReq->head.para[i].typeStr)));
        int apply_value = atoi(mmlReq->head.para[i].paraStr);
#else
        sprintf(apply_config, "server_cfg.http_config.%s",
                strlwr(mmlReq->head.para[i].paraName, strlen(mmlReq->head.para[i].paraName)));
        int apply_value = atoi(mmlReq->head.para[i].paraVal);
#endif

        if ((setting = config_lookup(&CFG, apply_config)) == NULL) {
            sprintf(err_reply_text, "ERROR> fail to find (%s) in config", apply_config);
            goto FCHC_RET_ERR;
        }

        /* skip value check because omp already do it */
        if (config_setting_set_int(setting, apply_value) < 0) {
            sprintf(err_reply_text, "ERROR> fail to change(%s) to val(%d)", apply_config, apply_value);
            goto FCHC_RET_ERR;
        }

        relaod_http_config(apply_config, apply_value);
    }

    // save to file
    config_write_file(&CFG, CONFIG_PATH);

    char after_apply[10240] = {0,};
    print_single_http_cfg(&CFG, "server_cfg.http_config", "http_config = ", "https - http/2 config", after_apply);

    print_dual_http_cfg(before_apply, after_apply, resBuf);

    return send_mml_res_succMsg(rxIxpcMsg, resBuf, FLAG_COMPLETE, 0, 0);

FCHC_RET_ERR:
    return send_mml_res_failMsg(rxIxpcMsg, err_reply_text);
}

char *https_weight_print(char *resBuf /*enough large*/)
{
    sprintf(resBuf + strlen(resBuf), "\n\n---------------------------------\n");
    sprintf(resBuf + strlen(resBuf), "     https weight load info      \n");
    sprintf(resBuf + strlen(resBuf), "---------------------------------\n");

    char temp_buff[1024] = {0,};
    for (int i = 0; i < SERVER_CONF.size; i++) {
        sprintf(temp_buff + strlen(temp_buff), "%d%s", SERVER_CONF.weight[i], i == (SERVER_CONF.size - 1) ? "" : ":");
    }

    int len = strlen(temp_buff);
    int jump_pos = (strlen("---------------------------------") - len) / 2;
    for (int i = 0; i < jump_pos; i++) {
        sprintf(resBuf + strlen(resBuf), " ");
    }

    sprintf(resBuf + strlen(resBuf), "%s\n", temp_buff);
    sprintf(resBuf + strlen(resBuf), "---------------------------------\n");

    return resBuf;
}

int func_https_weight_conf(IxpcQMsgType *rxIxpcMsg)
{
    APPLOG(APPLOG_DEBUG, "%s() called", __func__);

    MMLReqMsgType   *mmlReq=(MMLReqMsgType*)rxIxpcMsg->body;
    char *resBuf=respMsg;

    char *err_txt_para_cnt = "err) para count must 0 or 1";
    char *err_txt_para_invalid = "err) para string invaild (number or \':\' only)";
    char *err_txt_para_format = "err) para string not match with fep num";

    if (mmlReq->head.paraCnt != 0 && mmlReq->head.paraCnt != 1) {
        return send_mml_res_failMsg(rxIxpcMsg, err_txt_para_cnt);
    }

    /* Display weight load info & return */
    if (mmlReq->head.paraCnt == 0) {
        return send_mml_res_succMsg(rxIxpcMsg, https_weight_print(resBuf), FLAG_COMPLETE, 0, 0);
    }

    /* Change weight load info & save to config */
#ifdef MMLPARA_TYPESTR
    char *apply_value = mmlReq->head.para[0].paraStr;
#else
    char *apply_value = mmlReq->head.para[0].paraVal;
#endif

    /* --> check digit & : */
    int tok_size = 0;
    for (int i = 0; i < strlen(apply_value); i++) {
        if (isdigit(apply_value[i]) == 0 && apply_value[i] != ':')
            return send_mml_res_failMsg(rxIxpcMsg, err_txt_para_invalid);
        if (apply_value[i] == ':')
            tok_size++;
    }

    /* --> check : num */
    if (tok_size != (SERVER_CONF.size - 1)) {
        return send_mml_res_failMsg(rxIxpcMsg, err_txt_para_format);
    }

    /* save to memory */
    char *ptr = strtok(apply_value, ":");
    int index = 0;
    while (ptr != NULL) {
        SERVER_CONF.weight[index] = atoi(ptr);
        config_setting_t *cf_weight = config_setting_get_elem(LB_CONF.cf_fep_weight_balance, index);
        config_setting_set_int(cf_weight, SERVER_CONF.weight[index]);
        ptr = strtok(NULL, ":");
        index++;
    }

    /* save to .cfg */
    config_write_file(&CFG, CONFIG_PATH);

    return send_mml_res_succMsg(rxIxpcMsg, https_weight_print(resBuf), FLAG_COMPLETE, 0, 0);
}
