#include <nrfm.h>
#include <comm_msgtypes.h>

extern main_ctx_t MAIN_CTX;
extern int ixpcQid;
char mySysName[COMM_MAX_NAME_LEN];
char myProcName[COMM_MAX_NAME_LEN];

char respMsg[MAX_MML_RESULT_LEN], respBuff[MAX_MML_RESULT_LEN];

typedef enum nrfm_cmd {
	dis_nf_acc_token,
	dis_nf_profile,
	chg_nf_status,
	MAX_CMD_NUM
} nrfm_cmd_t;

MmcHdlrVector   mmcHdlrVecTbl[MAX_CMD_NUM] =
{
	{ "DIS-NF-ACC-TOKEN",     func_dis_nf_acc_token},
	{ "DIS-NF-PROFILE",       func_dis_nf_profile},
	{ "CHG-NF-STATUS",        func_chg_nf_status}
};

void mml_function(IxpcQMsgType *rxIxpcMsg)
{
    int i;
    MMLReqMsgType   *mmlReq=(MMLReqMsgType*)rxIxpcMsg->body;
    MmcHdlrVector   mmcHdlr;

    APPLOG(APPLOG_DEBUG, "%s() receive cmdName(%s)", __func__, mmlReq->head.cmdName);

    for (i = 0; i < MAX_CMD_NUM; i++) {
        if (!strcasecmp(mmlReq->head.cmdName, mmcHdlrVecTbl[i].cmdName)) {
            sprintf(mySysName, "%s", MAIN_CTX.my_info.mySysName);
            sprintf(myProcName, "%s", MAIN_CTX.my_info.myProcName);

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

void adjust_loglevel(TrcLibSetPrintMsgType *trcMsg)
{
    if (trcMsg->trcLogFlag.pres) {
        if (trcMsg->trcLogFlag.octet == 9) {
            MAIN_CTX.sysconfig.debug_mode = (MAIN_CTX.sysconfig.debug_mode == 1 ? 0 : 1);
            APPLOG(APPLOG_ERR,"---- log level 9 (debug_mode on/off) now [%s]", MAIN_CTX.sysconfig.debug_mode == 1 ? "ON" : "OFF");
        } else {
            APPLOG(APPLOG_ERR,"---- log level change (%d -> %d)\n", *lOG_FLAG, trcMsg->trcLogFlag.octet);
            *lOG_FLAG = trcMsg->trcLogFlag.octet;
        }
    }
}

int func_dis_nf_acc_token(IxpcQMsgType *rxIxpcMsg)
{   
	APPLOG(APPLOG_DEBUG, "%s() called", __func__);

	char *resBuf=malloc(1024 * 1024);
	resBuf[0] = '\0';

	print_token_info_raw(MAIN_CTX.nrf_access_token.ACC_TOKEN_LIST, resBuf);

	APPLOG(APPLOG_DETAIL, "%s() response is >>>\n%s", __func__, resBuf);

	int res = send_mml_res_succMsg(rxIxpcMsg, resBuf, FLAG_COMPLETE, 0, 0);

	free(resBuf);
	return res;
}  

int func_dis_nf_profile(IxpcQMsgType *rxIxpcMsg)
{   
	APPLOG(APPLOG_DEBUG, "%s() called", __func__);

	char *resBuf=malloc(1024 * 1024);
	resBuf[0] = '\0';

    char key_name[128] = "my_profile";
    json_object *request_nf_profile = search_json_object(MAIN_CTX.my_nf_profile, key_name);

    ft_table_t *table = ft_create_table();
    ft_set_border_style(table, FT_PLAIN_STYLE);
    ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);
    ft_set_cell_prop(table, 0, 0, FT_CPROP_MIN_WIDTH, 55);
    ft_set_cell_prop(table, 0, 1, FT_CPROP_MIN_WIDTH, 55);
    ft_write_ln(table, "[Request to NRF]", "[Response from NRF]");
    ft_printf_ln(table, "%s|%s",  
            json_object_to_json_string_ext(request_nf_profile, JSON_C_PRETTY_NOSLASH),
            json_object_to_json_string_ext(MAIN_CTX.received_nf_profile, JSON_C_PRETTY_NOSLASH));

    ft_add_separator(table);

    ft_printf_ln(table, "Regi Status=[%s]",
       MAIN_CTX.last_regi_resp_code < 0 ? "Trying" :
       MAIN_CTX.last_regi_resp_code >= 200 && MAIN_CTX.last_regi_resp_code < 300 ? "Registered" : "Error");
    ft_printf_ln(table, "Last RespCode=[%d]", MAIN_CTX.last_regi_resp_code);
    ft_printf_ln(table, "Last RecvTime=[%.24s]",
       MAIN_CTX.last_regi_resp_code >= 200 && MAIN_CTX.last_regi_resp_code < 300 ? ctime(&MAIN_CTX.last_regi_resp_time) : "Not Registered");
    ft_printf_ln(table, ">>>> NF Undiscoverable Set=[%d] <<<<",
        MAIN_CTX.prefer_undiscover_set);

    ft_add_separator(table);

    sprintf(resBuf, ft_to_string(table));

	APPLOG(APPLOG_DETAIL, "%s() response is >>>\n%s", __func__, resBuf);

	int res = send_mml_res_succMsg(rxIxpcMsg, resBuf, FLAG_COMPLETE, 0, 0);

	free(resBuf);
    ft_destroy_table(table);
    return res;
}

int func_chg_nf_status(IxpcQMsgType *rxIxpcMsg)
{   
	APPLOG(APPLOG_DEBUG, "%s() called", __func__);

    MMLReqMsgType   *mmlReq=(MMLReqMsgType*)rxIxpcMsg->body;

	char *resBuf=malloc(1024 * 1024);
	resBuf[0] = '\0';

    char *err_txt_para_cnt = "err) para count must 1";
    char *err_txt_para_format = "err) para string must be \"REGI\" or \"UNDISCOVER\"";
    char *err_txt_not_registered = "err) NF status not regi, can't change to \"UNDISCOVER\"";

    if (mmlReq->head.paraCnt != 1) {
        return send_mml_res_failMsg(rxIxpcMsg, err_txt_para_cnt);
    }

#ifdef MMLPARA_TYPESTR
    char *apply_value = mmlReq->head.para[0].paraStr;
#else
    char *apply_value = mmlReq->head.para[0].paraVal;
#endif
    if (strcasecmp(apply_value, "REGI") && strcasecmp(apply_value, "UNDISCOVER")) {
        return send_mml_res_failMsg(rxIxpcMsg, err_txt_para_format);
    }

    if (!strcasecmp(apply_value, "UNDISCOVER")) {
        if (MAIN_CTX.last_regi_resp_code < 200 || MAIN_CTX.last_regi_resp_code >= 300) {
            return send_mml_res_failMsg(rxIxpcMsg, err_txt_not_registered);
        }
    }

    if (!strcasecmp(apply_value, "REGI")) {
        MAIN_CTX.prefer_undiscover_set = 0;
        sprintf(resBuf, "\n\n[ change NF STATUS as REGISTERED, after next HEARTBEAT to NRF ]\n\n");
    } else {
        MAIN_CTX.prefer_undiscover_set = 1;
        sprintf(resBuf, "\n\n[ change NF STATUS is UNDISCOVERABLE, after next HEARTBEAT to NRF ]\n\n");
    }

	APPLOG(APPLOG_DETAIL, "%s() response is >>>\n%s", __func__, resBuf);

	int res = send_mml_res_succMsg(rxIxpcMsg, resBuf, FLAG_COMPLETE, 0, 0);

	free(resBuf);
    return res;
}
