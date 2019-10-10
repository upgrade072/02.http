#include <nrfm.h>
#include <comm_msgtypes.h>

extern main_ctx_t MAIN_CTX;
extern int ixpcQid;
char mySysName[COMM_MAX_NAME_LEN];
char myProcName[COMM_MAX_NAME_LEN];

char respMsg[MAX_MML_RESULT_LEN], respBuff[MAX_MML_RESULT_LEN];

typedef enum nrfm_cmd {
	dis_acc_token,
	MAX_CMD_NUM
} nrfm_cmd_t;

MmcHdlrVector   mmcHdlrVecTbl[MAX_CMD_NUM] =
{
	{ "DIS-ACC-TOKEN",     func_dis_acc_token}
};

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

int func_dis_acc_token(IxpcQMsgType *rxIxpcMsg)
{   
	APPLOG(APPLOG_DEBUG, "%s() called", __func__);

	char *resBuf=respMsg;
	sprintf(mySysName, "%s", MAIN_CTX.my_info.mySysName);
	sprintf(myProcName, "%s", MAIN_CTX.my_info.myProcName);

	print_token_info_raw(MAIN_CTX.nrf_access_token.ACC_TOKEN_LIST, resBuf);

	APPLOG(APPLOG_DETAIL, "%s() response is >>>\n%s", __func__, resBuf);
	return send_mml_res_succMsg(rxIxpcMsg, resBuf, FLAG_COMPLETE, 0, 0);
}  
