#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <comm_msgtypes.h>

#include <libs.h>

char mySysName[COMM_MAX_NAME_LEN];
char myProcName[COMM_MAX_NAME_LEN];
int ixpcQid;
char respBuff[MAX_MML_RESULT_LEN];

int get_mml_para_int (MMLReqMsgType *msg, char *paraName)
{           
	int	i=0;

	for( i=0; i<msg->head.paraCnt; i++ ) {
		if( !strcasecmp(msg->head.para[i].paraName, paraName)) {
			return (int)strtol(msg->head.para[i].paraVal,0,0);
		}
	}
	return -1;
}

int get_mml_para_str (MMLReqMsgType *msg, char *paraName, char *buff)
{   
	int	i=0;      

	for( i=0; i<msg->head.paraCnt; i++ ) {
		if( !strcasecmp (msg->head.para[i].paraName, paraName) ) {
			strcpy (buff, msg->head.para[i].paraVal);
			return 1;
		}
	}

	return -1; 
}

int get_mml_para_strMax (MMLReqMsgType *msg, char *paraName, char *buff, int maxSize)
{       
	int	i=0;

	for( i=0; i<msg->head.paraCnt; i++ ) {
		if( !strcasecmp (msg->head.para[i].paraName, paraName) ) {
			if( strlen(msg->head.para[i].paraVal)<=maxSize ) {
				strcpy (buff, msg->head.para[i].paraVal);
				return 1;
			}
			break;
		}
	}

	return -1;
}

int send_mml_res_failMsg(IxpcQMsgType *rxIxpcMsg, char *rltMsg)
{
	int		len=0;
	char	*txBuff=respBuff;

	len  = sprintf(txBuff, "\n  RESULT = FAIL\n  SYSTEM = %s\n\n", mySysName);
	len += sprintf(&txBuff[len], "  REASON = %s\n", rltMsg);

	return send_response_mml(rxIxpcMsg, txBuff, RES_FAIL, FLAG_COMPLETE, 0, 0);
}

int send_mml_res_succMsg(IxpcQMsgType *rxIxpcMsg, char *rltMsg, char contFlag, unsigned short extendTime, char seqNo)
{
	sprintf(rltMsg + strlen(rltMsg), "\n  RESULT = SUCCESS\n  SYSTEM = %s\n\n", mySysName);

	return send_response_mml(rxIxpcMsg, rltMsg, RES_SUCCESS, contFlag, extendTime, seqNo);
}


int send_response_mml(IxpcQMsgType *rxIxpcMsg, char *resbuf, char resCode, char contFlag, unsigned short extendTime, char seqNo)
{
    int              txLen;
	GeneralQMsgType  txGenQ;
    IxpcQMsgType     *txIxpcMsg;
    MMLResMsgType    *txResMsg;
    MMLReqMsgType    *mmlReqMsg;

	memset(&txGenQ, 0x00, sizeof(GeneralQMsgType));

    txIxpcMsg	= (IxpcQMsgType *)txGenQ.body;
    mmlReqMsg	= (MMLReqMsgType *)rxIxpcMsg->body;
    txResMsg	= (MMLResMsgType *)txIxpcMsg->body;

    txGenQ.mtype = MTYPE_MMC_RESPONSE;

    txIxpcMsg->head.msgId = rxIxpcMsg->head.msgId;
    strcpy (txIxpcMsg->head.srcSysName, mySysName);
    strcpy (txIxpcMsg->head.srcAppName, myProcName);
    strcpy (txIxpcMsg->head.dstSysName, rxIxpcMsg->head.srcSysName);
    strcpy (txIxpcMsg->head.dstAppName, rxIxpcMsg->head.srcAppName);

	int remain_len = strlen(resbuf);
	int seq_no = 0;

	/* split res buff */
	while (remain_len > 0) {
		txResMsg->head.mmcdJobNo 	= mmlReqMsg->head.mmcdJobNo;
		txResMsg->head.extendTime 	= extendTime;
		txResMsg->head.resCode 		= resCode;
		strcpy(txResMsg->head.cmdName, mmlReqMsg->head.cmdName);

		int send_limit_len = (MAX_MML_RESULT_LEN - 128); // maybe omp process use this buff
		int process_len = ((remain_len >= send_limit_len) ? send_limit_len : remain_len);
		memcpy(txResMsg->body, resbuf, process_len);
		txResMsg->body[process_len + 1] = '\0';

		resbuf += process_len;
		remain_len -= process_len;
		if (remain_len > 0) {
			txResMsg->head.contFlag = 1;
			txIxpcMsg->head.seqNo = seq_no++;
			txIxpcMsg->head.segFlag = FLAG_CONTINUE;
		} else {
			txResMsg->head.contFlag = 0;
			txIxpcMsg->head.seqNo = 0;
			txIxpcMsg->head.segFlag = FLAG_COMPLETE;
		}

		txIxpcMsg->head.bodyLen = sizeof(txResMsg->head) + strlen(txResMsg->body);
		txLen = sizeof(long) + sizeof(txIxpcMsg->head) + txIxpcMsg->head.bodyLen;

		if( msgsnd(ixpcQid, (void *)&txGenQ, txLen, IPC_NOWAIT )<0 ) {
			return -1;
		} 
		APPLOG(APPLOG_DETAIL, "sndMsg Success sendLen(%d)", txLen);
		APPLOG(APPLOG_DETAIL, "(%s)", txResMsg->body);
	}

    return 0;
}
