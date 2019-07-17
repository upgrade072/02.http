/* omp status and statistic related */

#include "libs.h"
           
/* for status */
extern char mySysName[COMM_MAX_NAME_LEN];
extern char myProcName[COMM_MAX_NAME_LEN];
extern int ixpcQid, mmibQid;

/* for statistic */
extern http_stat_t HTTP_STAT;
extern index_t INDEX[MAX_LIST_NUM];

/*
 * status
 */
void http_report_status(SFM_HttpConnStatusList *http_status, int msgId)
{
	GeneralQMsgType	txGenQMsg;
	IxpcQMsgType	*txIxpcMsg;
	int i, totalLen = 0, txLen = 0, len = 0;
	char *ptr;
#ifdef MMIB_STATUS
	int destQid = mmibQid; /* for nssf */
#else
	int destQid = ixpcQid;
#endif

	txIxpcMsg = (IxpcQMsgType*)txGenQMsg.body;
	ptr = (char *)txIxpcMsg->body;

	/* ixpc routing header */
	strcpy (txIxpcMsg->head.srcSysName, mySysName);
	strcpy (txIxpcMsg->head.srcAppName, myProcName);

	strcpy (txIxpcMsg->head.dstSysName, "OMP");
	strcpy (txIxpcMsg->head.dstAppName, "FIMD");

	/* set msgsnd mtype */
	txGenQMsg.mtype = MTYPE_STATUS_REPORT;

	/* http status report */
	txIxpcMsg->head.msgId = msgId;
	txIxpcMsg->head.seqNo = 0; // start from 1

	/* calc seq */
	totalLen = sizeof(int) + sizeof(SFM_HttpConnStatus) * http_status->cnt;
	if (totalLen > MAX_IXPC_QMSG_LEN) {
		txIxpcMsg->head.segFlag = 1;
	}

	for (i = 0; i < http_status->cnt; i++) {
		if (i == 0) {
			memcpy(ptr, &http_status->cnt, sizeof(int));
			ptr += sizeof(int);
			len += sizeof(int);
		}
		memcpy(ptr, &http_status->conn[i], sizeof(SFM_HttpConnStatus));
		ptr += sizeof(SFM_HttpConnStatus);
		len += sizeof(SFM_HttpConnStatus);

		/* check next size, send fulfilled msg  */
		if ((len + sizeof(SFM_HttpConnStatus)) > MAX_IXPC_QMSG_LEN) {
			/* send */
			txIxpcMsg->head.seqNo ++;
			txIxpcMsg->head.bodyLen = len;
			txLen = sizeof(txIxpcMsg->head) + txIxpcMsg->head.bodyLen;
			//DumpHex(&txGenQMsg, txLen);
			if (msgsnd(destQid, (void*)&txGenQMsg, txLen, IPC_NOWAIT) < 0) {
				//APPLOG(APPLOG_ERR, "DBG] http status send fail qid[%s]\n", strerror(errno));
				return;
			} else {
				/* init */
				ptr = (char *)&txIxpcMsg;
				len = 0;
			}
		}
	}
	/* send last msg*/
	txIxpcMsg->head.segFlag = 0;
	txIxpcMsg->head.seqNo ++;
	txIxpcMsg->head.bodyLen = len;
	txLen = sizeof(txIxpcMsg->head) + txIxpcMsg->head.bodyLen;
	//DumpHex(&txGenQMsg, txLen);
	if (msgsnd(destQid, (void*)&txGenQMsg, txLen, IPC_NOWAIT) < 0) {
		//APPLOG(APPLOG_ERR, "DBG] http status send fail qid[%s]\n", strerror(errno));
		return;
	}
	return;
}

/*
 * statistics
 */
void http_stat_inc(int thrd_idx, int host_idx, int stat_idx)
{
	if (thrd_idx < 0 || thrd_idx >= MAX_THRD_NUM)
		return;
	if (host_idx < 0 || host_idx >= HTTP_MAX_HOST) // host 0 --> unknown host
		return;
	if (stat_idx < 0 || stat_idx >= HTTP_STAT_MAX)
		return;

	int curr_idx = HTTP_STAT.current;
	HTTP_STAT.stat[curr_idx].http_stat_thrd[thrd_idx].http_stat_host[host_idx][stat_idx]++;
	return;
}

int httpc_stat_idx[] =
{ HTTP_TX_REQ, HTTP_RX_RSP, HTTP_CONN, HTTP_DISCONN, HTTP_TIMEOUT, HTTP_RX_RST, HTTP_STRM_N_FOUND, HTTP_DEST_N_AVAIL };
int https_stat_idx[] =
{ HTTP_RX_REQ, HTTP_TX_RSP, HTTP_CONN, HTTP_DISCONN, HTTP_TIMEOUT, HTTP_RX_RST, HTTP_PRE_END, HTTP_STRM_N_FOUND} ;
char httpc_stat_str[][128] =
{ "HTTP_TX_REQ", "HTTP_RX_RSP", "HTTP_CONN", "HTTP_DISCONN", "HTTP_TIMEOUT", "HTTP_RX_RST", "HTTP_STRM_N_FOUND", "HTTP_DEST_N_AVAIL" };
char https_stat_str[][128] =
{ "HTTP_RX_REQ", "HTTP_TX_RSP", "HTTP_CONN", "HTTP_DISCONN", "HTTP_TIMEOUT", "HTTP_RX_RST", "HTTP_PRE_END", "HTTP_STRM_N_FOUND"} ;
int httpc_stat_size = sizeof(httpc_stat_idx) / sizeof(int);
int https_stat_size = sizeof(https_stat_idx) / sizeof(int);

void stat_function(IxpcQMsgType *rxIxpcMsg, int running_thrd_num, int httpc, int https, int msgId)
{
    int (*http_stat_host)[HTTP_STAT_MAX] = NULL;
    int index = 0, item_size = 0, write_count = 0, i, j, k;
	int *item_ptr = NULL;
	char (*item_str)[128] = NULL;
	int pos = 0;
	int len = sizeof(int), txLen = 0;

    GeneralQMsgType sxGenQMsg;
    memset(&sxGenQMsg, 0x00, sizeof(GeneralQMsgType));

	IxpcQMsgType *sxIxpcMsg = (IxpcQMsgType*)sxGenQMsg.body;

	STM_CommonStatMsgType *commStatMsg=NULL;
	STM_CommonStatMsg     *commStatItem=NULL;

    sxGenQMsg.mtype = MTYPE_STATISTICS_REPORT;
	/* http status report */
	sxIxpcMsg->head.msgId = msgId;
	sxIxpcMsg->head.seqNo = 0; // start from 1

    strcpy(sxIxpcMsg->head.srcSysName, rxIxpcMsg->head.dstSysName);
    strcpy(sxIxpcMsg->head.srcAppName, rxIxpcMsg->head.dstAppName);
    strcpy(sxIxpcMsg->head.dstSysName, rxIxpcMsg->head.srcSysName);
    strcpy(sxIxpcMsg->head.dstAppName, rxIxpcMsg->head.srcAppName);

    /* change stat index step forward */
    index = HTTP_STAT.current;
    HTTP_STAT.current = (HTTP_STAT.current + 1) % HTTP_STAT_CHAIN; // now worker write to other side
	/* determine httpc / https */
	item_size = (httpc ? httpc_stat_size : (https ? https_stat_size : 0));
	item_ptr =  (httpc ? httpc_stat_idx  : (https ? https_stat_idx  : NULL));
	item_str =  (httpc ? httpc_stat_str  : (https ? https_stat_str  : NULL));
	/* if use incorrect, error return */
	if (item_ptr == NULL) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} something wrong func(%s) line(%d)\n",  __func__, __LINE__);
		return;
	}

	commStatMsg = (STM_CommonStatMsgType *)sxIxpcMsg->body;
	commStatItem = &commStatMsg->info[0];
	for (i = 0; i < HTTP_MAX_HOST; i++) {
		if (i != 0  && INDEX[i].occupied == 0) 
			continue;
		if (i == 0)
			snprintf(commStatItem->strkey1, sizeof(commStatItem->strkey1), "%s", "UNKNOWN");
		else
			snprintf(commStatItem->strkey1, sizeof(commStatItem->strkey1), "%s", INDEX[i].listname);

		APPLOG(APPLOG_ERR, "[STAT FOR HOST : %s ]", commStatItem->strkey1);

		for (j = 0; j < item_size; j++) {
			pos = item_ptr[j];
			for (k = 0; k < running_thrd_num; k++) {
				http_stat_host = HTTP_STAT.stat[index].http_stat_thrd[k].http_stat_host;
				commStatItem->ldata[j] += http_stat_host[i][pos];
			}
		}
		write_count++;
		commStatMsg->num = write_count;
		len += sizeof (STM_CommonStatMsg);
		print_stat(commStatMsg, commStatItem, item_str, item_size);

		/* check next size, send fulfilled msg  */
		if ((len + sizeof (STM_CommonStatMsg)) > MAX_IXPC_QMSG_LEN) {
			sxIxpcMsg->head.segFlag = 1;
			sxIxpcMsg->head.seqNo++;
			sxIxpcMsg->head.bodyLen = len;
			txLen = sizeof(sxIxpcMsg->head) + sxIxpcMsg->head.bodyLen;
			commStatItem = (STM_CommonStatMsg *)sxIxpcMsg->body;
			len = 0;
			if (msgsnd(ixpcQid, (void*)&sxGenQMsg, txLen, IPC_NOWAIT) < 0) {
				//APPLOG(APPLOG_ERR, "DBG] http status send fail qid[%s]\n", strerror(errno));
				goto HTTP_STATUS_SEND_FAIL;
			}
		} else {
			commStatItem ++;
		}
	}

	/* send last (or first) message */
	sxIxpcMsg->head.segFlag = 0;
	sxIxpcMsg->head.seqNo++;
	sxIxpcMsg->head.bodyLen = len;
	txLen = sizeof(sxIxpcMsg->head) + sxIxpcMsg->head.bodyLen;
#if 0 // for test
    fprintf(stderr, "\n\nDBG STAT SEND]\n");
    DumpHex(&sxGenQMsg, txLen);
    fprintf(stderr, "\n\n");
#endif
	if (msgsnd(ixpcQid, (void*)&sxGenQMsg, txLen, IPC_NOWAIT) < 0) {
		//APPLOG(APPLOG_ERR, "DBG] http status send fail qid[%s]\n", strerror(errno));
		goto HTTP_STATUS_SEND_FAIL;
	}

HTTP_STATUS_SEND_FAIL:
	memset(&HTTP_STAT.stat[index], 0x00, sizeof(http_stat_thrd_t));
	return;
}

void print_stat(STM_CommonStatMsgType *commStatMsg, STM_CommonStatMsg *commStatItem, char (*str)[128], int size)
{
	//APPLOG(APPLOG_ERR, "CommStatMsg num now [%d]\n", commStatMsg->num);
	//APPLOG(APPLOG_ERR, "Item Write [%-15s]  ", commStatItem->strkey1);
	for (int i = 0; i < size; i++) {
		APPLOG(APPLOG_ERR, "%-15s: %-7ld ", str[i], commStatItem->ldata[i]);
	}
	APPLOG(APPLOG_ERR, "\n");
}
