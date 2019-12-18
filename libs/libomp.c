/* omp status and statistic related */

#include "libs.h"
           
/* for status */
extern char mySysName[COMM_MAX_NAME_LEN];
extern char myProcName[COMM_MAX_NAME_LEN];
extern int ixpcQid;

/* for statistic */
extern http_stat_t HTTP_STAT;
extern index_t INDEX[MAX_LIST_NUM];

/*
 * status
 */
void http_report_status(SFM_HttpConnStatusList *http_status, int msgId)
{
	GeneralQMsgType	txGenQMsg = {0,};
	IxpcQMsgType	*txIxpcMsg;
	int i, totalLen = 0, txLen = 0, len = 0;
	char *ptr = NULL;
	int lenCnt = 0;
	char *lenPtr = NULL;
	int destQid = ixpcQid;

	txIxpcMsg = (IxpcQMsgType*)txGenQMsg.body;
	ptr = (char *)txIxpcMsg->body;

	/* first first space pointing num of item */
	lenPtr = ptr;
	ptr += sizeof(int);
	len += sizeof(int);

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

	for (i = 0; i < http_status->cnt; i++, lenCnt++) {
		memcpy(ptr, &http_status->conn[i], sizeof(SFM_HttpConnStatus));
		ptr += sizeof(SFM_HttpConnStatus);
		len += sizeof(SFM_HttpConnStatus);

		/* check next size, send fulfilled msg  */
#if 0
		if ((len + sizeof(SFM_HttpConnStatus)) > (MAX_IXPC_QMSG_LEN - 1024)) {
#else
		if (lenCnt >= 100) { /* because omp receive logic inaccuracy */
#endif

			memcpy(lenPtr, &lenCnt, sizeof(int)); /* len ptr pointing first space */

			/* send */
			txIxpcMsg->head.segFlag = 1;
			txIxpcMsg->head.seqNo ++;
			txIxpcMsg->head.bodyLen = len;
			txLen = sizeof(txIxpcMsg->head) + txIxpcMsg->head.bodyLen;
			if (msgsnd(destQid, (void*)&txGenQMsg, txLen, IPC_NOWAIT) < 0) {
				return;
			} 

			/* init */
			ptr = (char *)txIxpcMsg->body;
			len = 0;
			lenCnt = 0;

			lenPtr = ptr;
			ptr += sizeof(int);
			len += sizeof(int);
		}
	}

	memcpy(lenPtr, &lenCnt, sizeof(int)); /* len ptr pointing first space */

	/* send last msg*/
	txIxpcMsg->head.segFlag = 0;
	txIxpcMsg->head.seqNo ++;
	txIxpcMsg->head.bodyLen = len;
	txLen = sizeof(txIxpcMsg->head) + txIxpcMsg->head.bodyLen;
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
{ HTTP_RX_REQ, HTTP_TX_RSP, HTTP_CONN, HTTP_DISCONN, HTTP_TIMEOUT, HTTP_RX_RST, HTTP_PRE_END, HTTP_STRM_N_FOUND,\
 HTTP_S_INVLD_API, HTTP_S_INVLD_MSG_FORMAT, HTTP_S_MANDATORY_IE_INCORRECT, HTTP_S_INSUFFICIENT_RESOURCES,\
 HTTP_S_SYSTEM_FAILURE, HTTP_S_NF_CONGESTION };
char httpc_stat_str[][128] =
{ "HTTP_TX_REQ", "HTTP_RX_RSP", "HTTP_CONN", "HTTP_DISCONN", "HTTP_TIMEOUT", "HTTP_RX_RST", "HTTP_STRM_N_FOUND", "HTTP_DEST_N_AVAIL"};
char https_stat_str[][128] =
{ "HTTP_RX_REQ", "HTTP_TX_RSP", "HTTP_CONN", "HTTP_DISCONN", "HTTP_TIMEOUT", "HTTP_RX_RST", "HTTP_PRE_END", "HTTP_STRM_N_FOUND",\
 "HTTP_S_INVLD_API", "HTTP_S_INVLD_MSG_FORMAT", "HTTP_S_MANDATORY_IE_INCORRECT", "HTTP_S_INSUFFICIENT_RESOURCES",\
 "HTTP_S_SYSTEM_FAILURE", "HTTP_S_NF_CONGESTION" };
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
#ifdef STAT_LEGACY
    STM_HttpcStatisticMsgType stm_httpc = {0,};
    STM_HttpsStatisticMsgType stm_https = {0,};
#endif

	APPLOG(APPLOG_ERR, "%s() recv MTYPE_STATISTICS_REQUEST from OMP", __func__);

    GeneralQMsgType sxGenQMsg;
    memset(&sxGenQMsg, 0x00, sizeof(GeneralQMsgType));

	IxpcQMsgType *sxIxpcMsg = (IxpcQMsgType*)sxGenQMsg.body;

	STM_CommonStatMsgType *commStatMsg=(STM_CommonStatMsgType *)sxIxpcMsg->body;
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

	for (i = 0; i < HTTP_MAX_HOST; i++) {
		commStatItem = &commStatMsg->info[write_count];

		if (i != 0  && INDEX[i].occupied == 0) 
			continue;
		else
			write_count++;

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

		commStatMsg->num = write_count;
		len += sizeof (STM_CommonStatMsg);
		print_stat(commStatMsg, commStatItem, item_str, item_size);

		/* check next size, send fulfilled msg  */
		if (((len + sizeof (STM_CommonStatMsg)) > MAX_IXPC_QMSG_LEN) ||
				write_count >= MAX_STAT_DATA_NUM) {
			sxIxpcMsg->head.segFlag = 1;
			sxIxpcMsg->head.seqNo++;
#ifdef STAT_LEGACY
            // for 5G-eir, steal structure
            len = stat_cnvt_legacy_form(httpc, https, &stm_httpc, &stm_https, commStatMsg, item_size);
            if (httpc > 0) {
                memcpy(sxIxpcMsg->body, &stm_httpc, sizeof(int) + sizeof(STM_HttpcStatistic_s) * stm_httpc.num);
            } else {
                memcpy(sxIxpcMsg->body, &stm_https, sizeof(int) + sizeof(STM_HttpsStatistic_s) * stm_https.num);
            }
#endif
			sxIxpcMsg->head.bodyLen = len;
			txLen = sizeof(sxIxpcMsg->head) + sxIxpcMsg->head.bodyLen;
			write_count = 0;
			len = 0;
			if (msgsnd(ixpcQid, (void*)&sxGenQMsg, txLen, IPC_NOWAIT) < 0) {
				goto HTTP_STATUS_SEND_FAIL;
			}
			commStatMsg = (STM_CommonStatMsgType *)sxIxpcMsg->body;
			commStatItem = &commStatMsg->info[0];
			memset(commStatMsg, 0x00, sizeof(STM_CommonStatMsgType));
		}
	}

	/* send last (or first) message */
	sxIxpcMsg->head.segFlag = 0;
	sxIxpcMsg->head.seqNo++;
#ifdef STAT_LEGACY
    // for 5G-eir, steal structure
    len = stat_cnvt_legacy_form(httpc, https, &stm_httpc, &stm_https, commStatMsg, item_size);
    if (httpc > 0) {
        memcpy(sxIxpcMsg->body, &stm_httpc, sizeof(int) + sizeof(STM_HttpcStatistic_s) * stm_httpc.num);
    } else {
        memcpy(sxIxpcMsg->body, &stm_https, sizeof(int) + sizeof(STM_HttpsStatistic_s) * stm_https.num);
    }
#endif
	sxIxpcMsg->head.bodyLen = len;
	txLen = sizeof(sxIxpcMsg->head) + sxIxpcMsg->head.bodyLen;

	if (msgsnd(ixpcQid, (void*)&sxGenQMsg, txLen, IPC_NOWAIT) < 0) {
		goto HTTP_STATUS_SEND_FAIL;
	}

HTTP_STATUS_SEND_FAIL:
	memset(&HTTP_STAT.stat[index], 0x00, sizeof(http_stat_thrd_t));
	return;
}

void stat_cnvt_for_httpc(STM_HttpcStatisticMsgType *stm_httpc, STM_CommonStatMsg *commStatItem, int i, int k)
{
    switch (httpc_stat_idx[k]) {
        case HTTP_TX_REQ:
            stm_httpc->httpcSTAT[i].http_tx_req = commStatItem->ldata[k];
            break;
        case HTTP_RX_RSP:
            stm_httpc->httpcSTAT[i].http_rx_rsp = commStatItem->ldata[k];
            break;
        case HTTP_CONN:
            stm_httpc->httpcSTAT[i].http_conn = commStatItem->ldata[k];
            break;
        case HTTP_DISCONN:
            stm_httpc->httpcSTAT[i].http_disconn = commStatItem->ldata[k];
            break;
        case HTTP_TIMEOUT:
            stm_httpc->httpcSTAT[i].http_timeout = commStatItem->ldata[k];
            break;
        case HTTP_RX_RST:
            stm_httpc->httpcSTAT[i].http_rx_rst = commStatItem->ldata[k];
            break;
        case HTTP_STRM_N_FOUND:
            stm_httpc->httpcSTAT[i].http_strm_n_found = commStatItem->ldata[k];
            break;
        case HTTP_DEST_N_AVAIL:
            stm_httpc->httpcSTAT[i].http_dest_n_avail = commStatItem->ldata[k];
            break;
    }
}

void stat_cnvt_for_https(STM_HttpsStatisticMsgType *stm_https, STM_CommonStatMsg *commStatItem, int i, int k)
{
    switch (https_stat_idx[k]) {
        case HTTP_RX_REQ:
            stm_https->httpsSTAT[i].http_rx_req = commStatItem->ldata[k];
            break;
        case HTTP_TX_RSP:
            stm_https->httpsSTAT[i].http_tx_rsp = commStatItem->ldata[k];
            break;
        case HTTP_CONN:
            stm_https->httpsSTAT[i].http_conn = commStatItem->ldata[k];
            break;
        case HTTP_DISCONN:
            stm_https->httpsSTAT[i].http_disconn = commStatItem->ldata[k];
            break;
        case HTTP_TIMEOUT:
            stm_https->httpsSTAT[i].http_timeout = commStatItem->ldata[k];
            break;
        case HTTP_RX_RST:
            stm_https->httpsSTAT[i].http_rx_rst = commStatItem->ldata[k];
            break;
        case HTTP_PRE_END:
            stm_https->httpsSTAT[i].http_pre_end = commStatItem->ldata[k];
            break;
        case HTTP_STRM_N_FOUND:
            stm_https->httpsSTAT[i].http_strm_n_found = commStatItem->ldata[k];
            break;
        case HTTP_S_INVLD_API:
            stm_https->httpsSTAT[i].http_s_invld_api = commStatItem->ldata[k];
            break;
        case HTTP_S_INVLD_MSG_FORMAT:
            stm_https->httpsSTAT[i].http_s_invld_msg_format = commStatItem->ldata[k];
            break;
        case HTTP_S_MANDATORY_IE_INCORRECT:
            stm_https->httpsSTAT[i].http_s_mandatory_ie_incorrect = commStatItem->ldata[k];
            break;
        case HTTP_S_INSUFFICIENT_RESOURCES:
            stm_https->httpsSTAT[i].http_s_insufficient_resources = commStatItem->ldata[k];
            break;
        case HTTP_S_SYSTEM_FAILURE:
            stm_https->httpsSTAT[i].http_s_system_failure = commStatItem->ldata[k];
            break;
        case HTTP_S_NF_CONGESTION:
            stm_https->httpsSTAT[i].http_s_nf_congestion = commStatItem->ldata[k];
            break;
    }
}

int stat_cnvt_legacy_form(int httpc, int https, STM_HttpcStatisticMsgType *stm_httpc, STM_HttpsStatisticMsgType *stm_https, STM_CommonStatMsgType *commStatMsg, int item_size)
{
    int len = 0;

    if (httpc) {
        memset(stm_httpc, 0x00, sizeof(STM_HttpcStatisticMsgType));
        stm_httpc->num = commStatMsg->num;
        len = sizeof(int) + (sizeof(STM_HttpcStatistic_s) * stm_httpc->num);
    } else {
        memset(stm_https, 0x00, sizeof(STM_HttpsStatisticMsgType));
        stm_https->num = commStatMsg->num;
        len = sizeof(int) + (sizeof(STM_HttpsStatistic_s) * stm_https->num);
    }

    for (int i = 0; i < commStatMsg->num; i++) {
        STM_CommonStatMsg *commStatItem = &commStatMsg->info[i];
        sprintf(httpc > 0 ? stm_httpc->httpcSTAT[i].hostname : stm_https->httpsSTAT[i].hostname, "%s", commStatItem->strkey1);

        for (int k = 0; k < item_size; k++) {
            if (httpc > 0) {
                stat_cnvt_for_httpc(stm_httpc, commStatItem, i, k);
            } else {
                stat_cnvt_for_https(stm_https, commStatItem, i, k);
            }
        }
    }

    return len;
}
void print_stat(STM_CommonStatMsgType *commStatMsg, STM_CommonStatMsg *commStatItem, char (*str)[128], int size)
{
	for (int i = 0; i < size; i++) {
		APPLOG(APPLOG_ERR, "%-15s: %-7ld ", str[i], commStatItem->ldata[i]);
	}
	APPLOG(APPLOG_ERR, "\n");
}

void reportAlarm(char *ProcName, int code, int level, char *info, char *desc)
{
    GeneralQMsgType     sndMsg;
    IxpcQMsgType        *txIxpcMsg;
    AlmMsgInfo          *almMsg;
    int                 txLen;

    txIxpcMsg = (IxpcQMsgType*)sndMsg.body;
    almMsg = (AlmMsgInfo*)txIxpcMsg->body;

    memset((void*)&txIxpcMsg->head, 0, sizeof(txIxpcMsg->head));
    memset(almMsg, 0x00, sizeof(AlmMsgInfo));

    sndMsg.mtype = MTYPE_ALARM_REPORT;

    strcpy (txIxpcMsg->head.srcSysName, mySysName);
    strcpy (txIxpcMsg->head.srcAppName, ProcName);
    strcpy (txIxpcMsg->head.dstSysName, "OMP");
    strcpy (txIxpcMsg->head.dstAppName, "FIMD");
    txIxpcMsg->head.msgId   = code;
    txIxpcMsg->head.bodyLen = sizeof(AlmMsgInfo);

    txLen = sizeof(txIxpcMsg->head) + txIxpcMsg->head.bodyLen;

    almMsg->almCode = code;
    almMsg->almLevel = level;
    sprintf(almMsg->almInfo, info);
    sprintf(almMsg->almDesc, desc);

    if (msgsnd(ixpcQid, (void*)&sndMsg, txLen, IPC_NOWAIT) < 0) {
        APPLOG(APPLOG_ERR, "Send alarm message fail. errno=%d(%s)\n", __func__, errno, strerror(errno));
    }
}

int print_single_http_cfg(config_t *CFG_PTR, const char *cfg_path_str, const char *skip_str, const char *banner, char /*enough huge or NULL*/ *res_buff)
{

    config_setting_t *cfg_http_config = config_lookup(CFG_PTR, cfg_path_str);
    if (cfg_http_config == NULL) {
        APPLOG(APPLOG_ERR, "%s() fail to find cfg (%s)", __func__, cfg_path_str);
        return -1;
    }

    /* prepare FP */
    char *ptr = NULL;
    size_t file_size = 0;
    FILE *file_cfg_buffer = open_memstream(&ptr, &file_size);

    /* create temp cfg */
    config_t TEMP_CFG = {0, };
    TEMP_CFG.root = cfg_http_config;

    /* write cfg to FP */
    config_write(&TEMP_CFG, file_cfg_buffer);

    /* close FP */
    fclose(file_cfg_buffer);

    /* use PTR (to table scheme) */
    ft_table_t *table = ft_create_table();
    ft_set_border_style(table, FT_PLAIN_STYLE);
    ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);

    ft_write_ln(table, banner);
    ft_write_ln(table, ptr + strlen(skip_str));
    ft_add_separator(table);

    if (res_buff != NULL)
        sprintf(res_buff, ft_to_string(table));
    else
        APPLOG(APPLOG_ERR, "{{{DBG}}} %s\n%s", __func__, ft_to_string(table));
    ft_destroy_table(table);

    /* close ptr */
    free(ptr);

    return 0;
}

void print_dual_http_cfg(const char *before, const char *after, char *result)
{
    ft_table_t *table = ft_create_table();
    ft_set_border_style(table, FT_PLAIN_STYLE);
    ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);
    ft_write_ln(table, "BEFORE", "==>AFTER");
    ft_printf_ln(table, "%s|%s", before, after);
    if (result != NULL)
        sprintf(result, "%s", ft_to_string(table));
    else
        APPLOG(APPLOG_ERR, "{{{DBG}}} %s\n%s", __func__, ft_to_string(table));
    ft_destroy_table(table);
}
