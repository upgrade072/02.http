#include "client.h"
#include <comm_msgtypes.h>

extern int httpcQid;
extern int ixpcQid;
extern client_conf_t CLIENT_CONF;

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
	MAX_CMD_NUM
} client_cmd_t;

MmcHdlrVector   mmcHdlrVecTbl[MAX_CMD_NUM] =
{
	{ "DIS-HTTP-SERVER",     func_dis_http_server},
	{ "ADD-HTTP-SERVER",     func_add_http_server},
	{ "ADD-HTTP-SVR-IP",     func_add_http_svr_ip},
	{ "ACT-HTTP-SERVER",     func_act_http_server},
	{ "DACT-HTTP-SERVER",    func_dact_http_server},
	{ "CHG-HTTP-SERVER",     func_chg_http_server},
	{ "DEL-HTTP-SVR-IP",     func_del_http_svr_ip},
	{ "DEL-HTTP-SERVER",     func_del_http_server}
};

void message_handle(evutil_socket_t fd, short what, void *arg)
{
	char msgBuff[1024*64];
	GeneralQMsgType *msg = (GeneralQMsgType *)msgBuff;

	/* handle all pending msgs */
	while (msgrcv(httpcQid, msg, sizeof(GeneralQMsgType), 0, IPC_NOWAIT) >= 0) {
		switch (msg->mtype) {
			case MTYPE_MMC_REQUEST:
				mml_function((IxpcQMsgType *)msg->body);
				continue;
#ifndef TEST
			case MTYPE_STATISTICS_REQUEST:
				stat_function((IxpcQMsgType *)msg->body, CLIENT_CONF.worker_num, 1, 0, MSGID_HTTPC_STATISTICS_REPORT);
				continue;
#endif
			default:
				APPLOG(APPLOG_ERR, "not yet ready (mtype:%d)", msg->mtype);
				continue;
		}
	}
	if (errno != ENOMSG) {
		APPLOG(APPLOG_ERR,"[%s] >>> msgrcv fail; err=%d(%s)", __func__, errno, strerror(errno));
	}
	return;
}

void mml_function(IxpcQMsgType *rxIxpcMsg)
{
	int i;
    MMLReqMsgType   *mmlReq=(MMLReqMsgType*)rxIxpcMsg->body;
    MmcHdlrVector   mmcHdlr;

	APPLOG(APPLOG_ERR, "receive cmd %s", mmlReq->head.cmdName);

	for (i = 0; i < MAX_CMD_NUM; i++) {
		if (!strcmp(mmlReq->head.cmdName, mmcHdlrVecTbl[i].cmdName)) {
			mmcHdlr.func = mmcHdlrVecTbl[i].func;
			break;
		}
	}

	if (i >= MAX_CMD_NUM) {
		APPLOG(APPLOG_ERR, "not registered mml_cmd(%s)", mmlReq->head.cmdName);
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
	APPLOG(APPLOG_ERR, "DBG %s called", __func__);

	char *resBuf=respMsg;
	conn_list_status_t CONN_STATUS[MAX_CON_NUM];

	memset(CONN_STATUS, 0x00, sizeof(conn_list_status_t) * MAX_CON_NUM);

	gather_list(CONN_STATUS);
	write_list(CONN_STATUS, resBuf);

	print_raw_list();

	APPLOG(APPLOG_ERR, "\n%s", resBuf);
	return send_mml_res_succMsg(rxIxpcMsg, resBuf, FLAG_COMPLETE, 0, 0);
}

int func_add_http_server(IxpcQMsgType *rxIxpcMsg)
{
	APPLOG(APPLOG_ERR, "DBG %s called", __func__);

	MMLReqMsgType   *mmlReq=(MMLReqMsgType*)rxIxpcMsg->body;

	char *resBuf=respMsg;
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

	/* re-arrange */
	order_list();
	gather_list(CONN_STATUS);

	write_list(CONN_STATUS, resBuf);

	APPLOG(APPLOG_ERR, "\n%s", resBuf);
	return send_mml_res_succMsg(rxIxpcMsg, resBuf, FLAG_COMPLETE, 0, 0);
}
int func_add_http_svr_ip(IxpcQMsgType *rxIxpcMsg)
{
	APPLOG(APPLOG_ERR, "DBG %s called", __func__);

	MMLReqMsgType   *mmlReq=(MMLReqMsgType*)rxIxpcMsg->body;

	char *resBuf=respMsg;
	int ID = -1;
	char IPADDR[64];
	int PORT = -1;
	int CONN_CNT = -1;
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
	if ((CONN_CNT = get_mml_para_int(mmlReq, "CONN_CNT")) < 0)
		return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING(CONN_CNT)");

	if (ID >= HTTP_MAX_HOST)
		return send_mml_res_failMsg(rxIxpcMsg, "INVALID ID");
	if (inet_pton(AF_INET, IPADDR, &(sa.sin_addr))) {
	} else if (inet_pton(AF_INET6, IPADDR, &(sa6.sin6_addr))) {
	} else {
		return send_mml_res_failMsg(rxIxpcMsg, "INVALID IPADDR");
	}
	if (PORT <= 0 || PORT >= 65535)
		return send_mml_res_failMsg(rxIxpcMsg, "INVALID PORT");
	if (CONN_CNT <= 0 || CONN_CNT > HTTP_MAX_CONN)
		return send_mml_res_failMsg(rxIxpcMsg, "INVALID CONN_CNT");

	if (addcfg_server_ipaddr(ID, IPADDR, PORT, CONN_CNT) < 0)
		return send_mml_res_failMsg(rxIxpcMsg, "IPADDR ADD FAIL");

	/* re-arrange */
	order_list();
	gather_list(CONN_STATUS);

	write_list(CONN_STATUS, resBuf);

	APPLOG(APPLOG_ERR, "\n%s", resBuf);
	return send_mml_res_succMsg(rxIxpcMsg, resBuf, FLAG_COMPLETE, 0, 0);
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
	APPLOG(APPLOG_ERR, "DBG %s called", __func__);

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

	/* re-arrange */
	order_list();
	// for debug
	print_raw_list();

	sprintf(resBuf, "\n[INPUT PARAM]\n\
			ID        : %d\n\
			IPADDR    : %s\n\
			PORT      : %d\n\
			ACT       : %s\n", ID, IPADDR, PORT, change_to_act == 1 ? "ACT":"DACT");

	APPLOG(APPLOG_ERR, "\n%s", resBuf);
	return send_mml_res_succMsg(rxIxpcMsg, resBuf, FLAG_COMPLETE, 0, 0);
}
int func_chg_http_server(IxpcQMsgType *rxIxpcMsg)
{
	APPLOG(APPLOG_ERR, "DBG %s called\n", __func__);

	MMLReqMsgType   *mmlReq=(MMLReqMsgType*)rxIxpcMsg->body;

	char *resBuf=respMsg;
	int ID = -1;
	char IPADDR[64];
	int PORT = -1;
	int CONN_CNT = -1;
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
	if ((CONN_CNT = get_mml_para_int(mmlReq, "CONN_CNT")) < 0)
		return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING(CONN_CNT)");

	if (ID >= HTTP_MAX_HOST)
		return send_mml_res_failMsg(rxIxpcMsg, "INVALID ID");
	if (inet_pton(AF_INET, IPADDR, &(sa.sin_addr))) {
	} else if (inet_pton(AF_INET6, IPADDR, &(sa6.sin6_addr))) {
	} else {
		return send_mml_res_failMsg(rxIxpcMsg, "INVALID IPADDR");
	}
	if (PORT <= 0 || PORT >= 65535)
		return send_mml_res_failMsg(rxIxpcMsg, "INVALID PORT");
	if (CONN_CNT < 1 || CONN_CNT > HTTP_MAX_CONN) // 1~12 
		return send_mml_res_failMsg(rxIxpcMsg, "INVALID CONN_CNT");

	if (chgcfg_server_conn_cnt(ID, IPADDR, PORT, CONN_CNT) < 0)
		return send_mml_res_failMsg(rxIxpcMsg, "CONN COUNT CHG FAIL");

	/* re-arrange */
	order_list();
	gather_list(CONN_STATUS);

	write_list(CONN_STATUS, resBuf);

	APPLOG(APPLOG_ERR, "\n%s", resBuf);
	return send_mml_res_succMsg(rxIxpcMsg, resBuf, FLAG_COMPLETE, 0, 0);
}
int func_del_http_svr_ip(IxpcQMsgType *rxIxpcMsg)
{
	APPLOG(APPLOG_ERR, "DBG %s called\n", __func__);

	MMLReqMsgType   *mmlReq=(MMLReqMsgType*)rxIxpcMsg->body;

	char *resBuf=respMsg;
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

	/* re-arrange */
	order_list();
	gather_list(CONN_STATUS);

	write_list(CONN_STATUS, resBuf);

	APPLOG(APPLOG_ERR, "\n%s", resBuf);
	return send_mml_res_succMsg(rxIxpcMsg, resBuf, FLAG_COMPLETE, 0, 0);
}
int func_del_http_server(IxpcQMsgType *rxIxpcMsg)
{
	APPLOG(APPLOG_ERR, "DBG %s called\n", __func__);

	MMLReqMsgType   *mmlReq=(MMLReqMsgType*)rxIxpcMsg->body;

	char *resBuf=respMsg;
	int ID = -1;
	conn_list_status_t CONN_STATUS[MAX_CON_NUM];

	memset(CONN_STATUS, 0x00, sizeof(conn_list_status_t) * MAX_CON_NUM);

	if ((ID = get_mml_para_int(mmlReq, "ID")) < 0)
		return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING(ID)");

	if (ID >= HTTP_MAX_HOST)
		return send_mml_res_failMsg(rxIxpcMsg, "INVALID ID");

	if (delcfg_server_hostname(ID) < 0)
		return send_mml_res_failMsg(rxIxpcMsg, "HOSTNAME DEL FAIL");

	/* re-arrange */
	order_list();
	gather_list(CONN_STATUS);

	write_list(CONN_STATUS, resBuf);

	APPLOG(APPLOG_ERR, "\n%s", resBuf);
	return send_mml_res_succMsg(rxIxpcMsg, resBuf, FLAG_COMPLETE, 0, 0);
}
