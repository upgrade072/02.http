#include <nrfc.h>

extern main_ctx_t MAIN_CTX;

char mySysName[COMM_MAX_NAME_LEN];
char myProcName[COMM_MAX_NAME_LEN];
int ixpcQid;
char respMsg[MAX_MML_RESULT_LEN], respBuff[MAX_MML_RESULT_LEN];

typedef enum nrfc_cmd {
	dis_nf_status,
	dis_nf_mml,
	add_nf_mml,
	del_nf_mml,
	MAX_CMD_NUM
} nrfc_cmd_t;

MmcHdlrVector   mmcHdlrVecTbl[MAX_CMD_NUM] =
{ 
	{ "DIS-NF-STATUS",  func_dis_nf_status},
	{ "DIS-NF-MML",		func_dis_nf_mml},
	{ "ADD-NF-MML",		func_add_nf_mml},
	{ "DEL-NF-MML",		func_del_nf_mml}
};

void init_cmd(main_ctx_t *MAIN_CTX)
{
	sprintf(mySysName, "%s", MAIN_CTX->my_info.mySysName);
	sprintf(myProcName, "%s", MAIN_CTX->my_info.myProcName);
	ixpcQid = MAIN_CTX->my_qid.ixpc_qid;
}

void message_handle(evutil_socket_t fd, short what, void *arg)
{
    char msgBuff[1024*64];

    GeneralQMsgType *msg = (GeneralQMsgType *)msgBuff;

    while (msgrcv(MAIN_CTX.my_qid.nrfc_qid, msg, sizeof(GeneralQMsgType), 0, IPC_NOWAIT|MSG_NOERROR) >= 0) {
        switch (msg->mtype) {
			case MTYPE_MMC_REQUEST:
				mml_function((IxpcQMsgType *)msg->body);
				continue;
			case MTYPE_SETPRINT:
				adjust_loglevel((TrcLibSetPrintMsgType *)msg);
				continue;
            // TODO !!! check & broadcast
			case MSGID_NRF_LIB_NRFC_REQ_PROFILE:
				handle_appl_req_with_profile(&MAIN_CTX, (nf_disc_host_info *)msg);
				continue;
			case MSGID_NRF_LIB_NRFC_REQ_CALLBACK:
				handle_appl_req_with_cbinfo(&MAIN_CTX, (http_conn_handle_req_t *)msg);
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

void printf_nf_mml(main_ctx_t *MAIN_CTX, char *printBuff)
{
	APPLOG(APPLOG_ERR, "{{{DBG}}} %s called!", __func__);

	ft_table_t *table = ft_create_table();

	ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);
	ft_set_border_style(table, FT_PLAIN_STYLE);

	ft_write_ln(table, "INDEX", "CONF_NAME", "CONF_TYPE", "CONF_INFO", "TARGET_HOSTNAME");

	int mml_length = g_slist_length(MAIN_CTX->opr_mml_list);

	for (int i = 0; i < mml_length; i++) {
		mml_conf_t *mml_conf = g_slist_nth_data(MAIN_CTX->opr_mml_list, i);
		char key[128] = "nfProfile";
		json_object *js_profile = NULL;
		if ((js_profile = search_json_object(mml_conf->js_raw_profile, key)) != NULL) {
			ft_printf_ln(table, "%d|%s|%s|%s|%s",
					i,
					mml_conf->conf_name,
					mml_conf->nf_type,
					json_object_to_json_string_ext(js_profile, (JSON_C_TO_STRING_PRETTY|JSON_C_TO_STRING_NOSLASHESCAPE)),
					mml_conf->target_hostname);
		}
		ft_add_separator(table);
	}

	if (printBuff != NULL) {
		sprintf(printBuff, "%s", ft_to_string(table));
	} else {
		APPLOG(APPLOG_ERR, "\n%s", ft_to_string(table));
	}

	ft_destroy_table(table);
}

void printf_fep_nfs(nfs_avail_shm_t *SHM_NFS_AVAIL, char *printBuff)
{
	APPLOG(APPLOG_ERR, "{{{DBG}}} %s called!", __func__);

	ft_table_t *table = ft_create_table();

	ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);
	ft_set_border_style(table, FT_PLAIN_STYLE);

	ft_write_ln(table, "INDEX", "TYPE", "SERVICE", "ALLOWEDPLMNS\n(MCC+MNC)", "TYPEINFO", "HOSTNAME", "SCHEME", "IPV4", "PORT", "PRIORITY", "LOAD", "AUTO", "LB_ID");

	int POS = SHM_NFS_AVAIL->curr_pos;
	nf_list_shm_t *nf_avail_shm = &SHM_NFS_AVAIL->nfs_avail_shm[POS];

	for (int i = 0, index = 0; i < NF_MAX_LB_NUM; i++) {
		for (int k = 0; k < NF_MAX_AVAIL_LIST; k++) {
			nf_service_info *nf_info = &nf_avail_shm->nf_avail[i][k];

			if (nf_info->occupied <= 0)
				continue;

			/* allowd plmns */
			char allowdPlmnsStr[1024] = {0,};
			nf_get_allowd_plmns_str(nf_info->allowdPlmnsNum, nf_info->allowdPlmns, allowdPlmnsStr);

			/* nf-type specific info */
			char typeSpecStr[1024] = {0,};
            nf_get_specific_info_str(nf_info->nfType, &nf_info->nfTypeInfo, typeSpecStr);

			ft_printf_ln(table, "%d|%s|%s|%s|%s|%s|%s|%s|%d|%d|%d|%s(%d)|%d",
					index++,
					nf_info->type,
					strlen(nf_info->serviceName) ? nf_info->serviceName : "ANY",
					strlen(allowdPlmnsStr) ? allowdPlmnsStr : "ANY",
					strlen(typeSpecStr) ? typeSpecStr : "ANY",
					nf_info->hostname,
					nf_info->scheme,
					nf_info->ipv4Address,
					nf_info->port,
					nf_info->priority,
					nf_info->load,
					nf_info->auto_add == NF_ADD_MML ? "MML" :
					nf_info->auto_add == NF_ADD_NRF ? "NRF" :
					nf_info->auto_add == NF_ADD_CALLBACK ? "API" : "RAW",
					nf_info->auto_add,
					nf_info->lbId);
			ft_add_separator(table);
		}
	}

	if (printBuff != NULL) {
		sprintf(printBuff, "%s", ft_to_string(table));
	} else {
		APPLOG(APPLOG_ERR, "\n%s", ft_to_string(table));
	}

	ft_destroy_table(table);
}


int func_dis_nf_status(IxpcQMsgType *rxIxpcMsg)
{
	APPLOG(APPLOG_DEBUG, "%s() called", __func__);

    MMLReqMsgType   *mmlReq=(MMLReqMsgType*)rxIxpcMsg->body;

    char nf_type[32] = {0,};

    get_mml_para_str(mmlReq, "NF_TYPE", nf_type);
    if (strlen(nf_type) > 0)
        strupr(nf_type, strlen(nf_type));

	char *resBuf = malloc(1024 * 1024 * 12);
	resBuf[0] = '\0';

    if (!strcmp(nf_type, "DUMP"))
        printf_fep_nfs(MAIN_CTX.SHM_NFS_AVAIL, resBuf);
    else 
        printf_fep_nfs_well_form(MAIN_CTX.root_node, resBuf, nf_type);

	APPLOG(APPLOG_DETAIL, "%s() response is >>>\n%s", __func__, resBuf);
	int res = send_mml_res_succMsg(rxIxpcMsg, resBuf, FLAG_COMPLETE, 0, 0);

	free(resBuf);
	return res;
}

int add_cfg_nf_mml_udm(main_ctx_t *MAIN_CTX, const char *conf_name, const char *target_host, const char *nf_type, MMLReqMsgType *mmlReq, config_setting_t *mml_list, char *resBuf)
{

	char SERVICE[128] = {0,};
	char MCC[128] = {0,};
	char MNC[128] = {0,};
	char GROUP_ID[128] = {0,};
	char START[128] = {0,};
	char END[128] = {0,};
	char RI[128] = {0,};

	get_mml_para_str(mmlReq, "SERVICE", SERVICE);
	get_mml_para_str(mmlReq, "MCC", MCC);
	get_mml_para_str(mmlReq, "MNC", MNC);
	get_mml_para_str(mmlReq, "GROUP_ID", GROUP_ID);
	get_mml_para_str(mmlReq, "START", START);
	get_mml_para_str(mmlReq, "END", END);
	get_mml_para_str(mmlReq, "RI", RI);

	if ((strlen(MCC) > 0 && strlen(MNC) == 0) ||
			(strlen(MCC) == 0 && strlen(MNC) > 0)) {
		sprintf(resBuf, "MCC & MNC MUST BOTH EXIST");
		return -1;
	}
	if ((strlen(START) > 0 && strlen(END) == 0) ||
			(strlen(START) == 0 && strlen(END) > 0)) {
		sprintf(resBuf, "START & END MUST BOTH EXIST");
		return -1;
	}

	APPLOG(APPLOG_ERR, "{{{DBG}}} %s try add [%s:%s:%s]", __func__, conf_name, nf_type, target_host);

	/* mandatory */
	config_setting_t *item = config_setting_add(mml_list, conf_name, CONFIG_TYPE_GROUP);

	config_setting_t *cf_target = config_setting_add(item, "target_hostname", CONFIG_TYPE_STRING);
	config_setting_set_string(cf_target, target_host);

	config_setting_t *cf_profile = config_setting_add(item, "nfProfile", CONFIG_TYPE_GROUP);
	config_setting_t *cf_nfType = config_setting_add(cf_profile, "nfType", CONFIG_TYPE_STRING);
	config_setting_set_string(cf_nfType, nf_type);

	config_setting_t *cf_allowdPlmns = config_setting_add(cf_profile, "allowedPlmns", CONFIG_TYPE_LIST);
	config_setting_t *cf_udmInfo = config_setting_add(cf_profile, "udmInfo", CONFIG_TYPE_GROUP);

	if (strlen(SERVICE)) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s try set service=(%s)", __func__, SERVICE);
		config_setting_t *cf_service = config_setting_add(cf_profile, "serviceName", CONFIG_TYPE_STRING);
		config_setting_set_string(cf_service, SERVICE);
	}

	if (strlen(MCC)) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s try set mcc=(%s) mnc=(%s)", __func__, MCC, MNC);
		config_setting_t *cf_plmns = config_setting_add(cf_allowdPlmns, "", CONFIG_TYPE_GROUP);
		config_setting_t *cf_mcc = config_setting_add(cf_plmns, "mcc", CONFIG_TYPE_STRING);
		config_setting_t *cf_mnc = config_setting_add(cf_plmns, "mnc", CONFIG_TYPE_STRING);
		config_setting_set_string(cf_mcc, MCC);
		config_setting_set_string(cf_mnc, MNC);
	}

	if (strlen(GROUP_ID)) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s try set groupId=(%s)", __func__, GROUP_ID);
		config_setting_t *cf_group_id = config_setting_add(cf_udmInfo, "groupId", CONFIG_TYPE_STRING);
		config_setting_set_string(cf_group_id, GROUP_ID);
	}

	if (strlen(START)) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s try set start=(%s) end=(%s)", __func__, START, END);
		config_setting_t *cf_supi_ranges = config_setting_add(cf_udmInfo, "supiRanges", CONFIG_TYPE_LIST);
		config_setting_t *cf_supi = config_setting_add(cf_supi_ranges, "", CONFIG_TYPE_GROUP);
		config_setting_t *cf_start = config_setting_add(cf_supi, "start", CONFIG_TYPE_STRING);
		config_setting_t *cf_end = config_setting_add(cf_supi, "end", CONFIG_TYPE_STRING);
		config_setting_set_string(cf_start, START);
		config_setting_set_string(cf_end, END);
	}

	if (strlen(RI)) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s try set rouotingIndicators=(%s)", __func__, RI);
		config_setting_t *cf_routing_indicators = config_setting_add(cf_udmInfo, "routingIndicators", CONFIG_TYPE_ARRAY);
		config_setting_t *cf_ri = config_setting_add(cf_routing_indicators, "", CONFIG_TYPE_STRING);
		config_setting_set_string(cf_ri, RI);
	}

	write_cfg(MAIN_CTX);

	reload_mml(MAIN_CTX);

	printf_nf_mml(MAIN_CTX, resBuf);

	return 0;
}

int add_cfg_nf_mml(main_ctx_t *MAIN_CTX, const char *conf_name, const char *target_host, const char *nf_type, MMLReqMsgType *mml_req, char *resBuf)
{
	APPLOG(APPLOG_ERR, "{{{DBG}}} %s called", __func__);

	config_setting_t *mml_list = config_lookup(&MAIN_CTX->CFG, "mml_list");
	int mml_num = config_setting_length(mml_list);

	/* check name duplicate */
	for (int i = 0; i < mml_num; i++) {
		config_setting_t *mml_item = config_setting_get_elem(mml_list, i);
		if (!strcmp(mml_item->name, conf_name)) {
			sprintf(resBuf, "ALREADY EXIST MML NAME[%s]", conf_name);
			return -1;
		}
	}

	/* now only support nf_type UDM */
	if (!strcmp(nf_type, "UDM")) {
		return add_cfg_nf_mml_udm(MAIN_CTX, conf_name, target_host, nf_type, mml_req, mml_list, resBuf);
	} else {
		sprintf(resBuf, "UNSUPPORTED NF TYPE [%s]", nf_type);
		return -1;
	}
}

int del_cfg_nf_mml(main_ctx_t *MAIN_CTX, int ID, char *resBuf)
{
	APPLOG(APPLOG_ERR, "{{{DBG}}} %s called", __func__);

	config_setting_t *mml_list = config_lookup(&MAIN_CTX->CFG, "mml_list");
	int mml_num = config_setting_length(mml_list);

	if (ID >= mml_num) {
		sprintf(resBuf, "INVALID MML ID[%d]", ID);
		return -1;
	}

	config_setting_remove_elem(mml_list, ID);

	write_cfg(MAIN_CTX);

	reload_mml(MAIN_CTX);

	printf_nf_mml(MAIN_CTX, resBuf);

	return 0;
}

int func_dis_nf_mml(IxpcQMsgType *rxIxpcMsg)
{
	APPLOG(APPLOG_DEBUG, "%s() called", __func__);

    char *resBuf=malloc(1024 * 1024);
	resBuf[0] = '\0';

	printf_nf_mml(&MAIN_CTX, resBuf);

	int res = send_mml_res_succMsg(rxIxpcMsg, resBuf, FLAG_COMPLETE, 0, 0);

	free(resBuf);
	return res;
}

int func_add_nf_mml(IxpcQMsgType *rxIxpcMsg)
{
	APPLOG(APPLOG_DEBUG, "%s() called", __func__);

	MMLReqMsgType   *mmlReq=(MMLReqMsgType*)rxIxpcMsg->body;

	/* mandatory */
	char CONF_NAME[128] = {0,};
	char TARGET_HOST[128] = {0,};
	char NF_TYPE[128] = {0,};

    /* error handle */
	if (get_mml_para_str(mmlReq, "CONF_NAME", CONF_NAME) < 0)
		return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING(CONF_NAME)");
	if (get_mml_para_str(mmlReq, "TARGET_HOST", TARGET_HOST) < 0)
		return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING(TARGET_HOST)");
	if (get_mml_para_str(mmlReq, "NF_TYPE", NF_TYPE) < 0)
		return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING(NF_TYPE)");

    /* malloc - send & free */
    char *resBuf=malloc(1024 * 1024);
	resBuf[0] = '\0';

	if (add_cfg_nf_mml(&MAIN_CTX, CONF_NAME, TARGET_HOST, NF_TYPE, mmlReq, resBuf) < 0)
		return send_mml_res_failMsg(rxIxpcMsg, resBuf);

	int res =  send_mml_res_succMsg(rxIxpcMsg, resBuf, FLAG_COMPLETE, 0, 0);

	free(resBuf);
	return res;
}

int func_del_nf_mml(IxpcQMsgType *rxIxpcMsg)
{
	APPLOG(APPLOG_DEBUG, "%s() called", __func__);

	MMLReqMsgType   *mmlReq=(MMLReqMsgType*)rxIxpcMsg->body;

	/* mandatory */
	int ID = -1;

    /* error handle */
	if ((ID = get_mml_para_int(mmlReq, "ID")) < 0)
		return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING(ID)");

    /* malloc - send & free */
    char *resBuf=malloc(1024 * 1024);
	resBuf[0] = '\0';

	if (del_cfg_nf_mml(&MAIN_CTX, ID, resBuf) < 0)
		return send_mml_res_failMsg(rxIxpcMsg, resBuf);

	int res = send_mml_res_succMsg(rxIxpcMsg, resBuf, FLAG_COMPLETE, 0, 0);

	free(resBuf);
	return res;
}

void send_conn_req_profile(assoc_t *lb_assoc, nf_disc_host_info *nf_host_info)
{
    IsifMsgType txIsifMsg = {0,};

    nf_host_info->mtype = LIBNRF_MSG_ADD_NF_PROFILE;

	APPLOG(APPLOG_DEBUG, "{DBG} %s() send request! to node index(%d)", __func__, lb_assoc->index);

    isifc_create_pkt(&txIsifMsg, &MAIN_CTX.my_info, lb_assoc, nf_host_info, sizeof(nf_disc_host_info));
    isifc_send_pkt(MAIN_CTX.my_qid.isifc_tx_qid, &txIsifMsg);
}

void send_conn_handle_req(assoc_t *lb_assoc, http_conn_handle_req_t *handle_req)
{
    IsifMsgType txIsifMsg = {0,};

    handle_req->mtype = LIBNRF_MSG_ADD_NF_CALLBACK;

    isifc_create_pkt(&txIsifMsg, &MAIN_CTX.my_info, lb_assoc, handle_req, sizeof(http_conn_handle_req_t));
    isifc_send_pkt(MAIN_CTX.my_qid.isifc_tx_qid, &txIsifMsg);
}

void check_and_send_conn_req(assoc_t *lb_assoc, http_conn_handle_req_t *handle_req)
{
	if (MAIN_CTX.root_node == NULL) {
		APPLOG(APPLOG_ERR, "%s() cant handle req, SHM_NFS_AVAIL is null");
		return;
	}

	nf_search_key_t key = {0,};
	memset(&key, 0x00, sizeof(nf_search_key_t));
	create_cb_depth_key(&key, lb_assoc->index, handle_req); // TODO index mismatch check

	GNode *node_conn = search_node_data(MAIN_CTX.root_node, &key, NF_NODE_DATA_DEPTH);

	if ((handle_req->command == HTTP_MML_HTTPC_ADD && node_conn == NULL) ||
			(handle_req->command == HTTP_MML_HTTPC_DEL && node_conn != NULL)) {
		APPLOG(APPLOG_DEBUG, "{DBG} %s() send request! to node index(%d)", __func__, lb_assoc->index);
		send_conn_handle_req(lb_assoc, handle_req);
	} else {
		APPLOG(APPLOG_DEBUG, "{DBG} %s() NOT send(already exist) request! to node index(%d)", __func__, lb_assoc->index);
	}
}

void handle_appl_req_with_profile(main_ctx_t *MAIN_CTX, nf_disc_host_info *nf_host_info)
{
    g_slist_foreach(MAIN_CTX->lb_assoc_list, (GFunc)send_conn_req_profile, nf_host_info);
}

void handle_appl_req_with_cbinfo(main_ctx_t *MAIN_CTX, http_conn_handle_req_t *handle_req)
{
	g_slist_foreach(MAIN_CTX->lb_assoc_list, (GFunc)check_and_send_conn_req, handle_req);
}

void create_cb_depth_key(nf_search_key_t *key, int lb_index, http_conn_handle_req_t *handle_req)
{
	key->depth = 0;
	
	key->lb_id = lb_index + 1;
	key->nf_type = handle_req->type;
	key->nf_host = handle_req->host;

#if 1
	char empty_ptr[12] = {0,};
	empty_ptr[0] = '\0';
	key->nf_svcname = empty_ptr;
#endif

	sprintf(key->nf_conn_info, "%s%s://%s:%d",
			handle_req->scheme, !strcmp(handle_req->scheme, "https") ? "" : "-", handle_req->ip, handle_req->port);
}

void create_full_depth_key (nf_search_key_t *key, nf_service_info *insert_data)
{
    key->depth = 0;

    key->lb_id = insert_data->lbId;
    key->nf_type = insert_data->type;
    key->nf_host = insert_data->auto_add == NF_ADD_MML ? insert_data->confname : insert_data->hostname;
    key->nf_svcname = insert_data->serviceName;

    if (insert_data->auto_add == NF_ADD_MML) {
        sprintf(key->nf_conn_info, "lb_conf=[%s]", insert_data->hostname);
    } else {
        sprintf(key->nf_conn_info, "%s%s://%s:%d",
                insert_data->scheme, !strcmp(insert_data->scheme, "https") ? "" : "-", insert_data->ipv4Address, insert_data->port);
    }
};

void create_fep_nfs_node_tree(nfs_avail_shm_t *SHM_NFS_AVAIL)
{
    int prepare_pos = (SHM_NFS_AVAIL->curr_pos + 1) % MAX_NFS_SHM_POS;
    nf_list_shm_t *nf_avail_shm = &SHM_NFS_AVAIL->nfs_avail_shm[prepare_pos];

    if (MAIN_CTX.root_node != NULL) {
    //APPLOG(APPLOG_ERR, "{{{DBG}}} %s() remove rootnode pos[%d]", __func__, prepare_pos);
        /* free all node data */
        g_node_traverse(MAIN_CTX.root_node, G_IN_ORDER, G_TRAVERSE_ALL, -1, node_free_data, NULL);
        /* remove NODE */
        g_node_destroy(MAIN_CTX.root_node);
        MAIN_CTX.root_node = NULL;
    }
    MAIN_CTX.root_node = g_node_new(NULL);

    for (int i = 0 ; i < NF_MAX_LB_NUM; i++) {
        for (int k = 0; k < NF_MAX_AVAIL_LIST; k++) {
            nf_service_info *nf_info = &nf_avail_shm->nf_avail[i][k];

            if (nf_info->occupied <= 0)
                continue;

            nf_search_key_t key = {0,};
            create_full_depth_key(&key, nf_info);
            create_node_data(MAIN_CTX.root_node, &key, nf_info);
        }
    }
}
