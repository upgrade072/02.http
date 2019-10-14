#include <nrfm.h>

extern main_ctx_t MAIN_CTX;

extern shm_http_t *SHM_HTTP_PTR;

void NF_MANAGE_NF_ACT(main_ctx_t *MAIN_CTX, nf_retrieve_item_t *nf_item)
{
	nf_manage_create_httpc_cmd_conn_act_dact(MAIN_CTX, nf_item, 1);
	print_nrfm_mml_raw(&nf_item->httpc_cmd);
	nf_manage_send_httpc_cmd(MAIN_CTX, nf_item);
}

void NF_MANAGE_NF_ADD(main_ctx_t *MAIN_CTX, nf_retrieve_item_t *nf_item)
{
	nf_retrieve_item_token_add(MAIN_CTX, nf_item);
	nf_manage_create_httpc_cmd_conn_add(MAIN_CTX, nf_item);
	print_nrfm_mml_raw(&nf_item->httpc_cmd);
	nf_manage_send_httpc_cmd(MAIN_CTX, nf_item);
}

void NF_MANAGE_NF_CLEAR(main_ctx_t *MAIN_CTX)
{
    char msgBuff[sizeof(GeneralQMsgType)] = {0,};

    GeneralQMsgType *msg = (GeneralQMsgType *)msgBuff;
    nrfm_mml_t *httpc_cmd = (nrfm_mml_t *)msg->body;
        
    msg->mtype = (long)MSGID_NRFM_HTTPC_MMC_REQUEST;
    httpc_cmd->command = NRFM_MML_HTTPC_CLEAR;
            
    int res = msgsnd(MAIN_CTX->my_qid.httpc_qid, msg, sizeof(nrfm_mml_t), 0);
            
    if (res < 0) {
        APPLOG(APPLOG_ERR, "{{{DBG}}} %s called, res (%d:fail), will retry {httpc_qid:%d}",
                __func__, res, MAIN_CTX->my_qid.httpc_qid);
    }
}

void NF_MANAGE_NF_DACT(main_ctx_t *MAIN_CTX, nf_retrieve_item_t *nf_item)
{
	nf_manage_create_httpc_cmd_conn_act_dact(MAIN_CTX, nf_item, 0);
	print_nrfm_mml_raw(&nf_item->httpc_cmd);
	nf_manage_send_httpc_cmd(MAIN_CTX, nf_item);
}

void NF_MANAGE_NF_DEL(main_ctx_t *MAIN_CTX, nf_retrieve_item_t *nf_item)
{
    nf_retrieve_item_token_del(MAIN_CTX, nf_item);
	nf_manage_create_httpc_cmd_conn_del(MAIN_CTX, nf_item);
	print_nrfm_mml_raw(&nf_item->httpc_cmd);
	nf_manage_send_httpc_cmd(MAIN_CTX, nf_item);
}

void NF_MANAGE_RESTORE_HTTPC_CONN(main_ctx_t *MAIN_CTX)
{
	int nf_type_num = g_slist_length(MAIN_CTX->nf_retrieve_list);
	for (int ii = 0; ii < nf_type_num; ii++) {
		nf_retrieve_info_t *nf_retr_info = g_slist_nth_data(MAIN_CTX->nf_retrieve_list, ii);

		int nf_item_num = g_slist_length(nf_retr_info->nf_retrieve_items);
		for (int jj = 0; jj < nf_item_num; jj++) {
			nf_retrieve_item_t *nf_item = g_slist_nth_data(nf_retr_info->nf_retrieve_items, jj);
			// remove token from my list
			nf_retrieve_item_token_del(MAIN_CTX, nf_item);
			// add new
			NF_MANAGE_NF_ADD(MAIN_CTX, nf_item);
		}
	}
}

void nf_manage_collect_avail_each_nf(nf_retrieve_item_t *nf_item, nf_list_pkt_t *my_avail_nfs)
{
	json_object *js_specific_info = NULL;
	int nfType = nf_manage_search_specific_info(nf_item->item_nf_profile, &js_specific_info);

	nf_type_info nf_specific_info = {0,};
	nf_manage_get_specific_info(nfType, js_specific_info, &nf_specific_info);

	nf_comm_plmn allowdPlmns[NF_MAX_ALLOWD_PLMNS] = {0,};
	int allowdPlmnsNum = nf_manage_get_allowd_plmns(nf_item->item_nf_profile, &allowdPlmns[0]);

	int pos = SHM_HTTP_PTR->current;
	nrfm_mml_t *nf_mml = &nf_item->httpc_cmd;

	for (int i = 0; i < nf_mml->info_cnt; i++) {
		nf_conn_info_t *nf_conn = &nf_mml->nf_conns[i];

		for (int k = 0; k < MAX_CON_NUM; k++) {
			conn_list_status_t *conn_raw = &SHM_HTTP_PTR->connlist[pos][k];

			if (conn_raw->nrfm_auto_added <= 0) continue;

			if (conn_raw->occupied <= 0) continue;
			if (conn_raw->act <= 0) continue;
			if (conn_raw->conn_cnt <= 0) continue;
			if (conn_raw->token_acquired <= 0) continue;
			if (!strcmp(conn_raw->host, nf_item->nf_uuid) &&
					!strcmp(conn_raw->scheme, nf_conn->scheme) &&
					!strcmp(conn_raw->ip, nf_conn->ip) &&
					conn_raw->port == nf_conn->port) {
				/* hit */
				nf_manage_create_lb_list_pkt(&MAIN_CTX, conn_raw, nfType, &nf_specific_info, allowdPlmnsNum, allowdPlmns, nf_conn, nf_item->item_nf_profile, my_avail_nfs);
			}
		}
	}
}


void nf_manage_collect_avail_each_type(nf_retrieve_info_t *nf_retr_info, nf_list_pkt_t *my_avail_nfs)
{
	g_slist_foreach(nf_retr_info->nf_retrieve_items, (GFunc)nf_manage_collect_avail_each_nf, my_avail_nfs);
}

void nf_manage_broadcast_nfs_to_fep(main_ctx_t *MAIN_CTX, nf_list_pkt_t *my_avail_nfs)
{
	int seqNo = ++MAIN_CTX->MAIN_SEQNO;

	for (int i = 0; i < my_avail_nfs->nf_avail_num; i++) {
		nf_service_info *nf_info = &my_avail_nfs->nf_avail[i];
		nf_info->seqNo = seqNo;
		nf_info->index = i;
		nf_info->lastIndex = (my_avail_nfs->nf_avail_num - 1);

		/* broad cast to fep */
		g_slist_foreach(MAIN_CTX->fep_assoc_list, (GFunc)nf_manage_send_nfs_status_to_fep, nf_info);
	}
}

void nf_manage_collect_httpc_conn_status(main_ctx_t *MAIN_CTX)
{
	if (MAIN_CTX->httpc_alive_status <= 0) {
	} else {
		nf_list_pkt_t my_avail_nfs = {0,};

		/* collect operator added */
		nf_manage_collect_oper_added_nf(MAIN_CTX, &my_avail_nfs);

		/* collect auto added */
		g_slist_foreach(MAIN_CTX->nf_retrieve_list, (GFunc)nf_manage_collect_avail_each_type, &my_avail_nfs);

		printf_avail_nfs(&my_avail_nfs);

		//nf_manage_print_my_avail_nfs(&my_avail_nfs);
		nf_manage_broadcast_nfs_to_fep(MAIN_CTX, &my_avail_nfs);
	}

	MAIN_CTX->httpc_alive_status = 0; // clear
}

void nf_manage_collect_httpc_conn_status_cb(evutil_socket_t fd, short what, void *arg)
{
	nf_manage_collect_httpc_conn_status(&MAIN_CTX);
}

void nf_manage_collect_oper_added_nf(main_ctx_t *MAIN_CTX, nf_list_pkt_t *my_avail_nfs)
{
	int pos = SHM_HTTP_PTR->current;

	for (int k = 0; k < MAX_CON_NUM; k++) {
		conn_list_status_t *conn_raw = &SHM_HTTP_PTR->connlist[pos][k];

		if (my_avail_nfs->nf_avail_num >= NF_MAX_AVAIL_LIST)
			return;

		if (conn_raw->nrfm_auto_added >= 1) continue;

		if (conn_raw->occupied <= 0) continue;
		if (conn_raw->act <= 0) continue;
		if (conn_raw->conn_cnt <= 0) continue;
		if (conn_raw->token_acquired <= 0) continue;

		nf_service_info *nf_avail = &my_avail_nfs->nf_avail[my_avail_nfs->nf_avail_num++];

		nf_avail->occupied = 1;
		nf_avail->lbId = MAIN_CTX->my_info.myLabelNum;

		sprintf(nf_avail->hostname, "%s", conn_raw->host);
		sprintf(nf_avail->type, "%s", conn_raw->type);
		sprintf(nf_avail->scheme, "%s", conn_raw->scheme);
		sprintf(nf_avail->ipv4Address, "%s", conn_raw->ip);
		nf_avail->port = conn_raw->port;
	}
}

void nf_manage_create_httpc_cmd_conn_act_dact(main_ctx_t *MAIN_CTX, nf_retrieve_item_t *nf_item, int act)
{
	nrfm_mml_t *httpc_cmd = &nf_item->httpc_cmd;

	/* never added */
	if (httpc_cmd->id <= 0)
		return;
	if (httpc_cmd->info_cnt <= 0)
		return;

	if (act)
		httpc_cmd->command = NRFM_MML_HTTPC_ACT;
	else
		httpc_cmd->command = NRFM_MML_HTTPC_DACT;

	httpc_cmd->seqNo = nf_item->httpc_cmd_ctx.seqNo = ++MAIN_CTX->MAIN_SEQNO;

	return;
}

void nf_manage_create_httpc_cmd_conn_add(main_ctx_t *MAIN_CTX, nf_retrieve_item_t *nf_item)
{
	nrfm_mml_t httpc_add_cmd = {0,};

	httpc_add_cmd.command = NRFM_MML_HTTPC_ADD;
	httpc_add_cmd.seqNo = nf_item->httpc_cmd_ctx.seqNo = ++MAIN_CTX->MAIN_SEQNO;

	sprintf(httpc_add_cmd.host, "%s", nf_item->nf_uuid);

	char key_nfType[128] = "nfType";
	json_object *js_nfType = search_json_object(nf_item->item_nf_profile, key_nfType);
	sprintf(httpc_add_cmd.type, "%s", json_object_get_string(js_nfType));

	char key_services[128] = "nfServices";
	json_object *js_services = search_json_object(nf_item->item_nf_profile, key_services);

	int array_length = json_object_array_length(js_services);
	for (int i = 0; i < array_length; i++) {
		json_object *js_elem = json_object_array_get_idx(js_services, i);
		char key_service[128] = "serviceName";
		char key_scheme[128] = "scheme";
		char key_ip[128] = "/ipEndPoints/0/ipv4Address"; // we use only 0th index in ipEndPoints
		char key_port[128] = "/ipEndPoints/0/port";
		json_object *js_service = search_json_object(js_elem, key_service);
		json_object *js_scheme = search_json_object(js_elem, key_scheme);
		json_object *js_ip = search_json_object(js_elem, key_ip);
		json_object *js_port = search_json_object(js_elem, key_port);

		if (js_scheme == NULL || js_ip == NULL) {
			APPLOG(APPLOG_ERR, "{{{DBG}}} %s can't find scheme or ipv4Address in nfServices!", __func__);
			continue;
		}
		const char *service = json_object_get_string(js_service);
		const char *scheme = json_object_get_string(js_scheme);
		const char *ip = json_object_get_string(js_ip);
		int port = json_object_get_int(js_port);

		if (strcmp(scheme, "https") && strcmp(scheme, "http")) {
			APPLOG(APPLOG_ERR, "{{{DBG}}} %s scheme invalid [%s]!", __func__, scheme);
			continue;
		}
		struct sockaddr_in sa = {0,};
		if (inet_pton(AF_INET, ip, &(sa.sin_addr)) == 0) {
			APPLOG(APPLOG_ERR, "{{{DBG}}} %s ip invalid [%s]!", __func__, ip);
			continue;
		}
		if (port == 0) { /* port can not exist */
			if (!strcmp(scheme, "https")) 
				port = 443;
			else 
				port = 80;
			APPLOG(APPLOG_ERR, "{{{DBG}}} %s port setted as [%d]", __func__, port);
		}

		if (nf_manage_fill_nrfm_mml(&httpc_add_cmd, service, scheme, ip, port) >= HTTP_MAX_CONN) {
			APPLOG(APPLOG_ERR, "{{{DBG}}} %s httpc conn pkt full num", __func__);
			break;
		}
	}

	httpc_add_cmd.token_id = nf_item->token_id;

	memcpy(&nf_item->httpc_cmd, &httpc_add_cmd, sizeof(nrfm_mml_t));
}

void nf_manage_create_httpc_cmd_conn_del(main_ctx_t *MAIN_CTX, nf_retrieve_item_t *nf_item)
{
	nrfm_mml_t *httpc_cmd = &nf_item->httpc_cmd;

	/* never added */
	if (httpc_cmd->id <= 0)
		return;
	if (httpc_cmd->info_cnt <= 0)
		return;

	httpc_cmd->command = NRFM_MML_HTTPC_DEL;
	httpc_cmd->seqNo = nf_item->httpc_cmd_ctx.seqNo = ++MAIN_CTX->MAIN_SEQNO;

	return;
}

int nf_manage_create_lb_list_get_priority(json_object *nf_profile, char *service_name)
{
	char key_services[128] = "nfServices";
	json_object *js_services = search_json_object(nf_profile, key_services);

	int array_length = json_object_array_length(js_services);
	for (int i = 0; i < array_length; i++) {
		json_object *js_elem = json_object_array_get_idx(js_services, i);

		char key_service_name[128] = "serviceName";
		char key_priority[128] = "priority";
		json_object *js_service_name = search_json_object(js_elem, key_service_name);
		json_object *js_priority = search_json_object(js_elem, key_priority);
		const char *serviceName = json_object_get_string(js_service_name);
		int priority = json_object_get_int(js_priority);

		if (!strcmp(serviceName, service_name))
			return priority;
	}

	return 65535; /* lowest */
}

void nf_manage_create_lb_list_pkt(main_ctx_t *MAIN_CTX, conn_list_status_t *conn_raw, int nfType, nf_type_info *nf_specific_info, int allowdPlmnsNum, nf_comm_plmn *allowdPlmns, nf_conn_info_t *nf_conn, json_object *nf_profile, nf_list_pkt_t *my_avail_nfs)
{
	for (int i = 0; i < nf_conn->svcNum; i++) {

		if (my_avail_nfs->nf_avail_num >= NF_MAX_AVAIL_LIST)
			return;
		nf_service_info *nf_avail = &my_avail_nfs->nf_avail[my_avail_nfs->nf_avail_num++];

		nf_avail->occupied = 1;
		nf_avail->lbId = MAIN_CTX->my_info.myLabelNum;

		nf_avail->nfType = nfType;
		memcpy(&nf_avail->nfTypeInfo, nf_specific_info, sizeof(nf_type_info));
		nf_avail->allowdPlmnsNum = allowdPlmnsNum;
		memcpy(nf_avail->allowdPlmns, allowdPlmns, sizeof(nf_comm_plmn) * allowdPlmnsNum);

		sprintf(nf_avail->serviceName, "%s", nf_conn->service[i]);

		sprintf(nf_avail->hostname, "%s", conn_raw->host);
		sprintf(nf_avail->type, "%s", conn_raw->type);
		sprintf(nf_avail->scheme, "%s", nf_conn->scheme);
		sprintf(nf_avail->ipv4Address, "%s", nf_conn->ip);
		nf_avail->port = nf_conn->port;
		nf_avail->priority = nf_manage_create_lb_list_get_priority(nf_profile, nf_avail->serviceName);

		nf_avail->auto_add = 1;
	}
}

int nf_manage_fill_nrfm_mml(nrfm_mml_t *nrfm_cmd, const char *service, const char *scheme, const char *ip, int port)
{
	int curr_num = nrfm_cmd->info_cnt;
	if (curr_num >= HTTP_MAX_ADDR) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s exceed max conn [%d]!", __func__, HTTP_MAX_ADDR);
		return HTTP_MAX_ADDR;
	}

	/* check already exist */
	for (int i = 0; i < curr_num; i++) {
		nf_conn_info_t *nf_info = &nrfm_cmd->nf_conns[i];
		if (!nf_info->occupied)
			continue;
		if (!strcmp(scheme, nf_info->scheme) &&
				!strcmp(ip, nf_info->ip) &&
				(port == nf_info->port)) {
			if (nf_info->svcNum < MAX_NF_SVC) {
				sprintf(nf_info->service[nf_info->svcNum++], "%s", service);
			}
			return curr_num; // already exist
		}
	}

	/* add new */
	nf_conn_info_t *nf_info = &nrfm_cmd->nf_conns[nrfm_cmd->info_cnt++];
	nf_info->occupied = 1;
	sprintf(nf_info->scheme, "%s", scheme);
	sprintf(nf_info->ip, "%s", ip);
	nf_info->port = port;
	nf_info->cnt = 2;
	if (nf_info->svcNum < MAX_NF_SVC) {
		sprintf(nf_info->service[nf_info->svcNum++], "%s", service);
	}

	return nrfm_cmd->info_cnt;
}

int nf_manage_get_allowd_plmns(json_object *nf_profile, nf_comm_plmn *allowdPlmns)
{
	char key_allowd_plmns[128] = "allowedPlmns";
	json_object *js_allowd_plmns = search_json_object(nf_profile, key_allowd_plmns);

	int allowdPlmnsNum = (json_object_array_length(js_allowd_plmns) > NF_MAX_ALLOWD_PLMNS) ?
		NF_MAX_ALLOWD_PLMNS : json_object_array_length(js_allowd_plmns);

	for (int i = 0; i < allowdPlmnsNum; i++) {
		json_object *js_allowd_plmn_elem = json_object_array_get_idx(js_allowd_plmns, i);
		char key_mcc[128] = "mcc";
		char key_mnc[128] = "mnc";
		json_object *js_mcc = search_json_object(js_allowd_plmn_elem, key_mcc);
		json_object *js_mnc = search_json_object(js_allowd_plmn_elem, key_mnc);
		sprintf(allowdPlmns[i].mcc, "%s", json_object_get_string(js_mcc));
		sprintf(allowdPlmns[i].mnc, "%s", json_object_get_string(js_mnc));
	}

	return allowdPlmnsNum;
}

void nf_manage_get_specific_info(int nfType, json_object *js_specific_info, nf_type_info *nf_specific_info)
{
	if (nfType == NF_TYPE_UDM) {
		nf_udm_info *udmInfo = &nf_specific_info->udmInfo;

		/* group Id */
		char key_groupId[128] = "groupId";
		json_object *js_group_id = search_json_object(js_specific_info, key_groupId);
		sprintf(udmInfo->groupId, "%s", json_object_get_string(js_group_id));

		/* supiRanges */
		char key_supi_ranges[128] = "supiRanges";
		json_object *js_supi_ranges = search_json_object(js_specific_info, key_supi_ranges);
		udmInfo->supiRangesNum = (json_object_array_length(js_supi_ranges) > NF_MAX_SUPI_RANGES) ?
			NF_MAX_SUPI_RANGES : json_object_array_length(js_supi_ranges);
		for (int i = 0; i < udmInfo->supiRangesNum; i++) {
			json_object *js_supi_elem = json_object_array_get_idx(js_supi_ranges, i);
			char key_start[128] = "start";
			char key_end[128] = "end";
			json_object *js_start = search_json_object(js_supi_elem, key_start);
			json_object *js_end = search_json_object(js_supi_elem, key_end);
			sprintf(udmInfo->supiRanges[i].start, "%s", json_object_get_string(js_start));
			sprintf(udmInfo->supiRanges[i].end, "%s", json_object_get_string(js_end));
		}

		/* routingIndicators */
		char key_routing_indicators[128] = "routingIndicators";
		json_object *js_routing_indicators = search_json_object(js_specific_info, key_routing_indicators);
		udmInfo->routingIndicatorsNum = (json_object_array_length(js_routing_indicators) > NF_MAX_RI) ?
			NF_MAX_RI : json_object_array_length(js_routing_indicators);
		for (int i = 0; i < udmInfo->routingIndicatorsNum; i++) {
			json_object *js_ri_elem = json_object_array_get_idx(js_routing_indicators, i);
			sprintf(udmInfo->routingIndicators[i], "%s", json_object_get_string(js_ri_elem));
		}
	}
}

void nf_manage_handle_cmd_res(nrfm_mml_t *httpc_cmd_res)
{
	APPLOG(APPLOG_ERR, "{{{DBG}}} %s called", __func__);

	nf_retrieve_item_t *nf_item = nf_retrieve_search_item_via_seqNo(&MAIN_CTX, NF_ITEM_CTX_TYPE_CMD, httpc_cmd_res->seqNo);

	if (nf_item == NULL) {
		APPLOG(APPLOG_DEBUG, "{{{DBG}}} %s() something wrong, can't find ctx (seqNo:%d)",
				__func__, httpc_cmd_res->seqNo);
		return;
	}

	/* stop timer */
	stop_ctx_timer(NF_CTX_TYPE_HTTPC_CMD, &nf_item->httpc_cmd_ctx);

	switch (httpc_cmd_res->command) {
		case NRFM_MML_HTTPC_ADD:
			nf_item->httpc_cmd.id = httpc_cmd_res->id;
			APPLOG(APPLOG_ERR, "{{{DBG}}} %s add success response id (%d)", __func__,  nf_item->httpc_cmd.id);
			break;
		default:
			break;
	}

}

void nf_manage_handle_httpc_alive(nrfm_noti_t *httpc_noti)
{
	MAIN_CTX.httpc_alive_status = 1; // httpc alive

	if (MAIN_CTX.HTTPC_PID == 0) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s initial httpc pid (%d)", __func__, MAIN_CTX.HTTPC_PID);
		MAIN_CTX.HTTPC_PID = httpc_noti->my_pid;
	} else if (MAIN_CTX.HTTPC_PID != httpc_noti->my_pid) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s check httpc restart pid (%d) --> pid (%d)", __func__, MAIN_CTX.HTTPC_PID, httpc_noti->my_pid);
		MAIN_CTX.HTTPC_PID = httpc_noti->my_pid;

		NF_MANAGE_RESTORE_HTTPC_CONN(&MAIN_CTX);
	}
}

void nf_manage_print_my_avail_nfs(nf_list_pkt_t *avail_nfs)
{
	printf_avail_nfs(avail_nfs);
}

int nf_manage_search_specific_info(json_object *nf_profile, json_object **js_specific_info)
{
	char key_nfType[128] = "nfType";
	json_object *js_nfType = search_json_object(nf_profile, key_nfType);
	const char *nfType = json_object_get_string(js_nfType);

	if(!strcmp(nfType, "UDM")) {
		char key_specific_info[128] = "udmInfo";
		*js_specific_info = search_json_object(nf_profile, key_specific_info);
		return NF_TYPE_UDM;
	} else if(!strcmp(nfType, "UDR")) {
		char key_specific_info[128] = "udrInfo";
		*js_specific_info = search_json_object(nf_profile, key_specific_info);
		return NF_TYPE_UDR;
	} else {
		*js_specific_info = NULL;
		return NF_TYPE_UNKNOWN;
	}
}

void nf_manage_send_httpc_cmd(main_ctx_t *MAIN_CTX, nf_retrieve_item_t *nf_item)
{
	char msgBuff[sizeof(GeneralQMsgType)] = {0,};

	GeneralQMsgType *msg = (GeneralQMsgType *)msgBuff;
	nrfm_mml_t *httpc_cmd = (nrfm_mml_t *)msg->body;

	msg->mtype = (long)MSGID_NRFM_HTTPC_MMC_REQUEST;
	memcpy(httpc_cmd, &nf_item->httpc_cmd, sizeof(nrfm_mml_t));

    int res = msgsnd(MAIN_CTX->my_qid.httpc_qid, msg, sizeof(nrfm_mml_t), 0);

    if (res < 0) {
        /* CHECK !!! after 1 sec will auto retry */
        APPLOG(APPLOG_ERR, "{{{DBG}}} %s called, res (%d:fail), will retry {httpc_qid:%d}",
                __func__, res, MAIN_CTX->my_qid.httpc_qid);
    } else {
        /* start timer */
        APPLOG(APPLOG_ERR, "{{{DBG}}} %s called, res (%d:succ), will wait {httpc_qid:%d}",
                __func__, res, MAIN_CTX->my_qid.httpc_qid);
        start_ctx_timer(NF_CTX_TYPE_HTTPC_CMD, &nf_item->httpc_cmd_ctx);
    }
}

void nf_manage_send_nfs_status_to_fep(assoc_t *node_elem, nf_service_info *nf_info)
{
	IsifMsgType txIsifMsg = {0,};

	isifc_create_pkt_for_status(&txIsifMsg, nf_info, &MAIN_CTX.my_info, node_elem);
	isifc_send_pkt_for_status(MAIN_CTX.my_qid.isifc_tx_qid, &txIsifMsg);
}

