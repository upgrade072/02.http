#include <nrfm.h>

extern main_ctx_t MAIN_CTX;

void nf_retrieve_addnew_and_get_profile(main_ctx_t *MAIN_CTX, nf_retrieve_info_t *nf_retr_info, nf_retrieve_item_t *nf_add_item)
{
	nf_retrieve_item_t *nf_item = malloc(sizeof(nf_retrieve_item_t));
	memcpy(nf_item, nf_add_item, sizeof(nf_retrieve_item_t));

	nf_retr_info->nf_retrieve_items = g_slist_append(nf_retr_info->nf_retrieve_items, nf_item);

	nf_retrieve_single_instance(MAIN_CTX, nf_item);

	return;
}

void nf_retrieve_arrange_item(nf_retrieve_item_t *nf_item, nf_retrieve_info_t *nf_retr_info)
{
	for (int i = 0; i < json_object_array_length(nf_retr_info->js_retrieve_response); i++) {
		json_object *js_item = json_object_array_get_idx(nf_retr_info->js_retrieve_response, i);
		nf_retrieve_item_t temp_item = {0,};
		if (nf_retrieve_parse_list(js_item, &temp_item) <= 0)
			continue;;
		if (!strcmp(nf_item->nf_uuid, temp_item.nf_uuid)) {
			APPLOG(APPLOG_ERR, "{{{DBG}}} %s already item (uuid:%s) match with retr resp item, keep it",
					__func__, nf_item->nf_uuid);
			return;
		}
	}
	APPLOG(APPLOG_ERR, "{{{DBG}}} %s already item (uuid:%s) did'nt match with retr resp item, remove it",
			__func__, nf_item->nf_uuid);

	nf_retrieve_remove_nth_item(nf_retr_info, nf_item);
}

void nf_retrieve_arrange_legacy_list(nf_retrieve_info_t *nf_retr_info)
{
	g_slist_foreach(nf_retr_info->nf_retrieve_items, (GFunc)nf_retrieve_arrange_item, nf_retr_info);
}

void nf_retrieve_get_nf_profiles(main_ctx_t *MAIN_CTX, nf_retrieve_info_t *nf_retr_info)
{
	char key[128] = "_links/item";
	json_object *js_list = search_json_object(nf_retr_info->js_retrieve_response, key);

	for (int ii = 0; ii < json_object_array_length(js_list); ii++) {
		json_object *js_item = json_object_array_get_idx(js_list, ii);
		nf_retrieve_item_t temp_nf_item = {0,};
		nf_retrieve_item_t *nf_item = NULL;

		// get uuid
		if (nf_retrieve_parse_list(js_item, &temp_nf_item) <= 0) {
			APPLOG(APPLOG_ERR, "{{{CAUTION}}} %s() fail to parse [%s]", __func__, json_object_get_string(js_item));
			continue;
		}
		// check from list if exist
		if ((nf_item = nf_retrieve_search_item_by_uuid(nf_retr_info->nf_retrieve_items, temp_nf_item.nf_uuid)) != NULL) {
			APPLOG(APPLOG_ERR, "{{{DBG}}} %s() svc[%s] uuid[%s] already exist", __func__, nf_retr_info->nf_type, nf_item->nf_uuid);
			continue;
		}
		// if non, add one
		APPLOG(APPLOG_ERR, "{{{DBG}} %s will get nf profile for %s:%s",
				__func__, nf_retr_info->nf_type, temp_nf_item.nf_uuid);

		nf_retrieve_addnew_and_get_profile(MAIN_CTX, nf_retr_info, &temp_nf_item);
	}
}

void nf_retrieve_instance_create_pkt(main_ctx_t *MAIN_CTX, AhifHttpCSMsgType *ahifPkt, nf_retrieve_item_t *nf_item)
{
	AhifHttpCSMsgHeadType *head = &ahifPkt->head;
	head->mtype = MTYPE_NRFM_NF_PROFILE_REQUEST;
	head->ahifCid = nf_item->retrieve_item_ctx.seqNo = ++MAIN_CTX->MAIN_SEQNO;

	APPLOG(APPLOG_ERR, "{{{DBG}}} %s called, ahifPktCid(%d), retrieveItemCtxId(%d)",
			__func__, head->ahifCid, nf_item->retrieve_item_ctx.seqNo);

	/* scheme / method / rsrcUri */
	sprintf(head->scheme, "%s", "https"); // WE MUST USE TLS
	sprintf(head->httpMethod, "%s", "GET");

	sprintf(head->rsrcUri, "/nnrf-nfm/v1/nf-instances/%s", nf_item->nf_uuid);

#if 0
	/* destType */
	sprintf(head->destType, "%s", "NRF");
#else
    nf_regi_restore_httpc_info(MAIN_CTX, head);
#endif

    /* vheader */
    head->vheaderCnt = 2;
    ahifPkt->vheader[0].vheader_id = VH_CONTENT_TYPE;
    sprintf(ahifPkt->vheader[0].vheader_body, "%s", "application/json");
    ahifPkt->vheader[1].vheader_id = VH_ACCEPT_ENCODING;;
    sprintf(ahifPkt->vheader[1].vheader_body, "%s", "application/json");

    /* body */
	head->bodyLen = 0;
}

void nf_retrieve_instance_handle_resp_proc(AhifHttpCSMsgType *ahifPkt)
{
    APPLOG(APPLOG_ERR, "{{{DBG}}} %s called", __func__);

    AhifHttpCSMsgHeadType *head = &ahifPkt->head;

	APPLOG(APPLOG_ERR, "%s() receive NRF Retrieve (instance) Response (http resp:%d)", __func__, head->respCode);

	nf_retrieve_item_t *nf_item = nf_retrieve_search_item_via_seqNo(&MAIN_CTX, NF_ITEM_CTX_TYPE_PROFILE, head->ahifCid);

	if (nf_item == NULL) {
		APPLOG(APPLOG_DEBUG, "{{{DBG}}} %s() something wrong, can't find ctx (seqNo:%s)",
				__func__, head->ahifCid);
		return;
	}

    stop_ctx_timer(NF_CTX_TYPE_RETRIEVE_PROFILE, &nf_item->retrieve_item_ctx);

    switch (head->respCode) {
        case 200: // with nfProfile
			NRF_STAT_INC(MAIN_CTX.NRF_STAT, head->destHost, NFProfileRetrieval, NRFS_SUCCESS);

			nf_retrieve_save_recv_nf_profile(nf_item, ahifPkt);
            break;

		case 403: // you don't have right to query that nf-type
		case 500: // NRF have problem
			NRF_STAT_INC(MAIN_CTX.NRF_STAT, head->destHost, NFProfileRetrieval, NRFS_FAIL);
			nf_retrieve_item_retry_while_after(nf_item);
			break;

        default:
			NRF_STAT_INC(MAIN_CTX.NRF_STAT, head->destHost, NFProfileRetrieval, NRFS_FAIL);
			nf_retrieve_item_retry_while_after(nf_item);
            break;
    }
}

void nf_retrieve_instances_list(nf_retrieve_info_t *nf_retr_info, main_ctx_t *MAIN_CTX)
{
	APPLOG(APPLOG_ERR, "{{{DBG}}} %s called", __func__);

	char msgBuff[sizeof(GeneralQMsgType)] = {0,};

	GeneralQMsgType *msg = (GeneralQMsgType *)msgBuff;
	AhifHttpCSMsgType *ahifPkt = (AhifHttpCSMsgType *)msg->body;

	msg->mtype = (long)MSGID_NRFM_HTTPC_REQUEST;

	nf_retrieve_list_create_pkt(MAIN_CTX, ahifPkt, nf_retr_info);

    size_t shmqlen = AHIF_APP_MSG_HEAD_LEN + AHIF_VHDR_LEN + ahifPkt->head.queryLen + ahifPkt->head.bodyLen;

    int res = msgsnd(MAIN_CTX->my_qid.httpc_qid, msg, shmqlen, IPC_NOWAIT);

	NRF_STAT_INC(MAIN_CTX->NRF_STAT, ahifPkt->head.destHost, NFListRetrieval, NRFS_ATTEMPT);

    if (res < 0) {
        APPLOG(APPLOG_ERR, "{{{DBG}}} %s called, res (%d:fail), will retry {httpc_qid:%d}",
                __func__, res, MAIN_CTX->my_qid.httpc_qid);
        /* retry after */
		nf_retrieve_list_retry_while_after(nf_retr_info);
    } else {
        /* start timer */
        APPLOG(APPLOG_ERR, "{{{DBG}}} %s called, res (%d:succ), will wait {httpc_qid:%d}",
                __func__, res, MAIN_CTX->my_qid.httpc_qid);
        start_ctx_timer(NF_CTX_TYPE_RETRIEVE_LIST, &nf_retr_info->retrieve_list_ctx);
    }
}

void nf_retrieve_item_handle_timeout(nrf_ctx_t *nf_ctx)
{
	nf_retrieve_item_t *nf_item = nf_retrieve_search_item_via_seqNo(&MAIN_CTX, NF_ITEM_CTX_TYPE_PROFILE, nf_ctx->seqNo);

	if (nf_item == NULL) {
		APPLOG(APPLOG_DEBUG, "{{{DBG}}} %s() something wrong, can't find ctx (seqNo:%s)",
				__func__, nf_ctx->seqNo);
		return;
	}

    stop_ctx_timer(NF_CTX_TYPE_RETRIEVE_PROFILE, &nf_item->retrieve_item_ctx);

	nf_retrieve_item_retry_while_after(nf_item);
}

void nf_retrieve_item_recall_cb(evutil_socket_t fd, short what, void *arg)
{
	nf_retrieve_item_t *nf_item = (nf_retrieve_item_t *)arg;
	nf_retrieve_single_instance(&MAIN_CTX, nf_item);
}

void nf_retrieve_item_retry_while_after(nf_retrieve_item_t *nf_item)
{
	struct timeval timer_sec = {0,};

	config_setting_t *setting = config_lookup(&MAIN_CTX.CFG, CF_NRFM_RETRY_TM);
	APPLOG(APPLOG_ERR, "{{{DBG}}} %s retry after %d sec for uuid[%s]", 
			__func__, config_setting_get_int(setting), nf_item->nf_uuid);
	timer_sec.tv_sec = config_setting_get_int(setting);
	event_base_once(MAIN_CTX.EVBASE, -1, EV_TIMEOUT, nf_retrieve_item_recall_cb, nf_item, &timer_sec);
}

void nf_retrieve_item_token_add(main_ctx_t *MAIN_CTX, nf_retrieve_item_t *nf_item)
{
	/* insert to access token table */
	acc_token_info_t *token_info = new_acc_token_info(MAIN_CTX->nrf_access_token.ACC_TOKEN_LIST);
	if (token_info == NULL) {
		APPLOG(APPLOG_ERR, "{{{CAUTION!!!}}} %s cant assign access_token_info(shm)!", __func__);
	} else {
		nf_item->token_id = token_info->token_id;
		nf_token_add_shm_by_nf(token_info, nf_item);

		if (MAIN_CTX->sysconfig.debug_mode) {
			char *respBuff = malloc(1024 * 1024);
			print_token_info_raw(MAIN_CTX->nrf_access_token.ACC_TOKEN_LIST, respBuff);
			APPLOG(APPLOG_ERR, "NOW TOKEN SHM IS >>>\n%s", respBuff);
			free(respBuff);
		}
	}
}

void nf_retrieve_item_token_del(main_ctx_t *MAIN_CTX, nf_retrieve_item_t *nf_item)
{
	/* remove from access token table */
	acc_token_info_t *token_info = get_acc_token_info(MAIN_CTX->nrf_access_token.ACC_TOKEN_LIST, nf_item->token_id, 1);
	if (token_info == NULL) {
		APPLOG(APPLOG_ERR, "{{{CAUTION!!!}}} %s cant get access_token_info(shm)!", __func__);
	} else {
		nf_token_del_shm_by_nf(token_info);

		if (MAIN_CTX->sysconfig.debug_mode) {
			char *respBuff = malloc(1024 * 1024);
			print_token_info_raw(MAIN_CTX->nrf_access_token.ACC_TOKEN_LIST, respBuff);
			APPLOG(APPLOG_ERR, "NOW TOKEN SHM IS >>>\n%s", respBuff);
			free(respBuff);
		}
	}
}


void nf_retrieve_list_create_pkt(main_ctx_t *MAIN_CTX, AhifHttpCSMsgType *ahifPkt, nf_retrieve_info_t *nf_retr_info)
{
	AhifHttpCSMsgHeadType *head = &ahifPkt->head;
	head->mtype = MTYPE_NRFM_RETRIEVE_REQUEST;
	head->ahifCid = nf_retr_info->retrieve_list_ctx.seqNo = ++MAIN_CTX->MAIN_SEQNO;

	APPLOG(APPLOG_ERR, "{{{DBG}}} %s called, ahifPktCid(%d), retrieveListCtx(%d)",
			__func__, head->ahifCid, nf_retr_info->retrieve_list_ctx.seqNo);

	/* scheme / method / rsrcUri */
	sprintf(head->scheme, "%s", "https"); // WE MUST USE TLS
	sprintf(head->httpMethod, "%s", "GET");

	sprintf(head->rsrcUri, "/nnrf-nfm/v1/nf-instances?nf-type%%3D%s%%26limit%%3D%d", nf_retr_info->nf_type, nf_retr_info->limit);

#if 0
	/* destType */
	sprintf(head->destType, "%s", "NRF");
#else
    nf_regi_restore_httpc_info(MAIN_CTX, head);
#endif

    /* vheader */
    head->vheaderCnt = 2;
    ahifPkt->vheader[0].vheader_id = VH_CONTENT_TYPE;
    sprintf(ahifPkt->vheader[0].vheader_body, "%s", "application/json");
    ahifPkt->vheader[1].vheader_id = VH_ACCEPT_ENCODING;;
    sprintf(ahifPkt->vheader[1].vheader_body, "%s", "application/json");

    /* body */
	head->bodyLen = 0;
}

void nf_retrieve_list_handle_resp_proc(AhifHttpCSMsgType *ahifPkt)
{               
    APPLOG(APPLOG_ERR, "{{{DBG}}} %s called", __func__);

	int nf_retrieve_item_num = 0;

	AhifHttpCSMsgHeadType *head = &ahifPkt->head;

	APPLOG(APPLOG_ERR, "%s() receive NRF Retrieve (List) Response (http resp:%d)", __func__, head->respCode);

	nf_retrieve_info_t *nf_retr_info = nf_retrieve_search_info_via_seqNo(&MAIN_CTX, head->ahifCid);

	if (nf_retr_info == NULL) {
		APPLOG(APPLOG_DEBUG, "{{{DBG}}} %s() something wrong, can't find ctx (seqNo:%s)",
				__func__, head->ahifCid);
		return;
	}

    stop_ctx_timer(NF_CTX_TYPE_RETRIEVE_LIST, &nf_retr_info->retrieve_list_ctx);

    switch (head->respCode) {
        case 200: // with nfProfile
			NRF_STAT_INC(MAIN_CTX.NRF_STAT, head->destHost, NFListRetrieval, NRFS_SUCCESS);

			nf_retrieve_item_num = nf_retrieve_save_response(nf_retr_info, ahifPkt);

			if (nf_retrieve_item_num <= 0)
				return nf_retrieve_list_retry_while_after(nf_retr_info);

			/* remove manage list if it did't belong response uri list */
			nf_retrieve_arrange_legacy_list(nf_retr_info);
			/* go and get nf_profiles */
			nf_retrieve_get_nf_profiles(&MAIN_CTX, nf_retr_info);
            break;

		case 400: // request query param is wrong
		case 403: // you don't have right to query that nf-type
		case 500: // NRF have problem
			NRF_STAT_INC(MAIN_CTX.NRF_STAT, head->destHost, NFListRetrieval, NRFS_FAIL);
			nf_retrieve_list_retry_while_after(nf_retr_info);
			break;

        default:
			NRF_STAT_INC(MAIN_CTX.NRF_STAT, head->destHost, NFListRetrieval, NRFS_FAIL);
			nf_retrieve_list_retry_while_after(nf_retr_info);
            break;
    }
}

void nf_retrieve_list_handle_timeout(nrf_ctx_t *nf_ctx)
{
	nf_retrieve_info_t *nf_retr_info = nf_retrieve_search_info_via_seqNo(&MAIN_CTX, nf_ctx->seqNo);

	if (nf_retr_info == NULL) {
		APPLOG(APPLOG_DEBUG, "{{{DBG}}} %s() something wrong, can't find ctx (seqNo:%s)",
				__func__, nf_ctx->seqNo);
		return;
	}
    stop_ctx_timer(NF_CTX_TYPE_RETRIEVE_LIST, &nf_retr_info->retrieve_list_ctx);

	nf_retrieve_list_retry_while_after(nf_retr_info);
}

void nf_retrieve_list_recall_cb(evutil_socket_t fd, short what, void *arg)
{
	nf_retrieve_info_t *nf_retr_info = (nf_retrieve_info_t *)arg;
	nf_retrieve_instances_list(nf_retr_info, &MAIN_CTX);
}

void nf_retrieve_list_retry_while_after(nf_retrieve_info_t *nf_retr_info)
{
	struct timeval timer_sec = {0,};

	config_setting_t *setting = config_lookup(&MAIN_CTX.CFG, CF_NRFM_RETRY_TM);
	APPLOG(APPLOG_ERR, "{{{DBG}}} %s retry after %d sec for type[%s]", 
			__func__, config_setting_get_int(setting), nf_retr_info->nf_type);
	timer_sec.tv_sec = config_setting_get_int(setting);
	event_base_once(MAIN_CTX.EVBASE, -1, EV_TIMEOUT, nf_retrieve_list_recall_cb, nf_retr_info, &timer_sec);
}

int nf_retrieve_parse_list(json_object *js_item, nf_retrieve_item_t *item_ctx)
{
	char protocol[128] = {0,};
	char host[128] = {0,};

	sscanf(json_object_get_string(js_item), "%127[^:/]://%127[^/]/nnrf-nfm/v1/nf-instances/%255s", protocol, host, item_ctx->nf_uuid);
	APPLOG(APPLOG_DEBUG, "{{{DBG}}} %s() %s %s %s %s", 
			__func__, protocol, host, item_ctx->nf_uuid, strlen(item_ctx->nf_uuid) == 0 ? "fail" : "succ");
	return strlen(item_ctx->nf_uuid);
}

void nf_retrieve_remove_nth_item(nf_retrieve_info_t *nf_retr_info, nf_retrieve_item_t *nf_item)
{
	if (nf_item->item_nf_profile) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s object_put() legacy profile!", __func__);
		json_object_put(nf_item->item_nf_profile);
	}
	if (nf_item->retrieve_item_ctx.ev_action) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s event_del() legacy request!", __func__);
		event_del(nf_item->retrieve_item_ctx.ev_action);
	}

	NF_MANAGE_NF_DEL(&MAIN_CTX, nf_item);

	APPLOG(APPLOG_ERR, "{{{TODO|check memleak}}} %s remove nf_type(%s) nf_item (uuid:%s)!!!", __func__, nf_retr_info->nf_type, nf_item->nf_uuid);
	nf_retr_info->nf_retrieve_items = g_slist_remove(nf_retr_info->nf_retrieve_items, nf_item);
	free(nf_item);
}

void nf_retrieve_save_recv_nf_profile(nf_retrieve_item_t *nf_item, AhifHttpCSMsgType *ahifPkt)
{
	if (nf_item->item_nf_profile) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s release older nf_profile (from NRF)", __func__);
		json_object_put(nf_item->item_nf_profile);
	}       
	nf_item->item_nf_profile = json_tokener_parse(ahifPkt->data);

	NF_MANAGE_NF_ADD(&MAIN_CTX, nf_item);

	LOG_JSON_OBJECT("NRF RECEIVED NF INSTANCE PROFILE IS", nf_item->item_nf_profile);
}

int nf_retrieve_save_response(nf_retrieve_info_t *nf_retr_info, AhifHttpCSMsgType *ahifPkt)
{
	if (nf_retr_info->js_retrieve_response != NULL) {
		APPLOG(APPLOG_ERR, "{{{CAUTION!!!}}} %s release older nf_service_retrieve_list", __func__);
		json_object_put(nf_retr_info->js_retrieve_response);
	}

	if ((nf_retr_info->js_retrieve_response = json_tokener_parse(ahifPkt->data)) == NULL) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s response json something wrong", __func__);
		return -1;
	}

	LOG_JSON_OBJECT("NF RETRIEVE RESPONSE IS", nf_retr_info->js_retrieve_response);

	char key[128] = "_links/item";
	json_object *js_item = search_json_object(nf_retr_info->js_retrieve_response, key);

	if (js_item == NULL) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s can't find \"_links/item\"", __func__);
		json_object_put(nf_retr_info->js_retrieve_response);
		return -1;
	}

	LOG_JSON_OBJECT("NF RETRIEVE NF URI IS", js_item);

	return json_object_array_length(js_item);
}

nf_retrieve_info_t *nf_retrieve_search_info_via_nfType(main_ctx_t *MAIN_CTX, const char *nfType)
{
	int nf_type_num = g_slist_length(MAIN_CTX->nf_retrieve_list);
	for (int ii = 0; ii < nf_type_num; ii++) {

		nf_retrieve_info_t *nf_retr_info = g_slist_nth_data(MAIN_CTX->nf_retrieve_list, ii);

		if (!strcmp(nf_retr_info->nf_type, nfType)) { 
			APPLOG(APPLOG_DEBUG, "{{{DBG}}} %s() find from nf_retrieve_info type[%s]", __func__, nf_retr_info->nf_type);
			return nf_retr_info;
		}
	}

	return NULL;
}

nf_retrieve_info_t *nf_retrieve_search_info_via_seqNo(main_ctx_t *MAIN_CTX, int seqNo)
{
	int nf_type_num = g_slist_length(MAIN_CTX->nf_retrieve_list);
	for (int ii = 0; ii < nf_type_num; ii++) {

		nf_retrieve_info_t *nf_retr_info = g_slist_nth_data(MAIN_CTX->nf_retrieve_list, ii);
		nrf_ctx_t *nf_ctx = &nf_retr_info->retrieve_list_ctx;

		if (nf_ctx->seqNo == seqNo) {
			APPLOG(APPLOG_DEBUG, "{{{DBG}}} %s() find from nf_retrieve_info type[%s]", __func__, nf_retr_info->nf_type);
			return nf_retr_info;
		}
	}

	return NULL;
}

nf_retrieve_item_t *nf_retrieve_search_item_by_uuid(GSList *nf_retrieve_items, const char *nf_uuid)
{
	for (int i = 0; i < g_slist_length(nf_retrieve_items); i++) {
		nf_retrieve_item_t *nf_nth_item = g_slist_nth_data(nf_retrieve_items, i);
		if (!strcmp(nf_nth_item->nf_uuid, nf_uuid))
			return nf_nth_item;
	}
	return NULL;
}
nf_retrieve_item_t *nf_retrieve_search_item_via_seqNo(main_ctx_t *MAIN_CTX, int type, int seqNo)
{
	int nf_type_num = g_slist_length(MAIN_CTX->nf_retrieve_list);
	for (int ii = 0; ii < nf_type_num; ii++) {
		nf_retrieve_info_t *nf_retr_info = g_slist_nth_data(MAIN_CTX->nf_retrieve_list, ii);

		int nf_item_num = g_slist_length(nf_retr_info->nf_retrieve_items);
		for (int jj = 0; jj < nf_item_num; jj++) {
			nf_retrieve_item_t *nf_item = g_slist_nth_data(nf_retr_info->nf_retrieve_items, jj);

			if (type == NF_ITEM_CTX_TYPE_PROFILE) {
				if (seqNo == nf_item->retrieve_item_ctx.seqNo) 
					return nf_item;
			} else if (type == NF_ITEM_CTX_TYPE_CMD) {
				if (seqNo == nf_item->httpc_cmd_ctx.seqNo) 
					return nf_item;
			}
		}
	}

	return NULL;
}

void nf_retrieve_single_instance(main_ctx_t *MAIN_CTX, nf_retrieve_item_t *nf_item)
{
	APPLOG(APPLOG_ERR, "{{{DBG}}} %s called", __func__);

	char msgBuff[sizeof(GeneralQMsgType)] = {0,};

	GeneralQMsgType *msg = (GeneralQMsgType *)msgBuff;
	AhifHttpCSMsgType *ahifPkt = (AhifHttpCSMsgType *)msg->body;

	msg->mtype = (long)MSGID_NRFM_HTTPC_REQUEST;

	nf_retrieve_instance_create_pkt(MAIN_CTX, ahifPkt, nf_item);

    size_t shmqlen = AHIF_APP_MSG_HEAD_LEN + AHIF_VHDR_LEN + ahifPkt->head.queryLen + ahifPkt->head.bodyLen;

    int res = msgsnd(MAIN_CTX->my_qid.httpc_qid, msg, shmqlen, IPC_NOWAIT);

	NRF_STAT_INC(MAIN_CTX->NRF_STAT, ahifPkt->head.destHost, NFProfileRetrieval, NRFS_ATTEMPT);

    if (res < 0) {
        APPLOG(APPLOG_ERR, "{{{DBG}}} %s called, res (%d:fail), will retry {httpc_qid:%d}",
                __func__, res, MAIN_CTX->my_qid.httpc_qid);
        /* retry after */
		nf_retrieve_item_retry_while_after(nf_item);
    } else {
        /* start timer */
        APPLOG(APPLOG_ERR, "{{{DBG}}} %s called, res (%d:succ), will wait {httpc_qid:%d}",
                __func__, res, MAIN_CTX->my_qid.httpc_qid);
		start_ctx_timer(NF_CTX_TYPE_RETRIEVE_PROFILE, &nf_item->retrieve_item_ctx);
    }
}

void nf_retrieve_start_process(main_ctx_t *MAIN_CTX)
{
	g_slist_foreach(MAIN_CTX->nf_retrieve_list, (GFunc)nf_retrieve_instances_list, MAIN_CTX);
}

