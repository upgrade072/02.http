#include <nrfm.h>

extern main_ctx_t MAIN_CTX;

void nf_token_acquire_token(main_ctx_t *MAIN_CTX, acc_token_info_t *token_info)
{
	char msgBuff[sizeof(GeneralQMsgType)] = {0,};

	GeneralQMsgType *msg = (GeneralQMsgType *)msgBuff;
	AhifHttpCSMsgType *ahifPkt = (AhifHttpCSMsgType *)msg->body;

	msg->mtype = (long)MSGID_NRFM_HTTPC_REQUEST;

	token_ctx_list_t *token_request = nf_token_create_ctx(MAIN_CTX, token_info);

	nf_token_create_pkt(MAIN_CTX, ahifPkt, token_info, token_request);

    size_t shmqlen = AHIF_APP_MSG_HEAD_LEN + AHIF_VHDR_LEN + ahifPkt->head.queryLen + ahifPkt->head.bodyLen;

    int res = msgsnd(MAIN_CTX->my_qid.httpc_qid, msg, shmqlen, 0);

    if (res < 0) {
        /* CHECK !!! after 1 sec will auto retry */
        APPLOG(APPLOG_ERR, "{{{DBG}}} %s called, res (%d:fail), will retry {httpc_qid:%d}",
                __func__, res, MAIN_CTX->my_qid.httpc_qid);
		token_info->status = TA_FAILED;
    } else {
        /* start timer */
        APPLOG(APPLOG_ERR, "{{{DBG}}} %s called, res (%d:succ), will wait {httpc_qid:%d}",
                __func__, res, MAIN_CTX->my_qid.httpc_qid);
		token_info->status = TA_TRYING;
		//token_info->last_request_time = time(NULL);
        start_ctx_timer(NF_CTX_TYPE_ACQUIRE_TOKEN, &token_request->access_token_ctx);
    }
}

void nf_token_acquire_handlde_resp_proc(AhifHttpCSMsgType *ahifPkt)
{
	AhifHttpCSMsgHeadType *head = &ahifPkt->head;

	APPLOG(APPLOG_ERR, "{{{DBG}}} %s() receive NRF AccessToken Response (http resp:%d)", __func__, head->respCode);

	token_ctx_list_t *token_request = nf_token_find_ctx_by_seqNo(MAIN_CTX.nrf_access_token.token_accuire_list, head->ahifCid);

	if (token_request == NULL) {
		APPLOG(APPLOG_DEBUG, "{{{DBG}}} %s() something wrong, can't find ctx (seqNo:%s)",
				__func__, head->ahifCid);
		return;
	}

	stop_ctx_timer(NF_CTX_TYPE_ACQUIRE_TOKEN, &token_request->access_token_ctx);

	nf_token_print_log(ahifPkt, "NF ACCESS TOKEN RESPONSE IS ...");

	switch (head->respCode) {
		case 200:
			nf_token_update_shm_process(&MAIN_CTX, token_request, ahifPkt);
			break;

		default:
			nf_token_handle_resp_nok(&MAIN_CTX, token_request);
			break;
	}
}

void nf_token_acquire_token_handle_timeout(main_ctx_t *MAIN_CTX, nrf_ctx_t *timeout_ctx)
{
	token_ctx_list_t *token_request = nf_token_find_ctx_by_seqNo(MAIN_CTX->nrf_access_token.token_accuire_list, timeout_ctx->seqNo);
	if (token_request == NULL) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s called, can't find ctx seqNo(%d)", __func__, timeout_ctx->seqNo);
		return;
	} 

	acc_token_info_t *token_info = get_acc_token_info(MAIN_CTX->nrf_access_token.ACC_TOKEN_LIST, token_request->token_id, 1);
	if (token_info == NULL) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s called, can't find access token info (shm) token_id(%d)", __func__, token_request->token_id);
		return;
	}

	token_info->status = TA_FAILED;

	nf_token_free_ctx(MAIN_CTX, token_request);

	APPLOG(APPLOG_ERR, "{{{DBG}}} %s set access token (id:%d) to \"TA_FAILED\"", __func__,  token_info->token_id);
}

int nf_token_get_scope_by_profile(json_object *nf_profile, char *scope_buff, size_t buff_len)
{
	char key_services[128] = "nfServices";
	json_object *js_services = search_json_object(nf_profile, key_services);

	if (js_services == NULL) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s can't find nfServices in json profile", __func__);
		return (-1);
	}
	int array_length = json_object_array_length(js_services);
	for (int i = 0; i < array_length; i++) {
		json_object *js_elem = json_object_array_get_idx(js_services, i);

		char key_svc_name[128] = "serviceName";
		json_object *js_svc_name = search_json_object(js_elem, key_svc_name);
		if (js_svc_name == NULL) {
			APPLOG(APPLOG_ERR, "{{{DBG}}} %s fail to get serviceName in profile index [%d]", __func__, i);
			continue;
		} else {
			int expect_len = strlen(scope_buff) + strlen(json_object_get_string(js_svc_name)) + 1;
			if (expect_len >= buff_len) {
				APPLOG(APPLOG_ERR, "{{{DBG}}} %s expect len (%d) over buff size (%ld)!", __func__, expect_len, buff_len);
				return (-1);
			}
			sprintf(scope_buff + strlen(scope_buff), "%s%s", 
					json_object_get_string(js_svc_name), i == (array_length-1) ? "" : " ");
		}
	}

	return 0;
}

void nf_token_add_shm_by_nf(acc_token_info_t *token_info, nf_retrieve_item_t *nf_item)
{
	char scope_buff[1024] = {0,};
	if (nf_token_get_scope_by_profile(nf_item->item_nf_profile, scope_buff, sizeof(scope_buff)) < 0) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s can't handle js_profile uuid [%s]", __func__, nf_item->nf_uuid);
	}

	token_info->acc_type = AT_INST;
	sprintf(token_info->nf_instance_id, "%s", nf_item->nf_uuid);
	sprintf(token_info->scope, "%s", scope_buff);
	token_info->status = TA_INIT;
	token_info->operator_added = 0;
}

void nf_token_check_and_acquire_token(main_ctx_t *MAIN_CTX, acc_token_info_t *token_info)
{
	if (token_info->status == TA_TRYING)
		return; // wait more

	// before expire 1 hour ago or every 1 minute, refresh access token
	time_t current = time(NULL);
	if ((token_info->due_date - current) > 600) 
		return;
	if ((current - token_info->last_request_time) <= 60) 
		return;

	token_ctx_list_t *token_request = nf_token_find_ctx_by_id(MAIN_CTX->nrf_access_token.token_accuire_list, token_info->token_id);
	if (token_request != NULL) 
		return; // wait more

	nf_token_acquire_token(MAIN_CTX, token_info);
}

int nf_token_check_expires_in(long double timeval)
{
	time_t expire_time = timeval;
	time_t current_time = time(NULL);

	if (expire_time <= current_time) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s expires_in:%.19s invalid (curr_tm:%.19s)",  
				__func__,  ctime(&expire_time), ctime(&current_time));
		return -1;
	} else {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s expires_in:(%ld:%.19s) valid curr_tm:(%ld:%.19s)",  
				__func__,  expire_time, ctime(&expire_time), current_time, ctime(&current_time));
	}
	return 0;
}

token_ctx_list_t *nf_token_create_ctx(main_ctx_t *MAIN_CTX, acc_token_info_t *token_info)
{
	token_ctx_list_t *token_request = malloc(sizeof(token_ctx_list_t));
	memset(token_request, 0x00, sizeof(token_ctx_list_t));
	token_request->token_id = token_info->token_id;
	MAIN_CTX->nrf_access_token.token_accuire_list = 
		g_slist_append(MAIN_CTX->nrf_access_token.token_accuire_list, token_request);

	return token_request;
}

int nf_token_create_body(main_ctx_t *MAIN_CTX, AhifHttpCSMsgType *ahifPkt, acc_token_info_t *token_info)
{
	char request_body[1024] = {0,};
	char *my_uuid = cfg_get_my_uuid(MAIN_CTX); //free
	char *mp_nf_type = cfg_get_mp_nf_type(MAIN_CTX); // free

	if (token_info->acc_type == AT_SVC) {
		sprintf(request_body, HBODY_ACCESS_TOKEN_REQ_FOR_TYPE,
				my_uuid,
				mp_nf_type,
				token_info->nf_type,
				token_info->scope);
	} else {
		sprintf(request_body, HBODY_ACCESS_TOKEN_REQ_FOR_INSTANCE,
				my_uuid,
				token_info->scope,
				token_info->nf_instance_id);
	}

	encode(request_body, ahifPkt->data, HTTP_EN_XWWW);

	free(my_uuid);
	free(mp_nf_type);

	int bodyLen = strlen(ahifPkt->data);

	return bodyLen;
}

void nf_token_create_pkt(main_ctx_t *MAIN_CTX, AhifHttpCSMsgType *ahifPkt, acc_token_info_t *token_info, token_ctx_list_t *token_request)
{
	AhifHttpCSMsgHeadType *head = &ahifPkt->head;
	head->mtype = MTYPE_NRFM_TOKEN_REQUEST;
	head->ahifCid = token_request->access_token_ctx.seqNo = ++MAIN_CTX->MAIN_SEQNO;

	/* scheme / method / rsrcUri */
	sprintf(head->scheme, "%s", "https"); // WE MUST USE TLS
	sprintf(head->httpMethod, "%s", "POST");

	sprintf(head->rsrcUri, "/nnrf-nfm/v1/oauth2/token");

	/* destType */
	sprintf(head->destType, "%s", "NRF");

	/* vheader */
	head->vheaderCnt = 1;
	ahifPkt->vheader[0].vheader_id = VH_CONTENT_TYPE;
	sprintf(ahifPkt->vheader[0].vheader_body, "%s", "application/x-www-form-urlencoded");

	/* body */
	int bodyLen = nf_token_create_body(MAIN_CTX, ahifPkt, token_info);

	if (bodyLen < 0) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s called, body len is negative!\n", __func__);
		head->bodyLen = 0;
	} else {
		head->bodyLen = bodyLen;
	}
}

void nf_token_del_shm_by_nf(acc_token_info_t *token_info)
{
	memset(token_info, 0x00, sizeof(acc_token_info_t));
}

void nf_token_free_ctx(main_ctx_t *MAIN_CTX, token_ctx_list_t *token_request)
{
	MAIN_CTX->nrf_access_token.token_accuire_list = 
		g_slist_remove(MAIN_CTX->nrf_access_token.token_accuire_list, token_request);
	free(token_request);
}

token_ctx_list_t *nf_token_find_ctx_by_id(GSList *token_accuire_list, int token_id)
{
	int outbound_request_num = g_slist_length(token_accuire_list);
	for (int i = 0; i < outbound_request_num; i++) {
		token_ctx_list_t *token_request = g_slist_nth_data(token_accuire_list, i);
		if (token_request->token_id == token_id)
			return token_request;
	}

	return NULL;
}

token_ctx_list_t *nf_token_find_ctx_by_seqNo(GSList *token_accuire_list, int seqNo)
{
	int outbound_request_num = g_slist_length(token_accuire_list);
	for (int i = 0; i < outbound_request_num; i++) {
		token_ctx_list_t *token_request = g_slist_nth_data(token_accuire_list, i);
		if (token_request->access_token_ctx.seqNo == seqNo)
			return token_request;
	}

	return NULL;
}

void nf_token_get_token_cb(evutil_socket_t fd, short what, void *arg)
{
	for (int i = 0; i < MAX_ACC_TOKEN_NUM; i++) {
		acc_token_info_t *token_info = get_acc_token_info(MAIN_CTX.nrf_access_token.ACC_TOKEN_LIST, i, 1);
		if (token_info == NULL)
			continue;
		if (token_info->occupied != 1)
			continue;

		if (token_info->status < TA_ACQUIRED)
			nf_token_check_and_acquire_token(&MAIN_CTX, token_info);
	}
}

void nf_token_handle_resp_nok(main_ctx_t *MAIN_CTX, token_ctx_list_t *token_request)
{
	acc_token_info_t *token_info = get_acc_token_info(MAIN_CTX->nrf_access_token.ACC_TOKEN_LIST, token_request->token_id, 1);
	if (token_info == NULL) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s can't find access token shm!", __func__);
		return;
	}

	token_info->status = TA_FAILED;

	nf_token_free_ctx(MAIN_CTX, token_request);
}

void nf_token_print_log(AhifHttpCSMsgType *ahifPkt, const char *log_prefix)
{
	json_object *js_resp = json_tokener_parse(ahifPkt->data);

	LOG_JSON_OBJECT(log_prefix, js_resp);

	if (js_resp != NULL)
		json_object_put(js_resp);
}

void nf_token_start_process(main_ctx_t *MAIN_CTX)
{   
    struct timeval tm_token_loop = {1,}; // 1 sec interval

    MAIN_CTX->nrf_access_token.ev_acquire_token = event_new(MAIN_CTX->EVBASE, -1, EV_PERSIST, nf_token_get_token_cb, NULL);
    event_add(MAIN_CTX->nrf_access_token.ev_acquire_token, &tm_token_loop);

    APPLOG(APPLOG_ERR, "%s() will handle shm:token_table every (%d) sec", __func__, 1);
}   

void nf_token_update_shm(acc_token_info_t *token_info, const char *access_token, double due_date)
{
	int pos = (token_info->token_pos + 1) % 2;
	sprintf(token_info->access_token[pos], "%s", access_token);
	token_info->last_request_time = time(NULL);
	token_info->due_date = due_date;

	token_info->token_pos = pos;
	token_info->status = TA_ACQUIRED;
}

void nf_token_update_shm_process(main_ctx_t *MAIN_CTX, token_ctx_list_t *token_request, AhifHttpCSMsgType *ahifPkt)
{
	acc_token_info_t *token_info = get_acc_token_info(MAIN_CTX->nrf_access_token.ACC_TOKEN_LIST, token_request->token_id, 1);
	if (token_info == NULL) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s can't find access token shm!", __func__);
		return;
	}

	// response
	json_object *js_resp = json_tokener_parse(ahifPkt->data);

	// expires_in check
	json_object *js_expires_in = NULL;
	char key_expires_in[128] = "expires_in";

	if ((js_expires_in = search_json_object(js_resp, key_expires_in)) == NULL) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s failed search \"expires_in\"!", __func__);
		goto NTUSP_ERR;
	}

	if (nf_token_check_expires_in(json_object_get_int64(js_expires_in)) < 0) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s \"expires_in\" check invalid!", __func__);
		goto NTUSP_ERR;
	}

	// get token
	json_object *js_access_token = NULL;
	char key_access_token[128] = "access_token";

	if ((js_access_token = search_json_object(js_resp, key_access_token)) == NULL) {
		APPLOG(APPLOG_ERR, "{{{TODO}}} %s failed search \"access_token\"!", __func__);
		goto NTUSP_ERR;
	}

	// set token info
	nf_token_update_shm(token_info, json_object_get_string(js_access_token), json_object_get_int64(js_expires_in));

	nf_token_free_ctx(MAIN_CTX, token_request);

	if (js_resp != NULL)
		json_object_put(js_resp);

	return;

NTUSP_ERR:
	token_info->status = TA_FAILED;
	nf_token_free_ctx(MAIN_CTX, token_request);

	if (js_resp != NULL)
		json_object_put(js_resp);

	return;
}
