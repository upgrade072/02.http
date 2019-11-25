#include <nrfm.h>

extern main_ctx_t MAIN_CTX;
extern nrf_stat_t NRF_STAT;

void nf_subscribe_check_time(evutil_socket_t fd, short what, void *arg)
{
	nf_retrieve_info_t *nf_retr_info = (nf_retrieve_info_t *)arg;

	time_t tm_curr = {0,}, tm_expire = {0,};

	tm_curr = time(NULL);
	tm_expire = mktime(&nf_retr_info->tm_validity);

	int remain_time = tm_expire - tm_curr;

	if (remain_time <= 0) {
		/* already disappear */
		APPLOG(APPLOG_ERR, "{{{WARN}}} %s subscr[%s:%s] remain [%d (negative), will recreate subscription",
				__func__, nf_retr_info->nf_type, nf_retr_info->subscription_id, remain_time);

		if (nf_retr_info->subscribe_ctx.ev_action != NULL) {
			//event_del(nf_retr_info->subscribe_ctx.ev_action);
			event_free(nf_retr_info->subscribe_ctx.ev_action);
			nf_retr_info->subscribe_ctx.ev_action = NULL;
		}
		nf_subscribe_nf_type(nf_retr_info, &MAIN_CTX);

	} else if (remain_time <= 60) {

		if (nf_retr_info->subscribe_ctx.timer.ev_timeout != NULL) {
			APPLOG(APPLOG_ERR, "{{{DBG}}} %s subscr[%s:%s] only remain [%d] sec, will try patch - but wait already request",
					__func__, nf_retr_info->nf_type, nf_retr_info->subscription_id, remain_time);
		} else {
			nf_subscribe_patch_subscription(&MAIN_CTX, nf_retr_info);
		}
	}
}
void nf_subscribe_create_pkt(main_ctx_t *MAIN_CTX, AhifHttpCSMsgType *ahifPkt, nf_retrieve_info_t *nf_retr_info)
{
    AhifHttpCSMsgHeadType *head = &ahifPkt->head;
    head->mtype = MTYPE_NRFM_SUBSCRIBE_REQUEST;
    head->ahifCid = nf_retr_info->subscribe_ctx.seqNo = ++MAIN_CTX->MAIN_SEQNO;

    APPLOG(APPLOG_ERR, "{{{DBG}}} %s called, ahifPktCid(%d), retrieveListCtx(%d)",
            __func__, head->ahifCid, nf_retr_info->subscribe_ctx.seqNo);

    /* scheme / method / rsrcUri */
    sprintf(head->scheme, "%s", "https"); // WE MUST USE TLS
    sprintf(head->httpMethod, "%s", "POST");

    sprintf(head->rsrcUri, "/nnrf-nfm/v1/subscriptions");

    /* destType */
    sprintf(head->destType, "%s", "NRF");

    /* vheader */
    head->vheaderCnt = 2;
    ahifPkt->vheader[0].vheader_id = VH_CONTENT_TYPE;
    sprintf(ahifPkt->vheader[0].vheader_body, "%s", "application/json");
    ahifPkt->vheader[1].vheader_id = VH_ACCEPT_ENCODING;;
    sprintf(ahifPkt->vheader[1].vheader_body, "%s", "application/json");

	char key[128] = "subscription_form";
	json_object *js_sub_request = search_json_object(nf_retr_info->js_subscribe_request, key);

    /* body */
	int bodyLen = sprintf(ahifPkt->data, "%s", json_object_to_json_string_ext(js_sub_request, JSON_C_PRETTY_NOSLASH));

	if (bodyLen < 0) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s called, body len is negative!\n", __func__);
		head->bodyLen = 0; 
	} else {
		head->bodyLen = bodyLen;
	}   
}

void nf_subscribe_nf_type(nf_retrieve_info_t *nf_retr_info, main_ctx_t *MAIN_CTX)
{
    APPLOG(APPLOG_ERR, "{{{DBG}}} %s called", __func__);

    char msgBuff[sizeof(GeneralQMsgType)] = {0,};

    GeneralQMsgType *msg = (GeneralQMsgType *)msgBuff;
    AhifHttpCSMsgType *ahifPkt = (AhifHttpCSMsgType *)msg->body;

    msg->mtype = (long)MSGID_NRFM_HTTPC_REQUEST;

    nf_subscribe_create_pkt(MAIN_CTX, ahifPkt, nf_retr_info);

	size_t shmqlen = AHIF_APP_MSG_HEAD_LEN + AHIF_VHDR_LEN + ahifPkt->head.queryLen + ahifPkt->head.bodyLen;

    int res = msgsnd(MAIN_CTX->my_qid.httpc_qid, msg, shmqlen, 0);

	NRF_STAT_INC(&NRF_STAT, NFStatusSubscribe, NRFS_ATTEMPT);

    if (res < 0) {
        APPLOG(APPLOG_ERR, "{{{DBG}}} %s called, res (%d:fail), will retry {httpc_qid:%d}",
                __func__, res, MAIN_CTX->my_qid.httpc_qid);
        /* retry after */
        nf_subscribe_nf_type_retry_while_after(nf_retr_info);
    } else {
        /* start timer */
        APPLOG(APPLOG_ERR, "{{{DBG}}} %s called, res (%d:succ), will wait {httpc_qid:%d}",
                __func__, res, MAIN_CTX->my_qid.httpc_qid);
        start_ctx_timer(NF_CTX_TYPE_SUBSCRIBE, &nf_retr_info->subscribe_ctx);
    }
}

void nf_subscribe_nf_type_print_log(AhifHttpCSMsgType *ahifPkt, const char *log_prefix)
{
	json_object *js_resp = json_tokener_parse(ahifPkt->data);

	LOG_JSON_OBJECT(log_prefix, js_resp);

	if (js_resp != NULL)
		json_object_put(js_resp);
}

void nf_subscribe_nf_type_handle_resp_proc(AhifHttpCSMsgType *ahifPkt)
{
	AhifHttpCSMsgHeadType *head = &ahifPkt->head;

	APPLOG(APPLOG_ERR, "%s() receive NRF Subscribe (POST) Response (http resp:%d)", __func__, head->respCode);

	nf_retrieve_info_t *nf_retr_info = nf_subscribe_search_info_via_seqNo(&MAIN_CTX, head->ahifCid);

	if (nf_retr_info == NULL) {
		APPLOG(APPLOG_DEBUG, "{{{DBG}}} %s() something wrong, can't find ctx (seqNo:%s)",
				__func__, head->ahifCid);
		return;
	}

	stop_ctx_timer(NF_CTX_TYPE_SUBSCRIBE, &nf_retr_info->subscribe_ctx);

	switch (head->respCode) {
		case 201: 
			NRF_STAT_INC(&NRF_STAT, NFStatusSubscribe, NRFS_SUCCESS);
			nf_subscribe_nf_type_print_log(ahifPkt, "NF SUBSCRIBE (for nfType) RESPONSE IS ...");

			if (nf_subscribe_nf_type_recv_subcription_id(nf_retr_info, ahifPkt) < 0) {
				return nf_subscribe_nf_type_retry_while_after(nf_retr_info);
			}
			if (nf_subscribe_nf_type_recv_validity_time(nf_retr_info, ahifPkt) < 0) {
				return nf_subscribe_nf_type_retry_while_after(nf_retr_info);
			}

			/* update subscription before expire */
			nf_subscribe_nf_type_update_process(&MAIN_CTX, nf_retr_info);
			break;
		case 400: // json object fail
		case 500: // NRF have problem
			NRF_STAT_INC(&NRF_STAT, NFStatusSubscribe, NRFS_FAIL);
			nf_subscribe_nf_type_retry_while_after(nf_retr_info);
			break;
		default:
			NRF_STAT_INC(&NRF_STAT, NFStatusSubscribe, NRFS_FAIL);
			nf_subscribe_nf_type_retry_while_after(nf_retr_info);
			break;
	}
}

void nf_subscribe_nf_type_handle_timeout(nrf_ctx_t *nf_ctx)
{
	nf_retrieve_info_t *nf_retr_info = nf_subscribe_search_info_via_seqNo(&MAIN_CTX, nf_ctx->seqNo);

	if (nf_retr_info == NULL) {
		APPLOG(APPLOG_DEBUG, "{{{DBG}}} %s() something wrong, can't find ctx (seqNo:%s)",
				__func__, nf_ctx->seqNo);
		return;
	}

	stop_ctx_timer(NF_CTX_TYPE_SUBSCRIBE, &nf_retr_info->subscribe_ctx);

	nf_subscribe_nf_type_retry_while_after(nf_retr_info);
}

void nf_subscribe_nf_type_recall_cb(evutil_socket_t fd, short what, void *arg)
{
	nf_retrieve_info_t *nf_retr_info = (nf_retrieve_info_t *)arg;
	nf_subscribe_nf_type(nf_retr_info, &MAIN_CTX);
}

int nf_subscribe_nf_type_recv_subcription_id(nf_retrieve_info_t *nf_retr_info, AhifHttpCSMsgType *ahifPkt)
{
	int len = -1;
	json_object *js_resp = json_tokener_parse(ahifPkt->data);
	if (js_resp == NULL) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s() fail to parse resp", __func__);
		goto NSNTRSI_RET;
	}

	char key[128] = "subscriptionId";
	json_object *js_sub_id = search_json_object(js_resp, key);
	if (js_sub_id == NULL) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s() fail to find [subscriptionId] in resp", __func__);
		goto NSNTRSI_RET;
	}

	len = sprintf(nf_retr_info->subscription_id, "%s", json_object_get_string(js_sub_id));

	APPLOG(APPLOG_ERR, "{{{DBG}}} recv subscriptionId [%s]", nf_retr_info->subscription_id);

NSNTRSI_RET:
	if (js_resp != NULL)
		json_object_put(js_resp);

	return len;
}

int nf_subscribe_nf_type_recv_validity_time(nf_retrieve_info_t *nf_retr_info, AhifHttpCSMsgType *ahifPkt)
{
	int res = -1;
	json_object *js_resp = json_tokener_parse(ahifPkt->data);

	if (js_resp == NULL) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s() fail to parse resp", __func__);
		goto NSNTRVT_RET;
	}

	char key[128] = "validityTime";
	json_object *js_val_tm = search_json_object(js_resp, key);
	if (js_val_tm == NULL) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s() fail to find [validityTime] in resp", __func__);
		goto NSNTRVT_RET;
	}

	char recv_time[1024] = {0,};
	sprintf(recv_time, "%s",
			json_object_get_string(js_val_tm));

	APPLOG(APPLOG_ERR, "{{{DBG}}} recv validityTime [%s]", recv_time);

	char time_format[128] = "%FT%TZ";
	strptime(recv_time, time_format, &nf_retr_info->tm_validity);

	// for test */
	char buf[1024] = {0,};
	strftime(buf, sizeof(buf), "%Y %b %d %H:%M", &nf_retr_info->tm_validity);

	APPLOG(APPLOG_ERR, "{{{DBG}}} %s() save validityTime [%s]", __func__, buf);

	// success
	res = 1;

NSNTRVT_RET:
	if (js_resp != NULL)
		json_object_put(js_resp);

	return res;
}

void nf_subscribe_nf_type_retry_while_after(nf_retrieve_info_t *nf_retr_info)
{
	struct timeval timer_sec = {0,};

	config_setting_t *setting = config_lookup(&MAIN_CTX.CFG, CF_NRFM_RETRY_TM);
	APPLOG(APPLOG_ERR, "{{{DBG}}} %s retry after %d sec for type[%s]",
			__func__, config_setting_get_int(setting), nf_retr_info->nf_type);
	timer_sec.tv_sec = config_setting_get_int(setting);
	event_base_once(MAIN_CTX.EVBASE, -1, EV_TIMEOUT, nf_subscribe_nf_type_recall_cb, nf_retr_info, &timer_sec);
}

void nf_subscribe_nf_type_update_process(main_ctx_t *MAIN_CTX, nf_retrieve_info_t *nf_retr_info)
{
	if (nf_retr_info->subscribe_ctx.ev_action) {
		//event_del(nf_retr_info->subscribe_ctx.ev_action);
		event_free(nf_retr_info->subscribe_ctx.ev_action);
		nf_retr_info->subscribe_ctx.ev_action = NULL;
		APPLOG(APPLOG_ERR, "%s() remove old subscribe event!", __func__);
	}   
	struct timeval tic_sec = {1,0};
	nf_retr_info->subscribe_ctx.ev_action = event_new(MAIN_CTX->EVBASE, -1, EV_PERSIST, nf_subscribe_check_time, nf_retr_info);
	event_add(nf_retr_info->subscribe_ctx.ev_action, &tic_sec);

	APPLOG(APPLOG_ERR, "%s() subscr[%s:%s]  will check validity every (%d) sec", 
			__func__, nf_retr_info->nf_type, nf_retr_info->subscription_id, tic_sec.tv_sec);
}

#define JS_SUBSCRIBE_PATCH "{ \"op\":\"replace\", \"path\":\"/validityTime\", \"value\":\"%s\" }"
int nf_subscribe_patch_create_body(AhifHttpCSMsgType *ahifPkt, nf_retrieve_info_t *nf_retr_info)
{
	char time_str[1024] = {0,};
	nf_retr_info->tm_wish_in_patch_req = time(NULL) + (60 * 60 * 12); // 12 hour
	struct tm *cnvt_tm = localtime(&nf_retr_info->tm_wish_in_patch_req);
	strftime(time_str, sizeof(time_str), "%FT%TZ", cnvt_tm);

	char patch_body[1024] = {0,};
	sprintf(patch_body, JS_SUBSCRIBE_PATCH, time_str);

	json_object *js_body = json_tokener_parse(patch_body);

	APPLOG(APPLOG_ERR, "{{{DBG}}} %s called, calc body is [%s] for (%s)", __func__,
			json_object_to_json_string_ext(js_body, JSON_C_PRETTY_NOSLASH),
			nf_retr_info->nf_type);

	int bodyLen = sprintf(ahifPkt->data, "%s", json_object_to_json_string_ext(js_body, JSON_C_PRETTY_NOSLASH));

	json_object_put(js_body);

	return bodyLen;
}

void nf_subscribe_patch_create_pkt(main_ctx_t *MAIN_CTX, AhifHttpCSMsgType *ahifPkt, nf_retrieve_info_t *nf_retr_info)
{
    AhifHttpCSMsgHeadType *head = &ahifPkt->head;
    head->mtype = MTYPE_NRFM_SUBSCR_PATCH_REQUEST;
    head->ahifCid = nf_retr_info->subscribe_ctx.seqNo = ++MAIN_CTX->MAIN_SEQNO;

    APPLOG(APPLOG_ERR, "{{{DBG}}} %s called, ahifPktCid(%d), retrieveItemCtxId(%d)",
            __func__, head->ahifCid, nf_retr_info->subscribe_ctx.seqNo);

    /* scheme / method / rsrcUri */
    sprintf(head->scheme, "%s", "https"); // WE MUST USE TLS
    sprintf(head->httpMethod, "%s", "PATCH");

    sprintf(head->rsrcUri, "/nnrf-nfm/v1/subscriptions/%s", nf_retr_info->subscription_id);

    /* destType */
    sprintf(head->destType, "%s", "NRF");

    /* vheader */
    head->vheaderCnt = 2;
    ahifPkt->vheader[0].vheader_id = VH_CONTENT_TYPE;
    sprintf(ahifPkt->vheader[0].vheader_body, "%s", "application/json");
    ahifPkt->vheader[1].vheader_id = VH_ACCEPT_ENCODING;;
    sprintf(ahifPkt->vheader[1].vheader_body, "%s", "application/json");

    /* body */
	int bodyLen = nf_subscribe_patch_create_body(ahifPkt, nf_retr_info);

	if (bodyLen < 0) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s called, body len is negative!\n", __func__);
		head->bodyLen = 0;
	} else {
		head->bodyLen = bodyLen;
	}
}

void nf_subscribe_patch_handle_resp_proc(AhifHttpCSMsgType *ahifPkt)
{
	AhifHttpCSMsgHeadType *head = &ahifPkt->head;

	APPLOG(APPLOG_ERR, "%s() receive NRF Subscribe (PATCH) Response (http resp:%d)", __func__, head->respCode);

	nf_retrieve_info_t *nf_retr_info = nf_subscribe_search_info_via_seqNo(&MAIN_CTX, head->ahifCid);

	if (nf_retr_info == NULL) {
		APPLOG(APPLOG_DEBUG, "{{{DBG}}} %s() something wrong, can't find ctx (seqNo:%s)",
				__func__, head->ahifCid);
		return;
	}

	stop_ctx_timer(NF_CTX_TYPE_SUBSCR_PATCH, &nf_retr_info->subscribe_ctx);

	switch (head->respCode) {
		case 200: 
			NRF_STAT_INC(&NRF_STAT, NFStatusSubscribePatch, NRFS_SUCCESS);
			nf_subscribe_nf_type_print_log(ahifPkt, "NF SUBSCRIBE (for patch) RESPONSE IS ...");

			/* CAUTION!!! subscription changed with new ID & validity time */
			if (nf_subscribe_nf_type_recv_subcription_id(nf_retr_info, ahifPkt) < 0) {
				return nf_subscribe_nf_type_retry_while_after(nf_retr_info);
			}
			if (nf_subscribe_nf_type_recv_validity_time(nf_retr_info, ahifPkt) < 0) {
				return nf_subscribe_nf_type_retry_while_after(nf_retr_info);
			}
			// TODO!!! TEST this case !!!

			/* CAUTION!!! validity update process already started in nf_subscribe_nf_type_handle_resp_proc() */
			break;
		case 204:  // no contents (validity accepted)
			NRF_STAT_INC(&NRF_STAT, NFStatusSubscribePatch, NRFS_SUCCESS);
			nf_subscribe_patch_modify_validity_with_wish(nf_retr_info);
			break;
		case 400: // json object fail
		case 500: // NRF have problem
			NRF_STAT_INC(&NRF_STAT, NFStatusSubscribePatch, NRFS_FAIL);
			nf_subscribe_patch_wait_after(nf_retr_info);
			break;
		default:
			NRF_STAT_INC(&NRF_STAT, NFStatusSubscribePatch, NRFS_FAIL);
			nf_subscribe_patch_wait_after(nf_retr_info);

			break;
	}
}

void nf_subscribe_patch_modify_validity_with_wish(nf_retrieve_info_t *nf_retr_info)
{
	struct tm *new_validity = localtime(&nf_retr_info->tm_wish_in_patch_req);
	memcpy(&nf_retr_info->tm_validity, new_validity, sizeof(struct tm));

	// for test */
	char buf[1024] = {0,};
	strftime(buf, sizeof(buf), "%Y %b %d %H:%M", &nf_retr_info->tm_validity);

	APPLOG(APPLOG_ERR, "{{{DBG}}} %s() save validityTime [%s]", __func__, buf);
}

void nf_subscribe_patch_subscription(main_ctx_t *MAIN_CTX, nf_retrieve_info_t *nf_retr_info)
{
	APPLOG(APPLOG_ERR, "{{{DBG}}} %s subscr[%s:%s] called",
			__func__, nf_retr_info->nf_type, nf_retr_info->subscription_id);

	char msgBuff[sizeof(GeneralQMsgType)] = {0,};

	GeneralQMsgType *msg = (GeneralQMsgType *)msgBuff;
	AhifHttpCSMsgType *ahifPkt = (AhifHttpCSMsgType *)msg->body;

	msg->mtype = (long)MSGID_NRFM_HTTPC_REQUEST;

	nf_subscribe_patch_create_pkt(MAIN_CTX, ahifPkt, nf_retr_info);

	size_t shmqlen = AHIF_APP_MSG_HEAD_LEN + AHIF_VHDR_LEN + ahifPkt->head.queryLen + ahifPkt->head.bodyLen;

	int res = msgsnd(MAIN_CTX->my_qid.httpc_qid, msg, shmqlen, 0);

	NRF_STAT_INC(&NRF_STAT, NFStatusSubscribePatch, NRFS_ATTEMPT);

    if (res < 0) {
		/* CHECK !!! after 1 sec will auto retry */
        APPLOG(APPLOG_ERR, "{{{DBG}}} %s called, res (%d:fail), will retry {httpc_qid:%d}",
                __func__, res, MAIN_CTX->my_qid.httpc_qid);
    } else {
        /* start timer */
        APPLOG(APPLOG_ERR, "{{{DBG}}} %s called, res (%d:succ), will wait {httpc_qid:%d}",
                __func__, res, MAIN_CTX->my_qid.httpc_qid);
        start_ctx_timer(NF_CTX_TYPE_SUBSCR_PATCH, &nf_retr_info->subscribe_ctx);
    }
}

void nf_subscribe_patch_wait_after(nf_retrieve_info_t *nf_retr_info)
{
	config_setting_t *setting = config_lookup(&MAIN_CTX.CFG, CF_NRFM_RETRY_TM);
	APPLOG(APPLOG_ERR, "{{{DBG}}} %s retry after %d sec for type[%s]",
			__func__, config_setting_get_int(setting), nf_retr_info->nf_type);

	start_ctx_timer(NF_CTX_TYPE_SUBSCR_PATCH, &nf_retr_info->subscribe_ctx);
}

nf_retrieve_info_t *nf_subscribe_search_info_via_seqNo(main_ctx_t *MAIN_CTX, int seqNo)
{           
	int nf_type_num = g_slist_length(MAIN_CTX->nf_retrieve_list);
	for (int ii = 0; ii < nf_type_num; ii++) {

		nf_retrieve_info_t *nf_retr_info = g_slist_nth_data(MAIN_CTX->nf_retrieve_list, ii);
		nrf_ctx_t *nf_ctx = &nf_retr_info->subscribe_ctx;

		if (nf_ctx->seqNo == seqNo) {
			APPLOG(APPLOG_DEBUG, "{{{DBG}}} %s() find from nf_retrieve_info type[%s]", __func__, nf_retr_info->nf_type);
			return nf_retr_info;
		}   
	}

	return NULL;
}    

void nf_subscribe_start_process(main_ctx_t *MAIN_CTX)
{
	g_slist_foreach(MAIN_CTX->nf_retrieve_list, (GFunc)nf_subscribe_nf_type, MAIN_CTX);
}

