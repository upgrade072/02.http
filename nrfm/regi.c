#include <nrfm.h>

extern main_ctx_t MAIN_CTX;

int nf_regi_check_registered_status(main_ctx_t *MAIN_CTX)
{
	json_object *js_nf_status = NULL;
	char key[128] = "nfStatus";

	if ((js_nf_status = search_json_object(MAIN_CTX->received_nf_profile, key)) == NULL) {
		APPLOG(APPLOG_ERR, "{{{TODO}}} %s %d fail check!", __func__, __LINE__);
		return -1;
	}

	if (strcmp(json_object_get_string(js_nf_status), "REGISTERED")) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s check nfStatus fail! [%s]", __func__, json_object_get_string(js_nf_status));
		return -1;
	}

	APPLOG(APPLOG_ERR, "{{{DBG}}} %s check nfStatus success [%s]", __func__, json_object_get_string(js_nf_status));

	return 0;
}

void nf_regi_create_pkt(main_ctx_t *MAIN_CTX, AhifHttpCSMsgType *ahifPkt)
{
	AhifHttpCSMsgHeadType *head = &ahifPkt->head;
	head->mtype = MTYPE_NRFM_REGI_REQUEST;
	head->ahifCid = MAIN_CTX->regi_ctx.seqNo = ++MAIN_CTX->MAIN_SEQNO;

	APPLOG(APPLOG_ERR, "{{{DBG}}} %s called, ahifPktCid(%d), regiCtxCid(%d)",
			__func__, head->ahifCid, MAIN_CTX->regi_ctx.seqNo);

	/* scheme / method / rsrcUri */
	sprintf(head->scheme, "%s", "https"); // WE MUST USE TLS
	sprintf(head->httpMethod, "%s", "PUT");

	/* path */
	json_object *js_uuid = NULL;
	char path_key[128] = "my_profile/nfInstanceId";

	if ((js_uuid = search_json_object(MAIN_CTX->my_nf_profile, path_key)) == NULL) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s called, cant find \"nfInstanceId\" in my_profile", __func__);
		return;
	}
	sprintf(head->rsrcUri, "/nnrf-nfm/v1/nf-instances/%s", json_object_get_string(js_uuid));

	/* destType */
	sprintf(head->destType, "%s", "NRF");

	/* vheader */
	head->vheaderCnt = 2;
	ahifPkt->vheader[0].vheader_id = VH_CONTENT_TYPE;
	sprintf(ahifPkt->vheader[0].vheader_body, "%s", "application/json");
	ahifPkt->vheader[1].vheader_id = VH_ACCEPT_ENCODING;;
	sprintf(ahifPkt->vheader[1].vheader_body, "%s", "application/json");

	/* body */
	json_object *js_body = NULL;
	char body_key[128] = "my_profile";
	if ((js_body = search_json_object(MAIN_CTX->my_nf_profile, body_key)) == NULL) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s called, cant find \"nfInstanceId\" in my_profile", __func__);
		return;
	}

	int body_len = sprintf(ahifPkt->data, "%s", json_object_to_json_string_ext(js_body, JSON_C_PRETTY_NOSLASH));
	if (body_len < 0) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s called, body len is negative!\n", __func__);
		head->bodyLen = 0;
	} else {
		head->bodyLen = body_len;
	}
}

// TODO!!! CHECK, heartbeat timer, location header
void nf_regi_handle_resp_proc(AhifHttpCSMsgType *ahifPkt)
{
	AhifHttpCSMsgHeadType *head = &ahifPkt->head;

	APPLOG(APPLOG_ERR, "%s() receive NRF Regi Response (http resp:%d)", __func__, head->respCode);

	/* STOP TIMER */
	stop_ctx_timer(NF_CTX_TYPE_REGI, &MAIN_CTX.regi_ctx);

	switch (head->respCode) {
		case 201: // SUCCESS
			nf_regi_save_recv_nf_profile(&MAIN_CTX, ahifPkt);

			if (nf_regi_save_recv_heartbeat_timer(&MAIN_CTX) < 0)
				return nf_regi_retry_after_while();
			if (nf_regi_save_location_header(&MAIN_CTX, ahifPkt) < 0)
				return nf_regi_retry_after_while();
			if (nf_regi_check_registered_status(&MAIN_CTX) < 0) 
				return nf_regi_retry_after_while();

			/* retrieve process */
			nf_retrieve_start_process(&MAIN_CTX);

			/* subscribe process */
			nf_subscribe_start_process(&MAIN_CTX);

			/* start heartbeat */
			nf_heartbeat_start_process(&MAIN_CTX);

			break;
		default:
			nf_regi_retry_after_while();
			break;
	}
}

void nf_regi_init_proc(main_ctx_t *MAIN_CTX)
{
	APPLOG(APPLOG_ERR, "{{{DBG}}} %s called", __func__);

	char msgBuff[sizeof(GeneralQMsgType)] = {0,};

	GeneralQMsgType *msg = (GeneralQMsgType *)msgBuff;
	AhifHttpCSMsgType *ahifPkt = (AhifHttpCSMsgType *)msg->body;

	msg->mtype = (long)MSGID_NRFM_HTTPC_REQUEST;

	nf_regi_create_pkt(MAIN_CTX, ahifPkt);

	size_t shmqlen = AHIF_APP_MSG_HEAD_LEN + AHIF_VHDR_LEN + ahifPkt->head.queryLen + ahifPkt->head.bodyLen;

	int res = msgsnd(MAIN_CTX->my_qid.httpc_qid, msg, shmqlen, 0);
	if (res < 0) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s called, res (%d:fail), will retry {httpc_qid:%d}", 
				__func__, res, MAIN_CTX->my_qid.httpc_qid);
		/* retry after */
		nf_regi_retry_after_while();
	} else {
		/* start timer */
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s called, res (%d:succ), will wait {httpc_qid:%d}", 
				__func__, res, MAIN_CTX->my_qid.httpc_qid);
		start_ctx_timer(NF_CTX_TYPE_REGI, &MAIN_CTX->regi_ctx);
	}

}

void nf_regi_recall_cb(evutil_socket_t fd, short what, void *arg)
{
	nf_regi_init_proc(&MAIN_CTX);
}

void nf_regi_retry_after_while()
{
	struct timeval timer_sec = {0,};

	config_setting_t *setting = config_lookup(&MAIN_CTX.CFG, CF_NRFM_RETRY_TM);
	APPLOG(APPLOG_ERR, "{{{DBG}}} %s retry after %d sec", __func__, config_setting_get_int(setting));
	timer_sec.tv_sec = config_setting_get_int(setting);
	event_base_once(MAIN_CTX.EVBASE, -1, EV_TIMEOUT, nf_regi_recall_cb, NULL, &timer_sec);
}

// TODO!!! HOW TO DO if location header not exist
int nf_regi_save_location_header(main_ctx_t *MAIN_CTX, AhifHttpCSMsgType *ahifPkt)
{
	AhifHttpCSMsgHeadType *head = &ahifPkt->head;

	for (int i = 0; i < head->vheaderCnt; i++) {
		if (ahifPkt->vheader[i].vheader_id == VH_LOCATION) {
			sprintf(MAIN_CTX->location_uri, "%s", ahifPkt->vheader[i].vheader_body);
			APPLOG(APPLOG_ERR, "{{{DBG}}} %s got location header [%s]", __func__, MAIN_CTX->location_uri);
			return 0;
		}
	}
	return -1;
}

int nf_regi_save_recv_heartbeat_timer(main_ctx_t *MAIN_CTX)
{
	json_object *js_hb_timer = NULL;
	char key[128] = "heartBeatTimer";

	if ((js_hb_timer = search_json_object(MAIN_CTX->received_nf_profile, key)) == NULL) {
		APPLOG(APPLOG_ERR, "{{{TODO}}} %s %d fail check!", __func__, __LINE__);
		return -1;
	}

	config_setting_t *setting_hb = config_lookup(&MAIN_CTX->CFG, CF_HEARTBEAT_TIMER);
	config_setting_set_int(setting_hb, json_object_get_int(js_hb_timer));
	APPLOG(APPLOG_ERR, "{{{DBG}}} %s got heartbeat timer [%d sec]", __func__, config_setting_get_int(setting_hb));

	return 0;
}

void nf_regi_save_recv_nf_profile(main_ctx_t *MAIN_CTX, AhifHttpCSMsgType *ahifPkt)
{
	if (MAIN_CTX->received_nf_profile != NULL) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s release older nf_profile (from NRF)", __func__);
		json_object_put(MAIN_CTX->received_nf_profile);
	} 
	MAIN_CTX->received_nf_profile = json_tokener_parse(ahifPkt->data);

	LOG_JSON_OBJECT("NRF RECEIVED NF PROFILE IS", MAIN_CTX->received_nf_profile);
}

