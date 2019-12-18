#include <nrfm.h>

extern main_ctx_t MAIN_CTX;

void https_save_recv_fep_status(main_ctx_t *MAIN_CTX)
{
	MAIN_CTX->fep_conn_status = 1;
}

/*
 * serviceA -- fep1 | fep2 | fep3 | ...
 * serviceB -- fep1 | fep2 | fep3 | ...
 * ...
 * fep[0], not use
 */
void isif_save_recv_fep_status(service_info_t *fep_svc_info)
{
	if (fep_svc_info->sys_mp_id <= 0 || fep_svc_info->sys_mp_id >= MAX_FEP_NUM) {
		APPLOG(APPLOG_ERR, "%s() receive invalid sys_mp_id (%d)!", fep_svc_info->sys_mp_id);
		return;
	}

	int service_num = g_slist_length(MAIN_CTX.fep_service_list);
	for (int i = 0; i < service_num; i++) {
		fep_service_t *service_elem = g_slist_nth_data(MAIN_CTX.fep_service_list, i);
		if (!strcmp(service_elem->service_name, fep_svc_info->service_name)) {
			memcpy(&service_elem->fep_svc_info[fep_svc_info->sys_mp_id], fep_svc_info, sizeof(service_info_t));
			return;
		}
	}

    APPLOG(APPLOG_ERR, "%s() receive invalid service name(mp_id:%d service_name:%s)", 
            __func__, fep_svc_info->sys_mp_id, fep_svc_info->service_name);
	return;
}

void nf_heartbeat_clear_status(main_ctx_t *MAIN_CTX)
{
	/* clear fep connection status */
	MAIN_CTX->fep_conn_status = 0;

	/* clear fep load & capacity status */
	int service_num = g_slist_length(MAIN_CTX->fep_service_list);
	for (int ii = 0; ii < service_num; ii++) {
		fep_service_t *service_elem = g_slist_nth_data(MAIN_CTX->fep_service_list, ii);
		memset(service_elem->fep_svc_info, 0x00, sizeof(service_info_t) * MAX_FEP_NUM);
	}
}

/*
- it contain escape slash(\) ==> { \"op\" : \"replace\", ...
json_object_array_add(js_heartbeat_body, json_object_new_string(JS_HB_INSTANCE_STATUS));

- it remove escape slash(\) ==> { "op" : "replace", ...
json_object *js_temp = json_tokener_parse(JS_HB_INSTANCE_STATUS);
json_object_array_add(js_heartbeat_body, js_temp);
	- dont release *js_temp via js_object_put(), if parent free, all child auto free
*/
#define JS_HB_INSTANCE_STATUS_REGI "{ \"op\": \"replace\", \"path\": \"/nfStatus\", \"value\": \"REGISTERED\" }"
#define JS_HB_INSTANCE_STATUS_UNDISCOVER "{ \"op\": \"replace\", \"path\": \"/nfStatus\", \"value\": \"UNDISCOVERABLE\" }"
#define JS_HB_SERVICE_STATUS_REGI "{ \"op\": \"replace\", \"path\": \"/nfServiceStatus/%d/nfStatus\", \"value\": \"REGISTERED\" }"
#define JS_HB_SERVICE_STATUS_UNDISCOVER "{ \"op\": \"replace\", \"path\": \"/nfServiceStatus/%d/nfStatus\", \"value\": \"UNDISCOVERABLE\" }"
#define JS_HB_SERVICE_CAPACITY "{ \"op\": \"replace\", \"path\": \"/nfServiceStatus/%d/capacity\", \"value\": %d }"
#define JS_HB_SERVICE_LOAD "{ \"op\": \"replace\", \"path\": \"/nfServiceStatus/%d/load\", \"value\": %d }"
int nf_heartbeat_create_body(main_ctx_t *MAIN_CTX, AhifHttpCSMsgType *ahifPkt)
{
	json_object *js_heartbeat_body = json_object_new_array();

	json_object *js_temp = json_tokener_parse(MAIN_CTX->prefer_undiscover_set ? JS_HB_INSTANCE_STATUS_UNDISCOVER : JS_HB_INSTANCE_STATUS_REGI);
	json_object_array_add(js_heartbeat_body, js_temp);

	int service_num = g_slist_length(MAIN_CTX->fep_service_list);
	APPLOG(APPLOG_ERR, "{{{DBG}}} %s service num is %d fep conn status is %d", __func__, service_num, MAIN_CTX->fep_conn_status);

	for (int ii = 0; ii < service_num; ii++) {
		fep_service_t *service_elem = g_slist_nth_data(MAIN_CTX->fep_service_list, ii);
		int fep_num = 0;
		int capacity = 0;
		int load = 0;

		for (int jj = 0; jj < MAX_FEP_NUM; jj++) {
			service_info_t *svc_info = &service_elem->fep_svc_info[jj];
			if (svc_info->sys_mp_id == 0) continue;
			if (svc_info->proc_alive <= 0) continue;
			if (svc_info->bep_use > 0 && svc_info->bep_conn <= 0) continue;
			fep_num++;
			capacity += svc_info->ovld_tps;
			load += svc_info->curr_load;
		}
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s fep_num=(%d) capacity=(%d) collected", __func__, fep_num, capacity);

		if (capacity >= 65535) capacity = 65535;
		if (fep_num != 0) load = (double)load / (double)fep_num;

		char temp_buff[1024 * 12] = {0,};
		/* service status */
		sprintf(temp_buff, MAIN_CTX->prefer_undiscover_set ? JS_HB_SERVICE_STATUS_UNDISCOVER : JS_HB_SERVICE_STATUS_REGI, ii);
		js_temp = json_tokener_parse(temp_buff);
		json_object_array_add(js_heartbeat_body, js_temp);

		/* service capacity, if fep not connected --> 0 */
		sprintf(temp_buff, JS_HB_SERVICE_CAPACITY, ii, (MAIN_CTX->fep_conn_status == 0) ? 0 : capacity);
		js_temp = json_tokener_parse(temp_buff);
		json_object_array_add(js_heartbeat_body, js_temp);

		/* service load, if fep not connected --> 0 */
		sprintf(temp_buff, JS_HB_SERVICE_LOAD, ii, (MAIN_CTX->fep_conn_status == 0) ? 0 : load);
		js_temp = json_tokener_parse(temp_buff);
		json_object_array_add(js_heartbeat_body, js_temp);

	}

	LOG_JSON_OBJECT("CREATED NF HEARTBEAT BODY IS", js_heartbeat_body);

	int bodyLen = sprintf(ahifPkt->data, "%s", json_object_to_json_string_ext(js_heartbeat_body, JSON_C_PRETTY_NOSLASH));

	json_object_put(js_heartbeat_body);

	return bodyLen;
}

void nf_heartbeat_create_pkt(main_ctx_t *MAIN_CTX, AhifHttpCSMsgType *ahifPkt)
{
	AhifHttpCSMsgHeadType *head = &ahifPkt->head;
	head->mtype = MTYPE_NRFM_HEARTBEAT_REQUEST;
	head->ahifCid = MAIN_CTX->heartbeat_ctx.seqNo = ++MAIN_CTX->MAIN_SEQNO;

	APPLOG(APPLOG_ERR, "{{{DBG}}} %s called, ahifPktCid(%d), heartbeatCtxCid(%d)",
			__func__, head->ahifCid, MAIN_CTX->heartbeat_ctx.seqNo);

    /* scheme / method / rsrcUri */
    sprintf(head->scheme, "%s", "https"); // WE MUST USE TLS
    sprintf(head->httpMethod, "%s", "PATCH");
#if 0
    config_setting_t *setting = config_lookup(&MAIN_CTX->CFG, CF_MY_INSTANCE_ID);
    if (setting == NULL) {
        APPLOG(APPLOG_ERR, "{{{DBG}}} %s called, cant find setting [%s]", __func__, CF_MY_INSTANCE_ID);
        return;
    } else {
        sprintf(head->rsrcUri, "/nnrf-nfm/v1/nf-instances/%s", config_setting_get_string(setting));
    }
#else
	char *my_uuid = cfg_get_my_uuid(MAIN_CTX); //free
	sprintf(head->rsrcUri, "/nnrf-nfm/v1/nf-instances/%s", my_uuid);
	free(my_uuid);
#endif

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
	int bodyLen = nf_heartbeat_create_body(MAIN_CTX, ahifPkt);

	if (bodyLen < 0) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s called, body len is negative!\n", __func__);
		head->bodyLen = 0;
	} else {
		head->bodyLen = bodyLen;
	}
}

// TODO!!! CHECK, heartbeat timer, location header
void nf_heartbeat_handle_resp_proc(AhifHttpCSMsgType *ahifPkt)
{
    AhifHttpCSMsgHeadType *head = &ahifPkt->head;

	APPLOG(APPLOG_ERR, "{{{DBG}}} %s() receive NRF HeartBeat Response (http resp:%d)", __func__, head->respCode);
    
    stop_ctx_timer(NF_CTX_TYPE_HEARTBEAT, &MAIN_CTX.heartbeat_ctx);
            
    switch (head->respCode) {
        case 204: // No Content
			NRF_STAT_INC(MAIN_CTX.NRF_STAT, head->destHost, NFUpdate, NRFS_SUCCESS);
			// TODO
            break;
		case 200: // with nfProfile
			NRF_STAT_INC(MAIN_CTX.NRF_STAT, head->destHost, NFUpdate, NRFS_SUCCESS);

			/* save received nf_profile */
			nf_regi_save_recv_nf_profile(&MAIN_CTX, ahifPkt);

			if (nf_regi_save_recv_heartbeat_timer(&MAIN_CTX) < 0)
				return nf_regi_retry_after_while();
			if (nf_regi_save_location_header(&MAIN_CTX, ahifPkt) < 0)
				return nf_regi_retry_after_while();
			if (nf_regi_check_registered_status(&MAIN_CTX) < 0)
				return nf_regi_retry_after_while();

			nf_heartbeat_start_process(&MAIN_CTX);
            break;
        default:
			NRF_STAT_INC(MAIN_CTX.NRF_STAT, head->destHost, NFUpdate, NRFS_FAIL);
            break;
    }
}

void nf_heartbeat_send_proc(evutil_socket_t fd, short what, void *arg)
{
	APPLOG(APPLOG_ERR, "{{{DBG}}} %s called", __func__);

	char msgBuff[sizeof(GeneralQMsgType)] = {0,};

	GeneralQMsgType *msg = (GeneralQMsgType *)msgBuff;
	AhifHttpCSMsgType *ahifPkt = (AhifHttpCSMsgType *)msg->body;

	msg->mtype = (long)MSGID_NRFM_HTTPC_REQUEST;

	nf_heartbeat_create_pkt(&MAIN_CTX, ahifPkt);

	size_t shmqlen = AHIF_APP_MSG_HEAD_LEN + AHIF_VHDR_LEN + ahifPkt->head.queryLen + ahifPkt->head.bodyLen;

	int res = msgsnd(MAIN_CTX.my_qid.httpc_qid, msg, shmqlen, IPC_NOWAIT);

	NRF_STAT_INC(MAIN_CTX.NRF_STAT, ahifPkt->head.destHost, NFUpdate, NRFS_ATTEMPT);

	nf_heartbeat_clear_status(&MAIN_CTX);

	if (res < 0) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s called, res (%d:fail), will retry {httpc_qid:%d}",
				__func__, res, MAIN_CTX.my_qid.httpc_qid);
	// ANYTHING ?
	} else {
		/* start timer */
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s called, res (%d:succ), will wait {httpc_qid:%d}",
				__func__, res, MAIN_CTX.my_qid.httpc_qid);
		start_ctx_timer(NF_CTX_TYPE_HEARTBEAT, &MAIN_CTX.heartbeat_ctx);
	}

}

void nf_heartbeat_start_process(main_ctx_t *MAIN_CTX)
{
    struct timeval tm_hb_interval = {0,};

	if (MAIN_CTX->heartbeat_ctx.ev_action != NULL) {
		event_del(MAIN_CTX->heartbeat_ctx.ev_action);
		MAIN_CTX->heartbeat_ctx.ev_action = NULL;
		APPLOG(APPLOG_ERR, "%s() remove old heartbeat event!", __func__);
	}

	config_setting_t *setting_hb = config_lookup(&MAIN_CTX->CFG, CF_HEARTBEAT_TIMER);
	tm_hb_interval.tv_sec = config_setting_get_int(setting_hb);

    MAIN_CTX->heartbeat_ctx.ev_action = event_new(MAIN_CTX->EVBASE, -1, EV_PERSIST, nf_heartbeat_send_proc, NULL);
    event_add(MAIN_CTX->heartbeat_ctx.ev_action, &tm_hb_interval);

	APPLOG(APPLOG_ERR, "%s() will send heartbeat every (%d) sec", __func__, tm_hb_interval.tv_sec);
}

void shmq_recv_handle(evutil_socket_t fd, short what, void *arg)
{
	char msgBuff[1024*64];
	IsifMsgType *rxIsifMsg = (IsifMsgType *)msgBuff;

	int ret = 0;

	while ((ret = shmqlib_getMsg(MAIN_CTX.my_qid.isifs_rx_qid, (char *)rxIsifMsg)) > 0) {

		if (ret > sizeof(IsifMsgType)) {
			APPLOG(APPLOG_ERR, "%s() receive unknown size(%d) msg!", __func__, ret);
			continue;
		}

		switch (rxIsifMsg->head.mtype) {
			case MTYPE_NRFC_BROAD_STATUS_TO_LB:
				isif_save_recv_fep_status((service_info_t *)rxIsifMsg->body);
				continue;
			default:
				APPLOG(APPLOG_ERR, "%s() receive unknown type(%d) msg!", __func__, rxIsifMsg->head.mtype);
				continue;
		}
	}
	return;
}
