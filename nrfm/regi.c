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
	//sprintf(head->scheme, "%s", "https"); // WE MUST USE TLS
	sprintf(head->httpMethod, "%s", "PUT");

	/* path */
	json_object *js_uuid = NULL;
	char path_key[128] = "my_profile/nfInstanceId";

	if ((js_uuid = search_json_object(MAIN_CTX->my_nf_profile, path_key)) == NULL) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s called, cant find \"nfInstanceId\" in my_profile", __func__);
		return;
	}
	sprintf(head->rsrcUri, "/nnrf-nfm/v1/nf-instances/%s", json_object_get_string(js_uuid));

#if 0
    // further selected
	/* destType */
	sprintf(head->destType, "%s", "NRF");
#endif

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

void nf_regi_handle_save_footprint(main_ctx_t *MAIN_CTX, int resp_code)
{
    MAIN_CTX->last_regi_resp_time = time(NULL);
    MAIN_CTX->last_regi_resp_code = resp_code;
}

// TODO!!! CHECK, heartbeat timer, location header
void nf_regi_handle_resp_proc(AhifHttpCSMsgType *ahifPkt)
{
	AhifHttpCSMsgHeadType *head = &ahifPkt->head;

	APPLOG(APPLOG_ERR, "%s() receive NRF Regi Response (resp code:%d, scheme:%s type:%s host:%s ip:%s port:%d)", 
    __func__, head->respCode, head->scheme, head->destType, head->destHost, head->destIp, head->destPort);

	/* STOP TIMER */
	stop_ctx_timer(NF_CTX_TYPE_REGI, &MAIN_CTX.regi_ctx);

    /* save last regi time & status */
    nf_regi_handle_save_footprint(&MAIN_CTX, head->respCode);

	switch (head->respCode) {
		case 200:
		case 201: // SUCCESS
			NRF_STAT_INC(MAIN_CTX.NRF_STAT, head->destHost, NFRegister, NRFS_SUCCESS);

			nf_regi_save_recv_nf_profile(&MAIN_CTX, ahifPkt);

            if (nf_regi_save_recv_heartbeat_timer(&MAIN_CTX) < 0) {
                APPLOG(APPLOG_ERR, "%s() receive invalid heartbeat timer", __func__);
                return nf_regi_retry_after_while();
            }
			if (nf_regi_save_location_header(&MAIN_CTX, ahifPkt) < 0) {
                APPLOG(APPLOG_ERR, "%s() receive invalid location header", __func__);
				return nf_regi_retry_after_while();
            }
			if (nf_regi_check_registered_status(&MAIN_CTX) < 0)  {
                APPLOG(APPLOG_ERR, "%s() receive invalid register status", __func__);
				return nf_regi_retry_after_while();
            }

            /* SAVE REGI SUCCESS NRF-HTTP info, after all proc() use this */
            nf_regi_save_httpc_info(&MAIN_CTX, head);

			/* start heartbeat */
			nf_heartbeat_start_process(&MAIN_CTX);

			/* start init process */
			INITIAL_PROCESS(&MAIN_CTX);

			break;
		default:
			NRF_STAT_INC(MAIN_CTX.NRF_STAT, head->destHost, NFRegister, NRFS_FAIL);

			nf_regi_retry_after_while();
			break;
	}
}

int nf_regi_select_httpc(main_ctx_t *MAIN_CTX, AhifHttpCSMsgHeadType *head)
{
    conn_list_status_t nrf_conn = {0,};
    MAIN_CTX->last_try_nrf_index = select_next_httpc_conn("NRF", NULL, NULL, 0, MAIN_CTX->last_try_nrf_index, &nrf_conn);

    if (MAIN_CTX->last_try_nrf_index < 0) {
        APPLOG(APPLOG_ERR, "{{{DBG}}} %s can't find NRF httpc conn info!", __func__);
        return -1;
    } else {
        APPLOG(APPLOG_ERR, "{{{DBG}}} %s try to NRF (httpc conn index:%d)", __func__, MAIN_CTX->last_try_nrf_index);
        sprintf(head->scheme, nrf_conn.scheme);
        sprintf(head->destType, nrf_conn.type);
        sprintf(head->destHost, nrf_conn.host);
        sprintf(head->destIp, nrf_conn.ip);
        head->destPort = nrf_conn.port;
        return 0;
    }
}

void nf_regi_save_httpc_info(main_ctx_t *MAIN_CTX, AhifHttpCSMsgHeadType *head)
{
    sprintf(MAIN_CTX->nrf_selection_info.scheme, head->scheme);
    sprintf(MAIN_CTX->nrf_selection_info.type, head->destType);
    sprintf(MAIN_CTX->nrf_selection_info.host, head->destHost);
    sprintf(MAIN_CTX->nrf_selection_info.ip, head->destIp);
    MAIN_CTX->nrf_selection_info.port = head->destPort;
}

void nf_regi_restore_httpc_info(main_ctx_t *MAIN_CTX, AhifHttpCSMsgHeadType *head)
{
    sprintf(head->scheme, MAIN_CTX->nrf_selection_info.scheme);
    sprintf(head->destType, MAIN_CTX->nrf_selection_info.type);
    sprintf(head->destHost, MAIN_CTX->nrf_selection_info.host);
#if 0
	// nrf dual
    sprintf(head->destIp, MAIN_CTX->nrf_selection_info.ip);
    head->destPort = MAIN_CTX->nrf_selection_info.port;
#else
	memset(head->destIp, 0x00, sizeof(head->destIp));
	head->destPort = 0;
#endif
}

void nf_regi_init_proc(main_ctx_t *MAIN_CTX)
{
	APPLOG(APPLOG_ERR, "{{{DBG}}} %s called", __func__);

    nf_regi_handle_save_footprint(MAIN_CTX, -1);

	char msgBuff[sizeof(GeneralQMsgType)] = {0,};

	GeneralQMsgType *msg = (GeneralQMsgType *)msgBuff;
	AhifHttpCSMsgType *ahifPkt = (AhifHttpCSMsgType *)msg->body;

	msg->mtype = (long)MSGID_NRFM_HTTPC_REQUEST;

    if (nf_regi_select_httpc(MAIN_CTX, &ahifPkt->head) < 0) 
        return nf_regi_retry_after_while();

    nf_regi_create_pkt(MAIN_CTX, ahifPkt);

	size_t shmqlen = AHIF_APP_MSG_HEAD_LEN + AHIF_VHDR_LEN + ahifPkt->head.queryLen + ahifPkt->head.bodyLen;

	int res = msgsnd(MAIN_CTX->my_qid.httpc_qid, msg, shmqlen, IPC_NOWAIT);

	NRF_STAT_INC(MAIN_CTX->NRF_STAT, ahifPkt->head.destHost, NFRegister, NRFS_ATTEMPT);

	if (res < 0) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s called, res (%d:fail), will retry {httpc_qid:%d}", 
				__func__, res, MAIN_CTX->my_qid.httpc_qid);
		nf_regi_retry_after_while();
	} else {
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

<<<<<<< Updated upstream
	// NRF consider as NF Register
=======
    // NRF consider as NF Register 
>>>>>>> Stashed changes
	for (int i = 0; i < head->vheaderCnt; i++) {
		if (ahifPkt->vheader[i].vheader_id == VH_LOCATION) {
			sprintf(MAIN_CTX->location_uri, "%s", ahifPkt->vheader[i].vheader_body);
			APPLOG(APPLOG_ERR, "{{{DBG}}} %s got location header [%s]", __func__, MAIN_CTX->location_uri);
			return 0;
		}
	}
<<<<<<< Updated upstream
	// else NRF consider as NF Update
	char *my_uuid = cfg_get_my_uuid(MAIN_CTX); //free
	sprintf(MAIN_CTX->location_uri, "/nnrf-nfm/v1/nf-innstances/%s", my_uuid);
	free(my_uuid);
	APPLOG(APPLOG_ERR, "{{{DBG}}} %s set location header myself [%s]", __func__, MAIN_CTX->location_uri);
=======
    // else NRF consider as NF Update
    char *my_uuid = cfg_get_my_uuid(MAIN_CTX); //free
    sprintf(MAIN_CTX->location_uri, "/nnrf-nfm/v1/nf-innstances/%s", my_uuid);
    free(my_uuid);
    APPLOG(APPLOG_ERR, "{{{DBG}}} %s set location header myself [%s]", __func__, MAIN_CTX->location_uri);
>>>>>>> Stashed changes
	return 0;
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

