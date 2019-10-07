#include <nrfm.h>

extern main_ctx_t MAIN_CTX;

#define ERROR_NRFM_NOTIFICATION "\
{\
  \"title\" : \"your request rejected.\",\
  \"status\" : %d,\
  \"detail\" : \"%s\"\
}"

static char NRFM_NOTI_ERR_MSG_EMPTY[] = "";
static char NRFM_NOTI_ERR_MSG_WRONG[] = "Message format wrong.";
static char NRFM_NOTI_ERR_NO_RIGHT[] = "No authority.";
static char NRFM_NOTI_ERR_SUBSCR_NOT_FOUND[] = "Subscription not found.";
static char NRFM_NOTI_ERR_INTERNAL_ERR[] = "Fail to handle notify.";

// 204 no content (OK)
// 400 query wrong
// 403 no right
// 404 not found (subscription not exist)
// 500 internal error
int nf_notify_handle_check_req(AhifHttpCSMsgType *ahifPkt, char **problemDetail)
{
	AhifHttpCSMsgHeadType *head = &ahifPkt->head;
	json_object *js_recv_noti_req = NULL;
	int respCode = 0;

	/* check request */
	//	- check http/2 method
	if(strcmp(head->httpMethod, "POST")) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s metod not POST!", __func__);
		*problemDetail = NRFM_NOTI_ERR_NO_RIGHT;
		respCode = 403;
		goto NNHCR_RET;
	}
	//	received uri - N/A

	/* check body */
	js_recv_noti_req = json_tokener_parse(ahifPkt->data);
	LOG_JSON_OBJECT("NF NOTIFY REQUEST BODY IS ", js_recv_noti_req);

	//	- check json parsing result
	if (js_recv_noti_req == NULL) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s noti body is null!", __func__);
		*problemDetail = NRFM_NOTI_ERR_MSG_WRONG;
		respCode = 400;
		goto NNHCR_RET;
	}
	//	- check event name
	char key_event[128] = "event";
	json_object *js_event = search_json_object(js_recv_noti_req, key_event);
	if (js_event == NULL) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s event file not exist!", __func__);
		*problemDetail = NRFM_NOTI_ERR_MSG_WRONG;
		respCode = 400;
		goto NNHCR_RET;
	}
	char event_value[1024] = {0,};
	sprintf(event_value, "%s", json_object_get_string(js_event));
	if (strcmp(event_value, "NF_REGISTERED") &&
		strcmp(event_value, "NF_DEREGISTERED") &&
		strcmp(event_value, "NF_PROFILE_CHANGED")) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s event value not right[%s]!", __func__, event_value);
		*problemDetail = NRFM_NOTI_ERR_NO_RIGHT;
		respCode = 403;
		goto NNHCR_RET;
	}

	//	- check nf instance profie exist (by uuid)
	char key_instance_id[128] = "nfInstanceUri";
	json_object *js_uri = search_json_object(js_recv_noti_req, key_instance_id);
	if (js_uri == NULL) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s notification Uri not exist!", __func__);
		*problemDetail = NRFM_NOTI_ERR_SUBSCR_NOT_FOUND;
		respCode = 404;
		goto NNHCR_RET;
	}
	nf_retrieve_item_t temp_nf_item = {0,};
	nf_retrieve_parse_list(js_uri, &temp_nf_item);
	nf_retrieve_item_t *nf_item = nf_notify_search_item_by_uuid(&MAIN_CTX, temp_nf_item.nf_uuid);

	if (strcmp(event_value, "NF_REGISTERED") && nf_item == NULL) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s event value \"NF_DEREGISTERED\"|\"NF_PROFILE_CHANGED\" but nf item not exist!", __func__);
		*problemDetail = NRFM_NOTI_ERR_SUBSCR_NOT_FOUND;
		respCode = 404;
		goto NNHCR_RET;
	}

	//	- check event, nf_profile (new)update or (partial)change
	char key_nf_profile[128] = "nfProfile";
	json_object *js_nf_profile = search_json_object(js_recv_noti_req, key_nf_profile);
	char key_profile_changes[128] = "profileChanges";
	json_object *js_profile_changes = search_json_object(js_recv_noti_req, key_profile_changes);

	if (js_nf_profile != NULL && !strcmp(event_value, "NF_DEREGISTERED")) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s event \"NF_DEREGISTERED\" but request have nf_profile", __func__);
		*problemDetail = NRFM_NOTI_ERR_MSG_WRONG;
		respCode = 400;
		goto NNHCR_RET;
	} 

	if (js_profile_changes != NULL && strcmp(event_value, "NF_PROFILE_CHANGED")) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s event \"NF_PROFILE_CHANGED\" but request didn't have nf_changes", __func__);
		*problemDetail = NRFM_NOTI_ERR_MSG_WRONG;
		respCode = 400;
		goto NNHCR_RET;
	}

	/* replace process */
	int action_res = -1;
	if (!strcmp(event_value, "NF_REGISTERED")) {
		// add new
		action_res = nf_notify_profile_add(nf_item, js_nf_profile);
	} else if (!strcmp(event_value, "NF_DEREGISTERED")) {
		// remove exist
		action_res = nf_notify_profile_remove(nf_item);
	} else if (!strcmp(event_value, "NF_PROFILE_CHANGED")) {
		if (js_nf_profile != NULL) {
			// replace nf profile
			action_res = nf_notify_profile_replace(nf_item, js_nf_profile);
		} else if (js_profile_changes != NULL) {
			// update nf profile
			action_res = nf_notify_profile_modify(nf_item, js_profile_changes);
		}
	}

	if (action_res < 0) {
		*problemDetail = NRFM_NOTI_ERR_INTERNAL_ERR;
		respCode = 500;
		goto NNHCR_RET;
	} else {
		respCode = 204; // OK
	}

NNHCR_RET:
	if (js_recv_noti_req != NULL)
		json_object_put(js_recv_noti_req);

	return respCode;
}

void nf_notify_handle_request_proc(AhifHttpCSMsgType *ahifPkt)
{
	char *problemDetail = NRFM_NOTI_ERR_MSG_EMPTY;
	int respCode = nf_notify_handle_check_req(ahifPkt, &problemDetail);

	/* send response */
	nf_notify_send_resp(ahifPkt, respCode, problemDetail);

	return;
}

int nf_notify_profile_add(nf_retrieve_item_t *nf_older_item, json_object *js_nf_profile)
{
	//nfInstanceId, nfType
	// search nf type 
	char key_nfType[128] = "nfType";
	char key_uuid[128] = "nfInstanceId";
	json_object *js_nfType = search_json_object(js_nf_profile, key_nfType);
	json_object *js_uuid = search_json_object(js_nf_profile, key_uuid);

	if (js_nfType == NULL || js_uuid == NULL) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s can't find field [%s][%s] in nf_profile", __func__, key_nfType, key_uuid);
		return -1;
	}

	nf_retrieve_info_t *nf_retr_info = nf_retrieve_search_info_via_nfType(&MAIN_CTX, json_object_get_string(js_nfType));
	if (nf_retr_info == NULL) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s can't find nfType [%s] in my retrieve_list", __func__, json_object_get_string(js_nfType));
		return -1;
	}

	if (nf_older_item != NULL) {
		nf_retr_info->nf_retrieve_items = g_slist_remove(nf_retr_info->nf_retrieve_items, nf_older_item);
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s remove item addr(%x)", __func__, nf_older_item);

		if (nf_older_item->item_nf_profile) {
			APPLOG(APPLOG_ERR, "{{{DBG}}} %s remove nf_profile addr(%x)", __func__, nf_older_item->item_nf_profile);
			json_object_put(nf_older_item->item_nf_profile);
		}
		if (nf_older_item) {
			APPLOG(APPLOG_ERR, "{{{DBG}}} %s free nf_item addr(%x)", __func__, nf_older_item);
			free(nf_older_item);
		}
	}

	nf_retrieve_item_t *nf_item = malloc(sizeof(nf_retrieve_item_t));
	memset(nf_item, 0x00, sizeof(nf_retrieve_item_t));

	sprintf(nf_item->nf_uuid, "%s", json_object_get_string(js_uuid));

#if 0
	json_object_deep_copy(js_nf_profile, &nf_item->item_nf_profile, NULL);

	if (nf_item->item_nf_profile == NULL) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s fail to create json_nf_profile!", __func__);
		return -1;
	}
#else
	if ((nf_item->item_nf_profile = json_tokener_parse(json_object_get_string(js_nf_profile))) == NULL) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s fail to create json_nf_profile!", __func__);
		return -1;
	}
#endif

	APPLOG(APPLOG_ERR, "{{{DBG}}} %s success to create json_nf_profile! (ptr %x)", __func__, nf_item->item_nf_profile);

	nf_retr_info->nf_retrieve_items = g_slist_append(nf_retr_info->nf_retrieve_items, nf_item);

	APPLOG(APPLOG_ERR, "{{{DBG}}} %s now nf_item addr is (ptr %x)", __func__, nf_retr_info->nf_retrieve_items);

	return 0;
}

/*
{
  "event": "NF_PROFILE_CHANGED",
  "nfInstanceUri": ".../nf-instances/4947a69a-f61b-4bc1-b9da-47c9c5d14b64",
  "profileChanges": [
    {
      "op": "REPLACE",
      "path": "/recoveryTime",
      "newValue": "2018-12-30T23:20:50Z"
    },
    {
      "op": "REPLACE",
      "path": "/nfServices/0/ipEndPoints/0/port",
      "newValue": 8080
    }
}
*/
int nf_notify_profile_modify(nf_retrieve_item_t *nf_item, json_object *js_profile_changes)
{

	for (int i = 0; i < json_object_array_length(js_profile_changes); i++) {
		json_object *js_replace_item = json_object_array_get_idx(js_profile_changes, i);
		if (js_replace_item == NULL) {
			APPLOG(APPLOG_ERR, "{{{DBG}}} %s can't find json (%d)th item in array", __func__, i);
			return -1;
		}
		char key_op[128] = "op";
		json_object *js_op = search_json_object(js_replace_item, key_op);
		char key_path[128] = "path";
		json_object *js_path = search_json_object(js_replace_item, key_path);
		char key_newValue[128] = "newValue";
		json_object *js_newValue = search_json_object(js_replace_item, key_newValue);

		if (js_op == NULL || js_path == NULL || js_newValue == NULL) {
			APPLOG(APPLOG_ERR, "{{{DBG}}} %s \"op\" |  \"path\" | \"newValue\" not exist!", __func__);
			return -1;
		}

		char op_value[1024] = {0,};
		sprintf(op_value, "%s", json_object_get_string(js_op));
		if (strcmp(op_value, "REPLACE")) {
			APPLOG(APPLOG_ERR, "{{{DBG}}} %s \"op\" is not \"REPLACE\"", __func__);
			return -1;
		}

		char path_value[1024] = {0,}; /* /nfServices/0/ipEndPoints/0/port */
		sprintf(path_value, "%s", json_object_get_string(js_path));
		json_object *js_target_path = search_json_object(nf_item->item_nf_profile, path_value);
		if (js_target_path == NULL) {
			APPLOG(APPLOG_ERR, "{{{DBG}}} %s nf_profile not exist [%s]", path_value);
			return -1;
		}

		if (json_object_is_type(js_target_path, json_object_get_type(js_newValue)) == 0) {
			APPLOG(APPLOG_ERR, "{{{DBG}}} %s json type mismatch with", __func__);
			return -1;
		}
	
		if (json_set_val_by_type(js_target_path, js_newValue) < 0) {
			APPLOG(APPLOG_ERR, "{{{DBG}}} %s fail to replace val", __func__);
			return -1;
		}

		LOG_JSON_OBJECT("NF PROFILE CHANGED ...", nf_item->item_nf_profile);
	}

	return 0;
}

int nf_notify_profile_remove(nf_retrieve_item_t *nf_item)
{
	nf_retrieve_info_t *nf_retr_info = nf_notify_search_info_by_uuid(&MAIN_CTX, nf_item->nf_uuid);

	nf_retr_info->nf_retrieve_items = g_slist_remove(nf_retr_info->nf_retrieve_items, nf_item);
	APPLOG(APPLOG_ERR, "{{{DBG}}} %s remove item addr(%x)", __func__, nf_item);

	if (nf_item->item_nf_profile) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s remove nf_profile addr(%x)", __func__, nf_item->item_nf_profile);
		json_object_put(nf_item->item_nf_profile);
	}
	if (nf_item) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s free nf_item addr(%x)", __func__, nf_item);
		free(nf_item);
	}

	return 0;
}

int nf_notify_profile_replace(nf_retrieve_item_t *nf_item, json_object *js_nf_profile)
{
	if (nf_item->retrieve_item_ctx.ev_action) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s event_del() legacy request!", __func__);
		event_del(nf_item->retrieve_item_ctx.ev_action);
	}
	
	if (nf_item->item_nf_profile) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s release older nf profile!", __func__);
		json_object_put(nf_item->item_nf_profile);
		nf_item->item_nf_profile = NULL;
	}

	if ((nf_item->item_nf_profile = json_tokener_parse(json_object_get_string(js_nf_profile))) == NULL) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s can't make json objct!", __func__);
		return (-1);
	} else {
		LOG_JSON_OBJECT("NF NOTIFY REPLACE NF PROFILE", nf_item->item_nf_profile);
		return (0);
	}
}

nf_retrieve_info_t *nf_notify_search_info_by_uuid(main_ctx_t *MAIN_CTX, const char *nf_uuid)
{
	int nf_type_num = g_slist_length(MAIN_CTX->nf_retrieve_list);
	for (int ii = 0; ii < nf_type_num; ii++) {
		nf_retrieve_info_t *nf_retr_info = g_slist_nth_data(MAIN_CTX->nf_retrieve_list, ii);
		int nf_item_num = g_slist_length(nf_retr_info->nf_retrieve_items);
		for (int jj = 0; jj < nf_item_num; jj++) {
			nf_retrieve_item_t *nf_item = g_slist_nth_data(nf_retr_info->nf_retrieve_items, jj);
			if (!strcmp(nf_item->nf_uuid, nf_uuid)) {
				return nf_retr_info;
			}
		}
	}
	return NULL;
}

nf_retrieve_item_t *nf_notify_search_item_by_uuid(main_ctx_t *MAIN_CTX, const char *nf_uuid)
{
	int nf_type_num = g_slist_length(MAIN_CTX->nf_retrieve_list);
	for (int ii = 0; ii < nf_type_num; ii++) {
		nf_retrieve_info_t *nf_retr_info = g_slist_nth_data(MAIN_CTX->nf_retrieve_list, ii);
		int nf_item_num = g_slist_length(nf_retr_info->nf_retrieve_items);
		for (int jj = 0; jj < nf_item_num; jj++) {
			nf_retrieve_item_t *nf_item = g_slist_nth_data(nf_retr_info->nf_retrieve_items, jj);
			if (!strcmp(nf_item->nf_uuid, nf_uuid)) {
				return nf_item;
			}
		}
	}
	return NULL;
}

void nf_notify_send_resp(AhifHttpCSMsgType *ahifPktRecv, int respCode, char *problemDetail)
{
    APPLOG(APPLOG_ERR, "{{{DBG}}} %s called, ahifPktCid(%d)", __func__, ahifPktRecv->head.ahifCid);

    char msgBuff[sizeof(GeneralQMsgType)] = {0,};

    GeneralQMsgType *msg = (GeneralQMsgType *)msgBuff;
    AhifHttpCSMsgType *ahifPkt = (AhifHttpCSMsgType *)msg->body;
	AhifHttpCSMsgHeadType *head = &ahifPkt->head;

	msg->mtype = (long)MSGID_NRFM_HTTPS_RESPONSE;

	memcpy(&ahifPkt->head, &ahifPktRecv->head, sizeof(AhifHttpCSMsgHeadType));

	head->vheaderCnt = 0;
	head->queryLen = 0;
	head->bodyLen = 0;

    head->mtype = MTYPE_NRFM_NOTIFY_RESPONSE;
	head->respCode = respCode;

    /* vheader */
    head->vheaderCnt = 2;
    ahifPkt->vheader[0].vheader_id = VH_CONTENT_TYPE;
    sprintf(ahifPkt->vheader[0].vheader_body, "%s", "application/json");
    ahifPkt->vheader[1].vheader_id = VH_ACCEPT_ENCODING;;
    sprintf(ahifPkt->vheader[1].vheader_body, "%s", "application/json");

	switch(respCode) {
		case 204: // no contents
			break;
		default:
			head->bodyLen = sprintf(ahifPkt->data, ERROR_NRFM_NOTIFICATION, respCode, problemDetail);
			APPLOG(APPLOG_ERR, "{{{TEST}}} AHIF DATA is (%s)", ahifPkt->data);
			break;
	}

	size_t shmqlen = AHIF_APP_MSG_HEAD_LEN + AHIF_VHDR_LEN + ahifPkt->head.queryLen + ahifPkt->head.bodyLen;

	APPLOG(APPLOG_ERR, "{{{DBG}}} %s() head->bodyLen(%d) shmqlen(%ld)", __func__, head->bodyLen, shmqlen);

	int res = msgsnd(MAIN_CTX.my_qid.https_qid, msg, shmqlen, 0);

	if (res < 0) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s called, res (%d:fail), will discard, httpsQid(%d) err(%s)",
				__func__, res, MAIN_CTX.my_qid.https_qid, strerror(errno));
	}
}

