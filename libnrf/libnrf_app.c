#include <libnrf_app.h>

// handle_req : LB HTTPC 요청할 connection 정보 (자동 broadcasting)
// NRFC_QID : NRFC 메시지 큐 ID
int http2_appl_api_to_httpc(http_conn_handle_req_t *handle_req, int NRFC_QID)
{
	int result = 0;

	if (NRFC_QID < 0 || 
			(handle_req->command != HTTP_MML_HTTPC_ADD && handle_req->command != HTTP_MML_HTTPC_DEL)) 
		goto HAATC_RET_NEG;

	if ((strcmp(handle_req->scheme, "https") && strcmp(handle_req->scheme, "http")) ||
			strlen(handle_req->type) == 0 || strlen(handle_req->host) == 0 || strlen(handle_req->ip) == 0 ||
			(handle_req->port <= 0 || handle_req->port > 65535)) 
		goto HAATC_RET_NEG;

	// ok we send
	handle_req->mtype = MSGID_NRF_LIB_NRFC_REQ_CALLBACK;
	handle_req->cnt = 2;
	
	// to NRFC
	if ((result = msgsnd(NRFC_QID, handle_req, sizeof(http_conn_handle_req_t) - sizeof(long), IPC_NOWAIT)) < 0)
		goto HAATC_RET_NEG;

	return (1);

HAATC_RET_NEG:
	APPLOG(APPLOG_ERR, "(%s) can't handle req (nrfc_qid:%d, cmd:%d) (%s:%s:%s:%s:%d) (msgsnd_res:%d)", 
			__func__, NRFC_QID, handle_req->command,
			handle_req->scheme, handle_req->type, handle_req->host, handle_req->ip, handle_req->port, result);
	return (-1);
}

// search_info : routing info (매칭 조건 아닐 시 NULL 세팅할 것)
// DISC_TABLE : discover 결과 저장 테이블, 멀티 쓰레드/프로세스 경우 각각의 테이블 로컬 생성 사용할것 
// NFS_TABLE : connection 통합 테이블 
// NF_DISC_RESULT : NF Discover 결과 있다면 포인터 전달, 없다면 NULL 전달 
// NRFC_QID : NRFC 메시지 큐 ID
nf_service_info *nf_discover_search(nf_discover_key *search_info, nf_discover_table *DISC_TABLE, nfs_avail_shm_t *NFS_TABLE, char *NF_DISC_RESULT, int NRFC_QID)
{
    if (NF_DISC_RESULT != NULL) {
        int res = nf_discover_table_handle(DISC_TABLE, NF_DISC_RESULT);
        APPLOG(APPLOG_DEBUG, "(%s) update NFs(%d) raw in DISC_TABLE(%p)", __func__, res, DISC_TABLE);
    }

    return nf_discover_search_cache(search_info, DISC_TABLE, NFS_TABLE, NRFC_QID);
}

nf_service_info *nf_discover_search_cache(nf_discover_key *search_info, nf_discover_table *DISC_TABLE, nfs_avail_shm_t *NFS_TABLE, int NRFC_QID)
{
	switch (search_info->nfType) {
		case NF_TYPE_UDM:
			return nf_discover_search_udm(search_info, DISC_TABLE, NFS_TABLE, NRFC_QID);
		case NF_TYPE_AMF:
			return nf_discover_search_amf(search_info, DISC_TABLE, NFS_TABLE, NRFC_QID);
		default:
			APPLOG(APPLOG_ERR, "(%s) recv unknown nfType(%d)", __func__, search_info->nfType);
			return NULL;
	}
}

nf_service_info *nf_discover_search_udm(nf_discover_key *search_info, nf_discover_table *DISC_TABLE, nfs_avail_shm_t *NFS_TABLE, int NRFC_QID)
{
	switch (search_info->nfSearchType) {
		case NF_DISC_ST_SUPI:
			return nf_discover_search_udm_supi(search_info, DISC_TABLE, NFS_TABLE, NRFC_QID);
		case NF_DISC_ST_SUCI: 
			return nf_discover_search_udm_suci(search_info, DISC_TABLE, NFS_TABLE, NRFC_QID);
		default:
			APPLOG(APPLOG_ERR, "(%s) recv unknown searchType(%d)", __func__, search_info->nfSearchType);
			return NULL;
	}
}

nf_service_info *nf_discover_search_amf(nf_discover_key *search_info, nf_discover_table *DISC_TABLE, nfs_avail_shm_t *NFS_TABLE, int NRFC_QID)
{
	nf_discover_local_res result_cache = {0,};

	const char *default_svc_name = "namf-loc";
	if (search_info->serviceName == NULL)
		search_info->serviceName = default_svc_name;

	for (int i = 0; i < MAX_NF_CACHE_NUM; i++) {
		nf_discover_raw *disc_raw = &DISC_TABLE->disc_cache[i];

		if (nf_discover_check_cache_raw(disc_raw, search_info) < 0) /* default info matched */
			continue;

		nf_amf_info *amfInfo = &disc_raw->nfTypeInfo.amfInfo;

        // check regionId & amfSetId, if key exist
        if (search_info->region_id != NULL && strcmp(search_info->region_id, amfInfo->amfRegionId))
            continue;
        if (search_info->amf_set_id != NULL && strcmp(search_info->amf_set_id, amfInfo->amfSetId))
            continue;

#if 0
        if (search_info->plmnId_in_guami != NULL && search_info->amfId_in_guami) {
#else
        if (search_info->amfId_in_guami != NULL) {
#endif
            for (int k = 0; k < amfInfo->guamiListNum; k++) {
                nf_guami_info *nf_guami = &amfInfo->nf_guami[k];
#if 0
                if (!strcmp(search_info->plmnId_in_guami, nf_guami->plmnId) &&
                        !strcmp(search_info->amfId_in_guami, nf_guami->amfId))  {
#else
                if (!strcmp(search_info->amfId_in_guami, nf_guami->amfId)) {
#endif
                    nf_discover_order_local_res(disc_raw, &result_cache, search_info->selectionType);
                }
            }
        }
	}

	/* check result */
	nf_discover_res_log(&result_cache, search_info->selectionType);

	/* find host name from SHM & return */
	return nf_discover_result(&result_cache, search_info, DISC_TABLE, NFS_TABLE, NRFC_QID);
}

nf_service_info *nf_discover_search_udm_supi(nf_discover_key *search_info, nf_discover_table *DISC_TABLE, nfs_avail_shm_t *NFS_TABLE, int NRFC_QID)
{
	nf_discover_local_res result_cache = {0,};
	char imsi[128] = {0,};

	/* handle error check only library applicable */
	if ((search_info->supi == NULL) || (sscanf(search_info->supi, "imsi-%127s", imsi) != 1)) {
		APPLOG(APPLOG_ERR, "(%s) recv unknown supi(%s)", 
				__func__, search_info->supi == NULL ? "null" : search_info->supi);
		return NULL;
	}

	const char *default_svc_name = "nudm-ueauth";
	if (search_info->serviceName == NULL)
		search_info->serviceName = default_svc_name;

	for (int i = 0; i < MAX_NF_CACHE_NUM; i++) {
		nf_discover_raw *disc_raw = &DISC_TABLE->disc_cache[i];

		if (nf_discover_check_cache_raw(disc_raw, search_info) < 0) /* default info matched */
			continue;

		nf_udm_info *udmInfo = &disc_raw->nfTypeInfo.udmInfo;

		if (udmInfo->supiRangesNum <= 0) 
			continue;

		for (int k = 0; k < udmInfo->supiRangesNum && k < NF_MAX_SUPI_RANGES; k++) {
			nf_comm_supi_range *supiRange = &udmInfo->supiRanges[k];
			if (strncmp(imsi, supiRange->start, strlen(supiRange->start)) >= 0 && 
					strncmp(imsi, supiRange->end, strlen(supiRange->end)) <= 0) {
				nf_discover_order_local_res(disc_raw, &result_cache, search_info->selectionType);
			}
		}
	}

	/* check result */
	nf_discover_res_log(&result_cache, search_info->selectionType);

	/* find host name from SHM & return */
	return nf_discover_result(&result_cache, search_info, DISC_TABLE, NFS_TABLE, NRFC_QID);
}

nf_service_info *nf_discover_search_udm_suci(nf_discover_key *search_info, nf_discover_table *DISC_TABLE, nfs_avail_shm_t *NFS_TABLE, int NRFC_QID)
{
	nf_discover_local_res result_cache = {0,};

	/* handle error check only library applicable */
	if (search_info->routing_indicators == NULL) {
		APPLOG(APPLOG_ERR, "(%s) can't handle null routingIndicators", __func__);
		return NULL;
	}

	const char *default_svc_name = "nudm-ueauth";
	if (search_info->serviceName == NULL)
		search_info->serviceName = default_svc_name;

	for (int i = 0; i < MAX_NF_CACHE_NUM; i++) {
		nf_discover_raw *disc_raw = &DISC_TABLE->disc_cache[i];

		if (nf_discover_check_cache_raw(disc_raw, search_info) < 0) { /* default info matched */
			//APPLOG(APPLOG_DEBUG, "(%s) -> nf_discover_check_cache_raw fail", __func__);
			continue;
		}

		nf_udm_info *udmInfo = &disc_raw->nfTypeInfo.udmInfo;

		if (udmInfo->routingIndicatorsNum <= 0) {
			//APPLOG(APPLOG_DEBUG, "(%s) -> udmInfo->routingIndicatorsNum <= 0", __func__);
			continue;
		}

		for (int k = 0; k < udmInfo->routingIndicatorsNum && k < NF_MAX_RI; k++) {
			char *routingIndicators = udmInfo->routingIndicators[k];
			if (!strncmp(search_info->routing_indicators, routingIndicators, strlen(search_info->routing_indicators))) {
				nf_discover_order_local_res(disc_raw, &result_cache, search_info->selectionType);
			}
		}
	}

	/* check result */
	nf_discover_res_log(&result_cache, search_info->selectionType);

	/* find host name from SHM & return */
	return nf_discover_result(&result_cache, search_info, DISC_TABLE, NFS_TABLE, NRFC_QID);
}

nf_service_info *nf_discover_result(nf_discover_local_res *result_cache, nf_discover_key *search_info, nf_discover_table *DISC_TABLE, nfs_avail_shm_t *NFS_TABLE, int NRFC_QID)
{
	nf_list_shm_t *nfs_avail_shm = &NFS_TABLE->nfs_avail_shm[NFS_TABLE->curr_pos];

	for (int i = 0; i < result_cache->res_num && i < MAX_NF_CACHE_RES; i++) {

		nf_discover_res_info *res_info = &result_cache->nf_disc_res[i];
	 	if (res_info->occupied == 0 || res_info->disc_raw_index < 0 || res_info->disc_raw_index >= MAX_NF_CACHE_NUM) {
			APPLOG(APPLOG_ERR, "(%s) somthing wrong res_info invalid", __func__);
			continue;
		}

		/* key */
		nf_discover_raw *discover_info = &DISC_TABLE->disc_cache[res_info->disc_raw_index];

		if (search_info->lbNum <= 0)
			APPLOG(APPLOG_ERR, "{{{DBG}}} (%s) something wrong, input lbnum=(0)", __func__);

		for (int k = 0; k < search_info->lbNum && k < NF_MAX_LB_NUM; k++) {
			int lbIndex = (search_info->start_lbId + k) % search_info->lbNum;
			int availCount = nfs_avail_shm->nf_avail_cnt[lbIndex];
			int http2_conn_exist_in_lb = 0;

			for (int nfsIndex = 0; nfsIndex < availCount && nfsIndex < NF_MAX_AVAIL_LIST; nfsIndex++) {
				nf_service_info *nf_service = &nfs_avail_shm->nf_avail[lbIndex][nfsIndex];

				if (nf_service->occupied <= 0)
					continue;
				if (!strcmp(discover_info->hostname, nf_service->hostname) &&
                    !strcmp(discover_info->serviceName, nf_service->serviceName)) {
                    http2_conn_exist_in_lb = 1;
                    if (nf_service->available) {
                        discover_info->sel_count++;
                        APPLOG(APPLOG_DEBUG, "(%s) select (%s) in lb_idx[%d]", 
                                __func__, nf_service->hostname, lbIndex);
                        return nf_service;
                    }
				}
			}
			if (http2_conn_exist_in_lb == 0) {
				/* if not exist create node */
				nf_disc_host_info *hostInfo = nf_discover_search_node_by_hostname(&DISC_TABLE->root_node, discover_info->hostname);

				if (hostInfo != NULL && hostInfo->requested == 0 && NRFC_QID > 0) {
                    hostInfo->lbIndex = lbIndex;
					hostInfo->requested = 1;
					if (msgsnd(NRFC_QID, hostInfo, NF_DISC_HOSTINFO_LEN(hostInfo), IPC_NOWAIT) < 0) {
						APPLOG(APPLOG_ERR, "(%s) fail to send nfProfile[%s/%s] to NRFC",
								__func__, discover_info->serviceName, discover_info->hostname);
					}
				}
			}
		}
	}

	APPLOG(APPLOG_ERR, "(%s) cant find any hostname in SHM!!", __func__);
	return NULL;
}

void nf_discover_order_local_res(nf_discover_raw *disc_raw, nf_discover_local_res *result_cache, int selectionType)
{
	nf_discover_res_info request_info = {0,};
	request_info.occupied = 1;
	request_info.disc_raw_index = disc_raw->index;
	request_info.disc_raw_vector = (selectionType == NF_DISC_SE_LOW ? disc_raw->sel_count : disc_raw->priority);

	nf_discover_res_info temp_info = {0,};

	for (int i = 0; i < MAX_NF_CACHE_RES; i++) {
		nf_discover_res_info *curr_info = &result_cache->nf_disc_res[i];
		
		if (curr_info->occupied == 0) {
			/* last */
			memcpy(curr_info, temp_info.occupied == 1 ? &temp_info : &request_info, sizeof(nf_discover_res_info));
			result_cache->res_num++;
			return;
		} else if (request_info.disc_raw_vector < curr_info->disc_raw_vector) {
			/* swap (sorry for poor algorithm) */
			memcpy(&temp_info, curr_info, sizeof(nf_discover_res_info));
			memcpy(curr_info, &request_info, sizeof(nf_discover_res_info));
			memcpy(&request_info, &temp_info, sizeof(nf_discover_res_info));
		}
	}
}

void nf_discover_res_log(nf_discover_local_res *result_cache, int selectionType)
{
	char temp_buff[2048] = {0,};

	for (int i = 0; i < result_cache->res_num; i++) {
		nf_discover_res_info *curr_info = &result_cache->nf_disc_res[i];
		if (curr_info->occupied) {
			sprintf(temp_buff + strlen(temp_buff), "%d-(cache_index:%d)-(sel_count:%d) ",
					i, curr_info->disc_raw_index, curr_info->disc_raw_vector);
		}
	}

	APPLOG(APPLOG_DEBUG, "(%s) (%s) %s", __func__, selectionType == NF_DISC_SE_LOW ? "lowest send" : " priority", temp_buff);
}

int nf_discover_check_cache_raw(nf_discover_raw *disc_raw, nf_discover_key *search_info)
{
	/* check occupied */
	if (disc_raw->occupied == 0)
		return -1;

	/* check nfType */
	if (disc_raw->nfType != search_info->nfType) {
		APPLOG(APPLOG_DEBUG, "(%s) nfType mismatch (%d:%d)", __func__, search_info->nfType, disc_raw->nfType);
		return -1;
	}

	/* check serviceName if exist */
	if (search_info->serviceName != NULL 
			&& strncasecmp(disc_raw->serviceName, search_info->serviceName, strlen(search_info->serviceName))) {
		APPLOG(APPLOG_DEBUG, "(%s) serviceName mismatch (%s:%s)", __func__, search_info->serviceName, disc_raw->serviceName);
		return -1;
	}

	/* check mcc mnc if exist */
	if ((search_info->mcc != NULL && search_info->mnc != NULL) 
			&& disc_raw->allowdPlmnsNum) {
		APPLOG(APPLOG_DEBUG, "(%s) mcc mnc not null (%s:%s) disc_raw plmnNum(%d)",
			   	__func__, search_info->mcc, search_info->mnc, disc_raw->allowdPlmnsNum);
		int matched = 0;

		for (int i = 0; i < disc_raw->allowdPlmnsNum; i++) {
			nf_comm_plmn *disc_plmn = &disc_raw->allowdPlmns[i];

			if (!strcmp(search_info->mcc, disc_plmn->mcc) && !strcmp(search_info->mnc, disc_plmn->mnc)) {
				APPLOG(APPLOG_DEBUG, "(%s) mcc mnc find-match in index(%d)", __func__, i);
				matched = 1;
				break;
			}
		}
		if (matched == 0)
			return -1;
	}

	return 0;
}

int nf_discover_table_handle(nf_discover_table *DISC_TABLE, char *json_string)
{
	int res = 0; // return updated nf profile number

	json_object *js_resp = json_tokener_parse(json_string);
	if (js_resp == NULL) {
		APPLOG(APPLOG_ERR, "(%s) fail to parse json_string", __func__);
		return res;
	}

	/* get validity */
	char key_validity[128] = "validityPeriod";
	json_object *js_validity = search_json_object(js_resp, key_validity);
	if (js_validity == NULL) {
		APPLOG(APPLOG_ERR, "(%s) fail to search \"validityPeriod\"", __func__);
		goto NDTU_FAIL;
	}
	int remain_time = json_object_get_int(js_validity);
	time_t validity_time = time(NULL) + remain_time;
	APPLOG(APPLOG_DEBUG, "(%s) get valid period [%.24s]", __func__, ctime(&validity_time));

	/* get nf profiles - array */
	char key_nfInstances[128] = "nfInstances";
	json_object *js_profile_array = search_json_object(js_resp, key_nfInstances);
	if (js_profile_array == NULL) {
		APPLOG(APPLOG_ERR, "(%s) fail to search \"nfInstances\"", __func__);
		goto NDTU_FAIL;
	}

	/* check nf profiles - array - length */
	int array_length = json_object_array_length(js_profile_array);
	if (array_length <= 0) {
		APPLOG(APPLOG_ERR, "(%s) nfInstances Num wrong(%d)", __func__, array_length);
		goto NDTU_FAIL;
	} else {
		APPLOG(APPLOG_DEBUG, "(%s) nfInstances have (%d) item", __func__, array_length);
	}

	/* update nf discover table */
	for (int i = 0; i < array_length; i++) {
		json_object *js_elem = json_object_array_get_idx(js_profile_array, i);
		if (nf_discover_table_update(DISC_TABLE, js_elem, &validity_time) > 0) res ++;
	}

NDTU_FAIL:
	if (js_resp != NULL)
		json_object_put(js_resp);

	return res;
}

void nf_discover_update_nf_profiles(nf_discover_table *DISC_TABLE, int nfType, const char *nfInstanceId, json_object *js_nf_profile, time_t *validity_time)
{
    // prepare info
    nf_disc_host_info nf_host_info = {0,};

    nf_host_info.mtype = MSGID_NRF_LIB_NRFC_REQ_PROFILE;
    sprintf(nf_host_info.nfType, "%s", nf_type_to_str(nfType));
    sprintf(nf_host_info.hostname, "%s", nfInstanceId);
    sprintf(nf_host_info.nfProfile, "%s", json_object_to_json_string_length(js_nf_profile, JSON_C_TO_STRING_NOSLASHESCAPE, &nf_host_info.profile_length));

    memcpy(&nf_host_info.validityPeriod, validity_time, sizeof(time_t));

    // create child_node
    GNode *new_node = nf_discover_create_new_node(&nf_host_info);

    // add to root_node
    nf_discover_add_new_node(&DISC_TABLE->root_node, new_node);
}

int nf_discover_table_update(nf_discover_table *DISC_TABLE, json_object *js_nf_profile, time_t *validity_time)
{
	/* get nfInstanceId (hostname) */
	char key_nfInstanceId[128] = "nfInstanceId";
	json_object *js_nfInstanceId = search_json_object(js_nf_profile, key_nfInstanceId);
	if (js_nfInstanceId == NULL) {
		APPLOG(APPLOG_ERR, "(%s) fail to search \"nfInstanceId\"", __func__);
		return -1;
	}
	const char *nfInstanceId = json_object_get_string(js_nfInstanceId);
	APPLOG(APPLOG_DEBUG, "(%s) success to search \"nfInstanceId\"=[%s]", __func__, nfInstanceId);

	/* get specificInfo (ex) udmInfo) */
	json_object *js_specific_info = NULL;
	int nfType = nf_search_specific_info(js_nf_profile, &js_specific_info);
	if (nfType < 0) {
		APPLOG(APPLOG_ERR, "(%s) fail to search \"specificInfo\"", __func__);
		return -1;
	}

    /* CREATE(UPDATE) NR PROFILE LIST */
    nf_discover_update_nf_profiles(DISC_TABLE, nfType, nfInstanceId, js_nf_profile, validity_time);

	nf_type_info nf_specific_info = {0,};
	nf_get_specific_info(nfType, js_specific_info, &nf_specific_info);

	/* get allowdPlmns */
	nf_comm_plmn allowdPlmns[NF_MAX_ALLOWD_PLMNS] = {0,};
	int allowdPlmnsNum = nf_get_allowd_plmns(js_nf_profile, &allowdPlmns[0]);

	/* get nfServices */
	char key_services[128] = "nfServices";
	json_object *js_services = search_json_object(js_nf_profile, key_services);
	int array_length = json_object_array_length(js_services);

	/* add raw each nf service */
	for (int i = 0; i < array_length; i++) {
		json_object *js_elem = json_object_array_get_idx(js_services, i);

		char key_serviceName[128] = "serviceName";
		json_object *js_serviceName= search_json_object(js_elem, key_serviceName);

		if (js_serviceName == NULL) continue;
		const char *serviceName = json_object_get_string(js_serviceName);

		char key_priority[128] = "priority";
		int priority = 100;
		json_object *js_priority = search_json_object(js_elem, key_priority);
		if (js_priority != NULL)
			priority = json_object_get_int(js_priority);

		APPLOG(APPLOG_DEBUG, "(%s) try add raw uuid[%s] serviceName[%s] validity[%.24s]",
				__func__, nfInstanceId, serviceName, ctime(validity_time));

		nf_discover_raw_update(DISC_TABLE, 
				nfType,
				&nf_specific_info,
				allowdPlmnsNum,
				allowdPlmns,
				serviceName,
				nfInstanceId, 
				priority,
				validity_time);
	}

	return 1;
}

/* key value : nfInstanceId(uuid-xxxx) + serviceName(ue-auth) */
void nf_discover_raw_update(nf_discover_table *DISC_TABLE, int nfType, nf_type_info *nf_specific_info, int allowdPlmnsNum, nf_comm_plmn *allowdPlmns, const char *serviceName, const char *nfInstanceId, int priority, time_t *validity_time)
{
	int candidate_index = -1;

	/* update validate time */
	for (int i = 0; i < MAX_NF_CACHE_NUM; i++) {

		nf_discover_raw *disc_raw = &DISC_TABLE->disc_cache[i];

		if (disc_raw->occupied == 0) {
			if (candidate_index < 0) 
				candidate_index = i;
			continue;
		} else if (!strcmp(nfInstanceId, disc_raw->hostname) && !strcmp(serviceName, disc_raw->serviceName)) {
			APPLOG(APPLOG_DEBUG, "(%s) find [%s:%s] in raw update validity time to [%.24s]", 
					__func__,  serviceName, nfInstanceId, ctime(validity_time));
			memcpy(&disc_raw->validityPeriod, validity_time, sizeof(time_t));
			return;
		}
	}

	/* insert new raw */
	if (candidate_index >= 0) {

		nf_discover_raw *disc_raw = &DISC_TABLE->disc_cache[candidate_index];

		disc_raw->index = candidate_index;
		disc_raw->occupied = 1;
		disc_raw->priority = priority;
		disc_raw->sel_count = 0;
		disc_raw->nfType = nfType;
		memcpy(&disc_raw->nfTypeInfo, nf_specific_info, sizeof(nf_type_info));
		disc_raw->allowdPlmnsNum = allowdPlmnsNum;
		memcpy(&disc_raw->allowdPlmns, allowdPlmns, sizeof(nf_comm_plmn) * NF_MAX_ALLOWD_PLMNS);
		snprintf(disc_raw->serviceName, sizeof(disc_raw->serviceName), "%s", serviceName);
		snprintf(disc_raw->hostname, sizeof(disc_raw->hostname), "%s", nfInstanceId);
		memcpy(&disc_raw->validityPeriod, validity_time, sizeof(time_t));

		APPLOG(APPLOG_DEBUG, "(%s) discover_table index(%d) update new", __func__, candidate_index);
	}
}

/* must call this function every per sec */
int nf_discover_table_clear_cached(nf_discover_table *DISC_TABLE)
{
    /* 0. REMOVE expired nf profiles(s) */
    nf_discover_remove_expired_node(&DISC_TABLE->root_node);
             
	int reset_select_count = 0;

	if (DISC_TABLE->nf_discover_table_step++ >= 60) { /* 1min */
		DISC_TABLE->nf_discover_table_step = 0;
		reset_select_count = 1;
	}

	time_t current = time(NULL);
	int deleted_item_num = 0;

	for (int i = 0; i < MAX_NF_CACHE_NUM; i++) {

		nf_discover_raw *disc_raw = &DISC_TABLE->disc_cache[i];

		if (disc_raw->occupied == 0)
			continue;

		if (disc_raw->validityPeriod < current) {
			APPLOG(APPLOG_DEBUG, "(%s) delete old raw uuid[%s] serviceName[%s] validity[%.24s]",
					__func__, disc_raw->hostname, disc_raw->serviceName, ctime(&disc_raw->validityPeriod));
			memset(disc_raw, 0x00, sizeof(nf_discover_raw));
			deleted_item_num++;
		} else if (reset_select_count) {
			disc_raw->sel_count = 0;
		}
	}

	return deleted_item_num;
}

void nf_discover_table_print(nf_discover_table *DISC_TABLE, char *print_buffer, size_t buffer_size)
{
	ft_table_t *table = ft_create_table();

	ft_set_border_style(table, FT_PLAIN_STYLE);
	ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);

	ft_set_cell_prop(table, FT_ANY_ROW, 0, FT_CPROP_TEXT_ALIGN, FT_ALIGNED_CENTER);
	ft_set_cell_prop(table, FT_ANY_ROW, 1, FT_CPROP_TEXT_ALIGN, FT_ALIGNED_CENTER);

	ft_write_ln(table, 
			"index", "type", "service", "allowd_plmns\n(mcc-mnc)", "type_info", 
			"host(uuid)name", "selected_count", "validity_period");

	for (int i = 0; i < MAX_NF_CACHE_NUM; i++) {

		nf_discover_raw *disc_raw = &DISC_TABLE->disc_cache[i];
		if (disc_raw->occupied == 0) continue;

		char allowdPlmnsStr[1024] = {0,};
		if (disc_raw->allowdPlmnsNum) {
            nf_get_allowd_plmns_str(disc_raw->allowdPlmnsNum, disc_raw->allowdPlmns, allowdPlmnsStr);
        } else {
			sprintf(allowdPlmnsStr, "anyPlmns");
        }

        char typeSpecStr[1024] = {0,};
        nf_get_specific_info_str(disc_raw->nfType, &disc_raw->nfTypeInfo, typeSpecStr);

		// nf type to string
		ft_printf_ln(table, "%d|%s|%s|%s|%s|%s|%d|%.19s",
				disc_raw->index,
				nf_type_to_str(disc_raw->nfType),
				disc_raw->serviceName,
				allowdPlmnsStr,
				typeSpecStr,
				disc_raw->hostname,
				disc_raw->sel_count,
				ctime(&disc_raw->validityPeriod));
	}

	ft_add_separator(table);

	if (print_buffer != NULL) {
		snprintf(print_buffer, buffer_size, "%s", ft_to_string(table));
	} else {
		APPLOG(APPLOG_DEBUG, "\n%s", ft_to_string(table));
	}

	ft_destroy_table(table);
}

GNode *nf_discover_create_new_node(nf_disc_host_info *insert_item)
{
    nf_disc_host_info *new_node = malloc(sizeof(nf_disc_host_info));
    memcpy(new_node, insert_item, sizeof(nf_disc_host_info));

    return g_node_new(new_node);
}

GNode *nf_discover_add_new_node(GNode **root, GNode *child)
{
    // 0. if root is NULL create root 
    if (*root == NULL) {
        nf_disc_host_info root_null_data = {0,}; // create root node
        *root = nf_discover_create_new_node(&root_null_data);
    }

    // 1. if child num = 0, just add & return 
    unsigned int child_num = g_node_n_children(*root);
    if (child_num == 0) {
        return g_node_insert_before(*root, NULL, child);
    }

    // 2. else try bsearch
    nf_disc_host_info *insert_host_info =  (nf_disc_host_info *)child->data;
    GNode *nth_child = NULL;
    int low = 0;
    int high = (child_num - 1);
    int nth = 0;
    int compare_res = 0;

    // 2-1. if bsearch finded, update data
    while (low <= high) {
        nth = (low + high) / 2;

        nth_child = g_node_nth_child(*root, nth);
        nf_disc_host_info *compare_host_info = (nf_disc_host_info *)nth_child->data;

        compare_res = strcmp(insert_host_info->hostname, compare_host_info->hostname);

        if (compare_res == 0) {
            memcpy(compare_host_info, insert_host_info, sizeof(nf_disc_host_info));
            return nth_child;
        } else if (compare_res < 0) {
            high = nth - 1;
        } else {
            low = nth + 1;
        }
    }

    // 2-2. else insert before or after
    if (compare_res < 0) {
        return g_node_insert_before(*root, nth_child, child);
    } else {
        return g_node_insert_after(*root, nth_child, child);
    }
}

nf_disc_host_info *nf_discover_search_node_by_hostname(GNode **root, const char *hostname)
{
    unsigned int child_num = 0;

    // 0. if root is NULL  or child == 0 return NULL
    if (*root == NULL || (child_num = g_node_n_children(*root)) == 0) {
        return NULL;
    }

    // 1. try bsearch
    GNode *nth_child = NULL;
    int low = 0;
    int high = (child_num - 1);
    int nth = 0;
    int compare_res = 0;

    while (low <= high) {
        nth = (low + high) / 2;

        nth_child = g_node_nth_child(*root, nth);
        nf_disc_host_info *compare_host_info = (nf_disc_host_info *)nth_child->data;

        compare_res = strcmp(hostname, compare_host_info->hostname);

        if (compare_res == 0) {
            // we find return this
            return compare_host_info;
        } else if (compare_res < 0) {
            high = nth - 1;
        } else {
            low = nth + 1;
        }
    }

    // can't find return NULL
    return NULL;
}

void nf_discover_remove_expired_node(GNode **root)
{
    unsigned int child_num = 0;

    // 0. if root is NULL  or child == 0 return NULL
    if (*root == NULL || (child_num = g_node_n_children(*root)) == 0) {
        return;
    }
            
    time_t current = time(NULL);

    // 1. backward select & check expire & free mem, remove node
    for (int i = (child_num-1); i >= 0; i--) {
        GNode *nth_child = g_node_nth_child(*root, i);
        nf_disc_host_info *host_info = (nf_disc_host_info *)nth_child->data;

        // 2. reset requested info
        host_info->requested = 0;

        // 3. if expired remove node 
        if (host_info->validityPeriod < current) {
            free(host_info);
            g_node_destroy(nth_child);
        }
    }
}

int nf_search_specific_info(json_object *nf_profile, json_object **js_specific_info)
{
	if (nf_profile == NULL) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} something wrong %s nf_profile null!", __func__);
		return -1;
	}

    char key_nfType[128] = "nfType";
    json_object *js_nfType = search_json_object(nf_profile, key_nfType);
    const char *nfType = json_object_get_string(js_nfType);

    if(!strcmp(nfType, "UDM")) {
        char key_specific_info[128] = "udmInfo";
        *js_specific_info = search_json_object(nf_profile, key_specific_info);
        return NF_TYPE_UDM;
    } else if (!strcmp(nfType, "AMF")) {
        char key_specific_info[128] = "amfInfo";
        *js_specific_info = search_json_object(nf_profile, key_specific_info);
        return NF_TYPE_AMF;
	// 2020.01.21 for ePCF
    } else if (!strcmp(nfType, "UDR")) {
        char key_specific_info[128] = "udrInfo";
        *js_specific_info = search_json_object(nf_profile, key_specific_info);
        return NF_TYPE_UDR;
    } else if (!strcmp(nfType, "BSF")) {
        char key_specific_info[128] = "bsfInfo";
        *js_specific_info = search_json_object(nf_profile, key_specific_info);
        return NF_TYPE_BSF;
    } else if (!strcmp(nfType, "CHF")) {
        char key_specific_info[128] = "csfInfo";
        *js_specific_info = search_json_object(nf_profile, key_specific_info);
        return NF_TYPE_BSF;
    } else {
        *js_specific_info = NULL;
        return NF_TYPE_UNKNOWN;
    }       
}

void nf_get_specific_info(int nfType, json_object *js_specific_info, nf_type_info *nf_specific_info)
{           
    if (nfType == NF_TYPE_UDM) {
        nf_get_specific_info_udm(js_specific_info, nf_specific_info);
    } else if (nfType == NF_TYPE_AMF) {
        nf_get_specific_info_amf(js_specific_info, nf_specific_info);
	// 2020.01.21 for ePCF
    } else if (nfType == NF_TYPE_UDR) {
        nf_get_specific_info_udr(js_specific_info, nf_specific_info);
    } else if (nfType == NF_TYPE_BSF) {
        nf_get_specific_info_bsf(js_specific_info, nf_specific_info);
    } else if (nfType == NF_TYPE_CHF) {
        nf_get_specific_info_chf(js_specific_info, nf_specific_info);
    }
}

/*
"udmInfo":{
  "groupId":"0001",
  "supiRanges":[
    {
      "start":"450070000000000",
      "end":"450079999999999"
    }, {
      "start":"450080000000000",
      "end":"450089999999999"
    }
  ],
  "routingIndicators":[
    "0001", "0002"
  ]
},
*/
void nf_get_specific_info_udm(json_object *js_specific_info, nf_type_info *nf_specific_info)
{
    nf_udm_info *udmInfo = &nf_specific_info->udmInfo;
        
    /* group Id */
    char key_groupId[128] = "groupId";
    json_object *js_group_id = search_json_object(js_specific_info, key_groupId);
    if (js_group_id)
        sprintf(udmInfo->groupId, "%.27s", json_object_get_string(js_group_id));

    /* supiRanges */
    char key_supi_ranges[128] = "supiRanges";
    json_object *js_supi_ranges = search_json_object(js_specific_info, key_supi_ranges);
    if (js_supi_ranges) {
        udmInfo->supiRangesNum = (json_object_array_length(js_supi_ranges) > NF_MAX_SUPI_RANGES) ?
            NF_MAX_SUPI_RANGES : json_object_array_length(js_supi_ranges);
        for (int i = 0; i < udmInfo->supiRangesNum; i++) {
            json_object *js_supi_elem = json_object_array_get_idx(js_supi_ranges, i);
            char key_start[128] = "start";
            char key_end[128] = "end";
            json_object *js_start = search_json_object(js_supi_elem, key_start);
            json_object *js_end = search_json_object(js_supi_elem, key_end);
            if (js_start)
                sprintf(udmInfo->supiRanges[i].start, "%.21s", json_object_get_string(js_start));
            if (js_end)
                sprintf(udmInfo->supiRanges[i].end, "%.21s", json_object_get_string(js_end));
        }
    }
    
    /* routingIndicators */
    char key_routing_indicators[128] = "routingIndicators";
    json_object *js_routing_indicators = search_json_object(js_specific_info, key_routing_indicators);
    if (js_routing_indicators) {
        udmInfo->routingIndicatorsNum = (json_object_array_length(js_routing_indicators) > NF_MAX_RI) ?
            NF_MAX_RI : json_object_array_length(js_routing_indicators);
        for (int i = 0; i < udmInfo->routingIndicatorsNum; i++) {
            json_object *js_ri_elem = json_object_array_get_idx(js_routing_indicators, i);
            if (js_ri_elem != NULL)
                sprintf(udmInfo->routingIndicators[i], "%.4s", json_object_get_string(js_ri_elem));
        }
    }
}

/*
"amfInfo" : {
    "amfRegionId" : "01",
    "amfSetId" : "001",
    "guamiList" : [ {
                "plmnId" : "262-01",
                "amfId" : "000001"
            },
            {
                "plmnId", "302-720",
                "amfId" : "000002"
    } ],
}
*/
void nf_get_specific_info_amf(json_object *js_specific_info, nf_type_info *nf_specific_info)
{
    nf_amf_info *amfInfo = &nf_specific_info->amfInfo;

    /* amfRegionId */
    char key_regionId[128] = "amfRegionId";
    json_object *js_region_id = search_json_object(js_specific_info, key_regionId);
    if (js_region_id)
        sprintf(amfInfo->amfRegionId, "%.2s", json_object_get_string(js_region_id));

    /* amfSetId */
    char key_setId[128] = "amfSetId";
    json_object *js_set_id = search_json_object(js_specific_info, key_setId);
    if (js_set_id)
        sprintf(amfInfo->amfSetId, "%.3s", json_object_get_string(js_set_id));

    /* supiRanges */
    char key_guami_list[128] = "guamiList";
    json_object *js_guami_list = search_json_object(js_specific_info, key_guami_list);
    if (js_guami_list) {
        amfInfo->guamiListNum = (json_object_array_length(js_guami_list) > NF_MAX_GUAMI_NUM) ?
            NF_MAX_GUAMI_NUM : json_object_array_length(js_guami_list);
        for (int i = 0; i < amfInfo->guamiListNum; i++) {
            json_object *js_guami_elem = json_object_array_get_idx(js_guami_list, i);
            char key_plmnId[128] = "plmnId";
            char key_amfId[128] = "amfId";
            json_object *js_plmnId = search_json_object(js_guami_elem, key_plmnId);
            json_object *js_amfId = search_json_object(js_guami_elem, key_amfId);
            if (js_plmnId)
                sprintf(amfInfo->nf_guami[i].plmnId, "%.6s", json_object_get_string(js_plmnId));
            if (js_amfId)
                sprintf(amfInfo->nf_guami[i].amfId, "%.6s", json_object_get_string(js_amfId));
        }
    }
}

// 2020.01.21 for ePCF
void nf_get_specific_info_udr(json_object *js_specific_info, nf_type_info *nf_specific_info)
{
    nf_udr_info *udrInfo = &nf_specific_info->udrInfo;
        
    /* group Id */
    char key_groupId[128] = "groupId";
    json_object *js_group_id = search_json_object(js_specific_info, key_groupId);
    if (js_group_id)
        sprintf(udrInfo->groupId, "%.27s", json_object_get_string(js_group_id));

    /* supiRanges */
    char key_supi_ranges[128] = "supiRanges";
    json_object *js_supi_ranges = search_json_object(js_specific_info, key_supi_ranges);
    if (js_supi_ranges) {
        udrInfo->supiRangesNum = (json_object_array_length(js_supi_ranges) > NF_MAX_SUPI_RANGES) ?
            NF_MAX_SUPI_RANGES : json_object_array_length(js_supi_ranges);
        for (int i = 0; i < udrInfo->supiRangesNum; i++) {
            json_object *js_supi_elem = json_object_array_get_idx(js_supi_ranges, i);
            char key_start[128] = "start";
            char key_end[128] = "end";
            json_object *js_start = search_json_object(js_supi_elem, key_start);
            json_object *js_end = search_json_object(js_supi_elem, key_end);
            if (js_start)
                sprintf(udrInfo->supiRanges[i].start, "%.21s", json_object_get_string(js_start));
            if (js_end)
                sprintf(udrInfo->supiRanges[i].end, "%.21s", json_object_get_string(js_end));
        }
    }
    
    /* gpsiRanges */
    char key_gpsi_ranges[128] = "gpsiRanges";
    json_object *js_gpsi_ranges = search_json_object(js_specific_info, key_gpsi_ranges);
    if (js_gpsi_ranges) {
        udrInfo->gpsiRangesNum = (json_object_array_length(js_gpsi_ranges) > NF_MAX_GPSI_RANGES) ?
            NF_MAX_GPSI_RANGES : json_object_array_length(js_gpsi_ranges);
        for (int i = 0; i < udrInfo->gpsiRangesNum; i++) {
            json_object *js_gpsi_elem = json_object_array_get_idx(js_gpsi_ranges, i);
            char key_start[128] = "start";
            char key_end[128] = "end";
            json_object *js_start = search_json_object(js_gpsi_elem, key_start);
            json_object *js_end = search_json_object(js_gpsi_elem, key_end);
            if (js_start)
                sprintf(udrInfo->gpsiRanges[i].start, "%.21s", json_object_get_string(js_start));
            if (js_end)
                sprintf(udrInfo->gpsiRanges[i].end, "%.21s", json_object_get_string(js_end));
        }
    }

    /* externalGroupIdentifierRanges */
    char key_external_grp_id_ranges[128] = "externalGroupIdentifiersRanges";
    json_object *js_external_grp_id_ranges = search_json_object(js_specific_info, key_external_grp_id_ranges);
    if (js_external_grp_id_ranges) {
        udrInfo->externalGroupIdentifierRangesNum = (json_object_array_length(js_external_grp_id_ranges) > NF_MAX_EXTERNAL_GRP_ID_RANGES) ?
            NF_MAX_EXTERNAL_GRP_ID_RANGES : json_object_array_length(js_external_grp_id_ranges);
        for (int i = 0; i < udrInfo->externalGroupIdentifierRangesNum; i++) {
            json_object *js_external_grp_id_elem = json_object_array_get_idx(js_external_grp_id_ranges, i);
            char key_start[128] = "start";
            char key_end[128] = "end";
            json_object *js_start = search_json_object(js_external_grp_id_elem, key_start);
            json_object *js_end = search_json_object(js_external_grp_id_elem, key_end);
            if (js_start)
                sprintf(udrInfo->externalGrpIdRanges[i].start, "%.21s", json_object_get_string(js_start));
            if (js_end)
                sprintf(udrInfo->externalGrpIdRanges[i].end, "%.21s", json_object_get_string(js_end));
        }
    }

    /* supportedDataSets */
    char key_supportedDataSets[128] = "supportedDataSets";
    json_object *js_supported_data_set = search_json_object(js_specific_info, key_supportedDataSets);
    if (js_supported_data_set) {
        sprintf(udrInfo->supportedDataSets, "%s", json_object_get_string(js_supported_data_set));
	}
}

// 2020.01.21 for ePCF
void nf_get_specific_info_bsf(json_object *js_specific_info, nf_type_info *nf_specific_info)
{
    nf_bsf_info *bsfInfo = &nf_specific_info->bsfInfo;
        
    /* ipv4AddrRanges */
    char key_ipv4_addr_ranges[128] = "ipv4AddressRanges";
    json_object *js_ipv4_addr_ranges = search_json_object(js_specific_info, key_ipv4_addr_ranges);
    if (js_ipv4_addr_ranges) {
        bsfInfo->ipv4AddressRangesNum = (json_object_array_length(js_ipv4_addr_ranges) > NF_MAX_IPV4_ADDR_RANGES) ?
            NF_MAX_IPV4_ADDR_RANGES : json_object_array_length(js_ipv4_addr_ranges);
        for (int i = 0; i < bsfInfo->ipv4AddressRangesNum; i++) {
            json_object *js_ipv4_addr_elem = json_object_array_get_idx(js_ipv4_addr_ranges, i);
            char key_start[128] = "start";
            char key_end[128] = "end";
            json_object *js_start = search_json_object(js_ipv4_addr_elem, key_start);
            json_object *js_end = search_json_object(js_ipv4_addr_elem, key_end);
            if (js_start)
                sprintf(bsfInfo->ipv4AddrRanges[i].start, "%s", json_object_get_string(js_start));
            if (js_end)
                sprintf(bsfInfo->ipv4AddrRanges[i].end, "%s", json_object_get_string(js_end));
        }
    }
    
    /* ipv6PrefixRanges */
    char key_ipv6_prefix_ranges[128] = "ipv6PrefixRanges";
    json_object *js_ipv6_prefix_ranges = search_json_object(js_specific_info, key_ipv6_prefix_ranges);
    if (js_ipv6_prefix_ranges) {
        bsfInfo->ipv6PrefixRangesNum = (json_object_array_length(js_ipv6_prefix_ranges) > NF_MAX_IPV6_PREFIX_RANGES) ?
            NF_MAX_IPV6_PREFIX_RANGES : json_object_array_length(js_ipv6_prefix_ranges);
        for (int i = 0; i < bsfInfo->ipv6PrefixRangesNum; i++) {
            json_object *js_ipv6_prefix_elem = json_object_array_get_idx(js_ipv6_prefix_ranges, i);
            char key_start[128] = "start";
            char key_end[128] = "end";
            json_object *js_start = search_json_object(js_ipv6_prefix_elem, key_start);
            json_object *js_end = search_json_object(js_ipv6_prefix_elem, key_end);
            if (js_start)
                sprintf(bsfInfo->ipv6PrefixRanges[i].start, "%s", json_object_get_string(js_start));
            if (js_end)
                sprintf(bsfInfo->ipv6PrefixRanges[i].end, "%s", json_object_get_string(js_end));
        }
    }
    
#if 0 // please check syntax for dnnList and ipDomainList
    /* dnnList */
    char key_dnn_list[128] = "dnnList";
    json_object *js_dnn_list = search_json_object(js_specific_info, key_dnn_list);
    if (js_dnn_list) {
        bsfInfo->dnnListNum = (json_object_array_length(js_dnn_list) > NF_MAX_DNN_LIST_NUM) ?
            NF_MAX_DNN_LIST_NUM : json_object_array_length(js_dnn_list);
        for (int i = 0; i < bsfInfo->dnnListNum; i++) {
            json_object *js_dnn_list_elem = json_object_array_get_idx(js_dnn_list, i);
            char key_dnn[128] = "dnn";
            json_object *js_dnn = search_json_object(js_dnn_list_elem, key_dnn);
            if (js_dnn) {
                sprintf(bsfInfo->dnnList[i], "%s", json_object_get_string(js_dnn));
			}
        }
    }
    
    /* ipDomainList */
    char key_ip_domain_list[128] = "ipDomainList";
    json_object *js_ip_domain_list = search_json_object(js_specific_info, key_ip_domain_list);
    if (js_ip_domain_list) {
        bsfInfo->ipDomainListNum = (json_object_array_length(js_ip_domain_list) > NF_MAX_IP_DOMAIN_LIST_NUM) ?
            NF_MAX_IP_DOMAIN_LIST_NUM : json_object_array_length(js_ip_domain_list);
        for (int i = 0; i < bsfInfo->ipDomainListNum; i++) {
            json_object *js_ip_domain_list_elem = json_object_array_get_idx(js_ip_domain_list, i);
            char key_ipDomain[128] = "ipDomain";
            json_object *js_ipDomain = search_json_object(js_ip_domain_list_elem, key_ipDomain);
            if (js_ipDomain) {
                sprintf(bsfInfo->ipDomainList[i], "%s", json_object_get_string(js_ipDomain));
			}
        }
    }
#endif
}

// 2020.01.21 for ePCF
void nf_get_specific_info_chf(json_object *js_specific_info, nf_type_info *nf_specific_info)
{
    nf_chf_info *chfInfo = &nf_specific_info->chfInfo;
        
    /* supiRanges */
    char key_supi_ranges[128] = "supiRanges";
    json_object *js_supi_ranges = search_json_object(js_specific_info, key_supi_ranges);
    if (js_supi_ranges) {
        chfInfo->supiRangesNum = (json_object_array_length(js_supi_ranges) > NF_MAX_SUPI_RANGES) ?
            NF_MAX_SUPI_RANGES : json_object_array_length(js_supi_ranges);
        for (int i = 0; i < chfInfo->supiRangesNum; i++) {
            json_object *js_supi_elem = json_object_array_get_idx(js_supi_ranges, i);
            char key_start[128] = "start";
            char key_end[128] = "end";
            json_object *js_start = search_json_object(js_supi_elem, key_start);
            json_object *js_end = search_json_object(js_supi_elem, key_end);
            if (js_start)
                sprintf(chfInfo->supiRanges[i].start, "%.21s", json_object_get_string(js_start));
            if (js_end)
                sprintf(chfInfo->supiRanges[i].end, "%.21s", json_object_get_string(js_end));
        }
    }
    
    /* gpsiRanges */
    char key_gpsi_ranges[128] = "gpsiRanges";
    json_object *js_gpsi_ranges = search_json_object(js_specific_info, key_gpsi_ranges);
    if (js_gpsi_ranges) {
        chfInfo->gpsiRangesNum = (json_object_array_length(js_gpsi_ranges) > NF_MAX_GPSI_RANGES) ?
            NF_MAX_GPSI_RANGES : json_object_array_length(js_gpsi_ranges);
        for (int i = 0; i < chfInfo->gpsiRangesNum; i++) {
            json_object *js_gpsi_elem = json_object_array_get_idx(js_gpsi_ranges, i);
            char key_start[128] = "start";
            char key_end[128] = "end";
            json_object *js_start = search_json_object(js_gpsi_elem, key_start);
            json_object *js_end = search_json_object(js_gpsi_elem, key_end);
            if (js_start)
                sprintf(chfInfo->gpsiRanges[i].start, "%.21s", json_object_get_string(js_start));
            if (js_end)
                sprintf(chfInfo->gpsiRanges[i].end, "%.21s", json_object_get_string(js_end));
        }
    }

    /* plmnRanges */
    char key_plmn_ranges[128] = "plmnRanges";
    json_object *js_plmn_ranges = search_json_object(js_specific_info, key_plmn_ranges);
    if (js_plmn_ranges) {
        chfInfo->plmnRangesNum = (json_object_array_length(js_plmn_ranges) > NF_MAX_PLMN_RANGES) ?
            NF_MAX_PLMN_RANGES : json_object_array_length(js_plmn_ranges);
        for (int i = 0; i < chfInfo->plmnRangesNum; i++) {
            json_object *js_plmn_elem = json_object_array_get_idx(js_plmn_ranges, i);
            char key_start[128] = "start";
            char key_end[128] = "end";
            json_object *js_start = search_json_object(js_plmn_elem, key_start);
            json_object *js_end = search_json_object(js_plmn_elem, key_end);
            if (js_start)
                sprintf(chfInfo->plmnRanges[i].start, "%s", json_object_get_string(js_start));
            if (js_end)
                sprintf(chfInfo->plmnRanges[i].end, "%s", json_object_get_string(js_end));
        }
    }
}

int nf_get_allowd_plmns(json_object *nf_profile, nf_comm_plmn *allowdPlmns)
{   
    char key_allowd_plmns[128] = "allowedPlmns";
	int allowdPlmnsNum = 0;
    json_object *js_allowd_plmns = search_json_object(nf_profile, key_allowd_plmns);
    
	if (js_allowd_plmns) {
		allowdPlmnsNum = (json_object_array_length(js_allowd_plmns) > NF_MAX_ALLOWD_PLMNS) ?
			NF_MAX_ALLOWD_PLMNS : json_object_array_length(js_allowd_plmns);

		for (int i = 0; i < allowdPlmnsNum; i++) {
			json_object *js_allowd_plmn_elem = json_object_array_get_idx(js_allowd_plmns, i);
			char key_mcc[128] = "mcc";
			char key_mnc[128] = "mnc";
			json_object *js_mcc = search_json_object(js_allowd_plmn_elem, key_mcc);
			json_object *js_mnc = search_json_object(js_allowd_plmn_elem, key_mnc);
			if (js_mcc)
				sprintf(allowdPlmns[i].mcc, "%.3s", json_object_get_string(js_mcc));
			if (js_mnc)
			sprintf(allowdPlmns[i].mnc, "%.3s", json_object_get_string(js_mnc));
		}       
	}
            
    return allowdPlmnsNum;
} 

char *nf_type_to_str(int nfType)
{
    switch(nfType) {
        case NF_TYPE_NRF:
            return "NRF";
        case NF_TYPE_UDM:
            return "UDM";
        case NF_TYPE_AMF:
            return "AMF";
        case NF_TYPE_SMF:
            return "SMF";
        case NF_TYPE_AUSF:
            return "AUSF";
        case NF_TYPE_NEF:
            return "NEF";
        case NF_TYPE_PCF:
            return "PCF";
        case NF_TYPE_SMSF:
            return "SMSF";
        case NF_TYPE_NSSF:
            return "NSSF";
        case NF_TYPE_UDR:
            return "UDR";
        case NF_TYPE_LMF:
            return "LMF";
        case NF_TYPE_GMLC:
            return "GMLC";
        case NF_TYPE_5G_EIR:
            return "EIR";
        case NF_TYPE_SEPP:
            return "SEPP";
        case NF_TYPE_UPF:
            return "UPF";
        case NF_TYPE_N3IWF:
            return "N3IWF";
        case NF_TYPE_AF:
            return "AF";
        case NF_TYPE_UDSF:
            return "UDSF";
        case NF_TYPE_BSF:
            return "BSF";
        case NF_TYPE_CHF:
            return "CHF";
        case NF_TYPE_NWDAF:
            return "NWDAF";
        default:
            return "UNKNOWN";
    }
}
int nf_type_to_enum(char *type)
{
    if (!strcmp(type, "NRF"))
        return NF_TYPE_NRF;
    else if (!strcmp(type, "UDM"))
        return NF_TYPE_UDM;
    else if (!strcmp(type, "AMF"))
        return NF_TYPE_AMF;
    else if (!strcmp(type, "SMF"))
        return NF_TYPE_SMF;
    else if (!strcmp(type, "AUSF"))
        return NF_TYPE_AUSF;
    else if (!strcmp(type, "NEF"))
        return NF_TYPE_NEF;
    else if (!strcmp(type, "PCF"))
        return NF_TYPE_PCF;
    else if (!strcmp(type, "SMSF"))
        return NF_TYPE_SMSF;
    else if (!strcmp(type, "NSSF"))
        return NF_TYPE_NSSF;
    else if (!strcmp(type, "UDR"))
        return NF_TYPE_UDR;
    else if (!strcmp(type, "LMF"))
        return NF_TYPE_LMF;
    else if (!strcmp(type, "GMLC"))
        return NF_TYPE_GMLC;
    else if (!strcmp(type, "EIR"))
        return NF_TYPE_5G_EIR;
    else if (!strcmp(type, "SEPP"))
        return NF_TYPE_SEPP;
    else if (!strcmp(type, "UPF"))
        return NF_TYPE_UPF;
    else if (!strcmp(type, "N3IWF"))
        return NF_TYPE_N3IWF;
    else if (!strcmp(type, "AF"))
        return NF_TYPE_AF;
    else if (!strcmp(type, "UDSF"))
        return NF_TYPE_UDSF;
    else if (!strcmp(type, "BSF"))
        return NF_TYPE_BSF;
    else if (!strcmp(type, "CHF"))
        return NF_TYPE_CHF;
    else
        return NF_TYPE_UNKNOWN;
}

int check_number(char *ptr)
{
    for (int i = 0; i < strlen(ptr); i++) {
        if (isdigit(ptr[i]) == 0)
            return -1;
    }
    return atoi(ptr);
}

json_object *search_json_object(json_object *obj, char *key_string)
{   
    char *ptr = strtok(key_string, "/");
    json_object *input = obj;
    json_object *output = NULL;

    while (ptr != NULL) {
        int cnvt_num = check_number(ptr);

        if (cnvt_num >= 0) {
            if (json_object_get_type(input) != json_type_array)
                return NULL;
            if ((output = json_object_array_get_idx(input, cnvt_num)) == NULL)
                return NULL;
        } else {
            if (json_object_object_get_ex(input, ptr, &output) == 0)
                return NULL;
        }

        input = output;
        ptr = strtok(NULL, "/");
    }
    return output;
}

