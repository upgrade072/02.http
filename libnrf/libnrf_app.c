#include "libnrf.h"

nf_service_info *nf_discover_search_cache(nf_discover_key *search_info, nf_discover_table *DISC_TABLE, nfs_avail_shm_t *NFS_TABLE)
{
	switch (search_info->nfType) {
		case NF_TYPE_UDM:
			return nf_discover_search_udm(search_info, DISC_TABLE, NFS_TABLE);
		default:
			APPLOG(APPLOG_ERR, "(%s) recv unknown nfType(%d)", __func__, search_info->nfType);
			return NULL;
	}
}

nf_service_info *nf_discover_search_udm(nf_discover_key *search_info, nf_discover_table *DISC_TABLE, nfs_avail_shm_t *NFS_TABLE)
{
	switch (search_info->nfSearchType) {
		case NF_DISC_ST_SUPI:
			return nf_discover_search_udm_supi(search_info, DISC_TABLE, NFS_TABLE);
		case NF_DISC_ST_SUCI: 
			return nf_discover_search_udm_suci(search_info, DISC_TABLE, NFS_TABLE);
		default:
			APPLOG(APPLOG_ERR, "(%s) recv unknown searchType(%d)", __func__, search_info->nfSearchType);
			return NULL;
	}
}

nf_service_info *nf_discover_search_udm_supi(nf_discover_key *search_info, nf_discover_table *DISC_TABLE, nfs_avail_shm_t *NFS_TABLE)
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
	return nf_discover_result(&result_cache, search_info, DISC_TABLE, NFS_TABLE); 
}

nf_service_info *nf_discover_search_udm_suci(nf_discover_key *search_info, nf_discover_table *DISC_TABLE, nfs_avail_shm_t *NFS_TABLE)
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
	return nf_discover_result(&result_cache, search_info, DISC_TABLE, NFS_TABLE); 
}

nf_service_info *nf_discover_result(nf_discover_local_res *result_cache, nf_discover_key *search_info, nf_discover_table *DISC_TABLE, nfs_avail_shm_t *NFS_TABLE)
{
	nf_list_shm_t *nfs_avail_shm = &NFS_TABLE->nfs_avail_shm[NFS_TABLE->curr_pos];

	for (int i = 0; i < result_cache->res_num && i < MAX_NF_CACHE_NUM; i++) {

		nf_discover_res_info *res_info = &result_cache->nf_disc_res[i];
	 	if (res_info->occupied == 0 || res_info->disc_raw_index < 0 || res_info->disc_raw_index >= MAX_NF_CACHE_NUM) {
			APPLOG(APPLOG_ERR, "(%s) somthing wrong res_info invalid", __func__);
			continue;
		}

		/* key */
		nf_discover_raw *discover_info = &DISC_TABLE->disc_cache[res_info->disc_raw_index];

		for (int k = 0; k < search_info->lbNum && k < NF_MAX_LB_NUM; k++) {
			int lbIndex = (search_info->start_lbId + k) % search_info->lbNum;
			int availCount = nfs_avail_shm->nf_avail_cnt[lbIndex];

			for (int nfsIndex = 0; nfsIndex < availCount && nfsIndex < NF_MAX_AVAIL_LIST; nfsIndex++) {
				nf_service_info *nf_service = &nfs_avail_shm->nf_avail[lbIndex][nfsIndex];
				
				if (!strcmp(discover_info->hostname, nf_service->hostname)) {
					discover_info->sel_count++;
					APPLOG(APPLOG_DEBUG, "(%s) select (%s) in lb[%d]", 
							__func__, nf_service->hostname, lbIndex);
					return nf_service;
				}
			}
		}
	}

	//APPLOG(APPLOG_ERR, "(%s) cant find any hostname in SHM!!", __func__);
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
	int res = -1; // return updated nf profile number

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

	/* get specificInfo (udmInfo) */
	json_object *js_specific_info = NULL;
	int nfType = nf_search_specific_info(js_nf_profile, &js_specific_info);
	if (nfType < 0) {
		APPLOG(APPLOG_ERR, "(%s) fail to search \"specific(udm)Info\"", __func__);
		return -1;
	}
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
		int priority = 100; /* TODO! */
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
		} else if (!strcmp(serviceName, disc_raw->serviceName) && !strcmp(nfInstanceId, disc_raw->hostname)) {
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
int NF_DISCOVER_TABLE_STEP;
int nf_discover_table_clear_cached(nf_discover_table *DISC_TABLE)
{
	NF_DISCOVER_TABLE_STEP++;
	int reset_select_count = 0;
	if (NF_DISCOVER_TABLE_STEP >= 60) { /* 1min */
		reset_select_count = 1;
		NF_DISCOVER_TABLE_STEP = 0;
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
			"index", "type", "service", "allowd_plmns\n(mcc+mnc)", "type_info", 
			"host(uuid)name", "selected_count", "validity_period");

	for (int i = 0; i < MAX_NF_CACHE_NUM; i++) {

		nf_discover_raw *disc_raw = &DISC_TABLE->disc_cache[i];
		if (disc_raw->occupied == 0) continue;

		// TODO ! to library (~libnrf.c, same function)
		char allowdPlmnsStr[1024] = {0,};
		if (disc_raw->allowdPlmnsNum) {
			for (int k = 0; k < disc_raw->allowdPlmnsNum; k++) {
				nf_comm_plmn *plmns = &disc_raw->allowdPlmns[k];
				sprintf(allowdPlmnsStr + strlen(allowdPlmnsStr), "%s%s%s", 
					plmns->mcc, plmns->mnc, k == (disc_raw->allowdPlmnsNum - 1) ? "" : "\n");
			}
		} else {
			sprintf(allowdPlmnsStr, "%s", "anyPlmns");
		}

		// TODO ! to library (~libnrf.c, same function)
		char typeSpecStr[1024] = {0,};
		if (disc_raw->nfType == NF_TYPE_UDM) {
			nf_udm_info *udmInfo = &disc_raw->nfTypeInfo.udmInfo;
			sprintf(typeSpecStr + strlen(typeSpecStr), "%s\n", udmInfo->groupId);
			for (int i = 0; i < udmInfo->supiRangesNum; i++) {
				sprintf(typeSpecStr + strlen(typeSpecStr), "%s ~ %s\n",
						udmInfo->supiRanges[i].start,
						udmInfo->supiRanges[i].end);
			}
			for (int i = 0; i < udmInfo->routingIndicatorsNum; i++) {
				sprintf(typeSpecStr + strlen(typeSpecStr), "%s ", 
						udmInfo->routingIndicators[i]);
			}   
		} else {
			sprintf(allowdPlmnsStr, "%s", "unknownType");
		}

		// nf type to string
		ft_printf_ln(table, "%d|%s|%s|%s|%s|%s|%d|%.19s",
				disc_raw->index,
				disc_raw->nfType == NF_TYPE_UDM ? "udm" : "unknown",
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
