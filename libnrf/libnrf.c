#include "libnrf.h"

void def_sigaction()
{
    struct sigaction act;

    memset(&act, 0, sizeof(struct sigaction));
    act.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &act, NULL);
}

GSList *get_associate_node(GSList *node_assoc_list, const char *type_str)
{
    /* remove all fep list (prepare for scale in/out) */
    node_list_remove_all(node_assoc_list);
	GSList *new_assoc = NULL;

    char fname[1024] = {0,};
    sprintf(fname,"%s/%s", getenv(IV_HOME), ASSOCONF_FILE);

    FILE *fp = fopen(fname, "r");
    if (fp == NULL) {
        fprintf(stderr, "'%s' not opened\n", fname);
        return NULL;
    }

    char buffer[2048] = {0,};
    while (fgets(buffer, 2048, fp)) {
        assoc_t node_elem = {0,};

        sscanf(buffer, "%s%*s%s%s %*s%*s%*s %s", node_elem.name, node_elem.type, node_elem.group, node_elem.ip);
        if (isalpha(node_elem.name[0]) == 0)
            continue;
        if (strcmp(node_elem.type, type_str))
            continue;

        struct sockaddr_in sa = {0,};
        if (inet_pton(AF_INET, node_elem.ip, &(sa.sin_addr)) == 0)
            continue;

        /* re-arrange fep list */
        new_assoc = node_list_add_elem(new_assoc, &node_elem);
    }
    fclose(fp);

    /* check fep list */
    node_list_print_log(new_assoc);

	return new_assoc;
}

int get_sys_label_num()
{
    char fname[1024] = {0,};
	char label[1024] = {0,};

    sprintf(fname, "%s/%s", getenv(IV_HOME), SYSCONF_FILE);
    conflib_getNthTokenInFileSection (fname, "GENERAL", "SYSTEM_LABEL", 1, label);

	char buff[1024] = {0,};
	int pos = 0;
	for (int i = 0; i < strlen(label); i++) {
		if (isdigit(label[i])) 
			buff[pos++] = label[i];
	}
	buff[pos] = '\0';

	return atoi(buff);
}

void get_my_info(svr_info_t *my_info, const char *my_proc_name)
{
    char fname[1024] = {0,};

    sprintf(my_info->mySysName, "%s", getenv(MY_SYS_NAME));
    sprintf(my_info->myProcName, "%s", my_proc_name);

    sprintf(fname, "%s/%s", getenv(IV_HOME), SYSCONF_FILE);
    conflib_getNthTokenInFileSection (fname, "GENERAL", "SYSTEM_TYPE", 1, my_info->mySysType);
    conflib_getNthTokenInFileSection (fname, "GENERAL", "SERVER_ID", 1, my_info->mySvrId);

    fprintf(stderr, "TEST| %s %s %s %s\n",
            my_info->mySysName,
            my_info->myProcName,
            my_info->mySysType,
            my_info->mySvrId);

	my_info->myLabelNum = get_sys_label_num();
}

void node_assoc_release(assoc_t *node_elem)
{
    APPLOG(APPLOG_ERR, "{{{CHECK}}} node_elem (%s:%s:%s:%s) released!",
            node_elem->name, node_elem->type, node_elem->group, node_elem->ip);
    free(node_elem);
}

void node_list_remove_all(GSList *node_assoc_list)
{
    // TODO !!! check release func
    g_slist_free_full(node_assoc_list, (GDestroyNotify)node_assoc_release);
}

GSList *node_list_add_elem(GSList *node_assoc_list, assoc_t *node_elem)
{
    assoc_t *node_add = malloc(sizeof(assoc_t));
    memcpy(node_add, node_elem, sizeof(assoc_t));
    node_assoc_list = g_slist_append(node_assoc_list, node_add);

	return node_assoc_list;
}

void node_assoc_log(assoc_t *node_elem)
{
    APPLOG(APPLOG_ERR, "{{{CHECK}}} node_elem (%s:%s:%s:%s) exist!",
            node_elem->name, node_elem->type, node_elem->group, node_elem->ip);
}

void node_list_print_log(GSList *node_assoc_list)
{
    g_slist_foreach(node_assoc_list, (GFunc)node_assoc_log, NULL);
}

#define NOTIFY_WATCH_MAX_BUFF (1024 * 12)
extern void directory_watch_action(const char *file_name);
static void config_watch_callback(struct bufferevent *bev, void *args)
{   
    char buf[NOTIFY_WATCH_MAX_BUFF] = {0,};
    size_t numRead = bufferevent_read(bev, buf, NOTIFY_WATCH_MAX_BUFF);
    char *ptr; 
    for (ptr = buf; ptr < buf + numRead; ) {
        struct inotify_event *event = (struct inotify_event*)ptr;
        if (event->len > 0) {
            /* function point */
			directory_watch_action(event->name);
        }
        ptr += sizeof(struct inotify_event) + event->len;
    }
}

int watch_directory_init(struct event_base *evbase, const char *path_name)
{
	int inotifyFd = inotify_init();
	if (inotifyFd == -1) {
		fprintf(stderr, "INIT| ERR| inotify init fail!\n");
		return -1;
	}

	int inotifyWd = inotify_add_watch(inotifyFd, path_name, IN_CLOSE_WRITE | IN_MOVED_TO);
	if (inotifyWd == -1) {
		fprintf(stderr, "INIT| ERR| inotify add watch [%s] fail!\n", path_name);
		return -1;
	} else {
		fprintf(stderr, "INIT| inotify add watch [%d:%s]\n", inotifyWd, path_name);
	}


	struct bufferevent *ev_watch = bufferevent_socket_new(evbase, inotifyFd, BEV_OPT_CLOSE_ON_FREE);
	bufferevent_setcb(ev_watch, config_watch_callback, NULL, NULL, NULL);
	bufferevent_enable(ev_watch, EV_READ);

	return 0;
}

acc_token_info_t *get_acc_token_info(acc_token_shm_t *ACC_TOKEN_LIST, int id, int used)
{
	if (id < 1 || id > MAX_ACC_TOKEN_NUM)
		return NULL;

	if (used) {
		// get my 
		if (ACC_TOKEN_LIST->acc_token[id].occupied != 1)
			return NULL;

		return &ACC_TOKEN_LIST->acc_token[id];
	} else {
		// assign new
		if (ACC_TOKEN_LIST->acc_token[id].occupied == 1)
			return NULL;

		ACC_TOKEN_LIST->acc_token[id].occupied = 1;
		return &ACC_TOKEN_LIST->acc_token[id];
	}

	return NULL;
}

acc_token_info_t *new_acc_token_info(acc_token_shm_t *ACC_TOKEN_LIST)
{
	for (int id = MAX_ACC_TOKEN_NUM; id > 0; id--) {
		acc_token_info_t *token_info = &ACC_TOKEN_LIST->acc_token[id];
		if (token_info->occupied == 0) {
			memset(token_info, 0x00, sizeof(acc_token_info_t));
			token_info->occupied = 1;
			token_info->token_id = id;
			return token_info;
		}
	}

	return NULL;
}

char *get_access_token(acc_token_shm_t *ACC_TOKEN_LIST, int token_id)
{
    if (token_id < 0 || token_id >= MAX_ACC_TOKEN_NUM)
        return NULL;

    acc_token_info_t *token_info = &ACC_TOKEN_LIST->acc_token[token_id];
    if (token_info->status != TA_ACQUIRED)
        return NULL;
    
    int pos = token_info->token_pos;
    return token_info->access_token[pos];
} 

void print_token_info_raw(acc_token_shm_t *ACC_TOKEN_LIST, char *respBuff)
{
	ft_table_t *table = ft_create_table();

	ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);
	ft_set_border_style(table, FT_PLAIN_STYLE);
	ft_write_ln(table, "INDEX", "ID", "NF_INSTANCEID\nNF_TYPE\nTOKEN_TYPE", "SCOPE", "ADD_TYPE\nTOKEN_STATUS\nREQUEST_TIME\nRESONSE_TIME", "ACCESS_TOKEN");

	for (int i = 1; i < MAX_ACC_TOKEN_NUM; i++) {
        acc_token_info_t *token_info = get_acc_token_info(ACC_TOKEN_LIST, i, 1);
        if (token_info == NULL) {
            continue;
        } else {
            char request_time[128] = {0,};
            char validate_time[128] = {0,};
            sprintf(request_time, "%.19s", ctime(&token_info->last_request_time));
            sprintf(validate_time, "%.19s", ctime(&token_info->due_date));

			char *token_str = token_info->access_token[token_info->token_pos];
			char token_data[1024] = {0,};

			for (int k = 0, pos = 0; k < strlen(token_str); k++) {
				token_data[pos++] = token_str[k];
				if (pos % 42 == 0)
					token_data[pos++] = '\n';
			}

			ft_printf_ln(table, "%d|%d|%s\n%s\n%s|%s|%s\n%s\n%s\n%s|%s",
					i,
					token_info->token_id,
					token_info->nf_instance_id,
					strlen(token_info->nf_type) ? token_info->nf_type : "-",
					(token_info->acc_type == AT_SVC) ? "for Service" : "for Instance",
					strlen(token_info->scope) ? token_info->scope : "-",
					(token_info->operator_added) ? "oper add" : "auto add",
					(token_info->status == TA_INIT) ? "initial" :
					(token_info->status == TA_FAILED) ? "failed" :
					(token_info->status == TA_TRYING) ? "trying" : "acquired",
					request_time,
					validate_time,
					(token_info->status == TA_ACQUIRED) ? token_data: "-");
			ft_add_separator(table);
		}
	}

	sprintf(respBuff, "%s", ft_to_string(table));
	ft_destroy_table(table);
}


void print_nrfm_mml_raw(nrfm_mml_t *httpc_cmd)
{
	ft_table_t *table_c = ft_create_table();
	ft_set_border_style(table_c, FT_EMPTY_STYLE);
	ft_set_cell_prop(table_c, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);
	ft_write_ln(table_c, "occupied", "scheme", "ip", "port", "cnt");
    for (int i = 0; i < httpc_cmd->info_cnt; i++) {
		if (!httpc_cmd->nf_conns[i].occupied)
			continue;
		ft_printf_ln(table_c, "%d|%s|%s|%d|%d",
                httpc_cmd->nf_conns[i].occupied,
                httpc_cmd->nf_conns[i].scheme,
                httpc_cmd->nf_conns[i].ip,
                httpc_cmd->nf_conns[i].port,
                httpc_cmd->nf_conns[i].cnt);
    }

	ft_table_t *table_m = ft_create_table();
	ft_set_border_style(table_m, FT_PLAIN_STYLE);
	ft_set_cell_prop(table_m, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);
	ft_write_ln(table_m, "command", "host", "type", "info_cnt", "items");
	ft_printf_ln(table_m, "%s|%s|%s|%d|%s", 
			get_nrfm_cmd_str(httpc_cmd->command),
			httpc_cmd->host,
			httpc_cmd->type,
			httpc_cmd->info_cnt,
			ft_to_string(table_c));
	APPLOG(APPLOG_ERR, "\n%s", ft_to_string(table_m));
	ft_destroy_table(table_c);
	ft_destroy_table(table_m);
}

void getTypeSpecStr(nf_service_info *nf_info, char *resBuf)
{
	if (nf_info->nfType == NF_TYPE_UDM) {
		nf_udm_info *udmInfo = &nf_info->nfTypeInfo.udmInfo;
		sprintf(resBuf + strlen(resBuf), "%s\n", udmInfo->groupId);
		for (int i = 0; i < udmInfo->supiRangesNum; i++) {
			sprintf(resBuf + strlen(resBuf), "%s ~ %s\n", 
					udmInfo->supiRanges[i].start,
					udmInfo->supiRanges[i].end);
		}
		for (int i = 0; i < udmInfo->routingIndicatorsNum; i++) {
			sprintf(resBuf + strlen(resBuf), "%s ",
				   udmInfo->routingIndicators[i]);
		}
	}
}

void getAllowdPlmns(nf_service_info *nf_info, char *resBuf)
{
	for (int k = 0; k < nf_info->allowdPlmnsNum; k++) {
		nf_comm_plmn *plmns = &nf_info->allowdPlmns[k];
		sprintf(resBuf + strlen(resBuf),
				"%s%s%s", 
				plmns->mcc, plmns->mnc, k == (nf_info->allowdPlmnsNum - 1) ? "" : "\n");
	}
}

void printf_avail_nfs(nf_list_pkt_t *avail_nfs)
{
	ft_table_t *table = ft_create_table();

	ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);
	ft_set_border_style(table, FT_BASIC2_STYLE);
	ft_write_ln(table, "index", "type", "service", "allowedPlmns\n(mcc+mnc)", "typeInfo", "hostname", "scheme", "ipv4", "port", "priority", "auto", "lb_id");

    for (int i = 0, index = 1; i < avail_nfs->nf_avail_num; i++) {
        nf_service_info *nf_info = &avail_nfs->nf_avail[i];
        if (nf_info->occupied <= 0)
            continue;

		/* allowd plmns */
		char allowdPlmnsStr[1024] = {0,};
		getAllowdPlmns(nf_info, allowdPlmnsStr);

		/* nf-type specific info */
		char typeSpecStr[1024 * 12] = {0,};
		getTypeSpecStr(nf_info, typeSpecStr);

        ft_printf_ln(table, "%d|%s|%s|%s|%s|%s|%s|%s|%d|%d|%s|%d",
				index++,
                nf_info->type,
                strlen(nf_info->serviceName) ? nf_info->serviceName : "ANY", 
				strlen(allowdPlmnsStr) ? allowdPlmnsStr : "ANY",
				strlen(typeSpecStr) ? typeSpecStr : "ANY",
                nf_info->hostname,
                nf_info->scheme,
                nf_info->ipv4Address,
                nf_info->port,
                nf_info->priority,
				nf_info->auto_add == 0 ? "X" : "O",
				nf_info->lbId);
    }
	APPLOG(APPLOG_ERR, "\n%s", ft_to_string(table));
	ft_destroy_table(table);
}

char *get_nrfm_cmd_str(int cmd)
{
    switch (cmd) {
        case NRFM_MML_HTTPC_ADD:
			return "ADD";
		case NRFM_MML_HTTPC_ACT:
			return "ACT";
        case NRFM_MML_HTTPC_DACT:
			return "DACT";
        case NRFM_MML_HTTPC_DEL:
			return "DEL";
		case NRFM_MML_HTTPC_CLEAR:
			return "<CLEAR!!!>";
		default:
			return "UNKNOWN";
    }
}

int cnvt_cfg_to_json(json_object *obj, config_setting_t *setting, int callerType)
{
	json_object *obj_group = NULL;
	json_object *obj_array = NULL;
	int count = 0;

	switch (setting->type) {
		// SIMPLE CASE
		case CONFIG_TYPE_INT:
			json_object_object_add(obj, setting->name, json_object_new_int(setting->value.ival));
			break;
		case CONFIG_TYPE_STRING:
			if (callerType == CONFIG_TYPE_ARRAY || callerType == CONFIG_TYPE_LIST) {
				json_object_array_add(obj, json_object_new_string(setting->value.sval));
			} else {
				json_object_object_add(obj, setting->name, json_object_new_string(setting->value.sval));
			}
			break;
		case CONFIG_TYPE_BOOL:
			json_object_object_add(obj, setting->name, json_object_new_boolean(setting->value.ival));
			break;
		// COMPLEX CASE
		case CONFIG_TYPE_GROUP:
			obj_group = json_object_new_object();
			count = config_setting_length(setting);
			for (int i = 0; i < count; i++) {
				config_setting_t *elem = config_setting_get_elem(setting, i);
				cnvt_cfg_to_json(obj_group, elem, setting->type);
			}
			if (callerType == CONFIG_TYPE_ARRAY || callerType == CONFIG_TYPE_LIST) {
				json_object_array_add(obj, obj_group);
			} else {
				json_object_object_add(obj, setting->name, obj_group);
			}
			break;
		case CONFIG_TYPE_ARRAY:
		case CONFIG_TYPE_LIST:
			obj_array = json_object_new_array();
			json_object_object_add(obj, setting->name, obj_array);

			count = config_setting_length(setting);
			for (int i = 0; i < count; i++) {
				config_setting_t *elem = config_setting_get_elem(setting, i);
				cnvt_cfg_to_json(obj_array, elem, setting->type);
			}
			break;
		default:
			fprintf(stderr, "TODO| do something!\n");
			break;
	}

	return 0;
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
    } else if(!strcmp(nfType, "UDR")) {
        char key_specific_info[128] = "udrInfo";
        *js_specific_info = search_json_object(nf_profile, key_specific_info);
        return NF_TYPE_UDR;
    } else {
        *js_specific_info = NULL;
        return NF_TYPE_UNKNOWN;
    }       
}

void nf_get_specific_info(int nfType, json_object *js_specific_info, nf_type_info *nf_specific_info)
{           
    if (nfType == NF_TYPE_UDM) {
        nf_udm_info *udmInfo = &nf_specific_info->udmInfo;
            
        /* group Id */
        char key_groupId[128] = "groupId";
        json_object *js_group_id = search_json_object(js_specific_info, key_groupId);
		if (js_group_id)
			sprintf(udmInfo->groupId, "%s", json_object_get_string(js_group_id));

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
					sprintf(udmInfo->supiRanges[i].start, "%s", json_object_get_string(js_start));
				if (js_end)
					sprintf(udmInfo->supiRanges[i].end, "%s", json_object_get_string(js_end));
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
					sprintf(udmInfo->routingIndicators[i], "%s", json_object_get_string(js_ri_elem));
			}
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
				sprintf(allowdPlmns[i].mcc, "%s", json_object_get_string(js_mcc));
			if (js_mnc)
			sprintf(allowdPlmns[i].mnc, "%s", json_object_get_string(js_mnc));
		}       
	}
            
    return allowdPlmnsNum;
} 