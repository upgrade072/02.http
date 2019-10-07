#include "nrfm.h"
// TODO multi thread issue

char *cfg_get_my_ip(main_ctx_t *MAIN_CTX)
{
	config_setting_t *setting_svc_nic = NULL;
	if ((setting_svc_nic = config_lookup(&MAIN_CTX->CFG, CF_SVC_NIC)) == NULL) {
		fprintf(stderr, "TODO| cant find .cfg (%s)\n", CF_SVC_NIC);
		return strdup("unknown");
	}

	const char *nic_name = config_setting_get_string(setting_svc_nic);

	char temp[1024] = {0,};
	get_svc_ipv4_addr(nic_name, temp);
	char *res = strdup(temp);

	return res;
}

char *cfg_get_my_noti_uri(main_ctx_t *MAIN_CTX)
{
	/* get ip */
	config_setting_t *setting_svc_nic = NULL;
	if ((setting_svc_nic = config_lookup(&MAIN_CTX->CFG, CF_SVC_NIC)) == NULL) {
		fprintf(stderr, "TODO| cant find .cfg (%s)\n", CF_SVC_NIC);
		return strdup("unknown");
	}
	char ipv4_address[1024] = {0,};
	get_svc_ipv4_addr(config_setting_get_string(setting_svc_nic), ipv4_address);

	/* get port */
	config_setting_t *setting_svc_port = NULL;
	if ((setting_svc_port = config_lookup(&MAIN_CTX->CFG, CF_NOTIFY_PORT)) == NULL) {
		fprintf(stderr, "TODO| cant find .cfg (%s)\n", CF_NOTIFY_PORT);
		return strdup("unknown");
	}

	// TODO!!! change NOTI PATH
	char temp[1024] = {0,};
	sprintf(temp, "https://%s:%d%s", ipv4_address, config_setting_get_int(setting_svc_port), PATH_HTTPS_RECV_NOTIFY);
	char *res = strdup(temp);

	return res;
}

char *cfg_get_my_recovery_time(main_ctx_t *MAIN_CTX)
{
	config_setting_t *setting_recovery_time = NULL;
	if ((setting_recovery_time = config_lookup(&MAIN_CTX->CFG, CF_RECOVERY_TIME)) == NULL) {
		APPLOG(APPLOG_ERR, "TODO| cant find .cfg (%s)", CF_RECOVERY_TIME);
		return strdup("unknown");
	}

	const char *recovery_time = config_setting_get_string(setting_recovery_time);

	char temp[1024] = {0,};
	sprintf(temp, "%s", recovery_time);
	char *res = strdup(temp);

	return res;
}

char *cfg_get_my_uuid(main_ctx_t *MAIN_CTX)
{
	config_setting_t *setting_uuid_file = NULL;
	if ((setting_uuid_file = config_lookup(&MAIN_CTX->CFG, CF_UUID_FILE)) == NULL) {
		APPLOG(APPLOG_ERR, "TODO| cant find .cfg (%s)", CF_UUID_FILE);
		return strdup("unknown");
	}

	const char *filename = config_setting_get_string(setting_uuid_file);
	char *buffer = NULL;

	get_file_contents(filename, &buffer);
	json_object *vnf_file_obj = json_tokener_parse(buffer);

	json_object *js_vnf_uuid = NULL;
	char key[128] = "VNF_INSTANCE_ID";

	if ((js_vnf_uuid = search_json_object(vnf_file_obj, key)) == NULL) {
		APPLOG(APPLOG_ERR, "TODO| cant find in (%s) VNF_INSTANCE_ID", CF_UUID_FILE);
		return strdup("unknown");
	}

	char temp[1024] = {0,};
	sprintf(temp, "%s", json_object_get_string(js_vnf_uuid));
	char *res = strdup(temp);

	json_object_put(vnf_file_obj); // release tok obj
	free(buffer);

	return res;
}

char *cfg_get_nf_info(nf_retrieve_info_t *nf_retr_info)
{
	char temp[1024] = {0,};
	if (!strcmp(nf_retr_info->nf_type, "UDM")) {
		sprintf(temp, "/udmInfo");
	} else if (!strcmp(nf_retr_info->nf_type, "UDR")) {
		sprintf(temp, "/udrInfo");
	} else {
		sprintf(temp, "/unknwon");
	}

	char *res = strdup(temp);

	return res;
}

char *cfg_get_nf_type(nf_retrieve_info_t *nf_retr_info)
{
	char temp[1024] = {0,};
	if (!strcmp(nf_retr_info->nf_type, "UDM")) {
		sprintf(temp, "UDM");
	} else if (!strcmp(nf_retr_info->nf_type, "UDR")) {
		sprintf(temp, "UDR");
	} else {
		sprintf(temp, "UNKNOWN");
	}

	char *res = strdup(temp);

	return res;
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

json_object *create_json_with_cfg(config_t *CFG)
{
	// don't json_object_put() this
	json_object *js_raw_profile = json_object_new_object();

	config_setting_t *setting = NULL;
	if ((setting = config_lookup(CFG, CF_MY_PROFILE)) == NULL) {
		APPLOG(APPLOG_ERR, "fail to find my_profile!");
		return NULL;
	} 

	cnvt_cfg_to_json(js_raw_profile, setting, CONFIG_TYPE_GROUP);

	if (js_raw_profile == NULL) {
		APPLOG(APPLOG_ERR, "fail to create my_profile!");
		return NULL;
	}
	return js_raw_profile;
}

void fep_service_log(fep_service_t *svc_elem)
{
	APPLOG(APPLOG_ERR, "{{{CHECK}}} svc_elem (svc_name[%s] path(for load)[%s] (for_capacity)[%s]) exist!",
			svc_elem->service_name, svc_elem->path_for_load, svc_elem->path_for_capacity);
}

int init_cfg(config_t *CFG)
{
	char conf_path[1024] = {0,};
	sprintf(conf_path,"%s/data/nrfm.cfg", getenv(IV_HOME));
	if (!config_read_file(CFG, conf_path)) {
		fprintf(stderr, "config read fail! (%s|%d - %s)\n",
				config_error_file(CFG),
				config_error_line(CFG),
				config_error_text(CFG));
		return (-1);
	} else {
		fprintf(stderr, "TODO| config read from ./nrfm.cfg success!\n");
	}

	// save with indent
	config_set_tab_width(CFG, 4);
	config_write_file(CFG, conf_path);

	// set info to cfg
	set_cfg_sys_info(CFG);

	return 0;
}

int json_set_val_by_type(json_object *dst, json_object *new_value)
{
	int json_type = json_object_get_type(dst);

	switch(json_type) {
		case json_type_int:
			return json_object_set_int(dst, json_object_get_int(new_value));
		case json_type_string:        
			return json_object_set_string(dst, json_object_get_string(new_value));
		case json_type_boolean:
			return json_object_set_boolean(dst, json_object_get_boolean(new_value));
		case json_type_double:
			return json_object_set_double(dst, json_object_get_double(new_value));

		case json_type_object:
		case json_type_array:
		default:
			APPLOG(APPLOG_ERR, "{{{DBG}}} %s can't handle this type(object|array)", __func__);
			return (-1);
	}

}

void log_all_cfg_retrieve_list(main_ctx_t *MAIN_CTX)
{
	g_slist_foreach(MAIN_CTX->nf_retrieve_list, (GFunc)log_cfg_retrieve_list, NULL);
}

void log_all_cfg_subscribe_list(main_ctx_t *MAIN_CTX)
{
	g_slist_foreach(MAIN_CTX->nf_retrieve_list, (GFunc)log_cfg_subscribe_list, NULL);
}

int load_cfg_retrieve_list(main_ctx_t *MAIN_CTX)
{
	config_setting_t *setting_retrieval = config_lookup(&MAIN_CTX->CFG, CF_NRF_RETRIEVAL);
	if (setting_retrieval == NULL)
		return 0;

	int nf_type_num = config_setting_length(setting_retrieval);

	for (int i = 0; i < nf_type_num; i++) {
		config_setting_t *elem = config_setting_get_elem(setting_retrieval, i);
		config_setting_t *cf_nf_type = config_setting_lookup(elem, "nf-type");
		config_setting_t *cf_limit = config_setting_lookup(elem, "limit");

		if (cf_nf_type == NULL || cf_limit == NULL) {
			APPLOG(APPLOG_ERR, "{{{DBG}}} %s() config [%s:%dth] wrong!",
					__func__, CF_NRF_RETRIEVAL, i);
			continue;
		}

		nf_retrieve_info_t *retrieve_item = malloc(sizeof(nf_retrieve_info_t));
		memset(retrieve_item, 0x00, sizeof(nf_retrieve_info_t));

		sprintf(retrieve_item->nf_type, config_setting_get_string(cf_nf_type));
		retrieve_item->limit = config_setting_get_int(cf_limit);

		MAIN_CTX->nf_retrieve_list = g_slist_append(MAIN_CTX->nf_retrieve_list, retrieve_item);
	}

	return nf_type_num;
}

int load_cfg_subscribe_list(main_ctx_t *MAIN_CTX)
{
	config_setting_t *setting = NULL;

	if ((setting = config_lookup(&MAIN_CTX->CFG, CF_SUBSCRIBE_FORM)) == NULL) {
		APPLOG(APPLOG_ERR, "fail to find subscribe_form!");
		return 0;
	}   

	int nf_type_num = g_slist_length(MAIN_CTX->nf_retrieve_list);
	for (int i = 0; i < nf_type_num; i++) {
		nf_retrieve_info_t *nf_retr_info = g_slist_nth_data(MAIN_CTX->nf_retrieve_list, i);
		nf_retr_info->js_subscribe_request = json_object_new_object();

		cnvt_cfg_to_json(nf_retr_info->js_subscribe_request, setting, CONFIG_TYPE_GROUP);
		recurse_json_obj(nf_retr_info->js_subscribe_request, MAIN_CTX, nf_retr_info);
	}

	return nf_type_num;
}

void log_cfg_retrieve_list(nf_retrieve_info_t *nf_retr_info)
{
	APPLOG(APPLOG_ERR, "{{{DBG}}} retrieve list include nf_type[%s] limit[%d]",
			nf_retr_info->nf_type, nf_retr_info->limit);
}

void log_cfg_subscribe_list(nf_retrieve_info_t *nf_retr_info)
{
	LOG_JSON_OBJECT("MY SUBSCRIBE REQUEST IS", nf_retr_info->js_subscribe_request);
}

void recurse_json_obj(json_object *input_obj, main_ctx_t *MAIN_CTX, nf_retrieve_info_t *nf_retr_info)
{
	json_object_object_foreach(input_obj, key, val) {
		json_object *obj = json_object_object_get(input_obj, key);
		if (obj == NULL) {
			APPLOG(APPLOG_ERR, "%s() obj null! continue!", __func__);
			continue;
		}

		enum json_type o_type = json_object_get_type(obj);

		if (o_type == json_type_array) {
			for (int i = 0; i < json_object_array_length(obj); i++) {
				json_object *list = json_object_array_get_idx(obj, i);
				json_type l_type = json_object_get_type(list);
				if (l_type == json_type_array || l_type == json_type_object) {
					recurse_json_obj(list, MAIN_CTX, nf_retr_info);
				} else {
					char js_val[1024] = {0,};
					sprintf(js_val, "%s", json_object_get_string(list));
					if (!strncmp(js_val, "$func", 4)) {
						/* hold index & replace it */
						json_object_array_del_idx(obj, i, 1);
						char *replace_val = replace_json_val(js_val, MAIN_CTX, nf_retr_info);
						json_object_array_put_idx(obj, i, json_object_new_string(replace_val));
						free(replace_val);
					}
				}
			}
		} else if (o_type == json_type_object) {
			recurse_json_obj(obj, MAIN_CTX, nf_retr_info);
		} else {
			char js_val[1024] = {0,};
			sprintf(js_val, "%s", json_object_get_string(obj));
			if (!strncmp(js_val, "$func", 4)) {
				char *replace_val = replace_json_val(js_val, MAIN_CTX, nf_retr_info);
				json_object_set_string(obj, replace_val);
				free(replace_val);
			}
		}
	}
}

// CAUTION!!! must free to return val
char *replace_json_val(const char *input_str, main_ctx_t *MAIN_CTX, nf_retrieve_info_t *nf_retr_info)
{
	APPLOG(APPLOG_ERR, "%s() called for [%s]", __func__, input_str);
	/* for nf_profile */
	if (strstr(input_str, "$func_my_uuid")) {
		return cfg_get_my_uuid(MAIN_CTX);
	} else if (strstr(input_str, "$func_my_recovery_time")) {
		return cfg_get_my_recovery_time(MAIN_CTX);
	} else if (strstr(input_str, "func_my_ip")) {
		return cfg_get_my_ip(MAIN_CTX);
	}
	/* for subscribe form */
	else if (strstr(input_str, "$func_my_noti_uri")) {
		return cfg_get_my_noti_uri(MAIN_CTX);
	} else if (strstr(input_str, "$func_nf_type")) {
		return cfg_get_nf_type(nf_retr_info);
	} else if (strstr(input_str, "$func_nf_info")) {
		return cfg_get_nf_info(nf_retr_info);
	}

	return strdup("unknown");
}

/*
 search_json_object(/ausfInfo/supiRanges/0/start) -->

    "ausfInfo":{
      "groupId":"00",
      "supiRanges":[
        {
          "start":"4500070001000", * <-- here
          "end":"4500070001999"
        },
        {
          "start":"6666070001000",
          "end":"7777070001999"
        }
      ],
   }
*/
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

void set_cfg_sys_info(config_t *CFG)
{
	/* ISO 8601 time format */
	config_setting_t *setting_recovery_time = config_lookup(CFG, CF_RECOVERY_TIME);
	if (setting_recovery_time == NULL) {
		fprintf(stderr, "TODO| config read fail (%s)\n", CF_RECOVERY_TIME);
	} else {
		char buf[1024] = {0,};
		time_t now = time(NULL);
		struct tm *cnvt_tm = localtime(&now);
		strftime(buf, sizeof(buf), "%FT%TZ", cnvt_tm);
		config_setting_set_string(setting_recovery_time, buf);
		fprintf(stderr, "TODO| %s is now [%s]\n", 
				CF_RECOVERY_TIME, config_setting_get_string(setting_recovery_time));
	}
}
