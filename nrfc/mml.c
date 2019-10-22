#include <nrfc.h>

extern main_ctx_t MAIN_CTX;

void init_mml(main_ctx_t *MAIN_CTX)
{
	APPLOG(APPLOG_ERR, "{{{DBG}}} %s called", __func__);

	config_setting_t *mml_list = config_lookup(&MAIN_CTX->CFG, "mml_list");
	int mml_num = config_setting_length(mml_list);

	for (int i = 0; i < mml_num; i++) {
		config_setting_t *mml_item = config_setting_get_elem(mml_list, i);
		config_setting_t *mml_type = config_setting_lookup(mml_item, "nfProfile.nfType");
		config_setting_t *mml_profile = config_setting_lookup(mml_item, "nfProfile");
		config_setting_t *mml_target = config_setting_lookup(mml_item, "target_hostname");

		if (mml_item == NULL)
			continue;
		if (mml_type == NULL)
			continue;
		if (mml_profile == NULL)
			continue;
		if (mml_target == NULL)
			continue;

		mml_append_item_to_list(MAIN_CTX, 
				mml_item, 
				config_setting_get_string(mml_type), 
				mml_profile, 
				config_setting_get_string(mml_target));
	}
}

void destry_mml(mml_conf_t *mml_conf, main_ctx_t *MAIN_CTX)
{
	MAIN_CTX->opr_mml_list = g_slist_remove(MAIN_CTX->opr_mml_list, mml_conf);

	if (mml_conf->js_raw_profile)
		json_object_put(mml_conf->js_raw_profile);
	free(mml_conf);
}

void reload_mml(main_ctx_t *MAIN_CTX)
{
	APPLOG(APPLOG_ERR, "{{{DBG}}} %s called", __func__);

	// remove all
	g_slist_foreach(MAIN_CTX->opr_mml_list, (GFunc)destry_mml, MAIN_CTX);

	// remake 
	init_mml(MAIN_CTX);
}

void mml_append_item_to_list(main_ctx_t *MAIN_CTX, config_setting_t *mml_item, const char *nf_type_str, config_setting_t *mml_profile, const char *hostname)
{
	APPLOG(APPLOG_ERR, "{{{DBG}}} %s called", __func__);

	mml_conf_t *mml_conf = malloc(sizeof(mml_conf_t));
	memset(mml_conf, 0x00, sizeof(mml_conf_t));

	/* ADD NAME TAG */
	sprintf(mml_conf->conf_name, "%s", mml_item->name);

	/* ADD NF TYPE */
	sprintf(mml_conf->nf_type, "%s", nf_type_str);

	/* SAVE RAW JS PROFILE */
	mml_conf->js_raw_profile = json_object_new_object();
	cnvt_cfg_to_json(mml_conf->js_raw_profile, mml_profile, CONFIG_TYPE_GROUP);

	json_object *js_nf_profile = json_object_object_get(mml_conf->js_raw_profile, "nfProfile");

	/* SETTING SPECIFIC (UDM UDR ...) INFO */
	nf_service_info *service_info = &mml_conf->service_info;

	json_object *js_specific_info = NULL;
	int nfType = service_info->nfType = nf_search_specific_info(js_nf_profile, &js_specific_info);

	nf_get_specific_info(nfType, js_specific_info, &service_info->nfTypeInfo);

	/* SET SERVICE */
	json_object *js_nf_service = json_object_object_get(js_nf_profile, "serviceName");
	if (js_nf_service) {
		sprintf(service_info->serviceName, "%s", json_object_get_string(js_nf_service));
	}

	/* SET ALLOWD PLMN */
	service_info->allowdPlmnsNum = nf_get_allowd_plmns(js_nf_profile, &service_info->allowdPlmns[0]);

	/* SET TARGET HOST NAME */
	sprintf(mml_conf->target_hostname, "%s", hostname);

	/* APPEND TO LIST */
	MAIN_CTX->opr_mml_list = g_slist_append(MAIN_CTX->opr_mml_list, mml_conf);

	APPLOG(APPLOG_ERR, "TEST || mml append now mml num is [%d]", g_slist_length(MAIN_CTX->opr_mml_list));
}
