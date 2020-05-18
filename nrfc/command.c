#include <nrfc.h>

extern main_ctx_t MAIN_CTX;

char mySysName[COMM_MAX_NAME_LEN];
char myProcName[COMM_MAX_NAME_LEN];
int ixpcQid;
char respMsg[MAX_MML_RESULT_LEN], respBuff[MAX_MML_RESULT_LEN];

typedef enum nrfc_cmd {
	dis_nf_status,
	dis_nf_mml,
	add_nf_mml,
	del_nf_mml,
	MAX_CMD_NUM
} nrfc_cmd_t;

MmcHdlrVector   mmcHdlrVecTbl[MAX_CMD_NUM] =
{ 
	{ "DIS-NF-STATUS",  func_dis_nf_status},
	{ "DIS-NF-MML",		func_dis_nf_mml},
	{ "ADD-NF-MML",		func_add_nf_mml},
	{ "DEL-NF-MML",		func_del_nf_mml}
};

void init_cmd(main_ctx_t *MAIN_CTX)
{
	sprintf(mySysName, "%s", MAIN_CTX->my_info.mySysName);
	sprintf(myProcName, "%s", MAIN_CTX->my_info.myProcName);
	ixpcQid = MAIN_CTX->my_qid.ixpc_qid;
}

void message_handle(evutil_socket_t fd, short what, void *arg)
{
    char msgBuff[1024*64];

    GeneralQMsgType *msg = (GeneralQMsgType *)msgBuff;

    while (msgrcv(MAIN_CTX.my_qid.nrfc_qid, msg, sizeof(GeneralQMsgType), 0, IPC_NOWAIT|MSG_NOERROR) >= 0) {
        switch (msg->mtype) {
			case MTYPE_MMC_REQUEST:
				mml_function((IxpcQMsgType *)msg->body);
				continue;
			case MTYPE_SETPRINT:
				adjust_loglevel((TrcLibSetPrintMsgType *)msg);
				continue;
            // TODO !!! check & broadcast
			case MSGID_NRF_LIB_NRFC_REQ_PROFILE:
				handle_appl_req_with_profile(&MAIN_CTX, (nf_disc_host_info *)msg);
				continue;
			case MSGID_NRF_LIB_NRFC_REQ_CALLBACK:
				handle_appl_req_with_cbinfo(&MAIN_CTX, (http_conn_handle_req_t *)msg);
				continue;
            default:
                APPLOG(APPLOG_ERR, "%s() receive unknown msg (mtype:%ld)", __func__, (long)msg->mtype);
                continue;
        }
    }
    if (errno != ENOMSG) {
        APPLOG(APPLOG_ERR,"%s() msgrcv fail; err=%d(%s)", __func__, errno, strerror(errno));
    }

    return;
}

void mml_function(IxpcQMsgType *rxIxpcMsg)
{
	int i;
	MMLReqMsgType   *mmlReq=(MMLReqMsgType*)rxIxpcMsg->body;
	MmcHdlrVector   mmcHdlr;

	APPLOG(APPLOG_DEBUG, "%s() receive cmdName(%s)", __func__, mmlReq->head.cmdName);

	for (i = 0; i < MAX_CMD_NUM; i++) {
		if (!strncasecmp(mmlReq->head.cmdName, mmcHdlrVecTbl[i].cmdName, strlen(mmcHdlrVecTbl[i].cmdName))) {
			mmcHdlr.func = mmcHdlrVecTbl[i].func;
			break;
		}
	}

	if (i >= MAX_CMD_NUM) {
		APPLOG(APPLOG_ERR, "%s() not registered mml_cmd(%s) received!", __func__, mmlReq->head.cmdName);
	} else {
		respMsg[0]  = '\0';
		respBuff[0] = '\0';
		(int)(*(mmcHdlr.func)) (rxIxpcMsg);
	}
}

void adjust_loglevel(TrcLibSetPrintMsgType *trcMsg)
{
    if (trcMsg->trcLogFlag.pres) {
        if (trcMsg->trcLogFlag.octet == 9) {
            MAIN_CTX.sysconfig.debug_mode = (MAIN_CTX.sysconfig.debug_mode == 1 ? 0 : 1);
            APPLOG(APPLOG_ERR,"---- log level 9 (debug_mode on/off) now [%s]", MAIN_CTX.sysconfig.debug_mode == 1 ? "ON" : "OFF");
        } else {
            APPLOG(APPLOG_ERR,"---- log level change (%d -> %d)\n", *lOG_FLAG, trcMsg->trcLogFlag.octet);
            *lOG_FLAG = trcMsg->trcLogFlag.octet;
        }
    }
}

void get_connected_lb_str(main_ctx_t *MAIN_CTX, char *hostname, char *printBuff)
{
    nf_list_shm_t *nf_avail_shm = &MAIN_CTX->SHM_NFS_AVAIL->nfs_avail_shm[MAIN_CTX->SHM_NFS_AVAIL->curr_pos];

    for (int i = 0; i < NF_MAX_LB_NUM; i++) {
        for (int k = 0; k < NF_MAX_AVAIL_LIST; k++) {
            nf_service_info *nf_avail = &nf_avail_shm->nf_avail[i][k];
            if (nf_avail->occupied == 0)
                continue;
            if (nf_avail->auto_add != NF_ADD_RAW)
                continue;
            if (nf_avail->available == 0)
                continue;
            if (!strcmp(nf_avail->hostname, hostname)) {
                sprintf(printBuff + strlen(printBuff), "[lb_%02d: OK]\n", nf_avail->lbId);
                break;
            }
        }
    }
}

void printf_nf_mml(main_ctx_t *MAIN_CTX, char *printBuff, char *filter_type, char *filter_host)
{
	APPLOG(APPLOG_ERR, "{{{DBG}}} %s called!", __func__);

	ft_table_t *table = ft_create_table();

	ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);
	ft_set_border_style(table, FT_PLAIN_STYLE);

	ft_write_ln(table, "ID", "CONFIG NAME", "NF_TYPE", "SVC_NAME", "COMM_INFO", "TYPE_INFO", "HOSTNAME", "CONN_STS");

	int mml_count = g_slist_length(MAIN_CTX->opr_mml_list);

	for (int i = 0; i < mml_count; i++) {
		mml_conf_t *mml_conf = g_slist_nth_data(MAIN_CTX->opr_mml_list, i);
        nf_service_info *svc_info = &mml_conf->service_info;

        if (filter_type != NULL && strcmp(filter_type, mml_conf->nf_type))
            continue;
        if (filter_host != NULL && strcmp(filter_host, mml_conf->target_hostname))
            continue;

        char plmnStr[1024] = {0,};
        char typeStr[1024] = {0,};
        nf_get_allowd_plmns_str(svc_info->allowdPlmnsNum, svc_info->allowdPlmns, plmnStr);
        nf_get_specific_info_str(svc_info->nfType, &svc_info->nfTypeInfo, typeStr);

        char connStr[1024] = {0,};
        get_connected_lb_str(MAIN_CTX, mml_conf->target_hostname, connStr);

        ft_printf_ln(table, "%d|%s|%s|%s|%s|%s|%s|%s",
                i,
                mml_conf->conf_name, 
                mml_conf->nf_type,
                svc_info->serviceName,
                plmnStr,
                typeStr,
                mml_conf->target_hostname,
                connStr);
        ft_add_separator(table);
    }

	if (printBuff != NULL) {
		sprintf(printBuff, "%s", ft_to_string(table));
	} else {
		APPLOG(APPLOG_ERR, "\n%s", ft_to_string(table));
	}

	ft_destroy_table(table);
}

void printf_fep_nfs(nfs_avail_shm_t *SHM_NFS_AVAIL, char *printBuff)
{
	APPLOG(APPLOG_ERR, "{{{DBG}}} %s called!", __func__);

	ft_table_t *table = ft_create_table();

	ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);
	ft_set_border_style(table, FT_PLAIN_STYLE);

	ft_write_ln(table, "INDEX", "TYPE", "SERVICE", "ALLOWEDPLMNS\n(MCC+MNC)", "TYPEINFO", "HOSTNAME", "SCHEME", "IPV4", "PORT", "PRIORITY", "LOAD", "AUTO", "LB_ID(SHM_IDX)");

	int POS = SHM_NFS_AVAIL->curr_pos;
	nf_list_shm_t *nf_avail_shm = &SHM_NFS_AVAIL->nfs_avail_shm[POS];

	for (int i = 0, index = 0; i < NF_MAX_LB_NUM; i++) {
		for (int k = 0; k < NF_MAX_AVAIL_LIST; k++) {
			nf_service_info *nf_info = &nf_avail_shm->nf_avail[i][k];

			if (nf_info->occupied <= 0)
				continue;

			/* allowd plmns */
			char allowdPlmnsStr[1024] = {0,};
			nf_get_allowd_plmns_str(nf_info->allowdPlmnsNum, nf_info->allowdPlmns, allowdPlmnsStr);

			/* nf-type specific info */
			char typeSpecStr[1024] = {0,};
            nf_get_specific_info_str(nf_info->nfType, &nf_info->nfTypeInfo, typeSpecStr);

			ft_printf_ln(table, "%d|%s|%s|%s|%s|%s|%s|%s|%d|%d|%d|%s(%d)|%d(%d)",
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
					nf_info->load,
					nf_info->auto_add == NF_ADD_MML ? "MML" :
					nf_info->auto_add == NF_ADD_NRF ? "NRF" :
					nf_info->auto_add == NF_ADD_CALLBACK ? "API" : "RAW",
					nf_info->auto_add,
					nf_info->lbId, i);
			ft_add_separator(table);
		}
	}

	if (printBuff != NULL) {
		sprintf(printBuff, "%s", ft_to_string(table));
	} else {
		APPLOG(APPLOG_ERR, "\n%s", ft_to_string(table));
	}

	ft_destroy_table(table);
}


int func_dis_nf_status(IxpcQMsgType *rxIxpcMsg)
{
	APPLOG(APPLOG_DEBUG, "%s() called", __func__);

    MMLReqMsgType   *mmlReq=(MMLReqMsgType*)rxIxpcMsg->body;

    char nf_type[32] = {0,};

    get_mml_para_str(mmlReq, "NF_TYPE", nf_type);
    if (strlen(nf_type) > 0)
        strupr(nf_type, strlen(nf_type));

	char *resBuf = malloc(1024 * 1024 * 12);
	resBuf[0] = '\0';

    if (!strcmp(nf_type, "DUMP"))
        printf_fep_nfs(MAIN_CTX.SHM_NFS_AVAIL, resBuf);
    else 
        printf_fep_nfs_well_form(MAIN_CTX.root_node, resBuf, strlen(nf_type) > 0 ? nf_type : NULL);

	APPLOG(APPLOG_DETAIL, "%s() response is >>>\n%s", __func__, resBuf);
	int res = send_mml_res_succMsg(rxIxpcMsg, resBuf, FLAG_COMPLETE, 0, 0);

	free(resBuf);
	return res;
}

config_setting_t *config_setting_add_try(config_setting_t *parent, const char *name, int type)
{
    config_setting_t *setting = config_setting_add(parent, name, type);
    
    if (setting != NULL) {
        return setting;
    } else {
        return config_setting_get_member(parent, name);
    }
}

int add_cfg_nf_mml_udm(main_ctx_t *MAIN_CTX, const char *conf_name, const char *target_host, const char *nf_type, MMLReqMsgType *mmlReq, config_setting_t *mml_list, char *resBuf)
{
    char SVC_NAME[128] = {0,};

    char MCC_MNC1[128] = {0,};
    char MCC_MNC2[128] = {0,};
    char MCC_MNC3[128] = {0,};
    char *MCC1 = NULL, *MNC1 = NULL;
    char *MCC2 = NULL, *MNC2 = NULL;
    char *MCC3 = NULL, *MNC3 = NULL;

    char GROUP_ID[128] = {0,};

    char SUPI_RANGE1[128] = {0,};
    char SUPI_RANGE2[128] = {0,};
    char SUPI_RANGE3[128] = {0,};
    char *SP_START1 = NULL, *SP_END1 = NULL;
    char *SP_START2 = NULL, *SP_END2 = NULL;
    char *SP_START3 = NULL, *SP_END3 = NULL;

    char ROUTING_INDS[128] = {0,};

    get_mml_para_str(mmlReq, "SVC_NAME", SVC_NAME);
    if ((get_mml_para_str(mmlReq, "MCC_MNC1", MCC_MNC1) > 0 && divide_c_in_str(MCC_MNC1, '-', &MCC1, &MNC1) < 0) ||
        (get_mml_para_str(mmlReq, "MCC_MNC2", MCC_MNC2) > 0 && divide_c_in_str(MCC_MNC2, '-', &MCC2, &MNC2) < 0) ||
        (get_mml_para_str(mmlReq, "MCC_MNC3", MCC_MNC3) > 0 && divide_c_in_str(MCC_MNC3, '-', &MCC3, &MNC3) < 0)) {
        sprintf(resBuf, "MCC_MNC FORMAT MUST 000-00");
        return -1;
    }
    get_mml_para_str(mmlReq, "GROUP_ID", GROUP_ID);
    if ((get_mml_para_str(mmlReq, "SUPI_RANGE1", SUPI_RANGE1) > 0 && divide_c_in_str(SUPI_RANGE1, '~', &SP_START1, &SP_END1) < 0) ||
        (get_mml_para_str(mmlReq, "SUPI_RANGE2", SUPI_RANGE2) > 0 && divide_c_in_str(SUPI_RANGE2, '~', &SP_START2, &SP_END2) < 0) ||
        (get_mml_para_str(mmlReq, "SUPI_RANGE3", SUPI_RANGE3) > 0 && divide_c_in_str(SUPI_RANGE3, '~', &SP_START3, &SP_END3) < 0)) {
        sprintf(resBuf, "SUPI_RANGE FORMAT MUST 0000~0000");
        return -1;
    }
    get_mml_para_str(mmlReq, "ROUTING_INDS", ROUTING_INDS);


	APPLOG(APPLOG_ERR, "{{{DBG}}} %s try add [%s:%s:%s]", __func__, conf_name, nf_type, target_host);

	/* mandatory */
	config_setting_t *item = config_setting_add_try(mml_list, conf_name, CONFIG_TYPE_GROUP);

	config_setting_t *cf_target = config_setting_add_try(item, "target_hostname", CONFIG_TYPE_STRING);
	config_setting_set_string(cf_target, target_host);

	config_setting_t *cf_profile = config_setting_add_try(item, "nfProfile", CONFIG_TYPE_GROUP);

	config_setting_t *cf_nfType = config_setting_add_try(cf_profile, "nfType", CONFIG_TYPE_STRING);
	config_setting_set_string(cf_nfType, nf_type);

	if (strlen(SVC_NAME)) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s try set service=(%s)", __func__, SVC_NAME);
		config_setting_t *cf_service = config_setting_add_try(cf_profile, "serviceName", CONFIG_TYPE_STRING);
		config_setting_set_string(cf_service, SVC_NAME);
	}

	config_setting_t *cf_allowdPlmns = config_setting_add_try(cf_profile, "allowedPlmns", CONFIG_TYPE_LIST);

	if (strlen(MCC_MNC1)) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s try set mcc=(%s) mnc=(%s)", __func__, MCC1, MNC1);
		config_setting_t *cf_plmns = config_setting_add_try(cf_allowdPlmns, "", CONFIG_TYPE_GROUP);
		config_setting_t *cf_mcc = config_setting_add_try(cf_plmns, "mcc", CONFIG_TYPE_STRING);
		config_setting_t *cf_mnc = config_setting_add_try(cf_plmns, "mnc", CONFIG_TYPE_STRING);
		config_setting_set_string(cf_mcc, MCC1);
		config_setting_set_string(cf_mnc, MNC1);
	}
	if (strlen(MCC_MNC2)) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s try set mcc=(%s) mnc=(%s)", __func__, MCC2, MNC2);
		config_setting_t *cf_plmns = config_setting_add_try(cf_allowdPlmns, "", CONFIG_TYPE_GROUP);
		config_setting_t *cf_mcc = config_setting_add_try(cf_plmns, "mcc", CONFIG_TYPE_STRING);
		config_setting_t *cf_mnc = config_setting_add_try(cf_plmns, "mnc", CONFIG_TYPE_STRING);
		config_setting_set_string(cf_mcc, MCC2);
		config_setting_set_string(cf_mnc, MNC2);
	}
	if (strlen(MCC_MNC3)) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s try set mcc=(%s) mnc=(%s)", __func__, MCC3, MNC3);
		config_setting_t *cf_plmns = config_setting_add_try(cf_allowdPlmns, "", CONFIG_TYPE_GROUP);
		config_setting_t *cf_mcc = config_setting_add_try(cf_plmns, "mcc", CONFIG_TYPE_STRING);
		config_setting_t *cf_mnc = config_setting_add_try(cf_plmns, "mnc", CONFIG_TYPE_STRING);
		config_setting_set_string(cf_mcc, MCC3);
		config_setting_set_string(cf_mnc, MNC3);
	}

	config_setting_t *cf_udmInfo = config_setting_add_try(cf_profile, "udmInfo", CONFIG_TYPE_GROUP);

	if (strlen(GROUP_ID)) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s try set groupId=(%s)", __func__, GROUP_ID);
		config_setting_t *cf_group_id = config_setting_add_try(cf_udmInfo, "groupId", CONFIG_TYPE_STRING);
		config_setting_set_string(cf_group_id, GROUP_ID);
	}

	if (strlen(SUPI_RANGE1)) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s try set start=(%s) end=(%s)", __func__, SP_START1, SP_END1);
		config_setting_t *cf_supi_ranges = config_setting_add_try(cf_udmInfo, "supiRanges", CONFIG_TYPE_LIST);
		config_setting_t *cf_supi = config_setting_add_try(cf_supi_ranges, "", CONFIG_TYPE_GROUP);
		config_setting_t *cf_start = config_setting_add_try(cf_supi, "start", CONFIG_TYPE_STRING);
		config_setting_t *cf_end = config_setting_add_try(cf_supi, "end", CONFIG_TYPE_STRING);
		config_setting_set_string(cf_start, SP_START1);
		config_setting_set_string(cf_end, SP_END1);
	}
	if (strlen(SUPI_RANGE2)) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s try set start=(%s) end=(%s)", __func__, SP_START2, SP_END2);
		config_setting_t *cf_supi_ranges = config_setting_add_try(cf_udmInfo, "supiRanges", CONFIG_TYPE_LIST);
		config_setting_t *cf_supi = config_setting_add_try(cf_supi_ranges, "", CONFIG_TYPE_GROUP);
		config_setting_t *cf_start = config_setting_add_try(cf_supi, "start", CONFIG_TYPE_STRING);
		config_setting_t *cf_end = config_setting_add_try(cf_supi, "end", CONFIG_TYPE_STRING);
		config_setting_set_string(cf_start, SP_START2);
		config_setting_set_string(cf_end, SP_END2);
	}
	if (strlen(SUPI_RANGE3)) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s try set start=(%s) end=(%s)", __func__, SP_START3, SP_END3);
		config_setting_t *cf_supi_ranges = config_setting_add_try(cf_udmInfo, "supiRanges", CONFIG_TYPE_LIST);
		config_setting_t *cf_supi = config_setting_add_try(cf_supi_ranges, "", CONFIG_TYPE_GROUP);
		config_setting_t *cf_start = config_setting_add_try(cf_supi, "start", CONFIG_TYPE_STRING);
		config_setting_t *cf_end = config_setting_add_try(cf_supi, "end", CONFIG_TYPE_STRING);
		config_setting_set_string(cf_start, SP_START3);
		config_setting_set_string(cf_end, SP_END3);
	}

	if (strlen(ROUTING_INDS)) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s try set routingIndicators=(%s)", __func__, ROUTING_INDS);
        config_setting_t *cf_routing_indicators = config_setting_add_try(cf_udmInfo, "routingIndicators", CONFIG_TYPE_ARRAY);

        char *ptr = strtok(ROUTING_INDS, "_");
        int ri_nums = 0;

        while (ptr != NULL && ri_nums++ < NF_MAX_RI) {
            
            config_setting_t *cf_ri = config_setting_add_try(cf_routing_indicators, "", CONFIG_TYPE_STRING);
            config_setting_set_string(cf_ri, ptr);

            ptr = strtok(NULL, "_");
        }
	}

	write_cfg(MAIN_CTX);

	reload_mml(MAIN_CTX);

	printf_nf_mml(MAIN_CTX, resBuf, NULL, NULL);

	return 0;
}

void add_cfg_nf_mml_guami_plmn(config_setting_t *cf_guami, const char *plmn_str)
{
    config_setting_t *cf_plmn = config_setting_add_try(cf_guami, "plmnId", CONFIG_TYPE_GROUP);
    config_setting_t *cf_mcc = config_setting_add_try(cf_plmn, "mcc", CONFIG_TYPE_STRING);
    config_setting_t *cf_mnc = config_setting_add_try(cf_plmn, "mnc", CONFIG_TYPE_STRING);
    char mcc[128] = {0,};
    char mnc[128] = {0,};
    sscanf(plmn_str, "%127[^-]-%127s", mcc, mnc);
    config_setting_set_string(cf_mcc, mcc);
    config_setting_set_string(cf_mnc, mnc);
}

int add_cfg_nf_mml_amf(main_ctx_t *MAIN_CTX, const char *conf_name, const char *target_host, const char *nf_type, MMLReqMsgType *mmlReq, config_setting_t *mml_list, char *resBuf)
{
    char SVC_NAME[128] = {0,};

    char MCC_MNC1[128] = {0,};
    char MCC_MNC2[128] = {0,};
    char MCC_MNC3[128] = {0,};
    char *MCC1 = NULL, *MNC1 = NULL;
    char *MCC2 = NULL, *MNC2 = NULL;
    char *MCC3 = NULL, *MNC3 = NULL;

    char REGION_ID[128] = {0,};
    char SET_ID[128] = {0,};

    char GM_PLMN1[128] = {0,};
    char GM_AMF1[128] = {0,};
    char GM_PLMN2[128] = {0,};
    char GM_AMF2[128] = {0,};
    char GM_PLMN3[128] = {0,};
    char GM_AMF3[128] = {0,};
    char GM_PLMN4[128] = {0,};
    char GM_AMF4[128] = {0,};
    char GM_PLMN5[128] = {0,};
    char GM_AMF5[128] = {0,};

    get_mml_para_str(mmlReq, "SVC_NAME", SVC_NAME);
    if ((get_mml_para_str(mmlReq, "MCC_MNC1", MCC_MNC1) > 0 && divide_c_in_str(MCC_MNC1, '-', &MCC1, &MNC1) < 0) ||
        (get_mml_para_str(mmlReq, "MCC_MNC2", MCC_MNC2) > 0 && divide_c_in_str(MCC_MNC2, '-', &MCC2, &MNC2) < 0) ||
        (get_mml_para_str(mmlReq, "MCC_MNC3", MCC_MNC3) > 0 && divide_c_in_str(MCC_MNC3, '-', &MCC3, &MNC3) < 0)) {
        sprintf(resBuf, "MCC_MNC FORMAT MUST 000-00");
        return -1;
    }
    get_mml_para_str(mmlReq, "REGION_ID", REGION_ID);
    get_mml_para_str(mmlReq, "SET_ID", SET_ID);

    if ((get_mml_para_str(mmlReq, "GM_PLMN1", GM_PLMN1) > 0 && search_c_in_str(GM_PLMN1, '-') < 0) ||
        (get_mml_para_str(mmlReq, "GM_PLMN2", GM_PLMN2) > 0 && search_c_in_str(GM_PLMN1, '-') < 0) || 
        (get_mml_para_str(mmlReq, "GM_PLMN3", GM_PLMN3) > 0 && search_c_in_str(GM_PLMN1, '-') < 0) ||
        (get_mml_para_str(mmlReq, "GM_PLMN4", GM_PLMN4) > 0 && search_c_in_str(GM_PLMN1, '-') < 0) ||
        (get_mml_para_str(mmlReq, "GM_PLMN5", GM_PLMN5) > 0 && search_c_in_str(GM_PLMN1, '-') < 0)) {
        sprintf(resBuf, "GM_PLMN FORMAT MUST 000-00|000-000");
        return -1;
    }
    get_mml_para_str(mmlReq, "GM_AMF1", GM_AMF1);
    get_mml_para_str(mmlReq, "GM_AMF2", GM_AMF2);
    get_mml_para_str(mmlReq, "GM_AMF3", GM_AMF3);
    get_mml_para_str(mmlReq, "GM_AMF4", GM_AMF4);
    get_mml_para_str(mmlReq, "GM_AMF5", GM_AMF5);

    /* mandatory */
    config_setting_t *item = config_setting_add_try(mml_list, conf_name, CONFIG_TYPE_GROUP);

    config_setting_t *cf_target = config_setting_add_try(item, "target_hostname", CONFIG_TYPE_STRING);
    config_setting_set_string(cf_target, target_host);

    config_setting_t *cf_profile = config_setting_add_try(item, "nfProfile", CONFIG_TYPE_GROUP);

    config_setting_t *cf_nfType = config_setting_add_try(cf_profile, "nfType", CONFIG_TYPE_STRING);
    config_setting_set_string(cf_nfType, nf_type);

    if (strlen(SVC_NAME)) {
        APPLOG(APPLOG_ERR, "{{{DBG}}} %s try set service=(%s)", __func__, SVC_NAME);
        config_setting_t *cf_service = config_setting_add_try(cf_profile, "serviceName", CONFIG_TYPE_STRING);
        config_setting_set_string(cf_service, SVC_NAME);
    }

    config_setting_t *cf_allowdPlmns = config_setting_add_try(cf_profile, "allowedPlmns", CONFIG_TYPE_LIST);

    if (strlen(MCC_MNC1)) {
        APPLOG(APPLOG_ERR, "{{{DBG}}} %s try set mcc=(%s) mnc=(%s)", __func__, MCC1, MNC1);
        config_setting_t *cf_plmns = config_setting_add_try(cf_allowdPlmns, "", CONFIG_TYPE_GROUP);
        config_setting_t *cf_mcc = config_setting_add_try(cf_plmns, "mcc", CONFIG_TYPE_STRING);
        config_setting_t *cf_mnc = config_setting_add_try(cf_plmns, "mnc", CONFIG_TYPE_STRING);
        config_setting_set_string(cf_mcc, MCC1);
        config_setting_set_string(cf_mnc, MNC1);
    }
    if (strlen(MCC_MNC2)) {
        APPLOG(APPLOG_ERR, "{{{DBG}}} %s try set mcc=(%s) mnc=(%s)", __func__, MCC2, MNC2);
        config_setting_t *cf_plmns = config_setting_add_try(cf_allowdPlmns, "", CONFIG_TYPE_GROUP);
        config_setting_t *cf_mcc = config_setting_add_try(cf_plmns, "mcc", CONFIG_TYPE_STRING);
        config_setting_t *cf_mnc = config_setting_add_try(cf_plmns, "mnc", CONFIG_TYPE_STRING);
        config_setting_set_string(cf_mcc, MCC2);
        config_setting_set_string(cf_mnc, MNC2);
    }
    if (strlen(MCC_MNC3)) {
        APPLOG(APPLOG_ERR, "{{{DBG}}} %s try set mcc=(%s) mnc=(%s)", __func__, MCC3, MNC3);
        config_setting_t *cf_plmns = config_setting_add_try(cf_allowdPlmns, "", CONFIG_TYPE_GROUP);
        config_setting_t *cf_mcc = config_setting_add_try(cf_plmns, "mcc", CONFIG_TYPE_STRING);
        config_setting_t *cf_mnc = config_setting_add_try(cf_plmns, "mnc", CONFIG_TYPE_STRING);
        config_setting_set_string(cf_mcc, MCC3);
        config_setting_set_string(cf_mnc, MNC3);
    }

    config_setting_t *cf_amf_info = config_setting_add_try(cf_profile, "amfInfo", CONFIG_TYPE_GROUP);

    if (strlen(REGION_ID)) {
        APPLOG(APPLOG_ERR, "{{{DBG}}} %s try set amfRegionId=(%s)", __func__, REGION_ID);
        config_setting_t *cf_region_id = config_setting_add_try(cf_amf_info, "amfRegionId", CONFIG_TYPE_STRING);
        config_setting_set_string(cf_region_id, REGION_ID);
    }

    if (strlen(SET_ID)) {
        APPLOG(APPLOG_ERR, "{{{DBG}}} %s try set amfSetId=(%s)", __func__, SET_ID);
        config_setting_t *cf_set_id = config_setting_add_try(cf_amf_info, "amfSetId", CONFIG_TYPE_STRING);
        config_setting_set_string(cf_set_id, SET_ID);
    }

    if (strlen(GM_PLMN1) || strlen(GM_AMF1)) {
        APPLOG(APPLOG_ERR, "{{{DBG}}} %s try set guamiPlmnList={plmnId=(%s), amfId=(%s)}", __func__, GM_PLMN1, GM_AMF1);
        config_setting_t *cf_guami_list = config_setting_add_try(cf_amf_info, "guamiList", CONFIG_TYPE_LIST);
        config_setting_t *cf_guami = config_setting_add_try(cf_guami_list, "", CONFIG_TYPE_GROUP);
        if (strlen(GM_PLMN1)) {
#if 0
            config_setting_t *cf_plmn = config_setting_add_try(cf_guami, "plmnId", CONFIG_TYPE_STRING);
            config_setting_set_string(cf_plmn, GM_PLMN1);
#else
            add_cfg_nf_mml_guami_plmn(cf_guami, GM_PLMN1);
#endif
        }
        if (strlen(GM_AMF1)) {
            config_setting_t *cf_amf_id = config_setting_add_try(cf_guami, "amfId", CONFIG_TYPE_STRING);
            config_setting_set_string(cf_amf_id, GM_AMF1);
        }
    }

    if (strlen(GM_PLMN2) || strlen(GM_AMF2)) {
        APPLOG(APPLOG_ERR, "{{{DBG}}} %s try set guamiPlmnList={plmnId=(%s), amfId=(%s)}", __func__, GM_PLMN2, GM_AMF2);
        config_setting_t *cf_guami_list = config_setting_add_try(cf_amf_info, "guamiList", CONFIG_TYPE_LIST);
        config_setting_t *cf_guami = config_setting_add_try(cf_guami_list, "", CONFIG_TYPE_GROUP);
        if (strlen(GM_PLMN2)) {
#if 0
            config_setting_t *cf_plmn = config_setting_add_try(cf_guami, "plmnId", CONFIG_TYPE_STRING);
            config_setting_set_string(cf_plmn, GM_PLMN2);
#else
            add_cfg_nf_mml_guami_plmn(cf_guami, GM_PLMN2);
#endif
        }
        if (strlen(GM_AMF2)) {
            config_setting_t *cf_amf_id = config_setting_add_try(cf_guami, "amfId", CONFIG_TYPE_STRING);
            config_setting_set_string(cf_amf_id, GM_AMF2);
        }
    }

    if (strlen(GM_PLMN3) || strlen(GM_AMF3)) {
        APPLOG(APPLOG_ERR, "{{{DBG}}} %s try set guamiPlmnList={plmnId=(%s), amfId=(%s)}", __func__, GM_PLMN3, GM_AMF3);
        config_setting_t *cf_guami_list = config_setting_add_try(cf_amf_info, "guamiList", CONFIG_TYPE_LIST);
        config_setting_t *cf_guami = config_setting_add_try(cf_guami_list, "", CONFIG_TYPE_GROUP);
        if (strlen(GM_PLMN3)) {
#if 0
            config_setting_t *cf_plmn = config_setting_add_try(cf_guami, "plmnId", CONFIG_TYPE_STRING);
            config_setting_set_string(cf_plmn, GM_PLMN3);
#else
            add_cfg_nf_mml_guami_plmn(cf_guami, GM_PLMN3);
#endif
        }
        if (strlen(GM_AMF3)) {
            config_setting_t *cf_amf_id = config_setting_add_try(cf_guami, "amfId", CONFIG_TYPE_STRING);
            config_setting_set_string(cf_amf_id, GM_AMF3);
        }
    }

    if (strlen(GM_PLMN4) || strlen(GM_AMF4)) {
        APPLOG(APPLOG_ERR, "{{{DBG}}} %s try set guamiPlmnList={plmnId=(%s), amfId=(%s)}", __func__, GM_PLMN4, GM_AMF4);
        config_setting_t *cf_guami_list = config_setting_add_try(cf_amf_info, "guamiList", CONFIG_TYPE_LIST);
        config_setting_t *cf_guami = config_setting_add_try(cf_guami_list, "", CONFIG_TYPE_GROUP);
        if (strlen(GM_PLMN4)) {
#if 0
            config_setting_t *cf_plmn = config_setting_add_try(cf_guami, "plmnId", CONFIG_TYPE_STRING);
            config_setting_set_string(cf_plmn, GM_PLMN4);
#else
            add_cfg_nf_mml_guami_plmn(cf_guami, GM_PLMN4);
#endif
        }
        if (strlen(GM_AMF4)) {
            config_setting_t *cf_amf_id = config_setting_add_try(cf_guami, "amfId", CONFIG_TYPE_STRING);
            config_setting_set_string(cf_amf_id, GM_AMF4);
        }
    }

    if (strlen(GM_PLMN5) || strlen(GM_AMF5)) {
        APPLOG(APPLOG_ERR, "{{{DBG}}} %s try set guamiPlmnList={plmnId=(%s), amfId=(%s)}", __func__, GM_PLMN5, GM_AMF5);
        config_setting_t *cf_guami_list = config_setting_add_try(cf_amf_info, "guamiList", CONFIG_TYPE_LIST);
        config_setting_t *cf_guami = config_setting_add_try(cf_guami_list, "", CONFIG_TYPE_GROUP);
        if (strlen(GM_PLMN5)) {
#if 0
            config_setting_t *cf_plmn = config_setting_add_try(cf_guami, "plmnId", CONFIG_TYPE_STRING);
            config_setting_set_string(cf_plmn, GM_PLMN5);
#else
            add_cfg_nf_mml_guami_plmn(cf_guami, GM_PLMN5);
#endif
        }
        if (strlen(GM_AMF5)) {
            config_setting_t *cf_amf_id = config_setting_add_try(cf_guami, "amfId", CONFIG_TYPE_STRING);
            config_setting_set_string(cf_amf_id, GM_AMF5);
        }
    }

    write_cfg(MAIN_CTX);

    reload_mml(MAIN_CTX);

    printf_nf_mml(MAIN_CTX, resBuf, NULL, NULL);

    return 0;
}

int add_cfg_nf_mml(main_ctx_t *MAIN_CTX, const char *conf_name, const char *target_host, const char *nf_type, MMLReqMsgType *mml_req, char *resBuf)
{
	APPLOG(APPLOG_ERR, "{{{DBG}}} %s called", __func__);

	config_setting_t *mml_list = config_lookup(&MAIN_CTX->CFG, "mml_list");
	int mml_num = config_setting_length(mml_list);

	/* check name duplicate */
	for (int i = 0; i < mml_num; i++) {
		config_setting_t *mml_item = config_setting_get_elem(mml_list, i);
		if (!strcmp(mml_item->name, conf_name)) {
			sprintf(resBuf, "ALREADY EXIST MML NAME[%s]", conf_name);
			return -1;
		}
	}

	if (!strcmp(nf_type, "UDM")) {
		return add_cfg_nf_mml_udm(MAIN_CTX, conf_name, target_host, nf_type, mml_req, mml_list, resBuf);
    } else if (!strcmp(nf_type, "AMF")) {
		return add_cfg_nf_mml_amf(MAIN_CTX, conf_name, target_host, nf_type, mml_req, mml_list, resBuf);
	} else {
		sprintf(resBuf, "UNSUPPORTED NF TYPE [%s]", nf_type);
		return -1;
	}
}

int del_cfg_nf_mml(main_ctx_t *MAIN_CTX, int ID, char *resBuf)
{
	APPLOG(APPLOG_ERR, "{{{DBG}}} %s called", __func__);

	config_setting_t *mml_list = config_lookup(&MAIN_CTX->CFG, "mml_list");
	int mml_num = config_setting_length(mml_list);

	if (ID >= mml_num) {
		sprintf(resBuf, "INVALID MML ID[%d]", ID);
		return -1;
	}

	config_setting_remove_elem(mml_list, ID);

	write_cfg(MAIN_CTX);

	reload_mml(MAIN_CTX);

	printf_nf_mml(MAIN_CTX, resBuf, NULL, NULL);

	return 0;
}

int func_dis_nf_mml(IxpcQMsgType *rxIxpcMsg)
{
	APPLOG(APPLOG_DEBUG, "%s() called", __func__);

    MMLReqMsgType   *mmlReq=(MMLReqMsgType*)rxIxpcMsg->body;

    char nf_type[32] = {0,};
    get_mml_para_str(mmlReq, "NF_TYPE", nf_type);
    if (strlen(nf_type) > 0)
        strupr(nf_type, strlen(nf_type));

    char host[128] = {0,};
    get_mml_para_str(mmlReq, "HOST", host);

    char *resBuf=malloc(1024 * 1024);
	resBuf[0] = '\0';

	printf_nf_mml(&MAIN_CTX, resBuf, strlen(nf_type) > 0 ? nf_type : NULL, strlen(host) > 0 ? host : NULL);

	int res = send_mml_res_succMsg(rxIxpcMsg, resBuf, FLAG_COMPLETE, 0, 0);

	free(resBuf);
	return res;
}

int func_add_nf_mml(IxpcQMsgType *rxIxpcMsg)
{
	APPLOG(APPLOG_DEBUG, "%s() called", __func__);

	MMLReqMsgType   *mmlReq=(MMLReqMsgType*)rxIxpcMsg->body;

	/* mandatory */
	char CONF_NAME[128] = {0,};
	char TARGET_HOST[128] = {0,};
	char NF_TYPE[128] = {0,};

    /* error handle */
	if (get_mml_para_str(mmlReq, "CONF_NAME", CONF_NAME) < 0)
		return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING [CONF_NAME]");
	if (get_mml_para_str(mmlReq, "TARGET_HOST", TARGET_HOST) < 0)
		return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING [TARGET_HOST]");
#if 0
    if (get_mml_para_str(mmlReq, "NF_TYPE", NF_TYPE) < 0)
        return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING [NF_TYPE]");
#else
    if (!strcasecmp(mmlReq->head.cmdName, "ADD-NF-MML-AMF")) {
        sprintf(NF_TYPE, "AMF");
    } else if (!strcasecmp(mmlReq->head.cmdName, "ADD-NF-MML-UDM")) {
        sprintf(NF_TYPE, "UDM");
    } else {
        return send_mml_res_failMsg(rxIxpcMsg, "INVALID CMD NAME");
    }
#endif

    /* malloc - send & free */
    char *resBuf=malloc(1024 * 1024);
	resBuf[0] = '\0';

	if (add_cfg_nf_mml(&MAIN_CTX, CONF_NAME, TARGET_HOST, NF_TYPE, mmlReq, resBuf) < 0)
		return send_mml_res_failMsg(rxIxpcMsg, resBuf);

	int res = send_mml_res_succMsg(rxIxpcMsg, resBuf, FLAG_COMPLETE, 0, 0);

	free(resBuf);
	return res;
}

int func_del_nf_mml(IxpcQMsgType *rxIxpcMsg)
{
	APPLOG(APPLOG_DEBUG, "%s() called", __func__);

	MMLReqMsgType   *mmlReq=(MMLReqMsgType*)rxIxpcMsg->body;

	/* mandatory */
	int ID = -1;

    /* error handle */
	if ((ID = get_mml_para_int(mmlReq, "ID")) < 0)
		return send_mml_res_failMsg(rxIxpcMsg, "PARAMETER MISSING [ID]");

    /* malloc - send & free */
    char *resBuf=malloc(1024 * 1024);
	resBuf[0] = '\0';

	if (del_cfg_nf_mml(&MAIN_CTX, ID, resBuf) < 0)
		return send_mml_res_failMsg(rxIxpcMsg, resBuf);

	int res = send_mml_res_succMsg(rxIxpcMsg, resBuf, FLAG_COMPLETE, 0, 0);

	free(resBuf);
	return res;
}

void send_conn_req_profile(assoc_t *lb_assoc, nf_disc_host_info *nf_host_info)
{
    if (lb_assoc->index != nf_host_info->lbIndex)
        return;

    IsifMsgType txIsifMsg = {0,};

    nf_host_info->mtype = LIBNRF_MSG_ADD_NF_PROFILE;

	APPLOG(APPLOG_DEBUG, "{DBG} %s() send request! to node index(%d)", __func__, lb_assoc->index);

    isifc_create_pkt(&txIsifMsg, &MAIN_CTX.my_info, lb_assoc, nf_host_info, sizeof(nf_disc_host_info));
    isifc_send_pkt(MAIN_CTX.my_qid.isifc_tx_qid, &txIsifMsg);
}

void send_conn_handle_req(assoc_t *lb_assoc, http_conn_handle_req_t *handle_req)
{
    IsifMsgType txIsifMsg = {0,};

    handle_req->mtype = LIBNRF_MSG_ADD_NF_CALLBACK;

    isifc_create_pkt(&txIsifMsg, &MAIN_CTX.my_info, lb_assoc, handle_req, sizeof(http_conn_handle_req_t));
    isifc_send_pkt(MAIN_CTX.my_qid.isifc_tx_qid, &txIsifMsg);
}

void check_and_send_conn_req(assoc_t *lb_assoc, http_conn_handle_req_t *handle_req)
{
	// if shm not exist also there is no node tree, we can't handle
	if (MAIN_CTX.sysconfig.nfs_shm_create == 0) {
		send_conn_handle_req(lb_assoc, handle_req);
		return;
	}

	if (MAIN_CTX.root_node == NULL) {
		APPLOG(APPLOG_ERR, "%s() cant handle req, SHM_NFS_AVAIL is null", __func__);
		return;
	}
	nf_search_key_t key = {0,};
	memset(&key, 0x00, sizeof(nf_search_key_t));

	create_cb_depth_key(&key, lb_assoc->index, handle_req);

	GNode *node_conn = search_node_data(MAIN_CTX.root_node, &key, NF_NODE_DATA_DEPTH);

	if ((handle_req->command == HTTP_MML_HTTPC_ADD && node_conn == NULL) ||
			(handle_req->command == HTTP_MML_HTTPC_DEL && node_conn != NULL)) {
		APPLOG(APPLOG_DEBUG, "{DBG} %s() send request! to node index(%d)", __func__, lb_assoc->index);
		send_conn_handle_req(lb_assoc, handle_req);
	} else {
		APPLOG(APPLOG_DEBUG, "{DBG} %s() NOT send(already exist) request! to node index(%d)", __func__, lb_assoc->index);
	}
}

void handle_appl_req_with_profile(main_ctx_t *MAIN_CTX, nf_disc_host_info *nf_host_info)
{
	if (MAIN_CTX->sysconfig.isifcs_mode == 1) {
		g_slist_foreach(MAIN_CTX->lb_assoc_list, (GFunc)send_conn_req_profile, nf_host_info);
	} else {
		assoc_t lb_assoc = {0,};
		memset(&lb_assoc, 0x00, sizeof(assoc_t));
		send_conn_req_profile(&lb_assoc, nf_host_info);
	}
}

void handle_appl_req_with_cbinfo(main_ctx_t *MAIN_CTX, http_conn_handle_req_t *handle_req)
{
	if (MAIN_CTX->sysconfig.isifcs_mode == 1) {
		g_slist_foreach(MAIN_CTX->lb_assoc_list, (GFunc)check_and_send_conn_req, handle_req);
	} else {
		assoc_t lb_assoc = {0,};
		memset(&lb_assoc, 0x00, sizeof(assoc_t));
		check_and_send_conn_req(&lb_assoc, handle_req);
	}
}

char KEY_EMPTY_PTR[12] = {0,};
void create_cb_depth_key(nf_search_key_t *key, int lb_index, http_conn_handle_req_t *handle_req)
{
	key->depth = 0;
	
	key->lb_id = lb_index + 1;
	key->nf_type = handle_req->type;
	key->nf_host = handle_req->host;

	KEY_EMPTY_PTR[0] = '\0';
	key->nf_svcname = KEY_EMPTY_PTR;

	sprintf(key->nf_conn_info, "%s%s://%s:%d",
			handle_req->scheme, !strcmp(handle_req->scheme, "https") ? "" : "-", handle_req->ip, handle_req->port);
}

void create_full_depth_key (nf_search_key_t *key, nf_service_info *insert_data)
{
    key->depth = 0;

    key->lb_id = insert_data->lbId;
    key->nf_type = insert_data->type;
    key->nf_host = insert_data->auto_add == NF_ADD_MML ? insert_data->confname : insert_data->hostname;
    key->nf_svcname = insert_data->serviceName;

    if (insert_data->auto_add == NF_ADD_MML) {
        sprintf(key->nf_conn_info, "lb_conf=[%s]", insert_data->hostname);
    } else {
        sprintf(key->nf_conn_info, "%s%s://%s:%d",
                insert_data->scheme, !strcmp(insert_data->scheme, "https") ? "" : "-", insert_data->ipv4Address, insert_data->port);
    }
};

void create_fep_nfs_node_tree(nfs_avail_shm_t *SHM_NFS_AVAIL)
{
    int prepare_pos = (SHM_NFS_AVAIL->curr_pos + 1) % MAX_NFS_SHM_POS;
    nf_list_shm_t *nf_avail_shm = &SHM_NFS_AVAIL->nfs_avail_shm[prepare_pos];

    if (MAIN_CTX.root_node != NULL) {
    //APPLOG(APPLOG_ERR, "{{{DBG}}} %s() remove rootnode pos[%d]", __func__, prepare_pos);
        /* free all node data */
        g_node_traverse(MAIN_CTX.root_node, G_IN_ORDER, G_TRAVERSE_ALL, -1, node_free_data, NULL);
        /* remove NODE */
        g_node_destroy(MAIN_CTX.root_node);
        MAIN_CTX.root_node = NULL;
    }
    MAIN_CTX.root_node = g_node_new(NULL);

    for (int i = 0 ; i < NF_MAX_LB_NUM; i++) {
        for (int k = 0; k < NF_MAX_AVAIL_LIST; k++) {
            nf_service_info *nf_info = &nf_avail_shm->nf_avail[i][k];

            if (nf_info->occupied <= 0)
                continue;

            nf_search_key_t key = {0,};
            create_full_depth_key(&key, nf_info);
            create_node_data(MAIN_CTX.root_node, &key, nf_info);
        }
    }
}
