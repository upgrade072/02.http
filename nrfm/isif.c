#include <nrfm.h>

extern main_ctx_t MAIN_CTX;

void isifc_create_pkt_for_status(IsifMsgType *txIsifMsg, nf_service_info *nf_info, svr_info_t *my_info, assoc_t *fep_assoc)
{
    /* ISIF Header Set */
    txIsifMsg->head.mtype = MTYPE_NRFM_BROAD_STATUS_TO_FEP;

    /* Set Source Info */
    /* schlee, only use for set (a:b:c = 1 set) */
    sprintf(txIsifMsg->head.srcSysType, "%s", my_info->mySysType);
    sprintf(txIsifMsg->head.srcSysName, "%s", my_info->mySysName);
    sprintf(txIsifMsg->head.srcAppName, "%s", my_info->myProcName);

    /* Set Destination Info */
    sprintf(txIsifMsg->head.dstSysType, "%s", fep_assoc->type);
    sprintf(txIsifMsg->head.dstSysName, "%s", fep_assoc->name);
    sprintf(txIsifMsg->head.dstAppName, "%s", "NRFC");

    memcpy(txIsifMsg->body, nf_info, sizeof(nf_service_info));
    txIsifMsg->head.bodyLen = sizeof(nf_service_info);
}

void isifc_send_pkt_for_status(int isifc_qid, IsifMsgType *txIsifMsg)
{
    int tx_len = ISIF_HEAD_LEN + txIsifMsg->head.bodyLen;

    if (shmqlib_putMsg (isifc_qid, (char*)txIsifMsg, tx_len) < 0 ) {
        APPLOG(APPLOG_ERR, "%s() send shmq fail (isifc:%x)!!!", __func__, isifc_qid);
        return;
    }
}

void isif_save_recv_fep_status(service_info_t *fep_svc_info)
{
    if (fep_svc_info->sys_mp_id <= 0 || fep_svc_info->sys_mp_id >= MAX_FEP_NUM) {
        APPLOG(APPLOG_ERR, "%s() receive invalid sys_mp_id (%d)!", __func__, fep_svc_info->sys_mp_id);
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

void isif_handle_fep_conn_req_profile(nf_disc_host_info *nf_host_info)
{
    /* find nf_item (if exist) */
    nf_retrieve_item_t *nf_item = nf_notify_search_item_by_uuid(&MAIN_CTX, nf_host_info->hostname);

    json_object *js_nf_profile = json_tokener_parse(nf_host_info->nfProfile);
    if (js_nf_profile == NULL) {
        APPLOG(APPLOG_ERR, "%s() can't parse nfProfile(json) discard fep request[%s:%s]",
                __func__, nf_host_info->nfType, nf_host_info->hostname);
        return;
    }

    /* main job */
    nf_notify_profile_add(nf_item, js_nf_profile);

    if (js_nf_profile != NULL) {
        json_object_put(js_nf_profile);
    }
}

void shmq_recv_handle(evutil_socket_t fd, short what, void *arg)
{
    char msgBuff[1024*64];
    IsifMsgType *rxIsifMsg = (IsifMsgType *)msgBuff;
    long *subMsgType = (long *)rxIsifMsg->body;

    int ret = 0;

    while ((ret = shmqlib_getMsg(MAIN_CTX.my_qid.isifs_rx_qid, (char *)rxIsifMsg)) > 0) {

        if (ret > sizeof(IsifMsgType)) {
            APPLOG(APPLOG_ERR, "%s() receive unknown size(%d) msg!", __func__, ret);
            continue;
        }

        switch (rxIsifMsg->head.mtype) {
            case MTYPE_NRFC_BROAD_STATUS_TO_LB:
                if (*subMsgType == LIBNRF_MSG_SERVICE_INFO)
                    isif_save_recv_fep_status((service_info_t *)rxIsifMsg->body);
                else if (*subMsgType == LIBNRF_MSG_ADD_NF_PROFILE)
                    isif_handle_fep_conn_req_profile((nf_disc_host_info *)rxIsifMsg->body);
                continue;
            default:
                APPLOG(APPLOG_ERR, "%s() receive unknown type(%d) msg!", __func__, rxIsifMsg->head.mtype);
                continue;
        }
    }
    return;
}
