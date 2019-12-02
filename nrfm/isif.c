#include <nrfm.h>

extern main_ctx_t MAIN_CTX;

void isifc_create_pkt_for_status(IsifMsgType *txIsifMsg, nf_service_info *nf_info, svr_info_t *my_info, assoc_t *fep_assoc)
{
    /* ISIF Header Set */
    txIsifMsg->head.mtype = MTYPE_NRFM_BROAD_STATUS_TO_FEP;

    /* Set Source Info */
    /* schlee, only use for set (a:b:c = 1 set) */
    //txIsifMsg->head.srcSysSetID = atoi(my_info->mySvrId);
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
