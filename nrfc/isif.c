#include <nrfc.h>

SHM_IsifConnSts *shmConnSts;		// for BEP conn Status
SHM_IsifConnSts *commlib_initIsifConnSts(void);	// ??? function proto 

int isifc_init()
{
	if ((shmConnSts = (SHM_IsifConnSts *)commlib_initIsifConnSts()) == NULL) {
		APPLOG(APPLOG_ERR, "{{{INIT}}} fail to attach isifc shm!\n");
		return -1;
	}
	return 0;
}

void isifc_create_pkt_for_status(IsifMsgType *txIsifMsg, service_info_t *fep_svc, svr_info_t *my_info, assoc_t *lb_assoc)
{
    /* ISIF Header Set */
    txIsifMsg->head.mtype = MTYPE_NRFC_BROAD_STATUS_TO_LB;

    /* Set Source Info */
	/* schlee, only use for set (a:b:c = 1 set) */
    //txIsifMsg->head.srcSysSetID = atoi(my_info->mySvrId);
    sprintf(txIsifMsg->head.srcSysType, "%s", my_info->mySysType);
    sprintf(txIsifMsg->head.srcSysName, "%s", my_info->mySysName);
    sprintf(txIsifMsg->head.srcAppName, "%s", my_info->myProcName);

    /* Set Destination Info */
    sprintf(txIsifMsg->head.dstSysType, "%s", lb_assoc->type);
    sprintf(txIsifMsg->head.dstSysName, "%s", lb_assoc->name);
    sprintf(txIsifMsg->head.dstAppName, "%s", "NRFM");

	/* schlee, is it work ??? */
    //txIsifMsg.head.option |= ISIF_OPTION_ALL_SERVER;

	memcpy(txIsifMsg->body, fep_svc, sizeof(service_info_t));
	txIsifMsg->head.bodyLen = sizeof(service_info_t);
}

void isifc_send_pkt_for_status(int isifc_qid, IsifMsgType *txIsifMsg)
{
	int tx_len = ISIF_HEAD_LEN + txIsifMsg->head.bodyLen;

	if (shmqlib_putMsg (isifc_qid, (char*)txIsifMsg, tx_len) < 0 ) {
		APPLOG(APPLOG_ERR, "%s() send shmq fail (isifc:%x)!!!", __func__, isifc_qid);
		return;
	}
}
