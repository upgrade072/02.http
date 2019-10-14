#include <nrfc.h>

extern main_ctx_t MAIN_CTX;

void isif_save_recv_lb_status(main_ctx_t *MAIN_CTX, nf_service_info *nf_info)
{   
	int lbId = (nf_info->lbId - 1) % NF_MAX_LB_NUM;
	//int seqNo = nf_info->seqNo;
	int index = (nf_info->index) % NF_MAX_AVAIL_LIST;

	int prepare_pos = 0;

	//MAIN_CTX->fep_nfs_info[lbId].seqNo = seqNo;
	prepare_pos = (MAIN_CTX->SHM_NFS_AVAIL->curr_pos + 1) % MAX_NFS_SHM_POS;
	nf_list_shm_t *nf_avail_shm_prepare = &MAIN_CTX->SHM_NFS_AVAIL->nfs_avail_shm[prepare_pos];
	memcpy(&nf_avail_shm_prepare->nf_avail[lbId][index], nf_info, sizeof(nf_service_info));
	MAIN_CTX->fep_nfs_info[lbId].inProgress = (index == nf_info->lastIndex) ? 0 : 1;

	time_t now = time(NULL);
	int nowProgress = 0;
	for(int i = 0; i < NF_MAX_LB_NUM; i++) {
		if (MAIN_CTX->fep_nfs_info[i].inProgress)
			nowProgress++;
	}

	if (((now - MAIN_CTX->last_pub_time) >= 1) && (nowProgress == 0)) {
		MAIN_CTX->last_pub_time = now;
		MAIN_CTX->SHM_NFS_AVAIL->curr_pos = (MAIN_CTX->SHM_NFS_AVAIL->curr_pos + 1) % MAX_NFS_SHM_POS;
		int next_pos = (MAIN_CTX->SHM_NFS_AVAIL->curr_pos + 1) % MAX_NFS_SHM_POS;

		nf_list_shm_t *nf_avail_shm_prepare = &MAIN_CTX->SHM_NFS_AVAIL->nfs_avail_shm[next_pos];
		memset(nf_avail_shm_prepare, 0x00, sizeof(nf_list_shm_t));

		printf_fep_nfs(MAIN_CTX->SHM_NFS_AVAIL);
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s curr shm pos [%d]", __func__, MAIN_CTX->SHM_NFS_AVAIL->curr_pos);
	}
}
 
void printf_fep_nfs(nfs_avail_shm_t *SHM_NFS_AVAIL)
{
	APPLOG(APPLOG_ERR, "{{{DBG}}} %s called!", __func__);

	ft_table_t *TABLE = ft_create_table();

	ft_set_cell_prop(TABLE, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);
	ft_set_border_style(TABLE, FT_BASIC2_STYLE);
	ft_write_ln(TABLE, "index", "type", "service", "allowedPlmns\n(mcc+mnc)", "typeInfo", "hostname", "scheme", "ipv4", "port", "priority", "auto", "lb_id");

	int POS = SHM_NFS_AVAIL->curr_pos;
	nf_list_shm_t *nf_avail_shm = &SHM_NFS_AVAIL->nfs_avail_shm[POS];

	for (int i = 0, index = 0; i < NF_MAX_LB_NUM; i++) {
		for (int k = 0; k < NF_MAX_AVAIL_LIST; k++) {
			nf_service_info *nf_info = &nf_avail_shm->nf_avail[i][k];

			if (nf_info->occupied <= 0)
				continue;

			/* allowd plmns */
			char allowdPlmnsStr[1024] = {0,};
			getAllowdPlmns(nf_info, allowdPlmnsStr);

			/* nf-type specific info */
			char typeSpecStr[1024 * 12] = {0,};
			getTypeSpecStr(nf_info, typeSpecStr);

			ft_printf_ln(TABLE, "%d|%s|%s|%s|%s|%s|%s|%s|%d|%d|%s|%d",
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
					nf_info->auto_add ? "O" : "X",
					nf_info->lbId);
		}
	}
	APPLOG(APPLOG_ERR, "\n%s", ft_to_string(TABLE));
	ft_destroy_table(TABLE);
}

void clear_fep_nfs(evutil_socket_t fd, short what, void *arg)
{
	time_t now = time(NULL);

	if ((now - MAIN_CTX.last_pub_time) >= 2) {
		MAIN_CTX.last_pub_time = now;
		MAIN_CTX.SHM_NFS_AVAIL->curr_pos = (MAIN_CTX.SHM_NFS_AVAIL->curr_pos + 1) % MAX_NFS_SHM_POS;
		int next_pos = (MAIN_CTX.SHM_NFS_AVAIL->curr_pos + 1) % MAX_NFS_SHM_POS;

		nf_list_shm_t *nf_avail_shm_prepare = &MAIN_CTX.SHM_NFS_AVAIL->nfs_avail_shm[next_pos];
		memset(nf_avail_shm_prepare, 0x00, sizeof(nf_list_shm_t));

		printf_fep_nfs(MAIN_CTX.SHM_NFS_AVAIL);
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s curr shm pos [%d]", __func__, MAIN_CTX.SHM_NFS_AVAIL->curr_pos);
	}
}
