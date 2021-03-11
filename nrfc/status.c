#include <nrfc.h>

extern main_ctx_t MAIN_CTX;

// each lb
void attach_mml_info_into_lb_shm(mml_conf_t *mml_conf, nf_service_info *nf_avail_each_lb, int lb_id)
{
    int find_httpc_host = 0;
    int httpc_host_avail = 0;

	for (int i = 0; i < NF_MAX_AVAIL_LIST; i++) {
		nf_service_info *nf_avail = &nf_avail_each_lb[i];
		if (nf_avail->occupied == 0) continue;
        if (nf_avail->auto_add != NF_ADD_RAW) continue;
        if (!strcmp(mml_conf->target_hostname, nf_avail->hostname)) {
            find_httpc_host = 1;
            if (nf_avail->available > 0) {
                httpc_host_avail = 1;
                break;
            }
        }
	}

    nf_service_info *svc_mml = &mml_conf->service_info;

	for (int i = 0; i < NF_MAX_AVAIL_LIST; i++) {
		nf_service_info *nf_avail = &nf_avail_each_lb[i];
		if (nf_avail->occupied == 0) {
			nf_avail->occupied = 1;
			nf_avail->table_index = i;
			nf_avail->lbId = lb_id;
			nf_avail->nfType = svc_mml->nfType;
			memcpy(&nf_avail->nfTypeInfo, &svc_mml->nfTypeInfo, sizeof(nf_type_info));
			nf_avail->allowdPlmnsNum = svc_mml->allowdPlmnsNum;
			memcpy(nf_avail->allowdPlmns, svc_mml->allowdPlmns, sizeof(nf_comm_plmn) * NF_MAX_ALLOWD_PLMNS);
			memcpy(nf_avail->serviceName, svc_mml->serviceName, sizeof(nf_avail->serviceName));

            sprintf(nf_avail->type, "%s", mml_conf->nf_type);
			sprintf(nf_avail->hostname, "%s", mml_conf->target_hostname);
			sprintf(nf_avail->confname, "%s", mml_conf->conf_name);

            // -1: not exist, 0: not avail, 1: avail
            nf_avail->available = find_httpc_host == 0 ? -1 : httpc_host_avail;
			nf_avail->auto_add = NF_ADD_MML;

			return;
		}
	}
}

// by each mml
void attach_mml_info_into_shm(mml_conf_t *mml_conf, main_ctx_t *MAIN_CTX)
{
	int prepare_pos = (MAIN_CTX->SHM_NFS_AVAIL->curr_pos + 1) % MAX_NFS_SHM_POS;
	nf_list_shm_t *nf_avail_shm_prepare = &MAIN_CTX->SHM_NFS_AVAIL->nfs_avail_shm[prepare_pos];

    int lb_num = g_slist_length(MAIN_CTX->lb_assoc_list);
    for (int i = 0; i < lb_num; i++) {
        assoc_t *lb_assoc = g_slist_nth_data(MAIN_CTX->lb_assoc_list, i);
        if (lb_assoc->id >=  1 && lb_assoc->id <= NF_MAX_LB_NUM)
            attach_mml_info_into_lb_shm(mml_conf, nf_avail_shm_prepare->nf_avail[lb_assoc->id - 1], lb_assoc->id);
    }
}

void add_shm_avail_count(main_ctx_t *MAIN_CTX)
{
	int prepare_pos = (MAIN_CTX->SHM_NFS_AVAIL->curr_pos + 1) % MAX_NFS_SHM_POS;
	nf_list_shm_t *nf_avail_shm_prepare = &MAIN_CTX->SHM_NFS_AVAIL->nfs_avail_shm[prepare_pos];

	for(int i = 0; i < NF_MAX_LB_NUM; i++) {
		for (int k = 0; k < NF_MAX_AVAIL_LIST; k++) {
			nf_service_info *nf_avail = &nf_avail_shm_prepare->nf_avail[i][k];
			if (nf_avail->occupied == 0) {
				nf_avail_shm_prepare->nf_avail_cnt[i] = k;
				//APPLOG(APPLOG_DEBUG, "{{{DBG}}} %s set nf_avail_count lbIdx:%d cnt:%d", __func__, i, k);
				break;
			}
		}
	}
}

void isif_save_recv_lb_status(main_ctx_t *MAIN_CTX, nf_service_info *nf_info)
{   
	int lbId = (nf_info->lbId - 1) % NF_MAX_LB_NUM;
	int index = (nf_info->index) % NF_MAX_AVAIL_LIST;

	int prepare_pos = 0;

	prepare_pos = (MAIN_CTX->SHM_NFS_AVAIL->curr_pos + 1) % MAX_NFS_SHM_POS;
	nf_list_shm_t *nf_avail_shm_prepare = &MAIN_CTX->SHM_NFS_AVAIL->nfs_avail_shm[prepare_pos];
	memcpy(&nf_avail_shm_prepare->nf_avail[lbId][index], nf_info, sizeof(nf_service_info));
	nf_avail_shm_prepare->nf_avail[lbId][index].table_index = index;
	MAIN_CTX->fep_nfs_info[lbId].inProgress = (index == nf_info->lastIndex) ? 0 : 1;

	struct timeval now = {0,};
	gettimeofday(&now, NULL);

	struct timeval elapse = {0,};
	timersub(&now, &MAIN_CTX->last_pub_time, &elapse);

	long long elapse_milisec = elapse.tv_sec * 1000LL + (elapse.tv_usec / 1000LL);

	int nowProgress = 0;
	for(int i = 0; i < NF_MAX_LB_NUM; i++) {
		if (MAIN_CTX->fep_nfs_info[i].inProgress)
			nowProgress++;
	}

	/* 1 sec diff */
	if ((elapse_milisec >= 2000) && (nowProgress == 0)) {

		/* attach mml */
		g_slist_foreach(MAIN_CTX->opr_mml_list, (GFunc)attach_mml_info_into_shm, MAIN_CTX);
        /* create node tree data */
        create_fep_nfs_node_tree(MAIN_CTX->SHM_NFS_AVAIL);
		/* set max count */
		add_shm_avail_count(MAIN_CTX);

		MAIN_CTX->last_pub_time = now;
		MAIN_CTX->SHM_NFS_AVAIL->curr_pos = (MAIN_CTX->SHM_NFS_AVAIL->curr_pos + 1) % MAX_NFS_SHM_POS;
		int next_pos = (MAIN_CTX->SHM_NFS_AVAIL->curr_pos + 1) % MAX_NFS_SHM_POS;

		nf_list_shm_t *nf_avail_shm_prepare = &MAIN_CTX->SHM_NFS_AVAIL->nfs_avail_shm[next_pos];
        clear_nf_avail_shm(nf_avail_shm_prepare);

		memset(&MAIN_CTX->fep_nfs_info, 0x00, sizeof(fep_nfs_info_t) * NF_MAX_LB_NUM);

		if (MAIN_CTX->sysconfig.debug_mode) {
			printf_fep_nfs(MAIN_CTX->SHM_NFS_AVAIL, NULL);
			APPLOG(APPLOG_ERR, "{{{DBG}}} %s curr shm pos [%d]", __func__, MAIN_CTX->SHM_NFS_AVAIL->curr_pos);
		}
	}
}

void clear_nf_avail_shm(nf_list_shm_t *nf_avail_shm_prepare)
{
    for (int i = 0; i < NF_MAX_LB_NUM; i++) {    
        nf_avail_shm_prepare->nf_avail_cnt[i] = 0;
        for (int k = 0; k < NF_MAX_AVAIL_LIST; k++) {
            nf_avail_shm_prepare->nf_avail[i][k].occupied = 0;                                                                   
        }
    }
}

void clear_fep_nfs(evutil_socket_t fd, short what, void *arg)
{
	struct timeval now = {0,};
	gettimeofday(&now, NULL);

	struct timeval elapse = {0,};
	timersub(&now, &MAIN_CTX.last_pub_time, &elapse);

	long long elapse_milisec = elapse.tv_sec * 1000LL + (elapse.tv_usec / 1000LL);

	/* 10 sec diff */ 
	if (elapse_milisec >= 10000) {
        create_fep_nfs_node_tree(MAIN_CTX.SHM_NFS_AVAIL);

		MAIN_CTX.last_pub_time = now;
		MAIN_CTX.SHM_NFS_AVAIL->curr_pos = (MAIN_CTX.SHM_NFS_AVAIL->curr_pos + 1) % MAX_NFS_SHM_POS;
		int next_pos = (MAIN_CTX.SHM_NFS_AVAIL->curr_pos + 1) % MAX_NFS_SHM_POS;

		nf_list_shm_t *nf_avail_shm_prepare = &MAIN_CTX.SHM_NFS_AVAIL->nfs_avail_shm[next_pos];
        clear_nf_avail_shm(nf_avail_shm_prepare);

		if (MAIN_CTX.sysconfig.debug_mode) {
			printf_fep_nfs(MAIN_CTX.SHM_NFS_AVAIL, NULL);
			APPLOG(APPLOG_ERR, "{{{DBG}}} %s curr shm pos [%d]", __func__, MAIN_CTX.SHM_NFS_AVAIL->curr_pos);
		}
	}
}
