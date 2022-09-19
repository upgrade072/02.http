#include <nrfc.h>

main_ctx_t MAIN_CTX;
int logLevel = APPLOG_DEBUG;
int *lOG_FLAG = &logLevel;
extern T_OverloadInfo *ovldInfo;	// for API TPS
extern T_keepalive *keepalive;		// for Process Status
extern SHM_IsifConnSts *shmConnSts;		// for BEP conn Status
shm_http_t *SHM_HTTPC_PTR;

int get_my_qid(main_ctx_t *MAIN_CTX)
{
    char fname[1024] = {0,};
    char tmp[64] = {0,};
    int key = 0;
#ifdef SYSCONF_LEGACY
    int PROC_NAME_LOC = 1; // some old sysconf : eir ...
#else
    int PROC_NAME_LOC = 3;
#endif

    /* ~/data/sysconfig */
    sprintf(fname,"%s/%s", getenv(IV_HOME), SYSCONF_FILE);

    /* create receive queue */
    if (conflib_getNthTokenInFileSection (fname, "APPLICATIONS", MAIN_CTX->my_info.myProcName, PROC_NAME_LOC, tmp) < 0) {
        APPLOG(APPLOG_ERR, "{{{INIT}}} configlib get token APPLICATIONS [%s] fail!", MAIN_CTX->my_info.myProcName);
        return -1;
    }
    key = strtol(tmp,0,0);
    if ((MAIN_CTX->my_qid.nrfc_qid = msgget(key,IPC_CREAT|0666)) < 0) {
        APPLOG(APPLOG_ERR,"{{{INIT}}} [%s] msgget fail; key=0x%x,err=%d(%s)!", __func__, key, errno, strerror(errno));
        return -1;
	}

    /* create (cmd resp) send queue */
    if (conflib_getNthTokenInFileSection (fname, "APPLICATIONS", "IXPC", PROC_NAME_LOC, tmp) < 0) {
        APPLOG(APPLOG_ERR, "{{{INIT}}} configlib get token APPLICATIONS [%s] fail!", "IXPC");
        return -1;
    }
    key = strtol(tmp,0,0);
    if ((MAIN_CTX->my_qid.ixpc_qid = msgget(key,IPC_CREAT|0666)) < 0) {
        APPLOG(APPLOG_ERR,"{{{INIT}}} [%s] msgget fail; key=0x%x,err=%d(%s)!", __func__, key, errno, strerror(errno));
        return -1;
	}

    /* ~/data/isif.conf */
    if (MAIN_CTX->sysconfig.isifcs_mode == 1) {
        APPLOG(APPLOG_ERR, "{{{INIT}}} as isifcs mode=[%d], use ISIFC/S SHM from=[%s]", 
                MAIN_CTX->sysconfig.isifcs_mode, ISIF_CONF_FILE);

        sprintf(fname,"%s/%s", getenv(IV_HOME), ISIF_CONF_FILE);
        if ((MAIN_CTX->my_qid.isifc_tx_qid = 
                    shmqlib_getQid (fname, "APP_TO_ISIFC_SHMQ", MAIN_CTX->my_info.myProcName, SHMQLIB_MODE_PUTTER)) < 0) {
            APPLOG(APPLOG_ERR,"{{{INIT}}} fail to get isifc tx qid %s:%s!", fname, MAIN_CTX->my_info.myProcName);
            return -1;
        }

        if ((MAIN_CTX->my_qid.isifs_rx_qid = 
                    shmqlib_getQid (fname, "ISIFS_TO_APP_SHMQ", MAIN_CTX->my_info.myProcName, SHMQLIB_MODE_GETTER)) < 0) {
            APPLOG(APPLOG_ERR,"{{{INIT}}} fail to get isifs rx qid %s:%s!", fname, MAIN_CTX->my_info.myProcName);
            return -1;
        }
    } else {
        APPLOG(APPLOG_ERR, "{{{INIT}}} as isifcs mode=[%d], use NRFM/NRFC SHM from=[%s]", 
                MAIN_CTX->sysconfig.isifcs_mode, SYSCONF_FILE);

        sprintf(fname,"%s/%s", getenv(IV_HOME), SYSCONF_FILE);
        if ((MAIN_CTX->my_qid.isifc_tx_qid = get_shm_comm_key(fname, "NRFM", SHMQLIB_MODE_PUTTER)) < 0) {
            APPLOG(APPLOG_ERR,"{{{INIT}}} fail to get -->NRFM tx qid %s:%s!", fname, "NRFM");
            return -1;
        }

        if ((MAIN_CTX->my_qid.isifs_rx_qid = get_shm_comm_key(fname, "NRFC", SHMQLIB_MODE_GETTER)) < 0) {
            APPLOG(APPLOG_ERR,"{{{INIT}}} fail to get NRFC<-- rx qid %s:%s!", fname, "NRFC");
            return -1;
        }
    }

    return 0;
}

int get_olcd_index_with_tps(char *svc_name, int *tps)
{
	for (int i = 0; i < NUM_OVLD_CTRL_SVC; i++) {
		if (strlen(ovldInfo->cfg.svc_name[i]) > 0 && !strcmp(ovldInfo->cfg.svc_name[i], svc_name)) {
			*tps = ovldInfo->cfg.tps_limit_normal[i];
			return i;
		}
	}

	// cant'find
	*tps = -1;
	return -1;
}

void fep_service_log(service_info_t *fep_svc)
{
	APPLOG(APPLOG_ERR, "{{{CHECK}}} mp(%d) (%s:%s ... :tps %d), olcd index(%d) use_bep(%d:conn %d)",
			fep_svc->sys_mp_id,
			fep_svc->service_name,
			fep_svc->ovld_name,
			fep_svc->ovld_tps,
			fep_svc->olcd_table_index,
			fep_svc->bep_use,
			fep_svc->bep_conn);
}

int get_proc_table_index(char *proc_name)
{
	FILE *fp = NULL;
	int keepaliveIndex = 0;

	char buff[1024] = {0,};
    char fname[1024] = {0,};
    char token[1024] = {0,};

	int find_res = -1;

    /* ~/data/sysconfig */
    sprintf(fname,"%s/%s", getenv(IV_HOME), SYSCONF_FILE);

    if((fp = fopen(fname,"r")) == NULL) 
		goto GPTI_RET;

    if (conflib_seekSection (fp, "APPLICATIONS") < 0 )
		goto GPTI_RET;

    while (fgets(buff, sizeof(buff), fp) != NULL) {
        if (buff[0] == '[') /* end of section */
            break;
        if (buff[0]=='#' || buff[0]=='\n') /* comment line or empty */
            continue;

        sscanf(buff, "%s", token);
        if (!strcasecmp(token, proc_name)) {
			find_res = keepaliveIndex;
			goto GPTI_RET;
        }
        keepaliveIndex++;
    }

GPTI_RET:
	if (fp)
		fclose(fp);

	return find_res;
}

int set_overload_info(main_ctx_t *MAIN_CTX, config_setting_t *elem)
{
	config_setting_t *cf_svc_name = config_setting_lookup(elem, "svc_name");
	config_setting_t *cf_ovld_name = config_setting_lookup(elem, "ovld_name");
	config_setting_t *cf_proc_name = config_setting_lookup(elem, "proc_name");
	config_setting_t *cf_bep_use = config_setting_lookup(elem, "use_bep");
	config_setting_t *cf_all_active = config_setting_lookup(elem, "chk_all_active");

	if (cf_svc_name == NULL || cf_ovld_name == NULL || cf_proc_name == NULL || cf_bep_use == NULL || cf_all_active == NULL) {
		APPLOG(APPLOG_ERR, "{{{INIT}}} cfg service info wrong, must exist [svc_name][ovld_name][proc_name][chk_all_active][use_bep]!");
		return -1;
	}

	service_info_t svc_info = {0,};

	//svc_info.sys_mp_id = get_sys_label_num();
	svc_info.sys_mp_id = MAIN_CTX->my_info.myLabelNum;
	sprintf(svc_info.service_name, "%s",  config_setting_get_string(cf_svc_name));
	sprintf(svc_info.ovld_name, "%s", config_setting_get_string(cf_ovld_name));
    svc_info.chk_all_active = config_setting_get_int(cf_all_active);
	svc_info.bep_use = config_setting_get_int(cf_bep_use);

    int proc_num = config_setting_length(cf_proc_name);
    svc_info.proc_num = proc_num <= MAX_NRFC_CHK_PROC ? proc_num : MAX_NRFC_CHK_PROC;

    APPLOG(APPLOG_ERR, "{{{INIT}}} SVC=(%s:%s) CHK_ALL_ACTIVE=(%d) CHK_BEP=(%d) MEMBER_NUM=(%d)",
        svc_info.service_name, svc_info.ovld_name, svc_info.chk_all_active, svc_info.bep_use, svc_info.proc_num);

    for (int i = 0; i < svc_info.proc_num ; i++) {
        sprintf(svc_info.proc_name[i], "%s", config_setting_get_string_elem(cf_proc_name, i));
        APPLOG(APPLOG_ERR, "{{{INIT}}} %02d member [%s]", i, svc_info.proc_name[i]);
    }

	if ((svc_info.olcd_table_index = get_olcd_index_with_tps(svc_info.ovld_name, &svc_info.ovld_tps)) < 0) {
		APPLOG(APPLOG_ERR, "{{{INIT}}} cant find service info [%s] from OVLD_TABLE", svc_info.ovld_name);
		return -1;
	}

    for(int i = 0; i < svc_info.proc_num; i++) {
        if ((svc_info.proc_table_index[i] = get_proc_table_index(svc_info.proc_name[i])) < 0) {
            APPLOG(APPLOG_ERR, "{{{INIT}}} cant find service info [%s] from PROC_TABLE", svc_info.proc_name[i]);
            return -1;
        }
    }

	service_info_t *fep_svc = malloc(sizeof(service_info_t));
	memcpy(fep_svc, &svc_info, sizeof(service_info_t));
	MAIN_CTX->my_service_list = g_slist_append(MAIN_CTX->my_service_list, fep_svc);

	return 0;
}

int get_overload_info(main_ctx_t *MAIN_CTX)
{
	config_setting_t *setting_ovld = config_lookup(&MAIN_CTX->CFG, CF_OVLDINFO);
	if (setting_ovld == NULL) {
		APPLOG(APPLOG_ERR, "{{{INIT}}} config read fail(%s)!", CF_OVLDINFO);
	}
	int api_num = config_setting_length(setting_ovld);
	for (int i = 0; i < api_num; i++) {
		config_setting_t *elem = config_setting_get_elem(setting_ovld, i);
		if (set_overload_info(MAIN_CTX, elem) < 0) {
			APPLOG(APPLOG_ERR, "{{{INIT}}} fail to get overload info!\n");
			return -1;
		}
	}

	// check
	g_slist_foreach(MAIN_CTX->my_service_list, (GFunc)fep_service_log, NULL);

	return 0;
}

void init_log(main_ctx_t *MAIN_CTX)
{
    char log_path[1024] = {0,};
#ifdef LOG_LIB
    sprintf(log_path, "%s/log/STACK/%s", getenv(IV_HOME), MAIN_CTX->my_info.myProcName);
    initlog_for_loglib(MAIN_CTX->my_info.myProcName, log_path);
#elif LOG_APP
    sprintf(log_path, "%s/log/STACK", getenv(IV_HOME));
    LogInit(MAIN_CTX->my_info.myProcName, log_path);
#endif
    
    // read log level
    int log_level = 0;
    config_lookup_int(&MAIN_CTX->CFG, CF_LOGLEVEL, &log_level);
    *lOG_FLAG = log_level;

    APPLOG(APPLOG_ERR, "{{{INIT}}} WELCOME loglevel is [%d]\n", log_level);
}


int initialize(main_ctx_t *MAIN_CTX)
{
    def_sigaction();

    if (get_my_info(&MAIN_CTX->my_info, "NRFC") < 0) {
        fprintf(stderr, "{{{INIT}}} fail to get my info [MY_SYS_NAME:~associate_config], proc down\n");
        return -1;
    }

    init_cfg(&MAIN_CTX->CFG);

    init_log(MAIN_CTX);

    /* create msgq id(s) */
    if (get_my_qid(MAIN_CTX) < 0) {
        APPLOG(APPLOG_ERR, "{{{INIT}}} fail to get qid, proc down");
        return -1;
    }

	init_cmd(MAIN_CTX);

	init_mml(MAIN_CTX);

    /* load fep assoc list */
	if ((MAIN_CTX->lb_assoc_list = get_associate_node(MAIN_CTX->lb_assoc_list, "LB")) == NULL) {
        APPLOG(APPLOG_ERR, "{{{INIT}}} fail to get associate_lb, but proc continue");
        //return -1;
    }

	/* attach to overload table */

#ifdef OVLD_2TEAM
	if (ovldlib_init (0, MAIN_CTX->my_info.myProcName) < 0) {
#else
    if (ovldlib_attach_shm () < 0) {
#endif
        APPLOG(APPLOG_ERR, "{{{INIT}}} fail to attach overload table, proc down");
        return -1;
	}

	/* attach to ISIFC table */
    if (MAIN_CTX->sysconfig.isifcs_mode == 1 && isifc_init() < 0) {
        APPLOG(APPLOG_ERR, "{{{INIT}}} fail to attach isifc table, proc down");
        return -1;
    }

    /* I'm alive & attach to Process Status || TODO!!! CHECK ?? get_index func is empty */
    if (keepalivelib_init(MAIN_CTX->my_info.myProcName) < 0) {
        APPLOG(APPLOG_ERR, "{{{INIT}}} keepalive init fail!");
        return -1;
    }

	/* get overload info */
	if (get_overload_info(MAIN_CTX) < 0) {
        APPLOG(APPLOG_ERR, "{{{INIT}}} fail to get overload info, proc down");
        return -1;
	}

	/* create nfs avail shared memory */
#if 0
	if (MAIN_CTX->sysconfig.nfs_shm_create == 1 && create_nfs_avail_shm(MAIN_CTX) < 0) {
        APPLOG(APPLOG_ERR, "{{{INIT}}} fail to create nfs avail shared mem, proc down");
        return -1;
	} else {
        APPLOG(APPLOG_ERR, "{{{INIT}}} clear NFS SHM");
        memset(MAIN_CTX->SHM_NFS_AVAIL, 0x00, sizeof(nfs_avail_shm_t));
    }
#else
    if (MAIN_CTX->sysconfig.nfs_shm_create == 1) {
        if (create_nfs_avail_shm(MAIN_CTX) < 0) {
            APPLOG(APPLOG_ERR, "{{{INIT}}} fail to create nfs avail shared mem, proc down");
            return -1;
        }
        APPLOG(APPLOG_ERR, "{{{INIT}}} clear NFS SHM");
        memset(MAIN_CTX->SHM_NFS_AVAIL, 0x00, sizeof(nfs_avail_shm_t));
    }
#endif

    return 0;
}

int create_nfs_avail_shm(main_ctx_t *MAIN_CTX)
{
	char fname[1024] = {0,};
    sprintf(fname,"%s/%s", getenv(IV_HOME), SYSCONF_FILE);

	char tmp[1024] = {0,};
    if (conflib_getNthTokenInFileSection (fname, "SHARED_MEMORY_KEY", "SHM_NFS_CONN", 1, tmp) < 0 )
        return -1;
    int nfs_shm_key = strtol(tmp,(char**)0,0);

	int nfs_shm_id = 0;
    if ((nfs_shm_id = (int)shmget (nfs_shm_key, sizeof(nfs_avail_shm_t), 0644|IPC_CREAT)) < 0) {
        APPLOG(APPLOG_ERR,"[%s] SHM_NFS_CONN shmget fail; err=%d(%s)", __func__, errno, strerror(errno));
        return -1;
    }
    if ((void*)(MAIN_CTX->SHM_NFS_AVAIL = (nfs_avail_shm_t *)shmat(nfs_shm_id,0,0)) == (void*)-1) {
        APPLOG(APPLOG_ERR,"[%s] SHM_NFS_CONN shmat fail; err=%d(%s)", __func__, errno, strerror(errno));
        return -1;
    }

	return 0;
}

int main()
{
    if (initialize(&MAIN_CTX) < 0) {
        APPLOG(APPLOG_ERR, "{{{INIT}}} fail to initialize, proc down");
        return -1;
    } else {
        APPLOG(APPLOG_ERR, "{{{INIT}}} succ to initialize, proc up");
        sleep(1);
    }

    start_loop(&MAIN_CTX);
}

void main_tick_callback(evutil_socket_t fd, short what, void *arg)
{
    keepalivelib_increase();
    //APPLOG(APPLOG_ERR, "{{{DBG}}} %s called!", __func__);
}

int set_bep_conn_num(SHM_IsifConnSts *shmConnSts)
{
    if (MAIN_CTX.sysconfig.isifcs_mode == 0)
        return 0;

	int conn_count = 0;

	SHM_IsifConnList *isifc_conn = 
		(shmConnSts->updateTime[0] > shmConnSts->updateTime[1]) ? 
		&shmConnSts->sts[0] : &shmConnSts->sts[1];

	for (int i = 0; i < SFM_ISIF_MAX_CONN_NUM; i++) {
		SHM_IsifConnInfo *conn_info = &isifc_conn->conn[i];
		if (conn_info->setID <= 0)
			continue;
		if (strcmp(conn_info->sysType, "BEP"))
			continue;
		if (conn_info->status == SFM_LAN_CONNECTED) /* connected */
			conn_count ++;
	}

	return conn_count;
}

void collect_service_status(service_info_t *fep_svc)
{
	fep_svc->curr_tps = ovldInfo->sts.last_svc_tps[fep_svc->olcd_table_index];
#if 0
	fep_svc->curr_load = (int)((double)fep_svc->curr_tps / (double)fep_svc->ovld_tps * 100);
#else
	fep_svc->curr_load = (int)round((double)fep_svc->curr_tps / (double)fep_svc->ovld_tps * 100);
#endif
    int proc_status = 0;
    for (int i = 0; i < fep_svc->proc_num; i++) {
        fep_svc->proc_last_count[i] = fep_svc->proc_curr_count[i];
        fep_svc->proc_curr_count[i] = keepalive->cnt[fep_svc->proc_table_index[i]];
        proc_status += (fep_svc->proc_last_count[i] == fep_svc->proc_curr_count[i]) ? -1 : 1;
    }
    if (fep_svc->chk_all_active == 1 && proc_status != fep_svc->proc_num) {
        fep_svc->proc_alive = -1; // some fail mean all fail
    } else if (fep_svc->chk_all_active != 1 && proc_status == (-1 * fep_svc->proc_num)) {
        fep_svc->proc_alive = -1; // all fail mean all fail
    } else {
        fep_svc->proc_alive = 1;
    }
	fep_svc->bep_conn = set_bep_conn_num(shmConnSts);
	APPLOG(APPLOG_ERR, "{{{DBG}}} svc[%s] tps[curr:%d/max:%d] load[%d] alive[%s] bep[%d(conn:%d)]",
			fep_svc->service_name,
			fep_svc->curr_tps,
			fep_svc->ovld_tps,
			fep_svc->curr_load,
			(fep_svc->proc_alive > 0) ? "alive" : "dead",
			fep_svc->bep_use,
			fep_svc->bep_conn);
}

void send_status_to_lb(service_info_t *fep_svc, assoc_t *lb_assoc)
{
	IsifMsgType txIsifMsg = {0,};

    fep_svc->mtype = LIBNRF_MSG_SERVICE_INFO;

	isifc_create_pkt(&txIsifMsg, &MAIN_CTX.my_info, lb_assoc, fep_svc, sizeof(service_info_t));
	isifc_send_pkt(MAIN_CTX.my_qid.isifc_tx_qid, &txIsifMsg);
}

void broad_status_to_lb(assoc_t *lb_assoc)
{
	/* for loop service --> send servive status */
	g_slist_foreach(MAIN_CTX.my_service_list, (GFunc)send_status_to_lb, lb_assoc);
}

void service_status_broadcast(evutil_socket_t fd, short what, void *arg)
{
	/* collect each service info */
	g_slist_foreach(MAIN_CTX.my_service_list, (GFunc)collect_service_status, NULL);

    if (MAIN_CTX.sysconfig.isifcs_mode == 1) {
		/* send service info to each lb */
        g_slist_foreach(MAIN_CTX.lb_assoc_list, (GFunc)broad_status_to_lb, NULL);
    } else {
		/* send service info to local NRFM */
        assoc_t lb_assoc = {0,};
        memset(&lb_assoc, 0x00, sizeof(assoc_t));
        g_slist_foreach(MAIN_CTX.my_service_list, (GFunc)send_status_to_lb, &lb_assoc);
    }
}

void start_loop(main_ctx_t *MAIN_CTX)
{
    // single thread program, no evthread_use_pthreads()
    MAIN_CTX->EVBASE = event_base_new();

    /* every 1 sec */
    struct timeval tic_sec = {1,0};

    struct event *ev_tick = event_new(MAIN_CTX->EVBASE, -1, EV_PERSIST, main_tick_callback, NULL);
    event_add(ev_tick, &tic_sec);

	struct event *ev_send_status = event_new(MAIN_CTX->EVBASE, -1, EV_PERSIST, service_status_broadcast, NULL);
    event_add(ev_send_status, &tic_sec);

    if (MAIN_CTX->sysconfig.nfs_shm_create == 1) {
        struct event *ev_clear_status = event_new(MAIN_CTX->EVBASE, -1, EV_PERSIST, clear_fep_nfs, NULL);
        event_add(ev_clear_status, &tic_sec);
    }

    /* every 100 ms */
    struct timeval tm_milisec = {0, 100000}; // 100ms

    struct event *ev_msgq = event_new(MAIN_CTX->EVBASE, -1, EV_PERSIST, message_handle, NULL);
    event_add(ev_msgq, &tm_milisec);

	struct event *ev_shmq = event_new(MAIN_CTX->EVBASE, -1, EV_PERSIST, shmq_recv_handle, NULL);
	event_add(ev_shmq, &tm_milisec);

	/* start watching ~/data directory */
    if (MAIN_CTX->sysconfig.isifcs_mode == 1) {
        start_watching_dir(MAIN_CTX->EVBASE);
    }

    /* start loop */
    event_base_loop(MAIN_CTX->EVBASE, EVLOOP_NO_EXIT_ON_EMPTY);

    event_base_free(MAIN_CTX->EVBASE);
}

void shmq_recv_handle(evutil_socket_t fd, short what, void *arg)
{
    char msgBuff[1024*64];
    IsifMsgType *rxIsifMsg = (IsifMsgType *)msgBuff;

    int ret = 0;
    
    while ((ret = shmqlib_getMsg(MAIN_CTX.my_qid.isifs_rx_qid, (char *)rxIsifMsg)) > 0) {
    
        if (ret > sizeof(IsifMsgType)) {
            APPLOG(APPLOG_ERR, "%s() receive unknown size(%d) msg!", __func__, ret);
            continue;
        }

        switch (rxIsifMsg->head.mtype) {
            case MTYPE_NRFM_BROAD_STATUS_TO_FEP:
                if (MAIN_CTX.sysconfig.nfs_shm_create == 1) {
                    isif_save_recv_lb_status(&MAIN_CTX, (nf_service_info *)rxIsifMsg->body);
                }
                continue;
            default:
                APPLOG(APPLOG_ERR, "%s() receive unknown type(%d) msg!", __func__, rxIsifMsg->head.mtype);
                continue;
        }
    }
    return;
}

void directory_watch_action(const char *file_name)
{
	if (!strcmp(file_name, "associate_config")) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s() detect \"associate_config\" changed!", __func__);
		MAIN_CTX.lb_assoc_list = get_associate_node(MAIN_CTX.lb_assoc_list, "LB");
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s() re-arrange FEP node done!", __func__);
	}
}

void start_watching_dir(struct event_base *evbase)
{
	char watch_directory[1024] = {0,};
	sprintf(watch_directory, "%s/data", getenv("IV_HOME"));
	watch_directory_init(evbase, watch_directory, directory_watch_action);
}
