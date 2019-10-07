#include <nrfc.h>

main_ctx_t MAIN_CTX;
int logLevel = APPLOG_DEBUG;
int *lOG_FLAG = &logLevel;
extern T_OverloadInfo *ovldInfo;	// for API TPS
extern T_keepalive *keepalive;		// for Process Status
extern SHM_IsifConnSts *shmConnSts;		// for BEP conn Status

int get_my_qid(main_ctx_t *MAIN_CTX)
{
    char fname[1024] = {0,};
    char tmp[64] = {0,};
    int key = 0;

    /* ~/data/sysconfig */
    sprintf(fname,"%s/%s", getenv(IV_HOME), SYSCONF_FILE);

    /* create receive queue */
    if (conflib_getNthTokenInFileSection (fname, "APPLICATIONS", MAIN_CTX->my_info.myProcName, 3, tmp) < 0) {
        APPLOG(APPLOG_ERR, "{{{INIT}}} configlib get token APPLICATIONS [%s] fail!", MAIN_CTX->my_info.myProcName);
        return -1;
    }
    key = strtol(tmp,0,0);
    if ((MAIN_CTX->my_qid.nrfc_qid = msgget(key,IPC_CREAT|0666)) < 0) {
        APPLOG(APPLOG_ERR,"{{{INIT}}} [%s] msgget fail; key=0x%x,err=%d(%s)!", __func__, key, errno, strerror(errno));
        return -1;
	}

	/* ~/data/isif.conf */
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
	APPLOG(APPLOG_ERR, "{{{CHECK}}} mp(%d) (%s:%s:%s:tps %d), olcd index(%d) proc index(%d) use_bep(%d:conn %d)",
			fep_svc->sys_mp_id,
			fep_svc->service_name,
			fep_svc->ovld_name,
			fep_svc->proc_name,
			fep_svc->ovld_tps,
			fep_svc->olcd_table_index,
			fep_svc->proc_table_index,
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

	if (cf_svc_name == NULL || cf_ovld_name == NULL || cf_proc_name == NULL || cf_bep_use == NULL) {
		APPLOG(APPLOG_ERR, "{{{INIT}}} cfg service info wrong, must exist [svc_name][ovld_name][proc_name][use_bep]!");
		return -1;
	}

	service_info_t svc_info = {0,};

	svc_info.sys_mp_id = atoi(getenv("SYS_MP_ID"));
	sprintf(svc_info.service_name, "%s",  config_setting_get_string(cf_svc_name));
	sprintf(svc_info.ovld_name, "%s", config_setting_get_string(cf_ovld_name));
	sprintf(svc_info.proc_name, "%s", config_setting_get_string(cf_proc_name));
	svc_info.bep_use = config_setting_get_int(cf_bep_use);

	if ((svc_info.olcd_table_index = get_olcd_index_with_tps(svc_info.ovld_name, &svc_info.ovld_tps)) < 0) {
		APPLOG(APPLOG_ERR, "{{{INIT}}} cant find service info [%s] from OVLD_TABLE", svc_info.ovld_name);
		return -1;
	}

	if ((svc_info.proc_table_index = get_proc_table_index(svc_info.proc_name)) < 0) {
		APPLOG(APPLOG_ERR, "{{{INIT}}} cant find service info [%s] from PROC_TABLE", svc_info.proc_name);
		return -1;
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
    sprintf(log_path, "%s/log/ERR_LOG/%s", getenv(IV_HOME), MAIN_CTX->my_info.myProcName);
    initlog_for_loglib(MAIN_CTX->my_info.myProcName, log_path);
#elif LOG_APP
    sprintf(log_path, "%s/log", getenv(IV_HOME));
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

    get_my_info(&MAIN_CTX->my_info, "NRFC");

    init_cfg(&MAIN_CTX->CFG);

    init_log(MAIN_CTX);

    /* create msgq id(s) */
    if (get_my_qid(MAIN_CTX) < 0) {
        APPLOG(APPLOG_ERR, "{{{INIT}}} fail to get qid, proc down");
        return -1;
    }

    /* load fep assoc list */
	if ((MAIN_CTX->lb_assoc_list = get_associate_node(MAIN_CTX->lb_assoc_list, "LB")) == NULL) {
        APPLOG(APPLOG_ERR, "{{{INIT}}} fail to get associate_lb, proc down");
        return -1;
    }

	/* attach to overload table */
	if (ovldlib_init (MAIN_CTX->my_info.myProcName) < 0) {
        APPLOG(APPLOG_ERR, "{{{INIT}}} fail to attach overload table, proc down");
        return -1;
	}

	/* attach to ISIFC table */
	if (isifc_init() < 0) {
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
	fep_svc->curr_load = (int)((double)fep_svc->curr_tps / (double)fep_svc->ovld_tps * 100);
	fep_svc->proc_last_count = fep_svc->proc_curr_count;
	fep_svc->proc_curr_count = keepalive->cnt[fep_svc->proc_table_index];
	fep_svc->proc_alive = (fep_svc->proc_last_count == fep_svc->proc_curr_count) ? -1 : 1;
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

	isifc_create_pkt_for_status(&txIsifMsg, fep_svc, &MAIN_CTX.my_info, lb_assoc);
	isifc_send_pkt_for_status(MAIN_CTX.my_qid.isifc_tx_qid, &txIsifMsg);
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
	/* send service info to each lb */
	g_slist_foreach(MAIN_CTX.lb_assoc_list, (GFunc)broad_status_to_lb, NULL);
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

    /* every 100 ms */
    struct timeval tm_milisec = {0, 100000}; // 100ms

    struct event *ev_msgq = event_new(MAIN_CTX->EVBASE, -1, EV_PERSIST, message_handle, NULL);
    event_add(ev_msgq, &tm_milisec);

	/* start watching ~/data directory */
	start_watching_dir(MAIN_CTX->EVBASE);

    /* start loop */
    event_base_loop(MAIN_CTX->EVBASE, EVLOOP_NO_EXIT_ON_EMPTY);

    event_base_free(MAIN_CTX->EVBASE);
}


void message_handle(evutil_socket_t fd, short what, void *arg)
{
    char msgBuff[1024*64];

    GeneralQMsgType *msg = (GeneralQMsgType *)msgBuff;

    /* handle all pending msgs */
    while (msgrcv(MAIN_CTX.my_qid.nrfc_qid, msg, sizeof(GeneralQMsgType), 0, IPC_NOWAIT) >= 0) {
        switch (msg->mtype) {
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
	watch_directory_init(evbase, watch_directory);
}
