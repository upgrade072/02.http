#include <nrfm.h>

main_ctx_t MAIN_CTX;

int logLevel = APPLOG_DEBUG;
int *lOG_FLAG = &logLevel;

int ixpcQid; // for MML CMD

int get_my_profile(main_ctx_t *MAIN_CTX)
{
	MAIN_CTX->my_nf_profile = create_json_with_cfg(&MAIN_CTX->CFG);

	if (MAIN_CTX->my_nf_profile == NULL) {
		APPLOG(APPLOG_ERR, "{{{INIT}}} fail to load NF_PROFILE");
		return -1;
	} else {
		/* replace $func val */
		recurse_json_obj(MAIN_CTX->my_nf_profile, MAIN_CTX, NULL);

		LOG_JSON_OBJECT("MY NF PROFILE IS", MAIN_CTX->my_nf_profile);
		return 0;
	}
}

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
	if ((MAIN_CTX->my_qid.nrfm_qid = msgget(key,IPC_CREAT|0666)) < 0) {
		APPLOG(APPLOG_ERR,"{{{INIT}}} [%s] msgget fail; key=0x%x,err=%d(%s)!", __func__, key, errno, strerror(errno));
		return -1;
	}

	/* create send request queue */
	if (conflib_getNthTokenInFileSection (fname, "APPLICATIONS", "HTTPC", 3, tmp) < 0) {
		APPLOG(APPLOG_ERR, "{{{INIT}}} configlib get token APPLICATIONS [HTTPC] fail!");
		return -1;
	}
	key = strtol(tmp,0,0);
	if ((MAIN_CTX->my_qid.httpc_qid = msgget(key,IPC_CREAT|0666)) < 0) {
		APPLOG(APPLOG_ERR, "{{{INIT}}} [%s] msgget fail; key=0x%x,err=%d(%s)!", __func__, key, errno, strerror(errno));
		return -1;
	}

	/* create send response queue */
	if (conflib_getNthTokenInFileSection (fname, "APPLICATIONS", "HTTPS", 3, tmp) < 0) {
		APPLOG(APPLOG_ERR, "{{{INIT}}} configlib get token APPLICATIONS [HTTPS] fail!");
		return -1;
	}
	key = strtol(tmp,0,0);
	if ((MAIN_CTX->my_qid.https_qid = msgget(key,IPC_CREAT|0666)) < 0) {
		APPLOG(APPLOG_ERR, "{{{INIT}}} [%s] msgget fail; key=0x%x,err=%d(%s)!", __func__, key, errno, strerror(errno));
		return -1;
	}

	/* ~/data/isif.conf */
    sprintf(fname,"%s/%s", getenv(IV_HOME), ISIF_CONF_FILE);
    if ((MAIN_CTX->my_qid.isifs_rx_qid = 
                shmqlib_getQid (fname, "ISIFS_TO_APP_SHMQ", MAIN_CTX->my_info.myProcName, SHMQLIB_MODE_GETTER)) < 0) {
        APPLOG(APPLOG_ERR,"{{{INIT}}} fail to get isifs rx qid %s:%s!", fname, MAIN_CTX->my_info.myProcName);
        return -1;
    }

    if ((MAIN_CTX->my_qid.isifc_tx_qid = 
                shmqlib_getQid (fname, "APP_TO_ISIFC_SHMQ", MAIN_CTX->my_info.myProcName, SHMQLIB_MODE_PUTTER)) < 0) {
        APPLOG(APPLOG_ERR,"{{{INIT}}} fail to get isifc tx qid %s:%s!", fname, MAIN_CTX->my_info.myProcName);
        return -1;
    }
    
	/* create ixpc qid for mml */
	sprintf(fname,"%s/%s", getenv(IV_HOME), SYSCONF_FILE);
	if (conflib_getNthTokenInFileSection (fname, "APPLICATIONS", "IXPC", 3, tmp) < 0) {
		APPLOG(APPLOG_ERR, "{{{INIT}}} configlib get token APPLICATIONS [IXPC] fail!");
		return -1;
	}
	key = strtol(tmp,0,0);
	if ((ixpcQid = msgget(key,IPC_CREAT|0666)) < 0) {
		APPLOG(APPLOG_ERR, "{{{INIT}}} [%s] msgget fail; key=0x%x,err=%d(%s)!", __func__, key, errno, strerror(errno));
		return -1;
	}

	return 0;
}

int get_my_service_list(main_ctx_t *MAIN_CTX)
{
	char key[128] = "my_profile/nfServices";
	json_object *js_nf_services = NULL;
	size_t service_array_len = 0;

	if ((js_nf_services = search_json_object(MAIN_CTX->my_nf_profile, key)) == NULL) {
		APPLOG(APPLOG_ERR, "{{{INIT}}} fail to search NF_SERVICES(nfServices)");
		return -1;
	}

	if ((service_array_len = json_object_array_length(js_nf_services)) == 0) {
		APPLOG(APPLOG_ERR, "{{{INIT}}} fail to get NF_SERVICES(nfServices), may be 0");
		return -1;
	}

	for (int i = 0; i < service_array_len; i++) {
		json_object *js_service_elem = json_object_array_get_idx(js_nf_services, i);
		char key[128] = "serviceName";
		json_object *js_svc_name = search_json_object(js_service_elem, key);
		
		fep_service_t *fep_svc = malloc(sizeof(fep_service_t));
		sprintf(fep_svc->service_name, "%s", json_object_get_string(js_svc_name));
		sprintf(fep_svc->path_for_load, "/nfServices/%d/load", i);
		sprintf(fep_svc->path_for_capacity, "/nfServices/%d/capacity", i);
		MAIN_CTX->fep_service_list = g_slist_append(MAIN_CTX->fep_service_list, fep_svc);
	}

	// check
	g_slist_foreach(MAIN_CTX->fep_service_list, (GFunc)fep_service_log, NULL);

	return 0;
}

void httpc_response_handle(AhifHttpCSMsgType *ahifPkt)
{
	switch (ahifPkt->head.mtype) {
		case MTYPE_NRFM_REGI_RESPONSE:
			nf_regi_handle_resp_proc(ahifPkt);
			return;
		case MTYPE_NRFM_HEARTBEAT_RESPONSE:
			nf_heartbeat_handle_resp_proc(ahifPkt);
			return;
		case MTYPE_NRFM_RETRIEVE_RESPONSE:
			nf_retrieve_list_handle_resp_proc(ahifPkt);
			return;
		case MTYPE_NRFM_NF_PROFILE_RESPONSE:
			nf_retrieve_instance_handle_resp_proc(ahifPkt);
			return;
		case MTYPE_NRFM_SUBSCRIBE_RESPONSE:
			nf_subscribe_nf_type_handle_resp_proc(ahifPkt);
			return;
		case MTYPE_NRFM_SUBSCR_PATCH_RESPONSE:
			nf_subscribe_patch_handle_resp_proc(ahifPkt);
		case MTYPE_NRFM_TOKEN_RESPONSE:
			nf_token_acquire_handlde_resp_proc(ahifPkt);
			return;
		default:
			return;
	}
}

void https_request_handle(AhifHttpCSMsgType *ahifPkt)
{
	switch (ahifPkt->head.mtype) {
		case MTYPE_NRFM_NOTIFY_REQUEST:
			nf_notify_handle_request_proc(ahifPkt);
			return;
		default:
			return;
	}
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

	get_my_info(&MAIN_CTX->my_info, "NRFM");

	init_cfg(&MAIN_CTX->CFG);

	init_log(MAIN_CTX);

	/* create msgq id(s) */
	if (get_my_qid(MAIN_CTX) < 0) {
		APPLOG(APPLOG_ERR, "{{{INIT}}} fail to get qid, proc down");
		return -1;
	}

	/* create my json nf_profile */
	if (get_my_profile(MAIN_CTX) < 0) {
		APPLOG(APPLOG_ERR, "{{{INIT}}} fail to get my_profile, proc down");
		return -1;
	}

	/* create my json nf_services ... used for collect load info (heartbeat info) */
	if (get_my_service_list(MAIN_CTX) < 0) {
		APPLOG(APPLOG_ERR, "{{{INIT}}} fail to get my_services, proc down");
		return -1;
	}

	/* create access token shm & load operator added config / remove auto added config */
	if (load_access_token_shm(MAIN_CTX) < 0) {
		APPLOG(APPLOG_ERR, "{{{INIT}}} fail to load access token shm, proc down");
		return -1;
	}

	/* load fep assoc list */
    if ((MAIN_CTX->fep_assoc_list = get_associate_node(MAIN_CTX->fep_assoc_list, "FEP")) == NULL) {
        APPLOG(APPLOG_ERR, "{{{INIT}}} fail to get associate_fep, proc down");
        return -1;
    }

	/* I'm alive */
	if (keepalivelib_init(MAIN_CTX->my_info.myProcName) < 0) {
		APPLOG(APPLOG_ERR, "{{{INIT}}} keepalive init fail!");
		return -1;
	}

	/* load nf retrieve list */
	if (load_cfg_retrieve_list(MAIN_CTX) <=0) {
		APPLOG(APPLOG_ERR, "{{{INIT}}} there is no retrieve list!");
	} else {
		log_all_cfg_retrieve_list(MAIN_CTX);
	}

	/* load nf subscribe list */
	if (load_cfg_subscribe_list(MAIN_CTX) <= 0) {
		APPLOG(APPLOG_ERR, "{{{INIT}}} there is no subscribe list!");
	} else {
		log_all_cfg_subscribe_list(MAIN_CTX);
	}

	return 0;
}

void INITIAL_PROCESS(main_ctx_t *MAIN_CTX)
{
	if (MAIN_CTX->init_regi_success != 0) {
		return;
	} else {
		/* only once */
		MAIN_CTX->init_regi_success = 1;

		/* retrieve process */
		nf_retrieve_start_process(MAIN_CTX);

		/* subscribe process */
		nf_subscribe_start_process(MAIN_CTX);

		/* start token acquire */
		nf_token_start_process(MAIN_CTX);
	}
}

int load_access_token_shm(main_ctx_t *MAIN_CTX)
{
	if ((MAIN_CTX->nrf_access_token.acc_token_shm_key = cfg_get_access_token_shm_key(MAIN_CTX)) < 0) {
		APPLOG(APPLOG_ERR, "{{{INIT}}} fail to get access token shm key, proc down");
		return -1;
	}

	if ((MAIN_CTX->nrf_access_token.acc_token_shm_id = 
				shmget((size_t)MAIN_CTX->nrf_access_token.acc_token_shm_key, SHM_ACC_TOKEN_TABLE_SIZE, IPC_CREAT|0666)) < 0) {
		APPLOG(APPLOG_ERR, "{{{INIT}}} fail to create access token shm id, proc down");
		return -1;
	}
	
	if ((MAIN_CTX->nrf_access_token.ACC_TOKEN_LIST = 
				(acc_token_shm_t *)shmat(MAIN_CTX->nrf_access_token.acc_token_shm_id, NULL, 0)) == (acc_token_shm_t *)-1) {
		APPLOG(APPLOG_ERR, "{{{INIT}}} fail to attach access token shared memory, proc down");
		return -1;
	}

	/* initialize to 0x00 */
	memset(MAIN_CTX->nrf_access_token.ACC_TOKEN_LIST, 0x00, sizeof(acc_token_shm_t));
	
	if (load_access_token_cfg(MAIN_CTX) < 0) {
		APPLOG(APPLOG_ERR, "{{{INIT}}} fail to load access token (operator added) .cfg, proc down");
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
		APPLOG(APPLOG_ERR, "Welcome ===============================================================================");
		NF_MANAGE_NF_CLEAR(&MAIN_CTX); // httpc restoration
		sleep(1);
	}


	start_loop(&MAIN_CTX);
}

void main_tick_callback(evutil_socket_t fd, short what, void *arg)
{
	keepalivelib_increase();
	//APPLOG(APPLOG_ERR, "{{{DBG}}} %s called!", __func__);
}

void message_handle(evutil_socket_t fd, short what, void *arg)
{
	char msgBuff[1024*64];

	GeneralQMsgType *msg = (GeneralQMsgType *)msgBuff;
	AhifHttpCSMsgType *ahifPkt = (AhifHttpCSMsgType *)msg->body;

	/* handle all pending msgs */
	while (msgrcv(MAIN_CTX.my_qid.nrfm_qid, msg, sizeof(GeneralQMsgType), 0, IPC_NOWAIT) >= 0) {
		switch (msg->mtype) {
			/* OMP MML */
			case MTYPE_MMC_REQUEST:
				mml_function((IxpcQMsgType *)msg->body);
				continue;
			/* FEP conn status from https */
			case MSGID_HTTPS_NRFM_FEP_ALIVE_NOTI:
				https_save_recv_fep_status(&MAIN_CTX);
				continue;
			/* NRFM request result from httpc */
			case MSGID_HTTPC_NRFM_RESPONSE:
				httpc_response_handle(ahifPkt);
				continue;
			/* HTTPS notify to NRFM */
			case MSGID_HTTPS_NRFM_REQUEST:
				https_request_handle(ahifPkt);
				continue;
			/* NRFM cmd res from httpc */
			case MSGID_HTTPC_NRFM_MMC_RESPONSE:
				nf_manage_handle_cmd_res((nrfm_mml_t *)msg->body);
				continue;
			/* check HTTPC restart */
			case MSGID_HTTPC_NRFM_IMALIVE_NOTI:
				nf_manage_handle_httpc_alive((nrfm_noti_t *)msg->body);
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

void start_loop(main_ctx_t *MAIN_CTX)
{
	// single thread program, no evthread_use_pthreads()
	MAIN_CTX->EVBASE = event_base_new();

	/* tick func */
	struct timeval tic_sec = {1,0};
	struct event *ev_tick = event_new(MAIN_CTX->EVBASE, -1, EV_PERSIST, main_tick_callback, NULL);
	event_add(ev_tick, &tic_sec);

	/* message handle */
	struct timeval tm_milisec = {0, 100000}; // 100ms
	struct event *ev_msgq = event_new(MAIN_CTX->EVBASE, -1, EV_PERSIST, message_handle, NULL);
	event_add(ev_msgq, &tm_milisec);

	struct event *ev_shmq = event_new(MAIN_CTX->EVBASE, -1, EV_PERSIST, shmq_recv_handle, NULL);
	event_add(ev_shmq, &tm_milisec);

	/* start watching ~/data directory */
	start_watching_dir(MAIN_CTX->EVBASE);

	/* start trigger */
	nf_regi_init_proc(MAIN_CTX);

	/* start loop */
	event_base_loop(MAIN_CTX->EVBASE, EVLOOP_NO_EXIT_ON_EMPTY);

	event_base_free(MAIN_CTX->EVBASE);
}

void directory_watch_action(const char *file_name)
{
	if (!strcmp(file_name, "associate_config")) {
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s() detect \"associate_config\" changed!", __func__);
		MAIN_CTX.fep_assoc_list = get_associate_node(MAIN_CTX.fep_assoc_list, "FEP");
		APPLOG(APPLOG_ERR, "{{{DBG}}} %s() re-arrange FEP node done!", __func__);
	}
}

void start_watching_dir(struct event_base *evbase)
{
	char watch_directory[1024] = {0,};
	sprintf(watch_directory, "%s/data", getenv("IV_HOME"));
	watch_directory_init(evbase, watch_directory);
}
