#include "nrf_comm.h"

void def_sigaction()
{
    struct sigaction act;

    memset(&act, 0, sizeof(struct sigaction));
    act.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &act, NULL);
}

GSList *get_associate_node(GSList *node_assoc_list, const char *type_str)
{
    /* remove all fep list (prepare for scale in/out) */
    node_list_remove_all(node_assoc_list);
	GSList *new_assoc = NULL;

    char fname[1024] = {0,};
    sprintf(fname,"%s/%s", getenv(IV_HOME), ASSOCONF_FILE);

    FILE *fp = fopen(fname, "r");
    if (fp == NULL) {
        fprintf(stderr, "'%s' not opened\n", fname);
        return NULL;
    }

    char buffer[2048] = {0,};
    while (fgets(buffer, 2048, fp)) {
        assoc_t node_elem = {0,};

        sscanf(buffer, "%s%*s%s%s %*s%*s%*s %s", node_elem.name, node_elem.type, node_elem.group, node_elem.ip);
        if (isalpha(node_elem.name[0]) == 0)
            continue;
        if (strcmp(node_elem.type, type_str))
            continue;

        struct sockaddr_in sa = {0,};
        if (inet_pton(AF_INET, node_elem.ip, &(sa.sin_addr)) == 0)
            continue;

        /* re-arrange fep list */
        new_assoc = node_list_add_elem(new_assoc, &node_elem);
    }
    fclose(fp);

    /* check fep list */
    node_list_print_log(new_assoc);

	return new_assoc;
}

void get_my_info(svr_info_t *my_info, const char *my_proc_name)
{
    char fname[1024] = {0,};

    sprintf(my_info->mySysName, "%s", getenv(MY_SYS_NAME));
    sprintf(my_info->myProcName, "%s", my_proc_name);

    sprintf(fname, "%s/%s", getenv(IV_HOME), SYSCONF_FILE);
    conflib_getNthTokenInFileSection (fname, "GENERAL", "SYSTEM_TYPE", 1, my_info->mySysType);
    conflib_getNthTokenInFileSection (fname, "GENERAL", "SERVER_ID", 1, my_info->mySvrId);

    fprintf(stderr, "TEST| %s %s %s %s\n",
            my_info->mySysName,
            my_info->myProcName,
            my_info->mySysType,
            my_info->mySvrId);
}

void node_assoc_release(assoc_t *node_elem)
{
    APPLOG(APPLOG_ERR, "{{{CHECK}}} node_elem (%s:%s:%s:%s) released!",
            node_elem->name, node_elem->type, node_elem->group, node_elem->ip);
    free(node_elem);
}

void node_list_remove_all(GSList *node_assoc_list)
{
    // TODO !!! check release func
    g_slist_free_full(node_assoc_list, (GDestroyNotify)node_assoc_release);
}

GSList *node_list_add_elem(GSList *node_assoc_list, assoc_t *node_elem)
{
    assoc_t *node_add = malloc(sizeof(assoc_t));
    memcpy(node_add, node_elem, sizeof(assoc_t));
    node_assoc_list = g_slist_append(node_assoc_list, node_add);

	return node_assoc_list;
}

void node_assoc_log(assoc_t *node_elem)
{
    APPLOG(APPLOG_ERR, "{{{CHECK}}} node_elem (%s:%s:%s:%s) exist!",
            node_elem->name, node_elem->type, node_elem->group, node_elem->ip);
}

void node_list_print_log(GSList *node_assoc_list)
{
    g_slist_foreach(node_assoc_list, (GFunc)node_assoc_log, NULL);
}

#define NOTIFY_WATCH_MAX_BUFF (1024 * 12)
extern void directory_watch_action(const char *file_name);
static void config_watch_callback(struct bufferevent *bev, void *args)
{   
    char buf[NOTIFY_WATCH_MAX_BUFF] = {0,};
    size_t numRead = bufferevent_read(bev, buf, NOTIFY_WATCH_MAX_BUFF);
    char *ptr; 
    for (ptr = buf; ptr < buf + numRead; ) {
        struct inotify_event *event = (struct inotify_event*)ptr;
        if (event->len > 0) {
            /* function point */
			directory_watch_action(event->name);
        }
        ptr += sizeof(struct inotify_event) + event->len;
    }
}

int watch_directory_init(struct event_base *evbase, const char *path_name)
{
	int inotifyFd = inotify_init();
	if (inotifyFd == -1) {
		fprintf(stderr, "INIT| ERR| inotify init fail!\n");
		return -1;
	}

	int inotifyWd = inotify_add_watch(inotifyFd, path_name, IN_CLOSE_WRITE | IN_MOVED_TO);
	if (inotifyWd == -1) {
		fprintf(stderr, "INIT| ERR| inotify add watch [%s] fail!\n", path_name);
		return -1;
	} else {
		fprintf(stderr, "INIT| inotify add watch [%d:%s]\n", inotifyWd, path_name);
	}


	struct bufferevent *ev_watch = bufferevent_socket_new(evbase, inotifyFd, BEV_OPT_CLOSE_ON_FREE);
	bufferevent_setcb(ev_watch, config_watch_callback, NULL, NULL, NULL);
	bufferevent_enable(ev_watch, EV_READ);

	return 0;
}

acc_token_info_t *get_acc_token_info(acc_token_shm_t *ACC_TOKEN_LIST, int id, int used)
{
	if (id < 1 || id > MAX_ACC_TOKEN_NUM)
		return NULL;

	if (used) {
		// get my 
		if (ACC_TOKEN_LIST->acc_token[id].occupied != 1)
			return NULL;

		return &ACC_TOKEN_LIST->acc_token[id];
	} else {
		// assign new
		if (ACC_TOKEN_LIST->acc_token[id].occupied == 1)
			return NULL;

		ACC_TOKEN_LIST->acc_token[id].occupied = 1;
		return &ACC_TOKEN_LIST->acc_token[id];
	}

	return NULL;
}

acc_token_info_t *new_acc_token_info(acc_token_shm_t *ACC_TOKEN_LIST)
{
	for (int id = MAX_ACC_TOKEN_NUM; id > 0; id--) {
		acc_token_info_t *token_info = &ACC_TOKEN_LIST->acc_token[id];
		if (token_info->occupied == 0) {
			memset(token_info, 0x00, sizeof(acc_token_info_t));
			token_info->occupied = 1;
			token_info->token_id = id;
			return token_info;
		}
	}

	return NULL;
}

char *get_access_token(acc_token_shm_t *ACC_TOKEN_LIST, int token_id)
{
    if (token_id < 0 || token_id >= MAX_ACC_TOKEN_NUM)
        return NULL;

    acc_token_info_t *token_info = &ACC_TOKEN_LIST->acc_token[token_id];
    if (token_info->status != TA_ACQUIRED)
        return NULL;
    
    int pos = token_info->token_pos;
    return token_info->access_token[pos];
} 

void print_token_info_raw(acc_token_shm_t *ACC_TOKEN_LIST, char *resBuf)
{
    sprintf(resBuf + strlen(resBuf), "INDEX   ID TYPE  NFTYPE  NF_INSTANCE_ID                             SCOPE                            TOKEN_STATUS REQUEST_TIME          VALIDATE_TIME         TOKEN_INFO ACCESS_TOKEN\n");
    sprintf(resBuf + strlen(resBuf), "------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n");

    for (int i = 1; i < MAX_ACC_TOKEN_NUM; i++) {
        acc_token_info_t *token_info = get_acc_token_info(ACC_TOKEN_LIST, i, 1);
        if (token_info == NULL) {
            continue;
        } else {
            char request_time[128] = {0,};
            char validate_time[128] = {0,};
            sprintf(request_time, "%.19s", ctime(&token_info->last_request_time));
            sprintf(validate_time, "%.19s", ctime(&token_info->due_date));
            sprintf(resBuf + strlen(resBuf), "%4d] %4d %-5s   %-5s [%-40s] [%-30s] [%10s] [%.19s] [%.19s] [%8s] [%s]\n",
            i,
            token_info->token_id,
            (token_info->acc_type == AT_SVC) ? "SVC" : "INST",
            strlen(token_info->nf_type) ? token_info->nf_type : "-",
            token_info->nf_instance_id,
            strlen(token_info->scope) ? token_info->scope : "-",
            (token_info->status == TA_INIT) ? "INIT" :
            (token_info->status == TA_FAILED) ? "FAILED" :
            (token_info->status == TA_TRYING) ? "TRYING" : "ACCUIRED",
            request_time,
            validate_time,
            (token_info->operator_added) ? "OPER_ADD" : "AUTO_ADD",
            (token_info->status == TA_ACQUIRED) ? token_info->access_token[token_info->token_pos] : "-");
        }
    }
    sprintf(resBuf + strlen(resBuf), "------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n");
}


void print_nrfm_mml_raw(nrfm_mml_t *httpc_cmd)
{
    APPLOG(APPLOG_ERR, "nrfm_mml_t ===================================================================================");
    APPLOG(APPLOG_ERR, "command[%d] host[%s] type[%s] info_cnt[%d]",
            httpc_cmd->command, httpc_cmd->host, httpc_cmd->type, httpc_cmd->info_cnt);
    for (int i = 0; i < httpc_cmd->info_cnt; i++) {
        APPLOG(APPLOG_ERR, "occupied[%d] scheme[%s] ip[%s] port[%d] cnt[%d]",
                httpc_cmd->nf_conns[i].occupied,
                httpc_cmd->nf_conns[i].scheme,
                httpc_cmd->nf_conns[i].ip,
                httpc_cmd->nf_conns[i].port,
                httpc_cmd->nf_conns[i].cnt);
    }
    APPLOG(APPLOG_ERR, "===========================================================================================end");
}

char *get_nrfm_cmd_str(int cmd)
{
    switch (cmd) {
        case NRFM_MML_HTTPC_ADD:
			return "ADD";
		case NRFM_MML_HTTPC_ACT:
			return "ACT";
        case NRFM_MML_HTTPC_DACT:
			return "DACT";
        case NRFM_MML_HTTPC_DEL:
			return "DEL";
		case NRFM_MML_HTTPC_CLEAR:
			return "<CLEAR!!!>";
		default:
			return "UNKNOWN";
    }
}
