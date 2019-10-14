#include "libnrf.h"

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

int get_sys_label_num()
{
    char fname[1024] = {0,};
	char label[1024] = {0,};

    sprintf(fname, "%s/%s", getenv(IV_HOME), SYSCONF_FILE);
    conflib_getNthTokenInFileSection (fname, "GENERAL", "SYSTEM_LABEL", 1, label);

	char buff[1024] = {0,};
	int pos = 0;
	for (int i = 0; i < strlen(label); i++) {
		if (isdigit(label[i])) 
			buff[pos++] = label[i];
	}
	buff[pos] = '\0';

	return atoi(buff);
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

	my_info->myLabelNum = get_sys_label_num();
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

void print_token_info_raw(acc_token_shm_t *ACC_TOKEN_LIST, char *respBuff)
{
	ft_table_t *table = ft_create_table();

	ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);
	ft_set_border_style(table, FT_BASIC2_STYLE);
	ft_write_ln(table, "index", "id", "nfInstanceId\nnfType\ntokenType",
			"scope", "add_type\ntoken_status\nrequest_time\nresonse_time", "access_token");

	for (int i = 1; i < MAX_ACC_TOKEN_NUM; i++) {
        acc_token_info_t *token_info = get_acc_token_info(ACC_TOKEN_LIST, i, 1);
        if (token_info == NULL) {
            continue;
        } else {
            char request_time[128] = {0,};
            char validate_time[128] = {0,};
            sprintf(request_time, "%.19s", ctime(&token_info->last_request_time));
            sprintf(validate_time, "%.19s", ctime(&token_info->due_date));

			char *token_str = token_info->access_token[token_info->token_pos];
			char token_data[1024] = {0,};

			for (int k = 0, pos = 0; k < strlen(token_str); k++) {
				token_data[pos++] = token_str[k];
				if (pos % 42 == 0)
					token_data[pos++] = '\n';
			}

			ft_printf_ln(table, "%d|%d|%s\n%s\n%s|%s|%s\n%s\n%s\n%s|%s",
					i,
					token_info->token_id,
					token_info->nf_instance_id,
					strlen(token_info->nf_type) ? token_info->nf_type : "-",
					(token_info->acc_type == AT_SVC) ? "for Service" : "for Instance",
					strlen(token_info->scope) ? token_info->scope : "-",
					(token_info->operator_added) ? "OPER ADD" : "AUTO ADD",
					(token_info->status == TA_INIT) ? "INIT" :
					(token_info->status == TA_FAILED) ? "FAILED" :
					(token_info->status == TA_TRYING) ? "TRYING" : "ACQUIRED",
					request_time,
					validate_time,
					(token_info->status == TA_ACQUIRED) ? token_data: "-");
		}
	}

	sprintf(respBuff, "%s", ft_to_string(table));
	ft_destroy_table(table);
}


void print_nrfm_mml_raw(nrfm_mml_t *httpc_cmd)
{
	ft_table_t *table_c = ft_create_table();
	ft_set_border_style(table_c, FT_EMPTY_STYLE);
	ft_set_cell_prop(table_c, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);
	ft_write_ln(table_c, "occupied", "scheme", "ip", "port", "cnt");
    for (int i = 0; i < httpc_cmd->info_cnt; i++) {
		if (!httpc_cmd->nf_conns[i].occupied)
			continue;
		ft_printf_ln(table_c, "%d|%s|%s|%d|%d",
                httpc_cmd->nf_conns[i].occupied,
                httpc_cmd->nf_conns[i].scheme,
                httpc_cmd->nf_conns[i].ip,
                httpc_cmd->nf_conns[i].port,
                httpc_cmd->nf_conns[i].cnt);
    }

	ft_table_t *table_m = ft_create_table();
	ft_set_border_style(table_m, FT_PLAIN_STYLE);
	ft_set_cell_prop(table_m, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);
	ft_write_ln(table_m, "command", "host", "type", "info_cnt", "items");
	ft_printf_ln(table_m, "%s|%s|%s|%d|%s", 
			get_nrfm_cmd_str(httpc_cmd->command),
			httpc_cmd->host,
			httpc_cmd->type,
			httpc_cmd->info_cnt,
			ft_to_string(table_c));
	APPLOG(APPLOG_ERR, "\n%s", ft_to_string(table_m));
	ft_destroy_table(table_c);
	ft_destroy_table(table_m);
}

void getTypeSpecStr(nf_service_info *nf_info, char *resBuf)
{
	if (nf_info->nfType == NF_TYPE_UDM) {
		nf_udm_info *udmInfo = &nf_info->nfTypeInfo.udmInfo;
		sprintf(resBuf + strlen(resBuf), "%s\n", udmInfo->groupId);
		for (int i = 0; i < udmInfo->supiRangesNum; i++) {
			sprintf(resBuf + strlen(resBuf), "%s ~ %s\n", 
					udmInfo->supiRanges[i].start,
					udmInfo->supiRanges[i].end);
		}
		for (int i = 0; i < udmInfo->routingIndicatorsNum; i++) {
			sprintf(resBuf + strlen(resBuf), "%s ",
				   udmInfo->routingIndicators[i]);
		}
	}
}

void getAllowdPlmns(nf_service_info *nf_info, char *resBuf)
{
	for (int k = 0; k < nf_info->allowdPlmnsNum; k++) {
		nf_comm_plmn *plmns = &nf_info->allowdPlmns[k];
		sprintf(resBuf + strlen(resBuf),
				"%s%s%s", 
				plmns->mcc, plmns->mnc, k == (nf_info->allowdPlmnsNum - 1) ? "" : "\n");
	}
}

void printf_avail_nfs(nf_list_pkt_t *avail_nfs)
{
	ft_table_t *table = ft_create_table();

	ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);
	ft_set_border_style(table, FT_BASIC2_STYLE);
	ft_write_ln(table, "index", "type", "service", "allowedPlmns\n(mcc+mnc)", "typeInfo", "hostname", "scheme", "ipv4", "port", "priority", "auto", "lb_id");

    for (int i = 0, index = 1; i < avail_nfs->nf_avail_num; i++) {
        nf_service_info *nf_info = &avail_nfs->nf_avail[i];
        if (nf_info->occupied <= 0)
            continue;

		/* allowd plmns */
		char allowdPlmnsStr[1024] = {0,};
		getAllowdPlmns(nf_info, allowdPlmnsStr);

		/* nf-type specific info */
		char typeSpecStr[1024 * 12] = {0,};
		getTypeSpecStr(nf_info, typeSpecStr);

        ft_printf_ln(table, "%d|%s|%s|%s|%s|%s|%s|%s|%d|%d|%s|%d",
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
	APPLOG(APPLOG_ERR, "\n%s", ft_to_string(table));
	ft_destroy_table(table);
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
