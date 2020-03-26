#include "libnrf.h"

void def_sigaction()
{
    struct sigaction act;

    memset(&act, 0, sizeof(struct sigaction));
    act.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &act, NULL);
}

int get_id_from_name(char *name)
{
    char *temp = strdup(name);

    char *res = strlwr(temp, strlen(temp));
    char last_char = res[strlen(res) - 1];
    int num = isdigit(last_char) == 0 ? (last_char - 'a' + 1 ) : (last_char - '1' + 1); 

    free(temp);

	return num;
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
	int index = 0;
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

		node_elem.index = index++; // 01234
        node_elem.id = get_id_from_name(node_elem.name);

        /* re-arrange fep list */
        new_assoc = node_list_add_elem(new_assoc, &node_elem);
    }
    fclose(fp);

    /* check fep list */
    node_list_print_log(new_assoc);

	return new_assoc;
}

int get_my_info(svr_info_t *my_info, const char *my_proc_name)
{
    char fname[1024] = {0,};

    /* MY SYS NAME, MY PROC NAME */

    sprintf(my_info->mySysName, "%s", getenv(MY_SYS_NAME));
    sprintf(my_info->myProcName, "%s", my_proc_name);

    /* MY LABEL NUM (FEPA =A=> 1, LB01 =1=> 1) */

#if 0
    char temp_buff[1024] = { 0, };
    sprintf(temp_buff, getenv(MY_SYS_NAME));

    char *res = strlwr(temp_buff, strlen(temp_buff));
    char last_char = res[strlen(res) - 1];

	my_info->myLabelNum = isdigit(last_char) == 0 ? (last_char - 'a' + 1 ) : (last_char - '1' + 1);
#else
	my_info->myLabelNum = get_id_from_name(getenv(MY_SYS_NAME));
#endif

    /* MY SYS TYPE */

    sprintf(fname, "%s/%s", getenv(IV_HOME), ASSOCONF_FILE);

    char syscmd[1024] = {0,}; // system()
    char res_str[1024] = {0,}; // --> result

    sprintf(syscmd, "grep %s %s | awk '{print $3}'", getenv(MY_SYS_NAME), fname);

    FILE *ptr_syscmd = popen(syscmd, "r");
    if (ptr_syscmd == NULL) {
        fprintf(stderr, "{{{DBG}}} %s() fail to run syscmd [%s]\n", __func__, syscmd);
        return (-1);
    }

    char *result = fgets(res_str, 1024, ptr_syscmd);
    if (result == NULL || strlen(res_str) == 0) {
        fprintf(stderr, "{{{DBG}}} %s() fail to find [MY_SYS_NAME:%s] from file [%s]\n", 
                __func__, getenv(MY_SYS_NAME), fname);
        pclose(ptr_syscmd);
        return (-1);
    }
    res_str[strlen(res_str) -1] = '\0'; // remove newline
    pclose(ptr_syscmd);

    sprintf(my_info->mySysType, res_str);

    /* TEST LOG */

    fprintf(stderr, "TEST| %s %s %s %d\n",
            my_info->mySysName,
            my_info->myProcName,
            my_info->mySysType,
            my_info->myLabelNum);

    return 0;
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
    APPLOG(APPLOG_ERR, "{{{CHECK}}} node_elem idx:%d id %d (%s:%s:%s:%s) exist!",
            node_elem->index, node_elem->id,
            node_elem->name, node_elem->type, node_elem->group, node_elem->ip);
}

void node_list_print_log(GSList *node_assoc_list)
{
    g_slist_foreach(node_assoc_list, (GFunc)node_assoc_log, NULL);
}

#define NOTIFY_WATCH_MAX_BUFF (1024 * 12)
static void (*directory_watch_action)();
static void config_watch_callback(struct bufferevent *bev, void *args)
{   
    char buf[NOTIFY_WATCH_MAX_BUFF] = {0,};
    size_t numRead = bufferevent_read(bev, buf, NOTIFY_WATCH_MAX_BUFF);
    char *ptr; 
    for (ptr = buf; ptr < buf + numRead; ) {
        struct inotify_event *event = (struct inotify_event*)ptr;
        if (directory_watch_action != NULL && event->len > 0) {
            /* function point */
			directory_watch_action(event->name);
        }
        ptr += sizeof(struct inotify_event) + event->len;
    }
}

int watch_directory_init(struct event_base *evbase, const char *path_name, void (*callback_function)(const char *arg_is_path))
{
    if (callback_function == NULL) {
		fprintf(stderr, "INIT| ERR| callback function is NULL!");
		return -1;
    }

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

        /* ADD CALLBACK ACTION */
        directory_watch_action = callback_function;
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
	ft_set_border_style(table, FT_PLAIN_STYLE);
	ft_write_ln(table, "INDEX", "ID", "NF_INSTANCEID\nNF_TYPE\nTOKEN_TYPE", "SCOPE", "ADD_TYPE\nTOKEN_STATUS\nREQUEST_TIME\nRESONSE_TIME", "ACCESS_TOKEN");

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
					(token_info->operator_added) ? "oper add" : "auto add",
					(token_info->status == TA_INIT) ? "initial" :
					(token_info->status == TA_FAILED) ? "failed" :
					(token_info->status == TA_TRYING) ? "trying" : "acquired",
					request_time,
					validate_time,
					(token_info->status == TA_ACQUIRED) ? token_data: "-");
			ft_add_separator(table);
		}
	}

	sprintf(respBuff, "%s", ft_to_string(table));
	ft_destroy_table(table);
}

char *get_http_cmd_str(int cmd)
{
    switch (cmd) {
        case HTTP_MML_HTTPC_ADD:
            return "ADD";
        case HTTP_MML_HTTPC_ACT:
            return "ACT";
        case HTTP_MML_HTTPC_DACT:
            return "DACT";
        case HTTP_MML_HTTPC_DEL:
            return "DEL";
        case HTTP_MML_HTTPC_CLEAR:
            return "<NRF CLEAR!!!>";
		case HTTP_MML_HTTPC_TOMBSTONE:
			return "<tombstone clear>";
        default:
            return "UNKNOWN";
    }
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
			get_http_cmd_str(httpc_cmd->command),
			httpc_cmd->host,
			httpc_cmd->type,
			httpc_cmd->info_cnt,
			ft_to_string(table_c));
	APPLOG(APPLOG_DEBUG, "\n%s", ft_to_string(table_m));
	ft_destroy_table(table_c);
	ft_destroy_table(table_m);
}

int cnvt_cfg_to_json(json_object *obj, config_setting_t *setting, int callerType)
{
	json_object *obj_group = NULL;
	json_object *obj_array = NULL;
	int count = 0;

	switch (setting->type) {
		// SIMPLE CASE
		case CONFIG_TYPE_INT:
			json_object_object_add(obj, setting->name, json_object_new_int(setting->value.ival));
			break;
		case CONFIG_TYPE_STRING:
			if (callerType == CONFIG_TYPE_ARRAY || callerType == CONFIG_TYPE_LIST) {
				json_object_array_add(obj, json_object_new_string(setting->value.sval));
			} else {
				json_object_object_add(obj, setting->name, json_object_new_string(setting->value.sval));
			}
			break;
		case CONFIG_TYPE_BOOL:
			json_object_object_add(obj, setting->name, json_object_new_boolean(setting->value.ival));
			break;
		// COMPLEX CASE
		case CONFIG_TYPE_GROUP:
			obj_group = json_object_new_object();
			count = config_setting_length(setting);
			for (int i = 0; i < count; i++) {
				config_setting_t *elem = config_setting_get_elem(setting, i);
				cnvt_cfg_to_json(obj_group, elem, setting->type);
			}
			if (callerType == CONFIG_TYPE_ARRAY || callerType == CONFIG_TYPE_LIST) {
				json_object_array_add(obj, obj_group);
			} else {
				json_object_object_add(obj, setting->name, obj_group);
			}
			break;
		case CONFIG_TYPE_ARRAY:
		case CONFIG_TYPE_LIST:
			obj_array = json_object_new_array();
			json_object_object_add(obj, setting->name, obj_array);

			count = config_setting_length(setting);
			for (int i = 0; i < count; i++) {
				config_setting_t *elem = config_setting_get_elem(setting, i);
				cnvt_cfg_to_json(obj_array, elem, setting->type);
			}
			break;
		default:
			fprintf(stderr, "TODO| do something!\n");
			break;
	}

	return 0;
}

/*
 * statistics
 */
GNode *NRF_STAT_ADD_CHILD(GNode *ROOT_STAT, char *hostname)
{
    nrf_stat_t *stat_newhost = malloc(sizeof(nrf_stat_t));
    memset(stat_newhost, 0x00, sizeof(nrf_stat_t));
    sprintf(stat_newhost->hostname, hostname);

    GNode *new_node =  g_node_new(stat_newhost);

    g_node_append(ROOT_STAT, new_node);

    return new_node;
}

GNode *NRF_STAT_ADD_CHILD_POS(GNode *ROOT_NODE, GNode *SIBLING, char *hostname, int pre_or_append)
{
    nrf_stat_t *stat_newhost = malloc(sizeof(nrf_stat_t));
    memset(stat_newhost, 0x00, sizeof(nrf_stat_t));
    sprintf(stat_newhost->hostname, hostname);

    GNode *new_node =  g_node_new(stat_newhost);

    if (pre_or_append < 0)
        g_node_insert_before(ROOT_NODE, SIBLING, new_node);
    else if (pre_or_append > 0)
        g_node_insert_after(ROOT_NODE, SIBLING, new_node);

    return new_node;
}

GNode *NRF_STAT_FIND_CHILD(GNode *ROOT_STAT, char *hostname, int *compare_res)
{
    unsigned int child_num = g_node_n_children(ROOT_STAT);
    int low = 0;
    int high = (child_num - 1);
    int nth = 0;
    *compare_res = 0;

    while (low <= high) {
        nth = (low + high) / 2;
        GNode *nth_child = g_node_nth_child(ROOT_STAT, nth);
        nrf_stat_t *stat_host = (nrf_stat_t *)nth_child->data;

        *compare_res = strcmp(hostname, stat_host->hostname);

        if (*compare_res == 0) {
            return nth_child;
        } else if (*compare_res > 0) {
            high = nth - 1;
        } else {
            low = nth + 1;
        }
    }

    return NULL;
}

void NRF_STAT_INC(GNode *ROOT_STAT, char *hostname, int operation, int category)
{
    if (hostname == NULL)
        return;
	if (operation < 0 || operation >= NRFS_OP_MAX)
		return;
	if (category < 0 || category >= NRFS_CATE_MAX)
		return;

    if (g_node_n_children(ROOT_STAT) == 0) { // if no child, create one
        GNode *new_node = NRF_STAT_ADD_CHILD(ROOT_STAT, hostname);
        nrf_stat_t *new_stat_host = (nrf_stat_t *)new_node->data;
        new_stat_host->stat_count[operation][category]++;
        return;
    } else {
        int res = 0;
        GNode *search_node = NRF_STAT_FIND_CHILD(ROOT_STAT, hostname, &res); // bsearch host

        if (res == 0) { /* find */
            nrf_stat_t *target_stat_host = (nrf_stat_t *)search_node->data;
            target_stat_host->stat_count[operation][category]++; // searched
        } else { // insert before or after by res
            GNode *new_node = NRF_STAT_ADD_CHILD_POS(ROOT_STAT, search_node, hostname, res);
            nrf_stat_t *new_stat_host = (nrf_stat_t *)new_node->data;
            new_stat_host->stat_count[operation][category]++;
        }
    }

	return;
}

char *nrf_stat_op_str[] = {
	"NFRegister",
	"NFUpdate",
	"NFListRetrieval",
	"NFProfileRetrieval",
	"NFStatusSubscribe",
	"NFStatusSubscribePatch",
	"NFStatusNotify",
	"AccessToken",
	"NRFS_OP_MAX"
};

char *nrf_stat_cate_str[] = {
    "NRFS_ATTEMPT",
    "NRFS_SUCCESS",
    "NRFS_FAIL",
    "NRFS_TIMEOUT",
    "NRFS_CATE_MAX"
};

#ifdef STAT_LEGACY
void stat_cnvt_5geir_nrfm(STM_CommonStatMsg *commStatItem, STM_NrfmStatistics_s *nrfm_stat)
{
    for (int k = 0; k < NRFS_CATE_MAX; k++) {
        switch(k) {
            case NRFS_ATTEMPT:
                nrfm_stat->nrfs_attempt = commStatItem->ldata[k];
                break;
            case NRFS_SUCCESS:
                nrfm_stat->nrfs_success = commStatItem->ldata[k];
                break;
            case NRFS_FAIL:
                nrfm_stat->nrfs_fail = commStatItem->ldata[k];
                break;
            case NRFS_TIMEOUT:
                nrfm_stat->nrfs_timeout = commStatItem->ldata[k];
                break;
            default:
                break;
        }
    }
}
#endif

void nrf_stat_function(int ixpcQid, IxpcQMsgType *rxIxpcMsg, int event_code, GNode *ROOT_STAT)
{
	int len = sizeof(int), txLen = 0;
    int statCnt = 0;
#ifdef STAT_LEGACY
    STM_NrfmStatisticMsgType stm_nrfm = {0,};
    int stm_nrfm_row = 0;
#endif

    APPLOG(APPLOG_ERR, "%s() recv MTYPE_STATISTICS_REQUEST from OMP", __func__);

    GeneralQMsgType sxGenQMsg;
    memset(&sxGenQMsg, 0x00, sizeof(GeneralQMsgType));

    IxpcQMsgType *sxIxpcMsg = (IxpcQMsgType*)sxGenQMsg.body;

    STM_CommonStatMsgType *commStatMsg=(STM_CommonStatMsgType *)sxIxpcMsg->body;
    STM_CommonStatMsg     *commStatItem=NULL;

    sxGenQMsg.mtype = MTYPE_STATISTICS_REPORT;
    sxIxpcMsg->head.msgId = event_code;
    sxIxpcMsg->head.seqNo = 0; // start from 1

    strcpy(sxIxpcMsg->head.srcSysName, rxIxpcMsg->head.dstSysName);
    strcpy(sxIxpcMsg->head.srcAppName, rxIxpcMsg->head.dstAppName);
    strcpy(sxIxpcMsg->head.dstSysName, rxIxpcMsg->head.srcSysName);
    strcpy(sxIxpcMsg->head.dstAppName, rxIxpcMsg->head.srcAppName);

    int host_num = g_node_n_children(ROOT_STAT);
    APPLOG(APPLOG_ERR, "{{{DBG}}} in (%s) host_num is [%d]", __func__, host_num);

    for (int nth = 0; nth < host_num; nth++) {
        GNode *select_node = g_node_nth_child(ROOT_STAT, nth);
        nrf_stat_t *NRF_STAT = (nrf_stat_t *)select_node->data;

        for (int i = 0; i < NRFS_OP_MAX; i++) {
            //commStatItem = &commStatMsg->info[i];
            commStatItem = &commStatMsg->info[statCnt]; ++statCnt;
            len += sizeof (STM_CommonStatMsg);

            snprintf(commStatItem->strkey1, sizeof(commStatItem->strkey1), "%s", NRF_STAT->hostname);
            snprintf(commStatItem->strkey2, sizeof(commStatItem->strkey2), "%s", nrf_stat_op_str[i]);

            APPLOG(APPLOG_ERR, "[STAT OP : %s, %s]", commStatItem->strkey1, commStatItem->strkey2);
            for (int k = 0; k < NRFS_CATE_MAX; k++) {
                commStatItem->ldata[k] = NRF_STAT->stat_count[i][k];
                APPLOG(APPLOG_ERR, "--cate %s, VAL %ld", nrf_stat_cate_str[k], commStatItem->ldata[k]);
            }
#ifdef STAT_LEGACY
            int curr_row = stm_nrfm_row++;
            stm_nrfm.num = curr_row;
            STM_NrfmStatistics_s *curr_nrfm_stat = &stm_nrfm.nrfmSTAT[curr_row];

            sprintf(curr_nrfm_stat->hostname, NRF_STAT->hostname);
            sprintf(curr_nrfm_stat->operation, nrf_stat_op_str[i]);
            stat_cnvt_5geir_nrfm(commStatItem, curr_nrfm_stat);
            len = sizeof(int) + (sizeof(STM_NrfmStatistics_s) * curr_row);
#endif
        }
    }

    commStatMsg->num = statCnt;

    /* remove nodes data */
    for (int nth = host_num - 1; nth >= 0; nth--) {
        GNode *select_node = g_node_nth_child(ROOT_STAT, nth);
        nrf_stat_t *NRF_STAT = (nrf_stat_t *)select_node->data;
        if (NRF_STAT != NULL) {
            free(NRF_STAT);
        }
        g_node_destroy(select_node);
    }

    sxIxpcMsg->head.segFlag = 0;
    sxIxpcMsg->head.seqNo++;
    sxIxpcMsg->head.bodyLen = len;
#ifdef STAT_LEGACY
    memcpy(sxIxpcMsg->body, &stm_nrfm, len);
#endif
    txLen = sizeof(sxIxpcMsg->head) + sxIxpcMsg->head.bodyLen;

    if (msgsnd(ixpcQid, (void*)&sxGenQMsg, txLen, IPC_NOWAIT) < 0) {
        APPLOG(APPLOG_ERR, "DBG] nrfm status send fail IXPC qid[%d] err[%s]\n", ixpcQid, strerror(errno));
    }

	return;
}

gboolean node_free_data(GNode *node, gpointer data)
{
    if (node->data != NULL)
        free(node->data);
    return 0;
}

GNode *create_nth_child(nf_search_key_t *key, nf_service_info *insert_data)
{
    nf_lbid_info_t *nf_lb = NULL;
    nf_type_info_t *nf_type = NULL;
    nf_host_info_t *nf_host = NULL;
    nf_svcname_info_t *nf_svcname = NULL;
    nf_connection_info_t *nf_connection = NULL;

    switch(key->depth) {
        case 0:
            nf_lb = malloc(sizeof(nf_lbid_info_t));
			memset(nf_lb, 0x00, sizeof(nf_lbid_info_t));
            nf_lb->lb_id = key->lb_id;
            return g_node_new(nf_lb);
        case 1:
            nf_type = malloc(sizeof(nf_type_info_t));
			memset(nf_type, 0x00, sizeof(nf_type_info_t));
            sprintf(nf_type->type, "%.15s", key->nf_type);
            return g_node_new(nf_type);
        case 2:
            nf_host = malloc(sizeof(nf_host_info_t));
			memset(nf_host, 0x00, sizeof(nf_host_info_t));
            sprintf(nf_host->hostname, "%.51s", key->nf_host);
            
            nf_host->auto_add = insert_data->auto_add;
            if (nf_host->auto_add == NF_ADD_NRF || nf_host->auto_add == NF_ADD_MML) {
                nf_host->allowdPlmnsNum = insert_data->allowdPlmnsNum;
                memcpy(nf_host->allowdPlmns, insert_data->allowdPlmns, sizeof(nf_comm_plmn) * nf_host->allowdPlmnsNum);
                nf_host->nfType = insert_data->nfType;
                memcpy(&nf_host->nfTypeInfo, &insert_data->nfTypeInfo, sizeof(nf_type_info));
            }
            return g_node_new(nf_host);
        case 3:
            nf_svcname = malloc(sizeof(nf_svcname_info_t));
			memset(nf_svcname, 0x00, sizeof(nf_svcname_info_t));
            sprintf(nf_svcname->servicename, "%.31s", key->nf_svcname);
            return g_node_new(nf_svcname);
        case 4:
            nf_connection = malloc(sizeof(nf_connection_info_t));
			memset(nf_connection, 0x00, sizeof(nf_connection_info_t));
            sprintf(nf_connection->connInfoStr, "%.63s", key->nf_conn_info);

            nf_connection->auto_add = insert_data->auto_add;
            nf_connection->priority = insert_data->priority;
            nf_connection->load = insert_data->load;
            nf_connection->avail = insert_data->available;

            /* nf service shmtable pointer */
            nf_connection->nf_service_shm_ptr = insert_data;
            return g_node_new(nf_connection);
    }

    return NULL; // program will crashed 
}

int ln_depth_compare(nf_search_key_t *key, GNode *compare_node)
{
    nf_lbid_info_t *nf_lb = NULL;
    nf_type_info_t *nf_type = NULL;
    nf_host_info_t *nf_host = NULL;
    nf_svcname_info_t *nf_svcname = NULL;
    nf_connection_info_t *nf_connection = NULL;

    /* left input : right node */
    switch (key->depth) {
        case 0:
            nf_lb = (nf_lbid_info_t *)compare_node->data;
            return (key->lb_id  - nf_lb->lb_id);
        case 1:
            nf_type = (nf_type_info_t *)compare_node->data;
            return strcmp(key->nf_type, nf_type->type);
        case 2:
            nf_host = (nf_host_info_t *)compare_node->data;
            return strcmp(key->nf_host, nf_host->hostname);
        case 3:
            nf_svcname = (nf_svcname_info_t *)compare_node->data;
            return strcmp(key->nf_svcname, nf_svcname->servicename);
        case 4:
            nf_connection = (nf_connection_info_t *)compare_node->data;
            return strcmp(key->nf_conn_info, nf_connection->connInfoStr);
    }

    return 0; // program will crashed
}

GNode *search_or_create_node(GNode *node, nf_search_key_t *key, nf_service_info *insert_data, int create_if_none)
{
    int child_num = g_node_n_children(node);
    if (child_num == 0) {
        if (create_if_none) {
            GNode *new_node = create_nth_child(key, insert_data);
            g_node_append(node, new_node);
            return new_node;
        } else {
            return NULL;
        }
    }

    GNode *nth_child = NULL;
    int low = 0;
    int high = (child_num - 1);
    int nth = 0;
    int compare_res = 0;

    while (low <= high) {
        nth = (low + high) / 2;
        nth_child = g_node_nth_child(node, nth);

        compare_res = ln_depth_compare(key, nth_child);

        if (compare_res == 0) {
            return nth_child; // HIT !
        } else if (compare_res < 0) {
            high = nth - 1;
        } else {
            low = nth + 1;
        }
    }

    if (create_if_none == 0)
        return NULL;

    if (compare_res < 0) {
        GNode *new_node = create_nth_child(key, insert_data);
        g_node_insert_before(node, nth_child, new_node);
        return new_node;
    } else {
        GNode *new_node = create_nth_child(key, insert_data);
        g_node_insert_after(node, nth_child, new_node);
        return new_node;
    }
}

void create_node_data(GNode *root_node, nf_search_key_t *key, nf_service_info *insert_data)
{
    GNode *search_node = root_node;

    for (int i = 0; i < NF_NODE_DATA_DEPTH; i++) {
        key->depth = i;
        search_node = search_or_create_node(search_node, key, insert_data, 1);
    }
};

GNode *search_node_data(GNode *root_node, nf_search_key_t *key, int search_depth)
{
    GNode *search_node = root_node;

    for (int i = 0; i < search_depth; i++) {
		APPLOG(APPLOG_ERR, "{DBG} %s() search depth(%d)", __func__, i);
        key->depth = i;
        search_node = search_or_create_node(search_node, key, NULL, 0);
        if (search_node == NULL) {
			APPLOG(APPLOG_ERR, "{DBG} %s() giveup return NULL", __func__);
            return search_node; // giveup
		}
    }

	return search_node; // return result (null or not)
}

void print_node_table(ft_table_t *table, GNode *node, int depth, char *temp_buff, char *nf_type_arg)
{
    nf_lbid_info_t *nf_lb = NULL;
    nf_type_info_t *nf_type = NULL;
    nf_host_info_t *nf_host = NULL;
    nf_svcname_info_t *nf_svcname = NULL;
    nf_connection_info_t *nf_conn = NULL;

    char plmnStr[1024] = {0,};
    char typeStr[1024] = {0,};

    switch (depth) {
        case 0:
            ft_add_separator(table);
            nf_lb = (nf_lbid_info_t *)node->data;
            ft_set_cell_prop(table, FT_ANY_ROW, 0, FT_CPROP_MIN_WIDTH, 4);
            ft_printf_ln(table, "LB-[%d]|%s", nf_lb->lb_id, temp_buff);
            ft_add_separator(table);
            break;
        case 1:
            nf_type = (nf_type_info_t *)node->data;
            if (strlen(nf_type_arg) > 0 && strcmp(nf_type_arg, nf_type->type))
                return;
            ft_set_cell_prop(table, FT_ANY_ROW, 0, FT_CPROP_MIN_WIDTH, 8);
            ft_printf_ln(table, "%s|%s", nf_type->type, temp_buff);
            break;
        case 2:
            nf_host = (nf_host_info_t *)node->data;
            ft_set_cell_prop(table, FT_ANY_ROW, 0, FT_CPROP_MIN_WIDTH, 34);
            ft_set_cell_prop(table, FT_ANY_ROW, 1, FT_CPROP_MIN_WIDTH, 14);
            ft_set_cell_prop(table, FT_ANY_ROW, 2, FT_CPROP_MIN_WIDTH, 24);
            if (nf_host->auto_add == NF_ADD_NRF || nf_host->auto_add == NF_ADD_MML) {
                nf_get_allowd_plmns_str(nf_host->allowdPlmnsNum, nf_host->allowdPlmns, plmnStr);
                nf_get_specific_info_str(nf_host->nfType, &nf_host->nfTypeInfo, typeStr);
            }
            ft_printf_ln(table, "%s|%s|%s|%s", nf_host->hostname, plmnStr, typeStr, temp_buff);
            ft_add_separator(table);
            break;
        case 3:
            nf_svcname = (nf_svcname_info_t *)node->data;
            ft_set_cell_prop(table, FT_ANY_ROW, 0, FT_CPROP_MIN_WIDTH, 12);
            ft_printf_ln(table, "%s|%s", nf_svcname->servicename, temp_buff);
            ft_add_separator(table);
            break;
        case 4:
            nf_conn = (nf_connection_info_t *)node->data;
            ft_set_cell_prop(table, FT_ANY_ROW, 0, FT_CPROP_MIN_WIDTH, 32);
            ft_set_cell_prop(table, FT_ANY_ROW, 1, FT_CPROP_MIN_WIDTH, 8);
            ft_set_cell_prop(table, FT_ANY_ROW, 2, FT_CPROP_MIN_WIDTH, 5);
            ft_set_cell_prop(table, FT_ANY_ROW, 3, FT_CPROP_MIN_WIDTH, 5);
            ft_set_cell_prop(table, FT_ANY_ROW, 4, FT_CPROP_MIN_WIDTH, 10);
            if (nf_conn->auto_add == NF_ADD_MML) {
                ft_printf_ln(table, "%s|%s|%s|%s|%s", 
                        nf_conn->connInfoStr, 
                        "[by mml]",
                        "",
                        "", 
                        nf_conn->avail < 0 ? "NOT EXIST" : nf_conn->avail > 0 ? "AVAIL" : "NOT AVAIL");
            } else {
                ft_printf_ln(table, "%s|%s|p:%d|l:%d|%s", 
                        nf_conn->connInfoStr, 
                        nf_conn->auto_add == NF_ADD_RAW ? "[by opr]" : 
                        nf_conn->auto_add == NF_ADD_NRF ? "[by nrf]" : 
						nf_conn->auto_add == NF_ADD_MML ? "[by mml]" : "[by api]",
                        nf_conn->priority, 
                        nf_conn->load, 
                        nf_conn->avail < 0 ? "NOT EXIST" : nf_conn->avail > 0 ? "AVAIL" : "NOT AVAIL");
            }
            break;
        default:
            APPLOG(APPLOG_ERR, "%s() something wrong [cant handle depth:%d]", __func__, depth);
            break;
    }
}

void print_node(ft_table_t *table, GNode *node, int depth, char *nf_type)
{
    for (int i = 0; i < g_node_n_children(node); i++) {
        GNode *child_node = g_node_nth_child(node, i);
        ft_table_t *child_table = ft_create_table();
        ft_set_border_style(child_table, FT_PLAIN_STYLE);

        print_node(child_table, child_node, depth + 1, nf_type);

        char *temp_buff = NULL;
        asprintf(&temp_buff, "%s", ft_to_string(child_table));
        if (strlen(temp_buff) > 0)
            temp_buff[strlen(temp_buff) - 1] = '\0';
        
        print_node_table(table, child_node, depth, temp_buff, nf_type);

        free(temp_buff);

        ft_destroy_table(child_table);
    }
}

void printf_fep_nfs_by_node_order(GNode *root_node, char *printBuff, char *nf_type)
{
    if (root_node == NULL)
        return;

    /* main table */
    ft_table_t *table = ft_create_table();
    ft_set_border_style(table, FT_PLAIN_STYLE);

    /* start depth */
    int current_depth = 0;

    /* recursive call */
    print_node(table, root_node, current_depth, nf_type);

    /* print result */
    sprintf(printBuff, "%s\n", ft_to_string(table));

    /* resource clear */
    ft_destroy_table(table);
}

void printf_fep_nfs_well_form(GNode *root_node, char *printBuff, char *nf_type)
{
    /* print to buffer */
    printf_fep_nfs_by_node_order(root_node, printBuff, nf_type);
}
