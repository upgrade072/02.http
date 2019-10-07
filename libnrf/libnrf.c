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
