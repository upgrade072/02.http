#include "lbengine.h"

GNode *new_node_conn(sock_ctx_t *sock_ctx)
{
    sock_ctx_t *data = malloc(sizeof(sock_ctx_t));
    memcpy(data, sock_ctx, sizeof(sock_ctx_t));
    time(&data->create_time);

    return g_node_new(data);
}

GNode *add_node(GNode *parent, GNode *child, GNode *looser_brother)
{
    return g_node_insert_before(parent, looser_brother, child);
}

void remove_node(GNode *node)
{
	free(node->data);
    return g_node_destroy(node);
}

GNode *new_tcp_ctx(tcp_ctx_t *tcp_ctx)
{
	tcp_ctx_t *data = malloc(sizeof(tcp_ctx_t));
	memcpy(data, tcp_ctx, sizeof(tcp_ctx_t));

	return g_node_new(data);
}

void add_tcp_ctx_to_main(tcp_ctx_t *tcp_ctx, GNode *where_to_add)
{   
	GNode *new_tcp = new_tcp_ctx(tcp_ctx);
	if (new_tcp != NULL)  {
		add_node(where_to_add, new_tcp, NULL);
	} else {
		APPLOG(APPLOG_ERR, "{{{LB}}} %s() fail to create thread ctx!!!", __func__);
		exit(0);
	}
}

// deprecated
sock_ctx_t *search_node_by_ip(tcp_ctx_t *tcp_ctx, const char *ipaddr)
{
    GNode *root = tcp_ctx->root_conn;
    unsigned int conn_num = g_node_n_children(root);

    for (int i = 0; i < conn_num; i++) {
        GNode *nth_conn = g_node_nth_child(root, i);
        sock_ctx_t *sock_ctx = (sock_ctx_t *)nth_conn->data;
        if (!strcmp(sock_ctx->client_ip, ipaddr)) {
            return sock_ctx;
		}
    }
    return (sock_ctx_t *)NULL;
}

sock_ctx_t *get_last_conn_sock(tcp_ctx_t *tcp_ctx)
{
    GNode *root = tcp_ctx->root_conn;
	GNode *last_conn = g_node_last_child(root);
	if (last_conn != NULL) {
		return (sock_ctx_t *)last_conn->data;
	} else {
		return (sock_ctx_t *)NULL;
	}
}

sock_ctx_t *return_nth_sock(tcp_ctx_t *tcp_ctx, int idx)
{
    GNode *child = g_node_nth_child(tcp_ctx->root_conn, idx);

    if (child == NULL)
        return NULL;

    sock_ctx_t *sock_ctx = (sock_ctx_t *)child->data;
    return sock_ctx;
}

int return_sock_num(tcp_ctx_t *tcp_ctx)
{
    int sock_cnt = g_node_n_children(tcp_ctx->root_conn);
    return sock_cnt;
}

/*
	return 0 --> no it is ipaddr
	return 1 --> yes and converted to ipaddr
	return -1 --> yes but fail to resolv, don't use buff_val
*/
int is_host_if_cnvt(char *host_or_addr, char *cnvt_to_buff)
{
	/* gethostbyname() not work in container, try another way */
	FILE *fp = NULL;

	char cmd[1024] = {0,};
	char buff[1024] = {0,};
    struct sockaddr_in sa = {0,};

    if (inet_pton(AF_INET, host_or_addr, &(sa.sin_addr))) {
		return 0; // input is ipaddr
    }

	sprintf(cmd, "getent ahostsv4 %s | grep STREAM | awk '{print $1}'", host_or_addr);
	if ((fp = popen(cmd, "r")) == NULL) {
		return -1;
	}

	if (fgets(buff, 1024, fp) != NULL) {
		strtok(buff, "\n");
		if (inet_pton(AF_INET, buff, &(sa.sin_addr))) {
			sprintf(cnvt_to_buff, "%s", buff);
			pclose(fp);
			return 1; // get cnvt address
		}
	}
	pclose(fp);
	return -1;
}

int check_conf_via_sock(tcp_ctx_t *tcp_ctx, sock_ctx_t *sock_ctx)
{
	char converted_ip[128] = {0,};
	char *peer_ip_addr = NULL;
	int is_host = 0;

	if ((is_host = is_host_if_cnvt(tcp_ctx->peer_ip_addr, converted_ip)) == 0) {
		peer_ip_addr = tcp_ctx->peer_ip_addr;
	} else if (is_host == 1) {
		peer_ip_addr = converted_ip;
	} else {
		return 0;
	}

	if (!strcmp(sock_ctx->client_ip, peer_ip_addr))
		return 1; // find
	else
		return 0; // not find
}

void unexpect_readcb(struct bufferevent *bev, void *arg)
{
    sock_ctx_t *sock_ctx = (sock_ctx_t *)arg;

    APPLOG(APPLOG_ERR, "{{{LB}}} %s() called!", __func__);

    char buff[10240] = {0,};
    ssize_t rsize = bufferevent_read(bev, buff, sizeof(buff));

    buff[rsize + 1] = '\0';
    APPLOG(APPLOG_ERR, "{{{LB}}} %s() recv unexpected (from %s:%d) (%ld byte)!", 
			__func__, sock_ctx->client_ip, sock_ctx->client_port, rsize);

    release_conncb(sock_ctx);
}

void release_conncb(sock_ctx_t *sock_ctx)
{
    APPLOG(APPLOG_DETAIL, "{{{LB}}} sock %s:%d fd(%d) (%.19s ~ ) closed",
            sock_ctx->client_ip, sock_ctx->client_port, sock_ctx->client_fd,
            ctime(&sock_ctx->create_time));

    struct bufferevent *bev = sock_ctx->bev;

    // remove whole push item, unset caller ctx
    unset_pushed_item(&sock_ctx->push_items, sock_ctx->push_items.item_bytes, __func__);

	// CHECK event first? bev first?
    if (sock_ctx->event_flush_cb) 
        event_del(sock_ctx->event_flush_cb);
    if (sock_ctx->event_send_hb) 
        event_del(sock_ctx->event_send_hb);
    if (sock_ctx->event_chk_hb) 
        event_del(sock_ctx->event_chk_hb);

    // remove event, close sock
	if (sock_ctx->bev) 
		bufferevent_free(bev);

    // remove conn info 
    remove_node(sock_ctx->my_conn);
}

void svr_sock_eventcb(struct bufferevent *bev, short events, void *user_data)
{
    sock_ctx_t *sock_ctx = (sock_ctx_t *)user_data;

    APPLOG(APPLOG_DETAIL, "{{{LB}}} %s() called in conn(%s:%d)", __func__, sock_ctx->client_ip, sock_ctx->client_port);

    // client sock conneted
    if(events & BEV_EVENT_CONNECTED) {

        int fd = bufferevent_getfd(bev);
        APPLOG(APPLOG_DETAIL, "{{{LB}}} connected fd is (%d)", fd);

        if (util_set_linger(fd, 1, 0) != 0) 
            APPLOG(APPLOG_ERR, "{{{LB}}} fail to set SO_LINGER (ABORT) to fd!");

		sock_ctx->connected = 1;
        return;
    }

    if (events & BEV_EVENT_EOF) {
        APPLOG(APPLOG_DETAIL, "{{{LB}}} Connection closed.");
    } else if (events & BEV_EVENT_ERROR) {
        APPLOG(APPLOG_DETAIL, "{{{LB}}} Got an error on the connection: %s!", strerror(errno));
    }

    release_conncb(sock_ctx);
}

void packet_process_res(sock_ctx_t *sock_ctx, char *process_ptr, size_t processed_len)
{
    // if sock recv 10, process 3 ==> move remain 7 byte to front
    memmove(sock_ctx->buff, process_ptr, sock_ctx->rcv_len - processed_len);
    sock_ctx->rcv_len = sock_ctx->rcv_len - processed_len;

    return;
}

void create_heartbeat_msg(sock_ctx_t *sock_ctx)
{
	tcp_ctx_t *tcp_ctx = (tcp_ctx_t *)sock_ctx->tcp_ctx;

	sprintf(sock_ctx->hb_pkt_hdr.magicByte, "%s", AHIF_MAGIC_BYTE);
	sock_ctx->hb_pkt_hdr.mtype = MTYPE_HTTP2_AHIF_CONN_CHECK;
	sock_ctx->hb_pkt_hdr.staCause = HTTP_STA_CAUSE_NONE;
	sock_ctx->push_req.sender_tcp_ctx = tcp_ctx;
	sock_ctx->push_req.iov[0].iov_base = &sock_ctx->hb_pkt_hdr;
	sock_ctx->push_req.iov[0].iov_len = AHIF_HTTPCS_MSG_HEAD_LEN;
	sock_ctx->push_req.iov_cnt = 1;
	sock_ctx->push_req.remain_bytes = AHIF_HTTPCS_MSG_HEAD_LEN;

	/* recall myself */
	sock_ctx->push_req.unset_cb_func = create_heartbeat_msg;
	sock_ctx->push_req.unset_cb_arg = sock_ctx;
}

sock_ctx_t *assign_sock_ctx(tcp_ctx_t *tcp_ctx, evutil_socket_t fd, struct sockaddr *sa)
{
    sock_ctx_t sock_ctx = {0,};
    sprintf(sock_ctx.client_ip, "%s", util_get_ip_from_sa(sa));
    sock_ctx.client_port = util_get_port_from_sa(sa);
    sock_ctx.client_fd = fd;
    sock_ctx.lb_ctx = tcp_ctx->lb_ctx;
	sock_ctx.tcp_ctx = tcp_ctx;
	time(&sock_ctx.last_hb_recv_time); // heartbeat recv init

    GNode *new_conn = new_node_conn(&sock_ctx);
    if (new_conn != NULL) {
        add_node(tcp_ctx->root_conn, new_conn, NULL);
		APPLOG(APPLOG_DETAIL, "{{{LB}}} tcp ctx (%p) (%s:%d) now sock num (%d)",
				tcp_ctx,
				svc_type_to_str(tcp_ctx->svc_type),
				tcp_ctx->fep_tag,
				return_sock_num(tcp_ctx));

        sock_ctx_t *sock_ctx = (sock_ctx_t *)new_conn->data;
        sock_ctx->my_conn = new_conn;

		/* create heartbeat msg in sock */
		create_heartbeat_msg(sock_ctx);

        return sock_ctx;
    } else {
        APPLOG(APPLOG_ERR, "{{{LB}}} fail to create sock ctx!");
        return NULL;
    }
}

void sock_hb_send_cb(evutil_socket_t fd, short what, void *arg)
{
    sock_ctx_t *sock_ctx = (sock_ctx_t *)arg;
	tcp_ctx_t *tcp_ctx = (tcp_ctx_t *)sock_ctx->tcp_ctx;

	return iovec_push_req(tcp_ctx, &sock_ctx->push_req);
}

int sock_add_heartbeatcb(tcp_ctx_t *tcp_ctx, sock_ctx_t *sock_ctx)
{
    struct timeval tm_interval  = {1, 0}; // every 1 sec
    sock_ctx->event_send_hb = event_new(tcp_ctx->evbase, -1, EV_PERSIST, sock_hb_send_cb, sock_ctx);

    return event_add(sock_ctx->event_send_hb, &tm_interval);
}

void release_conn_by_hb(lb_ctx_t *lb_ctx, tcp_ctx_t *tcp_ctx, sock_ctx_t *sock_ctx)
{
	if (tcp_ctx->svc_type != TT_PEER_RECV && tcp_ctx->svc_type != TT_RX_ONLY) {
		APPLOG(APPLOG_ERR, "{{{LB}}} {{{DBG}}} in %s receive unknown svc type!!!");
		return;
	}

	if (tcp_ctx->svc_type == TT_PEER_RECV) {
		/* release my sock */
		release_conncb(sock_ctx);
	} else if (tcp_ctx->svc_type == TT_RX_ONLY) {
		/* release my sock */
		release_conncb(sock_ctx);

		/* find tx thread */
		unsigned int fep_num = g_node_n_children(lb_ctx->fep_tx_thrd);
		for (int i = 0; i < fep_num; i++) {
			GNode *temp_node = g_node_nth_child(lb_ctx->fep_tx_thrd, i);
			tcp_ctx_t *pair_tcp_ctx = (tcp_ctx_t *)temp_node->data;
			/* find tx-pair tcp */
			if (pair_tcp_ctx->fep_tag == tcp_ctx->fep_tag) {
				GNode *root = pair_tcp_ctx->root_conn;
				unsigned int conn_num = g_node_n_children(root);
				/* release tx-pair-sock */
				for (int i = 0; i < conn_num; i++) {
					GNode *nth_conn = g_node_nth_child(root, i);
					sock_ctx_t *peer_sock_ctx = (sock_ctx_t *)nth_conn->data;
					release_conncb(peer_sock_ctx);
				}
			}
		}
	}
}

void sock_hb_chk_cb(evutil_socket_t fd, short what, void *arg)
{
	time_t current = {0,};
	sock_ctx_t *sock_ctx = (sock_ctx_t *)arg;
	tcp_ctx_t *tcp_ctx = (tcp_ctx_t *)sock_ctx->tcp_ctx;
	lb_ctx_t *lb_ctx = (lb_ctx_t *)tcp_ctx->lb_ctx;

	time(&current);
	if (current - sock_ctx->last_hb_recv_time >= 5) {
		APPLOG(APPLOG_ERR, "{{{LB}}} FEP(%d) SVC(%s) HB PROBLEM (last recv %.19s)!!!",
				tcp_ctx->fep_tag, 
				svc_type_to_str(tcp_ctx->svc_type),
				ctime(&sock_ctx->last_hb_recv_time));
		release_conn_by_hb(lb_ctx, tcp_ctx, sock_ctx);
	}
}

int sock_chk_heartbeatcb(tcp_ctx_t *tcp_ctx, sock_ctx_t *sock_ctx)
{
    struct timeval tm_interval  = {1, 0}; // for test
    sock_ctx->event_chk_hb = event_new(tcp_ctx->evbase, -1, EV_PERSIST, sock_hb_chk_cb, sock_ctx);

    return event_add(sock_ctx->event_chk_hb, &tm_interval);
}

void sock_flush_callback(evutil_socket_t fd, short what, void *arg)
{
    sock_ctx_t *sock_ctx = (sock_ctx_t *)arg;
	tcp_ctx_t *tcp_ctx = (tcp_ctx_t *)sock_ctx->tcp_ctx;
    write_list_t *write_list = &sock_ctx->push_items;

	if (sock_ctx->connected != 1) {
		unset_pushed_item(&sock_ctx->push_items, sock_ctx->push_items.item_bytes, __func__);
		return;
	}

    /* push all remain item */
    ssize_t nwritten = push_write_item(sock_ctx->client_fd, write_list, INT_MAX, INT_MAX);
    if (nwritten > 0) {
        unset_pushed_item(write_list, nwritten, __func__);
		/* stat */
		tcp_ctx->tcp_stat.send_bytes += nwritten;
#if 0 // forget just release
	} else if (errno != EINTR && errno != EAGAIN) {
#else
	} else if (nwritten == 0) {
	} else { /* < 0 */
#endif
		APPLOG(APPLOG_ERR, "{{{LB}}} %s() something wrong (%d : %s), release sock!!!\n", __func__, errno, strerror(errno));
		release_conncb(sock_ctx);
	}
}

int sock_add_flushcb(tcp_ctx_t *tcp_ctx, sock_ctx_t *sock_ctx)
{
    struct timeval tm_interval  = {0, tcp_ctx->flush_tmval};
    sock_ctx->event_flush_cb = event_new(tcp_ctx->evbase, -1, EV_PERSIST, sock_flush_callback, sock_ctx);

    return event_add(sock_ctx->event_flush_cb, &tm_interval);
}

void release_older_sock(tcp_ctx_t *tcp_ctx)
{
	APPLOG(APPLOG_DETAIL, "{{{LB}}} new sock connected release olds conn!");

    GNode *root = tcp_ctx->root_conn;
    unsigned int conn_num = g_node_n_children(root);

    for (int i = 0; i < conn_num; i++) {
        GNode *nth_conn = g_node_nth_child(root, i);
        sock_ctx_t *sock_ctx = (sock_ctx_t *)nth_conn->data;
		release_conncb(sock_ctx);
    }
}

void lb_listener_cb(struct evconnlistener *listener, evutil_socket_t fd,
        struct sockaddr *sa, int socklen, void *user_data)
{
    tcp_ctx_t *tcp_ctx = (tcp_ctx_t *)user_data;
    struct event_base *evbase = tcp_ctx->evbase;

	release_older_sock(tcp_ctx);

    sock_ctx_t *sock_ctx = assign_sock_ctx(tcp_ctx, fd, sa);
    if (sock_ctx == NULL) {
        APPLOG(APPLOG_ERR, "{{{LB}}} something wrong (%s)", __func__);
        exit(0);
    } else {
		sock_ctx->tcp_ctx = tcp_ctx;
		sock_ctx->connected = 1;
	}

    if (util_set_linger(fd, 1, 0) != 0) 
        APPLOG(APPLOG_ERR, "{{{LB}}} fail to set SO_LINGER (ABORT) to fd!");
	if (util_set_rcvbuffsize(fd, INT_MAX) != 0)
        APPLOG(APPLOG_ERR, "{{{LB}}} fail to set SO_RCVBUF (size INT_MAX) to fd!");
	if (util_set_sndbuffsize(fd, INT_MAX) != 0)
        APPLOG(APPLOG_ERR, "{{{LB}}} fail to set SO_SNDBUF (size INT_MAX) to fd!");

    struct bufferevent *bev = sock_ctx->bev = bufferevent_socket_new(evbase, fd, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS|BEV_OPT_THREADSAFE);
    if (!bev) {
        APPLOG(APPLOG_ERR, "{{{LB}}} Error constructing bufferevent!");
        event_base_loopbreak(evbase);
        return;
    }

    switch (tcp_ctx->svc_type) {
        case TT_RX_ONLY:
		case TT_PEER_RECV:
            APPLOG(APPLOG_DETAIL, "{{{LB}}} RX ONLY (%s) CONNECTED! (fep_tag %d: heartbeat_enable: %d)", 
					svc_type_to_str(tcp_ctx->svc_type), tcp_ctx->fep_tag, tcp_ctx->heartbeat_enable);
			if (tcp_ctx->heartbeat_enable) {
				sock_chk_heartbeatcb(tcp_ctx, sock_ctx);
			} 
            bufferevent_setcb(bev, lb_buff_readcb, NULL, svr_sock_eventcb, sock_ctx);
            bufferevent_enable(bev, EV_READ);
            break;
        case TT_TX_ONLY:
            APPLOG(APPLOG_DETAIL, "{{{LB}}} TX ONLY (%s) CONNECTED! (fep_tag %d: heartbeat_enable: %d)", 
					svc_type_to_str(tcp_ctx->svc_type), tcp_ctx->fep_tag, tcp_ctx->heartbeat_enable);
            sock_add_flushcb(tcp_ctx, sock_ctx);
			if (tcp_ctx->heartbeat_enable) {
				sock_add_heartbeatcb(tcp_ctx, sock_ctx);
			}
            bufferevent_setcb(bev, unexpect_readcb, NULL, svr_sock_eventcb, sock_ctx);
            bufferevent_enable(bev, EV_READ);
            break;
        default:
            APPLOG(APPLOG_ERR, "{{{LB}}} %s() {DBG} wrong context received", __func__);
            exit(0);
    }

    APPLOG(APPLOG_DETAIL, "{{{LB}}} accepted fd (%d) addr %s port %d",
            sock_ctx->client_fd, sock_ctx->client_ip, sock_ctx->client_port);
}

char *svc_type_to_str(int svc_type)
{
	switch (svc_type) {
		case TT_RX_ONLY:
			return "fep rx only";
		case TT_TX_ONLY:
			return "fep tx only";
		case TT_PEER_RECV:
			return "peer recv";
		case TT_PEER_SEND:
			return "peer send";
		default:
			return "unknown";
	}
}

void *fep_conn_thread(void *arg)
{
	/* multiple WORKER approach to Thread-Evbase, use mutex */
	evthread_use_pthreads();

    tcp_ctx_t *tcp_ctx = (tcp_ctx_t *)arg;

    sock_ctx_t sock_ctx = {0,};
    tcp_ctx->root_conn = new_node_conn(&sock_ctx);

    struct sockaddr_in listen_addr = {0,};
    struct event_base *evbase = NULL;
    struct evconnlistener *listener = NULL;

    if ((evbase = tcp_ctx->evbase = event_base_new()) == NULL) {
        APPLOG(APPLOG_ERR, "{{{LB}}} Could not init event!");
        exit(0);
    }

    listen_addr.sin_family = AF_INET;
    listen_addr.sin_port = htons(tcp_ctx->listen_port);

    APPLOG(APPLOG_ERR, "{{{LB}}} [ %s / for FEP %02d] thread id [%jd] will listen [%s:%5d]",
            __func__, tcp_ctx->fep_tag, (intmax_t)util_gettid(), svc_type_to_str(tcp_ctx->svc_type), tcp_ctx->listen_port);

    // EVUTIL_SOCK_NONBLOCK default setted
    // backlog setted to 16
    if ((listener = tcp_ctx->listener = evconnlistener_new_bind(evbase, lb_listener_cb, (void *)tcp_ctx,
            LEV_OPT_REUSEABLE|LEV_OPT_CLOSE_ON_FREE|LEV_OPT_THREADSAFE, 
            16, (struct sockaddr*)&listen_addr, sizeof(listen_addr))) == NULL) {
        APPLOG(APPLOG_ERR, "{{{LB}}} Could not create a listener! (port : %d)", tcp_ctx->listen_port);
        return (void *)NULL;
    }

    /* loop */
    event_base_loop(evbase, EVLOOP_NO_EXIT_ON_EMPTY);

    /* resource free */
    // TODO!!! check AUTO close() by LEV_OPT_CLOSE_ON_FREE
    evconnlistener_free(listener);
    event_base_free(evbase);

    APPLOG(APPLOG_ERR, "{{{LB}}} %s() reach here~!", __func__);

	return (void *)NULL;
}

void cli_sock_eventcb(struct bufferevent *bev, short events, void *user_data)
{
    sock_ctx_t *sock_ctx = (sock_ctx_t *)user_data;

    APPLOG(APPLOG_DETAIL, "{{{LB}}} %s() called in conn(%s:%d)", __func__, sock_ctx->client_ip, sock_ctx->client_port);

    // normal connected
    if(events & BEV_EVENT_CONNECTED) {

		bufferevent_set_timeouts(bev, NULL, NULL); // remove SYN timeout 

        int fd = bufferevent_getfd(bev);
        APPLOG(APPLOG_DETAIL, "{{{LB}}} connected fd is (%d)", fd);

        if (util_set_linger(fd, 1, 0) != 0) 
            APPLOG(APPLOG_ERR, "{{{LB}}} fail to set SO_LINGER (ABORT) to fd!");

		sock_ctx->connected = 1;

		tcp_ctx_t *tcp_ctx = (tcp_ctx_t *)sock_ctx->tcp_ctx;
		sock_add_flushcb(tcp_ctx, sock_ctx);
		if (tcp_ctx->heartbeat_enable) {
			sock_add_heartbeatcb(tcp_ctx, sock_ctx);
		}
        return;
    }

    // error event
    if (events & BEV_EVENT_EOF) {
        APPLOG(APPLOG_DETAIL, "{{{LB}}} Connection closed!");
    } else if (events & BEV_EVENT_ERROR) {
        APPLOG(APPLOG_DETAIL, "{{{LB}}} Got an error on the connection: %s!", strerror(errno));
	} else {
		APPLOG(APPLOG_DETAIL, "{{{LB}}} We occured event 0x%x!", events);
	}

    release_conncb(sock_ctx);
}

static struct timeval TM_SYN_TIMEOUT = {3, 0};
sock_ctx_t *create_new_peer_sock(tcp_ctx_t *tcp_ctx, const char *peer_addr)
{
    struct sockaddr_in sin = {0,};

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr(peer_addr);
    sin.sin_port = htons(tcp_ctx->listen_port);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (evutil_make_socket_nonblocking(fd) == -1) {
		APPLOG(APPLOG_ERR, "{{{LB}}} peer sock set nonblock failed");
	}

    sock_ctx_t *sock_ctx = assign_sock_ctx(tcp_ctx, fd, (struct sockaddr *)&sin);
    if (sock_ctx == NULL) {
        APPLOG(APPLOG_ERR, "{{{LB}}} something wrong (%s)", __func__);
        exit(0);
    } else {
		sock_ctx->tcp_ctx = tcp_ctx;
	}

    struct event_base *evbase = tcp_ctx->evbase;
	// TODO!!! check BEB_OPV_THREADSAFE
    struct bufferevent *bev = sock_ctx->bev = bufferevent_socket_new(evbase, fd, 
			BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS|BEV_OPT_THREADSAFE);

    if (!bev) {
        APPLOG(APPLOG_ERR, "{{{LB}}} Error constructing bufferevent!");
        event_base_loopbreak(evbase);
        return NULL;
    }

    bufferevent_enable(bev, EV_READ);
    bufferevent_setcb(bev, unexpect_readcb, NULL, cli_sock_eventcb, sock_ctx);
    bufferevent_set_timeouts(bev, &TM_SYN_TIMEOUT, &TM_SYN_TIMEOUT);

    if(bufferevent_socket_connect(bev, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		release_conncb(sock_ctx);
        return NULL;
    }

    return sock_ctx;
}

void check_peer_conn(evutil_socket_t fd, short what, void *arg)
{
    tcp_ctx_t *tcp_ctx = (tcp_ctx_t *)arg;
    sock_ctx_t *sock_ctx = NULL;

	char converted_ip[128] = {0,};
	char *peer_ip_addr = NULL;
	int is_host = 0;

	if ((is_host = is_host_if_cnvt(tcp_ctx->peer_ip_addr, converted_ip)) == 0) {
		peer_ip_addr = tcp_ctx->peer_ip_addr;
	} else if (is_host == 1) {
		peer_ip_addr = converted_ip;
	} else {
		/* it is host but fail to resolv */
		APPLOG(APPLOG_ERR, "{{{LB}}} can't resolv peer_ip_addr conf (%s)", tcp_ctx->peer_ip_addr);
		return;
	}

    // config --> sock check --> create new
	if (search_node_by_ip(tcp_ctx, peer_ip_addr) == NULL) {
		sock_ctx = create_new_peer_sock(tcp_ctx, peer_ip_addr);
		APPLOG(APPLOG_DETAIL, "{{{LB}}} peer %s not exist create new one ... %s", 
				peer_ip_addr, sock_ctx == NULL ?  "failed" : "success");
		}

    // sock --> config check --> remove one
    int sock_cnt = return_sock_num(tcp_ctx);
    for (int i = 0; i < sock_cnt; i++) {
        sock_ctx = return_nth_sock(tcp_ctx, i);
        if (check_conf_via_sock(tcp_ctx, sock_ctx) == 0) {
            APPLOG(APPLOG_DETAIL, "{{{LB}}} peer %s not exist in config delete this one ...", 
                    sock_ctx->client_ip);
            release_conncb(sock_ctx);
        }
    }
}

void *fep_peer_thread(void *arg)
{
	/* multiple WORKER approach to Thread-Evbase, use mutex */
	evthread_use_pthreads();

    tcp_ctx_t *tcp_ctx = (tcp_ctx_t *)arg;

    sock_ctx_t sock_ctx = {0,};
    tcp_ctx->root_conn = new_node_conn(&sock_ctx);

    struct event_base *evbase = NULL;

    if ((evbase = tcp_ctx->evbase = event_base_new()) == NULL) {
        APPLOG(APPLOG_ERR, "{{{LB}}} ERR}} could not init event!");
        exit(0);
    }

    APPLOG(APPLOG_ERR, "{{{LB}}} [ %s / for FEP %02d] thread id [%jd] connect to  [peer(s): %s:%5d]",
            __func__, tcp_ctx->fep_tag, (intmax_t)util_gettid(), tcp_ctx->peer_ip_addr, tcp_ctx->listen_port);

    struct timeval tm_interval = {1, 0}; // 1sec interval
    struct event *ev_tmr;
    ev_tmr = event_new(evbase, -1, EV_PERSIST, check_peer_conn, tcp_ctx);
    event_add(ev_tmr, &tm_interval);

    /* loop */
    event_base_loop(evbase, EVLOOP_NO_EXIT_ON_EMPTY);

    event_base_free(evbase);

    APPLOG(APPLOG_ERR, "{{{LB}}} %s() reach here~!", __func__);

	return (void *)NULL;
}

void CREATE_LB_THREAD(GNode *root_node, size_t context_size, int context_num)
{   
    unsigned int thrd_num = g_node_n_children(root_node);
    for (int i = 0; i < thrd_num; i++) {
        GNode *nth_thrd = g_node_nth_child(root_node, i);
        tcp_ctx_t *tcp_ctx = (tcp_ctx_t *)nth_thrd->data;

		if (context_size != 0 && context_num != 0) {
			tcp_ctx->buff_exist = 1; // it use malloc buffer
			if ((tcp_ctx->httpcs_ctx_buff = calloc(context_num, context_size)) == NULL) {
				APPLOG(APPLOG_ERR, "{{{LB}}} fail to malloc for recv ctx ( %lu x %d ) !!!",
						context_size, context_num);
				exit(0);
			}	
		}
		tcp_ctx->context_num = context_num;

        switch (tcp_ctx->svc_type) {
			/* server sock */
            case TT_RX_ONLY:
            case TT_TX_ONLY:
			case TT_PEER_RECV:
                if (pthread_create(&tcp_ctx->thread_id, NULL, &fep_conn_thread, tcp_ctx) != 0) {
                    APPLOG(APPLOG_ERR, "{{{LB}}} cant invoke thread type %d, %d th!", tcp_ctx->svc_type, i);
                    exit(0);
                } else {
                    pthread_detach(tcp_ctx->thread_id);
                }
                break;
			/* client sock */
            case TT_PEER_SEND:
                if (pthread_create(&tcp_ctx->thread_id, NULL, &fep_peer_thread, tcp_ctx) != 0) {
                    APPLOG(APPLOG_ERR, "{{{LB}}} cant invoke thread type %d, %d th!", tcp_ctx->svc_type, i);
                    exit(0);
                } else {
                    pthread_detach(tcp_ctx->thread_id);
                }
                break;
            default:
                APPLOG(APPLOG_ERR, "{{{LB}}} in func (%s) unknown svc_type (%d)!", __func__, tcp_ctx->svc_type);
                break;
        }
    }
}
