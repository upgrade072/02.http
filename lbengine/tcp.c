#include "lbengine.h"

GNode *new_node_conn(sock_ctx_t *sock_ctx)
{
    sock_ctx_t *data = malloc(sizeof(sock_ctx_t));
    memcpy(data, sock_ctx, sizeof(sock_ctx_t));
    time(&data->create_time);

    return g_node_new(data);
}

GNode *add_node_conn(GNode *parent, GNode *child, GNode *looser_brother)
{
    return g_node_insert_before(parent, looser_brother, child);
}

void remove_node_conn(GNode *node)
{
	free(node->data);
    return g_node_destroy(node);
}

sock_ctx_t *search_node_by_ip(tcp_ctx_t *tcp_ctx, const char *ipaddr)
{
    GNode *root = tcp_ctx->root_conn;
    unsigned int conn_num = g_node_n_children(root);

    for (int i = 0; i < conn_num; i++) {
        GNode *nth_conn = g_node_nth_child(root, i);
        sock_ctx_t *sock_ctx = (sock_ctx_t *)nth_conn->data;
        if (!strcmp(sock_ctx->client_ip, ipaddr))
            return sock_ctx;
    }
    return (sock_ctx_t *)NULL;
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

int check_conf_via_sock(tcp_ctx_t *tcp_ctx, sock_ctx_t *sock_ctx)
{
    config_setting_t *peer_list = tcp_ctx->peer_list;
    int peer_cnt = config_setting_length(peer_list);

    for (int i = 0; i < peer_cnt; i++) {
        config_setting_t *list = config_setting_get_elem(peer_list, i);
        const char *peer_addr = config_setting_get_string(list);
        if (!strcmp(sock_ctx->client_ip, peer_addr))
            return 1; // find
    }
    return 0; // not find
}

void unexpect_readcb(struct bufferevent *bev, void *arg)
{
    sock_ctx_t *sock_ctx = (sock_ctx_t *)arg;

    fprintf(stderr, "((%s)) called\n", __func__);

    char buff[10240] = {0,};
    ssize_t rsize = bufferevent_read(bev, buff, sizeof(buff));

    buff[rsize + 1] = '\0';
    fprintf(stderr, "recv unexpected (%ld byte)\n", rsize);
    util_dumphex(buff, rsize);

    release_conncb(sock_ctx);
}

void release_conncb(sock_ctx_t *sock_ctx)
{
    fprintf(stderr, "warn] sock from %s:%d fd(%d) (%.19s ~ ) closed\n",
            sock_ctx->client_ip, sock_ctx->client_port, sock_ctx->client_fd,
            ctime(&sock_ctx->create_time));

    struct bufferevent *bev = sock_ctx->bev;

	// CHECK event first? bev first?
    if (sock_ctx->event)
        event_del(sock_ctx->event);

    // remove event, close sock
	if (sock_ctx->bev)
		bufferevent_free(bev);

    // remove whole push item, unset caller ctx
    unset_pushed_item(&sock_ctx->push_items, sock_ctx->push_items.item_bytes);
    // remove conn info 
    remove_node_conn(sock_ctx->my_conn);
}

void svr_sock_eventcb(struct bufferevent *bev, short events, void *user_data)
{
    sock_ctx_t *sock_ctx = (sock_ctx_t *)user_data;

    fprintf(stderr, "((%s)) called in conn(%s:%d)\n", __func__, sock_ctx->client_ip, sock_ctx->client_port);

    // client sock conneted
    if(events & BEV_EVENT_CONNECTED) {
        int fd = bufferevent_getfd(bev);
        fprintf(stderr, "connected fd is (%d)\n", fd);

        if (util_set_linger(fd, 1, 0) != 0) 
            fprintf(stderr, "fail to set SO_LINGER (ABORT) to fd\n");

		sock_ctx->connected = 1;
        return;
    }

    if (events & BEV_EVENT_EOF) {
        fprintf(stderr, "Connection closed.\n");
    } else if (events & BEV_EVENT_ERROR) {
        fprintf(stderr, "Got an error on the connection: %s\n", strerror(errno));
    }

    release_conncb(sock_ctx);
}

void packet_process_res(sock_ctx_t *sock_ctx, char *process_ptr, size_t processed_len)
{
	//fprintf(stderr, "{{{DBG}}} %s called (processed_len :%ld) it means we expect next turn!\n", __func__, processed_len);

    // if sock recv 10, process 3 ==> move remain 7 byte to front
    memmove(sock_ctx->buff, process_ptr, sock_ctx->rcv_len - (sock_ctx->rcv_len - processed_len));
    sock_ctx->rcv_len = sock_ctx->rcv_len - processed_len;
    return;
}

sock_ctx_t *assign_sock_ctx(tcp_ctx_t *tcp_ctx, evutil_socket_t fd, struct sockaddr *sa)
{
    sock_ctx_t sock_ctx = {0,};
    sprintf(sock_ctx.client_ip, "%s", util_get_ip_from_sa(sa));
    sock_ctx.client_port = util_get_port_from_sa(sa);
    sock_ctx.client_fd = fd;
    sock_ctx.main_ctx = tcp_ctx->main_ctx;

    GNode *new_conn = new_node_conn(&sock_ctx);
    if (new_conn != NULL) {
        add_node_conn(tcp_ctx->root_conn, new_conn, NULL);
        sock_ctx_t *sock_ctx = (sock_ctx_t *)new_conn->data;
        sock_ctx->my_conn = new_conn;
        return sock_ctx;
    } else {
        fprintf(stderr, "fail to create sock ctx!\n");
        return NULL;
    }
}

void sock_flush_callback(evutil_socket_t fd, short what, void *arg)
{
	if (fd < 0) return;

    sock_ctx_t *sock_ctx = (sock_ctx_t *)arg;
    write_list_t *write_list = &sock_ctx->push_items;

    /* push all remain item */
    ssize_t nwritten = push_write_item(sock_ctx->client_fd, write_list, 1024, 1024*1024);
    if (nwritten > 0)
        unset_pushed_item(write_list, nwritten);
}

int sock_add_flushcb(tcp_ctx_t *tcp_ctx, sock_ctx_t *sock_ctx)
{
    struct timeval tm_interval  = {0, tcp_ctx->flush_tmval};
    sock_ctx->event = event_new(tcp_ctx->evbase, -1, EV_PERSIST, sock_flush_callback, sock_ctx);

    return event_add(sock_ctx->event, &tm_interval);
}

void lb_listener_cb(struct evconnlistener *listener, evutil_socket_t fd,
        struct sockaddr *sa, int socklen, void *user_data)
{
    tcp_ctx_t *tcp_ctx = (tcp_ctx_t *)user_data;
    struct event_base *evbase = tcp_ctx->evbase;

    sock_ctx_t *sock_ctx = assign_sock_ctx(tcp_ctx, fd, sa);
    if (sock_ctx == NULL) {
        fprintf(stderr, "something wrong (%s)\n", __func__);
        exit(0);
    }

    if (util_set_linger(fd, 1, 0) != 0) 
        fprintf(stderr, "fail to set SO_LINGER (ABORT) to fd\n");
	//if (util_set_rcvbuffsize(fd, 1024 * 1024 * 1024 * 1 /*1MB*/) != 0)
	if (util_set_rcvbuffsize(fd, INT_MAX) != 0)
        fprintf(stderr, "fail to set SO_RCVBUF (size 1MB) to fd\n");
	//if (util_set_sndbuffsize(fd, 1024 * 1024 * 1024 * 1 /*1MB*/) != 0)
	if (util_set_sndbuffsize(fd, INT_MAX) != 0)
        fprintf(stderr, "fail to set SO_SNDBUF (size 1MB) to fd\n");

    /* only single thread approach to FD, cause we don't need BEV_OPT_THREADSAFE option */
#if 0
    struct bufferevent *bev = sock_ctx->bev = bufferevent_socket_new(evbase, fd, BEV_OPT_CLOSE_ON_FREE);
#else
    struct bufferevent *bev = sock_ctx->bev = bufferevent_socket_new(evbase, fd, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS|BEV_OPT_THREADSAFE);
#endif
    if (!bev) {
        fprintf(stderr, "Error constructing bufferevent!");
        event_base_loopbreak(evbase);
        return;
    }

    switch (tcp_ctx->svr_type) {
        case TT_RX_ONLY:
            fprintf(stderr, "{dbg} rx only connected!\n");
            bufferevent_setcb(bev, lb_buff_readcb, NULL, svr_sock_eventcb, sock_ctx);
            bufferevent_enable(bev, EV_READ);
            break;
        case TT_TX_ONLY:
            fprintf(stderr, "{dbg} tx only connected!\n");
            int res = sock_add_flushcb(tcp_ctx, sock_ctx); // TODO res < 0 ???
			if (res < 0) {
				// TODO!!!
			}
            bufferevent_setcb(bev, unexpect_readcb, NULL, svr_sock_eventcb, sock_ctx);
            bufferevent_enable(bev, EV_READ);
            break;
        default:
            fprintf(stderr, "{dbg} wrong context received\n");
            exit(0);
    }

    fprintf(stderr, "accepted fd (%d) addr %s port %d\n",
            sock_ctx->client_fd, sock_ctx->client_ip, sock_ctx->client_port);
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
        fprintf(stderr, "ERR}} could not init event!\n");
        exit(0);
    }

    listen_addr.sin_family = AF_INET;
    listen_addr.sin_port = htons(tcp_ctx->listen_port);

    fprintf(stderr, ">>>[ %-20s ] thread id [%jd] will listen [%s:%5d]<<<\n",
            __func__, (intmax_t)util_gettid(), tcp_ctx->svr_type == TT_RX_ONLY ? "rx only" : "tx only", tcp_ctx->listen_port);

    // EVUTIL_SOCK_NONBLOCK default setted
    // backlog setted to 16
    if ((listener = tcp_ctx->listener = evconnlistener_new_bind(evbase, lb_listener_cb, (void *)tcp_ctx,
            LEV_OPT_REUSEABLE|LEV_OPT_CLOSE_ON_FREE|LEV_OPT_THREADSAFE, 
            16, (struct sockaddr*)&listen_addr, sizeof(listen_addr))) == NULL) {
        fprintf(stderr, "Could not create a listener!\n");
        return (void *)NULL;
    }

    /* loop */
    event_base_loop(evbase, EVLOOP_NO_EXIT_ON_EMPTY);

    /* resource free */
    // TODO!!! check AUTO close() by LEV_OPT_CLOSE_ON_FREE
    evconnlistener_free(listener);
    event_base_free(evbase);

    fprintf(stderr, "reach here~!\n");

	return (void *)NULL;
}

void cli_sock_eventcb(struct bufferevent *bev, short events, void *user_data)
{
    sock_ctx_t *sock_ctx = (sock_ctx_t *)user_data;

    fprintf(stderr, "((%s)) called in conn(%s:%d)\n", __func__, sock_ctx->client_ip, sock_ctx->client_port);

    // normal connected
    if(events & BEV_EVENT_CONNECTED) {
        int fd = bufferevent_getfd(bev);
        fprintf(stderr, "connected fd is (%d)\n", fd);

        if (util_set_linger(fd, 1, 0) != 0) 
            fprintf(stderr, "fail to set SO_LINGER (ABORT) to fd\n");

        return;
    }

    // error event
    if (events & BEV_EVENT_EOF) {
        fprintf(stderr, "Connection closed.\n");
    } else if (events & BEV_EVENT_ERROR) {
        fprintf(stderr, "Got an error on the connection: %s\n", strerror(errno));
    }

    release_conncb(sock_ctx);
}

static struct timeval TM_SYN_TIMEOUT = {3, 0};
sock_ctx_t *create_new_peer_sock(tcp_ctx_t *tcp_ctx, const char *peer_addr)
{
    struct sockaddr_in sin = {0,};

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr(peer_addr);
    sin.sin_port = htons(tcp_ctx->peer_listen_port);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (evutil_make_socket_nonblocking(fd) == -1) {
		fprintf(stderr, "peer sock set nonblock failed\n");
	} else {
		fprintf(stderr, "peer sock set nonblock success\n");
	}

    sock_ctx_t *sock_ctx = assign_sock_ctx(tcp_ctx, fd, (struct sockaddr *)&sin);
    if (sock_ctx == NULL) {
        fprintf(stderr, "something wrong (%s)\n", __func__);
        exit(0);
    }

    struct event_base *evbase = tcp_ctx->evbase;
	// TODO!!! check BEB_OPV_THREADSAFE
    struct bufferevent *bev = sock_ctx->bev = bufferevent_socket_new(evbase, fd, 
			BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS|BEV_OPT_THREADSAFE);

    if (!bev) {
        fprintf(stderr, "Error constructing bufferevent!");
        event_base_loopbreak(evbase);
        return NULL;
    }

    int res = sock_add_flushcb(tcp_ctx, sock_ctx); // TODO res < 0 ???
	if (res < 0) {
		fprintf(stderr, "fail to add flush cb in (%s)\n", __func__);
		release_conncb(sock_ctx);
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

    // config --> sock check --> create new
    int peer_cnt = config_setting_length(tcp_ctx->peer_list);
    for (int i = 0; i < peer_cnt; i++) {
        config_setting_t *list = config_setting_get_elem(tcp_ctx->peer_list, i);
        const char *peer_addr = config_setting_get_string(list);
        if (search_node_by_ip(tcp_ctx, peer_addr) == NULL) {
            sock_ctx = create_new_peer_sock(tcp_ctx, peer_addr);
            fprintf(stderr, "dbg} peer %s not exist create new one ... %s\n", 
                    peer_addr, sock_ctx == NULL ?  "failed" : "success");
		}
    }

    // sock --> config check --> remove one
    int sock_cnt = return_sock_num(tcp_ctx);
    for (int i = 0; i < sock_cnt; i++) {
        sock_ctx = return_nth_sock(tcp_ctx, i);
        if (check_conf_via_sock(tcp_ctx, sock_ctx) == 0) {
            fprintf(stderr, "dbg} peer %s not exist in config delete this one ...\n", 
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
        fprintf(stderr, "ERR}} could not init event!\n");
        exit(0);
    }

    fprintf(stderr, ">>>[ %-20s ] thread id [%jd] connect to  [peer(s):%5d]<<<\n",
            __func__, (intmax_t)util_gettid(), tcp_ctx->peer_listen_port);

    struct timeval tm_interval = {1, 0}; // 1sec interval
    struct event *ev_tmr;
    ev_tmr = event_new(evbase, -1, EV_PERSIST, check_peer_conn, tcp_ctx);
    event_add(ev_tmr, &tm_interval);

    /* loop */
    event_base_loop(evbase, EVLOOP_NO_EXIT_ON_EMPTY);

    event_base_free(evbase);

    fprintf(stderr, "reach here~!\n");

	return (void *)NULL;
}

