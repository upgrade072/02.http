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
		fprintf(stderr, "fail to create thread ctx!!!\n");
		exit(0);
	}
}

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
	if (!strcmp(sock_ctx->client_ip, tcp_ctx->peer_ip_addr))
		return 1; // find
	else
		return 0; // not find
}

void unexpect_readcb(struct bufferevent *bev, void *arg)
{
    sock_ctx_t *sock_ctx = (sock_ctx_t *)arg;

    fprintf(stderr, "LB-ENGINE] ((%s)) called\n", __func__);

    char buff[10240] = {0,};
    ssize_t rsize = bufferevent_read(bev, buff, sizeof(buff));

    buff[rsize + 1] = '\0';
    fprintf(stderr, "LB-ENGINE] recv unexpected (%ld byte)\n", rsize);
    util_dumphex(buff, rsize);

    release_conncb(sock_ctx);
}

void release_conncb(sock_ctx_t *sock_ctx)
{
    fprintf(stderr, "LB-ENGINE] sock %s:%d fd(%d) (%.19s ~ ) closed\n",
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
    remove_node(sock_ctx->my_conn);
}

void svr_sock_eventcb(struct bufferevent *bev, short events, void *user_data)
{
    sock_ctx_t *sock_ctx = (sock_ctx_t *)user_data;

    fprintf(stderr, "LB-ENGINE] ((%s)) called in conn(%s:%d)\n", __func__, sock_ctx->client_ip, sock_ctx->client_port);

    // client sock conneted
    if(events & BEV_EVENT_CONNECTED) {

        int fd = bufferevent_getfd(bev);
        fprintf(stderr, "LB-ENGINE] connected fd is (%d)\n", fd);

        if (util_set_linger(fd, 1, 0) != 0) 
            fprintf(stderr, "LB-ENGINE] fail to set SO_LINGER (ABORT) to fd\n");

		sock_ctx->connected = 1;
        return;
    }

    if (events & BEV_EVENT_EOF) {
        fprintf(stderr, "LB-ENGINE] Connection closed.\n");
    } else if (events & BEV_EVENT_ERROR) {
        fprintf(stderr, "LB-ENGINE] Got an error on the connection: %s\n", strerror(errno));
    }

    release_conncb(sock_ctx);
}

void packet_process_res(sock_ctx_t *sock_ctx, char *process_ptr, size_t processed_len)
{

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
        add_node(tcp_ctx->root_conn, new_conn, NULL);
        sock_ctx_t *sock_ctx = (sock_ctx_t *)new_conn->data;
        sock_ctx->my_conn = new_conn;
        return sock_ctx;
    } else {
        fprintf(stderr, "LB-ENGINE] fail to create sock ctx!\n");
        return NULL;
    }
}

void sock_flush_callback(evutil_socket_t fd, short what, void *arg)
{
	/*
	if (fd < 0) return;
	*/

    sock_ctx_t *sock_ctx = (sock_ctx_t *)arg;
	tcp_ctx_t *tcp_ctx = (tcp_ctx_t *)sock_ctx->tcp_ctx;
    write_list_t *write_list = &sock_ctx->push_items;

    /* push all remain item */
    ssize_t nwritten = push_write_item(sock_ctx->client_fd, write_list, 1024, 1024*1024);
    if (nwritten > 0) {
        unset_pushed_item(write_list, nwritten);
		/* stat */
		tcp_ctx->send_bytes += nwritten;
		//fprintf(stderr, "{{{dbg}}} (%s) write %ld bytes\n", __func__, nwritten);
	}
}

int sock_add_flushcb(tcp_ctx_t *tcp_ctx, sock_ctx_t *sock_ctx)
{
    struct timeval tm_interval  = {0, tcp_ctx->flush_tmval};
    sock_ctx->event = event_new(tcp_ctx->evbase, -1, EV_PERSIST, sock_flush_callback, sock_ctx);

    return event_add(sock_ctx->event, &tm_interval);
}

void release_older_sock(tcp_ctx_t *tcp_ctx)
{
	fprintf(stderr, "LB-ENGINE] new sock connected release olds conn!\n");

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
        fprintf(stderr, "LB-ENGINE] something wrong (%s)\n", __func__);
        exit(0);
    } else {
		sock_ctx->tcp_ctx = tcp_ctx;
	}

    if (util_set_linger(fd, 1, 0) != 0) 
        fprintf(stderr, "LB-ENGINE] fail to set SO_LINGER (ABORT) to fd\n");
	if (util_set_rcvbuffsize(fd, INT_MAX) != 0)
        fprintf(stderr, "LB-ENGINE] fail to set SO_RCVBUF (size INT_MAX) to fd\n");
	if (util_set_sndbuffsize(fd, INT_MAX) != 0)
        fprintf(stderr, "LB-ENGINE] fail to set SO_SNDBUF (size INT_MAX) to fd\n");

    struct bufferevent *bev = sock_ctx->bev = bufferevent_socket_new(evbase, fd, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS|BEV_OPT_THREADSAFE);
    if (!bev) {
        fprintf(stderr, "LB-ENGINE] Error constructing bufferevent!");
        event_base_loopbreak(evbase);
        return;
    }

    switch (tcp_ctx->svc_type) {
        case TT_RX_ONLY:
            fprintf(stderr, "LB-ENGINE] {dbg} rx only connected!\n");
            bufferevent_setcb(bev, lb_buff_readcb, NULL, svr_sock_eventcb, sock_ctx);
            bufferevent_enable(bev, EV_READ);
            break;
        case TT_TX_ONLY:
            fprintf(stderr, "LB-ENGINE] {dbg} tx only connected!\n");
            int res = sock_add_flushcb(tcp_ctx, sock_ctx); // TODO res < 0 ???
			if (res < 0) {
				// TODO!!!
			}
            bufferevent_setcb(bev, unexpect_readcb, NULL, svr_sock_eventcb, sock_ctx);
            bufferevent_enable(bev, EV_READ);
            break;
        default:
            fprintf(stderr, "LB-ENGINE] {dbg} wrong context received\n");
            exit(0);
    }

    fprintf(stderr, "LB-ENGINE] accepted fd (%d) addr %s port %d\n",
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
        fprintf(stderr, "LB-ENGINE] ERR}} could not init event!\n");
        exit(0);
    }

    listen_addr.sin_family = AF_INET;
    listen_addr.sin_port = htons(tcp_ctx->listen_port);

    fprintf(stderr, ">>>[ %-20s ] thread id [%jd] will listen [%s:%5d]<<<\n",
            __func__, (intmax_t)util_gettid(), tcp_ctx->svc_type == TT_RX_ONLY ? "rx only" : "tx only", tcp_ctx->listen_port);

    // EVUTIL_SOCK_NONBLOCK default setted
    // backlog setted to 16
    if ((listener = tcp_ctx->listener = evconnlistener_new_bind(evbase, lb_listener_cb, (void *)tcp_ctx,
            LEV_OPT_REUSEABLE|LEV_OPT_CLOSE_ON_FREE|LEV_OPT_THREADSAFE, 
            16, (struct sockaddr*)&listen_addr, sizeof(listen_addr))) == NULL) {
        fprintf(stderr, "LB-ENGINE] Could not create a listener! (port : %d)\n", tcp_ctx->listen_port);
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

    fprintf(stderr, "LB-ENGINE] ((%s)) called in conn(%s:%d)\n", __func__, sock_ctx->client_ip, sock_ctx->client_port);

    // normal connected
    if(events & BEV_EVENT_CONNECTED) {

		bufferevent_set_timeouts(bev, NULL, NULL); // remove SYN timeout 

        int fd = bufferevent_getfd(bev);
        fprintf(stderr, "LB-ENGINE] connected fd is (%d)\n", fd);

        if (util_set_linger(fd, 1, 0) != 0) 
            fprintf(stderr, "LB-ENGINE] fail to set SO_LINGER (ABORT) to fd\n");

		sock_ctx->connected = 1;
        return;
    }

    // error event
    if (events & BEV_EVENT_EOF) {
        fprintf(stderr, "LB-ENGINE] Connection closed.\n");
    } else if (events & BEV_EVENT_ERROR) {
        fprintf(stderr, "LB-ENGINE] Got an error on the connection: %s\n", strerror(errno));
	} else {
		fprintf(stderr, "LB-ENGINE] We occured event 0x%x\n", events);
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
		fprintf(stderr, "LB-ENGINE] peer sock set nonblock failed\n");
	}

    sock_ctx_t *sock_ctx = assign_sock_ctx(tcp_ctx, fd, (struct sockaddr *)&sin);
    if (sock_ctx == NULL) {
        fprintf(stderr, "LB-ENGINE] something wrong (%s)\n", __func__);
        exit(0);
    } else {
		sock_ctx->tcp_ctx = tcp_ctx;
	}

    struct event_base *evbase = tcp_ctx->evbase;
	// TODO!!! check BEB_OPV_THREADSAFE
    struct bufferevent *bev = sock_ctx->bev = bufferevent_socket_new(evbase, fd, 
			BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS|BEV_OPT_THREADSAFE);

    if (!bev) {
        fprintf(stderr, "LB-ENGINE] Error constructing bufferevent!");
        event_base_loopbreak(evbase);
        return NULL;
    }

    int res = sock_add_flushcb(tcp_ctx, sock_ctx); // TODO res < 0 ???
	if (res < 0) {
		fprintf(stderr, "LB-ENGINE] fail to add flush cb in (%s)\n", __func__);
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
	if (search_node_by_ip(tcp_ctx, tcp_ctx->peer_ip_addr) == NULL) {
		sock_ctx = create_new_peer_sock(tcp_ctx, tcp_ctx->peer_ip_addr);
		fprintf(stderr, "LB-ENGINE] peer %s not exist create new one ... %s\n", 
				tcp_ctx->peer_ip_addr, sock_ctx == NULL ?  "failed" : "success");
		}

    // sock --> config check --> remove one
    int sock_cnt = return_sock_num(tcp_ctx);
    for (int i = 0; i < sock_cnt; i++) {
        sock_ctx = return_nth_sock(tcp_ctx, i);
        if (check_conf_via_sock(tcp_ctx, sock_ctx) == 0) {
            fprintf(stderr, "LB-ENGINE] peer %s not exist in config delete this one ...\n", 
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
        fprintf(stderr, "LB-ENGINE] ERR}} could not init event!\n");
        exit(0);
    }

    fprintf(stderr, ">>>[ %-20s ] thread id [%jd] connect to  [peer(s):%5d]<<<\n",
            __func__, (intmax_t)util_gettid(), tcp_ctx->listen_port);

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

void CREATE_LB_THREAD(GNode *root_node, size_t context_size, int context_num)
{   
	fprintf(stderr, "{{{dbg}}} %s called!\n", __func__);

    unsigned int thrd_num = g_node_n_children(root_node);
    for (int i = 0; i < thrd_num; i++) {
        GNode *nth_thrd = g_node_nth_child(root_node, i);
        tcp_ctx_t *tcp_ctx = (tcp_ctx_t *)nth_thrd->data;

		if (context_size != 0 && context_num != 0) {
			tcp_ctx->buff_exist = 1; // it use malloc buffer
			if ((tcp_ctx->httpcs_ctx_buff = calloc(context_num, context_size)) == NULL) {
				fprintf(stderr, "ERR} fail to malloc for recv ctx ( %ld x %d ) !!!\n",
						context_size, context_num);
				exit(0);
			}	
		}
		tcp_ctx->context_num = context_num;

        switch (tcp_ctx->svc_type) {
            case TT_RX_ONLY:
            case TT_TX_ONLY:
                if (pthread_create(&tcp_ctx->thread_id, NULL, &fep_conn_thread, tcp_ctx) != 0) {
                    fprintf(stderr, "ERR} cant invoke thread type %d, %d th\n", tcp_ctx->svc_type, i);
                    exit(0);
                } else {
                    pthread_detach(tcp_ctx->thread_id);
                }
                break;
            case TT_PEER_SEND:
                if (pthread_create(&tcp_ctx->thread_id, NULL, &fep_peer_thread, tcp_ctx) != 0) {
                    fprintf(stderr, "ERR} cant invoke thread type %d, %d th\n", tcp_ctx->svc_type, i);
                    exit(0);
                } else {
                    pthread_detach(tcp_ctx->thread_id);
                }
                break;
            default:
                fprintf(stderr, "ERR} in func (%s) unknown svc_type (%d)\n", __func__, tcp_ctx->svc_type);
                break;
        }
    }
}
