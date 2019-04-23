#include <server.h>

extern server_conf SERVER_CONF;   /* sysconfig from config.c */
extern thrd_context THRD_WORKER[MAX_THRD_NUM];

lb_global_t LB_CONF;                /* lb config */
main_ctx_t MAIN_CTX;                /* lb connection context */

https_ctx_t *get_null_recv_ctx(tcp_ctx_t *tcp_ctx)
{
	https_ctx_t *rcv_buff_ctx = (https_ctx_t *)tcp_ctx->httpcs_ctx_buff;

	for (int i = 0; i < tcp_ctx->context_num; i++) {
		https_ctx_t *recv_ctx = &rcv_buff_ctx[i];
		if (recv_ctx->occupied == 0) {
			memset(recv_ctx, 0x00, sizeof(https_ctx_t));
			recv_ctx->fep_tag = tcp_ctx->fep_tag;
			recv_ctx->recv_thread_id = tcp_ctx->thread_id;
			recv_ctx->occupied = 1;
			return recv_ctx;
		}
	}
	return NULL;
}

https_ctx_t *get_assembled_ctx(tcp_ctx_t *tcp_ctx, char *ptr)
{
    https_ctx_t *recv_ctx = NULL;
    AhifHttpCSMsgHeadType *head = (AhifHttpCSMsgHeadType *)ptr;

    char *vheader = ptr + sizeof(AhifHttpCSMsgHeadType);
    int vheaderCnt = head->vheaderCnt;

    char *body = ptr + sizeof(AhifHttpCSMsgHeadType) + (sizeof(hdr_relay) * vheaderCnt);
    int bodyLen = head->bodyLen;

    if((recv_ctx = get_null_recv_ctx(tcp_ctx)) == NULL)
        return NULL;

    memcpy(&recv_ctx->user_ctx.head, ptr, sizeof(AhifHttpCSMsgHeadType));
    memcpy(&recv_ctx->user_ctx.vheader, vheader, (sizeof(hdr_relay) * vheaderCnt));
    memcpy(&recv_ctx->user_ctx.body, body, bodyLen);

#if 0
	fprintf(stderr, "{{{DBG}}} GET TEMP CTX ASSIGN IT TH %d CTX %d\n", 
			recv_ctx->user_ctx.head.thrd_index, recv_ctx->user_ctx.head.ctx_id);
#endif

    return recv_ctx;
}

void set_iovec(tcp_ctx_t *dest_tcp_ctx, https_ctx_t *https_ctx, const char *dest_ip, iovec_item_t *push_req, void (*cbfunc)(), void *cbarg)
{
    AhifHttpCSMsgType *user_ctx = &https_ctx->user_ctx; // we send this [ahif packet]
    memset(push_req, 0x00, sizeof(iovec_item_t));       // this indicate header / vheader / body
    int item_cnt = 0;                                   // full count = 3 (hd, vhd, bdy) , or err count = 1 (only hd)
    int total_bytes = 0;                                // full packet size

    push_req->sender_tcp_ctx = dest_tcp_ctx;            // fep response or peer lb send
	if (dest_ip != NULL)
		sprintf(push_req->dest_ip, "%s", dest_ip);      // dest of this packet

    // header must exist
    if (1)  {
        push_req->iov[0].iov_base = &user_ctx->head;
        push_req->iov[0].iov_len = AHIF_HTTPCS_MSG_HEAD_LEN;
        item_cnt++;
        total_bytes += AHIF_HTTPCS_MSG_HEAD_LEN;
    }
    // vheader
    if (user_ctx->head.vheaderCnt) {
        push_req->iov[item_cnt].iov_base = user_ctx->vheader;
        push_req->iov[item_cnt].iov_len = user_ctx->head.vheaderCnt * sizeof(hdr_relay);
        item_cnt++;
        total_bytes += user_ctx->head.vheaderCnt * sizeof(hdr_relay);
    }
    // body
    if (user_ctx->head.bodyLen) {
        push_req->iov[item_cnt].iov_base = user_ctx->body;
        push_req->iov[item_cnt].iov_len = user_ctx->head.bodyLen;
        item_cnt++;
        total_bytes += user_ctx->head.bodyLen;
    }

    push_req->iov_cnt = item_cnt;
    push_req->remain_bytes = total_bytes;
    push_req->ctx_unset_ptr = NULL;						// CAUTION!!! HOLD CTX BEFORE RESPOSE

    if (cbfunc != NULL) {
        push_req->unset_cb_func = cbfunc;
        push_req->unset_cb_arg = cbarg;
    }
}

void push_callback(evutil_socket_t fd, short what, void *arg)
{
    iovec_item_t *push_item = (iovec_item_t *)arg;
    tcp_ctx_t *tcp_ctx = (tcp_ctx_t *)push_item->sender_tcp_ctx;
#if 0
    sock_ctx_t *sock_ctx = search_node_by_ip(tcp_ctx, push_item->dest_ip);
#else
	sock_ctx_t *sock_ctx = get_last_conn_sock(tcp_ctx);
#endif

    //fprintf(stderr, "((%s)) called dest %s (mypid(%jd))\n", __func__, push_item->dest_ip, (intmax_t)util_gettid());

    if (sock_ctx == NULL) {
        fprintf(stderr, "((%s)) dest (%s) not exist, unset item\n", __func__, push_item->dest_ip);
		if (push_item->ctx_unset_ptr != NULL)
			*push_item->ctx_unset_ptr = 0;
        return;
    } else {
        create_write_item(&sock_ctx->push_items, push_item);
    }

    write_list_t *write_list = &sock_ctx->push_items;

    /* bundle packet by config ==> send by once */
#if 0
	fprintf(stderr, "{{{{dbg}}} item_cnt %d item_bytes %d config (%d %d)\n", 
			write_list->item_cnt, write_list->item_bytes, LB_CONF.bundle_count, LB_CONF.bundle_bytes);
#endif
    if (write_list->item_cnt >= LB_CONF.bundle_count || write_list->item_bytes >= LB_CONF.bundle_bytes) {
        ssize_t nwritten = push_write_item(sock_ctx->client_fd, write_list, LB_CONF.bundle_count, LB_CONF.bundle_bytes);
        if (nwritten > 0) {
			unset_pushed_item(write_list, nwritten);
			/* stat */
			tcp_ctx->send_bytes += nwritten;
			//fprintf(stderr, "{{{dbg}}} nwritten (%ld)\n", nwritten);
		}
		else if (errno != EINTR && errno != EAGAIN) {
			fprintf(stderr, "there error! %d : %s\n", errno, strerror(errno));
		}
    }
}

void iovec_push_req(tcp_ctx_t *dest_tcp_ctx, iovec_item_t *push_req)
{
    struct event_base *peer_evbase = dest_tcp_ctx->evbase;

    if (event_base_once(peer_evbase, -1, EV_TIMEOUT, push_callback, push_req, NULL) < 0) {
        fprintf(stderr, "TODO!!! (%s) fail to add callback to dest evbase", __func__);
    }
}

tcp_ctx_t *get_loadshare_turn(https_ctx_t *https_ctx)
{
	GNode *root_node = MAIN_CTX.fep_tx_thrd;
	unsigned int fep_num = g_node_n_children(root_node);
	tcp_ctx_t *root_data = (tcp_ctx_t *)root_node->data;

	if (fep_num == 0 || root_data == NULL) {
	   	return NULL;
	}

	int turn_index = (root_data->round_robin_index[https_ctx->thrd_idx]++) % fep_num;

	for (int i = 0; i < fep_num; i++) {
		int loadshare_turn = (turn_index + i) % fep_num;
		GNode *nth_thread = g_node_nth_child(root_node, loadshare_turn);
		if (nth_thread != NULL) {
			tcp_ctx_t *fep_tcp_ctx = (tcp_ctx_t *)nth_thread->data;
			int sock_num = g_node_n_children(fep_tcp_ctx->root_conn);
			if (sock_num > 0) {
				https_ctx->fep_tag = fep_tcp_ctx->fep_tag;
				return fep_tcp_ctx;
			}
		}
	}

	return NULL;
}

int send_request_to_fep(https_ctx_t *https_ctx)
{
	tcp_ctx_t *fep_tcp_ctx = get_loadshare_turn(https_ctx);
	if (fep_tcp_ctx == NULL) {
		APPLOG(APPLOG_ERR, "(%s) fail to decision RR. there is no FEP TX conn", __func__);
		return -1; // http error response
	} else {
		fep_tcp_ctx->tps ++;
	}

    //set_iovec(fep_tcp_ctx, https_ctx, sock_ctx->client_ip, &https_ctx->push_req, NULL, NULL);
	// TODO!!!! check dest ip useless or not, if useless remove it
	// TODO!!!! where to get fep_tag
    set_iovec(fep_tcp_ctx, https_ctx, NULL, &https_ctx->push_req, NULL, NULL);

    iovec_push_req(fep_tcp_ctx, &https_ctx->push_req);

	return 0;
}

void send_to_worker(https_ctx_t *recv_ctx)
{
	int thrd_index = recv_ctx->user_ctx.head.thrd_index;
	int session_index = recv_ctx->user_ctx.head.session_index;
	int session_id =  recv_ctx->user_ctx.head.session_id;
	int stream_id = recv_ctx->user_ctx.head.stream_id;
	int ctx_id = recv_ctx->user_ctx.head.ctx_id;

	https_ctx_t *https_ctx = NULL;
	http2_session_data *session_data = NULL;

	//fprintf(stderr, "{{{DBG}}} %s TRY GET ORG CTX TH %d CTX %d\n", __func__, thrd_index, ctx_id);

	if ((https_ctx = get_context(thrd_index, ctx_id, 1)) == NULL) {
		fprintf(stderr, "{{{DBG}}} %s get context FAILED\n", __func__);
		if ((session_data = get_session(thrd_index, session_index, session_id)) == NULL) 
			http_stat_inc(0, 0, HTTP_STRM_N_FOUND); 
		else
			http_stat_inc(session_data->thrd_index, session_data->list_index, HTTP_STRM_N_FOUND);
		goto STW_RET;
	}   

	// check have same fep tag
	if (recv_ctx->fep_tag != https_ctx->fep_tag) {
		APPLOG(APPLOG_ERR, "ERR] fep tag mismatch (ahif recv %d, orig ctx %d)", recv_ctx->fep_tag, https_ctx->fep_tag);
	}

	intl_req_t intl_req = {0,};
	set_intl_req_msg(&intl_req, thrd_index, ctx_id, session_index, session_id, stream_id, HTTP_INTL_SND_REQ);

	assign_rcv_ctx_info(https_ctx, &recv_ctx->user_ctx);

	if (msgsnd(THRD_WORKER[thrd_index].msg_id, &intl_req, sizeof(intl_req) - sizeof(long), 0) == -1) {
		APPLOG(APPLOG_DEBUG, "(%s) internal msgsnd to worker [%d] failed", __func__, thrd_index);
	}

STW_RET:
	recv_ctx->occupied = 0;
	return;
}

void check_and_send(tcp_ctx_t *tcp_ctx, sock_ctx_t *sock_ctx)
{   
    https_ctx_t *recv_ctx = NULL;
    
    AhifHttpCSMsgHeadType *head = NULL;
    char *process_ptr = sock_ctx->buff;
    size_t processed_len = 0;

KEEP_PROCESS:
    if (sock_ctx->rcv_len < (processed_len + AHIF_HTTPCS_MSG_HEAD_LEN))
        return packet_process_res(sock_ctx, process_ptr, processed_len);
    
    head = (AhifHttpCSMsgHeadType *)&sock_ctx->buff[processed_len];
    process_ptr = (char *)head;
    
    if (sock_ctx->rcv_len < (processed_len + AHIF_TCP_MSG_LEN(head)))
        return packet_process_res(sock_ctx, process_ptr, processed_len);
    
    if ((recv_ctx = get_assembled_ctx(tcp_ctx, process_ptr)) == NULL) {
        // TODO!!! it means blocked, all drain ???
        APPLOG(APPLOG_ERR, "cant process packet, will just dropped");
        return packet_process_res(sock_ctx, process_ptr, processed_len);
    }

    process_ptr += AHIF_TCP_MSG_LEN(head);
    processed_len += AHIF_TCP_MSG_LEN(head);
    
	send_to_worker(recv_ctx);

    goto KEEP_PROCESS;
}

void lb_buff_readcb(struct bufferevent *bev, void *arg)
{
    sock_ctx_t *sock_ctx = (sock_ctx_t *)arg;
	tcp_ctx_t *tcp_ctx = (tcp_ctx_t *)sock_ctx->tcp_ctx;
    ssize_t rcv_len = bufferevent_read(bev,
            sock_ctx->buff + sock_ctx->rcv_len,
            MAX_RCV_BUFF_LEN - sock_ctx->rcv_len);

    // TODO !!! check strerror() & if critical, call relese_conn()
    if (rcv_len <= 0) {
        return;
	} else {
        sock_ctx->rcv_len += rcv_len;
		/* stat */
		tcp_ctx->recv_bytes += rcv_len;
	}

    return check_and_send(tcp_ctx, sock_ctx);
}

int get_httpcs_buff_used(tcp_ctx_t *tcp_ctx)
{
    if (tcp_ctx->buff_exist != 1)
        return 0;

    https_ctx_t *rcv_buff_ctx = (https_ctx_t *)tcp_ctx->httpcs_ctx_buff;
    int used = 0;

    for (int i = 0; i < tcp_ctx->context_num; i++) {
        https_ctx_t *recv_ctx = &rcv_buff_ctx[i];
        if (recv_ctx->occupied != 0)
            used++;
    }

    return used;
}

void clear_context_stat(tcp_ctx_t *tcp_ctx)
{
    tcp_ctx->recv_bytes = 0;
    tcp_ctx->send_bytes = 0;
    tcp_ctx->tps = 0;
}

void fep_stat_print(evutil_socket_t fd, short what, void *arg)
{
    char fep_read[1024] = {0,};
    char fep_write[1024] = {0,};

    for (int i = 0; i < LB_CONF.total_fep_num; i++) {
        GNode *nth_fep_rx = g_node_nth_child(MAIN_CTX.fep_rx_thrd, i);
        GNode *nth_fep_tx = g_node_nth_child(MAIN_CTX.fep_tx_thrd, i);

        tcp_ctx_t *fep_rx = (nth_fep_rx == NULL ? NULL : (tcp_ctx_t *)nth_fep_rx->data);
        tcp_ctx_t *fep_tx = (nth_fep_rx == NULL ? NULL : (tcp_ctx_t *)nth_fep_tx->data);

        if (fep_rx == NULL ||
            fep_tx == NULL) {
            APPLOG(APPLOG_ERR, "ERR] some of fep thread is NULL !!!");
            exit(0);
        }

        int fep_rx_used = get_httpcs_buff_used(fep_rx);

        APPLOG(APPLOG_ERR, "FEP [%2d] CTX [fep_rx %05d/%05d] FEP TX [%s] (TPS %d) FEP RX [%s]",
                i,
                fep_rx_used,
                fep_rx->context_num,
                measure_print(fep_tx->send_bytes, fep_write),
                fep_tx->tps,
                measure_print(fep_rx->recv_bytes, fep_read));

        clear_context_stat(fep_rx);
        clear_context_stat(fep_tx);
    }
}

void *fep_stat_thread(void *arg)
{
	main_ctx_t *main_ctx = (main_ctx_t *)arg;

	struct event_base *evbase;
	evbase = event_base_new();

	struct timeval one_sec = {1, 0};
	struct event *ev;
	ev = event_new(evbase, -1, EV_PERSIST, fep_stat_print, (void *)main_ctx);
	event_add(ev, &one_sec);

	/* start loop */
	event_base_loop(evbase, EVLOOP_NO_EXIT_ON_EMPTY);

	/* never reach here */
	event_base_free(evbase);

	return (void *)NULL;
}

void load_lb_config(server_conf *svr_conf, lb_global_t *lb_conf)
{
    config_setting_t *lb_config = svr_conf->lb_config;
	config_setting_t *setting = NULL;

    /* check fep / peer config list */
    setting = lb_conf->cf_fep_rx_listen_port = config_setting_get_member(lb_config, "fep_rx_listen_port");
    if (setting == NULL) {
        APPLOG(APPLOG_ERR, "fail to get lb_config.fep_rx_listen_port");
        exit(0);
    }
    setting = lb_conf->cf_fep_tx_listen_port = config_setting_get_member(lb_config, "fep_tx_listen_port");
    if (setting == NULL) {
        APPLOG(APPLOG_ERR, "fail to get lb_config.fep_tx_listen_port");
        exit(0);
    }
    /* check port num pair match, a == b == c == d */
    if (config_setting_length(lb_conf->cf_fep_rx_listen_port) ==
        config_setting_length(lb_conf->cf_fep_tx_listen_port)) {
        printf_config_list_int("fep_rx_listen_port", lb_conf->cf_fep_rx_listen_port);
        printf_config_list_int("fep_tx_listen_port", lb_conf->cf_fep_tx_listen_port);
    } else {
        APPLOG(APPLOG_ERR, "fep tx|rx port num not match!");
        exit(0);
    }
    /* check fep num */
    lb_conf->total_fep_num = config_setting_length(lb_conf->cf_fep_rx_listen_port);
    if (lb_conf->total_fep_num >= MAX_THRD_NUM) {
        APPLOG(APPLOG_ERR, "total_fep_num(%d) exceed max_thrd_num(%d)",
                lb_conf->total_fep_num, MAX_THRD_NUM);
    }

    /* get context num for fep */
    if (config_setting_lookup_int(lb_config, "context_num", &lb_conf->context_num) == CONFIG_FALSE) {
        APPLOG(APPLOG_ERR, "lb_config.fail to get context_num");
        exit(0);
    } else {
        APPLOG(APPLOG_ERR, "}}  lb_config.context_num = %d", lb_conf->context_num);
    }

    if (config_setting_lookup_int(lb_config, "bundle_bytes", &lb_conf->bundle_bytes) == CONFIG_FALSE) {
        APPLOG(APPLOG_ERR, "lb_config.fail to get bundle_bytes");
        exit(0);
    } else {
        APPLOG(APPLOG_ERR, "}}  lb_config.bundle_bytes = %d", lb_conf->bundle_bytes);
    }
    if (config_setting_lookup_int(lb_config, "bundle_count", &lb_conf->bundle_count) == CONFIG_FALSE) {
        APPLOG(APPLOG_ERR, "lb_config.fail to get bundle_count");
        exit(0);
    } else {
        APPLOG(APPLOG_ERR, "}}  lb_config.bundle_count = %d", lb_conf->bundle_count);
    }
    if (config_setting_lookup_int(lb_config, "flush_tmval", &lb_conf->flush_tmval) == CONFIG_FALSE) {
        APPLOG(APPLOG_ERR, "lb_config.fail to get flush_tmval");
        exit(0);
    } else {
        APPLOG(APPLOG_ERR, "}}  lb_config.flush_tmval = %d", lb_conf->flush_tmval);
    }


}

void attach_lb_thread(lb_global_t *lb_conf, main_ctx_t *main_ctx)
{
    /* CAUTION!!! ALL UNDER THREAD USE THIS */
    tcp_ctx_t tcp_ctx = {0,};
    tcp_ctx.flush_tmval = lb_conf->flush_tmval;
    tcp_ctx.main_ctx = main_ctx;

    // create root node for thread
    main_ctx->fep_tx_thrd = new_tcp_ctx(&tcp_ctx);
    main_ctx->fep_rx_thrd = new_tcp_ctx(&tcp_ctx);

    /* fep rx thread create */
    for (int i = 0; i < lb_conf->total_fep_num; i++) {
        tcp_ctx.fep_tag = i;
        tcp_ctx.svc_type = TT_RX_ONLY;
        config_setting_t *port = config_setting_get_elem(lb_conf->cf_fep_rx_listen_port, i);
        tcp_ctx.listen_port = config_setting_get_int(port);
        add_tcp_ctx_to_main(&tcp_ctx, main_ctx->fep_rx_thrd);
    }
    /* fep tx thread create */
    for (int i = 0; i < lb_conf->total_fep_num; i++) {
        tcp_ctx.fep_tag = i;
        tcp_ctx.svc_type = TT_TX_ONLY;
        config_setting_t *port = config_setting_get_elem(lb_conf->cf_fep_tx_listen_port, i);
        tcp_ctx.listen_port = config_setting_get_int(port);
        add_tcp_ctx_to_main(&tcp_ctx, main_ctx->fep_tx_thrd);
    }

    CREATE_LB_THREAD(main_ctx->fep_rx_thrd, sizeof(https_ctx_t), lb_conf->context_num);
    CREATE_LB_THREAD(main_ctx->fep_tx_thrd, 0, 0);

	/* for stat print small thread */
	if (pthread_create(&main_ctx->stat_thrd_id, NULL, &fep_stat_thread, main_ctx) != 0) {
		APPLOG(APPLOG_ERR, "fail to create thread\n");
		exit(0);
	} else {
		pthread_detach(main_ctx->stat_thrd_id);
	}
}

int create_lb_thread()
{
	load_lb_config(&SERVER_CONF, &LB_CONF);

	attach_lb_thread(&LB_CONF, &MAIN_CTX);

	return 0;
}
