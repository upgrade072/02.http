#include <client.h>

extern client_conf_t CLIENT_CONF;	/* sysconfig from config.c */
extern thrd_context_t THRD_WORKER[MAX_THRD_NUM];

lb_global_t LB_CONF;				/* lb config */
main_ctx_t MAIN_CTX;				/* lb connection context */
#define MAX_LB_CTX_NUM 10240
httpc_ctx_t LB_RECV_CTX[MAX_LB_CTX_NUM];

httpc_ctx_t *get_null_recv_ctx()
{
	for (int i = 0; i < MAX_LB_CTX_NUM; i++) {
		httpc_ctx_t *recv_ctx = &LB_RECV_CTX[i];
		if (recv_ctx->occupied == 0) {
			memset(recv_ctx, 0x00, sizeof(httpc_ctx_t));
			recv_ctx->occupied = 1;
			return recv_ctx;
		}
	}
	return NULL;
}

httpc_ctx_t *get_assembled_ctx(char *ptr)
{
	httpc_ctx_t *recv_ctx = NULL;
	AhifHttpCSMsgHeadType *head = (AhifHttpCSMsgHeadType *)ptr;

	char *vheader = ptr + sizeof(AhifHttpCSMsgHeadType);
	int vheaderCnt = head->vheaderCnt;

	char *body = ptr + sizeof(AhifHttpCSMsgHeadType) + (sizeof(hdr_relay) * vheaderCnt);
	int bodyLen = head->bodyLen;

	if((recv_ctx = get_null_recv_ctx()) == NULL)
		return NULL;

	memcpy(&recv_ctx->user_ctx.head, ptr, sizeof(AhifHttpCSMsgHeadType));
	memcpy(&recv_ctx->user_ctx.vheader, vheader, (sizeof(hdr_relay) * vheaderCnt));
	memcpy(&recv_ctx->user_ctx.body, body, bodyLen);

	return recv_ctx;
}

void send_to_worker(conn_list_t *httpc_conn, httpc_ctx_t *recv_ctx, char *client_ip)
{
	httpc_ctx_t *httpc_ctx = NULL;
	intl_req_t intl_req = {0,};

	int thrd_idx = httpc_conn->thrd_index;
	int sess_idx = httpc_conn->session_index;
	int session_id = httpc_conn->session_id;
	int ctx_idx = Get_CtxId(thrd_idx);

	if (ctx_idx < 0) {
		APPLOG(APPLOG_DEBUG, "(%s) assign context fail in worker [%d]", __func__, thrd_idx);
		goto STW_RET;
	}
	if ((httpc_ctx = get_context(thrd_idx, ctx_idx, 0)) == NULL) {
		APPLOG(APPLOG_DEBUG, "(%s) get contexx fail in worker [%d]", __func__, thrd_idx);
		goto STW_RET;
	}
	// TODO!!! maybe memset context ... or not
	//
	//
	httpc_ctx->recv_time_index = THRD_WORKER[thrd_idx].time_index;
	save_session_info(httpc_ctx, thrd_idx, sess_idx, session_id, ctx_idx, httpc_conn);
	httpc_ctx->occupied = 1; /* after time set */

	memcpy(&httpc_ctx->user_ctx.head, &recv_ctx->user_ctx.head, AHIF_HTTPCS_MSG_HEAD_LEN);
	memcpy(&httpc_ctx->user_ctx.vheader, &recv_ctx->user_ctx.vheader, sizeof(hdr_relay) * recv_ctx->user_ctx.head.vheaderCnt);
	memcpy(&httpc_ctx->user_ctx.body, &recv_ctx->user_ctx.body, recv_ctx->user_ctx.head.bodyLen);
	httpc_ctx->user_ctx.head.bodyLen = recv_ctx->user_ctx.head.bodyLen;

	sprintf(httpc_ctx->resp_client_ip, "%s", client_ip);					// for relay resp to fep
	httpc_ctx->user_ctx.head.mtype = MTYPE_HTTP2_RESPONSE_HTTPC_TO_AHIF;	// in advance set

	set_intl_req_msg(&intl_req, thrd_idx, ctx_idx, sess_idx, session_id, 0, HTTP_INTL_SND_REQ);

	if (msgsnd(THRD_WORKER[thrd_idx].msg_id, &intl_req, sizeof(intl_req) - sizeof(long), 0) == -1) {
		APPLOG(APPLOG_DEBUG, "(%s) internal msgsnd to worker [%d] failed", __func__, thrd_idx);
	}

STW_RET:
	recv_ctx->occupied = 0;
	return;
}

void set_iovec(tcp_ctx_t *dest_tcp_ctx, httpc_ctx_t *recv_ctx, const char *dest_ip, iovec_item_t *push_req, void (*cbfunc)(), void *cbarg)
{
	AhifHttpCSMsgType *user_ctx = &recv_ctx->user_ctx;  // we send this [ahif packet]
    memset(push_req, 0x00, sizeof(iovec_item_t));		// this indicate header / vheader / body
	int item_cnt = 0;									// full count = 3 (hd, vhd, bdy) , or err count = 1 (only hd)
	int total_bytes = 0;								// full packet size

    push_req->sender_tcp_ctx = dest_tcp_ctx;			// fep response or peer lb send
    sprintf(push_req->dest_ip, "%s", dest_ip);			// dest of this packet

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
    push_req->ctx_unset_ptr = &recv_ctx->occupied;			// if all pkt flight out unset this ctx

	if (cbfunc != NULL) {
		push_req->unset_cb_func = cbfunc;
		push_req->unset_cb_arg = cbarg;
	}
}

void push_callback(evutil_socket_t fd, short what, void *arg)
{
    iovec_item_t *push_item = (iovec_item_t *)arg;
    tcp_ctx_t *tcp_ctx = (tcp_ctx_t *)push_item->sender_tcp_ctx;
    sock_ctx_t *sock_ctx = search_node_by_ip(tcp_ctx, push_item->dest_ip);

    fprintf(stderr, "((%s)) called dest %s (mypid(%jd))\n", __func__, push_item->dest_ip, (intmax_t)util_gettid());

    if (sock_ctx == NULL) {
        fprintf(stderr, "((%s)) dest (%s) not exist, unset item\n", __func__, push_item->dest_ip);
        *push_item->ctx_unset_ptr = 0;
        return;
    } else {
        create_write_item(&sock_ctx->push_items, push_item);
        fprintf(stderr, "item pushed\n");
    }

    write_list_t *write_list = &sock_ctx->push_items;

	/* bundle packet by config ==> send by once */
    if (write_list->item_cnt >= LB_CONF.bundle_count || write_list->item_bytes >= LB_CONF.bundle_bytes) {
        ssize_t nwritten = push_write_item(sock_ctx->client_fd, write_list, LB_CONF.bundle_count, LB_CONF.bundle_bytes);
        if (nwritten > 0)
            unset_pushed_item(write_list, nwritten);
    }
}

void iovec_push_req(tcp_ctx_t *dest_tcp_ctx, iovec_item_t *push_req)
{
    struct event_base *peer_evbase = dest_tcp_ctx->evbase;

    if (event_base_once(peer_evbase, -1, EV_TIMEOUT, push_callback, push_req, NULL) < 0) {
        fprintf(stderr, "TODO!!! (%s) fail to add callback to dest evbase", __func__);
    }
}

void stp_err_to_fep(sock_ctx_t *sock_ctx, tcp_ctx_t *fep_tcp_ctx, httpc_ctx_t *recv_ctx)
{
	http_stat_inc(0, 0, HTTP_DEST_N_AVAIL);		/* stat increase */

	recv_ctx->user_ctx.head.mtype = MTYPE_HTTP2_RESPONSE_HTTPC_TO_AHIF;
	recv_ctx->user_ctx.head.respCode = HTTP_RESP_CODE_NOT_FOUND;

	/* response only header */
	recv_ctx->user_ctx.head.vheaderCnt = 0;
	recv_ctx->user_ctx.head.bodyLen = 0;

	set_iovec(fep_tcp_ctx, recv_ctx, sock_ctx->client_ip, &recv_ctx->push_req, NULL, NULL);

	return iovec_push_req(fep_tcp_ctx, &recv_ctx->push_req);
}

void stp_snd_to_peer(const char *peer_addr, tcp_ctx_t *peer_tcp_ctx, httpc_ctx_t *recv_ctx)
{
	http_stat_inc(0, 0, HTTP_DEST_N_AVAIL);		/* stat increase */

	recv_ctx->user_ctx.head.hopped_cnt++;		/* increase hop */
	set_iovec(peer_tcp_ctx, recv_ctx, peer_addr, &recv_ctx->push_req, NULL, NULL);

	return iovec_push_req(peer_tcp_ctx, &recv_ctx->push_req);
}

void free_ctx_with_httpc_ctx(httpc_ctx_t *httpc_ctx)
{
	int thrd_idx = httpc_ctx->thrd_idx;
	int ctx_idx = httpc_ctx->ctx_idx;

	clear_and_free_ctx(httpc_ctx);

	if (Free_CtxId(thrd_idx, ctx_idx) < 0) {
		APPLOG(APPLOG_ERR, "(%s) fail to free ctx", __func__);
	}
}

void send_response_to_fep(httpc_ctx_t *httpc_ctx)
{
	tcp_ctx_t *fep_tcp_ctx = &MAIN_CTX.fep_tx_thrd;

	set_iovec(fep_tcp_ctx, httpc_ctx, httpc_ctx->resp_client_ip, &httpc_ctx->push_req, free_ctx_with_httpc_ctx, httpc_ctx);
	
}

void send_to_peerlb(sock_ctx_t *sock_ctx, httpc_ctx_t *recv_ctx)
{
    main_ctx_t *main_ctx = (main_ctx_t *)sock_ctx->main_ctx;
    tcp_ctx_t *fep_tcp_ctx = &main_ctx->fep_tx_thrd;
    tcp_ctx_t *peer_tcp_ctx = &main_ctx->peer_tx_thrd;

	int peer_cnt = config_setting_length(peer_tcp_ctx->peer_list);

	if (recv_ctx->user_ctx.head.hopped_cnt > peer_cnt) 
		return stp_err_to_fep(sock_ctx, fep_tcp_ctx, recv_ctx); /* send err to fep */

	config_setting_t *list = config_setting_get_elem(peer_tcp_ctx->peer_list, recv_ctx->user_ctx.head.hopped_cnt);
	const char *peer_addr = config_setting_get_string(list);
	sock_ctx_t *target_sock_ctx = search_node_by_ip(peer_tcp_ctx, peer_addr);
	if (target_sock_ctx == NULL || target_sock_ctx->connected != 1) 
		return stp_err_to_fep(sock_ctx, fep_tcp_ctx, recv_ctx); /* send err to fep */

	return stp_snd_to_peer(peer_addr, peer_tcp_ctx, recv_ctx); /* send relay to peer */
}

void packet_process_res(sock_ctx_t *sock_ctx, char *process_ptr, size_t processed_len)
{
	// if sock recv 10, process 3 ==> move remain 7 byte to front
	memmove(sock_ctx->buff, process_ptr, sock_ctx->rcv_len - (sock_ctx->rcv_len - processed_len));
	sock_ctx->rcv_len = sock_ctx->rcv_len - processed_len;
	return;
}

void check_and_send(sock_ctx_t *sock_ctx)
{
	httpc_ctx_t *recv_ctx = NULL;

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

	if ((recv_ctx = get_assembled_ctx(process_ptr)) == NULL) {
		// TODO!!! it means blocked, all drain ???
		APPLOG(APPLOG_ERR, "cant process packet, will just dropped");
		return packet_process_res(sock_ctx, process_ptr, processed_len);
	}

	process_ptr += AHIF_TCP_MSG_LEN(head);
	processed_len += AHIF_TCP_MSG_LEN(head);

	conn_list_t *HTTPC_CONN = 0;
	if ((HTTPC_CONN = find_packet_index(recv_ctx->user_ctx.head.destHost, LSMODE_LS)) == NULL) {
		// TODO can't process (peer send or send err response)
		send_to_peerlb(sock_ctx, recv_ctx);
	} else {
		send_to_worker(HTTPC_CONN, recv_ctx, sock_ctx->client_ip);
	}
	goto KEEP_PROCESS;
}

void httpc_lb_buff_readcb(struct bufferevent *bev, void *arg)
{
	sock_ctx_t *sock_ctx = (sock_ctx_t *)arg;
	ssize_t rcv_len = bufferevent_read(bev, 
			sock_ctx->buff + sock_ctx->rcv_len, 
			MAX_RCV_BUFF_LEN - sock_ctx->rcv_len);

	// TODO !!! check strerror() & if critical, call relese_conn()
	if (rcv_len <= 0)
		return;
	else
		sock_ctx->rcv_len += rcv_len;

	return check_and_send(sock_ctx);
}

void load_lb_config(client_conf_t *cli_conf, lb_global_t *lb_conf)
{
	config_setting_t *lb_config = cli_conf->lb_config;

	if (config_setting_lookup_int(lb_config, "rxonly_port", &lb_conf->rxonly_port) == CONFIG_FALSE) {
		APPLOG(APPLOG_ERR, "lb_config.fail to get rxonly_port");
		exit(0);
	} else {
		APPLOG(APPLOG_ERR, "lb_config.rxonly_port = %d", lb_conf->rxonly_port);
	}
	if (config_setting_lookup_int(lb_config, "txonly_port", &lb_conf->txonly_port) == CONFIG_FALSE) {
		APPLOG(APPLOG_ERR, "lb_config.fail to get txonly_port");
		exit(0);
	} else {
		APPLOG(APPLOG_ERR, "lb_config.txonly_port = %d", lb_conf->txonly_port);
	}
	if (config_setting_lookup_int(lb_config, "bundle_bytes", &lb_conf->bundle_bytes) == CONFIG_FALSE) {
		APPLOG(APPLOG_ERR, "lb_config.fail to get bundle_bytes");
		exit(0);
	} else {
		APPLOG(APPLOG_ERR, "lb_config.bundle_bytes = %d", lb_conf->bundle_bytes);
	}
	if (config_setting_lookup_int(lb_config, "bundle_count", &lb_conf->bundle_count) == CONFIG_FALSE) {
		APPLOG(APPLOG_ERR, "lb_config.fail to get bundle_count");
		exit(0);
	} else {
		APPLOG(APPLOG_ERR, "lb_config.bundle_count = %d", lb_conf->bundle_count);
	}
	if (config_setting_lookup_int(lb_config, "flush_tmval", &lb_conf->flush_tmval) == CONFIG_FALSE) {
		APPLOG(APPLOG_ERR, "lb_config.fail to get flush_tmval");
		exit(0);
	} else {
		APPLOG(APPLOG_ERR, "lb_config.flush_tmval = %d", lb_conf->flush_tmval);
	}

    config_setting_t *setting = config_setting_get_member(lb_config, "peer_list");

    if (setting == NULL) {
		APPLOG(APPLOG_ERR, "lb_config.fail to get peer_list");
		exit(0);
    } else {
		lb_conf->peer_list = setting;
		int peer_list_cnt = config_setting_length(setting);
		for (int i = 0; i < peer_list_cnt; i++) {
			config_setting_t *list = config_setting_get_elem(setting, i);
			APPLOG(APPLOG_ERR, "lb_config.peer_list (%2d)[%s]", i, config_setting_get_string(list));
		}
	}
}

void attach_lb_thread(lb_global_t *lb_conf, main_ctx_t *main_ctx)
{

    /* rx thread ctx */
    main_ctx->fep_rx_thrd.svr_type = TT_RX_ONLY;
    main_ctx->fep_rx_thrd.listen_port = lb_conf->rxonly_port;
    main_ctx->fep_rx_thrd.flush_tmval = lb_conf->flush_tmval;
    main_ctx->fep_rx_thrd.main_ctx = main_ctx;

    /* tx thread ctx */
    main_ctx->fep_tx_thrd.svr_type = TT_TX_ONLY;
    main_ctx->fep_tx_thrd.listen_port = lb_conf->txonly_port;
    main_ctx->fep_tx_thrd.flush_tmval = lb_conf->flush_tmval;
    main_ctx->fep_tx_thrd.main_ctx = main_ctx;

    /* peer send thread ctx */
    main_ctx->peer_tx_thrd.peer_list = lb_conf->peer_list;
    main_ctx->peer_tx_thrd.peer_listen_port = lb_conf->rxonly_port;
    main_ctx->peer_tx_thrd.flush_tmval = lb_conf->flush_tmval;
    main_ctx->peer_tx_thrd.main_ctx = main_ctx;

    /* create rx thread */
    if (pthread_create(&main_ctx->fep_rx_thrd.my_thread_id, NULL, &fep_conn_thread, &main_ctx->fep_rx_thrd) != 0) {
        APPLOG(APPLOG_ERR, "fail to create thread\n");
        exit(0);
    } else {
        pthread_detach(main_ctx->fep_rx_thrd.my_thread_id);
    }

    /* create tx thread */
    if (pthread_create(&main_ctx->fep_tx_thrd.my_thread_id, NULL, &fep_conn_thread, &main_ctx->fep_tx_thrd) != 0) {
        APPLOG(APPLOG_ERR, "fail to create thread\n");
        exit(0);
    } else {
        pthread_detach(main_ctx->fep_tx_thrd.my_thread_id);
    }

    /* peer tx thread */
    if (pthread_create(&main_ctx->peer_tx_thrd.my_thread_id, NULL, &fep_peer_thread, &main_ctx->peer_tx_thrd) != 0) {
        APPLOG(APPLOG_ERR, "fail to create thread\n");
        exit(0);
    } else {
        pthread_detach(main_ctx->peer_tx_thrd.my_thread_id);
    }
}


int create_lb_thread()
{
	load_lb_config(&CLIENT_CONF, &LB_CONF);

	attach_lb_thread(&LB_CONF, &MAIN_CTX);

	return 0;
}
