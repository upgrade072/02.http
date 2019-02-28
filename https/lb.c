#include <server.h>

extern server_conf SERVER_CONF;   /* sysconfig from config.c */
extern thrd_context THRD_WORKER[MAX_THRD_NUM];

lb_global_t LB_CONF;                /* lb config */
main_ctx_t MAIN_CTX;                /* lb connection context */
#define MAX_LB_CTX_NUM 10240
https_ctx_t LB_RECV_CTX[MAX_LB_CTX_NUM];

https_ctx_t *get_null_recv_ctx()
{
	for (int i = 0; i < MAX_LB_CTX_NUM; i++) {
		https_ctx_t *recv_ctx = &LB_RECV_CTX[i];
		if (recv_ctx->occupied == 0) {
			memset(recv_ctx, 0x00, sizeof(https_ctx_t));
			recv_ctx->occupied = 1;
			return recv_ctx;
		}
	}
	return NULL;
}

https_ctx_t *get_assembled_ctx(char *ptr)
{
    https_ctx_t *recv_ctx = NULL;
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

int send_request_to_fep(https_ctx_t *https_ctx)
{
    tcp_ctx_t *fep_tcp_ctx = &MAIN_CTX.fep_tx_thrd;

    int sock_cnt = return_sock_num(fep_tcp_ctx);
	if (sock_cnt <= 0) 
		return -1;

	int loadshare_turn = fep_tcp_ctx->round_robin_index ++ % sock_cnt;
	sock_ctx_t *sock_ctx = return_nth_sock(fep_tcp_ctx, loadshare_turn);

    set_iovec(fep_tcp_ctx, https_ctx, sock_ctx->client_ip, &https_ctx->push_req, NULL, NULL);

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

	if ((https_ctx = get_context(thrd_index, ctx_id, 1)) == NULL) {
		if ((session_data = get_session(thrd_index, session_index, session_id)) == NULL) 
			http_stat_inc(0, 0, HTTP_STRM_N_FOUND); 
		else
			http_stat_inc(session_data->thrd_index, session_data->list_index, HTTP_STRM_N_FOUND);
		goto STW_RET;
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

void check_and_send(sock_ctx_t *sock_ctx)
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
    
    if ((recv_ctx = get_assembled_ctx(process_ptr)) == NULL) {
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

void load_lb_config(server_conf *svr_conf, lb_global_t *lb_conf)
{
    config_setting_t *lb_config = svr_conf->lb_config;

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
}

int create_lb_thread()
{
	load_lb_config(&SERVER_CONF, &LB_CONF);

	attach_lb_thread(&LB_CONF, &MAIN_CTX);

	return 0;
}
