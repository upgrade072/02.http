#include <client.h>

extern client_conf_t CLIENT_CONF;	/* sysconfig from config.c */
extern thrd_context_t THRD_WORKER[MAX_THRD_NUM];
extern int THREAD_NO[MAX_THRD_NUM];
extern conn_list_t CONN_LIST[MAX_SVR_NUM];
extern pthread_mutex_t GET_INIT_CTX_LOCK;

lb_global_t LB_CONF;	/* lb config */
lb_ctx_t LB_CTX;	/* lb connection context */

httpc_ctx_t *get_null_recv_ctx(tcp_ctx_t *tcp_ctx)
{
	httpc_ctx_t *rcv_buff_ctx = (httpc_ctx_t *)tcp_ctx->httpcs_ctx_buff;

	for (int i = 0; i < tcp_ctx->context_num; i++) {
		httpc_ctx_t *recv_ctx = &rcv_buff_ctx[i];
		if (recv_ctx->occupied == 0) {
			memset(recv_ctx, 0x00, sizeof(httpc_ctx_t));
			recv_ctx->occupied = 1;
			recv_ctx->fep_tag = tcp_ctx->fep_tag;
			return recv_ctx;
		}
	}
	return NULL;
}

httpc_ctx_t *get_assembled_ctx(tcp_ctx_t *tcp_ctx, char *ptr)
{
	httpc_ctx_t *recv_ctx = NULL;
	AhifHttpCSMsgHeadType *head = (AhifHttpCSMsgHeadType *)ptr;

	char *vheader = ptr + sizeof(AhifHttpCSMsgHeadType);
	int vheaderCnt = head->vheaderCnt;

	char *data = ptr + sizeof(AhifHttpCSMsgHeadType) + (sizeof(hdr_relay) * vheaderCnt);
	int dataLen = head->queryLen + head->bodyLen;

	if((recv_ctx = get_null_recv_ctx(tcp_ctx)) == NULL)
		return NULL;

	memcpy(&recv_ctx->user_ctx.head, ptr, sizeof(AhifHttpCSMsgHeadType));
	memcpy(&recv_ctx->user_ctx.vheader, vheader, (sizeof(hdr_relay) * vheaderCnt));
	memcpy(&recv_ctx->user_ctx.data, data, dataLen);

	return recv_ctx;
}

void send_to_worker(tcp_ctx_t *tcp_ctx, conn_list_t *httpc_conn, httpc_ctx_t *recv_ctx)
{
	httpc_ctx_t *httpc_ctx = NULL;
	intl_req_t intl_req = {0,};
	tcp_ctx_t *fep_tcp_ctx = NULL; // if error

	int thrd_idx = httpc_conn->thrd_index;
	int sess_idx = httpc_conn->session_index;
	int session_id = httpc_conn->session_id;

	pthread_mutex_lock(&GET_INIT_CTX_LOCK);
	int ctx_idx = Get_CtxId(thrd_idx);
	pthread_mutex_unlock(&GET_INIT_CTX_LOCK);

	if (ctx_idx < 0) {
		tcp_ctx->tcp_stat.ctx_assign_fail++;
		APPLOG(APPLOG_DETAIL, "%s() assign context fail in worker [%d]!", __func__, thrd_idx);
		goto STW_ERR;
	}
	if ((httpc_ctx = get_context(thrd_idx, ctx_idx, 0)) == NULL) {
		tcp_ctx->tcp_stat.ctx_assign_fail++;
		APPLOG(APPLOG_DETAIL, "%s() get context fail in worker [%d]!", __func__, thrd_idx);
		goto STW_ERR;
	}
	// TODO!!! maybe memset context ... or not
	//
	//
	httpc_ctx->recv_time_index = THRD_WORKER[thrd_idx].time_index;
	save_session_info(httpc_ctx, thrd_idx, sess_idx, session_id, ctx_idx, httpc_conn);
	httpc_ctx->fep_tag = recv_ctx->fep_tag;
	httpc_ctx->occupied = 1; /* after time set */

	memcpy(&httpc_ctx->user_ctx.head, &recv_ctx->user_ctx.head, AHIF_HTTPCS_MSG_HEAD_LEN);
	memcpy(&httpc_ctx->user_ctx.vheader, &recv_ctx->user_ctx.vheader, sizeof(hdr_relay) * recv_ctx->user_ctx.head.vheaderCnt);
#if 0
	memcpy(&httpc_ctx->user_ctx.body, &recv_ctx->user_ctx.body, recv_ctx->user_ctx.head.bodyLen);
#else
	memcpy(&httpc_ctx->user_ctx.data, &recv_ctx->user_ctx.data, 
			recv_ctx->user_ctx.head.queryLen + recv_ctx->user_ctx.head.bodyLen);
#endif

	httpc_ctx->user_ctx.head.mtype = MTYPE_HTTP2_RESPONSE_HTTPC_TO_AHIF;	// in advance set

	set_intl_req_msg(&intl_req, thrd_idx, ctx_idx, sess_idx, session_id, 0, HTTP_INTL_SND_REQ);

	if (msgsnd(THRD_WORKER[thrd_idx].msg_id, &intl_req, sizeof(intl_req) - sizeof(long), 0) == -1) {
		APPLOG(APPLOG_ERR, "%s() internal msgsnd to worker [%d] failed!!!", __func__, thrd_idx);
		clear_and_free_ctx(httpc_ctx);
		Free_CtxId(thrd_idx, ctx_idx);
	}

/* SUCCESS RETURN */
	recv_ctx->occupied = 0;
	return;

/* ERROR RETURN */
STW_ERR:
	fep_tcp_ctx = search_dest_via_tag(recv_ctx, LB_CTX.fep_tx_thrd);
	stp_err_to_fep(fep_tcp_ctx, recv_ctx); /* send err to fep */
	return;
}

void set_iovec(tcp_ctx_t *dest_tcp_ctx, httpc_ctx_t *recv_ctx, const char *dest_ip, iovec_item_t *push_req, void (*cbfunc)(), void *cbarg)
{
	AhifHttpCSMsgType *user_ctx = &recv_ctx->user_ctx;  // we send this [ahif packet]
    memset(push_req, 0x00, sizeof(iovec_item_t));		// this indicate header / vheader / body
	int item_cnt = 0;									// full count = 3 (hd, vhd, bdy) , or err count = 1 (only hd)
	int total_bytes = 0;								// full packet size

    push_req->sender_tcp_ctx = dest_tcp_ctx;			// fep response or peer lb send
	if (dest_ip != NULL)
		sprintf(push_req->dest_ip, "%s", dest_ip);		// dest of this packet

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
#if 0
		push_req->iov[item_cnt].iov_base = user_ctx->body;
		push_req->iov[item_cnt].iov_len = user_ctx->head.bodyLen;
#else
		// response only have body (not have query)
		push_req->iov[item_cnt].iov_base = user_ctx->data;
		push_req->iov[item_cnt].iov_len = user_ctx->head.bodyLen;
#endif
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
	sock_ctx_t *sock_ctx = get_last_conn_sock(tcp_ctx);

    if (sock_ctx == NULL) {
		if (push_item->unset_cb_func != NULL)
			push_item->unset_cb_func(push_item->unset_cb_arg);
		if (push_item->ctx_unset_ptr != NULL)
			*push_item->ctx_unset_ptr = 0;
        APPLOG(APPLOG_ERR, "%s() fail to find ahifSockCtx!", __func__);
        return;
    } else {
        create_write_item(&sock_ctx->push_items, push_item);
    }

    write_list_t *write_list = &sock_ctx->push_items;

	/* bundle packet by config ==> send by once */
    if (write_list->item_cnt >= LB_CONF.bundle_count || write_list->item_bytes >= LB_CONF.bundle_bytes) {
        ssize_t nwritten = push_write_item(sock_ctx->client_fd, write_list, INT_MAX, INT_MAX);
        if (nwritten > 0) {
            unset_pushed_item(write_list, nwritten, __func__);
			/* stat */
			tcp_ctx->tcp_stat.send_bytes += nwritten;
#if 0 // forget just release
		} else if (errno != EINTR && errno != EAGAIN) {
#else
		} else if (nwritten == 0) {
		} else { /* 0 < */
#endif
			APPLOG(APPLOG_ERR, "%s() fep sock error!!! %d : %s\n", __func__, errno, strerror(errno));
			release_conncb(sock_ctx);
		}
    }
}

void iovec_push_req(tcp_ctx_t *dest_tcp_ctx, iovec_item_t *push_req)
{
    struct event_base *peer_evbase = dest_tcp_ctx->evbase;

	if (push_req->iov_cnt <= 0 || push_req->remain_bytes <= 0) {
		APPLOG(APPLOG_ERR, "%s() push req item or bytes <= 0!", __func__);
		return;
	}

    if (event_base_once(peer_evbase, -1, EV_TIMEOUT, push_callback, push_req, NULL) < 0) {
        APPLOG(APPLOG_ERR, "%s() fail to add callback to dest evbase!", __func__);
    }
}

void stp_err_to_fep(tcp_ctx_t *fep_tcp_ctx, httpc_ctx_t *recv_ctx)
{
	http_stat_inc(0, 0, HTTP_DEST_N_AVAIL);		/* stat increase */

	if (fep_tcp_ctx == NULL || recv_ctx == NULL) {
		APPLOG(APPLOG_ERR, "%s() fep | httpc ctx null, can't do anything!", __func__);
		return;
	}

	recv_ctx->user_ctx.head.mtype = MTYPE_HTTP2_RESPONSE_HTTPC_TO_AHIF;
	recv_ctx->user_ctx.head.respCode = HTTP_RESP_CODE_NOT_FOUND;
	
	/* for error debuging */
	log_pkt_httpc_error_reply(recv_ctx, -HTTP_RESP_CODE_NOT_FOUND);

	/* response only header */
	recv_ctx->user_ctx.head.vheaderCnt = 0;
	recv_ctx->user_ctx.head.bodyLen = 0;
	recv_ctx->user_ctx.head.queryLen = 0;

	/* response to origin fep */
	//set_iovec(fep_tcp_ctx, recv_ctx, recv_ctx->user_ctx.head.fep_origin_addr, &recv_ctx->push_req, NULL, NULL);
	set_iovec(fep_tcp_ctx, recv_ctx, NULL, &recv_ctx->push_req, NULL, NULL);

	return iovec_push_req(fep_tcp_ctx, &recv_ctx->push_req);
}

//void stp_snd_to_peer(const char *peer_addr, tcp_ctx_t *peer_tcp_ctx, httpc_ctx_t *recv_ctx)
void stp_snd_to_peer(tcp_ctx_t *peer_tcp_ctx, httpc_ctx_t *recv_ctx)
{
	http_stat_inc(0, 0, HTTP_DEST_N_AVAIL);		/* stat increase */

	recv_ctx->user_ctx.head.hopped_cnt = 1;		/* hopped */
	//set_iovec(peer_tcp_ctx, recv_ctx, peer_addr, &recv_ctx->push_req, NULL, NULL);
	set_iovec(peer_tcp_ctx, recv_ctx, NULL, &recv_ctx->push_req, NULL, NULL);

	return iovec_push_req(peer_tcp_ctx, &recv_ctx->push_req);
}

void free_ctx_with_httpc_ctx(httpc_ctx_t *httpc_ctx)
{
	int thrd_idx = httpc_ctx->thrd_idx;
	int ctx_idx = httpc_ctx->ctx_idx;

	clear_and_free_ctx(httpc_ctx);
	Free_CtxId(thrd_idx, ctx_idx);
}

tcp_ctx_t *search_dest_via_tag(httpc_ctx_t *httpc_ctx, GNode *root_node)
{
	GNode *nth_thread = g_node_nth_child(root_node, httpc_ctx->fep_tag);
	if (nth_thread == NULL) {
		return NULL;
	} else {
		tcp_ctx_t *dest_tcp_ctx = (tcp_ctx_t *)nth_thread->data;
		return dest_tcp_ctx;
	}
}

void send_response_to_fep(httpc_ctx_t *httpc_ctx)
{
	// TODO!!!! check connect is exist or not !!!
	tcp_ctx_t *fep_tcp_ctx = search_dest_via_tag(httpc_ctx, LB_CTX.fep_tx_thrd);

	if (fep_tcp_ctx == NULL) {
		APPLOG(APPLOG_ERR, "%s() fail to search origin fep (%d)!!!", __func__, httpc_ctx->fep_tag);
		return;
	}

	// this (worker) ctx will push to tcp queue, don't timeout this
	httpc_ctx->tcp_wait = 1;

	set_iovec(fep_tcp_ctx, httpc_ctx, NULL, &httpc_ctx->push_req, free_ctx_with_httpc_ctx, httpc_ctx);
	
	return iovec_push_req(fep_tcp_ctx, &httpc_ctx->push_req);
}

void send_to_peerlb(sock_ctx_t *sock_ctx, httpc_ctx_t *recv_ctx)
{
    tcp_ctx_t *fep_tcp_ctx = search_dest_via_tag(recv_ctx, LB_CTX.fep_tx_thrd);
    tcp_ctx_t *peer_tcp_ctx = search_dest_via_tag(recv_ctx, LB_CTX.peer_tx_thrd);

	if (recv_ctx->user_ctx.head.hopped_cnt != 0 ||
			peer_tcp_ctx == NULL) {
		APPLOG(APPLOG_DEBUG, "%s() hopped cnt exist or peer ctx NULL!", __func__);
		return stp_err_to_fep(fep_tcp_ctx, recv_ctx); /* send err to fep */
	}

	//return stp_snd_to_peer(LB_CONF.peer_lb_address, peer_tcp_ctx, recv_ctx); /* send relay to peer */
	return stp_snd_to_peer(peer_tcp_ctx, recv_ctx); /* send relay to peer */
}

void send_to_remote(sock_ctx_t *sock_ctx, httpc_ctx_t *recv_ctx)
{
	conn_list_t *httpc_conn = 0;
	tcp_ctx_t *tcp_ctx = (tcp_ctx_t *)sock_ctx->tcp_ctx;

	/* save fep origin address */
	if (recv_ctx->user_ctx.head.hopped_cnt == 0) 
		sprintf(recv_ctx->user_ctx.head.fep_origin_addr, "%s", sock_ctx->client_ip);

#if 0
	/* our config lib can't use www.aaa.com, modified name is www_aaa_com */
	desthost_case_sensitive(recv_ctx);
#endif
    if (CLIENT_CONF.debug_mode == 1) {
        APPLOG(APPLOG_ERR, "{{{DBG}}} searchDest try ahifPkt ahifCid=(%d) api=[%s] type=(%s) host=(%s) ip=(%s) port=(%d)",
                recv_ctx->user_ctx.head.ahifCid,
                recv_ctx->user_ctx.head.rsrcUri,
                recv_ctx->user_ctx.head.destType,
                recv_ctx->user_ctx.head.destHost,
                recv_ctx->user_ctx.head.destIp,
                recv_ctx->user_ctx.head.destPort);
    }

	if ((httpc_conn = find_packet_index(&tcp_ctx->root_select, &recv_ctx->user_ctx.head)) == NULL) {

        /* something wrong */
        trig_refresh_select_node(&CLIENT_CONF);

		if (CLIENT_CONF.debug_mode == 1) {
			APPLOG(APPLOG_ERR, "{{{DBG}}} searchDest fail ahifPkt ahifCid=(%d) api=[%s] type=(%s) host=(%s) ip=(%s) port=(%d)",
					recv_ctx->user_ctx.head.ahifCid,
					recv_ctx->user_ctx.head.rsrcUri,
					recv_ctx->user_ctx.head.destType,
					recv_ctx->user_ctx.head.destHost,
					recv_ctx->user_ctx.head.destIp,
					recv_ctx->user_ctx.head.destPort);
		}
		tcp_ctx->tcp_stat.send_to_peer++;
		send_to_peerlb(sock_ctx, recv_ctx);
	} else {
		tcp_ctx->tcp_stat.send_to_fep++;
		send_to_worker(tcp_ctx, httpc_conn, recv_ctx);
	}
}

void heartbeat_process(httpc_ctx_t *recv_ctx, tcp_ctx_t *tcp_ctx, sock_ctx_t *sock_ctx)
{
	time(&sock_ctx->last_hb_recv_time);
	APPLOG(APPLOG_DETAIL, "heartbeat receive from fep(%d) svc(%s) (%s:%d)", 
			tcp_ctx->fep_tag, svc_type_to_str(tcp_ctx->svc_type), sock_ctx->client_ip, sock_ctx->client_port);

	clear_and_free_ctx(recv_ctx);
}

void check_and_send(tcp_ctx_t *tcp_ctx, sock_ctx_t *sock_ctx)
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

	if (strncmp(process_ptr, AHIF_MAGIC_BYTE, AHIF_MAGIC_BYTE_LEN)) {
		APPLOG(APPLOG_ERR, "%s() ahif rcv pkt wrong, it start with %8s!", __func__, process_ptr);
		release_conncb(sock_ctx);
		return;
	}

	if (sock_ctx->rcv_len < (processed_len + AHIF_TCP_MSG_LEN(head))) 
		return packet_process_res(sock_ctx, process_ptr, processed_len);

	if ((recv_ctx = get_assembled_ctx(tcp_ctx, process_ptr)) == NULL) {
		// TODO!!! it means blocked, all drain ???
		APPLOG(APPLOG_ERR, "%s() cant process packet, will just dropped", __func__);
		return packet_process_res(sock_ctx, process_ptr, processed_len);
	} else {
		tcp_ctx->tcp_stat.tps ++;
	}

	process_ptr += AHIF_TCP_MSG_LEN(head);
	processed_len += AHIF_TCP_MSG_LEN(head);

	if (recv_ctx->user_ctx.head.mtype == MTYPE_HTTP2_AHIF_CONN_CHECK) {
		heartbeat_process(recv_ctx, tcp_ctx, sock_ctx);
	} else {
		// for log stat
		tcp_ctx->tcp_stat.send_to_remote_called++;
		send_to_remote(sock_ctx, recv_ctx);
		tcp_ctx->tcp_stat.send_to_remote_success++;
	}

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
#if 0
		if (errno != EINTR && errno != EAGAIN) {
#else
		if (errno != EINTR) {
#endif
			APPLOG(APPLOG_ERR, "%s() fep sock error! %d : %s\n", __func__, errno, strerror(errno));
			release_conncb(sock_ctx);
			return;
		}
	} else {
		sock_ctx->rcv_len += rcv_len;
		/* stat */
		tcp_ctx->tcp_stat.recv_bytes += rcv_len;
	}

	return check_and_send(tcp_ctx, sock_ctx);
}

void load_lb_config(client_conf_t *cli_conf, lb_global_t *lb_conf)
{
	config_setting_t *lb_config = cli_conf->lb_config;
	config_setting_t *setting = NULL;

	/* check fep / peer config list */
	setting = lb_conf->cf_fep_rx_listen_port = config_setting_get_member(lb_config, "fep_rx_listen_port");
	if (setting == NULL) {
		APPLOG(APPLOG_ERR, "{{{CFG}}} fail to get lb_config.fep_rx_listen_port!");
		exit(0);
	}
	setting = lb_conf->cf_fep_tx_listen_port = config_setting_get_member(lb_config, "fep_tx_listen_port");
	if (setting == NULL) {
		APPLOG(APPLOG_ERR, "{{{CFG}}} fail to get lb_config.fep_tx_listen_port!");
		exit(0);
	}
	setting = lb_conf->cf_peer_listen_port = config_setting_get_member(lb_config, "peer_listen_port");
	if (setting == NULL) {
		APPLOG(APPLOG_ERR, "{{{CFG}}} fail to get lb_config.peer_listen_port!");
		exit(0);
	}
	setting = lb_conf->cf_peer_connect_port = config_setting_get_member(lb_config, "peer_connect_port");
	if (setting == NULL) {
		APPLOG(APPLOG_ERR, "{{{CFG}}} fail to get lb_config.peer_connect_port!");
		exit(0);
	}
	lb_conf->peer_lb_address = NULL;
	if (config_setting_lookup_string (lb_config, "peer_lb_address", &lb_conf->peer_lb_address) == CONFIG_FALSE) {
		APPLOG(APPLOG_ERR, "{{{CFG}}} fail to get lb_config.peer_lb_address!");
		exit(0);
	}
	/* check port num pair match, a == b == c == d */
	if (config_setting_length(lb_conf->cf_fep_rx_listen_port) ==
		config_setting_length(lb_conf->cf_fep_tx_listen_port) &&
		config_setting_length(lb_conf->cf_fep_tx_listen_port) ==
		config_setting_length(lb_conf->cf_peer_listen_port) &&
		config_setting_length(lb_conf->cf_peer_listen_port) ==
		config_setting_length(lb_conf->cf_peer_connect_port)) {
		printf_config_list_int("fep_rx_listen_port", lb_conf->cf_fep_rx_listen_port);
		printf_config_list_int("fep_tx_listen_port", lb_conf->cf_fep_tx_listen_port);
		printf_config_list_int("peer_listen_port", lb_conf->cf_peer_listen_port);
		printf_config_list_int("peer_connect_port", lb_conf->cf_peer_connect_port);
		APPLOG(APPLOG_ERR, "{{{CFG}}} peer_lb_address: %s", lb_conf->peer_lb_address);
	} else {
		APPLOG(APPLOG_ERR, "{{{CFG}}} fep tx|rx port num & peer connect|listen port num not match!");
		exit(0);
	}
	/* check fep num */
	lb_conf->total_fep_num = config_setting_length(lb_conf->cf_fep_rx_listen_port);
	if (lb_conf->total_fep_num >= MAX_THRD_NUM) {
		APPLOG(APPLOG_ERR, "{{{CFG}}} total_fep_num(%d) exceed max_thrd_num(%d)!",
				lb_conf->total_fep_num, MAX_THRD_NUM);
	}

	/* get context num for fep */
	if (config_setting_lookup_int(lb_config, "context_num", &lb_conf->context_num) == CONFIG_FALSE) {
		APPLOG(APPLOG_ERR, "{{{CFG}}} lb_config.fail to get context_num!");
		exit(0);
	} else {
		APPLOG(APPLOG_ERR, "{{{CFG}}} lb_config.context_num = %d", lb_conf->context_num);
	}

	if (config_setting_lookup_int(lb_config, "bundle_bytes", &lb_conf->bundle_bytes) == CONFIG_FALSE) {
		APPLOG(APPLOG_ERR, "{{{CFG}}} lb_config.fail to get bundle_bytes!");
		exit(0);
	} else {
		APPLOG(APPLOG_ERR, "{{{CFG}}} lb_config.bundle_bytes = %d", lb_conf->bundle_bytes);
	}
	if (config_setting_lookup_int(lb_config, "bundle_count", &lb_conf->bundle_count) == CONFIG_FALSE) {
		APPLOG(APPLOG_ERR, "{{{CFG}}} lb_config.fail to get bundle_count!");
		exit(0);
	} else {
		APPLOG(APPLOG_ERR, "{{{CFG}}} lb_config.bundle_count = %d", lb_conf->bundle_count);
	}
	if (config_setting_lookup_int(lb_config, "flush_tmval", &lb_conf->flush_tmval) == CONFIG_FALSE) {
		APPLOG(APPLOG_ERR, "{{{CFG}}} lb_config.fail to get flush_tmval!");
		exit(0);
	} else {
		APPLOG(APPLOG_ERR, "{{{CFG}}} lb_config.flush_tmval = %d", lb_conf->flush_tmval);
	}
	if (config_setting_lookup_int(lb_config, "heartbeat_enable", &lb_conf->heartbeat_enable) == CONFIG_FALSE) {
		APPLOG(APPLOG_ERR, "{{{CFG}}} lb_config.fail to get heartbeat_enable!");
		exit(0);
	} else {
		APPLOG(APPLOG_ERR, "{{{CFG}}} lb_config.heartbeat_enable = %d", lb_conf->heartbeat_enable);
	}

}

int get_httpcs_buff_used(tcp_ctx_t *tcp_ctx)
{
	if (tcp_ctx == NULL)
		return 0;
	if (tcp_ctx->buff_exist != 1)
		return 0;

	httpc_ctx_t *rcv_buff_ctx = (httpc_ctx_t *)tcp_ctx->httpcs_ctx_buff;
	int used = 0;

	for (int i = 0; i < tcp_ctx->context_num; i++) {
		httpc_ctx_t *recv_ctx = &rcv_buff_ctx[i];
		if (recv_ctx->occupied != 0) 
			used++;
	}

	return used;
}

void clear_context_stat(tcp_ctx_t *tcp_ctx)
{
	memset(&tcp_ctx->tcp_stat, 0x00, sizeof(tcp_stat_t));
}

void fep_stat_print(evutil_socket_t fd, short what, void *arg)
{
	if (CLIENT_CONF.debug_mode != 1)
		return;

	char fep_read[1024] = {0,};
	char fep_write[1024] = {0,};
	char peer_read[1024] = {0,};
	char peer_write[1024] = {0,};

	for (int i = 0; i < LB_CONF.total_fep_num; i++) {
		GNode *nth_fep_rx = g_node_nth_child(LB_CTX.fep_rx_thrd, i);
		GNode *nth_fep_tx = g_node_nth_child(LB_CTX.fep_tx_thrd, i);
		GNode *nth_peer_rx = g_node_nth_child(LB_CTX.peer_rx_thrd, i);
		GNode *nth_peer_tx = g_node_nth_child(LB_CTX.peer_tx_thrd, i);

		tcp_ctx_t *fep_rx = (nth_fep_rx == NULL ? NULL : (tcp_ctx_t *)nth_fep_rx->data);
		tcp_ctx_t *fep_tx = (nth_fep_rx == NULL ? NULL : (tcp_ctx_t *)nth_fep_tx->data);
		tcp_ctx_t *peer_rx = (nth_peer_rx == NULL ? NULL : (tcp_ctx_t *)nth_peer_rx->data);
		tcp_ctx_t *peer_tx = (nth_peer_tx == NULL ? NULL : (tcp_ctx_t *)nth_peer_tx->data);

		if (fep_rx == NULL || fep_tx == NULL)
			continue;

		int fep_rx_used = get_httpcs_buff_used(fep_rx);
		int peer_rx_used = (peer_rx == NULL ? 0 : get_httpcs_buff_used(peer_rx));

		APPLOG(APPLOG_ERR, "{{{DBG}}} FEP [%2d] CTX [fep_rx %05d/%05d peer_rx %05d/%05d] FEP RX [%s] (TPS %d) FEP TX [%s] ( PEER_RX [%s] PEER TX [%s] ), DBG {{{ called[%d] succ[%d] peer[%d] fep[%d] assign fail[%d] }}}",
				i,
				fep_rx_used,
				fep_rx->context_num,
				peer_rx == NULL ? 0 : peer_rx_used,
				peer_rx == NULL ? 0 : peer_rx->context_num,
				measure_print(fep_rx->tcp_stat.recv_bytes, fep_read),
				fep_rx->tcp_stat.tps,
				measure_print(fep_tx->tcp_stat.send_bytes, fep_write),
				peer_rx == NULL ? "N/A" : measure_print(peer_rx->tcp_stat.recv_bytes, peer_read),
				peer_tx == NULL ? "N/A" : measure_print(peer_tx->tcp_stat.send_bytes, peer_write),
				fep_rx->tcp_stat.send_to_remote_called,
				fep_rx->tcp_stat.send_to_remote_success,
				fep_rx->tcp_stat.send_to_peer,
				fep_rx->tcp_stat.send_to_fep,
				fep_rx->tcp_stat.ctx_assign_fail);

		clear_context_stat(fep_rx);
		clear_context_stat(fep_tx);
		if (peer_rx != NULL)
			clear_context_stat(peer_rx);
		if (peer_tx != NULL)
			clear_context_stat(peer_tx);
	}
}

#if 0
void *fep_stat_thread(void *arg)
{
	struct event_base *evbase;
	evbase = event_base_new();

	struct timeval one_sec = {1, 0};
	struct event *ev;
	ev = event_new(evbase, -1, EV_PERSIST, fep_stat_print, NULL);
	event_add(ev, &one_sec);

	/* start loop */
	event_base_loop(evbase, EVLOOP_NO_EXIT_ON_EMPTY);

	/* never reach here */
	event_base_free(evbase);

	return (void *)NULL;
}
#endif

void attach_lb_thread(lb_global_t *lb_conf, lb_ctx_t *lb_ctx)
{
	/* CAUTION!!! ALL UNDER THREAD USE THIS */
	tcp_ctx_t tcp_ctx = {0,};
	tcp_ctx.flush_tmval = lb_conf->flush_tmval;
	tcp_ctx.heartbeat_enable = lb_conf->heartbeat_enable;
	tcp_ctx.lb_ctx = lb_ctx;

	// create root node for thread, create null ctx
	lb_ctx->fep_tx_thrd = new_tcp_ctx(&tcp_ctx);
	lb_ctx->fep_rx_thrd = new_tcp_ctx(&tcp_ctx);
	lb_ctx->peer_rx_thrd = new_tcp_ctx(&tcp_ctx);
	lb_ctx->peer_tx_thrd = new_tcp_ctx(&tcp_ctx);

	/* fep rx thread create */
	for (int i = 0; i < lb_conf->total_fep_num; i++) {
		tcp_ctx.fep_tag = i;
		tcp_ctx.svc_type = TT_RX_ONLY;
		config_setting_t *port = config_setting_get_elem(lb_conf->cf_fep_rx_listen_port, i);
		tcp_ctx.listen_port = config_setting_get_int(port);

		add_tcp_ctx_to_main(&tcp_ctx, lb_ctx->fep_rx_thrd);

		/* create dest selection root */
		GNode *temp_node = g_node_nth_child(lb_ctx->fep_rx_thrd, i);
		tcp_ctx_t *temp_ctx = (tcp_ctx_t *)temp_node->data;
		rebuild_select_node(&temp_ctx->root_select);
	}	
	/* fep tx thread create */
	for (int i = 0; i < lb_conf->total_fep_num; i++) {
		tcp_ctx.fep_tag = i;
		tcp_ctx.svc_type = TT_TX_ONLY;
		config_setting_t *port = config_setting_get_elem(lb_conf->cf_fep_tx_listen_port, i);
		tcp_ctx.listen_port = config_setting_get_int(port);
		add_tcp_ctx_to_main(&tcp_ctx, lb_ctx->fep_tx_thrd);
	}	

	/* peer rx thread create (if lb address exist!) */
	for (int i = 0; strlen(lb_conf->peer_lb_address) && (i < lb_conf->total_fep_num); i++) {
		tcp_ctx.fep_tag = i;
		tcp_ctx.svc_type = TT_PEER_RECV;
		config_setting_t *port = config_setting_get_elem(lb_conf->cf_peer_listen_port, i);
		tcp_ctx.listen_port = config_setting_get_int(port);

		add_tcp_ctx_to_main(&tcp_ctx, lb_ctx->peer_rx_thrd);

		/* create dest selection root */
		GNode *temp_node = g_node_nth_child(lb_ctx->peer_rx_thrd, i);
		tcp_ctx_t *temp_ctx = (tcp_ctx_t *)temp_node->data;
		rebuild_select_node(&temp_ctx->root_select);
	}	
	/* peer tx thread create (if lb address exist!) */
	for (int i = 0; strlen(lb_conf->peer_lb_address) && (i < lb_conf->total_fep_num); i++) {
		tcp_ctx.fep_tag = i;
		tcp_ctx.svc_type = TT_PEER_SEND;
		config_setting_t *port = config_setting_get_elem(lb_conf->cf_peer_connect_port, i);
		tcp_ctx.listen_port = config_setting_get_int(port);
		sprintf(tcp_ctx.peer_ip_addr, "%s", lb_conf->peer_lb_address);
		add_tcp_ctx_to_main(&tcp_ctx, lb_ctx->peer_tx_thrd);
	}

	CREATE_LB_THREAD(lb_ctx->fep_rx_thrd, sizeof(httpc_ctx_t), lb_conf->context_num);
	CREATE_LB_THREAD(lb_ctx->fep_tx_thrd, 0, 0);
	CREATE_LB_THREAD(lb_ctx->peer_rx_thrd, sizeof(httpc_ctx_t), lb_conf->context_num);
	CREATE_LB_THREAD(lb_ctx->peer_tx_thrd, 0, 0);

#if 0 // move to main
	/* for stat print small thread */
	if (CLIENT_CONF.debug_mode == 1) {
		if (pthread_create(&lb_ctx->stat_thrd_id, NULL, &fep_stat_thread, lb_ctx) != 0) {
			APPLOG(APPLOG_ERR, "%s() fail to create thread!!!", __func__);
			exit(0);
		} else {
			pthread_detach(lb_ctx->stat_thrd_id);
		}
	}
#endif
}

void nrfm_send_conn_status_callback(tcp_ctx_t *tcp_ctx)
{
	// only for HTTPS
	return;
}

int create_lb_thread()
{
	load_lb_config(&CLIENT_CONF, &LB_CONF);

	attach_lb_thread(&LB_CONF, &LB_CTX);

	// wait for thread created ((we use thread[evbase]))
	sleep(1);

#if 0 // not by timer-audit refresh, just when mismatch refresh 
	init_refresh_select_node(&LB_CTX);
#endif

	return 0;
}
