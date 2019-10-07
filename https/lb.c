#include <server.h>

extern server_conf SERVER_CONF;   /* sysconfig from config.c */
extern thrd_context THRD_WORKER[MAX_THRD_NUM];
extern int nrfmQid;

lb_global_t LB_CONF;            /* lb config */
lb_ctx_t LB_CTX;                /* lb connection context */

https_ctx_t *get_null_recv_ctx(tcp_ctx_t *tcp_ctx)
{
	https_ctx_t *rcv_buff_ctx = (https_ctx_t *)tcp_ctx->httpcs_ctx_buff;

	for (int i = 0; i < tcp_ctx->context_num; i++) {
		https_ctx_t *recv_ctx = &rcv_buff_ctx[i];
		if (recv_ctx->occupied == 0) {
			memset(recv_ctx, 0x00, sizeof(https_ctx_t));
			recv_ctx->occupied = 1;
			recv_ctx->fep_tag = tcp_ctx->fep_tag;
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

#if 0
    char *body = ptr + sizeof(AhifHttpCSMsgHeadType) + (sizeof(hdr_relay) * vheaderCnt);
    int bodyLen = head->bodyLen;

    if((recv_ctx = get_null_recv_ctx(tcp_ctx)) == NULL)
        return NULL;

    memcpy(&recv_ctx->user_ctx.head, ptr, sizeof(AhifHttpCSMsgHeadType));
    memcpy(&recv_ctx->user_ctx.vheader, vheader, (sizeof(hdr_relay) * vheaderCnt));
    memcpy(&recv_ctx->user_ctx.body, body, bodyLen);
#else
    char *data = ptr + sizeof(AhifHttpCSMsgHeadType) + (sizeof(hdr_relay) * vheaderCnt);
    int dataLen = head->queryLen + head->bodyLen;

    if((recv_ctx = get_null_recv_ctx(tcp_ctx)) == NULL)
        return NULL;

    memcpy(&recv_ctx->user_ctx.head, ptr, sizeof(AhifHttpCSMsgHeadType));
    memcpy(&recv_ctx->user_ctx.vheader, vheader, (sizeof(hdr_relay) * vheaderCnt));
    memcpy(&recv_ctx->user_ctx.data, data, dataLen);
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
    if (user_ctx->head.queryLen || user_ctx->head.bodyLen) {
#if 0
        push_req->iov[item_cnt].iov_base = user_ctx->body;
        push_req->iov[item_cnt].iov_len = user_ctx->head.bodyLen;
#else
		// this request include ahif.data [ query | body ], we must send all
        push_req->iov[item_cnt].iov_base = user_ctx->data;
        push_req->iov[item_cnt].iov_len = user_ctx->head.queryLen + user_ctx->head.bodyLen;
#endif
        item_cnt++;
        total_bytes += (user_ctx->head.queryLen + user_ctx->head.bodyLen);
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
	sock_ctx_t *sock_ctx = get_last_conn_sock(tcp_ctx);

    if (sock_ctx == NULL) {
		if (push_item->unset_cb_func != NULL)
			push_item->unset_cb_func(push_item->unset_cb_arg);
		if (push_item->ctx_unset_ptr != NULL)
			*push_item->ctx_unset_ptr = 0;
        return;
    } else {
        create_write_item(&sock_ctx->push_items, push_item);
    }

    write_list_t *write_list = &sock_ctx->push_items;

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
		} else { /* < 0 */
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

tcp_ctx_t *get_loadshare_turn(https_ctx_t *https_ctx)
{
	GNode *root_node = LB_CTX.fep_tx_thrd;
	unsigned int fep_num = g_node_n_children(root_node);
	tcp_ctx_t *root_data = (tcp_ctx_t *)root_node->data;

	if (fep_num == 0 || root_data == NULL) {
	   	return NULL;
	}

	int turn_index = (root_data->round_robin_index[https_ctx->thrd_idx]) % fep_num;

	for (int i = 0; i < fep_num; i++) {
		int loadshare_turn = (turn_index + i) % fep_num;
		GNode *nth_thread = g_node_nth_child(root_node, loadshare_turn);
		if (nth_thread != NULL) {
			tcp_ctx_t *tcp_ctx = (tcp_ctx_t *)nth_thread->data;
			if (tcp_ctx->received_fep_status == HTTP_STA_CAUSE_SYS_ACTIVE) {
				unsigned int sock_num = g_node_n_children(tcp_ctx->root_conn);
				if (sock_num > 0) {
					https_ctx->fep_tag = tcp_ctx->fep_tag;
					root_data->round_robin_index[https_ctx->thrd_idx] = (tcp_ctx->fep_tag + 1);
					return tcp_ctx;
				}
			}
		}
	}

	return NULL;
}

tcp_ctx_t *get_direct_dest(https_ctx_t *https_ctx)
{
	GNode *root_node = LB_CTX.fep_tx_thrd;
	unsigned int fep_num = g_node_n_children(root_node);
	tcp_ctx_t *root_data = (tcp_ctx_t *)root_node->data;

	if (fep_num == 0 || root_data == NULL) {
	   	return NULL;
	}

	for (int i = 0; i < fep_num; i++) {
		GNode *nth_thread = g_node_nth_child(root_node, i);
		if (nth_thread != NULL) {
			tcp_ctx_t *fep_tcp_ctx = (tcp_ctx_t *)nth_thread->data;
			if (fep_tcp_ctx->fep_tag == https_ctx->relay_fep_tag) {
				int sock_num = g_node_n_children(fep_tcp_ctx->root_conn);
				if (sock_num > 0) {
					https_ctx->fep_tag = fep_tcp_ctx->fep_tag;
					return fep_tcp_ctx;
				}
			}
		}
	}

	return NULL;
}

void gb_clean_ctx(https_ctx_t *https_ctx)
{
    https_ctx->user_ctx.head.vheaderCnt = 0;
    memset(https_ctx->user_ctx.vheader, 0x00, sizeof(hdr_relay) * MAX_HDR_RELAY_CNT);
	https_ctx->tcp_wait = 0;
}

void set_callback_tag(https_ctx_t *https_ctx, tcp_ctx_t *fep_tcp_ctx)
{
    if (SERVER_CONF.dr_enabled == 0)
        return;

	if (fep_tcp_ctx->fep_tag < 0 || fep_tcp_ctx->fep_tag >= MAX_PORT_NUM) {
		APPLOG(APPLOG_ERR, "%s() fep_tcp_ctx->fep_tag num wrong [%d]!", __func__, fep_tcp_ctx->fep_tag);
		return;
	} else {
		if (!strcmp(https_ctx->user_ctx.head.scheme, "https")) {
			https_ctx->user_ctx.head.callback_port = SERVER_CONF.callback_port_tls[fep_tcp_ctx->fep_tag];
		} else {
			https_ctx->user_ctx.head.callback_port = SERVER_CONF.callback_port_tcp[fep_tcp_ctx->fep_tag];
		}
		sprintf(https_ctx->user_ctx.head.callback_ip, "%s", SERVER_CONF.callback_ip);
	}
}

int send_request_to_fep(https_ctx_t *https_ctx)
{
	tcp_ctx_t *fep_tcp_ctx = NULL;

	// case 0. if direct relay ctx find direct sock
	if (https_ctx->is_direct_ctx) {
		fep_tcp_ctx = get_direct_dest(https_ctx);
	}
	// case 0-1. if case 0 fail or ...
	// case 1. if loadshare ctx find any of sock
	if (fep_tcp_ctx == NULL) {
		fep_tcp_ctx = get_loadshare_turn(https_ctx);
	}

	if (fep_tcp_ctx == NULL) {
		// TODO !!! count this and log stat
		return -1; // http error response
	} else {
		set_callback_tag(https_ctx, fep_tcp_ctx);
		fep_tcp_ctx->tcp_stat.tps ++;
	}

	// this (worker) ctx will push to tcp queue, don't timeout this
	https_ctx->tcp_wait = 1;

    set_iovec(fep_tcp_ctx, https_ctx, NULL, &https_ctx->push_req, gb_clean_ctx, https_ctx);

    iovec_push_req(fep_tcp_ctx, &https_ctx->push_req);

	return 0;
}

void send_to_worker(tcp_ctx_t *tcp_ctx, https_ctx_t *recv_ctx, int intl_msg_type)
{
	int thrd_index = recv_ctx->user_ctx.head.thrd_index;
	int session_index = recv_ctx->user_ctx.head.session_index;
	int session_id =  recv_ctx->user_ctx.head.session_id;
	int stream_id = recv_ctx->user_ctx.head.stream_id;
	int ctx_id = recv_ctx->user_ctx.head.ctx_id;

	https_ctx_t *https_ctx = NULL;
	http2_session_data *session_data = NULL;

	if ((https_ctx = get_context(thrd_index, ctx_id, 1)) == NULL) {
		tcp_ctx->tcp_stat.ctx_assign_fail++;
		if ((session_data = get_session(thrd_index, session_index, session_id)) == NULL) 
			http_stat_inc(0, 0, HTTP_STRM_N_FOUND); 
		else
			http_stat_inc(session_data->thrd_index, session_data->list_index, HTTP_STRM_N_FOUND);
		goto STW_RET;
	}

	// check have same fep tag
	if (recv_ctx->fep_tag != https_ctx->fep_tag) {
		APPLOG(APPLOG_DETAIL, "%s() fep tag mismatch (ahif recv %d, orig ctx relay:%d tcp:%d) [%s]", 
				__func__, 
				recv_ctx->fep_tag, https_ctx->relay_fep_tag, https_ctx->fep_tag, 
				https_ctx->user_ctx.head.rsrcUri);
	}

	intl_req_t intl_req = {0,};

	/* HTTP_INTL_SND_REQ || HTTP_INTL_OVLD */
	set_intl_req_msg(&intl_req, thrd_index, ctx_id, session_index, session_id, stream_id, intl_msg_type);

	if (intl_msg_type == HTTP_INTL_SND_REQ)
		assign_rcv_ctx_info(https_ctx, &recv_ctx->user_ctx);

	if (msgsnd(THRD_WORKER[thrd_index].msg_id, &intl_req, sizeof(intl_req) - sizeof(long), 0) == -1) {
		APPLOG(APPLOG_ERR, "%s() internal msgsnd to worker [%d] failed!!!", __func__, thrd_index);
		clear_and_free_ctx(https_ctx);
		Free_CtxId(thrd_index, ctx_id);
	}

STW_RET:
	recv_ctx->occupied = 0;
	return;
}

void heartbeat_process(https_ctx_t *recv_ctx, tcp_ctx_t *tcp_ctx, sock_ctx_t *sock_ctx, int staCause)
{
	/* normal hb time save job (in RX sock) */
	time(&sock_ctx->last_hb_recv_time);

	APPLOG(APPLOG_DETAIL, "heartbeat receive from fep(%d) svc(%s) (%s:%d) (fep_status: %s)",
			tcp_ctx->fep_tag, svc_type_to_str(tcp_ctx->svc_type), sock_ctx->client_ip, sock_ctx->client_port,
			staCause == HTTP_STA_CAUSE_SYS_ACTIVE ? "active" :
			staCause == HTTP_STA_CAUSE_SYS_STANDBY ? "standby" :
			staCause == HTTP_STA_CAUSE_NONE ? "none" : "unknown");
	clear_and_free_ctx(recv_ctx);

	/* set active / or standby (to pair TX sock) */
	tcp_ctx->received_fep_status = staCause;
	lb_ctx_t *lb_ctx = (lb_ctx_t *)tcp_ctx->lb_ctx;

	/* find tx thread */
	unsigned int fep_num = g_node_n_children(lb_ctx->fep_tx_thrd);
	for (int i = 0; i < fep_num; i++) {
		GNode *temp_node = g_node_nth_child(lb_ctx->fep_tx_thrd, i);
		tcp_ctx_t *pair_tcp_ctx = (tcp_ctx_t *)temp_node->data;
		/* find tx-pair tcp */
		if (pair_tcp_ctx->fep_tag == tcp_ctx->fep_tag) {
			/* set system status */
			pair_tcp_ctx->received_fep_status = staCause;
			break;
		}
	}
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

	if (strncmp(process_ptr, AHIF_MAGIC_BYTE, AHIF_MAGIC_BYTE_LEN)) {
		APPLOG(APPLOG_ERR, "%s() ahif rcv pkt wrong, it start with %8s\n", __func__, process_ptr);
		release_conncb(sock_ctx);
		return;
	}
    
    if (sock_ctx->rcv_len < (processed_len + AHIF_TCP_MSG_LEN(head)))
        return packet_process_res(sock_ctx, process_ptr, processed_len);
    
    if ((recv_ctx = get_assembled_ctx(tcp_ctx, process_ptr)) == NULL) {
        // TODO!!! it means blocked, all drain ???
        APPLOG(APPLOG_ERR, "%s() cant process packet, will just dropped", __func__);
        return packet_process_res(sock_ctx, process_ptr, processed_len);
    }

    process_ptr += AHIF_TCP_MSG_LEN(head);
    processed_len += AHIF_TCP_MSG_LEN(head);

	if (recv_ctx->user_ctx.head.mtype == MTYPE_HTTP2_AHIF_CONN_CHECK) {
		heartbeat_process(recv_ctx, tcp_ctx, sock_ctx, recv_ctx->user_ctx.head.staCause);
	} else if (recv_ctx->user_ctx.head.mtype == MTYPE_HTTP2_STATUS_REPORT_TO_HTTP  &&
			recv_ctx->user_ctx.head.staCause == HTTP_STA_CAUSE_PREARRANGED_END) {
		/* AHIF ovld ctrl (silence discard) ==> HTTPS reset stream (internal error) */
		send_to_worker(tcp_ctx, recv_ctx, HTTP_INTL_OVLD);
	} else {
		send_to_worker(tcp_ctx, recv_ctx, HTTP_INTL_SND_REQ);
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

	if (rcv_len <= 0) {
		if (errno != EINTR && errno != EAGAIN) {
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

int get_httpcs_buff_used(tcp_ctx_t *tcp_ctx)
{
	if (tcp_ctx == NULL)
		return 0;
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
	memset(&tcp_ctx->tcp_stat, 0x00, sizeof(tcp_stat_t));
}

void fep_stat_print(evutil_socket_t fd, short what, void *arg)
{
	if (SERVER_CONF.debug_mode != 1)
		return;

    char fep_read[1024] = {0,};
    char fep_write[1024] = {0,};

    for (int i = 0; i < LB_CONF.total_fep_num; i++) {
        GNode *nth_fep_rx = g_node_nth_child(LB_CTX.fep_rx_thrd, i);
        GNode *nth_fep_tx = g_node_nth_child(LB_CTX.fep_tx_thrd, i);

        tcp_ctx_t *fep_rx = (nth_fep_rx == NULL ? NULL : (tcp_ctx_t *)nth_fep_rx->data);
        tcp_ctx_t *fep_tx = (nth_fep_rx == NULL ? NULL : (tcp_ctx_t *)nth_fep_tx->data);

		if (fep_rx == NULL || fep_tx == NULL)
			continue;

        int fep_rx_used = get_httpcs_buff_used(fep_rx);

        APPLOG(APPLOG_ERR, "{{{DBG}}} FEP [%2d] CTX [fep_rx %05d/%05d] FEP TX [%s] (TPS %d) FEP RX [%s] DBG {{{ assign fail[%d] }}}",
                i,
                fep_rx_used,
                fep_rx->context_num,
                measure_print(fep_tx->tcp_stat.send_bytes, fep_write),
                fep_tx->tcp_stat.tps,
                measure_print(fep_rx->tcp_stat.recv_bytes, fep_read),
				fep_tx->tcp_stat.ctx_assign_fail);

        clear_context_stat(fep_rx);
        clear_context_stat(fep_tx);
    }
}

#if 0
void *fep_stat_thread(void *arg)
{
	lb_ctx_t *lb_ctx = (lb_ctx_t *)arg;

	struct event_base *evbase;
	evbase = event_base_new();

	struct timeval one_sec = {1, 0};
	struct event *ev;
	ev = event_new(evbase, -1, EV_PERSIST, fep_stat_print, (void *)lb_ctx);
	event_add(ev, &one_sec);

	/* start loop */
	event_base_loop(evbase, EVLOOP_NO_EXIT_ON_EMPTY);

	/* never reach here */
	event_base_free(evbase);

	return (void *)NULL;
}
#endif

void load_lb_config(server_conf *svr_conf, lb_global_t *lb_conf)
{
    config_setting_t *lb_config = svr_conf->lb_config;
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
    /* check port num pair match, a == b == c == d */
    if (config_setting_length(lb_conf->cf_fep_rx_listen_port) ==
        config_setting_length(lb_conf->cf_fep_tx_listen_port)) {
        printf_config_list_int("fep_rx_listen_port", lb_conf->cf_fep_rx_listen_port);
        printf_config_list_int("fep_tx_listen_port", lb_conf->cf_fep_tx_listen_port);
    } else {
        APPLOG(APPLOG_ERR, "{{{CFG}}} fep tx|rx port num not match!");
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
		APPLOG(APPLOG_ERR, "{{{CFG}}} lb_config.fail to get heaertbeat_enable!");
		exit(0);
	} else {
        APPLOG(APPLOG_ERR, "{{{CFG}}} lb_config.heartbeat_enable = %d", lb_conf->heartbeat_enable);
	}

}

void attach_lb_thread(lb_global_t *lb_conf, lb_ctx_t *lb_ctx)
{
    /* CAUTION!!! ALL UNDER THREAD USE THIS */
    tcp_ctx_t tcp_ctx = {0,};
    tcp_ctx.flush_tmval = lb_conf->flush_tmval;
	tcp_ctx.heartbeat_enable = lb_conf->heartbeat_enable;
    tcp_ctx.lb_ctx = lb_ctx;

    // create root node for thread
    lb_ctx->fep_tx_thrd = new_tcp_ctx(&tcp_ctx);
    lb_ctx->fep_rx_thrd = new_tcp_ctx(&tcp_ctx);

    /* fep rx thread create */
    for (int i = 0; i < lb_conf->total_fep_num; i++) {
        tcp_ctx.fep_tag = i;
        tcp_ctx.svc_type = TT_RX_ONLY;
        config_setting_t *port = config_setting_get_elem(lb_conf->cf_fep_rx_listen_port, i);
        tcp_ctx.listen_port = config_setting_get_int(port);
        add_tcp_ctx_to_main(&tcp_ctx, lb_ctx->fep_rx_thrd);
    }
    /* fep tx thread create */
    for (int i = 0; i < lb_conf->total_fep_num; i++) {
        tcp_ctx.fep_tag = i;
        tcp_ctx.svc_type = TT_TX_ONLY;
        config_setting_t *port = config_setting_get_elem(lb_conf->cf_fep_tx_listen_port, i);
        tcp_ctx.listen_port = config_setting_get_int(port);
        add_tcp_ctx_to_main(&tcp_ctx, lb_ctx->fep_tx_thrd);
    }

    CREATE_LB_THREAD(lb_ctx->fep_rx_thrd, sizeof(https_ctx_t), lb_conf->context_num);
    CREATE_LB_THREAD(lb_ctx->fep_tx_thrd, 0, 0);

#if 0
	if (SERVER_CONF.debug_mode == 1) {
		/* for stat print small thread */
		if (pthread_create(&lb_ctx->stat_thrd_id, NULL, &fep_stat_thread, lb_ctx) != 0) {
			APPLOG(APPLOG_ERR, "%s() fail to create thread", __func__);
			exit(0);
		} else {
			pthread_detach(lb_ctx->stat_thrd_id);
		}
	}
#endif
}

void send_fep_conn_status(evutil_socket_t fd, short what, void *arg)
{
	// caution, it trigger in every tcp rx thread, use mutex_lock
	  
	tcp_ctx_t *tcp_ctx = (tcp_ctx_t *)arg;

	if (tcp_ctx->received_fep_status != HTTP_STA_CAUSE_SYS_ACTIVE) 
		return;

	if (g_node_n_children(tcp_ctx->root_conn) == 0)
		return;

	GeneralQMsgType msg = {0,};
	msg.mtype = (long)MSGID_HTTPS_NRFM_FEP_ALIVE_NOTI;

	int res = msgsnd(nrfmQid, &msg, 0, 0);

	if (res < 0) {
		APPLOG(APPLOG_DEBUG, "%s() fail to send status noti to NRFM", __func__);
	}
	return;
}

void nrfm_send_conn_status_callback(tcp_ctx_t *tcp_ctx)
{
	// every 300 ms, if fep connected send to NRFM

    struct timeval tm_300ms = {0, 300000}; // 300 ms
	struct event *ev_fep_conn_status;
	ev_fep_conn_status = event_new(tcp_ctx->evbase, -1, EV_PERSIST, send_fep_conn_status, tcp_ctx);
	event_add(ev_fep_conn_status, &tm_300ms);
}

int create_lb_thread()
{
	load_lb_config(&SERVER_CONF, &LB_CONF);

	attach_lb_thread(&LB_CONF, &LB_CTX);

	return 0;
}
