#include "ahifsim.h"

char *conn_name[] = {
	"HTTPC_TX",
	"HTTPC_RX",
	"HTTPS_TX",
	"HTTPS_RX",
	"UNKNOWN"
};

void sock_eventcb(struct bufferevent *bev, short events, void *user_data)
{
    thrd_ctx_t *thrd_ctx = (thrd_ctx_t *)user_data;

	// connect
    if(events & BEV_EVENT_CONNECTED) {
        int fd = bufferevent_getfd(bev);
        fprintf(stderr, "(%s) Connected fd is (get:%d set:%d)\n", conn_name[thrd_ctx->my_conn_type], fd, thrd_ctx->fd);

#if 0
        if (util_set_linger(thrd_ctx->fd, 1, 0) != 0)
            fprintf(stderr, "Fail to set SO_LINGER (ABORT) to fd\n");
		if (util_set_rcvbuffsize(thrd_ctx->fd, 10240) != 0)
			fprintf(stderr, "fail to set SO_RCVBUF (size 10240) to fd\n");
		if (util_set_sndbuffsize(thrd_ctx->fd, 10240) != 0)
			fprintf(stderr, "fail to set SO_SNDBUF (size 10240) to fd\n");
#else
		// move to before connect
#endif

		thrd_ctx->connected = 1;
        return;
    }

	// error
    if (events & BEV_EVENT_EOF) {
        fprintf(stderr, "(%s) Connection closed.\n", conn_name[thrd_ctx->my_conn_type]);
    } else if (events & BEV_EVENT_ERROR) {
        fprintf(stderr, "(%s) Got an error on the connection: %s\n", conn_name[thrd_ctx->my_conn_type], strerror(errno));
    } else if (events & BEV_EVENT_TIMEOUT) {
        fprintf(stderr, "(%s) Some timeout occured on the connection: %s\n", conn_name[thrd_ctx->my_conn_type], strerror(errno));
	}

	fprintf(stderr, "Program will dirty exited\n");
	exit(0); // program dirty exited
}

void packet_process_res(thrd_ctx_t *thrd_ctx, char *process_ptr, size_t processed_len)
{
	//if sock recv 10, process 3 ==> move remain 7 byte to front
	memmove(thrd_ctx->buff, process_ptr, thrd_ctx->rcv_len - (thrd_ctx->rcv_len - processed_len));
	thrd_ctx->rcv_len = thrd_ctx->rcv_len - processed_len;
	return;
} 

ahif_ctx_t *get_sended_ctx(main_ctx_t *MAIN_CTX, char *test_uri_with_ctx)
{
	int ctxId = atoi(test_uri_with_ctx + strlen(TEST_URI));
	if (ctxId < 0 || ctxId > MAX_TEST_CTX_NUM) {
		fprintf(stderr, "{dbg} we recv wrong ctxId (%d)\n", ctxId);
		return NULL;
	}

	ahif_ctx_t *ahif_ctx = &MAIN_CTX->ahif_ctx[ctxId];
	if (ahif_ctx->occupied == 0) {
		fprintf(stderr, "{dbg} we recv unoccupied ctxId (%d)\n", ctxId);
		return NULL;
	}

	return ahif_ctx;
}


ahif_ctx_t *get_assembled_ctx(main_ctx_t *MAIN_CTX, char *ptr)
{
    ahif_ctx_t *recv_ctx = NULL;
    AhifHttpCSMsgHeadType *head = (AhifHttpCSMsgHeadType *)ptr;
    
    char *vheader = ptr + sizeof(AhifHttpCSMsgHeadType);
    int vheaderCnt = head->vheaderCnt;
    
    char *body = ptr + sizeof(AhifHttpCSMsgHeadType) + (sizeof(hdr_relay) * vheaderCnt);
    int bodyLen = head->bodyLen;
    
	/* CAUTION we use appVer as ctxId */
    if((recv_ctx = get_sended_ctx(MAIN_CTX, head->rsrcUri)) == NULL) {
        return NULL;
	}
        
    memcpy(&recv_ctx->ahif_pkt.head, ptr, sizeof(AhifHttpCSMsgHeadType));
    memcpy(&recv_ctx->ahif_pkt.vheader, vheader, (sizeof(hdr_relay) * vheaderCnt));
    memcpy(&recv_ctx->ahif_pkt.body, body, bodyLen);

#if 0
	fprintf(stderr, "{{{dbg}}} in %s thrd %d ctx %d\n", 
			__func__, head->thrd_index, head->ctx_id);
#endif
    
    return recv_ctx;
}

void https_read_cb(struct bufferevent *bev, void *arg)
{
	thrd_ctx_t *thrd_ctx = (thrd_ctx_t *)arg;
	ssize_t rcv_len = bufferevent_read(bev,
			thrd_ctx->buff + thrd_ctx->rcv_len,
			MAX_RCV_BUFF_LEN - thrd_ctx->rcv_len);

	if (rcv_len <= 0)
		return;

	thrd_ctx->rcv_len += rcv_len;
	/* stat */
	thrd_ctx->recv_bytes += rcv_len;

	return rx_handle_func(thrd_ctx, https_echo_rx_to_tx);
}

void httpc_read_cb(struct bufferevent *bev, void *arg)
{
	thrd_ctx_t *thrd_ctx = (thrd_ctx_t *)arg;
	ssize_t rcv_len = bufferevent_read(bev,
			thrd_ctx->buff + thrd_ctx->rcv_len,
			MAX_RCV_BUFF_LEN - thrd_ctx->rcv_len);

	if (rcv_len <= 0)
		return;

	thrd_ctx->rcv_len += rcv_len;
	/* stat */
	thrd_ctx->recv_bytes += rcv_len;

	return rx_handle_func(thrd_ctx, httpc_remove_ctx);
}
