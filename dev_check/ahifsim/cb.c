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

ahif_ctx_t *get_sended_ctx(main_ctx_t *MAIN_CTX, int ctxId)
{
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


ahif_ctx_t *get_assembled_ctx(thrd_ctx_t *thrd_ctx, char *ptr)
{
	main_ctx_t *MAIN_CTX = thrd_ctx->MAIN_CTX;
    ahif_ctx_t *recv_ctx = NULL;

    AhifHttpCSMsgHeadType *head = (AhifHttpCSMsgHeadType *)ptr;
    
    char *vheader = ptr + sizeof(AhifHttpCSMsgHeadType);
    int vheaderCnt = head->vheaderCnt;
    
    char *body = ptr + sizeof(AhifHttpCSMsgHeadType) + (sizeof(hdr_relay) * vheaderCnt);
    int bodyLen = head->bodyLen;
    
	/* CAUTION we use appVer as ctxId */

	if (thrd_ctx->my_conn_type == TT_HTTPC_RX) {
		//pthread_mutex_lock(&MAIN_CTX->CtxLock);
		recv_ctx = get_sended_ctx(MAIN_CTX, head->ahifCid);
		//pthread_mutex_unlock(&MAIN_CTX->CtxLock);
	} else {
		recv_ctx = malloc(sizeof(ahif_ctx_t));
		recv_ctx->occupied = 1;
	}
	if (recv_ctx == NULL)
		return NULL;
        
    memcpy(&recv_ctx->ahif_pkt.head, ptr, sizeof(AhifHttpCSMsgHeadType));
    memcpy(&recv_ctx->ahif_pkt.vheader, vheader, (sizeof(hdr_relay) * vheaderCnt));
    memcpy(&recv_ctx->ahif_pkt.body, body, bodyLen);

    
    return recv_ctx;
}

void free_https_malloc_ctx(ahif_ctx_t *ahif_ctx)
{
	free(ahif_ctx);
}

void https_echo_rx_to_tx(main_ctx_t *MAIN_CTX, ahif_ctx_t *ahif_ctx)
{   
	/* stat */
	MAIN_CTX->https_recv_cnt ++;

	sprintf(ahif_ctx->ahif_pkt.head.magicByte, AHIF_MAGIC_BYTE);
    ahif_ctx->ahif_pkt.head.mtype = MTYPE_HTTP2_RESPONSE_AHIF_TO_HTTPS;
    ahif_ctx->ahif_pkt.head.respCode = 200;
	
	memset(&ahif_ctx->push_req, 0x00, sizeof(iovec_item_t));

	set_iovec(ahif_ctx, &ahif_ctx->push_req, &ahif_ctx->occupied, free_https_malloc_ctx, ahif_ctx);

	iovec_push_req(MAIN_CTX, &MAIN_CTX->https_tx_ctx, &ahif_ctx->push_req);
}
    
void httpc_remove_ctx(main_ctx_t *MAIN_CTX, ahif_ctx_t *ahif_ctx)
{
	//pthread_mutex_lock(&MAIN_CTX->CtxLock);
	ahif_ctx->occupied = 0;
	//pthread_mutex_unlock(&MAIN_CTX->CtxLock);
}

void rx_handle_func(thrd_ctx_t *thrd_ctx)
{   
    ahif_ctx_t *ahif_ctx = NULL;
    
    AhifHttpCSMsgHeadType *head = NULL;
    char *process_ptr = thrd_ctx->buff;
    size_t processed_len = 0;
    
KEEP_PROCESS:
    if (thrd_ctx->rcv_len < (processed_len + AHIF_HTTPCS_MSG_HEAD_LEN))
        return packet_process_res(thrd_ctx, process_ptr, processed_len);

	head = (AhifHttpCSMsgHeadType *)&thrd_ctx->buff[processed_len];
	process_ptr = (char *)head;
    
    if (thrd_ctx->rcv_len < (processed_len + AHIF_TCP_MSG_LEN(head)))
        return packet_process_res(thrd_ctx, process_ptr, processed_len);

    if ((ahif_ctx = get_assembled_ctx(thrd_ctx, process_ptr)) == NULL) {
        fprintf(stderr, "cant process packet, will just dropped\n");
        return packet_process_res(thrd_ctx, process_ptr, processed_len); 
    }   

	if (thrd_ctx->my_conn_type == TT_HTTPC_RX)
		httpc_remove_ctx(thrd_ctx->MAIN_CTX, ahif_ctx);
	else
		https_echo_rx_to_tx(thrd_ctx->MAIN_CTX, ahif_ctx);

    process_ptr += AHIF_TCP_MSG_LEN(head);
    processed_len += AHIF_TCP_MSG_LEN(head);

    goto KEEP_PROCESS;
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

	return rx_handle_func(thrd_ctx);
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

	return rx_handle_func(thrd_ctx);
}
