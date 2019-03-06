#include "ahifsim.h"

ahif_ctx_t *get_null_ctx(main_ctx_t *MAIN_CTX)
{
	for (int i = 0; i < AHIF_MAX_APP_VERSION_LEN; i++) {
		ahif_ctx_t *ahif_ctx = &MAIN_CTX->ahif_ctx[i];
		if (ahif_ctx->occupied == 0) {
			memset(ahif_ctx, 0x00, sizeof(ahif_ctx_t));
			sprintf(ahif_ctx->ahif_pkt.head.magicByte, AHIF_MAGIC_BYTE);
			ahif_ctx->ahif_pkt.head.mtype = MTYPE_HTTP2_REQUEST_AHIF_TO_HTTPC;
			sprintf(ahif_ctx->ahif_pkt.head.appVer, "%d", i);
			return ahif_ctx;
		}
	}
	return NULL;
}

void set_ahif_ctx(main_ctx_t *MAIN_CTX, ahif_ctx_t *ahif_ctx)
{
	config_setting_t *setting = config_lookup(&MAIN_CTX->CFG, "scenario");

	config_setting_t *dest_hosts_list = config_setting_get_member(setting, "dest_hosts");
	MAIN_CTX->dest_hosts_pos = (MAIN_CTX->dest_hosts_pos + 1) % config_setting_length(dest_hosts_list);
	config_setting_t *dest_host = config_setting_get_elem(dest_hosts_list, MAIN_CTX->dest_hosts_pos);
	sprintf(ahif_ctx->ahif_pkt.head.destIp, "%s", config_setting_get_string(dest_host));

	config_setting_t *vheader_cnts_list = config_setting_get_member(setting, "vheader_cnts");
	MAIN_CTX->vheader_cnts_pos = (MAIN_CTX->vheader_cnts_pos + 1) % config_setting_length(vheader_cnts_list);
	config_setting_t *vheader_cnt = config_setting_get_elem(vheader_cnts_list, MAIN_CTX->vheader_cnts_pos);
	ahif_ctx->ahif_pkt.head.vheaderCnt = config_setting_get_int(vheader_cnt);

	config_setting_t *body_lens_list = config_setting_get_member(setting, "body_lens");
	MAIN_CTX->body_lens_pos = (MAIN_CTX->body_lens_pos + 1) % config_setting_length(body_lens_list);
	config_setting_t *body_len = config_setting_get_elem(body_lens_list, MAIN_CTX->body_lens_pos);
	ahif_ctx->ahif_pkt.head.bodyLen = config_setting_get_int(body_len);
}

void set_iovec(ahif_ctx_t *ahif_ctx, iovec_item_t *push_req, char *ctx_unset_ptr)
{
	int item_cnt = 0;
	int total_bytes = 0;

	// header must exist
	if (1) {
		push_req->iov[0].iov_base = &ahif_ctx->ahif_pkt.head;
		push_req->iov[0].iov_len = AHIF_HTTPCS_MSG_HEAD_LEN;
		item_cnt++;
		total_bytes += AHIF_HTTPCS_MSG_HEAD_LEN;
	}
    // vheader
    if (ahif_ctx->ahif_pkt.head.vheaderCnt) {
        push_req->iov[item_cnt].iov_base = ahif_ctx->ahif_pkt.vheader;
        push_req->iov[item_cnt].iov_len = ahif_ctx->ahif_pkt.head.vheaderCnt * sizeof(hdr_relay);
        item_cnt++;
        total_bytes += ahif_ctx->ahif_pkt.head.vheaderCnt * sizeof(hdr_relay);
    }
    // body
    if (ahif_ctx->ahif_pkt.head.bodyLen) {
        push_req->iov[item_cnt].iov_base = ahif_ctx->ahif_pkt.body;
        push_req->iov[item_cnt].iov_len = ahif_ctx->ahif_pkt.head.bodyLen;
        item_cnt++;
        total_bytes += ahif_ctx->ahif_pkt.head.bodyLen;
    }

    push_req->iov_cnt = item_cnt;
    push_req->remain_bytes = total_bytes;

	if (ctx_unset_ptr != NULL)
		push_req->ctx_unset_ptr = ctx_unset_ptr;
}

void push_callback(evutil_socket_t fd, short what, void *arg)
{
	iovec_item_t *push_item = (iovec_item_t *)arg;
	thrd_ctx_t *sender_thrd_ctx = (thrd_ctx_t *)push_item->sender_thrd_ctx;
	write_list_t *write_list = &sender_thrd_ctx->push_items;
	config_t *CFG = push_item->CFG;

	create_write_item(write_list, push_item);

	int bundle_count = 0;
	int bundle_bytes = 0;
	config_setting_t *setting = config_lookup(CFG, "application");
	config_setting_lookup_int(setting, "bundle_count", &bundle_count);
	config_setting_lookup_int(setting, "bundle_bytes", &bundle_bytes);

	if (write_list->item_cnt >= bundle_count || write_list->item_bytes >= bundle_bytes) {
		ssize_t nwritten = push_write_item(sender_thrd_ctx->fd, write_list, bundle_count, bundle_bytes);
		if (nwritten > 0)
			unset_pushed_item(write_list, nwritten);
	}
}

void iovec_push_req(main_ctx_t *MAIN_CTX, thrd_ctx_t *tx_thread_ctx, iovec_item_t *push_req)
{
	struct event_base *evbase = tx_thread_ctx->evbase;
	push_req->sender_thrd_ctx = tx_thread_ctx;
	push_req->CFG = &MAIN_CTX->CFG;

	if (event_base_once(evbase, -1, EV_TIMEOUT, push_callback, push_req, NULL) < 0) {
		fprintf(stderr, "fail to add push event!\n");
	}
}

void snd_ahif_pkt(main_ctx_t *MAIN_CTX)
{
	// [prepare packet]
	//	- dest host
	//	- vheader cnt
	//	- body len
	ahif_ctx_t *ahif_ctx = get_null_ctx(MAIN_CTX);
	set_ahif_ctx(MAIN_CTX, ahif_ctx);

	// [send request]
	//  - make iovec
	//  - add to sender linked list
	set_iovec(ahif_ctx, &ahif_ctx->push_req, NULL);
	iovec_push_req(MAIN_CTX, &MAIN_CTX->httpc_tx_ctx, &ahif_ctx->push_req);
}

void https_echo_rx_to_tx(main_ctx_t *MAIN_CTX, ahif_ctx_t *ahif_ctx)
{   
    ahif_ctx->ahif_pkt.head.mtype = MTYPE_HTTP2_RESPONSE_AHIF_TO_HTTPS;
    ahif_ctx->ahif_pkt.head.respCode = 200;
	memset(&ahif_ctx->push_req, 0x00, sizeof(iovec_item_t));

	set_iovec(ahif_ctx, &ahif_ctx->push_req, NULL);
	iovec_push_req(MAIN_CTX, &MAIN_CTX->https_tx_ctx, &ahif_ctx->push_req);
}
    
void httpc_remove_ctx(main_ctx_t *MAIN_CTX, ahif_ctx_t *ahif_ctx)
{
	ahif_ctx->occupied = 0;
}

void rx_handle_func(thrd_ctx_t *thrd_ctx, void (*handle_func)())
{   
    ahif_ctx_t *ahif_ctx = NULL;
    
    AhifHttpCSMsgHeadType *head = NULL;
    char *process_ptr = thrd_ctx->buff;
    size_t processed_len = 0;
    
KEEP_PROCESS:
    if (thrd_ctx->rcv_len < (processed_len + AHIF_HTTPCS_MSG_HEAD_LEN))
        return packet_process_res(thrd_ctx, process_ptr, processed_len);
    
    if (thrd_ctx->rcv_len < (processed_len + AHIF_TCP_MSG_LEN(head)))
        return packet_process_res(thrd_ctx, process_ptr, processed_len);

    if ((ahif_ctx = get_assembled_ctx(thrd_ctx->MAIN_CTX, process_ptr)) == NULL) {
        fprintf(stderr, "cant process packet, will just dropped\n");
        return packet_process_res(thrd_ctx, process_ptr, processed_len); 
    }   

    handle_func(thrd_ctx->MAIN_CTX, ahif_ctx);

    process_ptr += AHIF_TCP_MSG_LEN(head);
    processed_len += AHIF_TCP_MSG_LEN(head);

    goto KEEP_PROCESS;
}
