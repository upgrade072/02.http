#include "ahifsim.h"

ahif_ctx_t *get_null_ctx(main_ctx_t *MAIN_CTX)
{
	for (int i = 0; i < MAX_TEST_CTX_NUM; i++) {
		ahif_ctx_t *ahif_ctx = &MAIN_CTX->ahif_ctx[i];

		if (ahif_ctx->occupied == 0) {
			memset(ahif_ctx, 0x00, sizeof(ahif_ctx_t));
			ahif_ctx->occupied = 1;
			ahif_ctx->ctxId = i;
			return ahif_ctx;
		}
	}
	return NULL;
}

void set_ahif_ctx(main_ctx_t *MAIN_CTX, ahif_ctx_t *ahif_ctx)
{
	sprintf(ahif_ctx->ahif_pkt.head.httpMethod, "TEST");
	sprintf(ahif_ctx->ahif_pkt.head.rsrcUri, "%s%d", TEST_URI, ahif_ctx->ctxId);
	ahif_ctx->ahif_pkt.head.ahifCid = ahif_ctx->ctxId;

	sprintf(ahif_ctx->ahif_pkt.head.magicByte, AHIF_MAGIC_BYTE);
	ahif_ctx->ahif_pkt.head.mtype = MTYPE_HTTP2_REQUEST_AHIF_TO_HTTPC;

	config_setting_t *setting = config_lookup(&MAIN_CTX->CFG, "scenario");

	config_setting_t *dest_hosts_list = config_setting_get_member(setting, "dest_hosts");
	MAIN_CTX->dest_hosts_pos = (MAIN_CTX->dest_hosts_pos + 1) % config_setting_length(dest_hosts_list);
	config_setting_t *dest_host = config_setting_get_elem(dest_hosts_list, MAIN_CTX->dest_hosts_pos);
	sprintf(ahif_ctx->ahif_pkt.head.destHost, "%s", config_setting_get_string(dest_host));

	config_setting_t *vheader_cnts_list = config_setting_get_member(setting, "vheader_cnts");
	MAIN_CTX->vheader_cnts_pos = (MAIN_CTX->vheader_cnts_pos + 1) % config_setting_length(vheader_cnts_list);
	config_setting_t *vheader_cnt = config_setting_get_elem(vheader_cnts_list, MAIN_CTX->vheader_cnts_pos);
	ahif_ctx->ahif_pkt.head.vheaderCnt = config_setting_get_int(vheader_cnt);

	config_setting_t *body_lens_list = config_setting_get_member(setting, "body_lens");
	MAIN_CTX->body_lens_pos = (MAIN_CTX->body_lens_pos + 1) % config_setting_length(body_lens_list);
	config_setting_t *body_len = config_setting_get_elem(body_lens_list, MAIN_CTX->body_lens_pos);
	ahif_ctx->ahif_pkt.head.bodyLen = config_setting_get_int(body_len);
}

void set_iovec(ahif_ctx_t *ahif_ctx, iovec_item_t *push_req, char *ctx_unset_ptr, void (*cbfunc)(), void *cbarg)
{
	int item_cnt = 0;
	int total_bytes = 0;

	memset(push_req, 0x00, sizeof(iovec_item_t));

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

	//fprintf(stderr, "{dbg} %s total bytes %d\n", __func__, total_bytes);

    push_req->iov_cnt = item_cnt;
    push_req->remain_bytes = total_bytes;

	if (ctx_unset_ptr != NULL)
		push_req->ctx_unset_ptr = ctx_unset_ptr;

	if (cbfunc != NULL) {
		push_req->unset_cb_func = cbfunc;
		push_req->unset_cb_arg = cbarg;
	}
}

void push_callback(evutil_socket_t fd, short what, void *arg)
{
	//fprintf(stderr, "{dbg} %s called\n", __func__);

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
		if (nwritten > 0) {
			unset_pushed_item(write_list, nwritten);
			/* stat */
			sender_thrd_ctx->send_bytes += nwritten;
		} else if (nwritten < 0 ) {
			if (errno != EINTR && errno != EAGAIN) {
				fprintf(stderr, "(FD: %d) there error! %d : %s\n", 
						sender_thrd_ctx->fd, errno, strerror(errno));
				exit(0);
			}
		}
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
	/* stat */
	MAIN_CTX->httpc_send_cnt++;

	//pthread_mutex_lock(&MAIN_CTX->CtxLock);
	ahif_ctx_t *ahif_ctx = get_null_ctx(MAIN_CTX);
	//pthread_mutex_unlock(&MAIN_CTX->CtxLock);

	if (ahif_ctx == NULL) {
		fprintf(stderr, "{dbg} %s fail to get ctx!\n", __func__);
		exit(0);
	}
	set_ahif_ctx(MAIN_CTX, ahif_ctx);

	set_iovec(ahif_ctx, &ahif_ctx->push_req, NULL, NULL, NULL);
	iovec_push_req(MAIN_CTX, &MAIN_CTX->httpc_tx_ctx, &ahif_ctx->push_req);
}