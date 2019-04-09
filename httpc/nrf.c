#include "client.h"
#ifdef OAUTH

extern acc_token_list_t	ACC_TOKEN_LIST[MAX_ACC_TOKEN_NUM];
extern nrf_worker_t		NRF_WORKER;
extern char 			mySysType[COMM_MAX_VALUE_LEN];
extern char 			mySvrId[COMM_MAX_VALUE_LEN];

void print_oauth_response(access_token_res_t *response)
{
	time_t due_time = response->expire_in;

	APPLOG(APPLOG_ERR, "");
	APPLOG(APPLOG_ERR, "{dbg} recv oauth 2.0 response ...");
	APPLOG(APPLOG_ERR, "  {access_token : %s", response->access_token);
	APPLOG(APPLOG_ERR, "  {token_type : %s", response->token_type);
	APPLOG(APPLOG_ERR, "  {expire_in : %d (%.19s)", response->expire_in, ctime(&due_time));
}

void parse_oauth_response(char *body, access_token_res_t *response)
{
	/* remove [ newline | space | { | , | } ] */
	json_delimiter(body);

	char *ptr = strtok(body, " ");

	while (ptr != NULL)
	{
		char *delimiter = NULL;

		//APPLOG(APPLOG_ERR, "dbg} %s", ptr);

		if (!strncmp(ptr, "access_token", strlen("access_token"))) {
			if ((delimiter = strchr(ptr, ':')) != NULL) 
				response->access_token = delimiter + 1;
		} else if (!strncmp(ptr, "token_type", strlen("token_type"))) {
			if ((delimiter = strchr(ptr, ':')) != NULL)
				response->token_type = delimiter + 1;
		} else if (!strncmp(ptr, "expires_in", strlen("expires_in"))) {
			if ((delimiter = strchr(ptr, ':')) != NULL)
				response->expire_in = atoi(delimiter + 1);
		}

		ptr = strtok(NULL, " ");
	}
}

void accuire_token(acc_token_list_t *token_list)
{
	char request_body[1024] = {0,};
	char encoded_body[2048] = {0,};

	token_list->status = TA_TRYING;

	if (token_list->acc_type == AT_SVC)
		sprintf(request_body, HBODY_ACCESS_TOKEN_REQ_FOR_TYPE,
				mySvrId,
				mySysType,
				token_list->nf_type,
				token_list->scope);
	else
		sprintf(request_body, HBODY_ACCESS_TOKEN_REQ_FOR_INSTANCE,
				mySvrId,
				mySysType,
				token_list->nf_type,
				token_list->scope,
				token_list->nf_instance_id);

	encode(request_body, encoded_body, HTTP_EN_XWWW);

	char request_uri[1024] = {0,};
	sprintf(request_uri, "https://%s/oauth2/token", token_list->nrf_addr);
	char request_method[] = "POST";
	char request_content_type[] = CONTENT_TYPE_OAUTH_REQ;
	char *body = encoded_body;

	libhttp_single_sndreq_t request = {request_uri, request_method, request_content_type, body, strlen(body) };
	char recv_body[4086] = {0,};
	libhttp_single_rcvres_t response = {0, recv_body, sizeof(recv_body), 0};

	single_run(&request, &response);

	if (response.res_code == 200 && response.body_len > 0) {
		access_token_res_t access_token_res = {0,};
		parse_oauth_response(response.body, &access_token_res);
		print_oauth_response(&access_token_res); /* for DBG */

		int pos = (token_list->token_pos + 1) % 2; // indicate [0] [1] [0] [1]
		sprintf(token_list->access_token[pos], "%s", access_token_res.access_token);
		token_list->due_date = access_token_res.expire_in;
		token_list->last_request_time = time(NULL);

		/* update pos & status */
		token_list->token_pos = pos;
		token_list->status = TA_ACCUIRED;

		print_token_list_raw(ACC_TOKEN_LIST);
	} else {
		token_list->status = TA_FAILED;
	}
}

void chk_and_accuire_token(acc_token_list_t *token_list)
{
	time_t current = time(NULL);
	if (token_list->due_date - current < 600 ||
			current - token_list->last_request_time > 60 ) {
		accuire_token(token_list);
	}
}

void nrf_get_token_cb(evutil_socket_t fd, short what, void *arg)
{
	for (int i = 0; i < MAX_ACC_TOKEN_NUM; i++) {
		acc_token_list_t *token_list = &ACC_TOKEN_LIST[i];
		if (token_list->occupied != 1) 
			continue;

		if (token_list->status < TA_ACCUIRED)
			accuire_token(token_list);
		else
			chk_and_accuire_token(token_list);
	}
}

void *nrf_access_thread(void *arg)
{
	struct event_base *evbase;

	evbase = event_base_new();
	NRF_WORKER.evbase = evbase;

	struct timeval tm_intval_nrf_access = {1, 0}; // 1 SEC
	struct event *ev_nrf_acc;
	ev_nrf_acc = event_new(evbase, -1, EV_PERSIST, nrf_get_token_cb, (void *)NULL);
	event_add(ev_nrf_acc, &tm_intval_nrf_access);

	/* if flag == 0 and no event pending, loop just exited */
	event_base_loop(evbase, EVLOOP_NO_EXIT_ON_EMPTY);

	event_base_free(evbase);

	APPLOG(APPLOG_ERR, "%s)%d)reach here\n", __func__, __LINE__);

	return NULL;
}

char *get_access_token(int token_id)
{
	if (token_id < 0 || token_id >= MAX_ACC_TOKEN_NUM)
		return NULL;

	acc_token_list_t *token_list = &ACC_TOKEN_LIST[token_id];
	if (token_list->status != TA_ACCUIRED)
		return NULL;

	int pos = token_list->token_pos;
	return token_list->access_token[pos];
}
#endif

