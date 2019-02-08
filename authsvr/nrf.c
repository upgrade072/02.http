#include "auth.h"

void parse_oauth_request(char *body, access_token_req_t *request)
{
	char *ptr = strtok(body, "&");

	while (ptr != NULL)
	{
		char *delimiter = NULL;

		fprintf(stderr, "dbg} %s\n", ptr);

		if (!strncmp(ptr, "grant_type", strlen("grant_type"))) {
			if ((delimiter = strchr(ptr, '=')) != NULL) 
				request->grant_type = delimiter + 1;

		} else if (!strncmp(ptr, "nfInstanceId", strlen("nfInstanceId"))) {
			if ((delimiter = strchr(ptr, '=')) != NULL) 
				request->nfInstanceId = delimiter + 1;

		} else if (!strncmp(ptr, "nfType", strlen("nfType"))) {
			if ((delimiter = strchr(ptr, '=')) != NULL) 
				request->nfType = delimiter + 1;

		} else if (!strncmp(ptr, "targetNfType", strlen("targetNfType"))) {
			if ((delimiter = strchr(ptr, '=')) != NULL) 
				request->targetNfType = delimiter + 1;

		} else if (!strncmp(ptr, "scope", strlen("scope"))) {
			if ((delimiter = strchr(ptr, '=')) != NULL) 
				sprintf(request->scope_raw, "%s", delimiter + 1);

		} else if (!strncmp(ptr, "targetNfInstanceId", strlen("targetNfInstanceId"))) {
			if ((delimiter = strchr(ptr, '=')) != NULL) 
				request->targetNfInstanceId = delimiter + 1;
		}

		ptr = strtok(NULL, "&");
	}

	/* strtok have nest problem (cant use in double for loop), handle it in out of loop */
	if (request->scope_raw[0]) {
		char *scope_ptr = strtok(request->scope_raw, " ");
		int scope_idx = 0;
		while (scope_ptr != NULL &&  scope_idx < MAX_SCOPE_NUM)
		{
			request->scope[scope_idx] = scope_ptr;
			scope_idx++;
			scope_ptr = strtok(NULL, " ");
		}
	}
}

void print_oauth_request(access_token_req_t *request)
{
	fprintf(stderr, "\n{dbg} recv oauth 2.0 request ...\n");
	fprintf(stderr, "  {grant_type : %s\n", request->grant_type);
	fprintf(stderr, "  {nfInstanceId : %s\n", request->nfInstanceId);
	fprintf(stderr, "  {nfType : %s\n", request->nfType);
	fprintf(stderr, "  {targetNfType : %s\n", request->targetNfType);
	fprintf(stderr, "  {((scope raw)) : %s\n", request->scope_raw);
	for (int i = 0; (i < MAX_SCOPE_NUM) && (request->scope[i] != NULL); i++)
		fprintf(stderr, "  {scope(%2d) : %s\n", i, request->scope[i]);
	fprintf(stderr, "  {targetNfInstanceId : %s\n", request->targetNfInstanceId);
}

int reply_response_nrf(nghttp2_session *session, 
		http2_stream_data *stream_data, int resp_code, char *body)
{
	nghttp2_nv hdrs[12];
	int hdrs_len = 0;

	/* ok / nok */
	nghttp2_nv hdr_ok[] = {MAKE_NV(":status", "200", strlen("200"))};
	nghttp2_nv hdr_error[] = { MAKE_NV(":status", "400", strlen("400")) };

	switch (resp_code) {
		case 200: /* ok */
			memcpy(&hdrs[hdrs_len], &hdr_ok, sizeof(nghttp2_nv));
			hdrs_len++;
			break;
		case 400: /* error */
			memcpy(&hdrs[hdrs_len], &hdr_error, sizeof(nghttp2_nv));
			hdrs_len++;
			break;
		default:
			return (-1);
	}

	/* common */
	nghttp2_nv hdr_content_type[] = { MAKE_NV("content-type", "application/json", strlen("application/json")) };
	nghttp2_nv hdr_cache_control[] = { MAKE_NV("cache-control", "no-store", strlen("no-store")) };
	nghttp2_nv hdr_pragma[] = { MAKE_NV("pragma", "no-cache", strlen("no-cache")) };

	memcpy(&hdrs[hdrs_len], &hdr_content_type, sizeof(nghttp2_nv));
	hdrs_len ++;
	memcpy(&hdrs[hdrs_len], &hdr_cache_control, sizeof(nghttp2_nv));
	hdrs_len ++;
	memcpy(&hdrs[hdrs_len], &hdr_pragma, sizeof(nghttp2_nv));
	hdrs_len ++;

	return send_response(session, stream_data->stream_id, hdrs, hdrs_len, body);
}

#define ACC_TOKEN_ERR_BODY "{\
\"error\":\"%s\",\
\"error_description\":\"%s\",\
\"error_uri\":\"http://www.3gpp.org/ftp/Specs/archive/29_series/29.510\"\
}"

/* return 1 : scope mismatch , return 0 : scope match */
int check_scope_mismatch(access_token_req_t *req, config_setting_t *scope)
{
	int count = config_setting_length(scope);
	if (count <= 0)
		return 1;

	for (int i = 0; (i < MAX_SCOPE_NUM) && (req->scope[i] != NULL); i++) {
		int find = 0;
		for (int j = 0; j < count; j++) {
			const char *scope_name;
			if ((scope_name = config_setting_get_string_elem(scope, j)) != NULL &&
					!strcmp(req->scope[i], scope_name)) {
				find = 1;
				break;
			}
		}
		if (!find)
			return 1;
	}
	return 0;
}

int issue_access_token(access_token_req_t *auth_req, config_setting_t *conf, char *token_buff)
{
	jwt_t *jwt = NULL;
	const char *credential = NULL;
	const char *nfProducerId = NULL;
	int jwt_alg = get_hash_alg();
	char *out = NULL;

	if (config_setting_lookup_string(conf, "credential", &credential) != CONFIG_TRUE)
		return (-1);
	if (config_setting_lookup_string(conf, "nfInstanceId", &nfProducerId) != CONFIG_TRUE)
		return (-1);

// CREATE HEADER
	if (jwt_new(&jwt) != 0)
		return (-1);
	if (jwt_set_alg(jwt, jwt_alg, (unsigned char *)credential, strlen(credential)) != 0)
		return (-1);

// CREATE CLAIMS
	/* issuer : nrf instanceId */
	if (jwt_add_grant(jwt, "issuer", NRF_UUID) != 0)
		return (-1);
	/* subject : nf consumer instanceId */
	if (jwt_add_grant(jwt, "subject", auth_req->nfInstanceId) != 0)
		return (-1);
	/* audience : nf producer instanceId */
	if (jwt_add_grant(jwt, "audience", nfProducerId) != 0)
		return (-1);
	/* scope : access token allow scope, can use wildcard */
	if (jwt_add_grant(jwt, "scope", auth_req->scope_raw) != 0)
		return (-1);
	/* expiration : token expire time (sec/int) */
	if (jwt_add_grant(jwt, "expiration", NRF_TOKEN_EXPIRE) != 0)
		return (-1);

// TEST PRINT 
	if ((out = jwt_dump_str(jwt, 1)) == NULL)
		return (-1);
	fprintf(stderr, "\n{dbg} access token (header.payload pretty) ...\n%s\n", out);
	free(out);

// ENCODE & SAVE TO BUFF
	if ((out = jwt_encode_str(jwt)) == NULL)
		return (-1);
	sprintf(token_buff, "%s", out);
	fprintf(stderr, "\n{dbg} access token (header.payload.signature encoded with credential) ...\n\n%s\n", out);
	free(out);

	jwt_free(jwt);

	return 1;
}

// if scope are same with reqest, it must be absent
#define ACC_TOKEN_REPLY_BODY "{\
\"access_token\":\"%s\",\
\"token_type\":\"JWT\",\
\"expires_in\":\"%s\"\
}"
int on_request_recv_nrf(nghttp2_session *session,
		http2_session_data *session_data,
		http2_stream_data *stream_data) 
{
	/* CAUTION!!! MUST use heap space */
	char *res_body = stream_data->body;

// CHECK REQUEST MESSAGE
	/* method = POST */
	if (strcmp(stream_data->method, "POST")) {
		sprintf(res_body, ACC_TOKEN_ERR_BODY, "invalid_request", "wrong method");
		goto OAUTH_RETURN_400;
	}
	/* content-type = application/x-www-form-urlencoded */
	if (strcmp(stream_data->content_type, "application/x-www-form-urlencoded")) {
		sprintf(res_body, ACC_TOKEN_ERR_BODY, "invalid_request", "wrong content type");
		goto OAUTH_RETURN_400;
	}
	
// DECODE PAYLOAD
	char decoded_body[MAX_BODY_LEN] = {0,};
	decode(stream_data->body, decoded_body);

	access_token_req_t auth_req = {0,};
	parse_oauth_request(decoded_body, &auth_req);
	print_oauth_request(&auth_req);

// CHECK PAYLOAD DATA
	/* grant_type = client_credentials */
	if (strcmp(auth_req.grant_type, "client_credentials")) {
		sprintf(res_body, ACC_TOKEN_ERR_BODY, "unsupported_grant_type", "wrong grant type");
		goto OAUTH_RETURN_400;
	}

	/* nfInstanceId = { NRF registered instance only } */
	config_setting_t *nfInstance = search_nf_by_value("nfInstanceId", auth_req.nfInstanceId);
	if (nfInstance == NULL) {
		sprintf(res_body, ACC_TOKEN_ERR_BODY, "unauthorized_client", "request by not registered nfInstance");
		goto OAUTH_RETURN_400;
	}

// REQUEST VIA TARGET_NF_INSTANCE_ID
	if (auth_req.targetNfInstanceId != NULL) {
		/* targetNfInstance = { NRF registered instance only } */
		config_setting_t *targetNfInstance = search_nf_by_value("nfInstanceId", auth_req.targetNfInstanceId);
		if (targetNfInstance == NULL) {
			sprintf(res_body, ACC_TOKEN_ERR_BODY, "unauthorized_client", "target NF Instance Not exist");
			goto OAUTH_RETURN_400;
		}

		/* check targetNF Type */
		const char *nfType = NULL;
		if (auth_req.targetNfType == NULL || 
				(config_setting_lookup_string(targetNfInstance, "nfType", &nfType) != CONFIG_TRUE) ||
				strcmp(nfType, auth_req.targetNfType)) {
			sprintf(res_body, ACC_TOKEN_ERR_BODY, "invalid_request", "target NFType mismatch");
			goto OAUTH_RETURN_400;
		}

		/* check request scope */
		config_setting_t *scope = NULL;
		int scope_mismatch = 1;
		if ((scope = config_setting_get_member(targetNfInstance, "scope")) != NULL) {
			scope_mismatch = check_scope_mismatch(&auth_req, scope); /* value change in here, if match */
		}
		if (scope_mismatch) {
			sprintf(res_body, ACC_TOKEN_ERR_BODY, "invalid_scope", "scope mismatch with targetNF have");
			goto OAUTH_RETURN_400;
		}

		/* ISSUE ACCESS TOKEN */
		char token_buff[1024] = {0,};
		if (issue_access_token(&auth_req, targetNfInstance, token_buff) > 0) {
			sprintf(res_body, ACC_TOKEN_REPLY_BODY, token_buff, NRF_TOKEN_EXPIRE);
			goto OAUTH_RETURN_200;
		}

		goto OAUTH_RETURN_400;
	} else {
// REQUEST VIA TARGET NF SERVICE
		config_setting_t *targetNfInstance = search_nf_by_auth_info(&auth_req);
		if (targetNfInstance == NULL) {
			sprintf(res_body, ACC_TOKEN_ERR_BODY, "unauthorized_client", "target NF Instance Not exist");
			goto OAUTH_RETURN_400;
		}

		/* ISSUE ACCESS TOKEN */
		char token_buff[1024] = {0,};
		if (issue_access_token(&auth_req, targetNfInstance, token_buff) > 0) {
			sprintf(res_body, ACC_TOKEN_REPLY_BODY, token_buff, NRF_TOKEN_EXPIRE);
			goto OAUTH_RETURN_200;
		}

		goto OAUTH_RETURN_400;
	}

OAUTH_RETURN_400:
	if (reply_response_nrf(session, stream_data, 400, res_body) != 0)
		return NGHTTP2_ERR_CALLBACK_FAILURE;
	return 0;

OAUTH_RETURN_200:
	if (reply_response_nrf(session, stream_data, 200, res_body) != 0)
		return NGHTTP2_ERR_CALLBACK_FAILURE;
	return 0;
}

