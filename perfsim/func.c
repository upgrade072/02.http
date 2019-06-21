#include "header.h"

/* config */
extern perf_conf_t PERF_CONF;

void execute_function(app_ctx_t *ctx, AhifAppMsgType *txMsg)
{
	if (!ctx->func_exist)
		return;
	if (strlen(ctx->func_name) == 0)
		return;

	func_run(ctx, txMsg);

	return;
}

void func_run(app_ctx_t *ctx, AhifAppMsgType *txMsg)
{
	if (!strcmp(ctx->func_name, "fn_000")) {
		fn_000(ctx->func_arg, txMsg);
	}
}

void fn_000(char *uri, AhifAppMsgType *txMsg)
{
	char protocol[128] = {0,};
	char host[128] = {0,};
	char path[256] = {0,};
	char ip[128] = {0,};
	char port[128] = {0,};

	sscanf(uri, "%127[^:/]://%127[^/]/%255s", protocol, host, path);

	sprintf(txMsg->head.scheme, "%s", protocol);
	sprintf(txMsg->head.authority, "%s", host);
	sprintf(txMsg->head.rsrcUri, "/%s", path);

	sscanf(host, "%127[^:]:%127s", ip, port);

	int port_num = atoi(port);

	sprintf(txMsg->head.destType, "AUSF");
	sprintf(txMsg->head.destHost, "%s", port_num == 9000 ? "AUSF_DIR_FEP00" : "AUSF_DIR_FEP01");
	sprintf(txMsg->head.destIp, "%s", ip);
	txMsg->head.destPort = port_num;
}
