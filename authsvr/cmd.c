#include "auth.h"

int cmd_run(char *nfName, char *nfInstanceId)
{
	config_setting_t *targetNfInstance = search_config(nfName);
	if (targetNfInstance == NULL) {
		fprintf(stderr, "{{{CMD}}} can't find NF name(%s), check .cfg!\n", nfName);
		return (-1);
	}


	config_setting_t *scope = NULL;
	if ((scope = config_setting_get_member(targetNfInstance, "scope")) == NULL) {
		fprintf(stderr, "{{{CMD}}} can't find NF->SCOPE name(%s), check .cfg!\n", nfName);
		return (-1);
	}

	access_token_req_t auth_req = {0,};
	auth_req.nfInstanceId = nfInstanceId;

	int count = config_setting_length(scope);
	for (int i = 0; i < count; i++) {
		config_setting_t *item = config_setting_get_elem(scope, i);
		const char *scope_string = config_setting_get_string(item);
		sprintf(auth_req.scope_req + strlen(auth_req.scope_req), i == 0 ? "%s" : " %s", scope_string);
	}

	char token_buff[1024] = {0,};
	if (issue_access_token(&auth_req, targetNfInstance, token_buff) < 0) {
		fprintf(stderr, "{{{CMD}}} fail to issue token!\n");
		return (-1);
	}

	return 0;
}
