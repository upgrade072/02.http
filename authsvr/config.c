
#include "auth.h"

extern config_t CFG;

void print_nf_list(config_setting_t *elem)
{
	const char *nfType;
	const char *nfInstanceId;
	config_setting_t *scope;
	const char *credential;

	if (config_setting_lookup_string(elem, "nfType", &nfType) == CONFIG_TRUE)
		fprintf(stderr, "  nfType: %s\n", nfType);
	if (config_setting_lookup_string(elem, "nfInstanceId", &nfInstanceId) == CONFIG_TRUE)
		fprintf(stderr, "  nfInstanceId : %s\n", nfInstanceId);
	if ((scope = config_setting_get_member(elem, "scope")) != NULL) {
		int count = config_setting_length(scope);
		const char *scope_name;
		fprintf(stderr, "  scope : ");
		for (int i = 0; i < count; i++) {
			if ((scope_name = config_setting_get_string_elem(scope, i)) != NULL)
				fprintf(stderr, "%s ", scope_name);
		}
		fprintf(stderr, "\n");
	}
	if (config_setting_lookup_string(elem, "credential", &credential) == CONFIG_TRUE)
		fprintf(stderr, "  nf credential : %s\n", credential);
}

config_setting_t *search_nf_by_value(const char *name, char *find_value)
{
	config_setting_t *setting = config_lookup(&CFG, "nf_list");
	if (setting == NULL) {
		fprintf(stderr, "err] config nf_list is NULL\n");
		return NULL;
	}

	int count = config_setting_length(setting);
	for (int i = 0; i < count; i++) {
		config_setting_t *elem = config_setting_get_elem(setting, i);

		const char *value;
		if ((config_setting_lookup_string(elem, name, &value) == CONFIG_TRUE) &&
				!strcmp(value, find_value)) {
			return elem;
		}
	}

	return NULL;
}

config_setting_t *search_nf_by_auth_info(access_token_req_t *auth_req)
{
	char *targetNfType = auth_req->targetNfType;

	config_setting_t *setting = config_lookup(&CFG, "nf_list");
	if (setting == NULL) {
		fprintf(stderr, "err] config nf_list is NULL\n");
		return NULL;
	}

	int count = config_setting_length(setting);
	for (int i = 0; i < count; i++) {
		config_setting_t *elem = config_setting_get_elem(setting, i);

		/* find nfType match case */
		const char *value = NULL;
		if ((config_setting_lookup_string(elem, "nfType", &value) == CONFIG_TRUE) &&
				strcmp(targetNfType, value)) {
			continue;
		}

		/* check scope match */
		config_setting_t *scope = NULL;
		if ((scope = config_setting_get_member(elem, "scope")) == NULL) {
			continue;
		}
		int scope_mismatch = check_scope_mismatch(auth_req, scope);
		if (scope_mismatch) {
			continue;
		} else {
			return elem;
		}
	}

	return NULL;
}

int get_hash_alg()
{
	int hash_alg;

	config_setting_t *setting = config_lookup(&CFG, "acc_token");
	config_setting_lookup_int(setting, "jwt_alg", &hash_alg);

	return hash_alg;
}

char *jwt_alg_string[128] = {
    "JWT_ALG_NONE",
    "JWT_ALG_HS256",
    "JWT_ALG_HS384",
    "JWT_ALG_HS512",
    "JWT_ALG_RS256",
    "JWT_ALG_RS384",
    "JWT_ALG_RS512",
    "JWT_ALG_ES256",
    "JWT_ALG_ES384",
    "JWT_ALG_ES512"
};

int init_cfg()
{
	char conf_name[] = "./auth.cfg";

	if (!config_read_file(&CFG, conf_name)) {
		fprintf(stderr, "%s:%d - %s\n",
				config_error_file(&CFG),
				config_error_line(&CFG),
				config_error_text(&CFG));
		goto CF_INIT_ERR;
	}

	fprintf(stderr, "\nconfig loading ...\n");

	/* acc_token config */
	config_setting_t *setting = config_lookup(&CFG, "acc_token");
	if (setting == NULL) {
		fprintf(stderr, "err] config acc_token is NULL\n");
		goto CF_INIT_ERR;
	}

	int hash_alg;
	if ((config_setting_lookup_int(setting, "jwt_alg", &hash_alg) == CONFIG_TRUE) 
		   && (hash_alg > JWT_ALG_NONE && hash_alg < JWT_ALG_TERM))	{
		fprintf(stderr, "\njwt alg is [%s]\n", jwt_alg_string[hash_alg]);
	} else {
		fprintf(stderr, "jwt alg not setted\n");
		goto CF_INIT_ERR;
	}

	/* nf_list config */
	setting = config_lookup(&CFG, "nf_list");
	if (setting == NULL) {
		fprintf(stderr, "err] config nf_list is NULL\n");
		goto CF_INIT_ERR;
	}

	int count = config_setting_length(setting);
	for (int i = 0; i < count; i++) {
		config_setting_t *elem = config_setting_get_elem(setting, i);
		fprintf(stderr, "\nconf name (%s)\n", elem->name);
		print_nf_list(elem);
	}

	return 0;

CF_INIT_ERR:
	fprintf(stderr, "cfg loading fail!!!!\n");
	fprintf(stderr, "\n=====================================================================\n");

	config_destroy(&CFG);

	return (-1);
}

