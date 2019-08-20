#include "client.h"

#define CF_CLIENT_CONF		"client.cfg"
#define CF_LOG_LEVEL		"client_cfg.sys_config.log_level"
#define CF_DEBUG_MODE		"client_cfg.sys_config.debug_mode"
#define CF_WORKER_SHMKEY	"client_cfg.sys_config.worker_shmkey_base"
#define CF_HTTPC_SHMKEY  	"client_cfg.sys_config.httpc_status_shmkey"
#define CF_MAX_WORKER_NUM	"client_cfg.http_config.worker_num"
#define CF_TIMEOUT_SEC	    "client_cfg.http_config.timeout_sec"
#define CF_PING_INTERVAL	"client_cfg.http_config.ping_interval"
#define CF_PING_TIMEOUT	    "client_cfg.http_config.ping_timeout"
#define CF_PKT_LOG		    "client_cfg.http_config.pkt_log"
#define CF_LB_CONFIG		"client_cfg.lb_config"
#define CF_CONNECT_LIST		"connect_list"

extern client_conf_t CLIENT_CONF;
extern conn_list_t CONN_LIST[MAX_SVR_NUM];
thrd_context_t THRD_WORKER[MAX_THRD_NUM];

config_t CFG;
char CONFIG_PATH[256] = {0,};

index_t INDEX[MAX_LIST_NUM];

#ifdef OAUTH  /* NRF OAuth 2.0 */
#define CF_ACCTOKEN_LIST	"access_token_info.list"
extern acc_token_list_t ACC_TOKEN_LIST[MAX_ACC_TOKEN_NUM];
#endif

int init_cfg()
{
	memset(INDEX, 0x00, sizeof(INDEX));

    config_init(&CFG);

    /* config path */
#ifndef TEST
	char *env = NULL;
    if ((env = getenv(IV_HOME)) == NULL) {
        sprintf(CONFIG_PATH, "./%s",  CF_CLIENT_CONF);
    } else {
        sprintf(CONFIG_PATH, "%s/data/%s", env, CF_CLIENT_CONF);
    }
#else
	sprintf(CONFIG_PATH, "./%s", CF_CLIENT_CONF);
#endif

    /* read config file */
    if (!config_read_file(&CFG, CONFIG_PATH)) {
        APPLOG(APPLOG_ERR, "{{{CFG}}} %s:%d - %s!!!",
                config_error_file(&CFG),
                config_error_line(&CFG),
                config_error_text(&CFG));
        goto CF_INIT_ERR;
    }

    APPLOG(APPLOG_ERR, "{{{CFG}}} loading [%s]", CONFIG_PATH);
    APPLOG(APPLOG_ERR, "==============================================================================================");

    config_set_tab_width(&CFG, 4);

	return (0);

CF_INIT_ERR:
    APPLOG(APPLOG_ERR, "{{{CFG}}} cfg loading fail!!!");
    APPLOG(APPLOG_ERR, "==============================================================================================");

    config_destroy(&CFG);
    return (-1);
}

int config_load_just_log()
{
    //config_setting_t *setting;
	int log_level;

    if (config_lookup_int(&CFG, CF_LOG_LEVEL, &log_level) == CONFIG_FALSE) {
        APPLOG(APPLOG_ERR, "{{{CFG}}} config log_level not exist!");
        goto CF_LOGLEVEL_LOAD_ERR;
    } else {
        if (log_level < APPLOG_NONE || log_level > APPLOG_DEBUG) {
            APPLOG(APPLOG_ERR, "{{{CFG}}} config log_level value invalid[%d] (%d~%d)!", 
					log_level, APPLOG_NONE, APPLOG_DEBUG);
			goto CF_LOGLEVEL_LOAD_ERR;
        }
        CLIENT_CONF.log_level = log_level;
        APPLOG(APPLOG_ERR, "{{{CFG}}} log level is [%d]", log_level);
    }
    return (0);

CF_LOGLEVEL_LOAD_ERR:
    APPLOG(APPLOG_ERR, "==============================================================================================");
    APPLOG(APPLOG_ERR, "{{{CFG}}} cfg loading fail!!!");

	/* if init fail, destroy and program exit */
    config_destroy(&CFG);
    return (-1);
}

int config_load()
{
    config_setting_t *setting;
	int list_index, item_index;

    /* debug mode */
    int debug_mode = 0;
    if (config_lookup_int(&CFG, CF_DEBUG_MODE, &debug_mode) == CONFIG_FALSE) {
        APPLOG(APPLOG_ERR, "{{{CFG}}} debug mode cfg not exist!");
        goto CF_LOAD_ERR;
    } else {
        CLIENT_CONF.debug_mode = (debug_mode == 1 ? 1: 0);
        APPLOG(APPLOG_ERR, "{{{CFG}}} debug mode is [%s]", CLIENT_CONF.debug_mode == 1 ? "ON" : "OFF");
    }

    /* worker num cfg loading */
    int worker_num;
    if (config_lookup_int(&CFG, CF_MAX_WORKER_NUM, &worker_num) == CONFIG_FALSE) {
        APPLOG(APPLOG_ERR, "{{{CFG}}} worker num cfg not exist!");
        goto CF_LOAD_ERR;
    } else {
        if (worker_num <= 0 || worker_num > MAX_THRD_NUM) {
            APPLOG(APPLOG_ERR, "{{{CFG}}} worker_num[%d] is zero or exceed max_thrd_num[%d]!",
                    worker_num, MAX_THRD_NUM);
            goto CF_LOAD_ERR;
        }
        CLIENT_CONF.worker_num = worker_num;
        APPLOG(APPLOG_ERR, "{{{CFG}}} worker num is [%d]", CLIENT_CONF.worker_num);
    }

    /* worker shmkey base */
    int worker_shmkey;
    if (config_lookup_int(&CFG, CF_WORKER_SHMKEY, &worker_shmkey) == CONFIG_FALSE) {
        APPLOG(APPLOG_ERR, "{{{CFG}}} worker shmkey base cfg not exist!");
        goto CF_LOAD_ERR;
    } else {
        CLIENT_CONF.worker_shmkey = worker_shmkey;
        APPLOG(APPLOG_ERR, "{{{CFG}}} worker shmkey is [0x%x]", CLIENT_CONF.worker_shmkey);
    }

    /* httpc status shmkey */
    int httpc_status_shmkey;
    if (config_lookup_int(&CFG, CF_HTTPC_SHMKEY, &httpc_status_shmkey) == CONFIG_FALSE) {
        APPLOG(APPLOG_ERR, "{{{CFG}}} httpc status shmkey cfg not exist!");
        goto CF_LOAD_ERR;
    } else {
        CLIENT_CONF.httpc_status_shmkey = httpc_status_shmkey;
        APPLOG(APPLOG_ERR, "{{{CFG}}} httpc status shmkey is [0x%x]", CLIENT_CONF.httpc_status_shmkey);
    }

    /* timeout sec */
    int timeout_sec = 0;
    if (config_lookup_int(&CFG, CF_TIMEOUT_SEC, &timeout_sec) == CONFIG_FALSE) {
        APPLOG(APPLOG_ERR, "{{{CFG}}} timeout sec cfg not exist!");
        goto CF_LOAD_ERR;
    } else {
        if (timeout_sec <= 0) {
            APPLOG(APPLOG_ERR, "{{{CFG}}} timeout sec[%d] is invalid!", timeout_sec);
            goto CF_LOAD_ERR;
        }
        CLIENT_CONF.timeout_sec = timeout_sec;
        APPLOG(APPLOG_ERR, "{{{CFG}}} timeout sec is [%d]", CLIENT_CONF.timeout_sec);
    }

    /* ping interval */
    int ping_interval = 0;
    if (config_lookup_int(&CFG, CF_PING_INTERVAL, &ping_interval) == CONFIG_FALSE) {
        APPLOG(APPLOG_ERR, "{{{CFG}}} ping interval cfg not exist!");
        goto CF_LOAD_ERR;
    } else {
        if (ping_interval <= 0) {
            APPLOG(APPLOG_ERR, "{{{CFG}}} ping interval[%d] is invalid!", ping_interval);
            goto CF_LOAD_ERR;
        }
        CLIENT_CONF.ping_interval = ping_interval;
        APPLOG(APPLOG_ERR, "{{{CFG}}} ping interval is [%d]", CLIENT_CONF.ping_interval);
    }

    /* ping timeout */
    int ping_timeout = 0;
    if (config_lookup_int(&CFG, CF_PING_TIMEOUT, &ping_timeout) == CONFIG_FALSE) {
        APPLOG(APPLOG_ERR, "{{{CFG}}} ping timeout cfg not exist!");
        goto CF_LOAD_ERR;
    } else {
        if (ping_timeout <= 0) {
            APPLOG(APPLOG_ERR, "{{{CFG}}} ping timeout[%d] is invalid!", ping_timeout);
            goto CF_LOAD_ERR;
        }
        CLIENT_CONF.ping_timeout = ping_timeout;
        APPLOG(APPLOG_ERR, "{{{CFG}}} ping timeout is [%d]", CLIENT_CONF.ping_timeout);
    }

    /* pkt_log enable */
    int pkt_log = 0;
    if (config_lookup_int(&CFG, CF_PKT_LOG, &pkt_log) == CONFIG_FALSE) {
        APPLOG(APPLOG_ERR, "{{{CFG}}} pkt log cfg not exist!");
        goto CF_LOAD_ERR;
    } else {
        CLIENT_CONF.pkt_log = (pkt_log == 1 ? 1 : 0);
        APPLOG(APPLOG_ERR, "{{{CFG}}} pkt log is [%s]", CLIENT_CONF.pkt_log == 1 ? "ON" : "OFF");
    }

	/* lb config load */
	if ((setting = config_lookup(&CFG, CF_LB_CONFIG)) == NULL) {
		APPLOG(APPLOG_ERR, "{{{CFG}}} lb config loading fail!!!");
		goto CF_LOAD_ERR;
	} else {
		CLIENT_CONF.lb_config = setting;
		APPLOG(APPLOG_ERR, "{{{CFG}}} lb config loading success");
	}

#ifdef OAUTH
	/* access token list loading */
	if ((setting = config_lookup(&CFG, CF_ACCTOKEN_LIST)) == NULL) {
		APPLOG(APPLOG_ERR, "{{{CFG}}} access token list not exist!");
		goto CF_LOAD_ERR;
	} else {
		int count = config_setting_length(setting);

		APPLOG(APPLOG_ERR, "{{{CFG}}} access token lists are ... (%d)", count);
		for (int i = 0; i < count; i++) {
			config_setting_t *list = config_setting_get_elem(setting, i);

			int id = 0;
			const char *nrf_addr;
			const char *acc_type;
			const char *nf_type;
			const char *nf_instance_id;
			const char *scope;
			struct sockaddr_in sa = {0,};
			struct sockaddr_in6 sa6 = {0,};

			if (config_setting_lookup_int (list, "id", &id) == CONFIG_FALSE) {
				APPLOG(APPLOG_ERR, "{{{CFG}}} acc token list, index(%2d) id NULL!", i);
				continue;
			} else if (id < 1 || id >= MAX_ACC_TOKEN_NUM) {
				APPLOG(APPLOG_ERR, "{{{CFG}}} acc token list, index(%2d) id(%d) invalid!", i, id);
				continue;
			}
			if (config_setting_lookup_string (list, "nrf_addr", &nrf_addr) == CONFIG_FALSE) {
				APPLOG(APPLOG_ERR, "{{{CFG}}} acc token list, index(%2d) nrf_addr NULL!", i);
				continue;
			}
			if (config_setting_lookup_string (list, "acc_type", &acc_type) == CONFIG_FALSE) {
				APPLOG(APPLOG_ERR, "{{{CFG}}} acc token list, index(%2d) acc_type NULL!", i);
				continue;
			} else if (strcmp(acc_type, "SVC") && strcmp(acc_type, "INST")) {
				APPLOG(APPLOG_ERR, "{{{CFG}}} acc token list, index(%2d) acc_type(%s) invalid!", i, acc_type);
				continue;
			}
			if (config_setting_lookup_string (list, "nf_type", &nf_type) == CONFIG_FALSE) {
				APPLOG(APPLOG_ERR, "{{{CFG}}} acc token list, index(%2d) nf_type NULL!", i);
				continue;
			}
			if (config_setting_lookup_string (list, "nf_instance_id", &nf_instance_id) == CONFIG_FALSE) {
				APPLOG(APPLOG_ERR, "{{{CFG}}} acc token list, index(%2d) nf_instance_id NULL!", i);
				continue;
			}
			if (config_setting_lookup_string (list, "scope", &scope) == CONFIG_FALSE) {
				APPLOG(APPLOG_ERR, "{{{CFG}}} acc token list, index(%2d) scope NULL!", i);
				continue;
			}

			char temp_str[INET6_ADDRSTRLEN + 12] = {0,};
			int port = 0;
			int inet_type = 0;
			sprintf(temp_str, nrf_addr);

			if((inet_type = parse_http_addr(temp_str, &sa, &sa6, &port)) < 0) {
				APPLOG(APPLOG_ERR, "{{{CFG}}} acc token list, index(%2d) nrf_addr(%s) invalid!", i, nrf_addr);
				continue;
			}
			
			acc_token_list_t *token_list = NULL;
			if ((token_list = get_token_list(id, 0)) == NULL) {
				APPLOG(APPLOG_ERR, "{{{CFG}}} acc token list, fail to get empty index!");
				continue;
			}

			token_list->token_id = id;
			sprintf(token_list->nrf_addr, "%s", nrf_addr);
			token_list->acc_type =!strcmp(acc_type, "SVC") ? AT_SVC : AT_INST;
			sprintf(token_list->nf_type, "%s", nf_type);
			sprintf(token_list->nf_instance_id, "%s", nf_instance_id);
			sprintf(token_list->scope, "%s", scope);
			token_list->status = TA_INIT;
			memset(&(token_list->due_date), 0x00, sizeof(time_t));
			token_list->inet_type = inet_type;
			memcpy(&(token_list->sa), &sa, sizeof(struct sockaddr_in));
			memcpy(&(token_list->sa6), &sa6, sizeof(struct sockaddr_in6));
			token_list->port = port;
		}
	}
	/* check token_list result */
	print_token_list_raw(ACC_TOKEN_LIST);
#endif

    /* connect list loading */
    if ((setting = config_lookup(&CFG, CF_CONNECT_LIST)) == NULL) {
        APPLOG(APPLOG_ERR, "{{{CFG}}} connect list cfg not exist!!!");
        goto CF_LOAD_ERR;
    } else {
        int count = config_setting_length(setting);
        int i, j, k, index = 0;
		struct sockaddr_in sa;
		struct sockaddr_in6 sa6;

		APPLOG(APPLOG_ERR, "{{{CFG}}} connect lists are ... (%d)", count);
		for (i = 0; i < count; i++) {
			config_setting_t *list = config_setting_get_elem(setting, i);
			APPLOG(APPLOG_ERR, "%3d) %-12s", i, list->name);
		}

		for (i = 0; i < count; i++) {
			config_setting_t *group;
			config_setting_t *list;
			int list_count;
			const char *scheme, *ip, *act;
			const char *type;
			int port;
			int cnt;

			group = config_setting_get_elem(setting, i);
			if (group == NULL)
				continue;
			if (config_setting_lookup_string (group, "type", &type) == CONFIG_FALSE) {
				APPLOG(APPLOG_ERR, "{{{CFG}}} group name (%s) member type is null!", group->name);
				continue;
			}
			list = config_setting_get_member(group, "list");
			if (list == NULL) {
				APPLOG(APPLOG_ERR, "{{{CFG}}} group name (%s) member list is null!", group->name);
				continue;
			}
			list_count = config_setting_length(list);
			list_index = new_list(group->name);

			APPLOG(APPLOG_DEBUG, "{{{CFG}}} %s have %d item", group->name, list_count);

			if (list_count == 0) {
				index ++;
				CONN_LIST[index].index = index;
				CONN_LIST[index].list_index = list_index;
				CONN_LIST[index].item_index = -1;
				CONN_LIST[index].used = 1;
				CONN_LIST[index].conn = 0;
				sprintf(CONN_LIST[index].type, "%s", type);
				sprintf(CONN_LIST[index].host, "%s", group->name);
				continue;
			}

			for (j = 0; j < list_count; j++) {
				config_setting_t *item = config_setting_get_elem(list, j);

				if (config_setting_lookup_string (item, "scheme", &scheme) == CONFIG_FALSE)
					continue;
				else if (strcmp(scheme, "http") && strcmp(scheme, "https")) 
					continue;
				if (config_setting_lookup_string (item, "ip", &ip) == CONFIG_FALSE)
					continue;
				if (config_setting_lookup_int (item, "port", &port) == CONFIG_FALSE)
					continue;
				if (config_setting_lookup_int (item, "cnt", &cnt) == CONFIG_FALSE)
					continue;
				if (config_setting_lookup_string (item, "act", &act) == CONFIG_FALSE)
					continue;
#ifdef OAUTH
				int token_id = 0;
				if (config_setting_lookup_int (item, "token_id", &token_id) == CONFIG_FALSE)
					continue;
#endif
				if (inet_pton(AF_INET, ip, &(sa.sin_addr)))  {
				} else if (inet_pton(AF_INET6, ip, &(sa6.sin6_addr))) {
				} else {
					APPLOG(APPLOG_ERR, "{{{CFG}}} incorrect numeric ip [%s]", ip);
					continue;
				}
				if (port <= 0 || port >= 65535) continue;
				if (cnt <= 0 || cnt > HTTP_MAX_CONN) continue;
				if (!strcmp(act, "ACT") &&!strcmp(act, "DACT")) continue;

#ifdef OAUTH
				APPLOG(APPLOG_ERR, "%3d) %-46s %-6d (x %-3d) %-5s %-5s %-5s %-5d", j, ip, port, cnt, act, scheme, type, token_id);
#else
				APPLOG(APPLOG_ERR, "%3d) %-46s %-6d (x %-3d) %-5s %-5s %-5s", j, ip, port, cnt, act, scheme, type);
#endif

				item_index = new_item(list_index, ip, port);

				/* insert into CONN_LIST */
				for (k = 0; k < cnt; k++) {
					index ++;	// index use from 1 ~
					if (index >= MAX_SVR_NUM) {
						APPLOG(APPLOG_ERR, "{{{CFG}}} connection list exceed max num[%d]!", MAX_SVR_NUM);
						break;
					} 
					CONN_LIST[index].index = index;
					CONN_LIST[index].list_index = list_index;
					CONN_LIST[index].item_index = item_index;
					CONN_LIST[index].used = 1;
					CONN_LIST[index].conn = 0;
					sprintf(CONN_LIST[index].host, "%s", group->name);
					sprintf(CONN_LIST[index].scheme, "%s", scheme);
					sprintf(CONN_LIST[index].type, "%s", type);
					sprintf(CONN_LIST[index].ip, "%s", ip);
					CONN_LIST[index].port = port;
					if (!strcmp(act, "ACT")) {
						CONN_LIST[index].act = 1;
					} else {
						CONN_LIST[index].act = 0;
					}
#ifdef OAUTH
						CONN_LIST[index].token_id = token_id;
#else
						CONN_LIST[index].token_id = 0;
#endif
				}
			}
		}
	}

    APPLOG(APPLOG_ERR, "==============================================================================================");
    APPLOG(APPLOG_ERR, "{{{CFG}}} all cfg loading success");

    config_set_tab_width(&CFG, 4);
    config_write_file(&CFG, CONFIG_PATH);

    return (0);

CF_LOAD_ERR:
    APPLOG(APPLOG_ERR, "==============================================================================================");
    APPLOG(APPLOG_ERR, "{{{CFG}}} cfg loading fail");

	/* if init fail, destroy and program exit */
    config_destroy(&CFG);
    return (-1);
}

/*
	get connect list
	(x) check raw num (it will be checked when insert ip)
	try add to empty slot
	return result
*/
int addcfg_server_hostname(char *hostname, char *type)
{
    config_setting_t *setting;
	int i, found = 0;

    if ((setting = config_lookup(&CFG, CF_CONNECT_LIST)) == NULL) {
        APPLOG(APPLOG_ERR, "connect list cfg not exist");
		goto CF_ADD_SVR_HOSTNAME_ERR;
	} else {
		config_setting_t *group;
		config_setting_t *val;
		int list_index;

		if ((group = config_setting_add(setting, hostname, CONFIG_TYPE_GROUP)) == NULL)
			goto CF_ADD_SVR_HOSTNAME_ERR;
		if ((val = config_setting_add(group, "type", CONFIG_TYPE_STRING)) == NULL)
			goto CF_ADD_SVR_HOSTNAME_ERR;
		config_setting_set_string(val, type);
		if ((val = config_setting_add(group, "list", CONFIG_TYPE_LIST)) == NULL)
			goto CF_ADD_SVR_HOSTNAME_ERR;

		if ((list_index = new_list(group->name)) < 0)
			goto CF_ADD_SVR_HOSTNAME_ERR;

		for (i = 1; i < MAX_SVR_NUM; i++) {
			if (CONN_LIST[i].used == 0) {
                CONN_LIST[i].index = i;
                CONN_LIST[i].list_index = list_index;
                CONN_LIST[i].item_index = -1;
                CONN_LIST[i].used = 1;
                CONN_LIST[i].conn = 0;
                sprintf(CONN_LIST[i].host, "%s", hostname);
				sprintf(CONN_LIST[i].type, "%s", type);
				found = 1;
				break;
			}
		}
	}
	if (!found)
		goto CF_ADD_SVR_HOSTNAME_ERR;

    config_set_tab_width(&CFG, 4);
    config_write_file(&CFG, CONFIG_PATH);

    return (0);

CF_ADD_SVR_HOSTNAME_ERR:
    return (-1);
}

int addcfg_server_ipaddr(int id, char *scheme, char *ipaddr, int port, int conn_cnt, int token_id)
{
    config_setting_t *setting;

    if ((setting = config_lookup(&CFG, CF_CONNECT_LIST)) == NULL) {
        APPLOG(APPLOG_ERR, "%s() connect list cfg not exist", __func__);
		goto CF_ADD_SVR_IPADDR_ERR;
	} else {
		config_setting_t *group;
		const char *type;
		config_setting_t *list;
		int list_count, list_index, item_index, i, cnt = 0;

        if (get_list_name(id) == NULL) {
            goto CF_ADD_SVR_IPADDR_ERR;
        }
		if ((group = config_setting_get_member(setting, get_list_name(id))) == NULL)
			goto CF_ADD_SVR_IPADDR_ERR;
		if (config_setting_lookup_string (group, "type", &type) == CONFIG_FALSE)
			goto CF_ADD_SVR_IPADDR_ERR;

		if ((list = config_setting_get_member(group, "list")) == NULL)
			goto CF_ADD_SVR_IPADDR_ERR;

		/* if first add, delete null row from raw-table */
		list_count = config_setting_length(list);
		if (list_count == 0) {
		 	APPLOG(APPLOG_DEBUG, "%s() check, %s have %d item", __func__, group->name, list_count);
		}

		if ((list_index = get_list(group->name)) < 0)
			goto CF_ADD_SVR_IPADDR_ERR;
		if ((item_index = new_item(list_index, ipaddr, port)) < 0)
			goto CF_ADD_SVR_IPADDR_ERR;

		/* first insert, delete null row */
		if (!list_count) {
			for (i = 1; i < MAX_SVR_NUM; i++) {
				if (CONN_LIST[i].used == 1 && CONN_LIST[i].list_index == list_index) {
					memset(&CONN_LIST[i], 0x00, sizeof(conn_list_t));
				}
			}
		/* not first insert, check duplicate row */ 
		} else {
			for (i = 1; i < MAX_SVR_NUM; i++) {
				if (CONN_LIST[i].used == 1 && CONN_LIST[i].list_index == list_index) {
					if ((!strcmp(CONN_LIST[i].ip, ipaddr)) && (CONN_LIST[i].port == port))
						goto CF_ADD_SVR_IPADDR_ERR;
				}
			}
		}

		config_setting_t *item = config_setting_add(list, NULL,  CONFIG_TYPE_GROUP);
		config_setting_t *val;

		val = config_setting_add(item, "ip", CONFIG_TYPE_STRING);
		config_setting_set_string(val, ipaddr);
		val = config_setting_add(item, "scheme", CONFIG_TYPE_STRING);
		config_setting_set_string(val, scheme);
		val = config_setting_add(item, "port", CONFIG_TYPE_INT);
		config_setting_set_int(val, port);
		val = config_setting_add(item, "cnt", CONFIG_TYPE_INT);
		config_setting_set_int(val, conn_cnt);
		val = config_setting_add(item, "token_id", CONFIG_TYPE_INT);
		config_setting_set_int(val, token_id);
		val = config_setting_add(item, "act", CONFIG_TYPE_STRING);
		config_setting_set_string(val, "DACT");

		for (i = 1; i < MAX_SVR_NUM; i++) {
			if (CONN_LIST[i].used == 0) {
				CONN_LIST[i].index = i;
				CONN_LIST[i].list_index = list_index;
				CONN_LIST[i].item_index = item_index;
				CONN_LIST[i].used = 1;
				CONN_LIST[i].conn = 0;
				sprintf(CONN_LIST[i].host, "%s", group->name);
				sprintf(CONN_LIST[i].type, "%s", type);
				sprintf(CONN_LIST[i].scheme, "%s", scheme);
				sprintf(CONN_LIST[i].ip, "%s", ipaddr);
				CONN_LIST[i].port = port;
				CONN_LIST[i].token_id = token_id;
				CONN_LIST[i].act = 0;
				if (++cnt == conn_cnt) break;
			}
		}
	}

    config_set_tab_width(&CFG, 4);
    config_write_file(&CFG, CONFIG_PATH);

    return (0);

CF_ADD_SVR_IPADDR_ERR:
    return (-1);
}

int actcfg_http_server(int id, int ip_exist, char *ipaddr, int port, int change_to_act)
{ 
    config_setting_t *setting;

    if ((setting = config_lookup(&CFG, CF_CONNECT_LIST)) == NULL) {
        APPLOG(APPLOG_ERR, "%s() connect list cfg not exist", __func__);
        goto CF_ACT_SERVER_ERR;
    } else {
        config_setting_t *group;
        config_setting_t *list;
        int list_count, list_index, item_index, i;
		int found = 0;

		/* if id param receive, but not exist */
        if (get_list_name(id) == NULL) {
            goto CF_ACT_SERVER_ERR;
        }
		if ((group = config_setting_get_member(setting, get_list_name(id))) == NULL) {
            goto CF_ACT_SERVER_ERR;
		} else {
			/* if only id case */
			if (ip_exist <= 0) {
				found = 1;
			}
		}
		list_index = get_list(group->name);

		if ((list = config_setting_get_member(group, "list")) == NULL)
            goto CF_ACT_SERVER_ERR;
		list_count = config_setting_length(list);

		for (i = 0; i < list_count; i++) {
			config_setting_t *item = config_setting_get_elem(list, i);
			config_setting_t *act;
			const char *cf_ip;
			int cf_port;

			if ((act = config_setting_get_member(item, "act")) == NULL) {
				continue; 
			}
			if (config_setting_lookup_string (item, "ip", &cf_ip) == CONFIG_FALSE) {
				continue;
			}
			if (config_setting_lookup_int (item, "port", &cf_port) == CONFIG_FALSE) {
				continue;
			}

			/* not matching case */
			if (ip_exist > 0) {
				if (strcmp(cf_ip, ipaddr) || (cf_port!= port)) {
					continue;
				} else {
					found = 1;
					item_index = get_item(list_index, ipaddr, port);
				}
			}

			/* set config to act */
			if (change_to_act) 
				config_setting_set_string(act, "ACT");
			else
				config_setting_set_string(act, "DACT");
		}

		/* not found case */
		if (!found) {
			goto CF_ACT_SERVER_ERR;
		}

		for (i = 1; i < MAX_SVR_NUM; i++) {
			if (CONN_LIST[i].used == 0) 
				continue;
			if (ip_exist > 0)  {
				if (CONN_LIST[i].list_index!= list_index || CONN_LIST[i].item_index!= item_index)
					continue;
			} else {
				if (CONN_LIST[i].list_index!= list_index)
					continue;
			}
			/* act */
			if (change_to_act)  {
				CONN_LIST[i].act = 1;
			} else {
				intl_req_t intl_req;
				int thrd_idx = CONN_LIST[i].thrd_index;
				CONN_LIST[i].act = 0;

				set_intl_req_msg(&intl_req, CONN_LIST[i].thrd_index, 0, 
						CONN_LIST[i].session_index, CONN_LIST[i].session_id, 0,  HTTP_INTL_SESSION_DEL);

				if (-1 == msgsnd(THRD_WORKER[thrd_idx].msg_id, &intl_req, sizeof(intl_req) - sizeof(long), 0)) {
					APPLOG(APPLOG_ERR, "%s() msgsnd fail!!! (msgq_idx %ld thrd_idx %d session_idx %d)",
							__func__, intl_req.msgq_index, intl_req.tag.thrd_index, intl_req.tag.session_index);
					continue;
				}
			}
		}
	}

    config_set_tab_width(&CFG, 4);
    config_write_file(&CFG, CONFIG_PATH);

    return (0);

CF_ACT_SERVER_ERR:
    return (-1);
}

int chgcfg_server_conn_cnt(int id, char *scheme, char *ipaddr, int port, int conn_cnt, int token_id)
{
    config_setting_t *setting;

    if ((setting = config_lookup(&CFG, CF_CONNECT_LIST)) == NULL) {
        APPLOG(APPLOG_ERR, "%s() connect list cfg not exist", __func__);
        goto CF_CHG_SERVER_CONN_ERR;
    } else {
        config_setting_t *group;
		const char *type;
        config_setting_t *list;
        config_setting_t *item_cnt;
        config_setting_t *item_token;
        int list_count, i, list_index, item_index, cnt = 0;
		int found = 0;
		const char *cf_scheme;
		const char *cf_ip;
		int cf_port;
		int cf_cnt;
		const char *cf_act;

		/* if id param receive, but not exist */
        if (get_list_name(id) == NULL) {
            goto CF_CHG_SERVER_CONN_ERR;
        }
		if ((group = config_setting_get_member(setting, get_list_name(id))) == NULL)
			goto CF_CHG_SERVER_CONN_ERR;
		if (config_setting_lookup_string (group, "type", &type) == CONFIG_FALSE)
			goto CF_CHG_SERVER_CONN_ERR;
		list_index = get_list(group->name);

		if ((list = config_setting_get_member(group, "list")) == NULL)
			goto CF_CHG_SERVER_CONN_ERR;
		list_count = config_setting_length(list);

		for (i = 0; i < list_count; i++) {
			config_setting_t *item = config_setting_get_elem(list, i);

			if (config_setting_lookup_string (item, "scheme", &cf_scheme) == CONFIG_FALSE) {
				continue;
			}
			if (config_setting_lookup_string (item, "ip", &cf_ip) == CONFIG_FALSE) {
				continue;
			}
			if (config_setting_lookup_int (item, "port", &cf_port) == CONFIG_FALSE) {
				continue;
			}
			if (config_setting_lookup_string (item, "act", &cf_act) == CONFIG_FALSE) {
				continue;
			}
			if (config_setting_lookup_int (item, "cnt", &cf_cnt) == CONFIG_FALSE) {
				continue;
			}
			if (!strcmp(cf_ip, ipaddr) && (cf_port == port)) {
				if (!strcmp(cf_act, "ACT"))
					goto CF_CHG_SERVER_CONN_ERR;
				if ((item_cnt = config_setting_get_member(item, "cnt")) == NULL)
					goto CF_CHG_SERVER_CONN_ERR;
				if ((item_token = config_setting_get_member(item, "token_id")) == NULL)
					goto CF_CHG_SERVER_CONN_ERR;
				found = 1;
				item_index = get_item(list_index, ipaddr, port);
				break;
			}
		}
		/* not found case */
		if (!found)
			goto CF_CHG_SERVER_CONN_ERR;

		/* save setting connection count*/
		config_setting_set_int(item_cnt, conn_cnt);
		/* save setting token id*/
		config_setting_set_int(item_token, token_id);

		/* increase case */
		if (conn_cnt > cf_cnt) {
			int gap = conn_cnt - cf_cnt;
			cnt = 0;
			for (i = 1; i < MAX_SVR_NUM; i++) {
				if (CONN_LIST[i].used == 1)  {
					if (CONN_LIST[i].item_index == item_index)  {
						CONN_LIST[i].token_id = token_id;
					}
				} else if (cnt < gap) {
					CONN_LIST[i].index = i;
					CONN_LIST[i].list_index = list_index;
					CONN_LIST[i].item_index = item_index;
					CONN_LIST[i].used = 1;
					CONN_LIST[i].conn = 0;
					sprintf(CONN_LIST[i].host, "%s", group->name);
					sprintf(CONN_LIST[i].type, "%s", type);
					sprintf(CONN_LIST[i].scheme, "%s", scheme);
					sprintf(CONN_LIST[i].ip, "%s", ipaddr);
					CONN_LIST[i].port = port;
					CONN_LIST[i].token_id = token_id;
					CONN_LIST[i].act = 0;
					++cnt;
				}
			}
		} else if (conn_cnt < cf_cnt) {
		/* decrease case */
			int gap = cf_cnt - conn_cnt;
			cnt = 0;
			for (i = MAX_SVR_NUM; i > 0; i--) {
				if (CONN_LIST[i].used == 0) 
					continue;
				if (CONN_LIST[i].list_index == list_index
						&& CONN_LIST[i].item_index == item_index) {
					if (cnt < gap) {
						memset(&CONN_LIST[i], 0x00, sizeof(conn_list_t));
						cnt++;
					} else {
						CONN_LIST[i].token_id = token_id;
					}
				}
			}
		} else {
		/* only change token id */
			for (i = MAX_SVR_NUM; i > 0; i--) {
				if (CONN_LIST[i].used == 0) 
					continue;
				if (CONN_LIST[i].list_index == list_index
						&& CONN_LIST[i].item_index == item_index) {
					CONN_LIST[i].token_id = token_id;
				}
			}
		}
	}

    config_set_tab_width(&CFG, 4);
    config_write_file(&CFG, CONFIG_PATH);

    return (0);

CF_CHG_SERVER_CONN_ERR:
    return (-1);
}

int delcfg_server_ipaddr(int id, char *ipaddr, int port)
{
    config_setting_t *setting;

    if ((setting = config_lookup(&CFG, CF_CONNECT_LIST)) == NULL) {
        APPLOG(APPLOG_ERR, "%s() connect list cfg not exist", __func__);
        goto CF_DEL_SVR_IPADDR_ERR;
    } else {
        config_setting_t *group;
        config_setting_t *list;
        //config_setting_t *item_cnt;
        int i, list_count, list_index, item_index, idx;
		int found = 0;
		const char *cf_ip, *cf_act;
		int cf_port;
		const char *type;

        if (get_list_name(id) == NULL) {
            goto CF_DEL_SVR_IPADDR_ERR;
        }
		if ((group = config_setting_get_member(setting, get_list_name(id))) == NULL)
			goto CF_DEL_SVR_IPADDR_ERR;
		if (config_setting_lookup_string (group, "type", &type) == CONFIG_FALSE)
			goto CF_DEL_SVR_IPADDR_ERR;
		list_index = get_list(group->name);

		if ((list = config_setting_get_member(group, "list")) == NULL)
			goto CF_DEL_SVR_IPADDR_ERR;
		list_count = config_setting_length(list);

		for (i = 0; i < list_count; i++) {
			config_setting_t *item = config_setting_get_elem(list, i);

			if (config_setting_lookup_string (item, "ip", &cf_ip) == CONFIG_FALSE) {
				continue;
			}
			if (config_setting_lookup_int (item, "port", &cf_port) == CONFIG_FALSE) {
				continue;
			}
			if (config_setting_lookup_string (item, "act", &cf_act) == CONFIG_FALSE) {
				continue;
			}
			if (!strcmp(cf_ip, ipaddr) && (cf_port == port)) {
				if (!strcmp(cf_act, "ACT"))
					goto CF_DEL_SVR_IPADDR_ERR;
				found = 1;
				idx = i;
				item_index = get_item(list_index, ipaddr, port);
				break;
			}
		}
		/* not found case */
		if (!found)
			goto CF_DEL_SVR_IPADDR_ERR;

		/* remove item from cfg*/
		del_item(list_index, ipaddr, port);
		config_setting_remove_elem(list, idx); // cfg 의 n 번째 item 을 삭제하기 때문에 idx 별도 사용 주의

		/* remove item from raw list */
		for (i = 0; i < MAX_SVR_NUM; i++) {
			if (CONN_LIST[i].used == 0) 
				continue;
			if (CONN_LIST[i].list_index == list_index
					&& CONN_LIST[i].item_index == item_index) {
				memset(&CONN_LIST[i], 0x00, sizeof(conn_list_t));
			}
		}

		/* if all ipaddr withdraw */
		list_count = config_setting_length(list); {
			APPLOG(APPLOG_DEBUG, "%s() check, name (%s) have item (%d)", __func__, group->name, list_count);
		}
		if (list_count == 0) {
			for (i = 1; i < MAX_SVR_NUM; i++) {
				if (CONN_LIST[i].used == 0) {
					CONN_LIST[i].used = 1;
					CONN_LIST[i].index = i;
					CONN_LIST[i].list_index = list_index;
					CONN_LIST[i].item_index = -1;
					CONN_LIST[i].used = 1;
					CONN_LIST[i].conn = 0;
					sprintf(CONN_LIST[i].host, "%s", group->name);
					sprintf(CONN_LIST[i].type, "%s", type);
					break;
				}
			}
		}
	}

    config_set_tab_width(&CFG, 4);
    config_write_file(&CFG, CONFIG_PATH);

    return (0);

CF_DEL_SVR_IPADDR_ERR:
    return (-1);
}

int delcfg_server_hostname(int id)
{
    config_setting_t *setting;

    if ((setting = config_lookup(&CFG, CF_CONNECT_LIST)) == NULL) {
        APPLOG(APPLOG_ERR, "%s() connect list cfg not exist", __func__);
		goto CF_DEL_SVR_HOSTNAME_ERR;
	} else {
		config_setting_t *group;
		config_setting_t *list;
		int list_count, list_index, i;

        if (get_list_name(id) == NULL) {
            goto CF_DEL_SVR_HOSTNAME_ERR;
        }
		if ((group = config_setting_get_member(setting, get_list_name(id))) == NULL)
			goto CF_DEL_SVR_HOSTNAME_ERR;
		list_index = get_list(group->name);

		if ((list = config_setting_get_member(group, "list")) == NULL)
			goto CF_DEL_SVR_HOSTNAME_ERR;
		list_count = config_setting_length(list);
		if (list_count!= 0) {
		 	APPLOG(APPLOG_DEBUG, "%s() check, %s have %d item\n", __func__, group->name, list_count);
			goto CF_DEL_SVR_HOSTNAME_ERR;
		}

		/* remove list from cfg */
		del_list(group->name);
		config_setting_remove(setting, group->name);

		/* remove item from raw list */
		for (i = 0; i < MAX_SVR_NUM; i++) {
			if (CONN_LIST[i].used == 0) 
				continue;
			if (CONN_LIST[i].list_index == list_index) {
				memset(&CONN_LIST[i], 0x00, sizeof(conn_list_t));
			}
		}
	}

    config_set_tab_width(&CFG, 4);
    config_write_file(&CFG, CONFIG_PATH);

    return (0);

CF_DEL_SVR_HOSTNAME_ERR:
    return (-1);
}
