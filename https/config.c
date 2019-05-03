#include "server.h"

#define CF_SERVER_CONF      "server.cfg"
#define CF_LOG_LEVEL	    "server_cfg.log_level"
#define CF_LISTEN_PORT      "server_cfg.listen_port"
#define CF_MAX_WORKER_NUM   "server_cfg.worker_num"
#define CF_TIMEOUT_SEC      "server_cfg.timeout_sec"
#define CF_CERT_FILE        "server_cfg.oauth_config.cert_file"
#define CF_KEY_FILE         "server_cfg.oauth_config.key_file"
#define CF_CREDENTIAL       "server_cfg.oauth_config.credential"
#define CF_LB_CONFIG        "server_cfg.lb_config"
#define CF_DRELAY_CONFIG	"server_cfg.direct_relay"
#define CF_DRELAY_ENABLE	"server_cfg.direct_relay.enable"
#define CF_CALLBACK_IP		"server_cfg.direct_relay.callback_ip"
#define CF_CALLBACK_PORT	"server_cfg.direct_relay.callback_port"
#define CF_ALLOW_LIST		"allow_list"

extern server_conf SERVER_CONF;
extern allow_list_t  ALLOW_LIST[MAX_LIST_NUM];
extern thrd_context THRD_WORKER[MAX_THRD_NUM];

config_t CFG;
char CONFIG_PATH[256] = {0,};

index_t INDEX[MAX_LIST_NUM];

int init_cfg()
{   
    config_init(&CFG);
    
    /* config path */
#ifndef TEST 
    char *env;
    if ((env = getenv(IV_HOME)) == NULL) {
        sprintf(CONFIG_PATH, "./%s",  CF_SERVER_CONF);
    } else {
        sprintf(CONFIG_PATH, "%s/data/%s", env, CF_SERVER_CONF);
    }
#else
    sprintf(CONFIG_PATH, "./%s", CF_SERVER_CONF);
#endif
    
    /* read config file */
    if (!config_read_file(&CFG, CONFIG_PATH)) {
        fprintf(stderr, "%s:%d - %s\n",
                config_error_file(&CFG),
                config_error_line(&CFG),
                config_error_text(&CFG));
        goto CF_INIT_ERR;
    }
    
    fprintf(stderr, "\nloading [%s]\n", CONFIG_PATH);
    fprintf(stderr, "=====================================================================\n");
    
    config_set_tab_width(&CFG, 4);
    
    return (0);

CF_INIT_ERR:
    fprintf(stderr, "cfg loading fail!!!!\n");
    fprintf(stderr, "\n=====================================================================\n");
    
    config_destroy(&CFG);
    return (-1);
}

#ifdef LOG_APP
int config_load_just_log()
{
    int log_level;

    if (config_lookup_int(&CFG, CF_LOG_LEVEL, &log_level) == CONFIG_FALSE) {
        fprintf(stderr, "config log_level not exist\n");
        goto CF_LOGLEVEL_LOAD_ERR;
    } else {
        if (log_level < APPLOG_NONE || log_level > APPLOG_DEBUG) {
            fprintf(stderr, "config log_level value invalid[%d] (%d~%d)\n",
                    log_level, APPLOG_NONE, APPLOG_DEBUG);
            goto CF_LOGLEVEL_LOAD_ERR;
        }
        SERVER_CONF.log_level = log_level;
        fprintf(stderr, "log_level is [%d]\n", log_level);
    }
    return (0);

CF_LOGLEVEL_LOAD_ERR:
    fprintf(stderr, "\n=====================================================================\n");
    fprintf(stderr, "cfg loading fail\n");

    /* if init fail, destroy and program exit */
    config_destroy(&CFG);
    return (-1);
}
#endif

int config_load()
{
    config_setting_t *setting;
    const char *str;
	int list_index, item_index;

	/* listen port cfg loading */
    if ((setting = config_lookup(&CFG, CF_LISTEN_PORT)) == NULL) {
		APPLOG(APPLOG_ERR, "listen port cfg not exist");
        goto CF_LOAD_ERR;
    } else {
        int count = config_setting_length(setting);
        int i, port, index = 0;

        APPLOG(APPLOG_ERR, "server listen ports are ... (%d)", count);
        for (i = 0; i < count; i++) {
            port =  config_setting_get_int_elem(setting, i);
            if (port == 0 || port >= 65535) continue;
			if (index >= MAX_PORT_NUM) {
				APPLOG(APPLOG_ERR, "server listen port exceed max port num[%d]", MAX_PORT_NUM);
				break;
			} else {
				SERVER_CONF.listen_port[index] = port; index++;
				APPLOG(APPLOG_ERR, " %-7d", port);
			}
        }
		if (index == 0) {
			APPLOG(APPLOG_ERR, "server listen port setting not exist");
			goto CF_LOAD_ERR;
		}
    }
	APPLOG(APPLOG_ERR, "\n");

	/* direct relay cfg loading */
	if ((setting = config_lookup(&CFG, CF_DRELAY_CONFIG)) == NULL ||
			config_lookup_int(&CFG, CF_DRELAY_ENABLE, &SERVER_CONF.dr_enabled) == CONFIG_FALSE ||
			SERVER_CONF.dr_enabled == 0) {
		APPLOG(APPLOG_ERR, "direct_replay section not exist or .enabled not exist or .enabled == 0");
		APPLOG(APPLOG_ERR, "\n");
	} else {
		if (config_lookup_string(&CFG, CF_CALLBACK_IP, &SERVER_CONF.callback_ip) == CONFIG_FALSE) {
			APPLOG(APPLOG_ERR, "direct_relay section .callback_ip not exist");
			goto CF_LOAD_ERR;
		} else {
			APPLOG(APPLOG_ERR, "direct_relay section .callback_ip [%s]", SERVER_CONF.callback_ip);
		}
		if ((setting = config_lookup(&CFG, CF_CALLBACK_PORT)) == NULL) {
			APPLOG(APPLOG_ERR, "direct_relay section .callback_port not exist");
			goto CF_LOAD_ERR;
		} else {
			int count = config_setting_length(setting);

			APPLOG(APPLOG_ERR, "direct relay ports ars ... (%d)", count);
			for (int i = 0; i < count; i++) {
				int port = config_setting_get_int_elem(setting, i);
				if (i >= MAX_PORT_NUM) {
					APPLOG(APPLOG_ERR, "direct relay section .callback_port exceed max[%d]", MAX_PORT_NUM);
					break;
				} else {
					SERVER_CONF.callback_port[i] = port;
					APPLOG(APPLOG_ERR, "  listen [%s:%d] direct relay to fep [%02d]",
							SERVER_CONF.callback_ip, SERVER_CONF.callback_port[i], i);
				}
			}
		}
		APPLOG(APPLOG_ERR, "\n");
	}

    /* worker num cfg loading */
    int worker_num;
    if (config_lookup_int(&CFG, CF_MAX_WORKER_NUM, &worker_num) == CONFIG_FALSE) {
		APPLOG(APPLOG_ERR, "worker num cfg not exist");
        goto CF_LOAD_ERR;
    } else {
		if (worker_num <= 0 || worker_num > MAX_THRD_NUM) { 
			APPLOG(APPLOG_ERR, "worker_num[%d] is zero or exceed max_thrd_num[%d]",
					worker_num, MAX_THRD_NUM);
			goto CF_LOAD_ERR;
		}
		SERVER_CONF.worker_num = worker_num;
		APPLOG(APPLOG_ERR, "worker num is [%d]", worker_num);
    }

    /* timeout sec */
    int timeout_sec = 0;
    if (config_lookup_int(&CFG, CF_TIMEOUT_SEC, &timeout_sec) == CONFIG_FALSE) {
        APPLOG(APPLOG_ERR, "timeout sec cfg not exist");
        goto CF_LOAD_ERR;
    } else {
        if (timeout_sec <= 0) {
            APPLOG(APPLOG_ERR, "timeout sec[%d] is invalid", timeout_sec);
            goto CF_LOAD_ERR;
        }
        SERVER_CONF.timeout_sec = timeout_sec;
        APPLOG(APPLOG_ERR, "timeout sec is [%d]", SERVER_CONF.timeout_sec);
    }

	/* certification file cfg loading */
    if (config_lookup_string(&CFG, CF_CERT_FILE, &str) == CONFIG_FALSE) {
		APPLOG(APPLOG_ERR, "cert file cfg not exist\n");
        goto CF_LOAD_ERR;
    } else {
#ifndef TEST
		sprintf(SERVER_CONF.cert_file, "%s/data/%s", getenv(IV_HOME), str);
#else
		sprintf(SERVER_CONF.cert_file, "%s", str);
#endif
		if (access(SERVER_CONF.cert_file, F_OK) < 0) {
			APPLOG(APPLOG_ERR, "cert file[%s] is not exist", SERVER_CONF.cert_file);
			goto CF_LOAD_ERR;
		}
        APPLOG(APPLOG_ERR, "cert file name is [%s]", SERVER_CONF.cert_file);
    }

	/* key file cfg loading */
    if (config_lookup_string(&CFG, CF_KEY_FILE, &str) == CONFIG_FALSE) {
		APPLOG(APPLOG_ERR, "key file cfg not exist");
        goto CF_LOAD_ERR;
    } else {
#ifndef TEST
		sprintf(SERVER_CONF.key_file, "%s/data/%s", getenv(IV_HOME), str);
#else
		sprintf(SERVER_CONF.key_file, "%s", str);
#endif
		if (access(SERVER_CONF.key_file, F_OK) < 0) {
			APPLOG(APPLOG_ERR, "key file[%s] is not exist", SERVER_CONF.key_file);
			goto CF_LOAD_ERR;
		}
        APPLOG(APPLOG_ERR, "key file name is  [%s]", SERVER_CONF.key_file);
    }

    /* lb config load */
    if ((setting = config_lookup(&CFG, CF_LB_CONFIG)) == NULL) {
        APPLOG(APPLOG_ERR, "lb config loading fail (nok)");
        goto CF_LOAD_ERR;
    } else {
        SERVER_CONF.lb_config = setting;
        APPLOG(APPLOG_ERR, "lb config loading success (ok)");
    }

#ifdef OAUTH
	/* oauth 2.0 secret key */
	if (config_lookup_string(&CFG, CF_CREDENTIAL, &str) == CONFIG_FALSE) {
		APPLOG(APPLOG_ERR, "oauth2.0 credential not exist");
		goto CF_LOAD_ERR;
	} else {
		sprintf(SERVER_CONF.credential, "%s", str);
		APPLOG(APPLOG_ERR, "oauth2.0 credential is [%s]", SERVER_CONF.credential);
	}
#endif

	/* allow list loading */
    if ((setting = config_lookup(&CFG, CF_ALLOW_LIST)) == NULL) {
		APPLOG(APPLOG_ERR, "allow list cfg not exist");
        goto CF_LOAD_ERR;
    } else {
        int count = config_setting_length(setting);
		int i, j, index = 0;
		struct sockaddr_in sa;
		struct sockaddr_in6 sa6;

        APPLOG(APPLOG_ERR, "allow lists are ... (%d)", count);
        for (i = 0; i < count; i++) {
            config_setting_t *group;
            config_setting_t *list;
            int list_count;
            const char *ip, *act;
            const char *type;
            int max;

			group = config_setting_get_elem(setting, i);
			if (group == NULL)
				continue;
			if (config_setting_lookup_string (group, "type", &type) == CONFIG_FALSE) {
				APPLOG(APPLOG_ERR, "group name (%s) member type is null", group->name);
				continue;
			}
            list = config_setting_get_member(group, "list");
			if (list == NULL) {
				APPLOG(APPLOG_ERR, "group name (%s) member list is null", group->name);
				continue;
			}
            list_count = config_setting_length(list);
            list_index = new_list(group->name);

            APPLOG(APPLOG_ERR, "%s have %d item", group->name, list_count);

            if (list_count == 0) {
                index ++;
                ALLOW_LIST[index].index = index;
                ALLOW_LIST[index].used = 1;
                ALLOW_LIST[index].list_index = list_index;
                ALLOW_LIST[index].item_index = -1;
                sprintf(ALLOW_LIST[index].host, "%s", group->name);
                sprintf(ALLOW_LIST[index].type, "%s", type);
                sprintf(ALLOW_LIST[index].ip, "%s", "-");
				ALLOW_LIST[index].act = 0;
                ALLOW_LIST[index].max = 0;
                ALLOW_LIST[index].curr = 0;
				ALLOW_LIST[index].auth_act = 0;
                continue;
            }

            for (j = 0; j < list_count; j++) {
                config_setting_t *item = config_setting_get_elem(list, j);

				if (config_setting_lookup_string (item, "ip", &ip) == CONFIG_FALSE)
					continue;
				if (config_setting_lookup_int (item, "max", &max) == CONFIG_FALSE)
					continue;
				if (config_setting_lookup_string (item, "act", &act) == CONFIG_FALSE)
					continue;
#ifdef OAUTH
				int auth_act = 0;
				if (config_setting_lookup_int (item, "auth_act", &auth_act) == CONFIG_FALSE)
					continue;
#endif
                if (inet_pton(AF_INET, ip, &(sa.sin_addr)))  {
                } else if (inet_pton(AF_INET6, ip, &(sa6.sin6_addr))) {
                } else {
                    APPLOG(APPLOG_ERR, "DBG, incorrect numeric ip [%s]", ip);
                    continue;
                }
				if (max <= 0 || max >= 65535) continue;
				if (!strcmp(act, "ACT") && !strcmp(act, "DACT")) continue;

				APPLOG(APPLOG_ERR, "%d) %-46s (max) %-4d %s", j, ip, max, act);

				item_index = new_item(list_index, ip, 0);

				index++; // from 1 ~
				if (index >= MAX_LIST_NUM) {
					APPLOG(APPLOG_ERR, "allow list exceed max num[%d]", MAX_LIST_NUM);
					break;
				}
                ALLOW_LIST[index].index = index;
                ALLOW_LIST[index].used = 1;
                ALLOW_LIST[index].list_index = list_index;
                ALLOW_LIST[index].item_index = item_index;
                sprintf(ALLOW_LIST[index].host, "%s", group->name);
                sprintf(ALLOW_LIST[index].type, "%s", type);
				sprintf(ALLOW_LIST[index].ip, "%s", ip);
				if (!strcmp(act, "ACT")) {
					ALLOW_LIST[index].act = 1;
				} else {
					ALLOW_LIST[index].act = 0;
				}
                ALLOW_LIST[index].max = max;
#ifdef OAUTH
                ALLOW_LIST[index].auth_act = auth_act;
#endif
                ALLOW_LIST[index].curr = 0;
			}
		}
	}

    APPLOG(APPLOG_ERR, "=====================================================================");
    APPLOG(APPLOG_ERR, "all cfg loading success\n");

	config_set_tab_width(&CFG, 4);
	config_write_file(&CFG, CONFIG_PATH);

    return (0);

CF_LOAD_ERR:
    APPLOG(APPLOG_ERR, "=====================================================================");
    APPLOG(APPLOG_ERR, "cfg loading fail");

	/* if init fail, destry and program exit */
    config_destroy(&CFG);
    return (-1);
}
int addcfg_client_hostname(char *hostname, char *type)
{
    config_setting_t *setting;
    int i, found = 0;

    if ((setting = config_lookup(&CFG, CF_ALLOW_LIST)) == NULL) {
        APPLOG(APPLOG_ERR, "allow list cfg not exist");
        goto CF_ADD_CLI_HOSTNAME_ERR;
    } else {
        config_setting_t *group;
		config_setting_t *val;
        int list_index;

        if ((group = config_setting_add(setting, hostname, CONFIG_TYPE_GROUP)) == NULL)
            goto CF_ADD_CLI_HOSTNAME_ERR;
        if ((val = config_setting_add(group, "type", CONFIG_TYPE_STRING)) == NULL)
            goto CF_ADD_CLI_HOSTNAME_ERR;
        config_setting_set_string(val, type);
        if ((val = config_setting_add(group, "list", CONFIG_TYPE_LIST)) == NULL)
            goto CF_ADD_CLI_HOSTNAME_ERR;

        if ((list_index = new_list(group->name)) < 0)
            goto CF_ADD_CLI_HOSTNAME_ERR;

        for (i = 1; i < MAX_LIST_NUM; i++) {
            if (ALLOW_LIST[i].used == 0) {
                ALLOW_LIST[i].index = i;
                ALLOW_LIST[i].used = 1;
                ALLOW_LIST[i].list_index = list_index;
                ALLOW_LIST[i].item_index = -1;
                sprintf(ALLOW_LIST[i].host, "%s", hostname);
                sprintf(ALLOW_LIST[i].type, "%s", type);
                ALLOW_LIST[i].act = 0;
                ALLOW_LIST[i].max = 0;
                ALLOW_LIST[i].curr = 0;
                found = 1;
                break;
            }
        }
    }
    if (!found)
        goto CF_ADD_CLI_HOSTNAME_ERR;

    config_set_tab_width(&CFG, 4);
    config_write_file(&CFG, CONFIG_PATH);

    return (0);

CF_ADD_CLI_HOSTNAME_ERR:
    return (-1);
}

int addcfg_client_ipaddr(int id, char *ipaddr, int max)
{
    config_setting_t *setting;

    if ((setting = config_lookup(&CFG, CF_ALLOW_LIST)) == NULL) {
        APPLOG(APPLOG_ERR, "allow list cfg not exist");
		goto CF_ADD_CLI_IPADDR_ERR;
	} else {
		config_setting_t *group;
		const char *type;
		config_setting_t *list;
		int list_count, list_index, item_index, i;

		/* if id param receive, but not exist */
        if (get_list_name(id) == NULL) {
			goto CF_ADD_CLI_IPADDR_ERR;
        }
		if ((group = config_setting_get_member(setting, get_list_name(id))) == NULL)
			goto CF_ADD_CLI_IPADDR_ERR;
		if (config_setting_lookup_string (group, "type", &type) == CONFIG_FALSE)
			goto CF_ADD_CLI_IPADDR_ERR;

		if ((list = config_setting_get_member(group, "list")) == NULL)
			goto CF_ADD_CLI_IPADDR_ERR;

		/* if first add, delete null row from raw-table */
		list_count = config_setting_length(list);
		if (list_count == 0) {
		 	APPLOG(APPLOG_ERR, "%s have %d item", group->name, list_count);
		}

		if ((list_index = get_list(group->name)) < 0)
			goto CF_ADD_CLI_IPADDR_ERR;
		if ((item_index = new_item(list_index, ipaddr, 0)) < 0)
			goto CF_ADD_CLI_IPADDR_ERR;

		/* first insert, delete null row */
		if (!list_count) {
			for (i = 1; i < MAX_LIST_NUM; i++) {
				if (ALLOW_LIST[i].used == 1 && ALLOW_LIST[i].list_index == list_index) {
					memset(&ALLOW_LIST[i], 0x00, sizeof(allow_list_t));
				}
			}
		/* not first insert, check duplicate row */ 
		} else {
			for (i = 1; i < MAX_LIST_NUM; i++) {
				if (ALLOW_LIST[i].used == 1 && ALLOW_LIST[i].list_index == list_index) {
					if (!strcmp(ALLOW_LIST[i].ip, ipaddr))
						goto CF_ADD_CLI_IPADDR_ERR;
				}
			}
		}

		config_setting_t *item = config_setting_add(list, NULL,  CONFIG_TYPE_GROUP);
		config_setting_t *val;

		val = config_setting_add(item, "ip", CONFIG_TYPE_STRING);
		config_setting_set_string(val, ipaddr);
		val = config_setting_add(item, "max", CONFIG_TYPE_INT);
		config_setting_set_int(val, max);
		val = config_setting_add(item, "act", CONFIG_TYPE_STRING);
		config_setting_set_string(val, "DACT");
		val = config_setting_add(item, "auth_act", CONFIG_TYPE_INT);
		config_setting_set_int(val, 0);

		for (i = 1; i < MAX_LIST_NUM; i++) {
			if (ALLOW_LIST[i].used == 0) {
				ALLOW_LIST[i].index = i;
				ALLOW_LIST[i].used = 1;
				ALLOW_LIST[i].list_index = list_index;
				ALLOW_LIST[i].item_index = item_index;
				sprintf(ALLOW_LIST[i].host, "%s", group->name);
				sprintf(ALLOW_LIST[i].type, "%s", type);
				sprintf(ALLOW_LIST[i].ip, "%s", ipaddr);
				ALLOW_LIST[i].act = 0;
				ALLOW_LIST[i].max = max;
				ALLOW_LIST[i].curr = 0;
				break;
			}
		}
	}

    config_set_tab_width(&CFG, 4);
    config_write_file(&CFG, CONFIG_PATH);

    return (0);

CF_ADD_CLI_IPADDR_ERR:
    return (-1);
}

int actcfg_http_client(int id, int ip_exist, char *ipaddr, int change_to_act)
{ 
    config_setting_t *setting;

    if ((setting = config_lookup(&CFG, CF_ALLOW_LIST)) == NULL) {
        APPLOG(APPLOG_ERR, "allow list cfg not exist");
        goto CF_ACT_CLIENT_ERR;
    } else {
        config_setting_t *group;
        config_setting_t *list;
        int list_count, list_index, item_index, i, j;
		int found = 0;

		/* if id param receive, but not exist */
        if (get_list_name(id) == NULL) {
			goto CF_ACT_CLIENT_ERR;
        }
		if ((group = config_setting_get_member(setting, get_list_name(id))) == NULL) {
            goto CF_ACT_CLIENT_ERR;
		} else {
			/* if only id case */
			if (ip_exist <= 0) {
				found = 1;
			}
		}
		list_index = get_list(group->name);

		if ((list = config_setting_get_member(group, "list")) == NULL)
			goto CF_ACT_CLIENT_ERR;
		list_count = config_setting_length(list);

		for (i = 0; i < list_count; i++) {
			config_setting_t *item = config_setting_get_elem(list, i);
			config_setting_t *act;
			const char *cf_ip;

			if ((act = config_setting_get_member(item, "act")) == NULL) {
				continue; 
			}
			if (config_setting_lookup_string (item, "ip", &cf_ip) == CONFIG_FALSE) {
				continue;
			}

			/* not matching case */
			if (ip_exist > 0) {
				if (strcmp(cf_ip, ipaddr)) {
					continue;
				} else {
					found = 1;
					item_index = get_item(list_index, ipaddr, 0);
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
			goto CF_ACT_CLIENT_ERR;
		}

		for (i = 1; i < MAX_LIST_NUM; i++) {
			if (ALLOW_LIST[i].used == 0) 
				continue;
			if (ip_exist > 0)  {
				if (ALLOW_LIST[i].list_index != list_index || ALLOW_LIST[i].item_index != item_index)
					continue;
			} else {
				if (ALLOW_LIST[i].list_index != list_index)
					continue;
			}
			/* act */
			if (change_to_act)  {
				ALLOW_LIST[i].act = 1;
			} else {
				ALLOW_LIST[i].act = 0;
				intl_req_t intl_req;
				int thrd_idx;
				for (j = 0; j < MAX_LIST_NUM; j++) {
					if (ALLOW_LIST[i].client[j].occupied != 1)
						continue;
					APPLOG(APPLOG_ERR, "DBG delete thrd %d sess %d",
						ALLOW_LIST[i].client[j].thrd_idx, ALLOW_LIST[i].client[j].sess_idx);
					thrd_idx = ALLOW_LIST[i].client[j].thrd_idx;
					set_intl_req_msg(&intl_req, ALLOW_LIST[i].client[j].thrd_idx, 0,
							ALLOW_LIST[i].client[j].sess_idx, ALLOW_LIST[i].client[j].session_id, 0, HTTP_INTL_SESSION_DEL);
					if (-1 == msgsnd(THRD_WORKER[thrd_idx].msg_id, &intl_req, sizeof(intl_req) - sizeof(long), 0)) {
						APPLOG(APPLOG_ERR, "some err in %s msgq_idx %ld thrd_idx %d session_idx %d ",
								__func__, intl_req.msgq_index, intl_req.tag.thrd_index, intl_req.tag.session_index);
						continue;
					}
				}
			}
		}
	}

    config_set_tab_width(&CFG, 4);
    config_write_file(&CFG, CONFIG_PATH);

    return (0);

CF_ACT_CLIENT_ERR:
    return (-1);
}

int chgcfg_client_max_cnt(int id, char *ipaddr, int max)
{
    config_setting_t *setting;

    if ((setting = config_lookup(&CFG, CF_ALLOW_LIST)) == NULL) {
        APPLOG(APPLOG_ERR, "allow list cfg not exist");
        goto CF_CHG_CLIENT_MAX_ERR;
    } else {
		config_setting_t *group;
		const char *type;
        config_setting_t *list;
        config_setting_t *item_max;
        int list_count, i, list_index, item_index;
		int found = 0;
		const char *cf_ip;
		int cf_max;
		const char *cf_act;

		/* if id param receive, but not exist */
        if (get_list_name(id) == NULL) {
			goto CF_CHG_CLIENT_MAX_ERR;
        }
		if ((group = config_setting_get_member(setting, get_list_name(id))) == NULL)
			goto CF_CHG_CLIENT_MAX_ERR;
		if (config_setting_lookup_string (group, "type", &type) == CONFIG_FALSE)
			goto CF_CHG_CLIENT_MAX_ERR;
		list_index = get_list(group->name);

		if ((list = config_setting_get_member(group, "list")) == NULL)
			goto CF_CHG_CLIENT_MAX_ERR;
		list_count = config_setting_length(list);

		for (i = 0; i < list_count; i++) {
			config_setting_t *item = config_setting_get_elem(list, i);

			if (config_setting_lookup_string (item, "ip", &cf_ip) == CONFIG_FALSE) {
				continue;
			}
			if (config_setting_lookup_string (item, "act", &cf_act) == CONFIG_FALSE) {
				continue;
			}
			if (config_setting_lookup_int (item, "max", &cf_max) == CONFIG_FALSE) {
				continue;
			}
			if (!strcmp(cf_ip, ipaddr)) {
				if (!strcmp(cf_act, "ACT"))
					goto CF_CHG_CLIENT_MAX_ERR;
				if ((item_max = config_setting_get_member(item, "max")) == NULL)
					goto CF_CHG_CLIENT_MAX_ERR;
				found = 1;
				item_index = get_item(list_index, ipaddr, 0);
				break;
			}
		}
		/* not found case */
		if (!found)
			goto CF_CHG_CLIENT_MAX_ERR;
		if (cf_max == max)
			goto CF_CHG_CLIENT_MAX_ERR;

		/* save setting */
		config_setting_set_int(item_max, max);

		/* change max */
		for (i = MAX_LIST_NUM; i > 0; i--) {
			if (ALLOW_LIST[i].used == 0) 
				continue;
			if (ALLOW_LIST[i].list_index == list_index
					&& ALLOW_LIST[i].item_index == item_index) {
				ALLOW_LIST[i].max = max;
			}
		}
	}

    config_set_tab_width(&CFG, 4);
    config_write_file(&CFG, CONFIG_PATH);

    return (0);

CF_CHG_CLIENT_MAX_ERR:
    return (-1);
}

int delcfg_client_ipaddr(int id, char *ipaddr)
{
    config_setting_t *setting;
    //const char *str;

    if ((setting = config_lookup(&CFG, CF_ALLOW_LIST)) == NULL) {
        APPLOG(APPLOG_ERR, "allow list cfg not exist");
        goto CF_DEL_CLI_IPADDR_ERR;
    } else {
		config_setting_t *group;
        config_setting_t *list;
        int i, list_count, list_index, item_index, idx;
		int found = 0;
		const char *cf_ip, *cf_act;
		const char *type;

        if (get_list_name(id) == NULL) {
			goto CF_DEL_CLI_IPADDR_ERR;
        }
		if ((group = config_setting_get_member(setting, get_list_name(id))) == NULL)
			goto CF_DEL_CLI_IPADDR_ERR;
		if (config_setting_lookup_string (group, "type", &type) == CONFIG_FALSE)
			goto CF_DEL_CLI_IPADDR_ERR;
		list_index = get_list(group->name);

		if ((list = config_setting_get_member(group, "list")) == NULL)
			goto CF_DEL_CLI_IPADDR_ERR;
		list_count = config_setting_length(list);

		for (i = 0; i < list_count; i++) {
			config_setting_t *item = config_setting_get_elem(list, i);

			if (config_setting_lookup_string (item, "ip", &cf_ip) == CONFIG_FALSE) {
				continue;
			}
			if (config_setting_lookup_string (item, "act", &cf_act) == CONFIG_FALSE) {
				continue;
			}
			if (!strcmp(cf_ip, ipaddr)) {
				if (!strcmp(cf_act, "ACT"))
					goto CF_DEL_CLI_IPADDR_ERR;
				found = 1;
				idx = i;
				item_index = get_item(list_index, ipaddr, 0);
				break;
			}
		}
		/* not found case */
		if (!found)
			goto CF_DEL_CLI_IPADDR_ERR;

		/* remove item from cfg*/
		del_item(list_index, ipaddr, 0);
		config_setting_remove_elem(list, idx); // cfg 의 n 번째 item 을 삭제하기 때문에 idx 별도 사용 주의

		/* remove item from raw list */
		for (i = 0; i < MAX_LIST_NUM; i++) {
			if (ALLOW_LIST[i].used == 0) 
				continue;
			if (ALLOW_LIST[i].list_index == list_index
					&& ALLOW_LIST[i].item_index == item_index) {
				memset(&ALLOW_LIST[i], 0x00, sizeof(allow_list_t));
			}
		}

		/* if all ipaddr withdraw */
		list_count = config_setting_length(list); {
			APPLOG(APPLOG_ERR, "name (%s) have item (%d)", group->name, list_count);
		}
		if (list_count == 0) {
			for (i = 1; i < MAX_LIST_NUM; i++) {
				if (ALLOW_LIST[i].used == 0) {
					ALLOW_LIST[i].used = 1;
					ALLOW_LIST[i].index = i;
					ALLOW_LIST[i].list_index = list_index;
					ALLOW_LIST[i].item_index = -1;
					sprintf(ALLOW_LIST[i].host, "%s", group->name);
					sprintf(ALLOW_LIST[i].type, "%s", type);
					sprintf(ALLOW_LIST[i].ip, "%s", "-");
					ALLOW_LIST[i].act = 0;
					ALLOW_LIST[i].max = 0;
					ALLOW_LIST[i].curr = 0;
					break;
				}
			}
		}
	}

    config_set_tab_width(&CFG, 4);
    config_write_file(&CFG, CONFIG_PATH);

    return (0);

CF_DEL_CLI_IPADDR_ERR:
    return (-1);
}

int delcfg_client_hostname(int id)
{
    config_setting_t *setting;

    if ((setting = config_lookup(&CFG, CF_ALLOW_LIST)) == NULL) {
        APPLOG(APPLOG_ERR, "allow list cfg not exist");
        goto CF_DEL_CLI_HOSTNAME_ERR;
    } else {
        config_setting_t *group;
        config_setting_t *list;
        int list_count, list_index, i;

        if (get_list_name(id) == NULL) {
			goto CF_DEL_CLI_HOSTNAME_ERR;
        }
        if ((group = config_setting_get_member(setting, get_list_name(id))) == NULL)
            goto CF_DEL_CLI_HOSTNAME_ERR;
        list_index = get_list(group->name);

		if ((list = config_setting_get_member(group, "list")) == NULL)
            goto CF_DEL_CLI_HOSTNAME_ERR;
        list_count = config_setting_length(list);
        if (list_count != 0) {
            APPLOG(APPLOG_ERR, "%s have %d item", group->name, list_count);
            goto CF_DEL_CLI_HOSTNAME_ERR;
        }

        /* remove list from cfg */
        del_list(group->name);
        config_setting_remove(setting, group->name);

        /* remove item from raw list */
        for (i = 0; i < MAX_LIST_NUM; i++) {
            if (ALLOW_LIST[i].used == 0)
                continue;
            if (ALLOW_LIST[i].list_index == list_index) {
                memset(&ALLOW_LIST[i], 0x00, sizeof(allow_list_t));
            }
        }
    }

    config_set_tab_width(&CFG, 4);
    config_write_file(&CFG, CONFIG_PATH);

    return (0);

CF_DEL_CLI_HOSTNAME_ERR:
    return (-1);
}
