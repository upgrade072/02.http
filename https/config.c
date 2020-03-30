#include "server.h"

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
    char *env;
    if ((env = getenv(IV_HOME)) == NULL) {
        sprintf(CONFIG_PATH, "./%s",  CF_SERVER_CONF);
    } else {
        sprintf(CONFIG_PATH, "%s/data/STACK/HTTP/%s", env, CF_SERVER_CONF);
    }
    
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
		SERVER_CONF.log_level = log_level;
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
    const char *str;
	int list_index, item_index;

    /* debug mode */
    int debug_mode = 0;
    if (config_lookup_int(&CFG, CF_DEBUG_MODE, &debug_mode) == CONFIG_FALSE) {
		APPLOG(APPLOG_ERR, "{{{CFG}}} debug mode cfg not exist!");
        goto CF_LOAD_ERR;
    } else {
        SERVER_CONF.debug_mode = (debug_mode == 1 ? 1: 0);
        APPLOG(APPLOG_ERR, "{{{CFG}}} debug mode is [%s]", SERVER_CONF.debug_mode == 1 ? "ON" : "OFF");
    }

	/* HTTPS listen port cfg loading */
    if ((setting = config_lookup(&CFG, CF_TLS_LISTEN_PORT)) == NULL) {
		APPLOG(APPLOG_ERR, "{{{CFG}}} https listen port cfg not exist!");
        goto CF_LOAD_ERR;
    } else {
        int count = config_setting_length(setting);
        int i, index = 0;

        APPLOG(APPLOG_ERR, "{{{CFG}}} server https listen ports are ... (%d)", count);
        for (i = 0; i < count; i++) {
            int port =  config_setting_get_int_elem(setting, i);
            if (port == 0 || port >= 65535) continue;
			if (index >= MAX_PORT_NUM) {
				APPLOG(APPLOG_ERR, "{{{CFG}}} server https listen port exceed max port num[%d]!", MAX_PORT_NUM);
				break;
			} else {
				SERVER_CONF.https_listen_port[index] = port; index++;
				APPLOG(APPLOG_ERR, " %-7d", port);
			}
        }
		if (index == 0) {
			APPLOG(APPLOG_ERR, "{{{CFG}}} server https listen port setting not exist!");
			//goto CF_LOAD_ERR;
		}
    }
	/* HTTP listen port cfg loading */
    if ((setting = config_lookup(&CFG, CF_TCP_LISTEN_PORT)) == NULL) {
		APPLOG(APPLOG_ERR, "{{{CFG}}} http listen port cfg not exist!");
        goto CF_LOAD_ERR;
    } else {
        int count = config_setting_length(setting);
        int i, index = 0;

        APPLOG(APPLOG_ERR, "{{{CFG}}} server http listen ports are ... (%d)", count);
        for (i = 0; i < count; i++) {
            int port =  config_setting_get_int_elem(setting, i);
            if (port == 0 || port >= 65535) continue;
			if (index >= MAX_PORT_NUM) {
				APPLOG(APPLOG_ERR, "{{{CFG}}} server http listen port exceed max port num[%d]!", MAX_PORT_NUM);
				break;
			} else {
				SERVER_CONF.http_listen_port[index] = port; index++;
				APPLOG(APPLOG_ERR, " %-7d", port);
			}
        }
		if (index == 0) {
			APPLOG(APPLOG_ERR, "{{{CFG}}} server http listen port setting not exist!");
			//goto CF_LOAD_ERR;
		}
    }

	/* direct relay cfg loading */
	if ((setting = config_lookup(&CFG, CF_DRELAY_CONFIG)) == NULL ||
			config_lookup_int(&CFG, CF_DRELAY_ENABLE, &SERVER_CONF.dr_enabled) == CONFIG_FALSE ||
			SERVER_CONF.dr_enabled == 0) {
		APPLOG(APPLOG_ERR, "{{{CFG}}} direct_replay section not exist or .enabled not exist or .enabled == 0!");
	} else {
		if (config_lookup_string(&CFG, CF_CALLBACK_IP, &SERVER_CONF.callback_ip) == CONFIG_FALSE) {
			APPLOG(APPLOG_ERR, "{{{CFG}}} direct_relay section .callback_ip not exist!");
			goto CF_LOAD_ERR;
		} else {
			APPLOG(APPLOG_ERR, "{{{CFG}}} direct_relay section .callback_ip [%s]", SERVER_CONF.callback_ip);
		}
		if ((setting = config_lookup(&CFG, CF_CALLBACK_TLS_PORT)) == NULL) {
			APPLOG(APPLOG_ERR, "{{{CFG}}} direct_relay section .callback_port_tls not exist!");
			goto CF_LOAD_ERR;
		} else {
			int count = config_setting_length(setting);

			APPLOG(APPLOG_ERR, "{{{CFG}}} direct relay ports (tls) ars ... (%d)", count);
			for (int i = 0; i < count; i++) {
				int port = config_setting_get_int_elem(setting, i);
				if (i >= MAX_PORT_NUM) {
					APPLOG(APPLOG_ERR, "{{{CFG}}} direct relay section .callback_port_tls exceed max[%d]!", MAX_PORT_NUM);
					break;
				} else {
					SERVER_CONF.callback_port_tls[i] = port;
					APPLOG(APPLOG_ERR, "  listen [%s:%d] direct relay to fep [%02d]",
							SERVER_CONF.callback_ip, SERVER_CONF.callback_port_tls[i], i);
				}
			}
		}
		if ((setting = config_lookup(&CFG, CF_CALLBACK_TCP_PORT)) == NULL) {
			APPLOG(APPLOG_ERR, "{{{CFG}}} direct_relay section .callback_port_tcp not exist!");
			goto CF_LOAD_ERR;
		} else {
			int count = config_setting_length(setting);

			APPLOG(APPLOG_ERR, "{{{CFG}}} direct relay ports (tcp) ars ... (%d)", count);
			for (int i = 0; i < count; i++) {
				int port = config_setting_get_int_elem(setting, i);
				if (i >= MAX_PORT_NUM) {
					APPLOG(APPLOG_ERR, "{{{CFG}}} direct relay section .callback_port_tcp exceed max[%d]!", MAX_PORT_NUM);
					break;
				} else {
					SERVER_CONF.callback_port_tcp[i] = port;
					APPLOG(APPLOG_ERR, "  listen [%s:%d] direct relay to fep [%02d]",
							SERVER_CONF.callback_ip, SERVER_CONF.callback_port_tcp[i], i);
				}
			}
		}
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
		SERVER_CONF.worker_num = worker_num;
		APPLOG(APPLOG_ERR, "{{{CFG}}} worker num is [%d]", worker_num);
    }

    /* worker shmkey base */
    int worker_shmkey;
    if (config_lookup_int(&CFG, CF_WORKER_SHMKEY, &worker_shmkey) == CONFIG_FALSE) {
        APPLOG(APPLOG_ERR, "{{{CFG}}} worker shmkey base cfg not exist!");
        goto CF_LOAD_ERR;
    } else {
        SERVER_CONF.worker_shmkey = worker_shmkey;
        APPLOG(APPLOG_ERR, "{{{CFG}}} worker shmkey is [0x%x]", SERVER_CONF.worker_shmkey);
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
        SERVER_CONF.timeout_sec = timeout_sec;
        APPLOG(APPLOG_ERR, "{{{CFG}}} timeout sec is [%d]", SERVER_CONF.timeout_sec);
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
        SERVER_CONF.ping_interval = ping_interval;
        APPLOG(APPLOG_ERR, "{{{CFG}}} ping interval is [%d]", SERVER_CONF.ping_interval);
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
        SERVER_CONF.ping_timeout = ping_timeout;
        APPLOG(APPLOG_ERR, "{{{CFG}}} ping timeout is [%d]", SERVER_CONF.ping_timeout);
    }

    /* ping event_ms */
    int ping_event_ms = 0;
    if (config_lookup_int(&CFG, CF_PING_EVENT_MS, &ping_event_ms) == CONFIG_FALSE) {
        APPLOG(APPLOG_ERR, "{{{CFG}}} ping event_ms cfg not exist!");
        goto CF_LOAD_ERR;
    } else {
        if (ping_event_ms <= 0) {
            APPLOG(APPLOG_ERR, "{{{CFG}}} ping event_ms[%d] is lower than 0 it means no event!", ping_event_ms);
        }
        SERVER_CONF.ping_event_ms = ping_event_ms;
        APPLOG(APPLOG_ERR, "{{{CFG}}} ping event_ms is [%d]", SERVER_CONF.ping_event_ms);
    }

    /* ping event_code */
    int ping_event_code = 0;
    if (config_lookup_int(&CFG, CF_PING_EVENT_CODE, &ping_event_code) == CONFIG_FALSE) {
        APPLOG(APPLOG_ERR, "{{{CFG}}} ping event_code cfg not exist!");
        goto CF_LOAD_ERR;
    } else {
        if (ping_event_code <= 0) {
            APPLOG(APPLOG_ERR, "{{{CFG}}} ping event_code[%d] is lower than 0 it means no event!", ping_event_code);
        }
        SERVER_CONF.ping_event_code = ping_event_code;
        APPLOG(APPLOG_ERR, "{{{CFG}}} ping event_code is [%d]", SERVER_CONF.ping_event_code);
    }

    /* cert event_code */
    int cert_event_code = 0;
    if (config_lookup_int(&CFG, CF_CERT_EVENT_CODE, &cert_event_code) == CONFIG_FALSE) {
        APPLOG(APPLOG_ERR, "{{{CFG}}} cert event_code cfg not exist!");
        goto CF_LOAD_ERR;
    } else {
        if (cert_event_code <= 0) {
            APPLOG(APPLOG_ERR, "{{{CFG}}} cert event_code[%d] is lower than 0 it means no event!", cert_event_code);
        }
        SERVER_CONF.cert_event_code = cert_event_code;
        APPLOG(APPLOG_ERR, "{{{CFG}}} cert event_code is [%d]", SERVER_CONF.cert_event_code);
    }

	/* default overload limit */
	int def_ovld_limit = 0;
	if (config_lookup_int(&CFG, CF_DEF_OVLD_LIMIT, &def_ovld_limit) == CONFIG_FALSE) {
		APPLOG(APPLOG_ERR, "{{{CFG}}} def_ovld_limit cfg not exist!");
		goto CF_LOAD_ERR;
	} else {
        if (def_ovld_limit <= 0) {
            APPLOG(APPLOG_ERR, "{{{CFG}}} def_ovld_limit[%d] is lower than 0 it means no ovld!", def_ovld_limit);
        }
        SERVER_CONF.def_ovld_limit = def_ovld_limit;
        APPLOG(APPLOG_ERR, "{{{CFG}}} def_ovld_limit is [%d]", SERVER_CONF.def_ovld_limit);
    }

	/* overload event_code */
	int ovld_event_code = 0;
	if (config_lookup_int(&CFG, CF_OVLD_EVENT_CODE, &ovld_event_code) == CONFIG_FALSE) {
		APPLOG(APPLOG_ERR, "{{{CFG}}} ovld_event_code cfg not exist!");
		goto CF_LOAD_ERR;
	} else {
        if (ovld_event_code <= 0) {
            APPLOG(APPLOG_ERR, "{{{CFG}}} ovld_event_code[%d] is lower than 0 it means no event!", ovld_event_code);
        }
        SERVER_CONF.ovld_event_code = ovld_event_code;
        APPLOG(APPLOG_ERR, "{{{CFG}}} ovld_event_code is [%d]", SERVER_CONF.ovld_event_code);
    }

	/* allow any client */
	int allow_any_client = 0;
	if (config_lookup_int(&CFG, CF_ALLOW_ANY_CLIENT, &allow_any_client) == CONFIG_FALSE) {
		APPLOG(APPLOG_ERR, "{{{CFG}}} allow_any_client cfg not exist!");
		goto CF_LOAD_ERR;
	} else {
        if (allow_any_client <= 0) {
            APPLOG(APPLOG_ERR, "{{{CFG}}} allow_any_client[%d] is lower than 0 it means no event!", allow_any_client);
        }
        SERVER_CONF.allow_any_client = allow_any_client;
        APPLOG(APPLOG_ERR, "{{{CFG}}} allow_any_client is [%d]", SERVER_CONF.allow_any_client);
    }

	/* any client default max */
	int any_client_default_max = 0;
    if (config_lookup_int(&CFG, CF_ANY_CLIENT_DEFAULT_MAX, &any_client_default_max) == CONFIG_FALSE ||
            any_client_default_max < 0) {
		APPLOG(APPLOG_ERR, "{{{CFG}}} any_client_default_max cfg not exist! or wrong value[%d]", any_client_default_max);
		goto CF_LOAD_ERR;
	} else {
        SERVER_CONF.any_client_default_max = any_client_default_max;
        APPLOG(APPLOG_ERR, "{{{CFG}}} any_client_default_max is [%d]", SERVER_CONF.any_client_default_max);
    }

    /* pkt_log enable */
    int pkt_log = 0;
    if (config_lookup_int(&CFG, CF_PKT_LOG, &pkt_log) == CONFIG_FALSE) {
        APPLOG(APPLOG_ERR, "{{{CFG}}} pkt log cfg not exist!");
        goto CF_LOAD_ERR;
    } else {
        SERVER_CONF.pkt_log = pkt_log;
        APPLOG(APPLOG_ERR, "{{{CFG}}} pkt log is [%s]", SERVER_CONF.pkt_log == 1 ? "ON" : "OFF");
    }

    /* trace_enable */
    int trace_enable = 0;
    if (config_lookup_int(&CFG, CF_TRACE_ENABLE, &trace_enable) == CONFIG_FALSE) {
        APPLOG(APPLOG_ERR, "{{{CFG}}} trace_enable cfg not exist!");
        goto CF_LOAD_ERR;
    } else {
        SERVER_CONF.trace_enable = trace_enable;
        APPLOG(APPLOG_ERR, "{{{CFG}}} trace_enable is [%s]", SERVER_CONF.trace_enable == 1 ? "ON" : "OFF");
    }

	/* http/2 option setting header table size */
	int setting_header_table_size = 0;
	if (config_lookup_int(&CFG, CF_HTTP_OPT_HDR_TABLE_SIZE, &setting_header_table_size) == CONFIG_FALSE) {
		APPLOG(APPLOG_ERR, "{{{CFG}}} setting header table size cfg not exist!");
		goto CF_LOAD_ERR;
	} else {
		SERVER_CONF.http_opt_header_table_size = setting_header_table_size;
		APPLOG(APPLOG_ERR, "{{{CFG}}} http/2 opt setting header table size is [%d]", SERVER_CONF.http_opt_header_table_size);
	}

	/* certification file cfg loading */
    if (config_lookup_string(&CFG, CF_CERT_FILE, &str) == CONFIG_FALSE) {
		APPLOG(APPLOG_ERR, "{{{CFG}}} cert file cfg not exist!");
        goto CF_LOAD_ERR;
    } else {
		sprintf(SERVER_CONF.cert_file, "%s/data/STACK/HTTP/%s", getenv(IV_HOME), str);
		if (access(SERVER_CONF.cert_file, F_OK) < 0) {
			APPLOG(APPLOG_ERR, "{{{CFG}}} cert file[%s] is not exist!", SERVER_CONF.cert_file);
			goto CF_LOAD_ERR;
		}
        APPLOG(APPLOG_ERR, "{{{CFG}}} cert file name is [%s]", SERVER_CONF.cert_file);
    }

	/* key file cfg loading */
    if (config_lookup_string(&CFG, CF_KEY_FILE, &str) == CONFIG_FALSE) {
		APPLOG(APPLOG_ERR, "{{{CFG}}} key file cfg not exist!");
        goto CF_LOAD_ERR;
    } else {
		sprintf(SERVER_CONF.key_file, "%s/data/STACK/HTTP/%s", getenv(IV_HOME), str);
		if (access(SERVER_CONF.key_file, F_OK) < 0) {
			APPLOG(APPLOG_ERR, "{{{CFG}}} key file[%s] is not exist!", SERVER_CONF.key_file);
			goto CF_LOAD_ERR;
		}
        APPLOG(APPLOG_ERR, "{{{CFG}}} key file name is [%s]", SERVER_CONF.key_file);
    }

    /* lb config load */
    if ((setting = config_lookup(&CFG, CF_LB_CONFIG)) == NULL) {
        APPLOG(APPLOG_ERR, "{{{CFG}}} lb config loading fail!!!");
        goto CF_LOAD_ERR;
    } else {
        SERVER_CONF.lb_config = setting;
        APPLOG(APPLOG_ERR, "{{{CFG}}} lb config loading success");
    }

	/* oauth 2.0 secret key */
	if (config_lookup_string(&CFG, CF_CREDENTIAL, &str) == CONFIG_FALSE) {
		APPLOG(APPLOG_ERR, "{{{CFG}}} oauth2.0 credential not exist!");
		goto CF_LOAD_ERR;
	} else {
		sprintf(SERVER_CONF.credential, "%s", str);
		APPLOG(APPLOG_ERR, "{{{CFG}}} oauth2.0 credential is [%s]", SERVER_CONF.credential);
	}

#if 0
	/* oauth 2.0 for my UUID */
	if (config_lookup_string(&CFG, CF_UUID_FILE, &str) == CONFIG_FALSE) {
		APPLOG(APPLOG_ERR, "{{{CFG}}} oauth2.0 uuidfile not exist!");
		goto CF_LOAD_ERR;
	} else {
		sprintf(SERVER_CONF.uuid_file, "%s", str);
		APPLOG(APPLOG_ERR, "{{{CFG}}} oauth2.0 uuid_file is [%s]", SERVER_CONF.uuid_file);
	}
#endif

	/* allow list loading */
    if ((setting = config_lookup(&CFG, CF_ALLOW_LIST)) == NULL) {
		APPLOG(APPLOG_ERR, "{{{CFG}}} allow list cfg not exist!");
        goto CF_LOAD_ERR;
    } else {
        int count = config_setting_length(setting);
		int i, j, index = 0;
		struct sockaddr_in sa;
		struct sockaddr_in6 sa6;

        APPLOG(APPLOG_ERR, "{{{CFG}}} allow lists are ... (%d)", count);
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

            APPLOG(APPLOG_ERR, "{{{CFG}}} %s have %d item", group->name, list_count);

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

				int auth_act = 0;
				if (config_setting_lookup_int (item, "auth_act", &auth_act) == CONFIG_FALSE)
					continue;

				int ovld_limit = 0;
				if (config_setting_lookup_int (item, "ovld_limit", &ovld_limit) == CONFIG_FALSE)
					continue;

                if (inet_pton(AF_INET, ip, &(sa.sin_addr)))  {
                } else if (inet_pton(AF_INET6, ip, &(sa6.sin6_addr))) {
                } else {
                    APPLOG(APPLOG_ERR, "{{{CFG}}} incorrect numeric ip [%s]!", ip);
                    continue;
                }
				if (max <= 0 || max >= 65535) continue;
				if (!strcmp(act, "ACT") && !strcmp(act, "DACT")) continue;

				APPLOG(APPLOG_ERR, "%d) %-46s (max) %-4d %s", j, ip, max, act);

				item_index = new_item(list_index, ip, 0);

				index++; // from 1 ~
				if (index >= MAX_LIST_NUM) {
					APPLOG(APPLOG_ERR, "{{{CFG}}} allow list exceed max num[%d]!", MAX_LIST_NUM);
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
                ALLOW_LIST[index].auth_act = auth_act;
				ALLOW_LIST[index].limit_tps = ovld_limit;
                ALLOW_LIST[index].curr = 0;
			}
		}
	}


	APPLOG(APPLOG_ERR, "==============================================================================================");
	APPLOG(APPLOG_ERR, "{{{CFG}}} all cfg loading success");

	config_set_tab_width(&CFG, 4);
	//config_write_file(&CFG, CONFIG_PATH);

    return (0);

CF_LOAD_ERR:
	APPLOG(APPLOG_ERR, "==============================================================================================");
	APPLOG(APPLOG_ERR, "{{{CFG}}} cfg loading fail");

	/* if init fail, destry and program exit */
    config_destroy(&CFG);
    return (-1);
}

int addcfg_client_hostname(char *hostname, char *type, const char **error_reason)
{
    static char err_internal_cfg[] = "[internal error .cfg]";
    static char err_host_already_exist[] = "[hostname already exist]";
    static char err_internal_assign[] = "[internal error assign fail]";

    config_setting_t *setting;
    int i, found = 0;

    if ((setting = config_lookup(&CFG, CF_ALLOW_LIST)) == NULL) {
        *error_reason = err_internal_cfg;
        goto CF_ADD_CLI_HOSTNAME_ERR;
    } else {
        config_setting_t *group;
		config_setting_t *val;
        int list_index;

        if ((group = config_setting_add(setting, hostname, CONFIG_TYPE_GROUP)) == NULL) {
            *error_reason = err_host_already_exist;
            goto CF_ADD_CLI_HOSTNAME_ERR;
        }
        if ((val = config_setting_add(group, "type", CONFIG_TYPE_STRING)) == NULL) {
            *error_reason = err_internal_cfg;
            goto CF_ADD_CLI_HOSTNAME_ERR;
        }
        config_setting_set_string(val, type);
        if ((val = config_setting_add(group, "list", CONFIG_TYPE_LIST)) == NULL) {
            *error_reason = err_internal_cfg;
            goto CF_ADD_CLI_HOSTNAME_ERR;
        }

        if ((list_index = new_list(group->name)) < 0) {
            *error_reason = err_internal_assign;
            goto CF_ADD_CLI_HOSTNAME_ERR;
        }

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
    if (!found) {
        *error_reason = err_internal_assign;
        goto CF_ADD_CLI_HOSTNAME_ERR;
    }

    config_set_tab_width(&CFG, 4);
    config_write_file(&CFG, CONFIG_PATH);

    return (0);

CF_ADD_CLI_HOSTNAME_ERR:
    APPLOG(APPLOG_ERR, "(%s) fail to run with [%s]", __func__, *error_reason);
    return (-1);
}

int addcfg_client_ipaddr(int id, char *ipaddr, int max, int auth_act, const char **error_reason)
{
    static char err_internal_cfg[] = "[internal error .cfg]";
    static char err_host_not_exist[] = "[hostname not exist (wrong ID) ]";
    static char err_ip_port_already_exist[] = "[ip/port already exist]";
    static char err_internal_assign[] = "[internal error assign fail]";

    config_setting_t *setting;

    if ((setting = config_lookup(&CFG, CF_ALLOW_LIST)) == NULL) {
        *error_reason = err_internal_cfg;
		goto CF_ADD_CLI_IPADDR_ERR;
	} else {
		config_setting_t *group;
		const char *type;
		config_setting_t *list;
		int list_count, list_index, item_index, i;

		/* if id param receive, but not exist */
        if (get_list_name(id) == NULL) {
            *error_reason = err_host_not_exist;
			goto CF_ADD_CLI_IPADDR_ERR;
        }
		if ((group = config_setting_get_member(setting, get_list_name(id))) == NULL) {
            *error_reason = err_internal_cfg;
			goto CF_ADD_CLI_IPADDR_ERR;
        }
		if (config_setting_lookup_string (group, "type", &type) == CONFIG_FALSE) {
            *error_reason = err_internal_cfg;
			goto CF_ADD_CLI_IPADDR_ERR;
        }

		if ((list = config_setting_get_member(group, "list")) == NULL) {
            *error_reason = err_internal_cfg;
			goto CF_ADD_CLI_IPADDR_ERR;
        }

		/* if first add, delete null row from raw-table */
		list_count = config_setting_length(list);
		if (list_count == 0) {
		 	APPLOG(APPLOG_DEBUG, "%s() check, %s have %d item", __func__, group->name, list_count);
		}

		if ((list_index = get_list(group->name)) < 0) {
            *error_reason = err_internal_assign;
			goto CF_ADD_CLI_IPADDR_ERR;
        }
		if ((item_index = new_item(list_index, ipaddr, 0)) < 0) {
            *error_reason = err_internal_assign;
			goto CF_ADD_CLI_IPADDR_ERR;
        }

		/* first insert, delete null row */
		if (!list_count) {
			for (i = 1; i < MAX_LIST_NUM; i++) {
				if (ALLOW_LIST[i].used == 1 && ALLOW_LIST[i].list_index == list_index && ALLOW_LIST[i].auto_added == 0) {
					memset(&ALLOW_LIST[i], 0x00, sizeof(allow_list_t));
				}
			}
		/* not first insert, check duplicate row */ 
		} else {
			for (i = 1; i < MAX_LIST_NUM; i++) {
				if (ALLOW_LIST[i].used == 1 && ALLOW_LIST[i].list_index == list_index && ALLOW_LIST[i].auto_added == 0) {
					if (!strcmp(ALLOW_LIST[i].ip, ipaddr)) {
                        *error_reason = err_ip_port_already_exist;
						goto CF_ADD_CLI_IPADDR_ERR;
                    }
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
		config_setting_set_int(val, auth_act);
		val = config_setting_add(item, "ovld_limit", CONFIG_TYPE_INT);
		config_setting_set_int(val, SERVER_CONF.def_ovld_limit);

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
				ALLOW_LIST[i].auth_act = auth_act;
				break;
			}
		}
	}

    config_set_tab_width(&CFG, 4);
    config_write_file(&CFG, CONFIG_PATH);

    return (0);

CF_ADD_CLI_IPADDR_ERR:
    APPLOG(APPLOG_ERR, "(%s) fail to run with [%s]", __func__, *error_reason);
    return (-1);
}

int actcfg_http_client(int id, int ip_exist, char *ipaddr, int change_to_act, const char **error_reason)
{ 
    static char err_internal_cfg[] = "[internal error .cfg]";
    static char err_host_not_exist[] = "[hostname not exist (wrong ID)]";
    static char err_ip_port_not_exist[] = "[ip/port not exist]";
    static char err_internal_assign[] = "[internal error assign fail]";

    config_setting_t *setting;

    if ((setting = config_lookup(&CFG, CF_ALLOW_LIST)) == NULL) {
        *error_reason = err_internal_cfg;
        goto CF_ACT_CLIENT_ERR;
    } else {
        config_setting_t *group;
        config_setting_t *list;
        int list_count, list_index, item_index, i;
		int found = 0;

		/* if id param receive, but not exist */
        if (get_list_name(id) == NULL) {
            *error_reason = err_host_not_exist;
			goto CF_ACT_CLIENT_ERR;
        }
		if ((group = config_setting_get_member(setting, get_list_name(id))) == NULL) {
            *error_reason = err_host_not_exist;
            goto CF_ACT_CLIENT_ERR;
		} else {
			/* if only id case */
			if (ip_exist <= 0) {
				found = 1;
			}
		}
		list_index = get_list(group->name);

		if ((list = config_setting_get_member(group, "list")) == NULL) {
            *error_reason = err_internal_assign;
			goto CF_ACT_CLIENT_ERR;
        }
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
            *error_reason = err_ip_port_not_exist;
			goto CF_ACT_CLIENT_ERR;
		}

		for (i = 1; i < MAX_LIST_NUM; i++) {
			if (ALLOW_LIST[i].used == 0) 
				continue;
			if (ip_exist > 0)  {
				if (ALLOW_LIST[i].list_index != list_index || ALLOW_LIST[i].item_index != item_index || ALLOW_LIST[i].auto_added == 1)
					continue;
			} else {
				if (ALLOW_LIST[i].list_index != list_index || ALLOW_LIST[i].auto_added == 1)
					continue;
			}
			/* act */
			if (change_to_act)  {
				ALLOW_LIST[i].act = 1;
			} else {
				ALLOW_LIST[i].act = 0;
                disconnect_all_client_in_allow_list(&ALLOW_LIST[i]);
			}
		}
	}

    config_set_tab_width(&CFG, 4);
    config_write_file(&CFG, CONFIG_PATH);

    return (0);

CF_ACT_CLIENT_ERR:
    APPLOG(APPLOG_ERR, "(%s) fail to run with [%s]", __func__, *error_reason);
    return (-1);
}

int chgcfg_client_max_cnt_with_auth_act_and_limit(int id, char *ipaddr, int max, int auth_act, int limit, const char **error_reason)
{
    static char err_internal_cfg[] = "[internal error .cfg]";
    static char err_host_not_exist[] = "[hostname not exist (wrong ID)]";
    static char err_ip_port_not_exist[] = "[ip/port not exist]";

    config_setting_t *setting;

    if ((setting = config_lookup(&CFG, CF_ALLOW_LIST)) == NULL) {
        *error_reason = err_internal_cfg;
        goto CF_CHG_CLIENT_MAX_ERR;
    } else {
		config_setting_t *group;
		const char *type;
        config_setting_t *list;
        config_setting_t *item_max;
        config_setting_t *item_limit;
        config_setting_t *item_auth_act;
        int list_count, i, list_index, item_index;
		int found = 0;
		const char *cf_ip;
		int cf_max;
		int cf_limit;
		const char *cf_act;
		int cf_auth_act;

		/* if id param receive, but not exist */
        if (get_list_name(id) == NULL) {
            *error_reason = err_host_not_exist;
			goto CF_CHG_CLIENT_MAX_ERR;
        }
		if ((group = config_setting_get_member(setting, get_list_name(id))) == NULL) {
            *error_reason = err_host_not_exist;
			goto CF_CHG_CLIENT_MAX_ERR;
        }
		if (config_setting_lookup_string (group, "type", &type) == CONFIG_FALSE) {
            *error_reason = err_internal_cfg;
			goto CF_CHG_CLIENT_MAX_ERR;
        }
		list_index = get_list(group->name);

		if ((list = config_setting_get_member(group, "list")) == NULL) {
            *error_reason = err_internal_cfg;
			goto CF_CHG_CLIENT_MAX_ERR;
        }
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
			if (config_setting_lookup_int (item, "ovld_limit", &cf_limit) == CONFIG_FALSE) {
				continue;
			}
			if (config_setting_lookup_int (item, "auth_act", &cf_auth_act) == CONFIG_FALSE) {
				continue;
			}
			if (!strcmp(cf_ip, ipaddr)) {
				if (!strcmp(cf_act, "ACT")) {
                    *error_reason = err_internal_cfg;
					goto CF_CHG_CLIENT_MAX_ERR;
                }
				if ((item_max = config_setting_get_member(item, "max")) == NULL) {
                    *error_reason = err_internal_cfg;
					goto CF_CHG_CLIENT_MAX_ERR;
                }
				if ((item_limit = config_setting_get_member(item, "ovld_limit")) == NULL) {
                    *error_reason = err_internal_cfg;
					goto CF_CHG_CLIENT_MAX_ERR;
                }
				if ((item_auth_act = config_setting_get_member(item, "auth_act")) == NULL) {
                    *error_reason = err_internal_cfg;
					goto CF_CHG_CLIENT_MAX_ERR;
                }
				found = 1;
				item_index = get_item(list_index, ipaddr, 0);
				break;
			}
		}
		/* not found case */
		if (!found) {
            *error_reason = err_ip_port_not_exist;
			goto CF_CHG_CLIENT_MAX_ERR;
        }

		/* save setting with auth_act */
		config_setting_set_int(item_max, max);
		config_setting_set_int(item_limit, limit);
		config_setting_set_int(item_auth_act, auth_act);

		/* change max with auth_act */
		for (i = MAX_LIST_NUM; i > 0; i--) {
			if (ALLOW_LIST[i].used == 0) 
				continue;
			if (ALLOW_LIST[i].list_index == list_index
					&& ALLOW_LIST[i].item_index == item_index && ALLOW_LIST[i].auto_added == 0) {
				ALLOW_LIST[i].max = max;
				ALLOW_LIST[i].auth_act = auth_act;
				ALLOW_LIST[i].limit_tps = limit;
			}
		}
	}

    config_set_tab_width(&CFG, 4);
    config_write_file(&CFG, CONFIG_PATH);

    return (0);

CF_CHG_CLIENT_MAX_ERR:
    APPLOG(APPLOG_ERR, "(%s) fail to run with [%s]", __func__, *error_reason);
    return (-1);
}

int delcfg_client_ipaddr(int id, char *ipaddr, const char **error_reason)
{
    static char err_internal_cfg[] = "[internal error .cfg]";
    static char err_host_not_exist[] = "[hostname not exist (wrong ID)]";
    static char err_ip_port_not_exist[] = "[ip/port not exist]";
    static char err_dact_first[] = "[conf state ACT, DACT first]";

    config_setting_t *setting;

    if ((setting = config_lookup(&CFG, CF_ALLOW_LIST)) == NULL) {
        *error_reason = err_internal_cfg;
        goto CF_DEL_CLI_IPADDR_ERR;
    } else {
		config_setting_t *group;
        config_setting_t *list;
        int i, list_count, list_index, item_index, idx;
		int found = 0;
		const char *cf_ip, *cf_act;
		const char *type;

        if (get_list_name(id) == NULL) {
            *error_reason = err_host_not_exist;
			goto CF_DEL_CLI_IPADDR_ERR;
        }
		if ((group = config_setting_get_member(setting, get_list_name(id))) == NULL) {
            *error_reason = err_host_not_exist;
			goto CF_DEL_CLI_IPADDR_ERR;
        }
		if (config_setting_lookup_string (group, "type", &type) == CONFIG_FALSE) {
            *error_reason = err_internal_cfg;
			goto CF_DEL_CLI_IPADDR_ERR;
        }
		list_index = get_list(group->name);

		if ((list = config_setting_get_member(group, "list")) == NULL) {
            *error_reason = err_internal_cfg;
			goto CF_DEL_CLI_IPADDR_ERR;
        }
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
				if (!strcmp(cf_act, "ACT")) {
                    *error_reason = err_dact_first;
					goto CF_DEL_CLI_IPADDR_ERR;
                }
				found = 1;
				idx = i;
				item_index = get_item(list_index, ipaddr, 0);
				break;
			}
		}
		/* not found case */
		if (!found) {
            *error_reason = err_ip_port_not_exist;
			goto CF_DEL_CLI_IPADDR_ERR;
        }

		/* remove item from cfg*/
		del_item(list_index, ipaddr, 0);
		config_setting_remove_elem(list, idx); // cfg 의 n 번째 item 을 삭제하기 때문에 idx 별도 사용 주의

		/* remove item from raw list */
		for (i = 0; i < MAX_LIST_NUM; i++) {
			if (ALLOW_LIST[i].used == 0) 
				continue;
			if (ALLOW_LIST[i].list_index == list_index
					&& ALLOW_LIST[i].item_index == item_index && ALLOW_LIST[i].auto_added == 0) {
				memset(&ALLOW_LIST[i], 0x00, sizeof(allow_list_t));
			}
		}

		/* if all ipaddr withdraw */
		list_count = config_setting_length(list); {
			APPLOG(APPLOG_DEBUG, "%s() check, name (%s) have item (%d)", __func__, group->name, list_count);
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
                    ALLOW_LIST[i].auto_added = 0;
					break;
				}
			}
		}
	}

    config_set_tab_width(&CFG, 4);
    config_write_file(&CFG, CONFIG_PATH);

    return (0);

CF_DEL_CLI_IPADDR_ERR:
    APPLOG(APPLOG_ERR, "(%s) fail to run with [%s]", __func__, *error_reason);
    return (-1);
}

int delcfg_client_hostname(int id, const char **error_reason)
{
    static char err_internal_cfg[] = "[internal error .cfg]";
    static char err_host_not_exist[] = "[hostname not exist (wrong ID)]";
    static char err_iplist_remain[] = "[ipaddr remain, del-nf-cli-ip first]";

    config_setting_t *setting;

    if ((setting = config_lookup(&CFG, CF_ALLOW_LIST)) == NULL) {
        *error_reason = err_internal_cfg;
        goto CF_DEL_CLI_HOSTNAME_ERR;
    } else {
        config_setting_t *group;
        config_setting_t *list;
        int list_count, list_index, i;

        if (get_list_name(id) == NULL) {
            *error_reason = err_host_not_exist;
			goto CF_DEL_CLI_HOSTNAME_ERR;
        }
        if ((group = config_setting_get_member(setting, get_list_name(id))) == NULL) {
            *error_reason = err_host_not_exist;
            goto CF_DEL_CLI_HOSTNAME_ERR;
        }
        list_index = get_list(group->name);

		if ((list = config_setting_get_member(group, "list")) == NULL) {
            *error_reason = err_internal_cfg;
            goto CF_DEL_CLI_HOSTNAME_ERR;
        }
        list_count = config_setting_length(list);
        if (list_count != 0) {
            *error_reason = err_iplist_remain;
            goto CF_DEL_CLI_HOSTNAME_ERR;
        }

        /* remove list from cfg */
        del_list(group->name);
        config_setting_remove(setting, group->name);

        /* remove item from raw list */
        for (i = 0; i < MAX_LIST_NUM; i++) {
            if (ALLOW_LIST[i].used == 0)
                continue;
            if (ALLOW_LIST[i].list_index == list_index && ALLOW_LIST[i].auto_added == 0) {
                memset(&ALLOW_LIST[i], 0x00, sizeof(allow_list_t));
            }
        }
    }

    config_set_tab_width(&CFG, 4);
    config_write_file(&CFG, CONFIG_PATH);

    return (0);

CF_DEL_CLI_HOSTNAME_ERR:
    APPLOG(APPLOG_ERR, "(%s) fail to run with [%s]", __func__, *error_reason);
    return (-1);
}
