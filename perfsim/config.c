#include "header.h"

extern char *__progname;

config_t CFG;
perf_conf_t PERF_CONF;
char CONFIG_PATH[256] = {0,};
char SCEN_NAME[256] = {0, };

int init_cfg()
{
    config_init(&CFG);
    memset(&PERF_CONF, 0x00, sizeof(perf_conf_t));

    sprintf(CONFIG_PATH, "%s/data/%s.cfg", getenv(IV_HOME), __progname);

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
    return (0);

CF_INIT_ERR:
    fprintf(stderr, "config(%s) loading fail!\n", CONFIG_PATH);
    fprintf(stderr, "=====================================================================\n");

    config_destroy(&CFG);
    return (-1);
}

int config_load()
{
    config_setting_t *setting;
    int scenario_num = 0;

    if (config_lookup_int(&CFG, "application.validate_mode", &PERF_CONF.validate_mode) == CONFIG_FALSE) 
        goto CF_LOAD_ERR;
    else
        fprintf(stderr, "\tvalidate mode : %d (1 for 1call/1sec)\n", PERF_CONF.validate_mode);

    if (config_lookup_int(&CFG, "application.json_parse", &PERF_CONF.json_parse) == CONFIG_FALSE) 
        goto CF_LOAD_ERR;
    else
        fprintf(stderr, "\tjson_parse : %d (0: don't parse, 1: parse and check)\n", PERF_CONF.json_parse);

    if (config_lookup_int(&CFG, "application.duration", &PERF_CONF.duration) == CONFIG_FALSE) 
        goto CF_LOAD_ERR;
    else
        fprintf(stderr, "\tduration : %d (min) (0 for iternal)\n", PERF_CONF.duration);

    if (config_lookup_int(&CFG, "application.sender_thread_num", &PERF_CONF.sender_thread_num) == CONFIG_FALSE) 
        goto CF_LOAD_ERR;
    else if (PERF_CONF.sender_thread_num > MAX_THREAD_NUM)
        goto CF_LOAD_ERR;
    else
        fprintf(stderr, "\tsender thread num : %d\n", PERF_CONF.sender_thread_num);

    if (config_lookup_int(&CFG, "application.receiver_thread_num", &PERF_CONF.receiver_thread_num) == CONFIG_FALSE) 
        goto CF_LOAD_ERR;
    else if (PERF_CONF.receiver_thread_num > MAX_THREAD_NUM)
        goto CF_LOAD_ERR;
    else
        fprintf(stderr, "\treciver thread num : %d\n", PERF_CONF.receiver_thread_num);

    if ((setting = config_lookup(&CFG, "scenario")) == NULL) {
        fprintf(stderr, "cfg cant load [scenario]\n");
        goto CF_LOAD_ERR;
    } else {
        scenario_num = config_setting_length(setting);
        fprintf(stderr, "\ncfg have [%d] scenarion num\n", scenario_num);

#if 0
        for (int i = 0; i < scenario_num; i++) {
            /* load each scenario */
            if (load_scenario_suit(setting, i) < 0) {
                fprintf(stderr, "fail occur in [%d]th scenario\n", i);
                goto CF_LOAD_ERR;
            }
        }
#else
        /* load only one scenario */
        if (load_scenario_suit(setting, 0) < 0) {
            //fprintf(stderr, "fail occur in [%d]th scenario\n", i);
            fprintf(stderr, "fail occur scenario\n");
            goto CF_LOAD_ERR;
        }
#endif
    }
    fprintf(stderr, "config(%s) loading success!\n", CONFIG_PATH);
    fprintf(stderr, "=====================================================================\n");
    return (0);

CF_LOAD_ERR:
    fprintf(stderr, "config(%s) loading fail!\n", CONFIG_PATH);
    fprintf(stderr, "=====================================================================\n");

    config_destroy(&CFG);
    return (-1);
}

int load_scenario_suit(config_setting_t *root, int index)
{
    perf_scenario_t *scen_config = NULL;

    config_setting_t *section = config_setting_get_elem(root, index);

    config_setting_t *setting = config_setting_get_member(section, "setting");
    config_setting_t *key_val = config_setting_get_member(section, "key_val");
    config_setting_t *scenario = config_setting_get_member(section, "scenario");

    sprintf(SCEN_NAME, section->name);
    fprintf(stderr, "\nload scenario [%s]\n", section->name);
    fprintf(stderr, "---------------------------------------------------------------------\n");

    if (setting == NULL || key_val == NULL || scenario == NULL) 
        goto CF_SCEN_FAIL;

    /* use this ptr */
    //scen_config = &PERF_CONF.scenario[index];
    scen_config = &PERF_CONF.scenario;
    scen_config->occupied = 1;

    /* load setting */
    if (config_setting_lookup_int(setting, "bulk_send", &scen_config->bulk_send)== CONFIG_FALSE) 
        goto CF_SCEN_FAIL;
    else
        fprintf(stderr, "\tbulk_send is (%d) you can change this by arrow key\n", scen_config->bulk_send);

    if (scen_config->bulk_send < 100) {
        fprintf(stderr, "\tbulk_send minimum value is 100, use validate_mode\n");
        goto CF_SCEN_FAIL;
    }

    if (config_setting_lookup_int(setting, "start_num", &scen_config->start_num) == CONFIG_FALSE) 
        goto CF_SCEN_FAIL;
    else
        fprintf(stderr, "\tstart_num is (%d)\n", scen_config->start_num);

    if (config_setting_lookup_int(setting, "end_num", &scen_config->end_num) == CONFIG_FALSE) 
        goto CF_SCEN_FAIL;
    else
        fprintf(stderr, "\tend_num is (%d)\n", scen_config->end_num);

#if 0
    if (config_setting_lookup_int(setting, "interval", &scen_config->interval) == CONFIG_FALSE) 
        goto CF_SCEN_FAIL;
    else
        fprintf(stderr, "\tinterval is (%d) milisec\n", scen_config->interval);
#endif

    if (config_setting_lookup_int(setting, "timeout", &scen_config->timeout) == CONFIG_FALSE) 
        goto CF_SCEN_FAIL;
    else
        fprintf(stderr, "\ttimeout is (%d)\n", scen_config->timeout);

    /* load key_val */
    int key_num = 0;
    key_num = config_setting_length(key_val);

    if (key_num > MAX_PF_KEY_NUM) {
        fprintf(stderr, "\n\tkey_val number(%d) exceed max (%d)\n", key_num, MAX_PF_KEY_NUM);
        goto CF_SCEN_FAIL;
    } else {
        fprintf(stderr, "\n\tkey_val number(%d)\n", key_num);
    }

    for (int i = 0; i < key_num; i++) {
        const char *type;
        const char *pfx;
        const char *epfx;
        config_setting_t *item = config_setting_get_elem(key_val, i);

        scen_config->key[i].occupied = 1;

        config_setting_lookup_string(item, "type", &type);
        config_setting_lookup_string(item, "pfx", &pfx);
        config_setting_lookup_string(item, "epfx", &epfx);

        sprintf(scen_config->key[i].type, "%s", type);
        sprintf(scen_config->key[i].pfx, "%s", pfx);
        sprintf(scen_config->key[i].epfx, "%s", epfx);
        fprintf(stderr, "\tkey member(%d) type[%s] pfx[%s] epfx[%s]\n",
                i, 
                scen_config->key[i].type,
                scen_config->key[i].pfx,
                scen_config->key[i].epfx);
    }

    /* load scenario */
    config_setting_t *file = config_setting_get_member(scenario, "file");
    config_setting_t *rsrc = config_setting_get_member(scenario, "rsrc");
    config_setting_t *method = config_setting_get_member(scenario, "method");
    config_setting_t *type = config_setting_get_member(scenario, "type");
    config_setting_t *dest = config_setting_get_member(scenario, "dest");
    config_setting_t *func = config_setting_get_member(scenario, "func");
    config_setting_t *farg = config_setting_get_member(scenario, "farg");
    config_setting_t *interval = config_setting_get_member(scenario, "interval");
    config_setting_t *forward = config_setting_get_member(scenario, "forward");
    config_setting_t *succ = config_setting_get_member(scenario, "succ");

    if (file == NULL || rsrc == NULL || method == NULL || type == NULL || dest == NULL || func == NULL || farg == NULL)
        goto CF_SCEN_FAIL;

    int file_num = config_setting_length(file);
    int rsrc_num = config_setting_length(rsrc);
    int method_num = config_setting_length(method);
    int type_num = config_setting_length(type);
    int dest_num = config_setting_length(dest);
    int func_num = config_setting_length(func);
    int farg_num = config_setting_length(farg);

    if ((file_num != method_num) || (file_num != rsrc_num) || (file_num != type_num) || (file_num != dest_num)
			|| (file_num != func_num) || (file_num != farg_num)) {
        fprintf(stderr, "\n\tfile(%2d)/rsrc(%2d)/method(%2d)/type(%2d)/dest(%2d)/func(%2d)/farg(%2d) number not same\n", 
                file_num, rsrc_num, method_num, type_num, dest_num, func_num, farg_num);
        goto CF_SCEN_FAIL;
    }

    if (file_num > MAX_PF_STEP_NUM) {
        fprintf(stderr, "\n\tfile number(%d) exceed max (%d)\n", file_num, MAX_PF_STEP_NUM);
        goto CF_SCEN_FAIL;
    } else {
        fprintf(stderr, "\n\tscenario have (%d) step\n", file_num);
    }

    for (int i = 0; i < file_num; i++) {
        const char *file_name = config_setting_get_string_elem(file, i);
        const char *rsrc_name = config_setting_get_string_elem(rsrc, i);
        const char *method_name = config_setting_get_string_elem(method, i);
        const char *type_name = config_setting_get_string_elem(type, i);
        const char *dest_name = config_setting_get_string_elem(dest, i);
        const char *func_name = config_setting_get_string_elem(func, i);
        const char *farg_name = config_setting_get_string_elem(farg, i);
        int interval_num = config_setting_get_int_elem(interval, i);
        char cmd[256] = {0, };
        int res;

        fprintf(stderr, "\tstep(%d) load file[%s] rsrc[%s] method[%s] type[%s] dest[%s] func[%s] farg[%s] interval[%d]\n", 
                i, file_name, rsrc_name, method_name, type_name, dest_name, func_name, farg_name, interval_num);
        sprintf(cmd, "stat %s/data/%s/%s > /dev/null", getenv(IV_HOME), FILE_LOCATION, file_name);
        if ((res = system(cmd)) != 0) {
            fprintf(stderr, "\tcmd [%s] fail\n", cmd);
            goto CF_SCEN_FAIL;
        } else {
            scen_config->step[i].occupied = 1;
            sprintf(scen_config->step[i].filename, "%s/data/%s/%s", getenv(IV_HOME), FILE_LOCATION, file_name);
            sprintf(scen_config->step[i].rsrc, "%s", rsrc_name);
            sprintf(scen_config->step[i].method, "%s", method_name);
            sprintf(scen_config->step[i].type, "%s", type_name);
            sprintf(scen_config->step[i].dest, "%s", dest_name);
            sprintf(scen_config->step[i].func, "%s", func_name);
            sprintf(scen_config->step[i].farg, "%s", farg_name);
            scen_config->step[i].interval = interval_num;
        }
    }

    int forward_num = config_setting_length(forward);

    if (forward_num > MAX_PF_STEP_NUM) {
        fprintf(stderr, "\n\tforward number(%d) exceed max (%d)\n", forward_num, MAX_PF_STEP_NUM);
        goto CF_SCEN_FAIL;
    } else {
        fprintf(stderr, "\n\tscenario will forward (%d)\n", forward_num);
    }

    for (int i = 0; i < forward_num; i++) {
        config_setting_t *item = config_setting_get_elem(forward, i);
        int item_length = config_setting_length(item);

        if (item_length > MAX_PF_FWD_OBJ) {
            fprintf(stderr, "\tforward item number(%d) exceed max (%d)\n", item_length, MAX_PF_FWD_OBJ);
            goto CF_SCEN_FAIL;
        } else {
            scen_config->forward[i].occupied = 1;
            fprintf(stderr, "\tstep(%d) item have (%d) forward\n", i, item_length);
        }
        for (int j = 0; j < item_length; j++) {
            const char *fwd_obj = config_setting_get_string_elem(item, j);
            scen_config->forward[i].obj[j].occupied = 1;
            sprintf(scen_config->forward[i].obj[j].obj_name, "%s", fwd_obj);
            fprintf(stderr, "\t\tfwd ==>[%s]\n",  scen_config->forward[i].obj[j].obj_name);
        }
    }

    int succ_num = config_setting_length(succ);

    if (succ_num > MAX_PF_STEP_NUM) {
        fprintf(stderr, "\n\tsucc number(%d) exceed max (%d)\n", succ_num, MAX_PF_STEP_NUM);
        goto CF_SCEN_FAIL;
    } else {
        fprintf(stderr, "\n\tscenario will check succ (%d)\n", succ_num);
    }

    for (int i = 0; i < succ_num; i++) {
        config_setting_t *item = config_setting_get_elem(succ, i);
        const char *name;
        const char *value;

        // caution! if next step exist and succ check not exist case, it means go next
        if (config_setting_lookup_string(item, "name", &name) == CONFIG_FALSE) continue;
        if (config_setting_lookup_string(item, "value", &value) == CONFIG_FALSE) continue;

        scen_config->success[i].occupied = 1;
        sprintf(scen_config->success[i].name, "%s", name);
        sprintf(scen_config->success[i].value, "%s", value);
        fprintf(stderr, "\tstep(%d) will check by %s:%s\n",
                i,
                scen_config->success[i].name,
                scen_config->success[i].value);
    }

    fprintf(stderr, "\nscenario(%s) loading success!\n", section->name);
    fprintf(stderr, "---------------------------------------------------------------------\n");

    return (0);

CF_SCEN_FAIL:
    fprintf(stderr, "\nscenario(%s) member load fail\n", section->name);
    fprintf(stderr, "---------------------------------------------------------------------\n");

    return (-1);
}

int getch(void)
{
    int ch;
    struct termios buf;
    struct termios save;

    tcgetattr(0, &save);
    buf = save;
    buf.c_lflag &= ~(ICANON|ECHO);
    buf.c_cc[VMIN] = 1;
    buf.c_cc[VTIME] = 0;
    tcsetattr(0, TCSAFLUSH, &buf);
    ch = getchar();
    tcsetattr(0, TCSAFLUSH, &save);
    return ch;
}

// main.c main()
extern float BULK_SND;
void *modifyThread(void *arg)
{
    int ch;
    //char conf_setting_name[256] = {0,};
    config_setting_t *root = NULL;
    config_setting_t *scenario = NULL;
    config_setting_t *setting = NULL;
    config_setting_t *set_bulk = NULL;

    root = config_lookup(&CFG, "scenario");
    scenario = config_setting_get_elem(root, 0);
    setting = config_setting_get_member(scenario, "setting");
    set_bulk = config_setting_get_member(setting, "bulk_send");

    while(1)
    {
        ch = getch();

        switch (ch) {
            case 65:
                PERF_CONF.scenario.bulk_send+= 10;
                BULK_SND = PERF_CONF.scenario.bulk_send / 100;
                fprintf(stderr, "keyinput up   ] bulk_send now %d --> calc snd(%f)/0.01(sec)\n",
                        PERF_CONF.scenario.bulk_send, BULK_SND);
                config_setting_set_int(set_bulk, PERF_CONF.scenario.bulk_send);
                config_write_file(&CFG, CONFIG_PATH);
                break;
            case 66:
                if (PERF_CONF.scenario.bulk_send >= 110) {
                    PERF_CONF.scenario.bulk_send-= 10;
                } else {
                    PERF_CONF.scenario.bulk_send = 100;
                }
                BULK_SND = PERF_CONF.scenario.bulk_send / 100;
                fprintf(stderr, "keyinput doen ] bulk_send now %d --> calc snd(%f)/0.01(sec)\n", 
                        PERF_CONF.scenario.bulk_send, BULK_SND);
                config_setting_set_int(set_bulk, PERF_CONF.scenario.bulk_send);
                config_write_file(&CFG, CONFIG_PATH);
                break;
            case 82: // R
                fprintf(stderr, "keyinput R    ] cleat sndrcv stat\n");
                clear_sndrcv_info();
                break;
            case 10: // enter
                fprintf(stderr, "\n");
                break;
        }
    }
}
