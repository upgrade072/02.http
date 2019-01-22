#include "header.h"
#include <ctype.h>

/* global */
float BULK_SND;
struct termios TERM_SAVE;

extern char *__progname;
static int KEY_NUMBER;
static int RUNNING;

int THREAD_NO[MAX_THREAD_NUM] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};

int appTxQid, appRxQid;

pthread_mutex_t SHMQ_WRITE_MUTEX = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t SHMQ_READ_MUTEX = PTHREAD_MUTEX_INITIALIZER;

/* context */
app_ctx_t *PERF_CTX[MAX_THREAD_NUM];
thrd_ctx_t SND_THREAD[MAX_THREAD_NUM];
thrd_ctx_t RCV_THREAD[MAX_THREAD_NUM];
thrd_ctx_t MNG_THREAD;

/* config */
extern perf_conf_t PERF_CONF;

/* statistic */
extern stat_t STAT;
extern sndrcv_t SNDRCV;

/* log */
#ifdef UDMR
int logLevel = APPLOG_DEBUG;
int *lOG_FLAG = &logLevel;
#endif

app_ctx_t *get_ctx(int thrd_idx, int ctx_idx)
{
    if (ctx_idx < 0 || ctx_idx >= SIZEID)
        return NULL;
    else if (thrd_idx < 0 || thrd_idx >= PERF_CONF.sender_thread_num)
        return NULL;
    else
        return &PERF_CTX[thrd_idx][ctx_idx];
}

app_ctx_t *assign_ctx(int ctx_idx, int cid, int thrd_idx)
{
    app_ctx_t *ctx = NULL;
    if (ctx_idx < 0 || ctx_idx >= SIZEID) {
        return NULL;
    } else {
        ctx = &PERF_CTX[thrd_idx][ctx_idx];
        memset(ctx, 0x00, sizeof(app_ctx_t));

        ctx->occupied = 1;
        ctx->thrd_idx = thrd_idx;
        ctx->ctx_idx = ctx_idx;
        ctx->cid = make_cid(thrd_idx, ctx_idx);
        ctx->curr_step = 0;

        ctx->ev_timeout = NULL;

        return ctx;
    }
}

void to_upper(char *progname, char *PROGNAME)
{
    int i = 0;
    for (; i < strlen(progname); i++) {
        PROGNAME[i] = toupper(progname[i]);
    }
    PROGNAME[i] = '\0';

    fprintf(stderr, "DBG %s\n", PROGNAME);
}

int initialize()
{
    char fname[256] = {0,};
    char my_name[256] = {0,};

    to_upper(__progname, my_name);

    /* libevent with thread */
    evthread_use_pthreads();

    /* for statistic sem */
    if (init_sem() < 0)  {
        fprintf(stderr, "semaphore get fail\n");
        return (-1);
    }

    /* log initialize */
    sprintf(fname, "%s/log", getenv(IV_HOME));
#ifdef UDMR
    LogInit(my_name, fname);
#endif
    APPLOG(APPLOG_ERR, "\n\n\n\n\n[Welcome Process Started]");

    /* shmq initialize */
    sprintf(fname, "%s/%s", getenv(IV_HOME), AHIF_CONF_FILE);
#ifdef UDMR
    if ((appRxQid = shmqlib_getQid (fname, "AHIF_TO_APP_SHMQ", my_name, SHMQLIB_MODE_GETTER)) < 0)
        return (-1);
    if ((appTxQid = shmqlib_getQid (fname, "APP_TO_AHIF_SHMQ", my_name, SHMQLIB_MODE_PUTTER)) < 0)
        return (-1);
#else
	char tmp[64] = {0,};
	int key = 0;

    if (conflib_getNthTokenInFileSection (fname, "AHIF_TO_APP_SHMQ", my_name, 3, tmp) < 0)
        return (-1);
    key = strtol(tmp,0,0);
    if ((appRxQid = msgget(key,IPC_CREAT|0666)) < 0) {
        APPLOG(APPLOG_ERR, "[%s] msgget fail; key=0x%x,err=%d(%s)", __func__, key, errno, strerror(errno));
        return (-1);
    }
    if (conflib_getNthTokenInFileSection (fname, "APP_TO_AHIF_SHMQ", my_name, 3, tmp) < 0)
        return (-1);
    key = strtol(tmp,0,0);
    if ((appTxQid = msgget(key,IPC_CREAT|0666)) < 0) {
        APPLOG(APPLOG_ERR, "[%s] msgget fail; key=0x%x,err=%d(%s)", __func__, key, errno, strerror(errno));
        return (-1);
    }
#endif

    /* sender thread initialize */
    for (int index = 0; index < PERF_CONF.sender_thread_num; index++) {
        if (PERF_CONF.scenario.occupied != 1)
            continue;

        fprintf(stderr, "\n\n[SEND THREAD INDEX] [%2d]\n", index);
        /* set scenario by thread */
        if (set_scenario_at_thread(index, &SND_THREAD[index]) < 0) {
            fprintf(stderr, "fail to set scenario to thread\n");
            return (-1);
        }

        /* alloc context / by thread, init TAG */
        if ((PERF_CTX[index] = calloc(SIZEID, sizeof(app_ctx_t))) == NULL) {
            fprintf(stderr, "fail to alloc memory for context\n");
            return (-1);
        }
        Init_CtxId(index);
    }

#ifndef LOCAL
    if (keepalivelib_init(my_name) < 0) {
        fprintf(stderr, "keepalive init fail");
        return (-1);
    }
#endif

    return (0);
}

int set_scenario_at_thread(int thrd_idx, thrd_ctx_t *thrd_ctx)
{
    char temp[1024 * 12] = {0,};
    char cmd[1024] = {0,};

    for (int index = 0; index < MAX_PF_STEP_NUM; index++) {
        perf_step_t *step = &PERF_CONF.scenario.step[index];
        json_object *base_obj;
        json_object *check_obj;

        if (step->occupied != 1)
            continue;

        /* set interval time */
        thrd_ctx->interval_milisec[index].tv_sec = PERF_CONF.scenario.step[index].interval / 1000;
        thrd_ctx->interval_milisec[index].tv_usec = (PERF_CONF.scenario.step[index].interval % 1000) * 1000;
        fprintf(stderr, "\tinterval set sec(%d) usec(%ld)\n", 
                thrd_ctx->interval_milisec[index].tv_sec,
                thrd_ctx->interval_milisec[index].tv_usec);

        /* verify input file format */
        sprintf(cmd, "jslint --format %s", step->filename);
        if (system(cmd) != 0) {
            fprintf(stderr, "json format err, file[%s]\n", step->filename);
            return (-1);
        }

        /* caution!! must use get-function */
        base_obj = json_object_from_file(step->filename);
        /* check correction of json format */
        sprintf(temp, "%s", json_object_to_json_string(base_obj));
        if ((check_obj = json_tokener_parse(temp)) == NULL) {
            fprintf(stderr, "CAUTION JSON FILE [%s] FORMAT FAIL\n", step->filename);
            return(-1);
        }
        thrd_ctx->base_obj[index] = json_object_get(base_obj);

        if (base_obj == (struct json_object*)error_ptr(-1)) {
            fprintf(stderr, "fail to get json from file (%s)\n", step->filename);
            return(-1);
        } else {
            thrd_ctx->step_exist[index] = 1;
            fprintf(stderr, "\tsender thrd[%2d] step(%2d) sendfile(%s) initialed\n", thrd_idx, index, step->filename);
#ifdef DEBUG
            char tmp_file[256] = {0,};

            sprintf(tmp_file, "./temp.json");
            json_object_to_file(tmp_file, base_obj);
            sprintf(cmd, "jslint --format %s\n", tmp_file);
            system(cmd);
#endif
        }
    }
}

int create_thread()
{
    /* create receiver thread */
    for (int index = 0; index < PERF_CONF.receiver_thread_num; index++) {
        int res = pthread_create(&RCV_THREAD[index].thread_id, NULL, &receiverThread, (void *)&THREAD_NO[index]);
        if (res != 0) {
            fprintf(stderr,"receiver thread index(%2d) create fail\n", index);
            return (-1);
        } else {
            pthread_detach(RCV_THREAD[index].thread_id);
        }
    }

    /* create sender thread */
    for (int index = 0; index < PERF_CONF.sender_thread_num; index++) {
        int res = pthread_create(&SND_THREAD[index].thread_id, NULL, &senderThread, (void *)&THREAD_NO[index]);
        if (res != 0) {
            fprintf(stderr,"sender thread index(%2d) create fail\n", index);
            return (-1);
        } else {
            pthread_detach(SND_THREAD[index].thread_id);
        }
    }

    /* create manage thread */
    int res = pthread_create(&MNG_THREAD.thread_id, NULL, &manageThread, NULL);
    if (res != 0) {
        fprintf(stderr,"manage thread create fail\n");
        return (-1);
    } else {
        pthread_detach(MNG_THREAD.thread_id);
    }

#if 0 // no use
    pthread_t modify_thrd_id;
    /* create modify thread */
    res = pthread_create(&modify_thrd_id, NULL, &modifyThread, NULL);
    if (res != 0) {
        fprintf(stderr,"modify thread create fail\n");
        return (-1);
    } else {
        pthread_detach(modify_thrd_id);
    }
#endif
}

void *receiverThread(void *arg)
{
    int index = *(int *)arg;
    char rxMsg[sizeof(AhifAppMsgType) + 1024] = {0,};
#ifndef UDMR
	size_t rxMsgSize = sizeof(rxMsg);
#endif
    AhifAppMsgType *recvMsg = (AhifAppMsgType *)&rxMsg;
    int msgSize = 0, sleep_cnt = 0;

    while (1)
    {
        pthread_mutex_lock(&SHMQ_READ_MUTEX);
#ifdef UDMR
        msgSize = shmqlib_getMsg(appRxQid, rxMsg);
#else
        msgSize = msgrcv(appRxQid, rxMsg, rxMsgSize - sizeof(long), 0, IPC_NOWAIT | MSG_NOERROR);
#endif
        pthread_mutex_unlock(&SHMQ_READ_MUTEX);

        if (msgSize <= 0) {
            sleep_cnt ++;
            if (sleep_cnt >= 1000) {
                usleep(1000);
                sleep_cnt = 0;
            }
            continue;
        } else {
            rxMsg[msgSize] = '\0';
            sleep_cnt = 0;
            recv_action(index, recvMsg);
        }
    }
}

void *senderThread(void *arg)
{
    int index = *(int *)arg;

    struct event_base *evbase;

    /* create event base */
    evbase = event_base_new();
    SND_THREAD[index].evbase = evbase;

    /* usec => milisec & set to queue time manage */
    // timeout 
    SND_THREAD[index].timeout_milisec.tv_sec = PERF_CONF.scenario.timeout / 1000;
    SND_THREAD[index].timeout_milisec.tv_usec = (PERF_CONF.scenario.timeout % 1000) * 1000;

    SND_THREAD[index].tm_timeout = event_base_init_common_timeout(evbase, &SND_THREAD[index].timeout_milisec);

    event_base_loop(evbase, EVLOOP_NO_EXIT_ON_EMPTY);
    fprintf(stderr, "reach here!\n");

    /* never reach here */
    event_base_free(evbase);
}

void *manageThread(void *arg)
{
    struct event_base *evbase;
    evbase = event_base_new();
    MNG_THREAD.evbase = evbase;

    event_base_loop(evbase, EVLOOP_NO_EXIT_ON_EMPTY);

    fprintf(stderr, "reach here!\n");

    /* never reach here */
    event_base_free(evbase);
}

void send_action(evutil_socket_t fd, short what, void *arg)
{
    cbarg_t *param = arg;
    parse_res_t *fwd = &param->fwd_value;
    struct event_base *evbase = NULL;
    thrd_ctx_t *thrd_ctx = NULL;
    app_ctx_t *ctx = NULL;
    json_object *curr_obj;
    int current_step = 0;
    int shmq_len = 0;

    if ((ctx = get_ctx(param->thrd_idx, param->ctx_idx)) == NULL) {
        fprintf(stderr, "DBG get ctx fail (t:%d c:%d)\n", param->thrd_idx, param->ctx_idx);
        /* stat fail */
        pf_stat_inc(0, PF_INTL_ERR);
        pf_stat_inc(0, PF_FAIL);
        return ;
    } else {
        thrd_ctx = &SND_THREAD[param->thrd_idx];
        evbase = thrd_ctx->evbase;
        current_step = ctx->curr_step;
    }

    /* check step */
    if (current_step >= MAX_PF_STEP_NUM ||
           thrd_ctx->step_exist[current_step] != 1) {
        fprintf(stderr, "DBG ctx step_num invalid (t:%d c:%d) step_num(%d)\n", 
                param->thrd_idx, param->ctx_idx, current_step);
        /* stat fail */
        pf_stat_inc(0, PF_INTL_ERR);
        pf_stat_inc(0, PF_FAIL);
        return;
    }

    /* make json body */
        /* set keyval */
        /* set forward val */
    curr_obj = json_object_get(thrd_ctx->base_obj[current_step]);

    /* change key */
    reset_key_val(ctx);
    change_keyvalue(curr_obj, &ctx->key_value);
    replace_obj(curr_obj, fwd);

    /* make ahif header */
    AhifAppMsgType txMsg;
    shmq_len = make_ahif_header(ctx, current_step, &txMsg, curr_obj);

    /* for DEBUG */
    if (PERF_CONF.validate_mode) {
        char cmd[256] = {0,};
        char tmp_file[256] = {0,};

        sprintf(tmp_file, "./temp.json");
        json_object_to_file(tmp_file, curr_obj);
        fprintf(stderr, "\n\n\nREQUEST(STEP %2d)]\n", current_step);
        sprintf(cmd, "jslint --format %s\n", tmp_file);
        system(cmd);
    }

    /* release json obj */
    json_object_put(curr_obj);

    /* send */
        /* save stat_tm */
        /* save snd byte */
        /* trigger timeout event*/

    pthread_mutex_lock(&SHMQ_WRITE_MUTEX);
#ifdef UDMR
    int res = shmqlib_putMsg(appTxQid, (char*)&txMsg, shmq_len);
#else
    int res = msgsnd(appTxQid, (char*)&txMsg, shmq_len - sizeof(long), 0);
#endif
    pthread_mutex_unlock(&SHMQ_WRITE_MUTEX);

    if (res <= 0) {
        /* stat sendfail */
        pf_stat_inc(ctx->thrd_idx, PF_INTL_ERR);
        pf_stat_inc(ctx->thrd_idx, PF_FAIL);
        free_ctx(ctx);
    } else {
        /* stat sended */
        pf_stat_inc(ctx->thrd_idx, PF_SENDED);
        pf_step_inc(ctx->thrd_idx, ctx->curr_step);

        ctx->curr_state = PF_CTX_SENDED;
        ctx->snd_byte = txMsg.head.bodyLen;

        set_timeout_event(thrd_ctx, ctx);
    }
}

void recv_action(int recv_thrd_idx, AhifAppMsgType *recvMsg)
{
    int thrd_idx = 0, ctx_idx = 0;
    int cid = recvMsg->head.appCid;
    int respCode = recvMsg->head.respCode;
    app_ctx_t *ctx = NULL;
    thrd_ctx_t *thrd_ctx = NULL;
    json_object *resp_obj = NULL;
    send_recv_statistic_t call_end_arg;
    double curr_tm = commlib_getCurrTime_double();

    resolve_cid(cid, &thrd_idx, &ctx_idx);

    /* get context by cid */
    if ((ctx = get_ctx(thrd_idx, ctx_idx)) == NULL) {
#if 0
        fprintf(stderr, "fail to get ctx t:%02d idx, c:%05d idx\n", thrd_idx, ctx_idx);
#endif
        /* stat fail */
        pf_recv_stat_inc(recv_thrd_idx, 0, PF_INTL_ERR);
        pf_recv_stat_inc(recv_thrd_idx, 0, PF_FAIL);
        return;
    } else {
        /* unset timeout */
        unset_timeout_event(ctx);
    }

    /* check more validation (shmq-lib broken issue) */
    if (ctx->occupied != 1 ||
            recvMsg->head.bodyLen >= AHIF_MAX_MSG_LEN ||
            recvMsg->head.respCode > 999) {
        /* stat fail */
        pf_recv_stat_inc(recv_thrd_idx, 0, PF_INTL_ERR);
        pf_recv_stat_inc(recv_thrd_idx, 0, PF_FAIL);
        return;
    } else {
        thrd_ctx = &SND_THREAD[ctx->thrd_idx];
    }

    /* set context state */
    ctx->curr_state = PF_CTX_RECEIVED;

    /* make recv info */
    save_call_end_info(&call_end_arg,
            ctx->start_tm,
            curr_tm,
            ctx->snd_byte,
            recvMsg->head.bodyLen);
    set_call_end_info(&call_end_arg);
    /* stat timeout */
    pf_recv_stat_inc(recv_thrd_idx, ctx->thrd_idx, PF_RECV);

    /* json_parse consume too many cpu, if mode off, don't parse and just check respCode */
    if (PERF_CONF.json_parse == 0) {
        if (recvMsg->head.respCode == 200) {
            goto DONT_CHECK_RESULT;
        } else {
            pf_recv_stat_inc(recv_thrd_idx, ctx->thrd_idx, PF_RCV_CAUSE_FAIL);
            pf_recv_stat_inc(recv_thrd_idx, ctx->thrd_idx, PF_FAIL);
            goto END_CALL;
        }
    }

PARSE_JSON_FROM_MSG:

    /* make json obj from resp */
    if ((resp_obj = json_tokener_parse(recvMsg->body)) == NULL) {
#ifdef DEBUG
        fprintf(stderr, "resp but json parse fail (cid:%d)\n", ctx->cid);
#endif
        /* some message response have no body */
        if (recvMsg->head.respCode == 200) {
            goto DONT_CHECK_RESULT;
        }

        /* this call fail */
        pf_recv_stat_inc(recv_thrd_idx, ctx->thrd_idx, PF_DECODE_FAIL);
        pf_recv_stat_inc(recv_thrd_idx, ctx->thrd_idx, PF_FAIL);
        if (PERF_CONF.validate_mode) {
            fprintf(stderr, "\nRESP DUMP RES[%d] BODYLEN[%d] ]\n", recvMsg->head.respCode, recvMsg->head.bodyLen);
            DumpHex(recvMsg->body, recvMsg->head.bodyLen);
        }
        goto END_CALL;
    }

    /* for DEBUG */
    if (PERF_CONF.validate_mode) {
        char cmd[256] = {0,};
        char tmp_file[256] = {0,};

        sprintf(tmp_file, "./temp.json");
        json_object_to_file(tmp_file, resp_obj);
        fprintf(stderr, "\n\n\nRESPONSE(STEP %2d)]\n", ctx->curr_step);
        sprintf(cmd, "jslint --format %s\n", tmp_file);
        system(cmd);
    }

    /* check result from resp */
    if (check_result(resp_obj, ctx) < 0) {
#ifdef DEBUG
        fprintf(stderr, "resp but result fail (cid:%d)\n", ctx->cid);
#endif
        /* this call fail */
        pf_recv_stat_inc(recv_thrd_idx, ctx->thrd_idx, PF_RCV_CAUSE_FAIL);
        pf_recv_stat_inc(recv_thrd_idx, ctx->thrd_idx, PF_FAIL);
        goto END_CALL;
    }

DONT_CHECK_RESULT:

    /* check next step exist, if last it count success */
    if (ctx->curr_step >= MAX_PF_STEP_NUM ||
           thrd_ctx->step_exist[ctx->curr_step + 1] != 1) {
#ifdef DEBUG
        fprintf(stderr, "resp reach to step-end (cid:%d)\n", ctx->cid);
#endif
        /* this call succ */
        pf_recv_stat_inc(recv_thrd_idx, ctx->thrd_idx, PF_SUCC);
        goto END_CALL;
    }

MOVE_TO_NEXT:

    if (resp_obj) {
        /* check forward obj exist */
        check_fwd_field(resp_obj, ctx);
        json_object_put(resp_obj);
    }

    /* move step_count & call send_action */
    event_base_once(thrd_ctx->evbase, -1, EV_TIMEOUT, send_action, &ctx->param, &thrd_ctx->interval_milisec[ctx->curr_step]);
    ctx->curr_step ++;
    return;

END_CALL:

    if (resp_obj)
        json_object_put(resp_obj);
    free_ctx(ctx);
    return;
}

void free_ctx(app_ctx_t *ctx)
{
    /* unset timeout */
    unset_timeout_event(ctx);
    free_ctx_event(ctx);
}

void free_ctx_event(app_ctx_t *ctx)
{
    event_base_once(SND_THREAD[ctx->thrd_idx].evbase, -1, EV_TIMEOUT, free_ctx_proc, ctx, NULL);
}

void free_ctx_proc(evutil_socket_t fd, short what, void *arg)
{
    app_ctx_t *ctx = arg;

    Free_CtxId(ctx->thrd_idx, ctx->ctx_idx);
    ctx->occupied = 0;
}

void set_timeout_event(thrd_ctx_t *thrd_ctx, app_ctx_t *ctx)
{
    if (ctx->ev_timeout != NULL) {
        //fprintf(stderr, "DBG] wierd, timeout event already running, ev_free call(%d)\n", ctx->ctx_idx);
        event_free(ctx->ev_timeout);
        ctx->ev_timeout = NULL;
    }
    cb_tmout_arg_t* tm_arg = &ctx->tmout;
    tm_arg->trigger_step = ctx->curr_step;
    tm_arg->thrd_idx = ctx->thrd_idx;
    tm_arg->ctx_idx = ctx->ctx_idx;
    tm_arg->send_time = ctx->start_tm = commlib_getCurrTime_double();

    ctx->ev_timeout = evtimer_new(thrd_ctx->evbase, ctx_timeout, tm_arg);
    event_add(ctx->ev_timeout, thrd_ctx->tm_timeout);
}

void unset_timeout_proc(evutil_socket_t fd, short what, void *arg)
{
    app_ctx_t *ctx = arg;

    if (ctx->ev_timeout == NULL || ctx->curr_state == PF_CTX_INIT) {
#if 0
        fprintf(stderr, "%s DBG (idx %d:step %d), wired NULL, returned\n",
                __func__, ctx->ctx_idx, ctx->curr_step);
#endif
        return;
    }
    event_free(ctx->ev_timeout);
    ctx->ev_timeout = NULL;
}

void unset_timeout_event(app_ctx_t *ctx)
{
    event_base_once(SND_THREAD[ctx->thrd_idx].evbase, -1, EV_TIMEOUT, unset_timeout_proc, ctx, NULL);
}

void main_tick_callback(evutil_socket_t fd, short what, void *arg)
{
    calc_and_print_stat();
    calc_and_print_sndrcv();
    view_context_use();
}

int check_result(json_object *resp_obj, app_ctx_t *ctx)
{
#ifdef DEBUG
    fprintf(stderr, "response!\n%s\n", json_object_to_json_string(resp_obj));
    fprintf(stderr, "ctx curr step is [%d]\n", ctx->curr_step);
#endif
    /* non exist */
    if (PERF_CONF.scenario.success[ctx->curr_step].occupied != 1)
        return (1);

    parse_res_t parse;
    memset(&parse, 0x00, sizeof(parse_res_t));

    parse.result[0].state = JS_INIT;
    sprintf(parse.result[0].name, "%s", PERF_CONF.scenario.success[ctx->curr_step].name);
    recurse_obj(resp_obj, &parse, JS_WANT_FIND);
#ifdef DEBUG
    fprintf(stderr, "recv res ]\n");
    print_parse_result(&parse);
#endif
    return check_success(&parse, 
            PERF_CONF.scenario.success[ctx->curr_step].name,
            PERF_CONF.scenario.success[ctx->curr_step].value);
}

void check_fwd_field(json_object *resp_obj, app_ctx_t *ctx)
{
    parse_res_t *parse = &ctx->param.fwd_value;
    memset(parse, 0x00, sizeof(parse_res_t));

    /* non exist */
    if (PERF_CONF.scenario.forward[ctx->curr_step].occupied != 1)
        return;

    for (int i = 0; i < MAX_PF_FWD_OBJ; i++) {
        if (PERF_CONF.scenario.forward[ctx->curr_step].obj[i].occupied != 1)
            continue;
        parse->result[i].state = JS_INIT;
        sprintf(parse->result[i].name, "%s", 
                PERF_CONF.scenario.forward[ctx->curr_step].obj[i].obj_name);
    }
    recurse_obj(resp_obj, parse, JS_WANT_FIND);
#ifdef DEBUG
    fprintf(stderr, "we found fwd ]\n");
    print_parse_result(parse);
#endif

    return;
}

int make_cid(int thrd_id, int ctx_id)
{
    int cid = 0;

    cid = cid | (thrd_id << 16);
    cid = cid | ctx_id;

    return cid;
}

void resolve_cid(int cid, int *thrd_idx, int *ctx_idx)
{
    *thrd_idx = (cid >> 16) & 0xff;
    *ctx_idx = cid & 0xffff;
}

int make_ahif_header(app_ctx_t *ctx, int current_step, AhifAppMsgType *txMsg, json_object *curr_obj)
{
    perf_step_t *step = &PERF_CONF.scenario.step[current_step];
    int body_len = 0;

    memset(&txMsg->head, 0x00, AHIF_APP_MSG_HEAD_LEN);
    txMsg->head.mtype   = MTYPE_HTTP2_REQUEST_APP_TO_AHIF;
    txMsg->head.appCid  = ctx->cid;
    sprintf(txMsg->head.appVer, "%s", "R100");
    sprintf(txMsg->head.rsrcName, "%s", step->rsrc);
    sprintf(txMsg->head.httpMethod, "%s", step->method);
    sprintf(txMsg->head.destType, "%s", step->type);
    txMsg->head.opTimer = 3;

#ifdef DEBUG
    fprintf(stderr, "DBG AH [%s] [%s] [%s] setting done\n",
            step->rsrc, step->method, step->type);
    fprintf(stderr, "DBG will push obj]\n%s\n", json_object_to_json_string(curr_obj));
#endif

    body_len = sprintf(txMsg->body, "%s", json_object_to_json_string(curr_obj));
    txMsg->head.bodyLen = body_len;

    return (AHIF_APP_MSG_HEAD_LEN + txMsg->head.bodyLen);
}

void save_call_end_info(send_recv_statistic_t *arg, double start_tm, double end_tm, int snd_byte, int rcv_byte)
{
    arg->start_tm = start_tm;
    arg->end_tm = end_tm;
    arg->snd_byte = snd_byte;
    arg->rcv_byte = rcv_byte;
}

void ctx_timeout(evutil_socket_t fd, short what, void *arg)
{
#ifdef DEBUG
    fprintf(stderr, "timeout occured\n");
#endif
    cb_tmout_arg_t *param = arg;
    send_recv_statistic_t call_end_arg;
    double curr_tm = commlib_getCurrTime_double();

    app_ctx_t *ctx = NULL;
    if ((ctx = get_ctx(param->thrd_idx, param->ctx_idx)) == NULL) {
        fprintf(stderr, "DBG get ctx fail (t:%d c:%d)\n", param->thrd_idx, param->ctx_idx);
        return ;
    } else {
        if ((ctx->occupied == 1) && 
                (ctx->start_tm == param->send_time) &&
                (ctx->curr_state == PF_CTX_SENDED)) {
            ctx->curr_state = PF_CTX_TIMEOUTED;
#if 1
            APPLOG(APPLOG_ERR, "DBG] timeout occured] (thrd_idx:%d ctx_idx:%d scen_step:%d) startrm %lf currtm %lf eplaspe_tm %lf",
                    ctx->thrd_idx, ctx->ctx_idx, ctx->curr_step,
                    ctx->start_tm, curr_tm, curr_tm - ctx->start_tm);
#endif

            /* make timeout info */
            save_call_end_info(&call_end_arg,
                    ctx->start_tm,
                    curr_tm,
                    ctx->snd_byte,
                    0);
            set_call_end_info(&call_end_arg);
            /* stat timeout */
            pf_stat_inc(ctx->thrd_idx, PF_TIMEOUT);
            pf_stat_inc(ctx->thrd_idx, PF_FAIL);
            free_ctx(ctx);
        } else {
            /* do not anything, already responsed or free-ed */
#ifdef DEBUG
            fprintf(stderr, "it's already free-ed object, OK case\n");
#endif
        }
    }
}


void set_key_val(app_ctx_t *ctx)
{
    perf_scenario_t *scen_config = &PERF_CONF.scenario;
    int index = 0;

    if (KEY_NUMBER >= scen_config->end_num)
        KEY_NUMBER = scen_config->start_num;
    else
        KEY_NUMBER ++;

    for (int i = 0; i < MAX_PF_KEY_NUM; i++) {
        if (scen_config->key[i].occupied != 1)
            continue;

        ctx->key_value.result[index].state = JS_KEYVAL;
        sprintf(ctx->key_value.result[index].name, "%s", scen_config->key[i].type);
        sprintf(ctx->key_value.result[index].buf, "\"%s%08d%s\"", 
                scen_config->key[i].pfx,
                KEY_NUMBER,
                scen_config->key[i].epfx);
#ifdef DEBUG
        fprintf(stderr, "DBG key %s : %s\n",
                ctx->key_value.result[index].name,
                ctx->key_value.result[index].buf);
#endif
        index++;
    }
}

void reset_key_val(app_ctx_t *ctx)
{
    perf_scenario_t *scen_config = &PERF_CONF.scenario;

    for (int i = 0; i < MAX_PF_KEY_NUM; i++) {
        if (scen_config->key[i].occupied != 1)
            continue;

        if (ctx->key_value.result[i].state == JS_KEYCHANGED) {
            ctx->key_value.result[i].state = JS_KEYVAL;
        }
    }
}

void perf_gen(int thrd_idx)
{
    int ctx_idx;
    int cid = 0;
    app_ctx_t *ctx = NULL;
    cbarg_t *param;

    if ((ctx_idx = Get_CtxId(thrd_idx)) < 0) {
        pf_stat_inc(0, PF_INTL_ERR);
        pf_stat_inc(0, PF_FAIL);
        //fprintf(stderr, "thrd(%2d) fail to get context\n", thrd_idx);
        return;
    }

    if((ctx = assign_ctx(ctx_idx, cid, thrd_idx)) == NULL) {
        fprintf(stderr, "thrd(%2d) ctx_idx(%d)/cid(%d) fail to assign context\n",
                thrd_idx, ctx_idx, cid);
        return;
    }

    set_key_val(ctx);

    param = &ctx->param;
    memset(param, 0x00, sizeof(cbarg_t));
    /* it only setting at first trigger-time */
    param->thrd_idx = thrd_idx;
    param->ctx_idx = ctx_idx;

    /* stat trigger */
    pf_stat_inc(thrd_idx, PF_TRIGGERED);

    event_base_once(SND_THREAD[thrd_idx].evbase, -1, EV_TIMEOUT, send_action, param, NULL);
}

void end_perf()
{
    fprintf(stderr, "perf ended by conf.duration\n");
    RUNNING = 0;
}
void restore_term()
{
    tcsetattr(0, TCSAFLUSH, &TERM_SAVE);
    exit(0);
}
void gather_remain_stat()
{
    for (int i = 0; i < (MAX_PF_STEP_NUM + 5); i++) { // max step
#ifndef LOCAL
        keepalivelib_increase();
#endif
        event_base_once(MNG_THREAD.evbase, -1, EV_TIMEOUT, main_tick_callback, NULL, NULL);
        sleep(1);
    }
}

int main()
{
    int snd_thread_no = 0;

    tcgetattr(0, &TERM_SAVE);
    signal(SIGINT, (void *)restore_term);

    if (init_cfg()      < 0) exit(0);
    if (config_load()   < 0) exit(0);
    if (initialize()    < 0) exit(0);
    if (create_thread() < 0) exit(0);

    sleep(2);

    KEY_NUMBER = PERF_CONF.scenario.start_num; /* set keynumber to config->start_num */
    RUNNING = 1;

    if (PERF_CONF.duration != 0) {
        signal(SIGALRM, end_perf);
        alarm(PERF_CONF.duration * 60);
    }

    double before_100, now;
    int snd_count = 0;
    BULK_SND = PERF_CONF.scenario.bulk_send / 100;
    fprintf(stderr, "\nbulk send %f (per 1/100)\n\n\n\n", BULK_SND);
    sleep(1);

    before_100 = commlib_getCurrTime_double();

    while (RUNNING) {
        /* 1 call per 1 sec */
        if (PERF_CONF.validate_mode) {
#ifndef LOCAL
            keepalivelib_increase();
#endif
            if (snd_count < PERF_CONF.validate_mode) {
                perf_gen(snd_thread_no);
                snd_count++;
            }
            sleep(1);
        } else {
        /* as configuration */
            now = commlib_getCurrTime_double();
            /* sec slice 100 */
            if ((now - before_100) >= 0.01) {
                before_100 = now;
                snd_thread_no = (snd_thread_no + 1) % PERF_CONF.sender_thread_num;
                for (int i = 0; i < BULK_SND; i++) {
                    perf_gen(snd_thread_no);
                }
                snd_count ++;
            } else {
                usleep(1);
            }
            /* sec move */
            if (snd_count >= 100) { 
#ifndef LOCAL
                keepalivelib_increase();
#endif
                snd_count = 0;
                event_base_once(MNG_THREAD.evbase, -1, EV_TIMEOUT, main_tick_callback, NULL, NULL);
            }
        }
    }

    APPLOG(APPLOG_ERR, "[Process Ended by Timer, Wait Response for STAT]");
    gather_remain_stat();

    /* last stat */
    APPLOG(APPLOG_ERR, "[DONE]");
    restore_term();

    return 0;
}
