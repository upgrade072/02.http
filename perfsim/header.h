/*
json hompage (http://www.json.org) indicate library by lang
try this with json-c (https://github.com/jehiah/json-c)
*/

#include <libs.h>

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <libconfig.h>
#include <event.h>
#include <event2/event.h>
#include <event2/thread.h>
#include <json-c/json.h>
#include <json-c/json_inttypes.h>
#include <term.h>
#include <termios.h>
#include <semaphore.h>
#include <inttypes.h>
#include <errno.h>
#include <time.h>

#ifndef EPCF
#include <appLog.h>
#endif
#include <shmQueue.h>

#include <commlib.h>
#include <ahif_msgtypes.h>
#include <http_comm.h> // schlee! for TEMP MACRO disable APPLOG

// JSON related -----------------------------------------------------------

#define MAX_PF_KEY_NUM 5
#define MAX_PF_FWD_OBJ 2
#define MAX_PARSE_NUM  MAX_PF_KEY_NUM +  MAX_PF_FWD_OBJ
typedef struct {
    char state;
    char name[128];
    char buf[1024];
} parse_buffer_t;
typedef struct {
    parse_buffer_t result[MAX_PARSE_NUM];
} parse_res_t;

typedef enum {
    JS_NONE = 0,
    JS_INIT,
    JS_FOUND,
    JS_ADD,         /* no need after state */
    JS_REPLACE,
    JS_REPLACED,
    JS_KEYVAL,      /* no add, only replace when exist */
    JS_KEYCHANGED
} parse_stat_t;

typedef enum {
    JS_WANT_FIND = 0,
    JS_WANT_REPLACE,
    JS_WANT_KEYCHANGE
} action_code_t;

// CONFIG related ---------------------------------------------------------

#define FILE_LOCATION "JSON_FILES"

typedef struct {
    int occupied;
    char type[128];
    char pfx[128];
    char epfx[128];
} perf_key_t;

typedef struct {
    int occupied;
    char filename[256];
    char rsrc[128];
    char method[128];
    char type[128];
    int interval;
} perf_step_t;

typedef struct {
    int occupied;
    char obj_name[128];
} perf_fwd_item_t;

#define MAX_PF_FWD_OBJ 2
typedef struct {
    int occupied;
    perf_fwd_item_t obj[MAX_PF_FWD_OBJ];
} perf_forward_t;

typedef struct {
    int occupied;
    char name[128];
    char value[128];
} perf_success_t;

#define MAX_PF_STEP_NUM 12
typedef struct {
    int occupied;

    int bulk_send;

    int start_num;
    int end_num;
    int timeout;
    //int interval;

    perf_key_t key[MAX_PF_KEY_NUM];
    perf_step_t step[MAX_PF_STEP_NUM];
    perf_forward_t forward[MAX_PF_STEP_NUM];
    perf_success_t success[MAX_PF_STEP_NUM];
} perf_scenario_t;

#undef MAX_THREAD_NUM
#define MAX_THREAD_NUM 12
//#define MAX_PF_SCENARIO_NUM 12
typedef struct {
    int validate_mode;
    int json_parse;
    int duration;
    int sender_thread_num;
    int receiver_thread_num;
    perf_scenario_t scenario;
} perf_conf_t;

// CONTEXT related --------------------------------------------------------

/* it come from http_comm.h */
#undef MAXMSG
#undef STARTID
#undef SIZEID
/* redefine maximum value */
#define MAXMSG   10000
#define STARTID  1
#define SIZEID 10000+1 

typedef struct {
    int thrd_idx;
    int ctx_idx;

    parse_res_t fwd_value;
} cbarg_t;

typedef struct {
    int thrd_idx;
    int ctx_idx;

    int trigger_step;
    double send_time;
} cb_tmout_arg_t;

typedef enum {
    PF_CTX_INIT = 0,
    PF_CTX_SENDED,
    PF_CTX_RECEIVED,
    PF_CTX_TIMEOUTED
} context_state_t;

typedef struct {
    int occupied;
    int thrd_idx;
    int ctx_idx;
    int cid;
    int curr_step;
    int curr_state;

    parse_res_t key_value;

    double start_tm;
    int snd_byte;

    struct event *ev_timeout;
    cbarg_t param;
    cb_tmout_arg_t tmout;
} app_ctx_t;

typedef struct {
    pthread_t thread_id;

    struct event_base *evbase;
    /* timeout milisec */
    struct timeval timeout_milisec;
    const struct timeval *tm_timeout;
    /* interval milisec */
    struct timeval interval_milisec[MAX_PF_STEP_NUM];

    int step_exist[MAX_PF_STEP_NUM];
    json_object *base_obj[MAX_PF_STEP_NUM];
} thrd_ctx_t;

// STATISTIC related ------------------------------------------------------

typedef enum {
PF_TRIGGERED = 0,   // done
PF_SENDED,          // done
PF_RECV,
PF_SUCC,
PF_FAIL,
PF_TIMEOUT,
PF_INTL_ERR,
PF_RCV_CAUSE_FAIL,
PF_DECODE_FAIL,
PF_STAT_MAX } pf_stat_enum_t;

typedef struct {
    int stat_count[PF_STAT_MAX];
    int step_count[MAX_PF_STEP_NUM];
} stat_cnt_t;

typedef struct {
    stat_cnt_t per_thread_stat[MAX_THREAD_NUM];
} statistic_t;

#define MAX_PF_CHAIN_NUM 2
typedef struct {
    int curr_idx;
    statistic_t stat[MAX_PF_CHAIN_NUM];
} stat_t;

#define MAX_RCV_CHAIN_NUM 10000
typedef struct {
    int occupied;
    double start_tm;
    double end_tm;
    int snd_byte;
    int rcv_byte;
} send_recv_statistic_t;

typedef struct {
    int curr_idx;
    send_recv_statistic_t sndrcv[MAX_RCV_CHAIN_NUM];
} sndrcv_t;

// func proto -------------------------------------------------------------

/* ------------------------- config.c --------------------------- */
int     init_cfg();
int     config_load();
int     load_scenario_suit(config_setting_t *root, int index);
int     getch(void);
void    *modifyThread(void *arg);

/* ------------------------- json.c --------------------------- */
int     check_success(parse_res_t *parse, char *name, char *value);
void    print_parse_result(parse_res_t *parse);
void    get_parse_data(const char *key, json_object *input_obj, parse_res_t *parse);
int     set_parse_data(const char *key, json_object *input_obj, parse_res_t *parse);
int     set_key_change(const char *key, json_object *input_obj, parse_res_t *parse);
void    change_keyvalue(json_object *input_obj, parse_res_t *parse);
void    replace_obj(json_object *input_obj, parse_res_t *parse);
void    recurse_obj(json_object *input_obj, parse_res_t *parse, int action);

/* ------------------------- main.c --------------------------- */
app_ctx_t       *get_ctx(int thrd_idx, int ctx_idx);
app_ctx_t       *assign_ctx(int ctx_idx, int cid, int thrd_idx);
int     initialize();
int     set_scenario_at_thread(int thrd_idx, thrd_ctx_t *thrd_ctx);
int     create_thread();
void    *receiverThread(void *arg);
void    *senderThread(void *arg);
void    *manageThread(void *arg);
void    send_action(evutil_socket_t fd, short what, void *arg);
void    recv_action(int recv_thrd_idx, AhifAppMsgType *recvMsg);
void    free_ctx(app_ctx_t *ctx);
void    free_ctx_event(app_ctx_t *ctx);
void    free_ctx_proc(evutil_socket_t fd, short what, void *arg);
void    set_timeout_event(thrd_ctx_t *thrd_ctx, app_ctx_t *ctx);
void    unset_timeout_event(app_ctx_t *ctx);
void    main_tick_callback(evutil_socket_t fd, short what, void *arg);
int     check_result(json_object *resp_obj, app_ctx_t *ctx);
void    check_fwd_field(json_object *resp_obj, app_ctx_t *ctx);
int     make_cid(int thrd_id, int ctx_id);
void    resolve_cid(int cid, int *thrd_idx, int *ctx_idx);
int     make_ahif_header(app_ctx_t *ctx, int current_step, AhifAppMsgType *txMsg, json_object *curr_obj);
void    save_call_end_info(send_recv_statistic_t *arg, double start_tm, double end_tm, int snd_byte, int rcv_byte);
void    ctx_timeout(evutil_socket_t fd, short what, void *arg);
void    set_key_val(app_ctx_t *ctx);
void    reset_key_val(app_ctx_t *ctx);
void    perf_gen(int thrd_idx);
void    end_perf();
void    restore_term();
void    gather_remain_stat();
int     main();

/* ------------------------- stat.c --------------------------- */
int     init_sem();
void    set_call_end_info(send_recv_statistic_t *end_info);
void    pf_stat_inc(int thrd_idx, int stat_idx);
void    pf_step_inc(int thrd_idx, int curr_step);
void    pf_recv_stat_inc(int recv_thrd_idx, int thrd_idx, int stat_idx);
void    calc_and_print_stat();
void    calc_and_print_sndrcv();
void    clear_sndrcv_info();
statistic_t     *move_stat_return_stat();
void    view_context_use();

/* ------------------------ somewhere library ----------------- */
double commlib_getCurrTime_double (void);
