#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

#include <libs.h>

#ifdef LOG_LIB
#include <loglib.h>
#elif LOG_APP
#include <appLog.h>
#endif

#include <libconfig.h>
#include <json-c/json.h>
#include <json-c/json_object.h>
#include <event.h>
#include <event2/event.h>

#include <gmodule.h>

// for httpc
#include <http_comm.h>

// for nrf
#include <nrf_comm.h>
#include <libnrf.h>
// for isif
#include <isif_msgtypes.h>

/* for NotificationPath */
#define PATH_HTTPS_RECV_NOTIFY  "/notifyForLb"

#define MAX_FEP_NUM			12
#define JSON_C_PRETTY_NOSLASH	(JSON_C_TO_STRING_PRETTY|JSON_C_TO_STRING_NOSLASHESCAPE)

/* for .cfg */
#define CF_MP_SYS_TYPE		"nrfm_cfg.sys_config.mp_sys_type"
#define CF_LOGLEVEL			"nrfm_cfg.sys_config.log_level"
#define CF_SVC_NIC			"nrfm_cfg.sys_config.svc_nic"
#define CF_NOTIFY_PORT		"nrfm_cfg.sys_config.notify_listen_port"
#define CF_ACC_TOKEN_SHM	"nrfm_cfg.sys_config.access_token_shm_key"
#define CF_NRF_STAT_CODE	"nrfm_cfg.sys_config.nrfm_stat_code"
#define CF_MP_SYS_TYPE		"nrfm_cfg.sys_config.mp_sys_type"
#define CF_LOGLEVEL			"nrfm_cfg.sys_config.log_level"
#define CF_OVLD_TPS_ENABLED	"nrfm_cfg.sys_config.ovld_tps_enabled"
#define CF_OVLD_NOTIFY_CODE	"nrfm_cfg.sys_config.ovld_notify_code"
//#define CF_UUID_FILE		"nrfm_cfg.sys_config.uuid_file"
#define CF_RECOVERY_TIME	"nrfm_cfg.sys_info.recovery_time"
#define CF_SUBSCRIBE_FORM	"nrfm_cfg.subscription_form"
#define CF_HTTP_RSP_WAIT_TM	"nrfm_cfg.timer_info.httpc_rsp_wait_tm"
#define CF_NRFM_RETRY_TM	"nrfm_cfg.timer_info.nrfm_retry_after_tm"
#define CF_NRF_RETRIEVAL	"nrfm_cfg.retrieval_nf_type"
#define CF_MY_PROFILE		"my_profile"
#define CF_MY_INSTANCE_ID	"my_profile.nfInstanceId"
#define CF_HEARTBEAT_TIMER	"my_profile.heartBeatTimer"
#define CF_ACC_TOKEN_LIST	"access_token"

/* for <--> NRF */
typedef enum {
	NF_CTX_TYPE_REGI = 0,
	NF_CTX_TYPE_HEARTBEAT,
	NF_CTX_TYPE_RETRIEVE_LIST,
	NF_CTX_TYPE_RETRIEVE_PROFILE,
	NF_CTX_TYPE_SUBSCRIBE,
	NF_CTX_TYPE_SUBSCR_PATCH,
	NF_CTX_TYPE_ACQUIRE_TOKEN,
	NF_CTX_TYPE_HTTPC_CMD
} nf_ctx_type_t;

typedef struct qid_ifo {
	int nrfm_qid;		// my recv queue
	int httpc_qid;		// to send request (to httpc) queue
	int https_qid;		// to send response (to https) queue
	int isifs_rx_qid;	// from FEP nrfc receive shm queue
	int isifc_tx_qid;	// to FEP nrfc send shm queue
} qid_info_t;

typedef struct timeout_arg {
	int type;
	struct event *ev_timeout;
	void *my_ctx;
} timeout_arg_t;

typedef struct nrf_ctx {
	/* common */
	int seqNo;
	timeout_arg_t timer;

	/* heartbeat | subscription */
	struct event *ev_action;
} nrf_ctx_t;

typedef struct fep_service {
	/* init value */
	char service_name[1024];	/* key value */
	char path_for_load[1024];
	char path_for_capacity[1024];

	/* collect value */
	int capacity;
	int load;
	service_info_t fep_svc_info[MAX_FEP_NUM];
} fep_service_t;

typedef enum nf_item_ctx_type {
	NF_ITEM_CTX_TYPE_PROFILE = 0,
	NF_ITEM_CTX_TYPE_CMD
} nf_item_ctx_type_t;

typedef struct nf_retrieve_item {
	/* item ctx type profile */
	char nf_uuid[1024];
	json_object *item_nf_profile;
	nrf_ctx_t retrieve_item_ctx;

	/* item ctx type cmd */
	int token_id;
	nrfm_mml_t httpc_cmd;
	nrf_ctx_t httpc_cmd_ctx;
} nf_retrieve_item_t;

typedef struct nf_retrieve_info {
	/* for retrieve list */
	char nf_type[128];
	int	limit;
	nrf_ctx_t retrieve_list_ctx;
	json_object *js_retrieve_response; // NRF receive response
	GSList *nf_retrieve_items;	// dynamic : nf_retrieve_item_t

	/* for subscription nftype */
	json_object *js_subscribe_request; // NRF send request
	char subscription_id[128];
	struct tm tm_validity;
	time_t tm_wish_in_patch_req;
	nrf_ctx_t subscribe_ctx;;
} nf_retrieve_info_t;

typedef struct token_ctx_list {
	int token_id;
	nrf_ctx_t access_token_ctx;
} token_ctx_list_t;

typedef struct nrf_token_info {
	struct event *ev_acquire_token;

	int acc_token_shm_key;
	int acc_token_shm_id;
	acc_token_shm_t *ACC_TOKEN_LIST;

	GSList *token_accuire_list;
} nrf_token_info_t;

typedef struct sys_conf {
	int debug_mode;
	int ovld_tps_enabled;
	int ovld_notify_code;
} sys_conf_t;

typedef struct main_ctx {
	int MAIN_SEQNO;
	config_t CFG;
	pid_t HTTPC_PID;

	struct event_base *EVBASE;
	int init_regi_success;

	sys_conf_t sysconfig;

	svr_info_t my_info;
	qid_info_t my_qid;

	json_object *my_nf_profile;	// static
	json_object *received_nf_profile;	// just for ref (location header / hb timer ..)
	char location_uri[1024];

	GSList *fep_service_list;	// static : fep_service_t
	GSList *fep_assoc_list;		// dynamic : assoc_t

	int httpc_alive_status;		// httpc --> nrfm : I'm alive
	int fep_conn_status;		// https --> nrfm : some FEP alive

	GSList *nf_retrieve_list;	// static : nf_retrieve_list_t

	nrf_ctx_t regi_ctx;
	nrf_ctx_t heartbeat_ctx;

	nrf_token_info_t nrf_access_token;
} main_ctx_t;

// glib
char *strptime(const char *s, const char *format, struct tm *tm);

/* ------------------------- config.c --------------------------- */
int		cfg_get_nrf_stat_code(main_ctx_t *MAIN_CTX);
int     cfg_get_access_token_shm_key(main_ctx_t *MAIN_CTX);
char    *cfg_get_my_ip(main_ctx_t *MAIN_CTX);
char    *cfg_get_mp_nf_type(main_ctx_t *MAIN_CTX);
char    *cfg_get_my_noti_uri(main_ctx_t *MAIN_CTX);
char    *cfg_get_my_recovery_time(main_ctx_t *MAIN_CTX);
char    *cfg_get_my_uuid(main_ctx_t *MAIN_CTX);
char    *cfg_get_nf_info(nf_retrieve_info_t *nf_retr_info);
char    *cfg_get_nf_type(nf_retrieve_info_t *nf_retr_info);
int     cnvt_cfg_to_json(json_object *obj, config_setting_t *setting, int callerType);
json_object     *create_json_with_cfg(config_t *CFG);
void    fep_service_log(fep_service_t *svc_elem);
int     init_cfg(config_t *CFG);
int     json_set_val_by_type(json_object *dst, json_object *new_value);
void    log_all_cfg_retrieve_list(main_ctx_t *MAIN_CTX);
void    log_all_cfg_subscribe_list(main_ctx_t *MAIN_CTX);
int     load_access_token_cfg(main_ctx_t *MAIN_CTX);
int     load_cfg_retrieve_list(main_ctx_t *MAIN_CTX);
int     load_cfg_subscribe_list(main_ctx_t *MAIN_CTX);
int     load_cfg_overload_info(main_ctx_t *MAIN_CTX);
void    log_cfg_retrieve_list(nf_retrieve_info_t *nf_retr_info);
void    log_cfg_subscribe_list(nf_retrieve_info_t *nf_retr_info);
void    recurse_json_obj(json_object *input_obj, main_ctx_t *MAIN_CTX, nf_retrieve_info_t *nf_retr_info);
char    *replace_json_val(const char *input_str, main_ctx_t *MAIN_CTX, nf_retrieve_info_t *nf_retr_info);
int     save_sysconfig(config_t *CFG, main_ctx_t *MAIN_CTX);
json_object     *search_json_object(json_object *obj, char *key_string);
void    set_cfg_sys_info(config_t *CFG);

/* ------------------------- token.c --------------------------- */
void    nf_token_acquire_token(main_ctx_t *MAIN_CTX, acc_token_info_t *token_info);
void    nf_token_acquire_handlde_resp_proc(AhifHttpCSMsgType *ahifPkt);
void    nf_token_acquire_token_handle_timeout(main_ctx_t *MAIN_CTX, nrf_ctx_t *timeout_ctx);
int     nf_token_get_scope_by_profile(json_object *nf_profile, char *scope_buff, size_t buff_len);
void    nf_token_add_shm_by_nf(acc_token_info_t *token_info, nf_retrieve_item_t *nf_item);
void    nf_token_check_and_acquire_token(main_ctx_t *MAIN_CTX, acc_token_info_t *token_info);
int     nf_token_check_expires_in(long double timeval);
token_ctx_list_t        *nf_token_create_ctx(main_ctx_t *MAIN_CTX, acc_token_info_t *token_info);
int     nf_token_create_body(main_ctx_t *MAIN_CTX, AhifHttpCSMsgType *ahifPkt, acc_token_info_t *token_info);
void    nf_token_create_pkt(main_ctx_t *MAIN_CTX, AhifHttpCSMsgType *ahifPkt, acc_token_info_t *token_info, token_ctx_list_t *token_request);
void    nf_token_del_shm_by_nf(acc_token_info_t *token_info);
void    nf_token_free_ctx(main_ctx_t *MAIN_CTX, token_ctx_list_t *token_request);
token_ctx_list_t        *nf_token_find_ctx_by_id(GSList *token_accuire_list, int token_id);
token_ctx_list_t        *nf_token_find_ctx_by_seqNo(GSList *token_accuire_list, int seqNo);
void    nf_token_get_token_cb(evutil_socket_t fd, short what, void *arg);
void    nf_token_handle_resp_nok(main_ctx_t *MAIN_CTX, token_ctx_list_t *token_request);
void    nf_token_print_log(AhifHttpCSMsgType *ahifPkt, const char *log_prefix);
void    nf_token_start_process(main_ctx_t *MAIN_CTX);
void    nf_token_update_shm(acc_token_info_t *token_info, const char *access_token, double due_date);
void    nf_token_update_shm_process(main_ctx_t *MAIN_CTX, token_ctx_list_t *token_request, AhifHttpCSMsgType *ahifPkt);

/* ------------------------- isif.c --------------------------- */
void    isifc_create_pkt_for_status(IsifMsgType *txIsifMsg, nf_service_info *nf_info, svr_info_t *my_info, assoc_t *fep_assoc);
void    isifc_send_pkt_for_status(int isifc_qid, IsifMsgType *txIsifMsg);

/* ------------------------- retrieve.c --------------------------- */
void    nf_retrieve_addnew_and_get_profile(main_ctx_t *MAIN_CTX, nf_retrieve_info_t *nf_retr_info, nf_retrieve_item_t *nf_add_item);
void    nf_retrieve_arrange_item(nf_retrieve_item_t *nf_item, nf_retrieve_info_t *nf_retr_info);
void    nf_retrieve_arrange_legacy_list(nf_retrieve_info_t *nf_retr_info);
void    nf_retrieve_get_nf_profiles(main_ctx_t *MAIN_CTX, nf_retrieve_info_t *nf_retr_info);
void    nf_retrieve_instance_create_pkt(main_ctx_t *MAIN_CTX, AhifHttpCSMsgType *ahifPkt, nf_retrieve_item_t *nf_item);
void    nf_retrieve_instance_handle_resp_proc(AhifHttpCSMsgType *ahifPkt);
void    nf_retrieve_instances_list(nf_retrieve_info_t *nf_retr_info, main_ctx_t *MAIN_CTX);
void    nf_retrieve_item_handle_timeout(nrf_ctx_t *nf_ctx);
void    nf_retrieve_item_recall_cb(evutil_socket_t fd, short what, void *arg);
void    nf_retrieve_item_retry_while_after(nf_retrieve_item_t *nf_item);
void    nf_retrieve_item_token_add(main_ctx_t *MAIN_CTX, nf_retrieve_item_t *nf_item);
void    nf_retrieve_item_token_del(main_ctx_t *MAIN_CTX, nf_retrieve_item_t *nf_item);
void    nf_retrieve_list_create_pkt(main_ctx_t *MAIN_CTX, AhifHttpCSMsgType *ahifPkt, nf_retrieve_info_t *nf_retr_info);
void    nf_retrieve_list_handle_resp_proc(AhifHttpCSMsgType *ahifPkt);
void    nf_retrieve_list_handle_timeout(nrf_ctx_t *nf_ctx);
void    nf_retrieve_list_recall_cb(evutil_socket_t fd, short what, void *arg);
void    nf_retrieve_list_retry_while_after(nf_retrieve_info_t *nf_retr_info);
int     nf_retrieve_parse_list(json_object *js_item, nf_retrieve_item_t *item_ctx);
void    nf_retrieve_remove_nth_item(nf_retrieve_info_t *nf_retr_info, nf_retrieve_item_t *nf_item);
void    nf_retrieve_save_recv_nf_profile(nf_retrieve_item_t *nf_item, AhifHttpCSMsgType *ahifPkt);
int     nf_retrieve_save_response(nf_retrieve_info_t *nf_retr_info, AhifHttpCSMsgType *ahifPkt);
nf_retrieve_info_t      *nf_retrieve_search_info_via_nfType(main_ctx_t *MAIN_CTX, const char *nfType);
nf_retrieve_info_t      *nf_retrieve_search_info_via_seqNo(main_ctx_t *MAIN_CTX, int seqNo);
nf_retrieve_item_t      *nf_retrieve_search_item_by_uuid(GSList *nf_retrieve_items, const char *nf_uuid);
nf_retrieve_item_t      *nf_retrieve_search_item_via_seqNo(main_ctx_t *MAIN_CTX, int type, int seqNo);
void    nf_retrieve_single_instance(main_ctx_t *MAIN_CTX, nf_retrieve_item_t *nf_item);
void    nf_retrieve_start_process(main_ctx_t *MAIN_CTX);

/* ------------------------- manage.c --------------------------- */
void    NF_MANAGE_NF_ACT(main_ctx_t *MAIN_CTX, nf_retrieve_item_t *nf_item);
void    NF_MANAGE_NF_ADD(main_ctx_t *MAIN_CTX, nf_retrieve_item_t *nf_item);
void    NF_MANAGE_NF_CLEAR(main_ctx_t *MAIN_CTX);
void    NF_MANAGE_NF_DACT(main_ctx_t *MAIN_CTX, nf_retrieve_item_t *nf_item);
void    NF_MANAGE_NF_DEL(main_ctx_t *MAIN_CTX, nf_retrieve_item_t *nf_item);
void    NF_MANAGE_RESTORE_HTTPC_CONN(main_ctx_t *MAIN_CTX);
void    nf_manage_collect_avail_each_nf(nf_retrieve_item_t *nf_item, nf_list_pkt_t *my_avail_nfs);
void    nf_manage_collect_avail_each_type(nf_retrieve_info_t *nf_retr_info, nf_list_pkt_t *my_avail_nfs);
void    nf_manage_broadcast_nfs_to_fep(main_ctx_t *MAIN_CTX, nf_list_pkt_t *my_avail_nfs);
void    nf_manage_collect_httpc_conn_status(main_ctx_t *MAIN_CTX);
void    nf_manage_collect_httpc_conn_status_cb(evutil_socket_t fd, short what, void *arg);
void    nf_manage_collect_oper_added_nf(main_ctx_t *MAIN_CTX, nf_list_pkt_t *my_avail_nfs);
void    nf_manage_create_httpc_cmd_conn_act_dact(main_ctx_t *MAIN_CTX, nf_retrieve_item_t *nf_item, int act);
void    nf_manage_create_httpc_cmd_conn_add(main_ctx_t *MAIN_CTX, nf_retrieve_item_t *nf_item);
void    nf_manage_create_httpc_cmd_conn_del(main_ctx_t *MAIN_CTX, nf_retrieve_item_t *nf_item);
int     nf_manage_create_lb_list_get_load(json_object *nf_profile, char *service_name);
int     nf_manage_create_lb_list_get_priority(json_object *nf_profile, char *service_name);
void    nf_manage_create_lb_list_pkt(main_ctx_t *MAIN_CTX, conn_list_status_t *conn_raw, int nfType, nf_type_info *nf_specific_info, int allowdPlmnsNum, nf_comm_plmn *allowdPlmns, nf_conn_info_t *nf_conn, json_object *nf_profile, nf_list_pkt_t *my_avail_nfs);
int     nf_manage_fill_nrfm_mml(nrfm_mml_t *nrfm_cmd, const char *service, const char *scheme, const char *ip, int port);
int     nf_manage_get_allowd_plmns(json_object *nf_profile, nf_comm_plmn *allowdPlmns);
void    nf_manage_get_specific_info(int nfType, json_object *js_specific_info, nf_type_info *nf_specific_info);
void    nf_manage_handle_cmd_res(nrfm_mml_t *httpc_cmd_res);
void    nf_manage_handle_httpc_alive(nrfm_noti_t *httpc_noti);
void    nf_manage_print_my_avail_nfs(nf_list_pkt_t *avail_nfs);
int     nf_manage_search_specific_info(json_object *nf_profile, json_object **js_specific_info);
void    nf_manage_send_httpc_cmd(main_ctx_t *MAIN_CTX, nf_retrieve_item_t *nf_item);
void    nf_manage_send_nfs_status_to_fep(assoc_t *node_elem, nf_service_info *nf_info);

/* ------------------------- main.c --------------------------- */
int     get_httpc_shm();
int     get_my_profile(main_ctx_t *MAIN_CTX);
int     get_my_qid(main_ctx_t *MAIN_CTX);
int     get_my_service_list(main_ctx_t *MAIN_CTX);
void    httpc_response_handle(AhifHttpCSMsgType *ahifPkt);
void    https_request_handle(AhifHttpCSMsgType *ahifPkt);
void    init_log(main_ctx_t *MAIN_CTX);
int     initialize(main_ctx_t *MAIN_CTX);
void    INITIAL_PROCESS(main_ctx_t *MAIN_CTX);
int     load_access_token_shm(main_ctx_t *MAIN_CTX);
int     main();
void    main_tick_callback(evutil_socket_t fd, short what, void *arg);
void    message_handle(evutil_socket_t fd, short what, void *arg);
void    start_loop(main_ctx_t *MAIN_CTX);
void    directory_watch_action(const char *file_name);
void    start_watching_dir(struct event_base *evbase);

/* ------------------------- heartbeat.c --------------------------- */
void    https_save_recv_fep_status(main_ctx_t *MAIN_CTX);
void    isif_save_recv_fep_status(service_info_t *fep_svc_info);
void    nf_heartbeat_clear_status(main_ctx_t *MAIN_CTX);
int     nf_heartbeat_create_body(main_ctx_t *MAIN_CTX, AhifHttpCSMsgType *ahifPkt);
void    nf_heartbeat_create_pkt(main_ctx_t *MAIN_CTX, AhifHttpCSMsgType *ahifPkt);
void    nf_heartbeat_handle_resp_proc(AhifHttpCSMsgType *ahifPkt);
void    nf_heartbeat_send_proc(evutil_socket_t fd, short what, void *arg);
void    nf_heartbeat_start_process(main_ctx_t *MAIN_CTX);
void    shmq_recv_handle(evutil_socket_t fd, short what, void *arg);

/* ------------------------- subscribe.c --------------------------- */
void    nf_subscribe_check_time(evutil_socket_t fd, short what, void *arg);
void    nf_subscribe_create_pkt(main_ctx_t *MAIN_CTX, AhifHttpCSMsgType *ahifPkt, nf_retrieve_info_t *nf_retr_info);
void    nf_subscribe_nf_type(nf_retrieve_info_t *nf_retr_info, main_ctx_t *MAIN_CTX);
void    nf_subscribe_nf_type_print_log(AhifHttpCSMsgType *ahifPkt, const char *log_prefix);
void    nf_subscribe_nf_type_handle_resp_proc(AhifHttpCSMsgType *ahifPkt);
void    nf_subscribe_nf_type_handle_timeout(nrf_ctx_t *nf_ctx);
void    nf_subscribe_nf_type_recall_cb(evutil_socket_t fd, short what, void *arg);
int     nf_subscribe_nf_type_recv_subcription_id(nf_retrieve_info_t *nf_retr_info, AhifHttpCSMsgType *ahifPkt);
int     nf_subscribe_nf_type_recv_validity_time(nf_retrieve_info_t *nf_retr_info, AhifHttpCSMsgType *ahifPkt);
void    nf_subscribe_nf_type_retry_while_after(nf_retrieve_info_t *nf_retr_info);
void    nf_subscribe_nf_type_update_process(main_ctx_t *MAIN_CTX, nf_retrieve_info_t *nf_retr_info);
int     nf_subscribe_patch_create_body(AhifHttpCSMsgType *ahifPkt, nf_retrieve_info_t *nf_retr_info);
void    nf_subscribe_patch_create_pkt(main_ctx_t *MAIN_CTX, AhifHttpCSMsgType *ahifPkt, nf_retrieve_info_t *nf_retr_info);
void    nf_subscribe_patch_handle_resp_proc(AhifHttpCSMsgType *ahifPkt);
void    nf_subscribe_patch_modify_validity_with_wish(nf_retrieve_info_t *nf_retr_info);
void    nf_subscribe_patch_subscription(main_ctx_t *MAIN_CTX, nf_retrieve_info_t *nf_retr_info);
void    nf_subscribe_patch_wait_after(nf_retrieve_info_t *nf_retr_info);
nf_retrieve_info_t      *nf_subscribe_search_info_via_seqNo(main_ctx_t *MAIN_CTX, int seqNo);
void    nf_subscribe_start_process(main_ctx_t *MAIN_CTX);

/* ------------------------- command.c --------------------------- */
void    mml_function(IxpcQMsgType *rxIxpcMsg);
void    adjust_loglevel(TrcLibSetPrintMsgType *trcMsg);
int     func_dis_acc_token(IxpcQMsgType *rxIxpcMsg);

/* ------------------------- notify.c --------------------------- */
int     nf_notify_handle_check_req(AhifHttpCSMsgType *ahifPkt, char **problemDetail);
void    nf_notify_handle_profile_changed(main_ctx_t *MAIN_CTX, nf_retrieve_item_t *nf_item);
void    nf_notify_handle_request_proc(AhifHttpCSMsgType *ahifPkt);
int     nf_notify_profile_add(nf_retrieve_item_t *nf_older_item, json_object *js_nf_profile);
int     nf_notify_profile_modify(nf_retrieve_item_t *nf_item, json_object *js_profile_changes);
int     nf_notify_profile_remove(nf_retrieve_item_t *nf_item);
int     nf_notify_profile_replace(nf_retrieve_item_t *nf_item, json_object *js_nf_profile);
nf_retrieve_info_t      *nf_notify_search_info_by_uuid(main_ctx_t *MAIN_CTX, const char *nf_uuid);
nf_retrieve_item_t      *nf_notify_search_item_by_uuid(main_ctx_t *MAIN_CTX, const char *nf_uuid);
int     nf_notify_send_resp(AhifHttpCSMsgType *ahifPktRecv, int respCode, char *problemDetail);

/* ------------------------- regi.c --------------------------- */
int     nf_regi_check_registered_status(main_ctx_t *MAIN_CTX);
void    nf_regi_create_pkt(main_ctx_t *MAIN_CTX, AhifHttpCSMsgType *ahifPkt);
void    nf_regi_handle_resp_proc(AhifHttpCSMsgType *ahifPkt);
void    nf_regi_init_proc(main_ctx_t *MAIN_CTX);
void    nf_regi_recall_cb(evutil_socket_t fd, short what, void *arg);
void    nf_regi_retry_after_while();
int     nf_regi_save_location_header(main_ctx_t *MAIN_CTX, AhifHttpCSMsgType *ahifPkt);
int     nf_regi_save_recv_heartbeat_timer(main_ctx_t *MAIN_CTX);
void    nf_regi_save_recv_nf_profile(main_ctx_t *MAIN_CTX, AhifHttpCSMsgType *ahifPkt);

/* ------------------------- util.c --------------------------- */
int     check_number(char *ptr);
void    dump_pkt_log(void *msg, ssize_t size);
int     get_file_contents(const char* filename, char** outbuffer);
void    get_svc_ipv4_addr(const char *nic_name, char *nic_addr);
void    handle_ctx_timeout(evutil_socket_t fd, short what, void *arg);
void    LOG_JSON_OBJECT(const char *banner, json_object *js_obj);
void    start_ctx_timer(int ctx_type, nrf_ctx_t *nf_ctx);
void    stop_ctx_timer(int ctx_type, nrf_ctx_t *nf_ctx);
void    util_dumphex(FILE *out, const void* data, size_t size);
