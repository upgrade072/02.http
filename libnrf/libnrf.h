#ifndef __LIBNRF_H__
#define __LIBNRF_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <ctype.h>

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

#include <nrf_comm.h>

// monitor config file change
#include <sys/inotify.h>

// table print
#include <libfort.h>

//------- message --------//
#define LIBNRF_MSG_SERVICE_INFO         1000
#define LIBNRF_MSG_ADD_NF_PROFILE       1001
#define LIBNRF_MSG_ADD_NF_CALLBACK      1002

typedef struct svr_info {
    char mySysName[COMM_MAX_NAME_LEN];
    char myProcName[COMM_MAX_NAME_LEN];
    char mySysType[COMM_MAX_VALUE_LEN];
    //char mySvrId[COMM_MAX_VALUE_LEN]; /* no use */
	int myLabelNum;
} svr_info_t;

typedef struct assoc {
    char name[1024];
    char type[1024];
    char group[1024];
    char ip[1024];
} assoc_t;

#define MAX_NRFC_CHK_PROC   12
typedef struct service_info {
    //------- message --------//
    long mtype;                                     /* LIB --> NRFC msgsnd, msg mtype */

    int sys_mp_id;
    char service_name[128];
    char ovld_name[128];
    int proc_num;
    char proc_name[MAX_NRFC_CHK_PROC][128];
    int chk_all_active;
    int ovld_tps;
    int curr_tps;
    int curr_load;
    int proc_table_index[MAX_NRFC_CHK_PROC];
    int proc_last_count[MAX_NRFC_CHK_PROC];  // mapping with keepalive shm table
    int proc_curr_count[MAX_NRFC_CHK_PROC];  // ..
    int proc_alive;       // -> alive of not 
    int olcd_table_index; // mapping with OLCD shm table
    int bep_use;
    int bep_conn;
} service_info_t;

// httpc/s to NRFM, i'm alive 
typedef struct nrfm_noti {
	pid_t	my_pid;
} nrfm_noti_t;

// for NRFM MML to HTTPC
#define MAX_NF_SVC	5
typedef struct nf_conn_info {
	int occupied;
	int svcNum;
	char service[MAX_NF_SVC][12];
	char scheme[12];
	char ip[64];
	int port;
	int cnt;
} nf_conn_info_t;

typedef enum nrfm_mml_cmd {
	NRFM_MML_HTTPC_CLEAR = 0, /* NRFM restart clear all */
	NRFM_MML_HTTPC_ADD,		/* add & act */
	NRFM_MML_HTTPC_ACT,
	NRFM_MML_HTTPC_DACT,
	NRFM_MML_HTTPC_DEL		/* dact & del */
} nrfm_mml_cmd_t;

typedef struct nrfm_mml {
	/* key */
	int seqNo;

	/* request */
	nrfm_mml_cmd_t command;
    int nrfm_auto_added;
	char host[64];
	char type[16];
	int info_cnt;
	nf_conn_info_t nf_conns[HTTP_MAX_ADDR];
	int token_id;

	/* response */
	int id;
} nrfm_mml_t;

// for Access Token

#define CONTENT_TYPE_OAUTH_REQ "application/x-www-form-urlencoded"

#define HBODY_ACCESS_TOKEN_REQ_FOR_TYPE "\
grant_type=client_credentials&\
nfInstanceId=%s&\
nfType=%s&\
targetNfType=%s&\
scope=%s"

#define HBODY_ACCESS_TOKEN_REQ_FOR_INSTANCE "\
grant_type=client_credentials&\
nfInstanceId=%s&\
scope=%s&\
targetNfInstanceId=%s"

typedef enum nrf_acc_type {
    AT_SVC = 0,         // token for SVC
    AT_INST             // token for specific {Instance}
} nrf_acc_type_t;

typedef enum token_acuire_status {
    TA_INIT = 0,        // not any action
    TA_FAILED,          // requested but failed
    TA_TRYING,          // trying to get token
    TA_ACQUIRED         // token accuired
} token_acuire_status_t;

#define MAX_NRF_TYPE_LEN    24
#define MAX_NRF_INST_LEN    128
#define MAX_NRF_SCOPE_LEN   256
#define MAX_ACC_TOKEN_LEN	512
typedef struct acc_token_info {
    /* used */
    int occupied;

    /* table view */
    int token_id;
    // don't use : char nrf_addr[INET6_ADDRSTRLEN + 12];
    int acc_type;
    char nf_type[MAX_NRF_TYPE_LEN];
    char nf_instance_id[MAX_NRF_INST_LEN];
    char scope[MAX_NRF_SCOPE_LEN];
    int status;
	char operator_added;
    time_t due_date;
    time_t last_request_time;

    int token_pos; // 0, 1
    char access_token[2][MAX_ACC_TOKEN_LEN];
} acc_token_info_t;

#define MAX_ACC_TOKEN_NUM	(1024 + 1) // id start from 1, 1~1024
typedef struct acc_token_shm_t {
	acc_token_info_t acc_token[MAX_ACC_TOKEN_NUM];
} acc_token_shm_t;
#define SHM_ACC_TOKEN_TABLE_SIZE (sizeof(acc_token_shm_t))

/* for NRF Statistics  -- start */
typedef enum {
    NRFS_ATTEMPT,
    NRFS_SUCCESS,
    NRFS_FAIL,
    NRFS_TIMEOUT,
    NRFS_CATE_MAX
} nrf_stat_cate_t;

typedef enum {
    NFRegister,
    NFUpdate,
    NFListRetrieval,
    NFProfileRetrieval,
    NFStatusSubscribe,
    NFStatusSubscribePatch,
    NFStatusNotify,
    AccessToken,
    NRFS_OP_MAX
} nrf_stat_op_enum_t;

typedef struct {
    char hostname[128];
    int stat_count[NRFS_OP_MAX][NRFS_CATE_MAX];
} nrf_stat_t;
/* for NRF Statistics  -- end */

/* ------------------------- libnrf.c --------------------------- */
void    def_sigaction();
GSList  *get_associate_node(GSList *node_assoc_list, const char *type_str);
int     get_my_info(svr_info_t *my_info, const char *my_proc_name);
void    node_assoc_release(assoc_t *node_elem);
void    node_list_remove_all(GSList *node_assoc_list);
GSList  *node_list_add_elem(GSList *node_assoc_list, assoc_t *node_elem);
void    node_assoc_log(assoc_t *node_elem);
void    node_list_print_log(GSList *node_assoc_list);
int     watch_directory_init(struct event_base *evbase, const char *path_name, void (*callback_function)(const char *arg_is_path));
acc_token_info_t        *get_acc_token_info(acc_token_shm_t *ACC_TOKEN_LIST, int id, int used);
acc_token_info_t        *new_acc_token_info(acc_token_shm_t *ACC_TOKEN_LIST);
char    *get_access_token(acc_token_shm_t *ACC_TOKEN_LIST, int token_id);
void    print_token_info_raw(acc_token_shm_t *ACC_TOKEN_LIST, char *respBuff);
void    print_nrfm_mml_raw(nrfm_mml_t *httpc_cmd);
void    getTypeSpecStrDump(nf_service_info *nf_info, char *resBuf);
void    getTypeSpecStrTest(nf_comm_type nfType, nf_type_info *nfTypeInfo, char *resBuf);
void    getAllowdPlmns(nf_service_info *nf_info, char *resBuf);
void    getAllowdPlmnsTest(int allowdPlmnsNum, nf_comm_plmn *allowdPlmns, char *resBuf);
void    printf_avail_nfs(nf_list_pkt_t *avail_nfs);
int     cnvt_cfg_to_json(json_object *obj, config_setting_t *setting, int callerType);
GNode   *NRF_STAT_ADD_CHILD(GNode *ROOT_STAT, char *hostname);
GNode   *NRF_STAT_ADD_CHILD_POS(GNode *ROOT_NODE, GNode *SIBLING, char *hostname, int pre_or_append);
GNode   *NRF_STAT_FIND_CHILD(GNode *ROOT_STAT, char *hostname, int *compare_res);
void    NRF_STAT_INC(GNode *ROOT_STAT, char *hostname, int operation, int category);
#ifdef STAT_LEGACY
void    stat_cnvt_5geir_nrfm(STM_CommonStatMsg *commStatItem, STM_NrfmStatistics_s *nrfm_stat);
#endif
void    nrf_stat_function(int ixpcQid, IxpcQMsgType *rxIxpcMsg, int event_code, GNode *ROOT_STAT);
char *get_nrfm_cmd_str(int cmd);

#endif /* __LIBNRF_H__ */


