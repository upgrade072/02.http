
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

// for nrf
#include <libnrf.h>
// for isif
#include <isif_msgtypes.h>

#include <nrf_comm.h>

/* for .cfg */
#define CF_LOGLEVEL         "nrfc_cfg.sys_config.log_level"
#define CF_OVLDINFO         "nrfc_cfg.service_profile"

typedef struct qid_info {
    int nrfc_qid;       // my recv queue
	int isifc_tx_qid;	// send
	int isifs_rx_qid;	// recv
} qid_info_t;

typedef struct fep_nfs_info {
	int lbId;
	int seqNo;
	int inProgress;
} fep_nfs_info_t;

typedef struct main_ctx {
    config_t CFG;
    struct event_base *EVBASE;

    svr_info_t my_info;
	qid_info_t my_qid;
	GSList *lb_assoc_list;		// dynamic
	GSList *my_service_list;	// static

	nfs_avail_shm_t *SHM_NFS_AVAIL;
	time_t last_pub_time;
	fep_nfs_info_t fep_nfs_info[NF_MAX_LB_NUM];
} main_ctx_t;
/* ------------------------- config.c --------------------------- */
int     init_cfg(config_t *CFG);

/* ------------------------- status.c --------------------------- */
void    isif_save_recv_lb_status(main_ctx_t *MAIN_CTX, nf_service_info *nf_info);
void    printf_fep_nfs(nfs_avail_shm_t *SHM_NFS_AVAIL);
void    clear_fep_nfs(evutil_socket_t fd, short what, void *arg);

/* ------------------------- isif.c --------------------------- */
SHM_IsifConnSts *commlib_initIsifConnSts(void); // ??? function proto ;
int     isifc_init();
void    isifc_create_pkt_for_status(IsifMsgType *txIsifMsg, service_info_t *fep_svc, svr_info_t *my_info, assoc_t *lb_assoc);
void    isifc_send_pkt_for_status(int isifc_qid, IsifMsgType *txIsifMsg);

/* ------------------------- main.c --------------------------- */
int     get_my_qid(main_ctx_t *MAIN_CTX);
int     get_olcd_index_with_tps(char *svc_name, int *tps);
void    fep_service_log(service_info_t *fep_svc);
int     get_proc_table_index(char *proc_name);
int     set_overload_info(main_ctx_t *MAIN_CTX, config_setting_t *elem);
int     get_overload_info(main_ctx_t *MAIN_CTX);
void    init_log(main_ctx_t *MAIN_CTX);
int     initialize(main_ctx_t *MAIN_CTX);
int     create_nfs_avail_shm(main_ctx_t *MAIN_CTX);
int     main();
void    main_tick_callback(evutil_socket_t fd, short what, void *arg);
int     set_bep_conn_num(SHM_IsifConnSts *shmConnSts);
void    collect_service_status(service_info_t *fep_svc);
void    send_status_to_lb(service_info_t *fep_svc, assoc_t *lb_assoc);
void    broad_status_to_lb(assoc_t *lb_assoc);
void    service_status_broadcast(evutil_socket_t fd, short what, void *arg);
void    start_loop(main_ctx_t *MAIN_CTX);
void    message_handle(evutil_socket_t fd, short what, void *arg);
void    shmq_recv_handle(evutil_socket_t fd, short what, void *arg);
void    directory_watch_action(const char *file_name);
void    start_watching_dir(struct event_base *evbase);
