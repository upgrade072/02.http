#ifndef __LIBNRF_APP_H__
#define __LIBNRF_APP_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <ctype.h>

#include <nrf_comm.h>
#include <libfort.h>

#ifdef LOG_LIB
#include <loglib.h>
#elif LOG_APP
#include <appLog.h>
#endif
#include <comm_msgtypes.h>

typedef struct http_con_handle_req {
	long mtype;

    http_mml_cmd_t command;
    char scheme[12];
    char type[16];
    char host[64];
    char ip[64];
    int port;
    int cnt;
} http_conn_handle_req_t;

typedef struct {
    int index;          /* my table index */
    int occupied;       /* use or not */
    int priority;       /* service priority - lowest better */ 
    int sel_count;      /* select count - lowest lowest */

    nf_comm_type    nfType;                         /* UDM UDR ETC DTC ... (now only avail UDM) */
    nf_type_info    nfTypeInfo;                     /* udmInfo udrInfo etc dtc ... (only avail udmInfo) */

    int allowdPlmnsNum;                             /* if 0, any plmn allowd */
    nf_comm_plmn allowdPlmns[NF_MAX_ALLOWD_PLMNS];  /* mcc mnc */

    char hostname[MAX_NF_UUID_LEN];                 /* nfInstance UUID */
    char serviceName[32];                           /* nudm-ueauth ... */

    time_t validityPeriod;                          /* NOW + remain time sec */
} nf_discover_raw;

#define MAX_NF_CACHE_NUM    1024
typedef struct {
    /* NF Profile(s) ... */
    GNode *root_node;
    /* NF Cache table raw ... */
    nf_discover_raw disc_cache[MAX_NF_CACHE_NUM];

    int nf_discover_table_step;     // every 60 sec, clear select info
} nf_discover_table;

typedef struct {
	int start_lbId;			/* lb id */
	int lbNum;				/* total lb num = 2 */

	int nfType;

    /* allowd plmn check */
	const char *mcc;
	const char *mnc;

    /* almost for UDM */
#define NF_DISC_ST_SUPI		0x0001
#define NF_DISC_ST_SUCI		0x0002
	int nfSearchType;
	const char *routing_indicators;
	const char *supi;

    /* almost for AMF */
    const char *region_id;
    const char *amf_set_id;
    const char *plmnId_in_guami;
    const char *amfId_in_guami;

	const char *serviceName;

#define NF_DISC_SE_LOW		0x0001
#define NF_DISC_SE_PRI		0x0002
	int selectionType;

} nf_discover_key;
/* for NRF APP -- end */

typedef struct {
	int occupied;
	int disc_raw_index;
	int disc_raw_vector;
} nf_discover_res_info;

#define MAX_NF_CACHE_RES	5
typedef struct {
	int res_num;
	nf_discover_res_info nf_disc_res[MAX_NF_CACHE_RES];
} nf_discover_local_res;


/* ------------------------- libnrf_app.c --------------------------- */
int     http2_appl_api_to_httpc(http_conn_handle_req_t *handle_req, int NRFC_QID);
nf_service_info *nf_discover_search(nf_discover_key *search_info, nf_discover_table *DISC_TABLE, nfs_avail_shm_t *NFS_TABLE, char *NF_DISC_RESULT, int NRFC_QID);
nf_service_info *nf_discover_search_cache(nf_discover_key *search_info, nf_discover_table *DISC_TABLE, nfs_avail_shm_t *NFS_TABLE, int NRFC_QID);
nf_service_info *nf_discover_search_udm(nf_discover_key *search_info, nf_discover_table *DISC_TABLE, nfs_avail_shm_t *NFS_TABLE, int NRFC_QID);
nf_service_info *nf_discover_search_amf(nf_discover_key *search_info, nf_discover_table *DISC_TABLE, nfs_avail_shm_t *NFS_TABLE, int NRFC_QID);
nf_service_info *nf_discover_search_udm_supi(nf_discover_key *search_info, nf_discover_table *DISC_TABLE, nfs_avail_shm_t *NFS_TABLE, int NRFC_QID);
nf_service_info *nf_discover_search_udm_suci(nf_discover_key *search_info, nf_discover_table *DISC_TABLE, nfs_avail_shm_t *NFS_TABLE, int NRFC_QID);
nf_service_info *nf_discover_result(nf_discover_local_res *result_cache, nf_discover_key *search_info, nf_discover_table *DISC_TABLE, nfs_avail_shm_t *NFS_TABLE, int NRFC_QID);
void    nf_discover_order_local_res(nf_discover_raw *disc_raw, nf_discover_local_res *result_cache, int selectionType);
void    nf_discover_res_log(nf_discover_local_res *result_cache, int selectionType);
int     nf_discover_check_cache_raw(nf_discover_raw *disc_raw, nf_discover_key *search_info);
int     nf_discover_table_handle(nf_discover_table *DISC_TABLE, char *json_string);
void    nf_discover_update_nf_profiles(nf_discover_table *DISC_TABLE, int nfType, const char *nfInstanceId, json_object *js_nf_profile, time_t *validity_time);
int     nf_discover_table_update(nf_discover_table *DISC_TABLE, json_object *js_nf_profile, time_t *validity_time);
void    nf_discover_raw_update(nf_discover_table *DISC_TABLE, int nfType, nf_type_info *nf_specific_info, int allowdPlmnsNum, nf_comm_plmn *allowdPlmns, const char *serviceName, const char *nfInstanceId, int priority, time_t *validity_time);
int     nf_discover_table_clear_cached(nf_discover_table *DISC_TABLE);
void    nf_discover_table_print(nf_discover_table *DISC_TABLE, char *print_buffer, size_t buffer_size);
GNode   *nf_discover_create_new_node(nf_disc_host_info *insert_item);
GNode   *nf_discover_add_new_node(GNode **root, GNode *child);
nf_disc_host_info       *nf_discover_search_node_by_hostname(GNode **root, const char *hostname);
void    nf_discover_remove_expired_node(GNode **root);
int     nf_search_specific_info(json_object *nf_profile, json_object **js_specific_info);
void    nf_get_specific_info(int nfType, json_object *js_specific_info, nf_type_info *nf_specific_info);
void    nf_get_specific_info_udm(json_object *js_specific_info, nf_type_info *nf_specific_info);
void    nf_get_specific_info_amf(json_object *js_specific_info, nf_type_info *nf_specific_info);
int     nf_get_allowd_plmns(json_object *nf_profile, nf_comm_plmn *allowdPlmns);
char    *nf_type_to_str(int nfType);
int     nf_type_to_enum(char *type);
int     check_number(char *ptr);
json_object     *search_json_object(json_object *obj, char *key_string);

#endif
