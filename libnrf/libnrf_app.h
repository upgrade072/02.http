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


/* -NF STATUS TABLE ------------------------------------------ */
#define NF_NODE_DATA_DEPTH  5

typedef struct nf_lbid_info {
    int lb_id;
} nf_lbid_info_t;

typedef struct nf_type_info {
    char type[16];
} nf_type_info_t;

typedef struct nf_host_info {
    char hostname[52];

    int allowdPlmnsNum;
    nf_comm_plmn allowdPlmns[NF_MAX_ALLOWD_PLMNS];

    nf_comm_type nfType;
    nf_type_info nfTypeInfo;

    int auto_add;
} nf_host_info_t;

typedef struct nf_svcname_info {
    char servicename[32];
} nf_svcname_info_t;

typedef struct nf_connection_info {
    char connInfoStr[64];   // https://192.168.200.231:5555

    int auto_add;
    int priority;
    int load;
    int avail;

    nf_service_info *nf_service_shm_ptr;
} nf_connection_info_t;

typedef struct nf_search_key {
    int depth;
    int lb_id;
    const char *nf_type;
    const char *nf_host;
    const char *nf_svcname;
    char nf_conn_info[64];
} nf_search_key_t;
/* -NF STATUS TABLE ------------------------------------------ */

/* ------------------------- libnrf_app.c --------------------------- */
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
void    nf_get_specific_info_str(nf_comm_type nfType, nf_type_info *nfTypeInfo, char *resBuf);
void    nf_get_allowd_plmns_str(int allowdPlmnsNum, nf_comm_plmn *allowdPlmns, char *resBuf);
char    *nf_type_to_str(int nfType);
int     nf_type_to_enum(char *type);
int     check_number(char *ptr);
json_object     *search_json_object(json_object *obj, char *key_string);
gboolean        node_free_data(GNode *node, gpointer data);
void    create_full_depth_key (nf_search_key_t *key, nf_service_info *insert_data);
GNode   *create_nth_child(nf_search_key_t *key, nf_service_info *insert_data);
int     depth_compare(nf_search_key_t *key, GNode *compare_node);
GNode   *search_or_create_node(GNode *node, nf_search_key_t *key, nf_service_info *insert_data, int create_if_none);
void    create_node_data(GNode *root_node, nf_search_key_t *key, nf_service_info *insert_data);
GNode   *search_node_data(GNode *root_node, nf_search_key_t *key, int search_depth);
void    print_node_table(ft_table_t *table, GNode *node, int depth, char *temp_buff, char *nf_type_arg);
void    print_node(ft_table_t *table, GNode *node, int depth, char *nf_type);
void    printf_fep_nfs_by_node_order(GNode *root_node, char *printBuff, char *nf_type);
void    printf_fep_nfs_well_form(nfs_avail_shm_t *SHM_NFS_AVAIL, char *printBuff, char *nf_type);

#endif
