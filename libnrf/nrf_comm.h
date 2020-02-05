#ifndef __NRF_COMM_H__
#define __NRF_COMM_H__

#include <stdio.h>
#include <glib.h>
#include <json-c/json.h>
#include <json-c/json_object.h>
#include <http_comm.h>

typedef enum {
	NF_TYPE_UNKNOWN = 0,
	NF_TYPE_NRF,
	NF_TYPE_UDM,
	NF_TYPE_AMF,
	NF_TYPE_SMF,
	NF_TYPE_AUSF,
	NF_TYPE_NEF,
	NF_TYPE_PCF,
	NF_TYPE_SMSF,
	NF_TYPE_NSSF,
	NF_TYPE_UDR,
	NF_TYPE_LMF,
	NF_TYPE_GMLC,
	NF_TYPE_5G_EIR,
	NF_TYPE_SEPP,
	NF_TYPE_UPF,
	NF_TYPE_N3IWF,
	NF_TYPE_AF,
	NF_TYPE_UDSF,
	NF_TYPE_BSF,
	NF_TYPE_CHF,
	NF_TYPE_NWDAF,
    NF_TYPE_MAX
} nf_comm_type;

// TODO
typedef enum {
	NF_ADD_RAW = 0,     // LB command added
	NF_ADD_NRF,         // NRF discover | retrieve | notify added
	NF_ADD_MML,         // FEP command added (not connection but only info)
    NF_ADD_CALLBACK     // FEP applicaton added
} nf_add_type;

typedef enum http_mml_cmd {
	HTTP_MML_HTTPC_CLEAR = 0,	// NRFM restarted, clear all auto add cmd
	HTTP_MML_HTTPC_ADD,			// -> add & auto act
	HTTP_MML_HTTPC_ACT,
	HTTP_MML_HTTPC_DACT,
	HTTP_MML_HTTPC_DEL,			// -> auto dact & delete
	HTTP_MML_HTTPC_TOMBSTONE	// -> remove tomestoned connection
} http_mml_cmd_t;


typedef struct {
	char mcc[3 + 1];    // '^\d{2,3}$'
	char mnc[3 + 1];
} nf_comm_plmn;

typedef struct  {
	char start[22];     //  '^(imsi-[0-9]{5,15}|nai-.+|.+)$'.  15 + 5
	char end[22];
} nf_comm_supi_range;

// 2020.01.21 for ePCF
// External Identifier or External Group Identifier or MSISDN
typedef struct  {
	char start[22];     //  ^([0-9]+$
	char end[22];
} nf_comm_identity_range;

typedef struct  {
	char start[20];     // e.g 192.168.70.1
	char end[20];
} nf_comm_ipv4_addr_range;

typedef struct  {
	char start[64];     // e.g 2001:db8:abcd:12::0/64
	char end[64];
} nf_comm_ipv6_prefix_range;

typedef struct  {
	char start[8];     // e.g [0-9]{3}[0-9]{2,3}$
	char end[8];
} nf_comm_plmn_range;


#define NF_MAX_SUPI_RANGES			3
#define NF_MAX_RI					5
typedef struct {
	char groupId[27 + 1];   // '^[A-Fa-f0-9]{8}-[0-9]{3}-[0-9]{2,3}-([A-Fa-f0-9][A-Fa-f0-9]){1,10}$' 8-3-3-10

	int supiRangesNum;
	nf_comm_supi_range supiRanges[NF_MAX_SUPI_RANGES];

	// gpsiRanges ?
	// externalGroupIdentifiersRanges ?

	int	routingIndicatorsNum;
	char routingIndicators[NF_MAX_RI][4 + 1];  // '^[0-9]{1,4}$'
} nf_udm_info;

typedef struct {
    char plmnId[6 + 1];     // ^[0-9]{3}-[0-9]{2,3}$  ex) 302-720
    char amfId[6 + 1];      // '^[A-Fa-f0-9]{6}$'
} nf_guami_info;

#define NF_MAX_GUAMI_NUM        5
typedef struct {
    char amfRegionId[2 + 1];    // '^[A-Fa-f0-9]{2}$'
    char amfSetId[3 + 1];   // '^[0-3][A-Fa-f0-9]{2}$'

    int guamiListNum;
    nf_guami_info nf_guami[NF_MAX_GUAMI_NUM];

    // taiList ?
    // taiRangeList ?
    // backupInfoAmfFailure ?
    // backupInfoAmfRemoval ?

    // n2InterfaceAmfInfo ? (X)
} nf_amf_info;

/*
 * 2020.01.21 for ePCF
 * UDR
 */
#define NF_MAX_GPSI_RANGES				3
#define NF_MAX_EXTERNAL_GRP_ID_RANGES	3
typedef struct {
	char groupId[27 + 1];   // '^[A-Fa-f0-9]{8}-[0-9]{3}-[0-9]{2,3}-([A-Fa-f0-9][A-Fa-f0-9]){1,10}$' 8-3-3-10

	int supiRangesNum;
	nf_comm_supi_range supiRanges[NF_MAX_SUPI_RANGES];

	int gpsiRangesNum;
	nf_comm_identity_range gpsiRanges[NF_MAX_GPSI_RANGES];

	int externalGroupIdentifierRangesNum;
	nf_comm_identity_range externalGrpIdRanges[NF_MAX_EXTERNAL_GRP_ID_RANGES];

	char supportedDataSets[16]; // SUSCRIPTION, POLICY, EXPOSURE, APPLICATION
} nf_udr_info;

/*
 * 2020.01.21 for ePCF
 * BSF
 */
#define NF_MAX_IPV4_ADDR_RANGES			3
#define NF_MAX_IPV6_PREFIX_RANGES		3
#define NF_MAX_DNN_LIST_NUM				10
#define NF_MAX_DNN_LEN					32
#define NF_MAX_IP_DOMAIN_LIST_NUM		10
#define NF_MAX_IP_DOMAIN_LEN			32
typedef struct {
	int ipv4AddressRangesNum;
	nf_comm_ipv4_addr_range ipv4AddrRanges[NF_MAX_IPV4_ADDR_RANGES];

	int ipv6PrefixRangesNum;
	nf_comm_ipv6_prefix_range ipv6PrefixRanges[NF_MAX_IPV6_PREFIX_RANGES];

	int dnnListNum;
	char dnnList[NF_MAX_DNN_LIST_NUM][NF_MAX_DNN_LEN];
	
	int ipDomainListNum;
	char ipDomainList[NF_MAX_IP_DOMAIN_LIST_NUM][NF_MAX_IP_DOMAIN_LEN];
} nf_bsf_info;

/*
 * 2020.01.21 for ePCF
 * CHF
 */
#define NF_MAX_PLMN_RANGES       		10
typedef struct {
	int supiRangesNum;
	nf_comm_supi_range supiRanges[NF_MAX_SUPI_RANGES];

	int gpsiRangesNum;
	nf_comm_identity_range gpsiRanges[NF_MAX_GPSI_RANGES];

	int plmnRangesNum;
	nf_comm_plmn_range plmnRanges[NF_MAX_PLMN_RANGES];
} nf_chf_info;


typedef union {
	nf_udm_info udmInfo;
	nf_amf_info amfInfo;
	// 2020.01.21 for ePCF
	nf_udr_info udrInfo;
	nf_bsf_info bsfInfo;
	nf_chf_info chfInfo;
} nf_type_info;

#define NF_MAX_ALLOWD_PLMNS			3
typedef struct {
	int occupied;		
	int lbId;

	/* [DON'T USE] only for nrfc */
	int seqNo;
	int index;
	int lastIndex;

	/* use for application */
	int table_index;

	nf_comm_type nfType;	// NF_TYPE_UDM
	nf_type_info nfTypeInfo;
	int allowdPlmnsNum;     /* if 0, can handle any plmn */
	nf_comm_plmn allowdPlmns[NF_MAX_ALLOWD_PLMNS];

	char serviceName[32];   // "nudm-ueauth"
    int available;

	char type[12];
	char hostname[52];
	char confname[52];
	char scheme[12];
	char ipv4Address[32];
	int port;
	int priority;
	int load;

	int auto_add;
} nf_service_info;

#define NF_MAX_LB_NUM				5
#define NF_MAX_AVAIL_LIST			(1024 * 4) /* MAX_CON_NUM : 1024 (host) * 4 (addr) */
typedef struct {
	int nf_avail_cnt[NF_MAX_LB_NUM]; /* num of item */
	nf_service_info nf_avail[NF_MAX_LB_NUM][NF_MAX_AVAIL_LIST];
} nf_list_shm_t;

/* for fep shared memory */
#define MAX_NFS_SHM_POS				3
typedef struct {
	int curr_pos;
	nf_list_shm_t nfs_avail_shm[MAX_NFS_SHM_POS];
} nfs_avail_shm_t;

/* for lb send pkt */
typedef struct {
	int nf_avail_num;
	nf_service_info nf_avail[NF_MAX_AVAIL_LIST];
} nf_list_pkt_t;


#define MAX_NF_UUID_LEN 52
#define MAX_NF_PROFILE_LEN 8192
typedef struct {
    //------- message --------//
    long mtype;                                     /* LIB --> NRFC msgsnd, msg mtype */

    //------- body ptr -------//
    int  lbIndex;                                   /* this message send for */
    char nfType[16];                                /* UDM UDR ... */
    char hostname[MAX_NF_UUID_LEN];                 /* nfInstance UUID */
    size_t profile_length;                          /* profile string length */
    char nfProfile[MAX_NF_PROFILE_LEN];             /* save json profile as compact scheme */

    //--------- info ---------//
    time_t validityPeriod;                          /* NOW + remain time sec */
    int requested;                                  /* send request only 1 times per sec */
} nf_disc_host_info;
#define NF_DISC_HOSTINFO_LEN(a) (sizeof(a->mtype) + sizeof(a->lbIndex) + sizeof(a->nfType) + sizeof(a->hostname) + sizeof(a->profile_length) + a->profile_length)

void    nf_get_specific_info_str(nf_comm_type nfType, nf_type_info *nfTypeInfo, char *resBuf);
void    nf_get_allowd_plmns_str(int allowdPlmnsNum, nf_comm_plmn *allowdPlmns, char *resBuf);
#endif
