#ifndef __NRF_COMM_H__
#define __NRF_COMM_H__

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
	NF_TYPE_NWDAF
} nf_comm_type;

// TODO
typedef enum {
	NF_ADD_RAW = 0,
	NF_ADD_NRF,
	NF_ADD_MML
} nf_add_type;

typedef struct {
	char mcc[12];
	char mnc[12];
} nf_comm_plmn;

typedef struct  {
	char start[32];
	char end[32];
} nf_comm_supi_range;

#define NF_MAX_SUPI_RANGES			3
#define NF_MAX_RI					5
typedef struct {
	char groupId[12];

	int supiRangesNum;
	nf_comm_supi_range supiRanges[NF_MAX_SUPI_RANGES];

	// gpsiRanges ?
	// externalGroupIdentifiersRanges ?

	int	routingIndicatorsNum;
	char routingIndicators[NF_MAX_RI][12];
} nf_udm_info;

typedef union {
	nf_udm_info udmInfo;
} nf_type_info;

#define NF_MAX_ALLOWD_PLMNS			3
typedef struct {
	int occupied;		
	int lbId;

	/* nrfc */
	int seqNo;
	int index;
	int lastIndex;

	nf_comm_type nfType;	// NF_TYPE_UDM
	nf_type_info nfTypeInfo;

	int allowdPlmnsNum;	/* if 0, can handle any plmn */
	nf_comm_plmn allowdPlmns[NF_MAX_ALLOWD_PLMNS];

	char serviceName[32];   // "nudm-ueauth"

	char hostname[52];
	char type[12];
	char scheme[12];
	char ipv4Address[32];
	int port;
	int priority;

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

#endif
