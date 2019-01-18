
// system header wierd
#include "uninclude.h"

#include <http_comm.h>
#include <commlib.h>
#ifdef UDMR
#include <stm_msgtypes_udmudr.h>
#else
#include <sfm_msgtypes.h>
#include <stm_msgtypes.h>
#endif

/* ------------------------- libmml.c --------------------------- */
int     get_mml_para_int (MMLReqMsgType *msg, char *paraName);
int     get_mml_para_str (MMLReqMsgType *msg, char *paraName, char *buff);
int     get_mml_para_strMax (MMLReqMsgType *msg, char *paraName, char *buff, int maxSize);
int     send_mml_res_failMsg(IxpcQMsgType *rxIxpcMsg, char *rltMsg);
int     send_mml_res_succMsg(IxpcQMsgType *rxIxpcMsg, char *rltMsg, char contFlag, unsigned short extendTime, char seqNo);
int     send_response_mml(IxpcQMsgType *rxIxpcMsg, char *resbuf, char resCode, char contFlag, unsigned short extendTime, char seqNo);

/* ------------------------- libomp.c --------------------------- */
void    http_report_status(SFM_HttpConnStatusList *http_status, int msgId);
void    http_stat_inc(int thrd_idx, int host_idx, int stat_idx);
void 	stat_function(IxpcQMsgType *rxIxpcMsg, int running_thrd_num, int httpc, int https, int msgId);
void    print_stat(STM_CommonStatMsgType *commStatMsg, STM_CommonStatMsg *commStatItem, char (*str)[128], int size);

/* ------------------------- liblist.c --------------------------- */
int     new_list(const char *name);
int     get_list(const char *name);
char*   get_list_name(int list_id);
int     del_list(const char *name);
int     new_item(int list_index, const char *name, int port);
int     get_item(int list_index, const char *name, int port);
int     del_item(int list_index, const char *name, int port);

/* ------------------------- libid.c --------------------------- */
int     Init_CtxId(int thrd_idx);
int     Get_CtxId(int thrd_idx);
int     Free_CtxId(int thrd_idx, uint id);
int     Check_CtxId(int thrd_idx, uint id);

/* ------------------------- libutil.c --------------------------- */
void    DumpHex(const void* data, size_t size);
unsigned        long create_unique_id(unsigned long u_id);
