
#ifndef __HTTP_LIBS_INVOKED__
#define __HTTP_LIBS_INVOKED__

// system header wierd
#include "uninclude.h"

#include <http_comm.h>
#include <commlib.h>
#include <nghttp2/nghttp2.h>

#ifdef EPCF
#include <sfm_msgtypes.h>
#include <stm_msgtypes.h>
#else
#include <stm_msgtypes_udmudr.h>
#endif

#if 0
#ifdef LOG_LIB
#include <loglib.h>
#elif LOG_APP
#include <appLog.h>
#elif LOG_PRINT
#endif

#ifdef LOG_LIB
#define APPLOG(level, fmt, ...) logPrint(ELI, FL, fmt "\n", ##__VA_ARGS__)
#elif LOG_APP
#else
#define APPLOG(level, fmt, ...) fprintf(stderr, fmt "\n", ##__VA_ARGS__)
#endif
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

/* ------------------------- libutil.c --------------------------- */
void    DumpHex(const void* data, size_t size);
unsigned        long create_unique_id(unsigned long u_id);
int 	ishex(int x);
void    encode(const char *s, char *enc, int scheme);
int     decode(const char *s, char *dec);
void	json_delimiter(char *string);
char    *replaceAll(char *s, const char *olds, const char *news) ;

/* ------------------------- libhdr.c --------------------------- */
int     set_defined_header(hdr_index_t HDR_INDEX[], char *name, char *val, AhifHttpCSMsgType *appData);
int		assign_more_headers(hdr_index_t HDR_INDEX[], nghttp2_nv *hdrs, int size, int cur_len, AhifHttpCSMsgType *appData);
void    print_header(FILE *f, const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen);
void    print_headers(FILE *f, nghttp2_nv *nva, size_t nvlen);

/* ------------------------- liblog.c --------------------------- */
int     initlog_for_loglib(char *appName, char *path);

/* ------------------------- libid.c --------------------------- */
int     Init_CtxId(int thrd_idx);
int     Get_CtxId(int thrd_idx);
int     Free_CtxId(int thrd_idx, uint id);
int     Check_CtxId(int thrd_idx, uint id);

#endif
