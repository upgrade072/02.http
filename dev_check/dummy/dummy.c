#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#include <unistd.h>
#include <pthread.h>

#include <time.h>

#include <shmQueue.h>
#include <commlib.h>
#include <ahif_msgtypes.h>

#include <http_comm.h>
#include <libs.h>

#include "body.h"

int httpsRxQid, httpsTxQid;

int initialize()
{
    char fname[64] = { 0, }; 
    char TEMP_CONF_FILE[128] = { "../temp.conf" };
    
    sprintf(fname, "%s", TEMP_CONF_FILE);
    if ((httpsRxQid = shmqlib_getQid (fname, "AHIF_TO_APP_SHMQ", "HTTPS", SHMQLIB_MODE_PUTTER)) < 0)
        return -1;
    if ((httpsTxQid = shmqlib_getQid (fname, "APP_TO_AHIF_SHMQ", "HTTPS", SHMQLIB_MODE_GETTER)) < 0)
        return -1;

	return 0;
}

int main() {
    char ResMsg[sizeof(AhifHttpCSMsgType) + 1024];
    AhifHttpCSMsgType *ReqMsg = (AhifHttpCSMsgType *)&ResMsg;
	AhifHttpCSMsgType res;
	int sleep_cnt = 0, receive_cnt = 0, msgSize;
	int length = strlen(helloworld);

	if (initialize() < 0) {
		fprintf(stderr,">>>>>> dummy_initial fail\n");
		return -1;
	}

	// make response
	sprintf(res.body, "%s", helloworld);
	fprintf(stderr, "FUCK BODY LEN [%d]\n", length);
		
	while (1) 
	{
		if((msgSize = shmqlib_getMsg (httpsTxQid, ResMsg)) <= 0 ) {
			sleep_cnt ++;
			if (sleep_cnt == 1000) {
				usleep(1);
				sleep_cnt = 0;
			}
			continue;
		}
		ResMsg[msgSize] = '\0';
		sleep_cnt = 0;
		receive_cnt ++;

#ifndef PERFORM
		fprintf(stderr, "RECEIVE RAW[ MSGLEN:%d (HEADER:%zu) (RES_T:%zu) ]\n", msgSize, 
				AHIF_HTTPCS_MSG_HEAD_LEN, sizeof(AhifHttpCSMsgType));
		DumpHex(ReqMsg, AHIF_HTTPCS_MSG_HEAD_LEN + ReqMsg->head.bodyLen);
		fprintf(stderr, "request_method: %s\n", ReqMsg->head.httpMethod);
		fprintf(stderr, "request_path  : %s\n", ReqMsg->head.rsrcUri);
		fprintf(stderr, "request_body_len : %d\n", ReqMsg->head.bodyLen);
		fprintf(stderr, "request_body  :\n%s", ReqMsg->body);
		fprintf(stderr, "=====================================================================\n\n");
#endif
		//DumpHex(ReqMsg, AHIF_HTTPCS_MSG_HEAD_LEN + ReqMsg->head.bodyLen);
#if 1
		fprintf(stderr, "request_path  : %s\n", ReqMsg->head.rsrcUri);
		fprintf(stderr, "test %d %s\n", ReqMsg->vheader[0].vheader_id, ReqMsg->vheader[0].vheader_body);
		fprintf(stderr, "test %d %s\n", ReqMsg->vheader[1].vheader_id, ReqMsg->vheader[1].vheader_body);
#endif

		res.head.thrd_index = ReqMsg->head.thrd_index;
		res.head.session_index = ReqMsg->head.session_index;
		res.head.session_id = ReqMsg->head.session_id;
		res.head.stream_id = ReqMsg->head.stream_id;
		res.head.ctx_id = ReqMsg->head.ctx_id;

		memcpy(&res.head, &ReqMsg->head, AHIF_HTTPCS_MSG_HEAD_LEN);
		sprintf(res.head.contentEncoding, "%s", "killencoding");
		res.head.bodyLen = length;
		// test result
		res.head.respCode = 300;
#ifndef PERFORM
		fprintf(stderr, "response_body_len : %d\n", res.head.bodyLen);
		//DumpHex(&res, AHIF_HTTPCS_MSG_HEAD_LEN + res.head.bodyLen);
		fprintf(stderr, "=====================================================================\n\n");
#endif
		if (shmqlib_putMsg(httpsRxQid, (char *)&res, AHIF_HTTPS_SEND_SIZE(res)) <= 0) {
			fprintf(stderr, "DBG cant send to server\n");
		}
	}
}
