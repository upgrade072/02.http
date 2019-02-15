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

const char METHOD[] = "PUT";
const char PATH[] = "/index.html/aaa/bbb";

int httpcRxQid, httpcTxQid;

int initialize()
{
    char fname[64] = { 0, };
    char TEMP_CONF_FILE[128] = { "../temp.conf" };

    sprintf(fname, "%s", TEMP_CONF_FILE);
    if ((httpcRxQid = shmqlib_getQid (fname, "AHIF_TO_APP_SHMQ", "HTTPC", SHMQLIB_MODE_PUTTER)) < 0)
        return -1;
    if ((httpcTxQid = shmqlib_getQid (fname, "APP_TO_AHIF_SHMQ", "HTTPC", SHMQLIB_MODE_GETTER)) < 0)
        return -1;

	return 0;
}

int main() {
	if (initialize() < 0) {
		fprintf(stderr,">>>>>> sender_initial fail\n");
		return -1;
	}

	AhifHttpCSMsgType req;
    char ResMsg[sizeof(AhifHttpCSMsgType) + 1024];
	AhifHttpCSMsgType *res = (AhifHttpCSMsgType *)&ResMsg;
	int msgSize;
	int body_len = strlen(BODY);

	sprintf(req.head.contentEncoding, "%s", "fuckencoding");
	sprintf(req.body, "%s", BODY);
	req.head.bodyLen = body_len;

	req.vheader[0].vheader_id = VH_HELLO_WORLD;
	sprintf(req.vheader[0].vheader_body, "%s", "hello world!!!");
	req.vheader[1].vheader_id = VH_ARIEL_NETS;
	sprintf(req.vheader[1].vheader_body, "%s", "it company");
	req.vheader[2].vheader_id = VH_WRONG_HEADER;
	sprintf(req.vheader[2].vheader_body, "%s", "it company");

	fprintf(stderr, "body (len %d) \n%s\n", body_len, BODY);

	while(shmqlib_getMsg (httpcTxQid, ResMsg) > 0) {
		;
	}
	while(1) {
		sprintf(req.head.destHost, "udmlb");
		sprintf(req.head.destType, "ahif set this");

		sprintf(req.head.httpMethod, "%s", METHOD);
		sprintf(req.head.rsrcUri, "%s", PATH);

		if (shmqlib_putMsg(httpcRxQid, (char *)&req, AHIF_HTTPC_SEND_SIZE(req)) < 0) {
			fprintf(stderr, "SEND ERROR\n");
			continue;
		}

		sleep(1);

		memset(ResMsg, 0x00, sizeof(ResMsg));
		if((msgSize = shmqlib_getMsg (httpcTxQid, ResMsg)) <= 0 ) {
			fprintf(stderr, "RECV ERROR\n");
			continue;
		} else {
			ResMsg[msgSize] = '\0';
			fprintf(stderr, "RECEIVE RAW[ MSGLEN:%d ]\n", msgSize);
			//DumpHex(ResMsg, AHIF_HTTPCS_MSG_HEAD_LEN + res->head.bodyLen);
			fprintf(stderr, "response_len : %d\n", res->head.bodyLen);
			fprintf(stderr, "request_path : %s\n", res->head.rsrcUri);
			fprintf(stderr, "response_res : %d\n", res->head.respCode);
			fprintf(stderr, "response_msg : \n%s", res->body);
			fprintf(stderr, "content-encoding : %s\n", res->head.contentEncoding); 
			fprintf(stderr, "=====================================================================\n\n");
		}
	}
	return 0;
}
