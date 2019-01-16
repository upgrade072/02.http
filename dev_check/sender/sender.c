#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#include <unistd.h>
#include <pthread.h>

#include <time.h>

#include <pthread.h>

#include <shmQueue.h>
#include <commlib.h>
#include <ahif_msgtypes.h>

#include <http_comm.h>
#include <libs.h>

#include "body.h"

const char METHOD[] = "PUT";
//const char PATH[] = "/index.html/aaa/bbb?test_query";
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
}

int SEND, RECV;
int COUNTER;
int SLEEP_TM;
void *senderThread(void *arg)
{

	AhifHttpCSMsgType req;
	AhifHttpCSMsgType rsp;

    int sleep_cnt = 0;
    int index;
	int body_len = strlen(BODY);

	sleep(3);

	sprintf(req.body, "%s", BODY);
	req.head.bodyLen = body_len;

	fprintf(stderr, "FUCK BODY LEN [%d]\n", body_len);

	while(1) 
	{
		sprintf(req.head.destHost, "udmlb");
		sprintf(req.head.httpMethod, "%s", METHOD);
		sprintf(req.head.rsrcUri, "%s", PATH);
		if (shmqlib_putMsg(httpcRxQid, (char *)&req, AHIF_HTTPC_SEND_SIZE(req)) < 0) {
		} else {
#if 1 // 4k 50000 tps, send 10, usleep 150
			SEND++;
			if (SEND > 20) {
				usleep(100);
				SEND = 0;
			}
#endif
		}
	}
}

void *receiverThread(void *arg)
{
    char ResMsg[sizeof(AhifHttpCSMsgType) + 1024];
	int msgSize, counter = 0;
	while (1) {
		if((msgSize = shmqlib_getMsg (httpcTxQid, ResMsg)) <= 0 ) {
			counter++;
			if (counter >= 1000) {
				usleep(10);
				counter = 0;
			}
		} else {
			RECV++;
			counter = 0;
		}
	}
}

void create_thread()
{
	int res;
	pthread_t id;

	if ((res = pthread_create(&id, NULL, &senderThread, NULL)) != 0) {
		fprintf(stderr, "senderThread creation fail\n");
		exit(0);
	}
	pthread_detach(id);

	if ((res = pthread_create(&id, NULL, &receiverThread, NULL)) != 0) {
		fprintf(stderr, "receiverThread creation fail\n");
		exit(0);
	}
	pthread_detach(id);
}

int main() {
	if (initialize() < 0) {
		fprintf(stderr,">>>>>> sender_initial fail\n");
		return -1;
	}

#ifdef PERFORM
	create_thread();
	while (1)
		sleep(1);
#else
	AhifHttpCSMsgType req;
    char ResMsg[sizeof(AhifHttpCSMsgType) + 1024];
	AhifHttpCSMsgType *res = (AhifHttpCSMsgType *)&ResMsg;
	int index, msgSize;
	int body_len = strlen(BODY);

	// make request
	sprintf(req.body, "%s", BODY);
	sprintf(req.head.contentEncoding, "%s", "fuckencoding");
	req.head.bodyLen = body_len;

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
#if 1
			fprintf(stderr, "RECEIVE RAW[ MSGLEN:%d (RES_T:%d) ]\n", msgSize, sizeof(AhifHttpCSMsgType));
			DumpHex(ResMsg, AHIF_HTTPCS_MSG_HEAD_LEN + res->head.bodyLen);
			fprintf(stderr, "response_len : %d\n", res->head.bodyLen);
			fprintf(stderr, "request_path : %s\n", res->head.rsrcUri);
			fprintf(stderr, "response_res : %d\n", res->head.respCode);
			fprintf(stderr, "response_msg : \n%s", res->body);
			fprintf(stderr, "content-encoding : %s\n", res->head.contentEncoding); 
			fprintf(stderr, "=====================================================================\n\n");
#endif
		}
	}
#endif
	return 0;
}
