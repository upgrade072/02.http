#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <json/json.h>

#include <shmQueue.h>
#include <commlib.h>
#include <ahif_msgtypes.h>

#include <http_comm.h>
#include <libs.h>

int RESP_CNT;
int ahifRxQid, ahifTxQid;
json_object *base_obj;
json_object *check_obj;

int initialize()
{
    char myAppName[COMM_MAX_NAME_LEN] = { "AHIF" };
    char fname[128] = {0, }; 
    char temp[1024 * 4] = {0,};
    
    sprintf(fname, "%s/%s", getenv("IV_HOME"), "data/ahif.conf");
    fprintf(stderr, "%s", fname);

    if ((ahifRxQid = shmqlib_getQid (fname, "APP_TO_AHIF_SHMQ", "PERFSIM", SHMQLIB_MODE_GETTER)) < 0)
        return (-1);
    if ((ahifTxQid = shmqlib_getQid (fname, "AHIF_TO_APP_SHMQ", "PERFSIM", SHMQLIB_MODE_PUTTER)) < 0)
        return (-1);

    base_obj = json_object_from_file("./response.json");

    if (base_obj == (struct json_object*)error_ptr(-1)) {
        fprintf(stderr, "fail to get json from file (%s)\n", "./response.json");
        return(-1);
    }
    sprintf(temp, "%s", json_object_to_json_string(base_obj));
    if ((check_obj = json_tokener_parse(temp)) == NULL) {
        fprintf(stderr, "resp but json parse fail ]\n", temp);
        return (-1);
    }

    return (0);
}

void sig_handler(int signo)
{
    fprintf(stderr, "\n\nresponse cnt %d\n\n", RESP_CNT);
    exit(0);
}

int main() 
{
    int sleep_cnt = 0;
    AhifAppMsgType rxMsg, txMsg;
    AhifAppMsgType *respMsg = &txMsg;
    int respLen = 0;

    signal(SIGINT, (void *)sig_handler);
	if (initialize() < 0) {
		fprintf(stderr,">>>>>> dummy_initial fail\n");
		return -1;
	}

	while (1) 
	{
		if (shmqlib_getMsg (ahifRxQid, (char *)&rxMsg) <= 0 ) {
#if 1
			sleep_cnt ++;
			if (sleep_cnt == 10000) {
				usleep(1);
				sleep_cnt = 0;
			}
#endif
			continue;
        } else {
#if 0
            /* Dump request */
            fprintf(stderr, "\nREQUEST]\n");
            DumpHex(rxMsg.body, rxMsg.head.bodyLen);
            fprintf(stderr, "\n");
#endif

            memset(&respMsg->head, 0x00, AHIF_APP_MSG_HEAD_LEN);
            respMsg->head.mtype   = MTYPE_HTTP2_RESPONSE_AHIF_TO_APP;
            respMsg->head.appCid  = rxMsg.head.appCid;
            sprintf(respMsg->head.appVer, "%s", "R100");
            sprintf(respMsg->head.rsrcName, "%s", rxMsg.head.rsrcName);
            sprintf(respMsg->head.httpMethod, "%s", rxMsg.head.httpMethod);
            sprintf(respMsg->head.destType, "%s", rxMsg.head.destType);
            respMsg->head.opTimer = 3;

            /* response result code */
            respMsg->head.bodyLen = sprintf(respMsg->body, "%s", json_object_to_json_string(base_obj));

            /* response */
            respLen = AHIF_APP_MSG_HEAD_LEN + respMsg->head.bodyLen;

#if 0
            /* Dump response */
            fprintf(stderr, "\nRESPONSE]\n");
            DumpHex(respMsg->body, respMsg->head.bodyLen);
            fprintf(stderr, "\n");
#endif

            RESP_CNT ++;
            shmqlib_putMsg(ahifTxQid, (char *)&txMsg, respLen);
        }
	}
    json_object_put(base_obj);
    json_object_put(check_obj);
}
