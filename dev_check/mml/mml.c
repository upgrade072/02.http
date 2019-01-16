#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <unistd.h>
#include <time.h>

#include <commlib.h>

#include <http_comm.h>
#include <libs.h>

#if 0
[APPLICATIONS]
# range  60001 ~ 60100
#name   =   where       alarm_level                 msgQkey     msgQkey_2
#                   (1:minor, 2:major, 3:critical)
#----------------------------------------------------------------------------------------
IXPC     =  bin/ixpc        2                       0x70001     NULL        NULL
HTTPC    =  bin/httpc       3                       0x70017     NULL        NULL
HTTPS    =  bin/https       3                       0x70018     NULL        NULL
#endif
#if 1
const char HTTP_TMP[] = "0x70017";
#else
const char HTTP_TMP[] = "0x70018";
#endif
const char IXPC_TMP[] = "0x70001";

int httpcQid, ixpcQid, key;

int initialize()
{
	key = strtol(HTTP_TMP, 0, 0);
	if ((httpcQid = msgget(key,IPC_CREAT|0666)) < 0) {
		fprintf(stderr,"[%s] msgget fail; key=0x%x,err=%d(%s)\n", __func__,key,errno,strerror(errno));
		return -1;
	}
	key = strtol(IXPC_TMP, 0, 0);
	if ((ixpcQid = msgget(key,IPC_CREAT|0666)) < 0) {
		fprintf(stderr,"[%s] msgget fail; key=0x%x,err=%d(%s)\n", __func__,key,errno,strerror(errno));
		return -1;
	}
	return 0;
}

int msg_send()
{
	GeneralQMsgType msg;
	IxpcQMsgType   *txIxpcMsg=(IxpcQMsgType*)&msg.body;
	MMLReqMsgType  *mmlReq=(MMLReqMsgType*)txIxpcMsg->body;

	msg.mtype = MTYPE_MMC_REQUEST;

	/* dis-http-server */
	sprintf(mmlReq->head.cmdName, "DIS-HTTP-SERVER");

#if 0
	/* add-http-server */
	sprintf(mmlReq->head.cmdName, "ADD-HTTP-SERVER");
	mmlReq->head.paraCnt = 2;
	sprintf(mmlReq->head.para[0].paraName, "%s", "HOSTNAME");
	sprintf(mmlReq->head.para[0].paraVal, "%s", "FUCKYOU");
	sprintf(mmlReq->head.para[1].paraName, "%s", "TYPE");
	sprintf(mmlReq->head.para[1].paraVal, "%s", "NIGIMI");

	/* add-http-svr-ip */
	sprintf(mmlReq->head.cmdName, "ADD-HTTP-SVR-IP");
	mmlReq->head.paraCnt = 4;
	sprintf(mmlReq->head.para[0].paraName, "%s", "ID");
	sprintf(mmlReq->head.para[0].paraVal, "%d", 2);
	sprintf(mmlReq->head.para[1].paraName, "%s", "IPADDR");
	sprintf(mmlReq->head.para[1].paraVal, "%s", "1.1.1.1");
	sprintf(mmlReq->head.para[2].paraName, "%s", "PORT");
	sprintf(mmlReq->head.para[2].paraVal, "%d", 666);
	sprintf(mmlReq->head.para[3].paraName, "%s", "CONN_CNT");
	sprintf(mmlReq->head.para[3].paraVal, "%d", 3);

	/* act-http-server */
	sprintf(mmlReq->head.cmdName, "DACT-HTTP-SERVER");
	mmlReq->head.paraCnt = 3;
	sprintf(mmlReq->head.para[0].paraName, "%s", "ID");
	sprintf(mmlReq->head.para[0].paraVal, "%d", 2);
	sprintf(mmlReq->head.para[1].paraName, "%s", "IPADDR");
	sprintf(mmlReq->head.para[1].paraVal, "%s", "1.1.1.1");
	sprintf(mmlReq->head.para[2].paraName, "%s", "PORT");
	sprintf(mmlReq->head.para[2].paraVal, "%d", 666);

	/* chg-http-svr-ip */
	sprintf(mmlReq->head.cmdName, "CHG-HTTP-SERVER");
	mmlReq->head.paraCnt = 4;
	sprintf(mmlReq->head.para[0].paraName, "%s", "ID");
	sprintf(mmlReq->head.para[0].paraVal, "%d", 2);
	sprintf(mmlReq->head.para[1].paraName, "%s", "IPADDR");
	sprintf(mmlReq->head.para[1].paraVal, "%s", "1.1.1.1");
	sprintf(mmlReq->head.para[2].paraName, "%s", "PORT");
	sprintf(mmlReq->head.para[2].paraVal, "%d", 666);
	sprintf(mmlReq->head.para[3].paraName, "%s", "CONN_CNT");
	sprintf(mmlReq->head.para[3].paraVal, "%d", 2);

	/* del-http-server */
	sprintf(mmlReq->head.cmdName, "DEL-HTTP-SVR-IP");
	mmlReq->head.paraCnt = 3;
	sprintf(mmlReq->head.para[0].paraName, "%s", "ID");
	sprintf(mmlReq->head.para[0].paraVal, "%d", 2);
	sprintf(mmlReq->head.para[1].paraName, "%s", "IPADDR");
	sprintf(mmlReq->head.para[1].paraVal, "%s", "1.1.1.1");
	sprintf(mmlReq->head.para[2].paraName, "%s", "PORT");
	sprintf(mmlReq->head.para[2].paraVal, "%d", 666);

	/* del-http-server */
	sprintf(mmlReq->head.cmdName, "DEL-HTTP-SERVER");
	mmlReq->head.paraCnt = 1;
	sprintf(mmlReq->head.para[0].paraName, "%s", "ID");
	sprintf(mmlReq->head.para[0].paraVal, "%d", 2);

	/* dis-http-client */
	sprintf(mmlReq->head.cmdName, "DIS-HTTP-CLIENT");

	/* add-http-client */
	sprintf(mmlReq->head.cmdName, "ADD-HTTP-CLIENT");
	mmlReq->head.paraCnt = 2;
	sprintf(mmlReq->head.para[0].paraName, "%s", "HOSTNAME");
	sprintf(mmlReq->head.para[0].paraVal, "%s", "KILLYOU");
	sprintf(mmlReq->head.para[1].paraName, "%s", "TYPE");
	sprintf(mmlReq->head.para[1].paraVal, "%s", "JOTTO");

	/* add-http-cli-ip */
	sprintf(mmlReq->head.cmdName, "ADD-HTTP-CLI-IP");
	mmlReq->head.paraCnt = 3;
	sprintf(mmlReq->head.para[0].paraName, "%s", "ID");
	sprintf(mmlReq->head.para[0].paraVal, "%d", 2);
	sprintf(mmlReq->head.para[1].paraName, "%s", "IPADDR");
	sprintf(mmlReq->head.para[1].paraVal, "%s", "1.1.1.1");
	sprintf(mmlReq->head.para[2].paraName, "%s", "MAX");
	sprintf(mmlReq->head.para[2].paraVal, "%d", 666);

	/* act-http-client */
	sprintf(mmlReq->head.cmdName, "DACT-HTTP-CLIENT");
	mmlReq->head.paraCnt = 2;
	sprintf(mmlReq->head.para[0].paraName, "%s", "ID");
	sprintf(mmlReq->head.para[0].paraVal, "%d", 2);
	sprintf(mmlReq->head.para[1].paraName, "%s", "IPADDR");
	sprintf(mmlReq->head.para[1].paraVal, "%s", "1.1.1.1");

	/* act-http-client */
	sprintf(mmlReq->head.cmdName, "CHG-HTTP-CLIENT");
	mmlReq->head.paraCnt = 3;
	sprintf(mmlReq->head.para[0].paraName, "%s", "ID");
	sprintf(mmlReq->head.para[0].paraVal, "%d", 2);
	sprintf(mmlReq->head.para[1].paraName, "%s", "IPADDR");
	sprintf(mmlReq->head.para[1].paraVal, "%s", "1.1.1.1");
	sprintf(mmlReq->head.para[2].paraName, "%s", "MAX");
	sprintf(mmlReq->head.para[2].paraVal, "%d", 333);

	/* act-http-client */
	sprintf(mmlReq->head.cmdName, "DEL-HTTP-CLI-IP");
	mmlReq->head.paraCnt = 2;
	sprintf(mmlReq->head.para[0].paraName, "%s", "ID");
	sprintf(mmlReq->head.para[0].paraVal, "%d", 2);
	sprintf(mmlReq->head.para[1].paraName, "%s", "IPADDR");
	sprintf(mmlReq->head.para[1].paraVal, "%s", "1.1.1.1");

	/* act-http-client */
	sprintf(mmlReq->head.cmdName, "DEL-HTTP-CLIENT");
	mmlReq->head.paraCnt = 1;
	sprintf(mmlReq->head.para[0].paraName, "%s", "ID");
	sprintf(mmlReq->head.para[0].paraVal, "%d", 2);
#endif

	DumpHex((void *)&msg, 246);

	if(msgsnd(httpcQid, (void *)&msg, sizeof(GeneralQMsgType), IPC_NOWAIT )<0 ) {
		fprintf(stderr,"[%s] msgsend fail; key=0x%x,err=%d(%s)\n", __func__,key,errno,strerror(errno));
		return (-1);
	}
}

int main()
{
	if (initialize() < 0) {
		exit(0);
	}
	msg_send();

	return 0;
}
