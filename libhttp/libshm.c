#include "libhttp.h"

extern shm_http_t *SHM_HTTP_PTR;

int get_http_shm(int httpc_status_shmkey)
{
	int shm_http_id = 0;

	if ((shm_http_id = shmget((size_t)httpc_status_shmkey, SHM_HTTP_SIZE, IPC_CREAT|0666)) < 0) {
		APPLOG(APPLOG_ERR, "http shmget fail, check if shm size changed!!!");
		return (-1);
	}

	if ((SHM_HTTP_PTR = (shm_http_t *)shmat(shm_http_id, NULL, 0)) == (shm_http_t *)-1) {
		APPLOG(APPLOG_ERR, "http shared memory attach failed!!!");
		return (-1);
	}

	return (0);
}

/* 
 * [httpc use this] 
 *
 */
void set_httpc_status(conn_list_status_t conn_status[])
{
	int index = (SHM_HTTP_PTR->current + 1) % HTTP_STATUS_CHAIN;
	memset(SHM_HTTP_PTR->connlist[index], 0x00, sizeof(conn_list_status_t) * MAX_CON_NUM);
	memcpy(SHM_HTTP_PTR->connlist[index], conn_status, sizeof(conn_list_status_t) * MAX_CON_NUM);

	SHM_HTTP_PTR->current = index;
}

void print_httpc_status()
{
	int pos = SHM_HTTP_PTR->current;
	for (int i = 0; i < MAX_CON_NUM; i++) {
		conn_list_status_t *conn_raw = &SHM_HTTP_PTR->connlist[pos][i];
		if (conn_raw->occupied <= 0)
			continue;
		if (conn_raw->act <= 0)
			continue;
		if (conn_raw->conn_cnt <= 0)
			continue;
		APPLOG(APPLOG_ERR, "[%4d] [%12s] [%8s] [%40s] [%20s] [%5d] [%3d] [%3d] [%5d] [%s]",
				i,
				conn_raw->scheme,
				conn_raw->type,
				conn_raw->host,
				conn_raw->ip,
				conn_raw->port,
				conn_raw->sess_cnt,
				conn_raw->conn_cnt,
				conn_raw->token_id,
				(conn_raw->nrfm_auto_added) ? "AUTO" : "OPER");
	}
}

/* [applications do]
 *
 * index = SHM_HTTP_PTR->current;
 *
 * do something like this
 * func(SHM_HTTP_PTR->connlist[index]);
 */
