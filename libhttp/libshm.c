#include "libhttp.h"

static int shm_http_id;

extern shm_http_t *SHM_HTTP_PTR;

int get_http_shm(void)
{
	if ((shm_http_id = shmget((size_t)HTTPC_SHM_MEM_KEY, SHM_HTTP_SIZE, IPC_CREAT|0666)) < 0) {
		fprintf(stderr, "http shmget fail, check if shm size changed\n");
		return (-1);
	}

	if ((SHM_HTTP_PTR = (shm_http_t *)shmat(shm_http_id, NULL, 0)) == (shm_http_t *)-1) {
		fprintf(stderr, "http shared memory attach failed\n");
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

/* [applications do]
 *
 * index = SHM_HTTP_PTR->current;
 *
 * do something like this
 * func(SHM_HTTP_PTR->connlist[index]);
 */
