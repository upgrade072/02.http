#include "libhttp.h"

extern shm_http_t *SHM_HTTPC_PTR;

int get_http_shm(int httpc_status_shmkey)
{
	int shm_http_id = 0;

	if ((shm_http_id = shmget((size_t)httpc_status_shmkey, SHM_HTTP_SIZE, IPC_CREAT|0666)) < 0) {
		APPLOG(APPLOG_ERR, "http shmget fail, check if shm size changed!!!");
		return (-1);
	}

	if ((SHM_HTTPC_PTR = (shm_http_t *)shmat(shm_http_id, NULL, 0)) == (shm_http_t *)-1) {
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
	int index = (SHM_HTTPC_PTR->current + 1) % HTTP_STATUS_CHAIN;
	memset(SHM_HTTPC_PTR->connlist[index], 0x00, sizeof(conn_list_status_t) * MAX_CON_NUM);
	memcpy(SHM_HTTPC_PTR->connlist[index], conn_status, sizeof(conn_list_status_t) * MAX_CON_NUM);

	SHM_HTTPC_PTR->current = index;
}

void print_httpc_status()
{
	int pos = SHM_HTTPC_PTR->current;
	for (int i = 0; i < MAX_CON_NUM; i++) {
		conn_list_status_t *conn_raw = &SHM_HTTPC_PTR->connlist[pos][i];
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

int select_next_httpc_conn(char *type, char *host, char *ip, int port, int last_selected_index, conn_list_status_t *find_raw)
{
    int start_line = last_selected_index + 1;

	int pos = SHM_HTTPC_PTR->current;

	for (int i = 0; i < MAX_CON_NUM; i++) {
        int select_node = (start_line + i) % MAX_CON_NUM;

		conn_list_status_t *conn_raw = &SHM_HTTPC_PTR->connlist[pos][select_node];

        /* check basic info */
		if (conn_raw->occupied <= 0)
			continue;
		if (conn_raw->act <= 0)
			continue;
		if (conn_raw->conn_cnt <= 0)
			continue;

        /* check user input values */
        if (type != NULL && strcmp(type, conn_raw->type))
            continue;
        if (host != NULL && strcmp(host, conn_raw->host))
            continue;
        if (ip != NULL && strcmp(ip, conn_raw->ip))
            continue;
        if (port != 0 && (port != conn_raw->port))
            continue;

        /* return find info */
        memcpy(find_raw, conn_raw, sizeof(conn_list_status_t));
        return select_node;
    }

    /* we can't find */
    memset(find_raw, 0x00, sizeof(conn_list_status_t));
    return (-1);
}

/* [applications do]
 *
 * index = SHM_HTTPC_PTR->current;
 *
 * do something like this
 * func(SHM_HTTPC_PTR->connlist[index]);
 */
int get_shm_comm_key(char *fname, char *proc_name, int shm_mode)
{
    char token[8][CONFLIB_MAX_TOKEN_LEN] = {0,};
    int  rxKey, numRow, maxLen, shmSiz;
    int  ret_shm_comm_key = 0;
    
    if (conflib_getNTokenInFileSection (fname, "APP_Q_INFO", proc_name, 4, token) < 4) {
        fprintf(stderr, "conflib_getNTokenInFileSection fail. filename=[%s], section=[%s], procName=[%s]\n",
                fname, "APP_Q_INFO", proc_name);
        return -1;
    }
    rxKey  = strtol (token[1],0,0);
    numRow = strtol (token[3],0,0);
    maxLen = strtol (token[4],0,0);
    shmSiz = strtol (token[5],0,0);

    if ((ret_shm_comm_key = shmqlib_init (rxKey, numRow, maxLen, shmSiz, shm_mode)) <  0) {
        fprintf(stderr, "shmqlib_init fail. filename=[%s], section=[%s], procName=[%s], rxKey=0x%x\n",
                fname, "APP_Q_INFO", proc_name, rxKey);
    }
    fprintf (stderr, "[%s] fromNrfmShmQid=[%d]\n", __func__, ret_shm_comm_key);
    
    return ret_shm_comm_key;
}   
