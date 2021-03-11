#include <http_comm.h>
#include <stdio.h>

shm_http_t *SHM_HTTPC_PTR;
int main()
{
	if (get_http_shm(0x520000) < 0) {
		fprintf(stderr, "shmget fail\n");
		return 0;
	}

	while (1) 
	{
		system("clear");

		int index = SHM_HTTPC_PTR->current;
		chk_list(SHM_HTTPC_PTR->connlist[index]);

		sleep(1);
	}
}
