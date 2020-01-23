#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <unistd.h>
#include <libcli.h>

#include <sysconf.h>
#include <commlib.h>
#include <libnrf_app.h>
#include <libs.h>

typedef struct main_ctx {
	struct cli_def *CLI_ROOT;

	int NRFC_QID;					// nrfc message queue id
	nf_discover_table DISC_TABLE;	// nf discover table
	nfs_avail_shm_t *SHM_NFS_AVAIL;	// nfs avail shared memory
} main_ctx_t;

/* ------------------------- main.c --------------------------- */
int     initialize(main_ctx_t *MAIN_CTX);
void    start_loop(main_ctx_t *MAIN_CTX);
int     main();

/* ------------------------- command.c --------------------------- */
void    register_command(main_ctx_t *MAIN_CTX);
int     cmd_common_print(struct cli_def *cli, const char *command, char *argv[], int argc);
int     cmd_load_nrfm_qid(struct cli_def *cli, const char *command, char *argv[], int argc);
int     cmd_load_nfs_shm(struct cli_def *cli, const char *command, char *argv[], int argc);
int     cmd_register_callback(struct cli_def *cli, const char *command, char *argv[], int argc);
int     cmd_discover_show(struct cli_def *cli, const char *command, char *argv[], int argc);
int     cmd_discover_clear(struct cli_def *cli, const char *command, char *argv[], int argc);
int     cmd_discover_search(struct cli_def *cli, const char *command, char *argv[], int argc);
