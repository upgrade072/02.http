#include "check.h"

extern main_ctx_t MAIN_CTX;

void register_command(main_ctx_t *MAIN_CTX)
{
	/* load section */
	char help_load[] = "[LOAD] purpose section";
	struct cli_command *cli_load = cli_register_command(MAIN_CTX->CLI_ROOT, NULL, "load", 
			NULL, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 
			help_load);

	char help_nrfm_qid[] = "Load NRFC msgq id";
	cli_register_command(MAIN_CTX->CLI_ROOT, cli_load, "NRFC_QID", 
			cmd_load_nrfm_qid, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 
			help_nrfm_qid);

	char help_nfs_shm[] = "Attach NFS Table Shm";
	cli_register_command(MAIN_CTX->CLI_ROOT, cli_load, "NFS_SHM", 
			cmd_load_nfs_shm, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 
			help_nfs_shm);


	/* test section */
	char help_test[] = "[TEST] purpose section";
	struct cli_command *cli_test = cli_register_command(MAIN_CTX->CLI_ROOT, NULL, "test", 
			NULL, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 
			help_test);

	char help_callback[] = "Send callback Request [1(add)|4(del) https UDM udm_01 1.1.1.1 8000]";
	cli_register_command(MAIN_CTX->CLI_ROOT, cli_test, "callback", 
			cmd_register_callback, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 
			help_callback);

	char help_discover[] = "NF discover";
	struct cli_command *cli_discover = cli_register_command(MAIN_CTX->CLI_ROOT, cli_test, "discover", 
			NULL, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 
			help_discover);

	char help_discover_show[] = "NF discover show table";
	cli_register_command(MAIN_CTX->CLI_ROOT, cli_discover, "show",
			cmd_discover_show, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 
			help_discover_show);

	char help_discover_clear[] = "NF discover clear table";
	cli_register_command(MAIN_CTX->CLI_ROOT, cli_discover, "clear",
			cmd_discover_clear, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 
			help_discover_clear);

	char help_discover_search[] = "NF discover search func call test\n\
\t\t\t-a : file_name (discover_result json ex: ./tmp/discover_res.json)\n\
\t\t\t-b : start_lb Id\n\
\t\t\t-c : lb num\n\
\t\t\t-d : nfType (1: NRF 2: UDM 3: AMF)\n\
\t\t\t-e : mcc\n\
\t\t\t-f : mnc\n\
\t\t\t-g : nfSearchType (1 : UDM SUPI 2: UDM SUCI)\n\
\t\t\t-h : routing indicators\n\
\t\t\t-i : supi\n\
\t\t\t-j : region id\n\
\t\t\t-k : amf set id\n\
\t\t\t-l : plmnId in guami\n\
\t\t\t-m : amfId in guami\n\
\t\t\t-n : serviceName\n\
\t\t\t-o : selectionType (1 : DISC_SE LOW 2 : DISC_SE PRI)\n";
	cli_register_command(MAIN_CTX->CLI_ROOT, cli_discover, "search",
			cmd_discover_search, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, 
			help_discover_search);
}

int cmd_common_print(struct cli_def *cli, const char *command, char *argv[], int argc)
{
    cli_print(cli, " => called %s() by [%s]", __func__, command);
    cli_print(cli, "%d arguments:", argc);
    for (int i = 0; i < argc; i++) {
		cli_print(cli, "        %s", argv[i]);
	}
    return CLI_OK;
}

int cmd_load_nrfm_qid(struct cli_def *cli, const char *command, char *argv[], int argc)
{
	cmd_common_print(cli, command, argv, argc);

	char fname[1024] = {0,};
	char tmp[64] = {0,};
	int key = 0, PROC_NAME_LOC = 3;

	sprintf(fname,"%s/%s", getenv(IV_HOME), SYSCONF_FILE);

	if (conflib_getNthTokenInFileSection (fname, "APPLICATIONS", "NRFC", PROC_NAME_LOC, tmp) < 0) {
		cli_error(cli, "can't load fname[%s] or can't find section [APPL.../NRFC]", fname);
		return CLI_ERROR;
	}

	key = strtol(tmp,0,0);
	if ((MAIN_CTX.NRFC_QID = msgget(key,IPC_CREAT|0666)) < 0) {
		cli_error(cli, "[%s] msgget fail; key=0x%x,err=%d(%s)!", __func__, key, errno, strerror(errno));
		return CLI_ERROR;
	}

	/* success */
	cli_print(cli, "load success main_ctx NRFC_QID is [%d]", MAIN_CTX.NRFC_QID);
	return CLI_OK;
}

int cmd_load_nfs_shm(struct cli_def *cli, const char *command, char *argv[], int argc)
{
	cmd_common_print(cli, command, argv, argc);

    char fname[1024] = {0,};
    sprintf(fname,"%s/%s", getenv(IV_HOME), SYSCONF_FILE);

    char tmp[1024] = {0,};
    if (conflib_getNthTokenInFileSection (fname, "SHARED_MEMORY_KEY", "SHM_NFS_CONN", 1, tmp) < 0 )
        return CLI_ERROR;

    int nfs_shm_key = strtol(tmp,(char**)0,0);
    int nfs_shm_id = 0;
    if ((nfs_shm_id = (int)shmget (nfs_shm_key, sizeof(nfs_avail_shm_t), 0644|IPC_CREAT)) < 0) {
        cli_error(cli, "[%s] SHM_NFS_CONN shmget fail; err=%d(%s)", __func__, errno, strerror(errno));
        return CLI_ERROR;
    }
    if ((void*)(MAIN_CTX.SHM_NFS_AVAIL = (nfs_avail_shm_t *)shmat(nfs_shm_id,0,0)) == (void*)-1) {
        cli_error(cli, "[%s] SHM_NFS_CONN shmat fail; err=%d(%s)", __func__, errno, strerror(errno));
        return CLI_ERROR;
    }

	/* success */
	cli_print(cli, "load success main_ctx SHM_NFS_AVAIL is [%p]", MAIN_CTX.SHM_NFS_AVAIL);
	return CLI_OK;
}


int cmd_register_callback(struct cli_def *cli, const char *command, char *argv[], int argc)
{
	cmd_common_print(cli, command, argv, argc);

	if (argc != 6) {
		cli_error(cli, "[%s] argv mismatch error", __func__);
		return CLI_ERROR;
	}

	http_conn_handle_req_t handle_req = {0,};

	handle_req.command = atoi(argv[0]);
	sprintf(handle_req.scheme, argv[1]);
	sprintf(handle_req.type, argv[2]);
	sprintf(handle_req.host, argv[3]);
	sprintf(handle_req.ip, argv[4]);
	handle_req.port = atoi(argv[5]);

	int res = http2_appl_api_to_httpc(&handle_req, MAIN_CTX.NRFC_QID);
	cli_print(cli, "%s() call res = [%d]", __func__, res);
	
	return CLI_OK;
}

int cmd_discover_show(struct cli_def *cli, const char *command, char *argv[], int argc)
{
	cmd_common_print(cli, command, argv, argc);

	char res_buf[10240] = {0,};

	nf_discover_table_print(&MAIN_CTX.DISC_TABLE, res_buf, sizeof(res_buf));

	cli_print(cli, "%s() call res = \n%s", __func__, res_buf);
	
	return CLI_OK;
}

int cmd_discover_clear(struct cli_def *cli, const char *command, char *argv[], int argc)
{
	cmd_common_print(cli, command, argv, argc);

	int res = nf_discover_table_clear_cached(&MAIN_CTX.DISC_TABLE);

	cli_print(cli, "%s() call res = (%d)", __func__, res);
	
	return CLI_OK;
}

int cmd_discover_search(struct cli_def *cli, const char *command, char *argv[], int argc)
{
	cmd_common_print(cli, command, argv, argc);

	int c = 0;
	char *pointer = NULL;

	nf_discover_key search_info = {0,};
	memset(&search_info, 0x00, sizeof(nf_discover_key));

	optind = -1; // start parse from argv[0]

	while ((c = getopt(argc, argv, "a:b:c:d:e:f:g:h:i:j:k:l:m:n:o:")) != -1) {
		switch(c)
		{
			//- a : file_name (discover_result json)
			case 'a':
				pointer = read_file_stream(optarg);
				cli_print(cli, "{dbg} %s() opt(%c) filename(%s) pointer(%s)",
						__func__, c, optarg, pointer);
				break;
			//- b : start_lb Id
			case 'b':
				search_info.start_lbId = atoi(optarg);
				break;
			//- c : lb num
			case 'c':
				search_info.lbNum = atoi(optarg);
				break;
			//- d : nfType
			case 'd':
				search_info.nfType = atoi(optarg);
				break;
			//- e : mcc
			case 'e':
				search_info.mcc = optarg;
				break;
			//- f : mnc
			case 'f':
				search_info.mnc = optarg;
				break;
			//- g : nfSearchType (1 : UDM SUPI 2: UDM SUCI)
			case 'g':
				search_info.nfSearchType = atoi(optarg);
				break;
			//- h : routing indicators
			case 'h':
				search_info.routing_indicators = optarg;
				break;
			//- i : supi
			case 'i':
				search_info.supi = optarg;
			//- j : region id
			case 'j':
				search_info.region_id = optarg;
				break;
			//- k : amf set id
			case 'k':
				search_info.amf_set_id = optarg;
				break;
			//- l : plmnId in guami
			case 'l':
				search_info.plmnId_in_guami = optarg;
				break;
			//- m : amfId in guami
			case 'm':
				search_info.amfId_in_guami = optarg;
				break;
			//- n : serviceName
			case 'n':
				search_info.serviceName = optarg;
				break;
			//- o : selectionType (1 : DISC_SE LOW 2 : DISC_SE PRI)
			case 'o':
				search_info.selectionType = atoi(optarg);
				break;
			default:
				cli_print(cli, "unknown opt [%c:%s]", c, optarg);
				break;
		}
	}
	nf_service_info *nf_svc_res = nf_discover_search(&search_info, &MAIN_CTX.DISC_TABLE, MAIN_CTX.SHM_NFS_AVAIL, pointer, MAIN_CTX.NRFC_QID);

	cli_print(cli, "%s() call res = \n%p", __func__, nf_svc_res);

	if (nf_svc_res != NULL) {
		cli_print(cli, "%s() selected\n lbId(%d) serviceName(%s) %s:%s:%s:%d (load:%d, pri:%d)",
				__func__, 
				nf_svc_res->lbId, nf_svc_res->serviceName,
				nf_svc_res->type, nf_svc_res->hostname, nf_svc_res->ipv4Address, nf_svc_res->port,
				nf_svc_res->load, nf_svc_res->priority);
	} else {
		cli_print(cli, "%s() find nothing", __func__);
	}

	if (pointer != NULL)
		free(pointer);

	return CLI_OK;
}
