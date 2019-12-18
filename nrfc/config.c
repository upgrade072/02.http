#include <nrfc.h>

extern main_ctx_t MAIN_CTX;

void write_cfg(main_ctx_t *MAIN_CTX)
{
	char conf_path[1024] = {0,};
	sprintf(conf_path,"%s/data/nrfc.cfg", getenv(IV_HOME));

    // save with indent
    config_set_tab_width(&MAIN_CTX->CFG, 4);
	config_write_file(&MAIN_CTX->CFG, conf_path);
}

int init_cfg(config_t *CFG)
{
    char conf_path[1024] = {0,};
    sprintf(conf_path,"%s/data/nrfc.cfg", getenv(IV_HOME));
    if (!config_read_file(CFG, conf_path)) {
        fprintf(stderr, "config read fail! (%s|%d - %s)\n",
                config_error_file(CFG),
                config_error_line(CFG),
                config_error_text(CFG));
        return (-1);
    } else {
        fprintf(stderr, "TODO| config read from ./nrfc.cfg success!\n");
    }   

	// sysconfig
	save_sysconfig(CFG, &MAIN_CTX);
        
    write_cfg(&MAIN_CTX);
    
    return 0;
}       

int save_sysconfig(config_t *CFG, main_ctx_t *MAIN_CTX)
{
	if (config_lookup_int(CFG, CF_SYS_DBG_MODE, &MAIN_CTX->sysconfig.debug_mode) == CONFIG_FALSE) {
		APPLOG(APPLOG_ERR, "DBG| (%s) .cfg [%s] not exist!", __func__, CF_SYS_DBG_MODE);
		return -1;
	}
    if (config_lookup_int(CFG, CF_ISIFCS_MODE, &MAIN_CTX->sysconfig.isifcs_mode) == CONFIG_FALSE) {
		APPLOG(APPLOG_ERR, "DBG| (%s) .cfg [%s] not exist!", __func__, CF_ISIFCS_MODE);
		return -1;
	}
    if (config_lookup_int(CFG, CF_NFS_SHM_CREATE, &MAIN_CTX->sysconfig.nfs_shm_create) == CONFIG_FALSE) {
		APPLOG(APPLOG_ERR, "DBG| (%s) .cfg [%s] not exist!", __func__, CF_NFS_SHM_CREATE);
		return -1;
	}

	return 0;
}
