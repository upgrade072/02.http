#include <nrfc.h>


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
        
    // save with indent
    config_set_tab_width(CFG, 4);
    config_write_file(CFG, conf_path);
    
    return 0;
}       

