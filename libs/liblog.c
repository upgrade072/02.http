#include "libs.h"
           
#ifdef LOG_LIB
int initlog_for_loglib(char *appName, char *path)
{   
    LoglibProperty  property;

    if( loglib_initLog(appName) < 0 ) {
        fprintf (stderr,"[%s:%d] loglib_initLog failed\n", FL);
        return -1;
    }   
        
    memset(&property, 0, sizeof(property));

    strcpy(property.appName, appName);
    property.num_suffix = 0;
    property.limit_val  = 0;
    property.mode       = LOGLIB_MODE_LIMIT_SIZE |
                          LOGLIB_FLUSH_IMMEDIATE |
                          LOGLIB_MODE_DAILY |
                          LOGLIB_TIME_STAMP_FIRST |
                          LOGLIB_FNAME_LNUM;
        
    strcpy(property.subdir_format, "%Y-%m-%d");
    
    sprintf (property.fname, "%s/%s", path, appName);
    if( (ELI = loglib_openLog(&property)) < 0 ) {
        fprintf (stderr, "[%s:%d] [%s] openLog fail[%s]\n", FL, __func__, property.fname);
        return -1;
    }   

    return 0;
}       
#endif
