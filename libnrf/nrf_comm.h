#ifndef __NRF_COMMON_H__
#define __NRF_COMMON_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

#include <libs.h>

#ifdef LOG_LIB
#include <loglib.h>
#elif LOG_APP
#include <appLog.h>
#endif

#include <libconfig.h>
#include <json-c/json.h>
#include <json-c/json_object.h>
#include <event.h>
#include <event2/event.h>

#include <gmodule.h>

// monitor config file change
#include <sys/inotify.h>

typedef struct svr_info {
    char mySysName[COMM_MAX_NAME_LEN];
    char myProcName[COMM_MAX_NAME_LEN];
    char mySysType[COMM_MAX_VALUE_LEN];
    char mySvrId[COMM_MAX_VALUE_LEN];
} svr_info_t;

typedef struct assoc {
    char name[1024];
    char type[1024];
    char group[1024];
    char ip[1024];
} assoc_t;

typedef struct service_info {
    int sys_mp_id;
    char service_name[1024];
    char ovld_name[1024];
    char proc_name[1024];
    int ovld_tps;
    int curr_tps;
    int curr_load;
    int proc_table_index;
    int proc_last_count;  // mapping with keepalive shm table
    int proc_curr_count;  // ..
    int proc_alive;       // -> alive of not 
    int olcd_table_index; // mapping with OLCD shm table
    int bep_use;
    int bep_conn;
} service_info_t;

/* ------------------------- libnrf.c --------------------------- */
void    def_sigaction();
GSList  *get_associate_node(GSList *node_assoc_list, const char *type_str);
void    get_my_info(svr_info_t *my_info, const char *my_proc_name);
void    node_assoc_release(assoc_t *node_elem);
void    node_list_remove_all(GSList *node_assoc_list);
GSList  *node_list_add_elem(GSList *node_assoc_list, assoc_t *node_elem);
void    node_assoc_log(assoc_t *node_elem);
void    node_list_print_log(GSList *node_assoc_list);
int     watch_directory_init(struct event_base *evbase, const char *path_name);

#endif /* __NRF_COMMON_H__ */
