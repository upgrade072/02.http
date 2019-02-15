#include "libhttp.h"

void chk_list(conn_list_status_t conn_status[]) 
{
    int i, j;

    fprintf(stderr, "\n  ID HOSTNAME   TYPE       IP_ADDR                                         PORT CONN(max/curr)   ACT STATUS\n");
    fprintf(stderr, "---------------------------------------------------------------------------------------------------------------\n");
    for ( i = 0; i < MAX_LIST_NUM; i++) {
        for ( j = 0; j < MAX_CON_NUM; j++) {
            if (conn_status[j].occupied != 1)	/* no occupied, just skip for save time */
                continue;
            if (conn_status[j].list_index != i) /* just for order result */
                continue;
            fprintf(stderr, "%4d %-10s %-10s %-46s %5d (%4d  / %4d) %4d %s\n",
                    conn_status[j].list_index,	/* don't care */
                    conn_status[j].host,		/* udmbep, udmlb, ... */
                    conn_status[j].type,		/* udm, pcf, ... */
                    conn_status[j].ip,			/* 192.168.0.1 */
                    conn_status[j].port,		/* 7000 */
                    conn_status[j].sess_cnt,	/* don't care */
                    conn_status[j].conn_cnt,	/* if conn_cnt > 0 , ready to send */
                    conn_status[j].act,			/* don't care */
                    (conn_status[j].conn_cnt > 0) ?  "Connected" : (conn_status[j].act == 1) ? "Disconnect" : "Deact");
        }
    }
    fprintf(stderr, "---------------------------------------------------------------------------------------------------------------\n\n");
}
