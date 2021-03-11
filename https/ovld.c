#include "server.h"

extern server_conf SERVER_CONF;
extern ovld_state_t OVLD_STATE;
extern allow_list_t ALLOW_LIST[MAX_LIST_NUM];

void ovld_send_alarm(allow_list_t *allow_list, int occur)
{
	if (SERVER_CONF.ovld_event_code <= 0)
		return;

	char alarm_info[1024] = {0,};
	char alarm_desc[1024] = {0,};

	if (occur) {
		sprintf(alarm_info, "HTTPS-%s:%s",  allow_list->host, allow_list->ip);
		sprintf(alarm_desc, "limit:%d", allow_list->limit_tps);
		reportAlarm("HTTPS", SERVER_CONF.ovld_event_code, SFM_ALM_MAJOR, alarm_info, alarm_desc);
	} else {
		sprintf(alarm_info, "HTTPS-%s:%s",  allow_list->host, allow_list->ip);
		sprintf(alarm_desc, "limit:%d", allow_list->limit_tps);
		reportAlarm("HTTPS", SERVER_CONF.ovld_event_code, SFM_ALM_MAJOR, alarm_info, alarm_desc);
	}
}

int ovld_calc_check(http2_session_data *session_data)
{
    /* boundary check */
    if (session_data->allowlist_index < 0 || session_data->allowlist_index >= MAX_LIST_NUM) {
        APPLOG(APPLOG_ERR, "{{{WARN}}} func_%s() check session (%s:%s) have invalid allowlist (%d)",
                __func__, session_data->type, session_data->hostname, session_data->allowlist_index);
        return 0; // act like normal
    }

	/* check limit */
	allow_list_t *allow_list = &ALLOW_LIST[session_data->allowlist_index];
	int tps_limit = ALLOW_LIST[session_data->allowlist_index].limit_tps;

	/* check ovld state */
	int curr_pos = OVLD_STATE.curr_pos;
	int allowlist_index = session_data->allowlist_index;
	int thrd_index = session_data->thrd_index;
	int curr_tps = 0;

	/* calc curr tps */
	for (int i = 0; i < MAX_THRD_NUM; i++) {
		curr_tps += OVLD_STATE.peer_ovld[curr_pos][i].curr_tps[allowlist_index];
	}

	/* ovld decision */
	if (tps_limit == 0) {
		if (ALLOW_LIST[session_data->allowlist_index].ovld_alrm_sts != 0) {
			ALLOW_LIST[session_data->allowlist_index].ovld_alrm_sts = 0;
			ovld_send_alarm(allow_list, 0);
		}
		OVLD_STATE.peer_ovld[curr_pos][thrd_index].curr_tps[allowlist_index]++;

		return 0; // disabled
	} else if (curr_tps >= tps_limit) {
		if (ALLOW_LIST[session_data->allowlist_index].ovld_alrm_sts == 0) {
			ALLOW_LIST[session_data->allowlist_index].ovld_alrm_sts = 1;
			ovld_send_alarm(allow_list, 1);
		}
		OVLD_STATE.peer_ovld[curr_pos][thrd_index].drop_tps[allowlist_index]++;
		return -1; // overload
	} else {
		if (ALLOW_LIST[session_data->allowlist_index].ovld_alrm_sts != 0) {
			ALLOW_LIST[session_data->allowlist_index].ovld_alrm_sts = 0;
			ovld_send_alarm(allow_list, 0);
		}
		OVLD_STATE.peer_ovld[curr_pos][thrd_index].curr_tps[allowlist_index]++;

		return 0; // normal
	}
}

void ovld_step_forward()
{
	int curr_pos = OVLD_STATE.curr_pos;

	/* save curr ovld state */
	for (int i = 0; i < MAX_LIST_NUM; i++) {
		allow_list_t *allow_list = &ALLOW_LIST[i];
		allow_list->last_curr_tps = 0;
		allow_list->last_drop_tps = 0;

		if (allow_list->used == 0)
			continue;
		for (int k = 0; k < MAX_THRD_NUM; k++) {
			peer_ovld_t *ovld_curr = &OVLD_STATE.peer_ovld[curr_pos][k];
			allow_list->last_curr_tps += ovld_curr->curr_tps[i];
			allow_list->last_drop_tps += ovld_curr->drop_tps[i];
		}

		if (SERVER_CONF.debug_mode == 1) {
			APPLOG(APPLOG_ERR, "{{{TEST}}} OVLD STATE host=(%s) ip=(%s) limit=(%d) curr=(%d) drop=(%d)",
					allow_list->host, allow_list->ip, allow_list->limit_tps, allow_list->last_curr_tps, allow_list->last_drop_tps);
		}
	}

	/* prepare next step */
	int next_pos = (OVLD_STATE.curr_pos + 1) % MAX_OVLD_POS;

	for(int k = 0; k < MAX_THRD_NUM; k++) {
		peer_ovld_t *ovld_next = &OVLD_STATE.peer_ovld[next_pos][k];
		memset(ovld_next, 0x00, sizeof(peer_ovld_t));
	}

	/* move forward */
	OVLD_STATE.curr_pos = next_pos;
}
