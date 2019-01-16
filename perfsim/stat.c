#include "header.h"

extern char *__progname;
extern perf_conf_t PERF_CONF;
extern app_ctx_t *PERF_CTX[MAX_THREAD_NUM];

char SEM_NAME[128] = {0,};
static sem_t *MY_SEM;

/* statistic */
stat_t STAT;
stat_t RECV_STAT[MAX_THRD_NUM];
sndrcv_t SNDRCV;

int stat_ind[] = {
PF_TRIGGERED,
PF_SENDED,
PF_RECV,
PF_SUCC,
PF_FAIL,
PF_TIMEOUT,
PF_INTL_ERR,
PF_RCV_CAUSE_FAIL,
PF_DECODE_FAIL };
char stat_str[][128] = {
"[trigger]",
"sended",
"recv",
"[succ]",
"[fail]",
"timeout",
"intl_err",
"rcv_c_fail",
"dec_fail" };

int init_sem()
{
    sprintf(SEM_NAME, "%s.sem", __progname);
    sem_unlink(SEM_NAME);

    sem_unlink(SEM_NAME);
    if ((MY_SEM = sem_open(SEM_NAME, O_CREAT, 0777, 1)) == NULL) {
        fprintf(stderr, "fail to create semapore\n");
        return (-1);
    } else {
        return (0);
    }
}

void set_call_end_info(send_recv_statistic_t *end_info)
{
    if (sem_trywait(MY_SEM) == 0) { // here
        int index = 0;
        SNDRCV.curr_idx = (SNDRCV.curr_idx + 1) % MAX_RCV_CHAIN_NUM;
        index = SNDRCV.curr_idx;

        SNDRCV.sndrcv[index].occupied = 1;
        SNDRCV.sndrcv[index].start_tm = end_info->start_tm;
        SNDRCV.sndrcv[index].end_tm = end_info->end_tm;
        SNDRCV.sndrcv[index].snd_byte = end_info->snd_byte;
        SNDRCV.sndrcv[index].rcv_byte = end_info->rcv_byte;
        sem_post(MY_SEM);           // here
    }
}


void pf_stat_inc(int thrd_idx, int stat_idx)
{
    if (thrd_idx < 0 || thrd_idx >= MAX_THREAD_NUM)
        return;
    if (stat_idx < 0 || stat_idx >= PF_STAT_MAX)
        return;

    int curr_idx = STAT.curr_idx;
    STAT.stat[curr_idx].per_thread_stat[thrd_idx].stat_count[stat_idx]++;
}

void pf_step_inc(int thrd_idx, int curr_step)
{
    if (thrd_idx < 0 || thrd_idx >= MAX_THREAD_NUM)
        return;
    if (curr_step < 0 || curr_step >= MAX_PF_STEP_NUM)
        return;

    int curr_idx = STAT.curr_idx;
    STAT.stat[curr_idx].per_thread_stat[thrd_idx].step_count[curr_step]++;
}

void pf_recv_stat_inc(int recv_thrd_idx, int thrd_idx, int stat_idx)
{
    if (recv_thrd_idx < 0 || recv_thrd_idx >= MAX_THREAD_NUM)
        return;
    if (thrd_idx < 0 || thrd_idx >= MAX_THREAD_NUM)
        return;
    if (stat_idx < 0 || stat_idx >= PF_STAT_MAX)
        return;

    int curr_idx = STAT.curr_idx;
    RECV_STAT[recv_thrd_idx].stat[curr_idx].per_thread_stat[thrd_idx].stat_count[stat_idx]++;
}

static int LOGWRITE_STAT;
static stat_cnt_t STAT_CNT;
void calc_and_print_stat()
{
    char buf[1024] = {0,};
    char logbuf_avg[1024] = {0,};
    char logbuf_sum[1024] = {0,};
    char buf_dbg[1024] = {0,};
    char buf_step[1024] = {0,};

    /* for sum */
    stat_cnt_t stat_cnt;
    memset(&stat_cnt, 0x00, sizeof(stat_cnt_t));

    /* save idx for recv thrd calc and move idx forward for next stat */
    statistic_t *stat = NULL;
    int curr_idx = STAT.curr_idx;
    if ((stat = move_stat_return_stat()) == NULL) {
        return;
    }

    /* make stat summary (send) */
    for (int i = 0; i < MAX_THREAD_NUM; i++) {
        for (int j = 0; j < PF_STAT_MAX; j++) {
            stat_cnt.stat_count[j] += stat->per_thread_stat[i].stat_count[j];
            STAT_CNT.stat_count[j] += stat->per_thread_stat[i].stat_count[j];
        }

        for (int j = 0; j < MAX_PF_STEP_NUM; j++) {
            stat_cnt.step_count[j] += stat->per_thread_stat[i].step_count[j];
        }
    }
    memset(stat, 0x00, sizeof(statistic_t));

    /* make stat summary (recv) */
    for (int k = 0; k < MAX_THREAD_NUM; k++) {
        statistic_t *recv_stat = NULL;
        recv_stat = &RECV_STAT[k].stat[curr_idx];
        for (int i = 0; i < MAX_THREAD_NUM; i++) {
            for (int j = 0; j < PF_STAT_MAX; j++) {
                stat_cnt.stat_count[j] += recv_stat->per_thread_stat[i].stat_count[j];
                STAT_CNT.stat_count[j] += recv_stat->per_thread_stat[i].stat_count[j];
            }

            for (int j = 0; j < MAX_PF_STEP_NUM; j++) {
                stat_cnt.step_count[j] += recv_stat->per_thread_stat[i].step_count[j];
            }
        }
        memset(recv_stat, 0x00, sizeof(statistic_t));
    }

    /* statictic */
    sprintf(buf, "\nSTAT ]\n");
    sprintf(buf_dbg, "\nDBG ] ");
    for (int i = 0; i < PF_STAT_MAX; i++) {
        sprintf(buf + strlen(buf), "%15s : %10d\n", stat_str[i], stat_cnt.stat_count[i]);
        sprintf(buf_dbg + strlen(buf_dbg), "%10d  ", stat_cnt.stat_count[i]);
    }
    fprintf(stderr, "%s\n", buf);
    fprintf(stderr, "%s\n", buf_dbg);

    /* send step num */
    sprintf(buf_step, "\nSTEP ]\n");
    for (int i = 0; i < MAX_PF_STEP_NUM; i++) {
        sprintf(buf_step + strlen(buf_step), "%15s : %10d\n",
                PERF_CONF.scenario.step[i].occupied != 1 ? "NULL" : PERF_CONF.scenario.step[i].rsrc,
                stat_cnt.step_count[i]);
    }
    fprintf(stderr, "%s\n", buf_step);

    LOGWRITE_STAT ++;
    if (LOGWRITE_STAT >= 20) {
        sprintf(logbuf_avg, "%s", "AVG]");
        sprintf(logbuf_sum, "%s", "SUM]");
        for (int i = 0; i < PF_STAT_MAX; i++) {
            sprintf(logbuf_avg + strlen(logbuf_avg), "%s: %11d ", stat_str[i], stat_cnt.stat_count[i]); 
            sprintf(logbuf_sum + strlen(logbuf_sum), "%s: %11d ", stat_str[i], STAT_CNT.stat_count[i]); 
        }
        APPLOG(APPLOG_ERR, "%s", logbuf_avg);
        APPLOG(APPLOG_ERR, "%s", logbuf_sum);
        LOGWRITE_STAT = 0;
    }
}

static int LOGWRITE_AVG;
void calc_and_print_sndrcv()
{
    int ncount = 0;
    long double resp_tm = 0;
    int send_byte = 0;
    int recv_byte = 0;

    if (sem_wait(MY_SEM) == 0) {
        for (int i = 0; i < MAX_RCV_CHAIN_NUM; i++) {
            if (SNDRCV.sndrcv[i].occupied != 1) continue;
            ncount ++;
            resp_tm += SNDRCV.sndrcv[i].end_tm - SNDRCV.sndrcv[i].start_tm;
            send_byte += SNDRCV.sndrcv[i].snd_byte;
            recv_byte += SNDRCV.sndrcv[i].rcv_byte;
        }
        if (ncount != 0) {
            resp_tm = resp_tm / ncount;
            send_byte = send_byte / ncount;
            recv_byte = recv_byte / ncount;
            fprintf(stderr, "AVG ] TM %10llf(double) SND_BYTE %10d RCV_BYTE %10d\n", resp_tm, send_byte, recv_byte);
        }

        LOGWRITE_AVG++;
        if (LOGWRITE_AVG >= 20) {
            APPLOG(APPLOG_ERR, "AVG] TM %10llf(double) SND_BYTE %10d RCV_BYTE %10d", resp_tm, send_byte, recv_byte);
            LOGWRITE_AVG = 0;
        }
        sem_post(MY_SEM);
    }
}

void clear_sndrcv_info()
{
    if (sem_wait(MY_SEM) == 0) {
        memset(&SNDRCV, 0x00, sizeof(sndrcv_t));
        sem_post(MY_SEM);
    }
}

statistic_t *move_stat_return_stat()
{
    statistic_t *stat = &STAT.stat[STAT.curr_idx];
    STAT.curr_idx = (STAT.curr_idx + 1) % MAX_PF_CHAIN_NUM; 
    return stat;
}
void view_context_use()
{
    int ctx_use[MAX_THRD_NUM];
    memset(&ctx_use, 0x00, sizeof(ctx_use));

    for (int index = 0; index < PERF_CONF.sender_thread_num; index++) {
        for (int j = 0; j < SIZEID; j++) {
        if (PERF_CTX[index][j].occupied == 1)
            ctx_use[index]++;
        }
    }

    fprintf(stderr, "\nCTX USE ]\n");
    for (int index = 0; index < PERF_CONF.sender_thread_num; index++) {
        fprintf(stderr, "\tsender %2d) %5d / %d\n", index, ctx_use[index], SIZEID - 1);
    }
    fprintf(stderr, "\n");
}
