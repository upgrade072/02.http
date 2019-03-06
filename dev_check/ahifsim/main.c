#include "ahifsim.h"

static struct timeval TM_SYN_TIMEOUT = {3, 0};
static int RUNNING;

int init_cfg(main_ctx_t *MAIN_CTX)
{
	config_init(&MAIN_CTX->CFG);
	if (!config_read_file(&MAIN_CTX->CFG, CONFIG_PATH)) {
		fprintf(stderr, "%s:%d - %s\n",
				config_error_file(&MAIN_CTX->CFG),
				config_error_line(&MAIN_CTX->CFG),
				config_error_text(&MAIN_CTX->CFG));
		fprintf(stderr, "config(%s) loading fail!\n", CONFIG_PATH);
		fprintf(stderr, "=====================================================================\n");

		config_destroy(&MAIN_CTX->CFG);
		return (-1);
	} else {
		fprintf(stderr, "\nloading [%s]\n", CONFIG_PATH);
		fprintf(stderr, "=====================================================================\n");
		return (0);
	}
}

thrd_ctx_t *read_thread_conf(main_ctx_t *MAIN_CTX, config_setting_t *setting, char conn_type)
{
	thrd_ctx_t *thrd_ctx = NULL;

	switch (conn_type) {
		case TT_HTTPC_TX:
			thrd_ctx = &MAIN_CTX->httpc_tx_ctx;
			thrd_ctx->my_conn_type = TT_HTTPC_TX;
			thrd_ctx->MAIN_CTX = MAIN_CTX;
			if (config_setting_lookup_string(setting, "httpc_tx_ip", &thrd_ctx->ipaddr)== CONFIG_FALSE ||
					config_setting_lookup_int(setting, "httpc_tx_port", &thrd_ctx->port) == CONFIG_FALSE)
				return NULL;
			break;
		case TT_HTTPC_RX:
			thrd_ctx = &MAIN_CTX->httpc_rx_ctx;
			thrd_ctx->my_conn_type = TT_HTTPC_RX;
			thrd_ctx->MAIN_CTX = MAIN_CTX;
			if (config_setting_lookup_string(setting, "httpc_rx_ip", &thrd_ctx->ipaddr) == CONFIG_FALSE ||
					config_setting_lookup_int(setting, "httpc_rx_port", &thrd_ctx->port) == CONFIG_FALSE)
				return NULL;
			break;
		case TT_HTTPS_TX:
			thrd_ctx = &MAIN_CTX->https_tx_ctx;
			thrd_ctx->my_conn_type = TT_HTTPS_TX;
			thrd_ctx->MAIN_CTX = MAIN_CTX;
			if (config_setting_lookup_string(setting, "https_tx_ip", &thrd_ctx->ipaddr) == CONFIG_FALSE ||
					config_setting_lookup_int(setting, "https_tx_port", &thrd_ctx->port) == CONFIG_FALSE)
				return NULL;
			break;
		case TT_HTTPS_RX:
			thrd_ctx = &MAIN_CTX->https_rx_ctx;
			thrd_ctx->my_conn_type = TT_HTTPS_RX;
			thrd_ctx->MAIN_CTX = MAIN_CTX;
			if (config_setting_lookup_string(setting, "https_rx_ip", &thrd_ctx->ipaddr) == CONFIG_FALSE ||
					config_setting_lookup_int(setting, "https_rx_port", &thrd_ctx->port) == CONFIG_FALSE)
				return NULL;
			break;
		default:
			fprintf(stderr, "(%s) unknown type received!\n", __func__);
			return NULL;
	}

	return thrd_ctx;
}

double commlib_getCurrTime_double (void)
{           
    struct timeval  now;
    double          tval;
                    
    gettimeofday (&now, NULL);
                
    tval = (double)now.tv_sec + (double)now.tv_usec/1000000;
                
    return tval;
}

int util_set_linger(int fd, int onoff, int linger)
{   
	struct linger l = { .l_linger = linger, .l_onoff = onoff};
	int res = setsockopt(fd, SOL_SOCKET, SO_LINGER, &l, sizeof(l));

	return res;
}

int crt_new_conn(thrd_ctx_t *thrd_ctx, bufferevent_data_cb readcb, bufferevent_data_cb writecb, bufferevent_event_cb eventcb)
{
    struct sockaddr_in sin = {0,};
    
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr(thrd_ctx->ipaddr);
    sin.sin_port = htons(thrd_ctx->port);
    
    thrd_ctx->fd = socket(AF_INET, SOCK_STREAM, 0); 
	if (evutil_make_socket_nonblocking(thrd_ctx->fd) == -1)
		fprintf(stderr, "sock set nonblock failed\n");
    
	thrd_ctx->evbase = event_base_new();

    thrd_ctx->bev = bufferevent_socket_new(thrd_ctx->evbase, thrd_ctx->fd,
            BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);

    if (!thrd_ctx->bev) {
        fprintf(stderr, "Error constructing bufferevent!");
        event_base_loopbreak(thrd_ctx->evbase);
        return (-1);
    }

    bufferevent_enable(thrd_ctx->bev, EV_READ);
    bufferevent_setcb(thrd_ctx->bev, readcb, writecb, sock_eventcb, thrd_ctx);
    bufferevent_set_timeouts(thrd_ctx->bev, &TM_SYN_TIMEOUT, &TM_SYN_TIMEOUT);

    if(bufferevent_socket_connect(thrd_ctx->bev, (struct sockaddr *)&sin, sizeof(sin)) < 0)
		return (-1);

	return (0);
}

void *perf_thread(void *arg)
{
	thrd_ctx_t *thrd_ctx = (thrd_ctx_t *)arg;
	int res = -1;

	switch (thrd_ctx->my_conn_type) {
		case TT_HTTPC_TX:
			res = crt_new_conn(thrd_ctx, NULL, NULL, sock_eventcb);
			break;
		case TT_HTTPC_RX:
			res = crt_new_conn(thrd_ctx, httpc_read_cb, NULL, sock_eventcb);
			break;
		case TT_HTTPS_TX:
			res = crt_new_conn(thrd_ctx, NULL, NULL, sock_eventcb);
			break;
		case TT_HTTPS_RX:
			res = crt_new_conn(thrd_ctx, https_read_cb, NULL, sock_eventcb);
			break;
	}
	if (res < 0) {
		fprintf(stderr, "fail to create thread\n");
		exit(0);
	}

	event_base_loop(thrd_ctx->evbase, EVLOOP_NO_EXIT_ON_EMPTY);

	fprintf(stderr, "never reach here~!\n");

	return (void *)NULL;
}

int create_thread(thrd_ctx_t *thrd_ctx)
{
	pthread_t thread_id = {0,};
	if (pthread_create(&thread_id, NULL, &perf_thread, thrd_ctx) != 0)
		return (-1);
	if (pthread_detach(thread_id) != 0)
		return (-1);

	return 0;
}

int init_thread(main_ctx_t *MAIN_CTX)
{
	config_setting_t *setting = NULL;

	if ((setting = config_lookup(&MAIN_CTX->CFG, "scenario")) == NULL) {
		fprintf(stderr, "fail to load scenario. in cfg\n");
		return (-1);
	}

	for (int i = 0; i < TT_NUMOF; i++) {
		thrd_ctx_t *thrd_ctx = NULL;
		if ((thrd_ctx = read_thread_conf(MAIN_CTX, setting, i)) == NULL) {
			fprintf(stderr, "fail to load thread conf\n");
			return (-1);
		}
		if (create_thread(thrd_ctx) < 0) {
			fprintf(stderr, "fail to create thread\n");
			return (-1);
		}
	}

	return 0;

}

void end_perf()
{
	fprintf(stderr, "perf ended by duration\n");
	RUNNING = 0;
}

void perf_gen(main_ctx_t *MAIN_CTX)
{
	config_setting_t *setting = NULL;

	if ((setting = config_lookup(&MAIN_CTX->CFG, "application")) == NULL) {
		fprintf(stderr, "fail to load application. in cfg\n");
		exit(0);
	}

	int validate_mode = 0;
	int amount_per_sec = 0;
	int duration = 0;
	if (config_setting_lookup_int(setting, "validate_mode", &validate_mode) == CONFIG_FALSE ||
		config_setting_lookup_int(setting, "amount_per_sec", &amount_per_sec) == CONFIG_FALSE ||
		config_setting_lookup_int(setting, "duration", &duration) == CONFIG_FALSE) {
		fprintf(stderr, "fail to load .validate_mode | .amount_per_sec | . duration\n");
		exit(0);
	}

	if (duration != 0) {
		fprintf(stderr, "Program will exit after %d min\n", duration * 60);

		signal(SIGALRM, end_perf);
		alarm(duration * 60);
	}

	double before_100, now;
	int snd_count = 0;
	float bulk_snd = amount_per_sec / 100;

	before_100 = commlib_getCurrTime_double();
	while (RUNNING) {
		if (validate_mode) {
			if (snd_count < validate_mode) {
				snd_ahif_pkt(MAIN_CTX);
				snd_count++;
			}
			sleep(1);
		} else {
			now = commlib_getCurrTime_double();
			if ((now - before_100) >= 0.01) {
				before_100 = now;
				for (int i = 0; i < bulk_snd; i++) {
					snd_ahif_pkt(MAIN_CTX);
				}
				snd_count++;
			} else {
				usleep(1);
			}
			if (snd_count >= 100) {
				snd_count = 0;
			}
		}
	}
}

// TODO!!! tx must continuely flush all write items!!!
int main()
{
	main_ctx_t MAIN_CTX = { .dest_hosts_pos = 0, .vheader_cnts_pos = 0, .body_lens_pos = 0 };

	evthread_use_pthreads();

	if (init_cfg(&MAIN_CTX) < 0) {
		fprintf(stderr, "fail to init_cfg()\n");
		exit(-1);
	}

	if (init_thread(&MAIN_CTX) < 0) {
		fprintf(stderr, "fail to init_thread()\n");
		exit(-1);
	}

	while (MAIN_CTX.httpc_tx_ctx.connected != 1 &&
		MAIN_CTX.httpc_rx_ctx.connected != 1 &&
		MAIN_CTX.https_tx_ctx.connected != 1 &&
		MAIN_CTX.https_rx_ctx.connected != 1) {
		fprintf(stderr, "(%s) wait until all conn is connected\n", __func__);
		sleep(1);
	}

	perf_gen(&MAIN_CTX);

	return 0;
}
