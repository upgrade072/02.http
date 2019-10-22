#include <nrfm.h>

extern main_ctx_t MAIN_CTX;


void dump_pkt_log(void *msg, ssize_t size)
{
	FILE *temp_file = NULL; 
	size_t file_size = 0;
	char *ptr = NULL; 

	temp_file = open_memstream(&ptr, &file_size); // buff size auto-grow
	if (temp_file == NULL) {
		APPLOG(APPLOG_ERR, "{{{PKT}}} in %s fail to call open_memstream!", __func__);
		return; 
	}     
	util_dumphex(temp_file, msg, size);
	fclose(temp_file);
	APPLOG(APPLOG_ERR, "{{{{PKT}}} RECV\n%s\n", ptr);
	free(ptr);
}

// CAUTION!!! must free after use, outbuffer
int get_file_contents(const char* filename, char** outbuffer)
{
	FILE* file = NULL;
	long filesize;
	const int blocksize = 1;
	size_t readsize;
	char* filebuffer;

	// Open the file
	file = fopen(filename, "r");
	if (NULL == file) {
		fprintf(stderr, "'%s' not opened\n", filename);
		return -1;
	}

	// Determine the file size
	fseek(file, 0, SEEK_END);
	filesize = ftell(file);
	rewind (file);

	// Allocate memory for the file contents
	filebuffer = (char*) malloc(sizeof(char) * filesize);
	*outbuffer = filebuffer;
	if (filebuffer == NULL) {
		fprintf(stderr, "malloc out-of-memory\n");
		return -1;
	}

	// Read in the file
	readsize = fread(filebuffer, blocksize, filesize, file);
	if (readsize != filesize) {
		fprintf(stderr, "didn't read file completely\n");
		return -1;
	}

	// Clean exit
	fclose(file);
	return 0;
}

void get_svc_ipv4_addr(const char *nic_name, char *nic_addr)
{
	int fd = 0;
	struct ifreq ifr = {0,};

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	/* only need ipv4 address */
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, nic_name, IFNAMSIZ-1);
	ioctl(fd, SIOCGIFADDR, &ifr);

	close(fd);

	sprintf(nic_addr, "%s", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
}

void handle_ctx_timeout(evutil_socket_t fd, short what, void *arg)
{
	timeout_arg_t *timer = arg;

	if (timer->ev_timeout != NULL) {
		event_free(timer->ev_timeout);
		timer->ev_timeout = NULL;
	}

	switch (timer->type) {
		// re try to another NRF
		case NF_CTX_TYPE_REGI:
			APPLOG(APPLOG_ERR, "{{{DBG}}} %s nf register ctx timed out!", __func__);
			nf_regi_init_proc(&MAIN_CTX);
			break;
		case NF_CTX_TYPE_HEARTBEAT:
			APPLOG(APPLOG_ERR, "{{{DBG}}} %s nf heartbeat ctx timed out!", __func__);
			break;
		case NF_CTX_TYPE_RETRIEVE_LIST:
			APPLOG(APPLOG_ERR, "{{{DBG}}} %s nf retrieve(list) ctx timed out!", __func__);
			nf_retrieve_list_handle_timeout(timer->my_ctx);
			break;
		case NF_CTX_TYPE_RETRIEVE_PROFILE:
			APPLOG(APPLOG_ERR, "{{{DBG}}} %s nf retrieve(profile) ctx timed out!", __func__);
			nf_retrieve_item_handle_timeout(timer->my_ctx);
			break;
		case NF_CTX_TYPE_SUBSCRIBE:
			APPLOG(APPLOG_ERR, "{{{DBG}}} %s nf subscribe ctx timed out!", __func__);
			nf_subscribe_nf_type_handle_timeout(timer->my_ctx);
			break;
		case NF_CTX_TYPE_SUBSCR_PATCH:
			APPLOG(APPLOG_ERR, "{{{DBG}}} %s nf subscribe ctx timed out!", __func__);
			break;
		case NF_CTX_TYPE_ACQUIRE_TOKEN:
			APPLOG(APPLOG_ERR, "{{{DBG}}} %s nf acuire token ctx timed out!", __func__);
			nf_token_acquire_token_handle_timeout(&MAIN_CTX, timer->my_ctx);
			break;
		case NF_CTX_TYPE_HTTPC_CMD:
			APPLOG(APPLOG_ERR, "{{{DBG}}} %s nf management ctx timed out!", __func__);
			break;
		default:
			APPLOG(APPLOG_ERR, "{{{DBG}}} %s recv unknown type(%d)", __func__, timer->type);
			break;
	}
}

void LOG_JSON_OBJECT(const char *banner, json_object *js_obj)
{
#if 0
	char temp_buff[1024 *12] = {0,};
	sprintf(temp_buff, "%s", json_object_to_json_string_ext(js_obj, JSON_C_PRETTY_NOSLASH));
	APPLOG(APPLOG_ERR, "[%s]\n%s\n", banner, temp_buff);
#else
	APPLOG(APPLOG_ERR, "[%s]\n%s\n", banner, json_object_to_json_string_ext(js_obj, JSON_C_PRETTY_NOSLASH));
#endif
}

void start_ctx_timer(int ctx_type, nrf_ctx_t *nf_ctx)
{
	struct timeval timer_sec = {0,};

	config_setting_t *setting = config_lookup(&MAIN_CTX.CFG, CF_HTTP_RSP_WAIT_TM);
	timer_sec.tv_sec = config_setting_get_int(setting);

	if (nf_ctx->timer.ev_timeout != NULL) {
		APPLOG(APPLOG_ERR, "{{{CAUTION!!!}}} %s find already timer exist (from seqNo:%d) and free it!!",
				__func__, nf_ctx->seqNo);
		event_free(nf_ctx->timer.ev_timeout);
		nf_ctx->timer.ev_timeout = NULL;
	}

	nf_ctx->timer.type = ctx_type;
	nf_ctx->timer.ev_timeout = evtimer_new(MAIN_CTX.EVBASE, handle_ctx_timeout, &nf_ctx->timer);
	nf_ctx->timer.my_ctx = nf_ctx;
	event_add(nf_ctx->timer.ev_timeout, &timer_sec);
}

void stop_ctx_timer(int ctx_type, nrf_ctx_t *nf_ctx)
{
	if (nf_ctx->timer.ev_timeout != NULL) {
		event_free(nf_ctx->timer.ev_timeout);
		nf_ctx->timer.ev_timeout = NULL;
		APPLOG(APPLOG_DEBUG, "%s() stop timer for seqNo(%d)", __func__, nf_ctx->seqNo);
	}
}

void util_dumphex(FILE *out, const void* data, size_t size)
{
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        fprintf(out, "%02X ", ((unsigned char*)data)[i]);
        if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i+1) % 8 == 0 || i+1 == size) {
            fprintf(out, " ");
            if ((i+1) % 16 == 0) {
                fprintf(out, "|  %s \n", ascii);
            } else if (i+1 == size) {
                ascii[(i+1) % 16] = '\0';
                if ((i+1) % 16 <= 8) {
                    fprintf(out, " ");
                }
                for (j = (i+1) % 16; j < 16; ++j) {
                    fprintf(out, "   ");
                }
                fprintf(out, "|  %s \n", ascii);
            }
        }
    }
}

