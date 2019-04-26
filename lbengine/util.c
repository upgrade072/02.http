#include "lbengine.h"

// return ip address 
char *util_get_ip_from_sa(struct sockaddr *sa)
{
    struct sockaddr_in *peer_addr = (struct sockaddr_in *)sa;
    return inet_ntoa(peer_addr->sin_addr);
}

// return port no
int util_get_port_from_sa(struct sockaddr *sa)
{
    in_port_t port = {0,};

    if (sa->sa_family == AF_INET) {
        port = (((struct sockaddr_in*)sa)->sin_port);
    } else {
        port = (((struct sockaddr_in6*)sa)->sin6_port);
    }

    return ntohs(port);
}

// set so_linger (abort) option to sock
int util_set_linger(int fd, int onoff, int linger)
{
    struct linger l = { .l_linger = linger, .l_onoff = onoff};
    int res = setsockopt(fd, SOL_SOCKET, SO_LINGER, &l, sizeof(l));

    return res;
}

int util_set_rcvbuffsize(int fd, int byte)
{
	int opt = byte;
	int res = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt));

	return res;
}

int util_set_sndbuffsize(int fd, int byte)
{
	int opt = byte;
	int res = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &opt, sizeof(opt));

	return res;
}

// set keepalived option to sock
int util_set_keepalive(int fd, int keepalive, int cnt, int idle, int intvl)
{
    int res = setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));
    res = setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &idle, sizeof(idle));
    res = setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
    res = setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));

    return res;
}

// get process pid used for top -p H
pid_t util_gettid(void)
{
    return(syscall(SYS_gettid));
}

// hexa dump raw data
void util_dumphex(const void* data, size_t size)
{
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        fprintf(stderr, "%02X ", ((unsigned char*)data)[i]);
        if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i+1) % 8 == 0 || i+1 == size) {
            fprintf(stderr, " ");
            if ((i+1) % 16 == 0) {
                fprintf(stderr, "|  %s \n", ascii);
            } else if (i+1 == size) {
                ascii[(i+1) % 16] = '\0';
                if ((i+1) % 16 <= 8) {
                    fprintf(stderr, " ");
                }
                for (j = (i+1) % 16; j < 16; ++j) {
                    fprintf(stderr, "   ");
                }
                fprintf(stderr, "|  %s \n", ascii);
            }
        }
    }
}

#define GIB 1073741824
#define MIB 1048576
#define KIB 1024
#define BYTE 1
typedef enum measure_print {
    M_GIB = 0,
    M_MIB,
    M_KIB,
    M_BYTE,
    M_MAX
} measure_print_t;

char measure_str[][1024] = {
    "GB",
    "MB",
    "KB",
    "BYTE",
    "MAX"
};

char *measure_print(int bytes, char *return_str)
{
    int measure = bytes > GIB ? M_GIB :
        bytes > MIB ? M_MIB :
        bytes > KIB ? M_KIB : M_BYTE;
    int val = bytes > GIB ? (bytes / GIB) :
        bytes > MIB ? (bytes / MIB) :
        bytes > KIB ? (bytes / KIB) : bytes;

    sprintf(return_str, "%d %s", val, measure_str[measure]);

    return return_str;
}

void printf_config_list_int(char *annotation, config_setting_t *int_list)
{
	int item_count = config_setting_length(int_list);
	for (int i = 0; i < item_count; i++) {
		config_setting_t *item = config_setting_get_elem(int_list, i);
		fprintf(stderr, "}} %2d st %s: %d\n", i, annotation, config_setting_get_int(item));
	}
}
