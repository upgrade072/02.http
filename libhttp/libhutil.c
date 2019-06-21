#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "http_comm.h"

int parse_ipv4(char *temp_str, struct sockaddr_in *sa, int *port)
{
	char ip[INET6_ADDRSTRLEN] = {0,};
	char *ptr = strtok(temp_str, ":");

	if (ptr == NULL)
		return (-1);
	else
		sprintf(ip, "%s", ptr);

	ptr = strtok(NULL, " ");
	if (ptr == NULL) 
		return (-1);
	else
		*port = atoi(ptr);

	if (inet_pton(AF_INET, ip, &(sa->sin_addr)) <= 0)
		return (-1);
#if 0
	else
		fprintf(stderr, "[%s] ip %s port %d\n", __func__, ip, *port);
#endif

	return AF_INET;
}

int parse_ipv6(char *temp_str, struct sockaddr_in6 *sa6, int *port)
{
	char ip[INET6_ADDRSTRLEN] = {0,};
	char *ptr = strrchr(temp_str, ':');

	if (ptr == NULL) {
		return (-1);
	} else {
		*port = atoi(ptr+1);
		*ptr  = '\0';
	}

	int len = strlen(temp_str) - 1;
	for (int i = 0; i < len; i++) {
		temp_str[i] = temp_str[i+1];
		if (temp_str[i] == ']') {
			temp_str[i] = '\0';
			break;
		}
	}
	sprintf(ip, "%s", temp_str);

	if (inet_pton(AF_INET6, ip, &(sa6->sin6_addr)) <= 0)
		return (-1);
#if 0
	else
		fprintf(stderr, "[%s] ip %s port %d\n", __func__, ip, *port);
#endif

	return AF_INET;
}

/* input 192.168.1.1:8888 | [2001:db8::1]:8080 */
/* return -1, AF_INET, AF_INET6 */
int parse_http_addr(char *temp_str, struct sockaddr_in *sa, struct sockaddr_in6 *sa6, int *port)
{
	int addr_type = 0;

	if (temp_str[0] == '[') {
		//fprintf(stderr, "[%s] input ipv6 %s\n", __func__, temp_str);
		addr_type = AF_INET6;
	} else if (temp_str[0] >= '0' && temp_str[0] <= '9') {
		//fprintf(stderr, "[%s] input ipv4 %s\n", __func__, temp_str);
		addr_type = AF_INET;
	} else {
		APPLOG(APPLOG_ERR, "%s() input wrong address %s", __func__, temp_str);
		return (-1);
	}

	switch (addr_type) {
		case AF_INET:
			if (parse_ipv4(temp_str, sa, port) < 0)
				goto HTTP_ADDR_PARSE_ERR;
			break;
		case AF_INET6:
			if (parse_ipv6(temp_str, sa6, port) < 0)
				goto HTTP_ADDR_PARSE_ERR;
			break;
		default:
			goto HTTP_ADDR_PARSE_ERR;
	}
	//fprintf(stderr,"[%s] success\n\n", __func__);
	return addr_type;

HTTP_ADDR_PARSE_ERR:
	APPLOG(APPLOG_ERR, "%s() parse error !!!", __func__);
	return (-1);
}


void divide_string(char *input, int delim, char *head, ssize_t head_size, char *tail, ssize_t tail_size)
{
    char *delim_ptr;

    if ((delim_ptr = strchr(input, delim)) == NULL) {
        snprintf(head, head_size, "%s", input);
        return;
    } else {
        snprintf(head, (delim_ptr + 1 - input) % head_size, "%s", input);
        snprintf(tail, tail_size, "%s", delim_ptr + 1);
    }
}
