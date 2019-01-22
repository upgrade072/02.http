#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum http_vheader {
	VH_START,
	VH_ACCEPT,
	VH_ACCEPT_ENCODING,
	VH_CONTENT_LENGTH,
	VH_CONTENT_TYPE,
	VH_USER_AGENT,
	VH_CACHE_CONTROL,
	VH_IF_MODIFIED_SINCE,
	VH_IF_NONE_MATCH,
	VH_IF_MATCH,
	VH_VIA,
	VH_AUTHORIZATION,
	VH_END
} http_vheader_t;

#define HTTP_VHEADER "\
VH_START\n\
Accept\n\
Accept-Encoding\n\
Content-Length\n\
Content-Type\n\
User-Agent\n\
Cache-Control\n\
If-Modified-Since\n\
If-None-Match\n\
If-Match\n\
Via\n\
Authorization\n\
VH_END\n"

#define MAX_HDR_RELAY_CNT 12
#define MAX_HDR_BODY_LEN 256

typedef struct {
	int vheader_id;
	char vheader_body[MAX_HDR_BODY_LEN];
} hdr_relay;

int main()
{
	int copy_pos = 0;
	char vheader_str[VH_END][128] = {0,};

	char *line = strtok(strdup(HTTP_VHEADER), "\n");
	while (line) {
		printf("%d %s\n", copy_pos, line);
		sprintf(vheader_str[copy_pos++], "%s", line);
		line = strtok(NULL, "\n");
	}

	printf("\ntest [VH_AUTHORIZATION] is (%s)\n\n", vheader_str[VH_AUTHORIZATION]);
}


