
#ifndef HTTP_VHDR_DEFINED
#define HTTP_VHDR_DEFINED 1

/* ��� virtual ����� ���� enum/string �� ���� */
// VH_START �� VH_END �� ����
typedef enum {
	VH_START,
	VH_HELLO_WORLD,
	VH_ARIEL_NETS,
	VH_CACHE_CONTROLS,
	VH_WRONG_HEADER,
	VH_END
} http_vheader;
#define HTTP_VHEADER "\
VH_START\n\
hdr-hello-world\n\
hdr-ariel-nets\n\
cache-controls\n\
:wrong_header\n\
VH_END\n\n"

#define MAX_HDR_RELAY_CNT 12
#define MAX_HDR_NAME_LEN 32
#define MAX_HDR_BODY_LEN 256

/* for AHIF/APP */
typedef struct {
	int vheader_id;
	char vheader_body[MAX_HDR_BODY_LEN];
} hdr_relay;

/* for HTTPC/S */
typedef struct hdr_index {
	char vheader_name[MAX_HDR_NAME_LEN];
	int vheader_id;
} hdr_index_t;

#endif
