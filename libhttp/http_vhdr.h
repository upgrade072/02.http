
#ifndef HTTP_VHDR_DEFINED
#define HTTP_VHDR_DEFINED 1

/* 사용 virtual 헤더에 대한 enum/string 을 정의 */
// VH_START 와 VH_END 는 유지
typedef enum {
	VH_START,
	VH_TEST_2,
	VH_TEST_1,
	VH_TEST_3,
	VH_TEST_4,
	VH_TEST_5,
	VH_TEST_9,
	VH_TEST_6,
	VH_TEST_7,
	VH_TEST_8,
	VH_END
} http_vheader;

// schlee, now testing
#define HTTP_VHEADER "\
VH_START\n\
VH_TEST_2\n\
VH_TEST_1\n\
VH_TEST_3\n\
VH_TEST_4\n\
VH_TEST_5\n\
VH_TEST_9\n\
VH_TEST_6\n\
VH_TEST_7\n\
VH_TEST_8\n\
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
