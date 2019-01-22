/* this lib related with libhttp.a */

#include "libs.h"

/* httpc/s global */
extern hdr_index_t HDR_INDEX[];

void set_defined_header(char *name, char *val, AhifHttpCSMsgType *appData)
{
	hdr_relay *vheader = appData->vheader;

	/* check header content length */
	if (strlen(val) >= MAX_HDR_BODY_LEN)
		return;

	/* get empty slot */
	int index = 0;
	for (; index < MAX_HDR_RELAY_CNT; index++) {
		if (vheader[index].vheader_id != 0)
			break;
	}

	/* if all slot full we cant */
	if (index == MAX_HDR_RELAY_CNT)
		return;

	/* search header-enum and set to appData */
	hdr_index_t *ptr = search_vhdr(HDR_INDEX, VH_END, name);

	if (ptr != NULL) {
		vheader[index].vheader_id = ptr->vheader_id;
		sprintf(vheader[index].vheader_body, "%s", val);
	}

	return;
}

int assign_more_headers(nghttp2_nv *hdrs, int size, int cur_len, AhifHttpCSMsgType *appData)
{
	/* if contain Content-Encoding */
	int hdrs_len = cur_len;
	AhifHttpCSMsgHeadType *head = &appData->head;
	hdr_relay *vheader = appData->vheader;

	if (head->contentEncoding[0]) {
		nghttp2_nv hd_add[] = { MAKE_NV(HDR_CONTENT_ENCODING, head->contentEncoding, strlen(head->contentEncoding)) };
		memcpy(&hdrs[hdrs_len], &hd_add, sizeof(nghttp2_nv));
		hdrs_len ++;
	}

	for (int i = 0; i < MAX_HDR_RELAY_CNT; i++) {
		if (hdrs_len >= size)
			return hdrs_len;
		if (vheader[i].vheader_id > VH_START && vheader[i].vheader_id < VH_END) {
			int header_enum = vheader[i].vheader_id;
			char *header_name = HDR_INDEX[header_enum].vheader_name;
			int value_len = strlen(vheader[i].vheader_body);
			nghttp2_nv hd_add[] = { MAKE_NV(header_name, vheader[i].vheader_body, value_len) };
			memcpy(&hdrs[hdrs_len], &hd_add, sizeof(nghttp2_nv));
			hdrs_len ++;
		}
	}

	return hdrs_len;
}
