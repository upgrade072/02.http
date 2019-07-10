/* this lib related with libhttp.a */

#include "libs.h"

/* httpc/s global */

int set_defined_header(hdr_index_t HDR_INDEX[], char *name, char *val, AhifHttpCSMsgType *appData)
{
	hdr_relay *vheader = appData->vheader;

	/* check header content length */
	if (strlen(val) >= MAX_HDR_BODY_LEN) {
		return (-1);
	}

	/* get empty slot */
	int index = 0;
	for (; index < MAX_HDR_RELAY_CNT; index++) {
		if (vheader[index].vheader_id == 0) {
			break;
		}
	}

	/* if all slot full we cant */
	if (index == MAX_HDR_RELAY_CNT) {
		return (-1);
	}

	/* search header-enum and set to appData */
	hdr_index_t *ptr = search_vhdr(HDR_INDEX, VH_END, name);

	if (ptr != NULL) {
		vheader[index].vheader_id = ptr->vheader_id;
		sprintf(vheader[index].vheader_body, "%s", val);
		return 0;
	}

	return (-1);
}

int assign_more_headers(hdr_index_t HDR_INDEX[], nghttp2_nv *hdrs, int size, int cur_len, AhifHttpCSMsgType *appData)
{
	/* if contain Content-Encoding */
	int hdrs_len = cur_len;
	//AhifHttpCSMsgHeadType *head = &appData->head;
	hdr_relay *vheader = appData->vheader;

#if 0 // it move to vhdr
	if (head->contentEncoding[0]) {
		nghttp2_nv hd_add[] = { MAKE_NV(HDR_CONTENT_ENCODING, head->contentEncoding, strlen(head->contentEncoding)) };
		memcpy(&hdrs[hdrs_len], &hd_add, sizeof(nghttp2_nv));
		hdrs_len ++;
	}
#endif

	for (int i = 0; i < MAX_HDR_RELAY_CNT; i++) {
		if (hdrs_len >= size)
			return hdrs_len;
		if (vheader[i].vheader_id > VH_START && vheader[i].vheader_id < VH_END) {
			int header_enum = vheader[i].vheader_id;
			char *header_name = HDR_INDEX[header_enum].vheader_name;

			nghttp2_nv hd_add[] = { MAKE_NV_STR(header_name, vheader[i].vheader_body) };
			memcpy(&hdrs[hdrs_len], &hd_add, sizeof(nghttp2_nv));
			hdrs_len ++;
		}
	}

	return hdrs_len;
}

void print_header(FILE *f, const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen) 
{
    fwrite(name, 1, namelen, f);
    fprintf(f, ": ");
    fwrite(value, 1, valuelen, f);
	fprintf(f, "\n");
}

void print_headers(FILE *f, nghttp2_nv *nva, size_t nvlen) 
{
    size_t i;
    for (i = 0; i < nvlen; ++i) {
        print_header(f, nva[i].name, nva[i].namelen, nva[i].value, nva[i].valuelen);
    }
}
